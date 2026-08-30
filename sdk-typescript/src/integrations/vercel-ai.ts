/**
 * Vercel AI SDK Integration
 *
 * Language-model middleware for `wrapLanguageModel` from the `ai` package.
 * Duck-typed (no hard `ai` dependency): implements `transformParams`,
 * `wrapGenerate`, and `wrapStream`, handling both LanguageModelV1 and
 * LanguageModelV2 result shapes.
 *
 * `transformParams` provides real pre-call enforcement: PII can be redacted
 * in the params, or the call blocked entirely.
 *
 * KNOWN LIMITATION on `ai` below 5.0.0 — blocked-call attribution only.
 * Enforcement is fully correct across the whole supported range: the call is
 * blocked, `status_code` is 403, and the reason code and blocked types are
 * right. What degrades is the EVIDENCE on a blocked event, which carries
 * `provider: "unknown"` and `model: "unknown"` there.
 *
 * The cause is upstream and not recoverable here. At language-model spec v1
 * `transformParams` receives `{ params, type }` and no model; the middleware
 * object is destructured to exactly three hooks, so there is no wrap-time
 * callback that could supply one; and obsvr never calls `wrapLanguageModel`
 * itself — the caller does — so the model never enters obsvr's closure either.
 * A block is emitted and thrown from `transformParams` before `wrapGenerate`
 * ever runs, so caching a model learned from a previous call would still leave
 * the first one unattributed and would cross-attribute a middleware instance
 * reused across models.
 *
 * From `ai` 5.0.0 the spec passes `model` to `transformParams` and blocked
 * events are fully attributed. Per-provider or per-model reporting OVER BLOCKED
 * CALLS is therefore unavailable on 3.3.28-4.x; every other event is unaffected.
 *
 * @example
 * ```ts
 * import { wrapLanguageModel } from "ai";
 * import { openai } from "@ai-sdk/openai";
 * import { obsvr } from "@obsvr/sdk";
 * import { obsvrMiddleware } from "@obsvr/sdk/vercel-ai";
 *
 * obsvr.init({ apiKey: "..." });
 * const model = wrapLanguageModel({
 *   model: openai("gpt-4o"),
 *   middleware: obsvrMiddleware(),
 * });
 * ```
 *
 * @packageDocumentation
 */

// Interception: Vercel AI middleware API (non-mutating). Returns a middleware object for wrapLanguageModel(model, middleware) - zero mutation.

import {
  applyPreCallPolicy,
  assertRedactionApplied,
  blockedCallError,
  blockedPromptForStorage,
  blockedUserInputForStorage,
  emitIntegrationEvent,
  getConfig,
  inferProviderFromString,
  monitorModeRequiresEvidence,
  redactBuiltinPii,
  redactForStorage,
  setupExitHandlers,
  shouldSample,
  type ComplianceInfo,
  type IntegrationOptions,
  type IntegrationProvider,
  type PreCallPolicyResult,
  DEFAULT_COMPLIANCE,
  outboundRedactionBlockedCompliance,
} from "./core.js";
import { applyOutboundRedaction } from "../policy/detector-guard.js";
import {
  normalizeTokenUsage,
  type UsageShape,
} from "../proxy/extractors/token-usage.js";

const SOURCE = "vercel_ai";
const OPERATION = "generate";
const STREAM_OPERATION = "stream";
const POLICY_REDACTION_PLACEHOLDER = "[REDACTED_BY_POLICY]";

export interface ObsvrMiddlewareOptions extends IntegrationOptions {
  /** Middleware version flag expected by `wrapLanguageModel` (default "v1") */
  middlewareVersion?: string;
}

/** Minimal duck-typed model shape passed to middleware hooks */
interface ModelLike {
  modelId?: string;
  provider?: string;
}

/** Per-call state stashed between transformParams and wrapGenerate/wrapStream */
interface CallState {
  compliance: ComplianceInfo;
  /** Sampled in, OR the policy acted — governed calls are always recorded. */
  auditThisCall: boolean;
}

const callState = new WeakMap<object, CallState>();

// ---------------------------------------------------------------------------
// Prompt helpers (LanguageModelV1/V2 prompt: string | message array)
// ---------------------------------------------------------------------------

function stringLeaves(value: unknown, into: string[] = []): string[] {
  if (typeof value === "string") {
    into.push(value);
  } else if (Array.isArray(value)) {
    for (const item of value) stringLeaves(item, into);
  } else if (value && typeof value === "object") {
    for (const item of Object.values(value as Record<string, unknown>)) {
      stringLeaves(item, into);
    }
  }
  return into;
}

function partText(part: unknown): string {
  if (typeof part === "string") return part;
  if (!part || typeof part !== "object") return "";

  const p = part as Record<string, unknown>;
  const text: string[] = [];
  if (typeof p.text === "string") text.push(p.text);

  // AI SDK generations have used `args` and `input` for tool calls, `result`
  // for V1 tool results, and `output` for V2/V3 tool results. These values are
  // provider-bound content just as much as a user text part is.
  for (const field of ["args", "input", "result", "output"] as const) {
    if (field in p) stringLeaves(p[field], text);
  }

  // Inline text files are prompt content. Binary/base64 media is deliberately
  // excluded: applying a text redactor to it would corrupt the payload.
  const mediaType = p.mediaType ?? p.mimeType;
  if (
    p.type === "file" &&
    typeof mediaType === "string" &&
    mediaType.toLowerCase().startsWith("text/") &&
    typeof p.data === "string"
  ) {
    text.push(p.data);
  }
  return text.join(" ");
}

function contentText(content: unknown): string {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content.map(partText).filter(Boolean).join(" ");
  }
  return partText(content);
}

function promptMessages(params: unknown): Record<string, unknown>[] {
  if (!params || typeof params !== "object") return [];
  const prompt = (params as Record<string, unknown>).prompt;
  if (Array.isArray(prompt)) return prompt as Record<string, unknown>[];
  return [];
}

function extractParamsPrompt(params: unknown): string {
  if (!params || typeof params !== "object") return "";
  const value = params as Record<string, unknown>;
  const lines: string[] = [];
  const system = contentText(value.system);
  if (system) lines.push(`system: ${system}`);

  const prompt = value.prompt;
  if (typeof prompt === "string") {
    lines.push(`user: ${prompt}`);
  } else if (Array.isArray(prompt)) {
    for (const message of prompt) {
      if (!message || typeof message !== "object") continue;
      const msg = message as Record<string, unknown>;
      const role = typeof msg.role === "string" ? msg.role : "unknown";
      const text = contentText(msg.content);
      if (text) lines.push(`${role}: ${text}`);
    }
  }
  return lines.join("\n");
}

function extractParamsLastUser(params: unknown): string {
  const prompt =
    params && typeof params === "object"
      ? (params as Record<string, unknown>).prompt
      : undefined;
  if (typeof prompt === "string") return prompt;
  const messages = promptMessages(params);
  for (let i = messages.length - 1; i >= 0; i--) {
    if (messages[i].role === "user") {
      return contentText(messages[i].content);
    }
  }
  return extractParamsPrompt(params);
}

function redactStringLeaves(value: unknown): unknown {
  if (typeof value === "string") return redactBuiltinPii(value);
  if (Array.isArray(value)) return value.map(redactStringLeaves);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, item]) => [
        key,
        redactStringLeaves(item),
      ]),
    );
  }
  return value;
}

function redactPart(part: unknown): unknown {
  if (typeof part === "string") return redactBuiltinPii(part);
  if (!part || typeof part !== "object") return part;
  const input = part as Record<string, unknown>;
  const out = { ...input };
  if (typeof input.text === "string") out.text = redactBuiltinPii(input.text);
  for (const field of ["args", "input", "result", "output"] as const) {
    if (field in input) out[field] = redactStringLeaves(input[field]);
  }
  const mediaType = input.mediaType ?? input.mimeType;
  if (
    input.type === "file" &&
    typeof mediaType === "string" &&
    mediaType.toLowerCase().startsWith("text/") &&
    typeof input.data === "string"
  ) {
    out.data = redactBuiltinPii(input.data);
  }
  return out;
}

function redactMessage(message: unknown): unknown {
  if (!message || typeof message !== "object") return message;
  const input = message as Record<string, unknown>;
  const content = input.content;
  return {
    ...input,
    content:
      typeof content === "string"
        ? redactBuiltinPii(content)
        : Array.isArray(content)
          ? content.map(redactPart)
          : redactPart(content),
  };
}

function structuredRedactedParams(
  params: Record<string, unknown>,
): Record<string, unknown> {
  const out = { ...params };
  if (typeof params.system === "string") {
    out.system = redactBuiltinPii(params.system);
  } else if (params.system !== undefined) {
    out.system = redactStringLeaves(params.system);
  }
  if (typeof params.prompt === "string") {
    out.prompt = redactBuiltinPii(params.prompt);
  } else if (Array.isArray(params.prompt)) {
    out.prompt = params.prompt.map(redactMessage);
  }
  return out;
}

function collapsedRedactedParams(
  params: Record<string, unknown>,
  safeText: string,
): Record<string, unknown> {
  const out = { ...params };
  delete out.system;
  out.prompt =
    typeof params.prompt === "string"
      ? safeText
      : [{ role: "user", content: [{ type: "text", text: safeText }] }];
  return out;
}

function redactParams(
  params: Record<string, unknown>,
  prompt: string,
  policy: PreCallPolicyResult,
): Record<string, unknown> {
  const builtinWhole = redactBuiltinPii(prompt);
  const hasNonBuiltinRewrite =
    policy.redactedPrompt !== prompt && policy.redactedPrompt !== builtinWhole;
  const requiresWholePromptRewrite =
    policy.compliance.redacted_types.length === 0 || hasNonBuiltinRewrite;

  const out = requiresWholePromptRewrite
    ? collapsedRedactedParams(
        params,
        policy.redactedPrompt !== prompt
          ? policy.redactedPrompt
          : POLICY_REDACTION_PLACEHOLDER,
      )
    : structuredRedactedParams(params);

  assertRedactionApplied(extractParamsPrompt(out), policy.compliance);
  return out;
}

// ---------------------------------------------------------------------------
// Result helpers (V1: result.text / usage.promptTokens;
//                 V2: result.content[] / usage.inputTokens)
// ---------------------------------------------------------------------------

function extractResultText(result: unknown): string {
  if (!result || typeof result !== "object") return "";
  const r = result as Record<string, unknown>;
  if (typeof r.text === "string") return r.text;
  if (Array.isArray(r.content)) {
    return (r.content as Record<string, unknown>[])
      .filter((p) => p.type === "text")
      .map((p) => (typeof p.text === "string" ? p.text : ""))
      .join("");
  }
  return "";
}

/**
 * Token counts off an AI SDK result, across every language-model spec version.
 *
 * This is the ONE site in the SDK that reads an SDK-versioned framework object
 * rather than a provider wire format, and it is the one that broke. The spec
 * has changed the shape of this object three times:
 *
 *   v1   usage.promptTokens / completionTokens / totalTokens   (numbers)
 *   v2   usage.inputTokens  / outputTokens     / totalTokens   (numbers)
 *   v3+  usage.inputTokens  = { total, noCache, cacheRead, cacheWrite }
 *        usage.outputTokens = { total, text, reasoning }
 *        totalTokens REMOVED
 *
 * v3 kept the field NAMES and changed their TYPE, so every existence check
 * still passed while `typeof v === "number"` answered "not a number" for both
 * counts — and the total, being derived from them, went with it. Nothing threw;
 * the events kept arriving with prompt, response and resolved model intact, and
 * only the numbers disappeared.
 *
 * Delegating to the shared normaliser means the nested form is understood here
 * the same way it would be anywhere else, and a shape this SDK has never seen
 * is reported as unreadable instead of silently counting as zero.
 */
function extractResultUsage(result: unknown): {
  input?: number;
  output?: number;
  total?: number;
  shape: UsageShape;
} {
  if (!result || typeof result !== "object") return { shape: "absent" };
  const { usage, shape } = normalizeTokenUsage(
    (result as Record<string, unknown>).usage,
  );
  return {
    input: usage?.input_tokens,
    output: usage?.output_tokens,
    total: usage?.total_tokens,
    shape,
  };
}

/**
 * Reserved telemetry for a usage payload obsvr could not read, and nothing at
 * all otherwise. Stamped only for `unrecognized` so the normal path adds no
 * bytes to the wire: an absent count with no reason beside it means the model
 * reported nothing, and an absent count WITH this reason means the shape moved.
 */
function usageShapeTelemetry(shape: UsageShape) {
  return shape === "unrecognized" ? { usage_shape: shape } : undefined;
}

function modelInfo(model: ModelLike | undefined): {
  model: string;
  provider: IntegrationProvider;
} {
  return {
    model: model?.modelId ?? "unknown",
    provider: inferProviderFromString(model?.provider ?? ""),
  };
}

/**
 * Provider-RESOLVED model snapshot for temporal provenance. The AI SDK v2
 * doGenerate result carries the serving model on `response.modelId`; undefined
 * when the provider/version does not report it.
 */
function extractResolvedModel(result: unknown): string | undefined {
  const response = (result as { response?: { modelId?: unknown } } | undefined)
    ?.response;
  const id = response?.modelId;
  return typeof id === "string" && id.trim().length > 0 ? id.trim() : undefined;
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

/**
 * Create an obsvr audit middleware for the Vercel AI SDK's
 * `wrapLanguageModel`.
 */
export function obsvrMiddleware(opts: ObsvrMiddlewareOptions = {}) {
  const middlewareVersion = opts.middlewareVersion ?? "v1";

  return {
    middlewareVersion,

    async transformParams(args: {
      type?: string;
      params: Record<string, unknown>;
      model?: ModelLike;
    }): Promise<Record<string, unknown>> {
      const { params } = args;
      const config = getConfig();
      if (config.disabled) return params;
      setupExitHandlers(config);

      // Sampling gates the EMISSION of clean allowed events, never enforcement.
      // Returning here skipped applyPreCallPolicy below, so a sub-1.0
      // sample_rate silently disabled PII/policy blocking on a fraction of
      // traffic and let the raw prompt reach the provider. Carry the decision
      // to the emit sites instead, as vertex.ts and bedrock.ts already do.
      const sampled = shouldSample(config.sample_rate);

      const { model, provider } = modelInfo(args.model);
      const promptText = extractParamsPrompt(params);
      const userText = extractParamsLastUser(params);
      const policy = await applyPreCallPolicy(promptText, {
        config,
        provider,
        operation: args.type === "stream" ? STREAM_OPERATION : OPERATION,
        userId: opts.user_id,
        serviceName: opts.service_name,
        model,
        metadata: opts.metadata,
      });

      if (policy.decision === "block") {
        emitIntegrationEvent({
          config,
          provider,
          model,
          operation: args.type === "stream" ? STREAM_OPERATION : OPERATION,
          source: opts.source ?? SOURCE,
          prompt: blockedPromptForStorage(
            promptText,
            policy.compliance,
            policy.securityNormalized,
          ),
          response: "",
          userInput: blockedUserInputForStorage(userText, policy),
          latencyMs: 0,
          success: false,
          statusCode: 403,
          options: opts,
          canaryTelemetry: policy.canaryTelemetry,
        floorTelemetry: policy.floorTelemetry,
          compliance: policy.compliance,
        });
        throw blockedCallError(policy.compliance);
      }
      let outboundParams = params;
      if (policy.decision === "redact") {
        // Enforcement application: a redaction that cannot be carried out
        // blocks rather than forwarding the content it was told to remove.
        const notRedacted = applyOutboundRedaction(() => {
          outboundParams = redactParams(params, promptText, policy);
        });
        if (notRedacted) {
          const blocked = outboundRedactionBlockedCompliance(policy.compliance, notRedacted);
          emitIntegrationEvent({
            config,
            provider,
            model,
            operation: args.type === "stream" ? STREAM_OPERATION : OPERATION,
            source: opts.source ?? SOURCE,
            prompt: blockedPromptForStorage(
              promptText,
              blocked,
              policy.securityNormalized,
            ),
            response: "",
            userInput: blockedUserInputForStorage(userText, policy),
            latencyMs: 0,
            success: false,
            statusCode: 403,
            options: opts,
            canaryTelemetry: policy.canaryTelemetry,
            floorTelemetry: policy.floorTelemetry,
            compliance: blocked,
          });
          throw blockedCallError(blocked);
        }
      }

      // Enforce-mode allows are sampled. Monitor mode and redaction are
      // complete evidence and always recorded (a block already threw).
      callState.set(outboundParams, {
        compliance: policy.compliance,
        auditThisCall:
          monitorModeRequiresEvidence(config) || sampled || policy.decision !== "allow",
      });
      return outboundParams;
    },

    async wrapGenerate(args: {
      doGenerate: () => PromiseLike<unknown>;
      params: Record<string, unknown>;
      model?: ModelLike;
    }): Promise<unknown> {
      const { doGenerate, params } = args;
      const config = getConfig();
      if (config.disabled) return doGenerate();

      const state = callState.get(params);
      if (state && !state.auditThisCall) return doGenerate();
      const compliance = state?.compliance ?? DEFAULT_COMPLIANCE;
      const { model, provider } = modelInfo(args.model);

      const startTime = performance.now();
      let result: unknown;
      try {
        result = await doGenerate();
      } catch (error) {
        emitIntegrationEvent({
          config,
          provider,
          model,
          operation: OPERATION,
          source: opts.source ?? SOURCE,
          prompt: extractParamsPrompt(params),
          response: "",
          userInput: extractParamsLastUser(params),
          latencyMs: Math.round(performance.now() - startTime),
          success: false,
          error,
          options: opts,
          compliance,
        });
        throw error;
      }

      const usage = extractResultUsage(result);
      const resolvedModel = extractResolvedModel(result);
      emitIntegrationEvent({
        config,
        provider,
        model,
        model_resolved: resolvedModel,
        // Read from the AI SDK's response abstraction (framework-mediated) → framework_reported.
        provenance_source: resolvedModel ? "framework_reported" : undefined,
        operation: OPERATION,
        source: opts.source ?? SOURCE,
        prompt: extractParamsPrompt(params),
        response: extractResultText(result),
        userInput: extractParamsLastUser(params),
        inputTokens: usage.input,
        outputTokens: usage.output,
        totalTokens: usage.total,
        telemetry: usageShapeTelemetry(usage.shape),
        latencyMs: Math.round(performance.now() - startTime),
        options: opts,
        compliance,
      });

      return result;
    },

    async wrapStream(args: {
      doStream: () => PromiseLike<unknown>;
      params: Record<string, unknown>;
      model?: ModelLike;
    }): Promise<unknown> {
      const { doStream, params } = args;
      const config = getConfig();
      if (config.disabled) return doStream();

      const state = callState.get(params);
      if (state && !state.auditThisCall) return doStream();
      const compliance = state?.compliance ?? DEFAULT_COMPLIANCE;
      const { model, provider } = modelInfo(args.model);

      const startTime = performance.now();
      let result: unknown;
      try {
        result = await doStream();
      } catch (error) {
        emitIntegrationEvent({
          config,
          provider,
          model,
          operation: STREAM_OPERATION,
          source: opts.source ?? SOURCE,
          prompt: extractParamsPrompt(params),
          response: "",
          userInput: extractParamsLastUser(params),
          latencyMs: Math.round(performance.now() - startTime),
          success: false,
          error,
          options: opts,
          compliance,
        });
        throw error;
      }

      const res = result as Record<string, unknown>;
      const stream = res?.stream as ReadableStream<unknown> | undefined;
      if (!stream || typeof stream.pipeThrough !== "function") {
        return result;
      }

      let accumulated = "";
      let firstChunkTime: number | null = null;
      let usage: {
        input?: number;
        output?: number;
        total?: number;
        shape: UsageShape;
      } = { shape: "absent" };
      // Resolved model arrives on the V2 `response-metadata` stream part.
      let modelResolved: string | undefined;

      const transformed = stream.pipeThrough(
        new TransformStream<unknown, unknown>({
          transform(chunk, controller) {
            if (firstChunkTime === null) firstChunkTime = performance.now();
            if (chunk && typeof chunk === "object") {
              const c = chunk as Record<string, unknown>;
              if (c.type === "text-delta") {
                // V1: textDelta; V2: delta
                const delta =
                  typeof c.textDelta === "string"
                    ? c.textDelta
                    : typeof c.delta === "string"
                      ? c.delta
                      : "";
                accumulated += delta;
              } else if (c.type === "finish") {
                usage = extractResultUsage({ usage: c.usage });
              } else if (c.type === "response-metadata") {
                const id = c.modelId;
                if (typeof id === "string" && id.trim().length > 0) {
                  modelResolved = id.trim();
                }
              }
            }
            controller.enqueue(chunk);
          },
          flush() {
            emitIntegrationEvent({
              config,
              provider,
              model,
              model_resolved: modelResolved,
              // AI SDK stream metadata (framework-mediated) → framework_reported.
              provenance_source: modelResolved ? "framework_reported" : undefined,
              operation: STREAM_OPERATION,
              source: opts.source ?? SOURCE,
              prompt: extractParamsPrompt(params),
              response: accumulated,
              userInput: extractParamsLastUser(params),
              inputTokens: usage.input,
              outputTokens: usage.output,
              totalTokens: usage.total,
              telemetry: usageShapeTelemetry(usage.shape),
              latencyMs: Math.round(performance.now() - startTime),
              timeToFirstTokenMs:
                firstChunkTime !== null
                  ? Math.round(firstChunkTime - startTime)
                  : undefined,
              options: opts,
              compliance,
            });
          },
        }),
      );

      return { ...res, stream: transformed };
    },
  };
}
