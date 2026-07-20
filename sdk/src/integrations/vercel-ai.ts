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
  blockedCallError,
  blockedPromptForStorage,
  blockedUserInputForStorage,
  emitIntegrationEvent,
  getConfig,
  inferProviderFromString,
  redactBuiltinPii,
  redactForStorage,
  setupExitHandlers,
  shouldSample,
  type ComplianceInfo,
  type IntegrationOptions,
  type IntegrationProvider,
  DEFAULT_COMPLIANCE,
} from "./core.js";

const SOURCE = "vercel_ai";
const OPERATION = "generate";
const STREAM_OPERATION = "stream";

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
  sampled: boolean;
}

const callState = new WeakMap<object, CallState>();

// ---------------------------------------------------------------------------
// Prompt helpers (LanguageModelV1/V2 prompt: string | message array)
// ---------------------------------------------------------------------------

function partText(part: unknown): string {
  if (typeof part === "string") return part;
  if (part && typeof part === "object") {
    const p = part as Record<string, unknown>;
    if (typeof p.text === "string") return p.text;
  }
  return "";
}

function promptMessages(params: unknown): Record<string, unknown>[] {
  if (!params || typeof params !== "object") return [];
  const prompt = (params as Record<string, unknown>).prompt;
  if (Array.isArray(prompt)) return prompt as Record<string, unknown>[];
  return [];
}

function extractParamsPrompt(params: unknown): string {
  if (!params || typeof params !== "object") return "";
  const prompt = (params as Record<string, unknown>).prompt;
  if (typeof prompt === "string") return prompt;
  if (!Array.isArray(prompt)) return "";
  return (prompt as Record<string, unknown>[])
    .map((msg) => {
      const role = typeof msg.role === "string" ? msg.role : "unknown";
      const content = msg.content;
      const text =
        typeof content === "string"
          ? content
          : Array.isArray(content)
            ? content.map(partText).filter((t) => t.length > 0).join(" ")
            : "";
      return `${role}: ${text}`;
    })
    .join("\n");
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
      const content = messages[i].content;
      if (typeof content === "string") return content;
      if (Array.isArray(content)) {
        return content.map(partText).filter((t) => t.length > 0).join(" ");
      }
    }
  }
  return extractParamsPrompt(params);
}

function redactParamsInPlace(params: Record<string, unknown>): void {
  if (typeof params.prompt === "string") {
    params.prompt = redactBuiltinPii(params.prompt);
    return;
  }
  if (typeof params.system === "string") {
    params.system = redactBuiltinPii(params.system);
  }
  for (const msg of promptMessages(params)) {
    if (typeof msg.content === "string") {
      msg.content = redactBuiltinPii(msg.content);
    } else if (Array.isArray(msg.content)) {
      for (const part of msg.content as Record<string, unknown>[]) {
        if (typeof part.text === "string") {
          part.text = redactBuiltinPii(part.text);
        }
      }
    }
  }
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

function extractResultUsage(result: unknown): {
  input?: number;
  output?: number;
  total?: number;
} {
  if (!result || typeof result !== "object") return {};
  const usage = (result as Record<string, unknown>).usage as
    | Record<string, unknown>
    | undefined;
  if (!usage) return {};
  const num = (v: unknown): number | undefined =>
    typeof v === "number" && Number.isFinite(v) ? v : undefined;
  const input = num(usage.inputTokens) ?? num(usage.promptTokens);
  const output = num(usage.outputTokens) ?? num(usage.completionTokens);
  const total =
    num(usage.totalTokens) ??
    (input !== undefined && output !== undefined ? input + output : undefined);
  return { input, output, total };
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

      const sampled = shouldSample(config.sample_rate);
      if (!sampled) {
        callState.set(params, { compliance: DEFAULT_COMPLIANCE, sampled });
        return params;
      }

      const { model, provider } = modelInfo(args.model);
      const userText = extractParamsLastUser(params);
      const policy = await applyPreCallPolicy(userText, {
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
            extractParamsPrompt(params),
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
      if (policy.decision === "redact") {
        redactParamsInPlace(params);
      }

      callState.set(params, { compliance: policy.compliance, sampled });
      return params;
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
      if (state && !state.sampled) return doGenerate();
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
      if (state && !state.sampled) return doStream();
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
      let usage: { input?: number; output?: number; total?: number } = {};
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
