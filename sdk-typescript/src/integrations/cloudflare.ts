/**
 * Cloudflare Workers AI Integration
 *
 * Wraps a Workers AI binding (`env.AI`), intercepting `ai.run(model, inputs)`.
 * Prompt is extracted from `inputs.messages` (OpenAI-style) or `inputs.prompt`;
 * response text from `result.response`. When an ExecutionContext is provided,
 * audit delivery uses `ctx.waitUntil(fetch(...))` so events survive the
 * Worker's response lifecycle; otherwise the default fire-and-forget queue
 * is used. Supports pre-call block/redact.
 *
 * @example
 * ```ts
 * import { obsvr } from "@obsvr/sdk";
 * import { wrapWorkersAI } from "@obsvr/sdk/cloudflare";
 *
 * export default {
 *   async fetch(request, env, ctx) {
 *     obsvr.init({ apiKey: env.OBSVR_API_KEY, ingestUrl: env.OBSVR_URL });
 *     const ai = wrapWorkersAI(env.AI, { ctx });
 *     const out = await ai.run("@cf/meta/llama-3-8b-instruct", {
 *       messages: [{ role: "user", content: "Hello" }],
 *     });
 *     return Response.json(out);
 *   },
 * };
 * ```
 *
 * @packageDocumentation
 */

// Interception: ES Proxy (non-mutating). Original AI binding is never modified; returns a new Proxy. Double-wrap guard via WRAPPED_MARKER Symbol.

import { filterArgs } from "../proxy/filters/filter.js";
import { INGEST_PATH, API_KEY_HEADER } from "../constants.js";
import {
  applyPreCallPolicy,
  blockedCallError,
  blockedPromptForStorage,
  blockedUserInputForStorage,
  buildIntegrationEvent,
  debugLog,
  emitIntegrationEvent,
  extractAllPromptText,
  extractLastUserText,
  getConfig,
  isAsyncIterable,
  monitorModeRequiresEvidence,
  redactBuiltinPii,
  redactForStorage,
  redactRequestMessagesInPlace,
  setupExitHandlers,
  shouldSample,
  type IntegrationEventParams,
  type IntegrationOptions,
  outboundRedactionBlockedCompliance,
} from "./core.js";
import { applyOutboundRedaction } from "../policy/detector-guard.js";

const PROVIDER = "cloudflare" as const;
const OPERATION = "ai.run";
const WRAPPED_MARKER = Symbol("obsvr-cloudflare-wrapped");

/** Minimal ExecutionContext shape (avoids @cloudflare/workers-types dep) */
export interface WorkersExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
}

export interface WorkersAIOptions extends IntegrationOptions {
  /**
   * Workers ExecutionContext. When provided, audit events are delivered
   * via `ctx.waitUntil(fetch(...))` for reliability inside Workers.
   */
  ctx?: WorkersExecutionContext;
}

interface WorkersAIRunInputs {
  messages?: Array<Record<string, unknown>>;
  prompt?: string;
  stream?: boolean;
  [key: string]: unknown;
}

/**
 * Extract prompt text from Workers AI inputs (messages or prompt).
 */
function extractWorkersPrompt(inputs: WorkersAIRunInputs | undefined): string {
  if (!inputs) return "";
  if (typeof inputs.prompt === "string") return inputs.prompt;
  if (Array.isArray(inputs.messages)) {
    return inputs.messages
      .map((m) => {
        const role = typeof m.role === "string" ? m.role : "unknown";
        const content = typeof m.content === "string" ? m.content : "";
        return `${role}: ${content}`;
      })
      .join("\n");
  }
  return "";
}

function extractWorkersLastUser(inputs: WorkersAIRunInputs | undefined): string {
  if (!inputs) return "";
  if (Array.isArray(inputs.messages)) {
    return extractLastUserText(inputs);
  }
  if (typeof inputs.prompt === "string") return inputs.prompt;
  return "";
}

function redactWorkersInputsInPlace(inputs: WorkersAIRunInputs): void {
  if (typeof inputs.prompt === "string") {
    inputs.prompt = redactBuiltinPii(inputs.prompt);
  }
  redactRequestMessagesInPlace(inputs);
}

/**
 * Extract response text from a Workers AI result.
 */
function extractWorkersResponse(result: unknown): string {
  if (typeof result === "string") return result;
  if (!result || typeof result !== "object") return "";
  const r = result as Record<string, unknown>;
  if (typeof r.response === "string") return r.response;
  // Some models return { result: { response } }
  if (r.result && typeof r.result === "object") {
    const inner = r.result as Record<string, unknown>;
    if (typeof inner.response === "string") return inner.response;
  }
  return "";
}

function extractWorkersUsage(result: unknown): {
  input?: number;
  output?: number;
  total?: number;
} {
  if (!result || typeof result !== "object") return {};
  const usage = (result as Record<string, unknown>).usage as
    | Record<string, unknown>
    | undefined;
  if (!usage) return {};
  const input =
    typeof usage.prompt_tokens === "number" ? usage.prompt_tokens : undefined;
  const output =
    typeof usage.completion_tokens === "number"
      ? usage.completion_tokens
      : undefined;
  const total =
    typeof usage.total_tokens === "number"
      ? usage.total_tokens
      : input !== undefined && output !== undefined
        ? input + output
        : undefined;
  return { input, output, total };
}

/**
 * Emit an event; if a Workers ExecutionContext is available, deliver via
 * ctx.waitUntil(fetch) so delivery outlives the response. Falls back to the
 * default queue otherwise.
 */
function emitWorkersEvent(
  params: IntegrationEventParams,
  ctx: WorkersExecutionContext | undefined,
): void {
  if (!ctx) {
    emitIntegrationEvent(params);
    return;
  }
  const { config } = params;
  try {
    const event = buildIntegrationEvent(params);
    const url = `${config.ingest_url.replace(/\/$/, "")}${INGEST_PATH}`;
    ctx.waitUntil(
      fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          [API_KEY_HEADER]: config.api_key,
        },
        body: JSON.stringify(event),
      }).catch((err) => {
        debugLog(
          config,
          "error",
          "Workers AI audit delivery failed:",
          err instanceof Error ? err.message : String(err),
        );
      }),
    );
    debugLog(
      config,
      "info",
      `Audit event sent via waitUntil (cloudflare): ${event.request_id}`,
    );
  } catch (err) {
    debugLog(
      config,
      "error",
      "Failed to build Workers AI audit event:",
      err instanceof Error ? err.message : String(err),
    );
  }
}

/**
 * Wrap a Workers AI binding. Intercepts `run`; everything else passes
 * through.
 */
export function wrapWorkersAI<T extends object>(
  aiBinding: T,
  opts: WorkersAIOptions = {},
): T {
  const config = getConfig();
  if (config.disabled) return aiBinding;
  if ((aiBinding as Record<symbol, unknown>)[WRAPPED_MARKER]) return aiBinding;
  // Exit-handler flush only matters for the queue path (non-Workers runtimes)
  if (!opts.ctx) setupExitHandlers(config);

  return new Proxy(aiBinding, {
    get(target, prop: string | symbol) {
      if (prop === WRAPPED_MARKER) return true;
      if (typeof prop === "symbol") return Reflect.get(target, prop);

      const value = Reflect.get(target, prop);
      if (typeof value !== "function") return value;
      if (prop !== "run") return value.bind(target);

      return createAuditedRun(value, target, opts);
    },
    has(target, prop) {
      if (prop === WRAPPED_MARKER) return true;
      return Reflect.has(target, prop);
    },
  });
}

function createAuditedRun(
  originalRun: Function,
  target: object,
  opts: WorkersAIOptions,
): Function {
  return async function auditedRun(...args: unknown[]): Promise<unknown> {
    const config = getConfig();
    // Workers AI takes the exact model id as the first arg and echoes no
    // resolved model in the response, so there is no distinct model_resolved.
    const model = typeof args[0] === "string" ? args[0] : "unknown";
    const rawInputs = args[1];

    // Audit fields live on the inputs object (second argument)
    const { cleaned_args, audit_fields } = filterArgs(
      rawInputs !== undefined ? [rawInputs] : [],
    );
    const inputs = cleaned_args[0] as WorkersAIRunInputs | undefined;
    const callArgs = [...args];
    if (rawInputs !== undefined) callArgs[1] = inputs;

    // Sampling gates the EMISSION of clean allowed events, never enforcement.
    // Returning here skipped applyPreCallPolicy below, so a sub-1.0 sample_rate
    // silently disabled PII/policy blocking on a fraction of traffic and let the
    // raw prompt reach the provider. Carry the decision to the emit sites
    // instead, as vertex.ts and bedrock.ts already do.
    const shouldAudit = shouldSample(config.sample_rate);

    const isStreaming = inputs?.stream === true;

    const options: IntegrationOptions = {
      source: audit_fields.source || opts.source,
      region: audit_fields.region || opts.region,
      service_name: opts.service_name,
      user_id: opts.user_id,
      metadata: audit_fields.metadata ?? opts.metadata,
    };

    const userText = extractWorkersLastUser(inputs);
    const policy = await applyPreCallPolicy(userText, {
      config,
      provider: PROVIDER,
      operation: OPERATION,
      userId: options.user_id,
      serviceName: options.service_name,
      model,
      metadata: options.metadata,
    });

    if (policy.decision === "block") {
      emitWorkersEvent(
        {
          config,
          provider: PROVIDER,
          model,
          operation: OPERATION,
          source: opts.source ?? "cloudflare",
          prompt: blockedPromptForStorage(
            extractAllPromptText(inputs) || extractWorkersPrompt(inputs),
            policy.compliance,
            policy.securityNormalized,
          ),
          response: "",
          userInput: blockedUserInputForStorage(userText, policy),
          latencyMs: 0,
          success: false,
          statusCode: 403,
          requestId: audit_fields.request_id,
          metadata: audit_fields.metadata,
          options,
          canaryTelemetry: policy.canaryTelemetry,
        floorTelemetry: policy.floorTelemetry,
          compliance: policy.compliance,
        },
        opts.ctx,
      );
      throw blockedCallError(policy.compliance);
    }
    if (policy.decision === "redact") {
      // Enforcement application: a redaction that cannot be carried out blocks
      // the call rather than forwarding the content it was told to remove.
      //
      // NOT GUARDED ON `inputs` BEING TRUTHY. It used to be — `decision ===
      // "redact" && inputs` — so a falsy inputs skipped the redaction entirely
      // while `policy.compliance` still carried `action_taken: "redacted"`.
      // Whatever the scanner found the verdict on came from somewhere, and a
      // shape this redactor cannot reach is a redaction that could not be
      // applied, which is a block. Missing inputs now resolve through the same
      // fail-closed path as any other unappliable redaction rather than
      // silently reading as a completed one.
      const notRedacted = applyOutboundRedaction(() => {
        if (!inputs) {
          throw new Error(
            "redaction could not be applied: the request carried no inputs to rewrite",
          );
        }
        redactWorkersInputsInPlace(inputs);
      });
      if (notRedacted) {
        const blocked = outboundRedactionBlockedCompliance(policy.compliance, notRedacted);
        emitWorkersEvent(
          {
            config,
            provider: PROVIDER,
            model,
            operation: OPERATION,
            source: opts.source ?? "cloudflare",
            prompt: blockedPromptForStorage(
              extractAllPromptText(inputs) || extractWorkersPrompt(inputs),
              blocked,
              policy.securityNormalized,
            ),
            response: "",
            userInput: blockedUserInputForStorage(userText, policy),
            latencyMs: 0,
            success: false,
            statusCode: 403,
            requestId: audit_fields.request_id,
            metadata: audit_fields.metadata,
            options,
            canaryTelemetry: policy.canaryTelemetry,
            floorTelemetry: policy.floorTelemetry,
            compliance: blocked,
          },
          opts.ctx,
        );
        throw blockedCallError(blocked);
      }
    }

    // Enforce-mode allows are sampled. Monitor mode and anything the policy
    // acted on are complete evidence and are always recorded, as are errors.
    const monitorRequiresEvidence = monitorModeRequiresEvidence(config);
    const auditThisCall =
      monitorRequiresEvidence || shouldAudit || policy.decision !== "allow";

    // Skip mode opts out of stream evidence in enforce mode, but it must not
    // skip the pre-call boundary above. Monitor mode promises complete
    // evidence, so it continues through the normal stream event path.
    if (
      isStreaming &&
      config.streaming_mode === "skip" &&
      !monitorRequiresEvidence
    ) {
      return originalRun.apply(target, callArgs);
    }

    const startTime = performance.now();
    let result: unknown;
    try {
      result = await originalRun.apply(target, callArgs);
    } catch (error) {
      const latencyMs = Math.round(performance.now() - startTime);
      emitWorkersEvent(
        {
          config,
          provider: PROVIDER,
          model,
          operation: OPERATION,
          source: opts.source ?? "cloudflare",
          prompt: extractWorkersPrompt(inputs),
          response: "",
          userInput: extractWorkersLastUser(inputs),
          latencyMs,
          success: false,
          error,
          requestId: audit_fields.request_id,
          metadata: audit_fields.metadata,
          options,
          compliance: policy.compliance,
        },
        opts.ctx,
      );
      throw error;
    }

    // Streaming results (ReadableStream / async iterable) are returned
    // unchanged; we audit what we know (prompt) without consuming output.
    // M-3: Stream content is NOT accumulated - the response field will be
    // empty and post-response policy checks cannot evaluate the output.
    // A `streaming: true` metadata flag is added so downstream consumers
    // can distinguish incomplete audit records from non-streaming ones.
    const isStreamResult =
      isAsyncIterable(result) ||
      (typeof ReadableStream !== "undefined" &&
        result instanceof ReadableStream);

    const latencyMs = Math.round(performance.now() - startTime);
    const usage = isStreamResult ? {} : extractWorkersUsage(result);
    const eventMetadata = {
      ...audit_fields.metadata,
      ...(isStreamResult ? { streaming: true } : {}),
    };
    if (auditThisCall) emitWorkersEvent(
      {
        config,
        provider: PROVIDER,
        model,
        operation: OPERATION,
        source: opts.source ?? "cloudflare",
        prompt: extractWorkersPrompt(inputs),
        response: isStreamResult ? "" : extractWorkersResponse(result),
        userInput: extractWorkersLastUser(inputs),
        inputTokens: usage.input,
        outputTokens: usage.output,
        totalTokens: usage.total,
        latencyMs,
        requestId: audit_fields.request_id,
        metadata: eventMetadata,
        options,
        compliance: policy.compliance,
      },
      opts.ctx,
    );

    return result;
  };
}
