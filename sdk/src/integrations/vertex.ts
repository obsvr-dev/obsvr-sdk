/**
 * Google Vertex AI Integration
 *
 * Wraps a `@google-cloud/vertexai` GenerativeModel instance, intercepting
 * `generateContent` and `generateContentStream`. Vertex responses wrap the
 * Gemini payload as `{ response: GenerateContentResponse }`, so we unwrap
 * `.response` and reuse the existing google extractors. Supports pre-call
 * block/redact like the other infra integrations.
 *
 * @example
 * ```ts
 * import { VertexAI } from "@google-cloud/vertexai";
 * import { obsvr } from "@obsvr/sdk";
 * import { wrapVertexAI } from "@obsvr/sdk/vertex";
 *
 * obsvr.init({ apiKey: "..." });
 * const vertex = new VertexAI({ project: "...", location: "..." });
 * const model = wrapVertexAI(
 *   vertex.getGenerativeModel({ model: "gemini-1.5-pro" }),
 * );
 * ```
 *
 * @packageDocumentation
 */

// Interception: ES Proxy (non-mutating). Original GenerativeModel is never modified; returns a new Proxy. Double-wrap guard via WRAPPED_MARKER Symbol.

import type { AuditFields } from "../proxy/types.js";
import { filterArgs } from "../proxy/filters/filter.js";
import {
  extractPrompt,
  extractResponse,
  extractModel,
  extractTokenUsage,
} from "../proxy/extractors/google.js";
import type {
  GeminiRequest,
  GeminiResponse,
} from "../proxy/extractors/google.js";
import {
  applyPreCallPolicy,
  blockedCallError,
  blockedPromptForStorage,
  blockedUserInputForStorage,
  emitIntegrationEvent,
  extractAllPromptText,
  extractLastUserText,
  getConfig,
  redactBuiltinPii,
  redactForStorage,
  redactRequestMessagesInPlace,
  setupExitHandlers,
  shouldSample,
  type ComplianceInfo,
  type IntegrationOptions,
} from "./core.js";
import type { ResolvedConfig } from "../proxy/types.js";

const PROVIDER = "vertex_ai" as const;
const WRAPPED_MARKER = Symbol("obsvr-vertex-wrapped");

const TARGET_METHODS = new Set(["generateContent", "generateContentStream"]);

interface VertexResult {
  response?: GeminiResponse;
}

interface VertexStreamResult {
  stream?: AsyncIterable<unknown>;
  response?: Promise<GeminiResponse>;
}

function mergeOptions(
  opts: IntegrationOptions,
  auditFields: AuditFields,
): IntegrationOptions {
  return {
    source: auditFields.source || opts.source,
    region: auditFields.region || opts.region,
    service_name: auditFields.service_name || opts.service_name,
    user_id: auditFields.user_id || opts.user_id,
    metadata: auditFields.metadata ?? opts.metadata,
  };
}

/**
 * Wrap a Vertex AI GenerativeModel. Intercepts `generateContent` and
 * `generateContentStream`; everything else passes through.
 */
export function wrapVertexAI<T extends object>(
  generativeModel: T,
  opts: IntegrationOptions = {},
): T {
  const config = getConfig();
  if (config.disabled) return generativeModel;
  if ((generativeModel as Record<symbol, unknown>)[WRAPPED_MARKER]) {
    return generativeModel;
  }
  setupExitHandlers(config);

  return new Proxy(generativeModel, {
    get(target, prop: string | symbol) {
      if (prop === WRAPPED_MARKER) return true;
      if (typeof prop === "symbol") return Reflect.get(target, prop);

      const value = Reflect.get(target, prop);
      if (typeof value !== "function") return value;
      if (!TARGET_METHODS.has(prop)) return value.bind(target);

      return createAuditedMethod(value, target, prop, config, opts);
    },
    has(target, prop) {
      if (prop === WRAPPED_MARKER) return true;
      return Reflect.has(target, prop);
    },
  });
}

function modelHintOf(target: object): string | undefined {
  const m = (target as Record<string, unknown>).model;
  return typeof m === "string" ? m : undefined;
}

/**
 * Provider-RESOLVED model snapshot for temporal provenance. Gemini echoes the
 * exact serving version (e.g. `gemini-1.5-pro-002`) in `modelVersion` on the
 * aggregated response; undefined when absent (older SDKs / mocked responses).
 */
function extractResolvedModel(response: unknown): string | undefined {
  const v = (response as { modelVersion?: unknown } | undefined)?.modelVersion;
  return typeof v === "string" && v.trim().length > 0 ? v.trim() : undefined;
}

function createAuditedMethod(
  originalMethod: Function,
  target: object,
  methodName: string,
  config: ResolvedConfig,
  opts: IntegrationOptions,
): Function {
  const isStream = methodName === "generateContentStream";
  const operation = isStream
    ? "generateContentStream"
    : "generateContent";

  return async function auditedGenerate(
    ...args: unknown[]
  ): Promise<unknown> {
    const { cleaned_args, audit_fields } = filterArgs(args);

    // sampling gates ONLY audit emission (below), never enforcement — the
    // compliance boundary must run for every call.
    const shouldAudit = shouldSample(config.sample_rate);

    const request = cleaned_args[0];
    const options = mergeOptions(opts, audit_fields);
    const modelHint = modelHintOf(target);
    const model = extractModel(request as GeminiRequest, modelHint);

    const userText = extractLastUserText(request);
    const policy = await applyPreCallPolicy(userText, {
      config,
      provider: PROVIDER,
      operation,
      userId: options.user_id,
      serviceName: options.service_name,
      model,
      metadata: options.metadata,
    });

    if (policy.decision === "block") {
      emitIntegrationEvent({
        config,
        provider: PROVIDER,
        model,
        operation,
        source: options.source ?? "vertex_ai",
        prompt: blockedPromptForStorage(
          extractAllPromptText(request),
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
      });
      throw blockedCallError(policy.compliance);
    }
    if (policy.decision === "redact") {
      if (typeof request === "string") {
        cleaned_args[0] = redactBuiltinPii(request);
      } else {
        redactRequestMessagesInPlace(request);
      }
    }

    // Allowed/redacted: emit only when sampled in; redaction is always recorded.
    const auditThisCall = shouldAudit || policy.decision !== "allow";

    // streaming_mode:"skip" opts out of stream wrapping (enforcement already ran).
    if (isStream && config.streaming_mode === "skip") {
      return originalMethod.apply(target, cleaned_args);
    }

    const finalRequest = cleaned_args[0];
    const startTime = performance.now();
    let result: unknown;
    try {
      result = await originalMethod.apply(target, cleaned_args);
    } catch (error) {
      const latencyMs = Math.round(performance.now() - startTime);
      emitIntegrationEvent({
        config,
        provider: PROVIDER,
        model,
        operation,
        source: options.source ?? "vertex_ai",
        prompt: extractPrompt(finalRequest as GeminiRequest),
        response: "",
        userInput: extractLastUserText(finalRequest),
        latencyMs,
        success: false,
        error,
        requestId: audit_fields.request_id,
        metadata: audit_fields.metadata,
        options,
        compliance: policy.compliance,
      });
      throw error;
    }

    if (isStream) {
      // Vertex stream results expose `response`: a promise resolving to the
      // aggregated GenerateContentResponse once the stream completes.
      if (auditThisCall) {
        observeStreamCompletion(
          result as VertexStreamResult,
          finalRequest,
          model,
          config,
          operation,
          options,
          audit_fields,
          startTime,
          policy.compliance,
        );
      }
      return result;
    }

    if (!auditThisCall) {
      return result;
    }

    const latencyMs = Math.round(performance.now() - startTime);
    const response = (result as VertexResult)?.response;
    const resolvedModel = extractResolvedModel(response);
    emitIntegrationEvent({
      config,
      provider: PROVIDER,
      model,
      model_resolved: resolvedModel,
      // Read directly from the native Vertex response → highest trust.
      provenance_source: resolvedModel ? "provider_response" : undefined,
      operation,
      source: options.source ?? "vertex_ai",
      prompt: extractPrompt(finalRequest as GeminiRequest),
      response: extractResponse(response as GeminiResponse),
      userInput: extractLastUserText(finalRequest),
      inputTokens: extractTokenUsage(response as GeminiResponse)?.input_tokens,
      outputTokens: extractTokenUsage(response as GeminiResponse)
        ?.output_tokens,
      totalTokens: extractTokenUsage(response as GeminiResponse)?.total_tokens,
      latencyMs,
      requestId: audit_fields.request_id,
      metadata: audit_fields.metadata,
      options,
      compliance: policy.compliance,
    });

    return result;
  };
}

/**
 * Audit a streaming call by awaiting the aggregated `.response` promise.
 * Never throws - stream consumption errors surface to the caller, not here.
 */
function observeStreamCompletion(
  result: VertexStreamResult,
  request: unknown,
  model: string,
  config: ResolvedConfig,
  operation: string,
  options: IntegrationOptions,
  auditFields: AuditFields,
  startTime: number,
  compliance: ComplianceInfo,
): void {
  const responsePromise = result?.response;
  if (!responsePromise || typeof responsePromise.then !== "function") return;

  responsePromise.then(
    (response) => {
      const latencyMs = Math.round(performance.now() - startTime);
      const resolvedModel = extractResolvedModel(response);
      emitIntegrationEvent({
        config,
        provider: PROVIDER,
        model,
        model_resolved: resolvedModel,
        provenance_source: resolvedModel ? "provider_response" : undefined,
        operation,
        source: options.source ?? "vertex_ai",
        prompt: extractPrompt(request as GeminiRequest),
        response: extractResponse(response as GeminiResponse),
        userInput: extractLastUserText(request),
        inputTokens: extractTokenUsage(response as GeminiResponse)
          ?.input_tokens,
        outputTokens: extractTokenUsage(response as GeminiResponse)
          ?.output_tokens,
        totalTokens: extractTokenUsage(response as GeminiResponse)
          ?.total_tokens,
        latencyMs,
        requestId: auditFields.request_id,
        metadata: auditFields.metadata,
        options,
        compliance,
      });
    },
    (error: unknown) => {
      const latencyMs = Math.round(performance.now() - startTime);
      emitIntegrationEvent({
        config,
        provider: PROVIDER,
        model,
        operation,
        source: options.source ?? "vertex_ai",
        prompt: extractPrompt(request as GeminiRequest),
        response: "",
        userInput: extractLastUserText(request),
        latencyMs,
        success: false,
        error,
        requestId: auditFields.request_id,
        metadata: auditFields.metadata,
        options,
        compliance,
      });
    },
  );
}
