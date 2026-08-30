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
  assertRedactionApplied,
  extractLastUserText,
  getConfig,
  monitorModeRequiresEvidence,
  redactBuiltinPii,
  redactForStorage,
  setupExitHandlers,
  shouldSample,
  type ComplianceInfo,
  type IntegrationOptions,
  outboundRedactionBlockedCompliance,
} from "./core.js";
import { applyOutboundRedaction } from "../policy/detector-guard.js";
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

function extractCompletePrompt(request: GeminiRequest, target: object): string {
  const configuredSystem = (target as Record<string, unknown>).systemInstruction;
  const parts: string[] = [];
  if (configuredSystem !== undefined) {
    const systemPrompt = extractPrompt({
      contents: [],
      systemInstruction: configuredSystem,
    } as GeminiRequest);
    if (systemPrompt) parts.push(systemPrompt);
  }
  const requestPrompt = extractPrompt(request);
  if (requestPrompt) parts.push(requestPrompt);
  return parts.join("\n");
}

function redactVertexContent(value: unknown): unknown {
  if (typeof value === "string") return redactBuiltinPii(value);
  if (Array.isArray(value)) return value.map(redactVertexContent);
  if (!value || typeof value !== "object") return value;
  const item = value as Record<string, unknown>;
  if (typeof item.text === "string") {
    return { ...item, text: redactBuiltinPii(item.text) };
  }
  if (Array.isArray(item.parts)) {
    return { ...item, parts: item.parts.map(redactVertexContent) };
  }
  return value;
}

function redactVertexRequest(request: GeminiRequest): GeminiRequest {
  if (typeof request === "string") return redactBuiltinPii(request);
  const out: Record<string, unknown> = { ...request };
  out.contents = redactVertexContent(request.contents);
  if ("systemInstruction" in request) {
    out.systemInstruction = redactVertexContent(request.systemInstruction);
  }
  if (request.config && typeof request.config === "object") {
    const config = request.config as Record<string, unknown>;
    out.config = "systemInstruction" in config
      ? {
          ...config,
          systemInstruction: redactVertexContent(config.systemInstruction),
        }
      : config;
  }
  return out as unknown as GeminiRequest;
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

    const promptText = extractCompletePrompt(request as GeminiRequest, target);
    const policy = await applyPreCallPolicy(promptText, {
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
          promptText,
          policy.compliance,
          policy.securityNormalized,
        ),
        response: "",
        userInput: blockedUserInputForStorage(promptText, policy),
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
      // Enforcement application: a redaction that cannot be carried out blocks
      // the call rather than forwarding the content it was told to remove.
      const notRedacted = applyOutboundRedaction(() => {
        cleaned_args[0] = redactVertexRequest(request as GeminiRequest);
        assertRedactionApplied(
          extractCompletePrompt(cleaned_args[0] as GeminiRequest, target),
          policy.compliance,
        );
      });
      if (notRedacted) {
        const blocked = outboundRedactionBlockedCompliance(policy.compliance, notRedacted);
        emitIntegrationEvent({
          config,
          provider: PROVIDER,
          model,
          operation,
          source: options.source ?? "vertex_ai",
          prompt: blockedPromptForStorage(
            promptText,
            blocked,
            policy.securityNormalized,
          ),
          response: "",
          userInput: blockedUserInputForStorage(promptText, policy),
          latencyMs: 0,
          success: false,
          statusCode: 403,
          requestId: audit_fields.request_id,
          metadata: audit_fields.metadata,
          options,
          canaryTelemetry: policy.canaryTelemetry,
          floorTelemetry: policy.floorTelemetry,
          compliance: blocked,
        });
        throw blockedCallError(blocked);
      }
    }

    // Enforce-mode allows are sampled. Monitor mode, redaction, and other policy
    // action are complete evidence and are always recorded.
    const auditThisCall =
      monitorModeRequiresEvidence(config) || shouldAudit || policy.decision !== "allow";

    // Enforce-mode skip opts out of stream observation only. Monitor mode is a
    // complete evidence stream and therefore follows the normal observation
    // path even when skip was configured.
    if (
      isStream &&
      config.streaming_mode === "skip" &&
      !monitorModeRequiresEvidence(config)
    ) {
      return originalMethod.apply(target, cleaned_args);
    }

    const finalRequest = cleaned_args[0];
    const finalPromptText = extractCompletePrompt(finalRequest as GeminiRequest, target);
    const finalUserText = extractLastUserText(finalRequest);
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
        prompt: finalPromptText,
        response: "",
        userInput: finalUserText,
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
          finalPromptText,
          finalUserText,
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
      prompt: finalPromptText,
      response: extractResponse(response as GeminiResponse),
      userInput: finalUserText,
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
  promptText: string,
  userText: string,
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
        prompt: promptText,
        response: extractResponse(response as GeminiResponse),
        userInput: userText,
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
        prompt: promptText,
        response: "",
        userInput: userText,
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
