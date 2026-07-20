/**
 * OpenAI-Compatible Client Wrapper
 *
 * Minimal Proxy that intercepts `chat.completions.create` on any
 * OpenAI-compatible client (Azure OpenAI, Together AI, etc.) and audits
 * calls with a custom provider/source label. Reuses the existing OpenAI
 * chat extractors. Supports pre-call block/redact and streaming via
 * chunk accumulation.
 *
 * @packageDocumentation
 */

// Interception: ES Proxy (non-mutating). Original client is never modified; returns a new Proxy. Double-wrap guard via WRAPPED_MARKER Symbol.

import type { AuditFields } from "../proxy/types.js";
import { filterArgs } from "../proxy/filters/filter.js";
import {
  extractPrompt,
  extractResponse,
  extractModel,
  extractResolvedModel,
  extractTokenUsage,
  accumulateOpenAIStream,
} from "../proxy/extractors/openai-chat.js";
import type {
  OpenAIChatRequest,
  OpenAIChatResponse,
} from "../proxy/extractors/types.js";
import {
  applyPreCallPolicy,
  blockedCallError,
  blockedPromptForStorage,
  blockedUserInputForStorage,
  emitIntegrationEvent,
  extractAllPromptText,
  extractLastUserText,
  getConfig,
  isAsyncIterable,
  redactForStorage,
  redactRequestMessagesInPlace,
  setupExitHandlers,
  shouldSample,
  type ComplianceInfo,
  type IntegrationOptions,
  type IntegrationProvider,
} from "./core.js";
import type { ResolvedConfig } from "../proxy/types.js";

const TARGET_PATH = ["chat", "completions", "create"];
const OPERATION = "chat.completions.create";
const WRAPPED_MARKER = Symbol("obsvr-integration-wrapped");

export interface OpenAICompatConfig extends IntegrationOptions {
  provider: IntegrationProvider;
  source: string;
}

/**
 * Merge per-request audit fields over per-wrap options.
 */
function mergeOptions(
  opts: OpenAICompatConfig,
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
 * Wrap an OpenAI-compatible client. Intercepts only
 * `chat.completions.create`; everything else passes through.
 */
export function wrapOpenAICompatible<T extends object>(
  client: T,
  opts: OpenAICompatConfig,
): T {
  const config = getConfig();
  if (config.disabled) return client;
  if ((client as Record<symbol, unknown>)[WRAPPED_MARKER]) return client;
  setupExitHandlers(config);
  return proxyPath(client, [], config, opts);
}

function proxyPath<T extends object>(
  target: T,
  path: string[],
  config: ResolvedConfig,
  opts: OpenAICompatConfig,
): T {
  return new Proxy(target, {
    get(obj, prop: string | symbol) {
      if (prop === WRAPPED_MARKER) return true;
      if (typeof prop === "symbol") return Reflect.get(obj, prop);

      const value = Reflect.get(obj, prop);
      if (value === undefined || value === null) return value;

      const newPath = [...path, prop];
      const onTargetPath =
        TARGET_PATH.slice(0, newPath.length).join(".") === newPath.join(".");

      if (typeof value === "function") {
        if (onTargetPath && newPath.length === TARGET_PATH.length) {
          return createAuditedCreate(value, obj, config, opts);
        }
        return value.bind(obj);
      }

      if (typeof value === "object" && onTargetPath) {
        return proxyPath(value as object, newPath, config, opts);
      }

      return value;
    },
    has(obj, prop) {
      if (prop === WRAPPED_MARKER) return true;
      return Reflect.has(obj, prop);
    },
  });
}

function createAuditedCreate(
  originalMethod: Function,
  target: object,
  config: ResolvedConfig,
  opts: OpenAICompatConfig,
): Function {
  return async function auditedCreate(...args: unknown[]): Promise<unknown> {
    // Always strip audit fields, even when not sampling
    const { cleaned_args, audit_fields } = filterArgs(args);

    if (!shouldSample(config.sample_rate)) {
      return originalMethod.apply(target, cleaned_args);
    }

    const request = cleaned_args[0] as Record<string, unknown> | undefined;
    const isStreaming = request?.stream === true;
    if (isStreaming && config.streaming_mode === "skip") {
      return originalMethod.apply(target, cleaned_args);
    }

    const options = mergeOptions(opts, audit_fields);
    const userText = extractLastUserText(request);
    const policy = await applyPreCallPolicy(userText, {
      config,
      provider: opts.provider,
      operation: OPERATION,
      userId: options.user_id,
      serviceName: options.service_name,
      model: extractModel(request as OpenAIChatRequest),
      metadata: options.metadata,
    });

    if (policy.decision === "block") {
      emitIntegrationEvent({
        config,
        provider: opts.provider,
        model: extractModel(request as OpenAIChatRequest),
        operation: OPERATION,
        source: opts.source,
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
      redactRequestMessagesInPlace(request);
    }

    const startTime = performance.now();
    let response: unknown;
    try {
      response = await originalMethod.apply(target, cleaned_args);
    } catch (error) {
      const latencyMs = Math.round(performance.now() - startTime);
      emitIntegrationEvent({
        config,
        provider: opts.provider,
        model: extractModel(request as OpenAIChatRequest),
        operation: OPERATION,
        source: opts.source,
        prompt: extractPrompt(request as OpenAIChatRequest),
        response: "",
        userInput: extractLastUserText(request),
        latencyMs,
        success: false,
        statusCode:
          (error as { status?: number })?.status ??
          (error as { statusCode?: number })?.statusCode ??
          500,
        error,
        requestId: audit_fields.request_id,
        metadata: audit_fields.metadata,
        options,
        compliance: policy.compliance,
      });
      throw error;
    }

    if (isAsyncIterable(response)) {
      return wrapOpenAICompatStream(
        response,
        request,
        config,
        opts,
        options,
        audit_fields,
        startTime,
        policy.compliance,
      );
    }

    const latencyMs = Math.round(performance.now() - startTime);
    const resolvedModel = extractResolvedModel(response as OpenAIChatResponse);
    emitIntegrationEvent({
      config,
      provider: opts.provider,
      model: extractModel(request as OpenAIChatRequest),
      model_resolved: resolvedModel,
      // Read directly from the native OpenAI-compatible response → highest trust.
      // (Azure/Together delegate here, so they inherit provider_response too.)
      provenance_source: resolvedModel ? "provider_response" : undefined,
      operation: OPERATION,
      source: opts.source,
      prompt: extractPrompt(request as OpenAIChatRequest),
      response: extractResponse(response as OpenAIChatResponse),
      userInput: extractLastUserText(request),
      inputTokens: extractTokenUsage(response as OpenAIChatResponse)
        ?.input_tokens,
      outputTokens: extractTokenUsage(response as OpenAIChatResponse)
        ?.output_tokens,
      totalTokens: extractTokenUsage(response as OpenAIChatResponse)
        ?.total_tokens,
      latencyMs,
      requestId: audit_fields.request_id,
      metadata: audit_fields.metadata,
      options,
      compliance: policy.compliance,
    });

    return response;
  };
}

/**
 * Wrap a streaming response, yielding chunks unchanged while accumulating
 * content. Fires a single audit event when the stream ends.
 */
function wrapOpenAICompatStream(
  iter: AsyncIterable<unknown>,
  request: unknown,
  config: ResolvedConfig,
  opts: OpenAICompatConfig,
  options: IntegrationOptions,
  auditFields: AuditFields,
  startTime: number,
  compliance: ComplianceInfo,
): AsyncGenerator<unknown, void, unknown> {
  return (async function* () {
    const chunks: unknown[] = [];
    let streamError: unknown = null;
    let firstChunkTime: number | null = null;
    try {
      for await (const chunk of iter) {
        if (firstChunkTime === null) firstChunkTime = performance.now();
        chunks.push(chunk);
        yield chunk;
      }
    } catch (err) {
      streamError = err;
      throw err;
    } finally {
      const latencyMs = Math.round(performance.now() - startTime);
      const acc = accumulateOpenAIStream(chunks);
      emitIntegrationEvent({
        config,
        provider: opts.provider,
        model:
          acc.model !== "unknown"
            ? acc.model
            : extractModel(request as OpenAIChatRequest),
        model_resolved: acc.model !== "unknown" ? acc.model : undefined,
        // Native provider stream snapshot → highest trust (present iff model_resolved).
        provenance_source: acc.model !== "unknown" ? "provider_response" : undefined,
        operation: OPERATION,
        source: opts.source,
        prompt: extractPrompt(request as OpenAIChatRequest),
        response: acc.text,
        userInput: extractLastUserText(request),
        inputTokens: acc.usage?.input_tokens,
        outputTokens: acc.usage?.output_tokens,
        totalTokens: acc.usage?.total_tokens,
        latencyMs,
        timeToFirstTokenMs:
          firstChunkTime !== null
            ? Math.round(firstChunkTime - startTime)
            : undefined,
        success: streamError === null,
        statusCode:
          streamError === null
            ? 200
            : ((streamError as { status?: number })?.status ??
              (streamError as { statusCode?: number })?.statusCode ??
              500),
        error: streamError ?? undefined,
        requestId: auditFields.request_id,
        metadata: auditFields.metadata,
        options,
        compliance,
      });
    }
  })();
}
