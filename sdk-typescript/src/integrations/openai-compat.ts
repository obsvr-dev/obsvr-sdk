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
  outboundRedactionBlockedCompliance,
  setupExitHandlers,
  shouldSample,
  type ComplianceInfo,
  type IntegrationOptions,
  type IntegrationProvider,
} from "./core.js";
import type { ResolvedConfig } from "../proxy/types.js";
import { applyOutboundRedaction } from "../policy/detector-guard.js";

const TARGET_PATH = ["chat", "completions", "create"];
const OPERATION = "chat.completions.create";
const WRAPPED_MARKER = Symbol("obsvr-integration-wrapped");

export interface OpenAICompatConfig extends IntegrationOptions {
  /**
   * Fallback label, used ONLY when the client exposes no readable base URL.
   * The recorded provider is derived from the endpoint the call actually goes
   * to whenever that can be read — see `resolveDestination`.
   */
  provider: IntegrationProvider;
  source: string;
}

/** Internal: `OpenAICompatConfig` plus the attribution decided at wrap time. */
interface ResolvedCompatConfig extends OpenAICompatConfig {
  /** Reserved metadata describing WHERE the call goes and how sure we are. */
  attribution: Record<string, unknown>;
}

/**
 * Hosts whose identity we can state, and what to call them.
 *
 * `provider` is constrained to the ingest canonical enum. A destination the
 * enum cannot express records `provider: "unknown"` and keeps its real identity
 * in `provider_detail` — the same carriage MCP already uses, rather than
 * widening a union the backend would reject.
 */
const KNOWN_ENDPOINTS: Array<{
  pattern: RegExp;
  provider: IntegrationProvider;
  detail: string;
}> = [
  { pattern: /(^|\.)together\.(xyz|ai)$/i, provider: "together", detail: "together" },
  { pattern: /(^|\.)openai\.azure\.com$/i, provider: "azure_openai", detail: "azure_openai" },
  { pattern: /(^|\.)openai\.com$/i, provider: "openai", detail: "openai" },
  { pattern: /(^|\.)anthropic\.com$/i, provider: "anthropic", detail: "anthropic" },
  { pattern: /(^|\.)googleapis\.com$/i, provider: "google", detail: "google" },
  { pattern: /(^|\.)cloudflare\.com$/i, provider: "cloudflare", detail: "cloudflare" },
  // Real destinations the canonical enum has no member for.
  { pattern: /(^|\.)groq\.com$/i, provider: "unknown", detail: "groq" },
  { pattern: /(^|\.)mistral\.ai$/i, provider: "unknown", detail: "mistral" },
  { pattern: /(^|\.)fireworks\.ai$/i, provider: "unknown", detail: "fireworks" },
  { pattern: /(^|\.)perplexity\.ai$/i, provider: "unknown", detail: "perplexity" },
  { pattern: /(^|\.)deepseek\.com$/i, provider: "unknown", detail: "deepseek" },
];

/** A local server is a destination too, and a materially different one. */
const LOCAL_HOSTS = /^(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0|host\.docker\.internal)$/i;

/**
 * The client's configured base URL, if it will tell us.
 *
 * Read defensively: this runs against any OpenAI-shaped client, a getter may
 * throw, and a wrapper that crashed while working out what to call something
 * would be a worse failure than a vague label.
 */
function readBaseUrl(client: unknown): string | undefined {
  for (const key of ["baseURL", "baseUrl", "base_url"]) {
    try {
      const value = (client as Record<string, unknown>)?.[key];
      if (typeof value === "string" && value.length > 0) return value;
    } catch {
      /* a throwing getter is a non-answer, not a failure */
    }
  }
  return undefined;
}

/**
 * Host and port only — never credentials, path or query.
 *
 * A base URL is a place users put secrets (`https://user:token@host/v1`), and
 * this value goes into an audit record that gets shipped and stored. Only the
 * destination is wanted here, and only the destination is taken.
 */
function safeHost(baseUrl: string): { host?: string; hostname?: string } {
  try {
    const url = new URL(baseUrl);
    return { host: url.host, hostname: url.hostname };
  } catch {
    return {};
  }
}

/**
 * Decide what to record about where this call is going.
 *
 * THE DEFECT THIS REPLACES. `wrapTogether` stamped `provider: "together"` on
 * every call regardless of endpoint. Demonstrated with one wrapper: pointed at
 * Groq's API it recorded "together", and pointed at a localhost server it also
 * recorded "together" — a local model logged as served by a US cloud vendor.
 * That is a lie about a destination, in the field a compliance reviewer reads
 * for data residency, and no event field anywhere derived from the real host.
 *
 * So the provider is now taken from the endpoint whenever the endpoint can be
 * read, and the caller's label is a fallback rather than an assertion. Where we
 * can see the host but cannot name it, `unknown` is recorded: vague is a
 * lesser fault than wrong.
 *
 * `provider_attribution` states which of those happened, borrowing the trust
 * vocabulary `provenance_source` already uses for `model_resolved`, so a reader
 * can tell a checked value from a declared one.
 */
function resolveDestination(
  client: unknown,
  declared: IntegrationProvider,
): { provider: IntegrationProvider; attribution: Record<string, unknown> } {
  const baseUrl = readBaseUrl(client);
  if (!baseUrl) {
    // Nothing to check against. The declared label is all there is, and the
    // record says so rather than presenting it as verified.
    return {
      provider: declared,
      attribution: { provider_attribution: "client_declared" },
    };
  }

  const { host, hostname } = safeHost(baseUrl);
  if (!hostname) {
    return {
      provider: declared,
      attribution: { provider_attribution: "client_declared" },
    };
  }

  if (LOCAL_HOSTS.test(hostname)) {
    return {
      provider: "unknown",
      attribution: {
        provider_attribution: "endpoint",
        provider_detail: "local",
        endpoint_host: host,
      },
    };
  }

  const match = KNOWN_ENDPOINTS.find((entry) => entry.pattern.test(hostname));
  if (match) {
    return {
      provider: match.provider,
      attribution: {
        provider_attribution: "endpoint",
        provider_detail: match.detail,
        endpoint_host: host,
      },
    };
  }

  // A host we have no name for — a private gateway, a proxy, a new vendor.
  // Recording the caller's guess here is what produced the original defect.
  return {
    provider: "unknown",
    attribution: {
      provider_attribution: "endpoint",
      provider_detail: "unrecognized_endpoint",
      endpoint_host: host,
    },
  };
}

/**
 * Merge per-request audit fields over per-wrap options.
 *
 * Attribution is applied LAST and deliberately wins. It describes where the
 * call went, which is not a caller-supplied opinion; letting per-request
 * metadata shadow it would drop the destination evidence exactly when a caller
 * attaches metadata of their own.
 */
function mergeOptions(
  opts: ResolvedCompatConfig,
  auditFields: AuditFields,
): IntegrationOptions {
  const caller = auditFields.metadata ?? opts.metadata;
  return {
    source: auditFields.source || opts.source,
    region: auditFields.region || opts.region,
    service_name: auditFields.service_name || opts.service_name,
    user_id: auditFields.user_id || opts.user_id,
    metadata: { ...(caller ?? {}), ...opts.attribution },
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
  // Resolved ONCE, at wrap time: the base URL is fixed when the client is
  // constructed, so re-deriving it per call would buy nothing and cost a URL
  // parse on the hot path.
  const { provider, attribution } = resolveDestination(client, opts.provider);
  return proxyPath(client, [], config, { ...opts, provider, attribution });
}

function proxyPath<T extends object>(
  target: T,
  path: string[],
  config: ResolvedConfig,
  opts: ResolvedCompatConfig,
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
  opts: ResolvedCompatConfig,
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
      // Enforcement application: a redaction that cannot be carried out blocks
      // the call rather than forwarding the content it was told to remove.
      const notRedacted = applyOutboundRedaction(() => {
        redactRequestMessagesInPlace(request);
      });
      if (notRedacted) {
        const blocked = outboundRedactionBlockedCompliance(policy.compliance, notRedacted);
        emitIntegrationEvent({
          config,
          provider: opts.provider,
          model: extractModel(request as OpenAIChatRequest),
          operation: OPERATION,
          source: opts.source,
          prompt: blockedPromptForStorage(
            extractAllPromptText(request),
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
        });
        throw blockedCallError(blocked);
      }
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
  opts: ResolvedCompatConfig,
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
