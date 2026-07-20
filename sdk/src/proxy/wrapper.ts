/**
 * Core Proxy Wrapper
 *
 * Implements a recursive JavaScript Proxy that intercepts LLM client
 * method calls for automatic audit tracking.
 *
 * @packageDocumentation
 */

import type {
  AuditEvent,
  AuditFields,
  ResolvedConfig,
  WrapOptions,
} from "./types.js";
import type { OpenAIChatRequest } from "./extractors/types.js";
import { getConfig, isWrapped, markWrapped, isPolicyEnforcementDegraded } from "./config.js";
import { evaluatePolicyHook, redactBuiltinPii, resolvePiiPolicy, runBuiltinPiiScan } from "../policy/hook.js";
import {
  runConfiguredPiiScan,
  escalateViewOnlyAction,
  redactForStorage,
} from "../policy/deobfuscate.js";
import type { DeobfuscationView } from "../policy/deobfuscate.js";
import {
  scanForCanary,
  canaryRegistrySize,
  canaryLeakTelemetry,
  CANARY_REDACTION_PLACEHOLDER,
} from "../policy/canary.js";
import {
  resolveSessionTaint,
  deriveSessionKey,
  evaluateSessionTaint,
  markTainted,
  touchTaint,
  sessionTaintSize,
} from "../policy/session-taint.js";
import { getCurrentSubject } from "./subject.js";
import { presidioScan, presidioRedactText, presidioRedactArgs } from "../policy/presidio.js";
import { evaluatePolicyRules, derivePolicyVersion, evaluateShadowRules, evaluateFloor, deriveFloorVersion } from "../policy/rules.js";
import {
  ENGINE_VERSION,
  buildDecisionInput,
  computeDecisionInputHash,
  sha256Hex,
} from "../policy/decision-record.js";
import type { HookDisposition } from "../policy/decision-record.js";
import {
  buildBackendInput,
  runExternalBackendStep,
} from "../policy/external-backend.js";
import type { ExternalBackendRecord } from "../policy/external-backend.js";
import { scoreTurn } from "../policy/injection-session.js";
import { requestApproval } from "../policy/approvals.js";
import { recordTokenUsage } from "../governance/quota.js";
import type { PolicyEvalContext } from "../policy/rules.js";
import { filterArgs } from "./filters/filter.js";
import {
  extractPrompt as extractOpenAIPrompt,
  extractResponse as extractOpenAIResponse,
  extractModel as extractOpenAIModel,
  extractTokenUsage as extractOpenAITokenUsage,
  accumulateOpenAIStream,
} from "./extractors/openai-chat.js";
import {
  extractPrompt as extractResponsesPrompt,
  extractResponse as extractResponsesText,
  extractModel as extractResponsesModel,
  extractTokenUsage as extractResponsesTokenUsage,
  accumulateResponsesStream,
} from "./extractors/openai-responses.js";
import type {
  OpenAIResponsesRequest,
  OpenAIResponsesResponse,
} from "./extractors/openai-responses.js";
import { extractCallTelemetry, withTelemetryMetadata } from "./extractors/telemetry.js";
import { applyPostCallPolicy, mergePostCallOutcome } from "../integrations/core.js";
import { spanEnvelopeFor, withSpanMetadata } from "./span.js";
import { withRunMetadata } from "./agent-run.js";
import {
  extractPrompt as extractAnthropicPrompt,
  extractResponse as extractAnthropicResponse,
  extractModel as extractAnthropicModel,
  extractTokenUsage as extractAnthropicTokenUsage,
  extractStreamingResponse,
} from "./extractors/anthropic.js";
import type {
  AnthropicMessagesRequest,
  AnthropicMessagesResponse,
  AnthropicStreamEvent,
} from "./extractors/anthropic.js";
import {
  extractPrompt as extractGeminiPrompt,
  extractResponse as extractGeminiResponse,
  extractModel as extractGeminiModel,
  extractTokenUsage as extractGeminiTokenUsage,
  unwrapGeminiResponse,
} from "./extractors/google.js";
import type { GeminiRequest, GeminiResponse } from "./extractors/google.js";
import {
  sendAuditAsync,
  shouldSample,
  setupExitHandlers,
} from "./sender/index.js";
import { truncate } from "../utils/truncate.js";
import { debugLog } from "../utils/logger.js";
import { generateUUID } from "../client.js";

/**
 * Compliance context captured at the pre-LLM boundary.
 * A single value of this type is built once per call and stamped on every
 * audit event emitted (allowed, redacted, blocked, or streaming completion).
 */
type ComplianceCtx = {
  eventType: "llm_call" | "blocked_call";
  policyVersion: string;
  actionTaken: "allowed" | "blocked" | "redacted";
  actionReason: "pii_detected" | "policy_violation" | "customer_override" | "none";
  actionSource: "builtin" | "builtin+presidio" | "customer_hook" | "policy_rules" | "external_backend" | "unknown";
  redactedTypes: string[];
  blockedTypes: string[];
  ruleId?: string;
  policyReason?: string;
  /** What the shadow rules would have done (EV-21); never affects the decision. */
  shadowOutcome?: { rule_id: string; would: "block" | "redact" | "flag"; reason: string } | null;
  /** SHA-256 of the canonical decision-input document (ADR-2); additive. */
  decisionInputHash?: string;
  /** Rules-engine semantics version ("obsvr-rules/<N>"); additive. */
  engineVersion?: string;
  /** Inbound external policy backend provenance (ADR-4); additive. */
  externalBackend?: ExternalBackendRecord;
};

/** Default compliance context - used for all pre-compliance code paths */
const DEFAULT_COMPLIANCE: ComplianceCtx = {
  eventType: "llm_call",
  policyVersion: "v1",
  actionTaken: "allowed",
  actionReason: "none",
  actionSource: "unknown",
  redactedTypes: [],
  blockedTypes: [],
};

/**
 * Methods that should be audited with their nested paths
 * Format: "namespace.method"
 *
 * COVERAGE BOUNDARY: wrap() governs TEXT-generation surfaces only. Other
 * client methods (embeddings.create, images.generate, audio.*, files.*,
 * fine_tuning.*, ...) pass through UNGOVERNED and UNAUDITED — they carry no
 * chat-shaped prompt/response text for the policy engine to evaluate. This
 * is a deliberate, documented boundary: do not assume wrap() covers them.
 */
const AUDITABLE_METHODS = new Set([
  "chat.completions.create", // OpenAI / Azure OpenAI
  "messages.create", // Anthropic
  "generateContent", // Google Gemini
  "responses.create", // OpenAI Responses API
]);

/**
 * Symbol to mark wrapped objects
 */
const WRAPPED_MARKER = Symbol("obsvr-wrapped");

/**
 * Track the current method path during proxy traversal
 */
type PathContext = {
  path: string[];
  options: WrapOptions;
  config: ResolvedConfig;
  provider: "openai" | "anthropic" | "google" | "unknown";
};

/**
 * Check if an object is an AsyncIterable (stream)
 */
function isAsyncIterable(obj: unknown): obj is AsyncIterable<unknown> {
  return obj !== null && typeof obj === "object" && Symbol.asyncIterator in obj;
}

/**
 * Detect the provider type from a client instance (V2: includes google)
 */
function detectProvider(
  client: unknown,
): "openai" | "anthropic" | "google" | "unknown" {
  if (!client || typeof client !== "object") {
    return "unknown";
  }

  const c = client as Record<string, unknown>;

  // Duck-type by the actual method path each SDK exposes. This is robust to
  // minified class names and to hand-rolled/proxy clients, and matches the
  // AUDITABLE_METHODS the proxy intercepts.
  const chat = c.chat as Record<string, unknown> | undefined;
  const completions = chat?.completions as Record<string, unknown> | undefined;
  if (typeof completions?.create === "function") {
    return "openai";
  }

  // OpenAI Responses API: responses.create (present alongside chat on the
  // real client; matched here too so trimmed clients still resolve).
  const responses = c.responses as Record<string, unknown> | undefined;
  if (typeof responses?.create === "function") {
    return "openai";
  }

  // Google Gemini: generateContent lives directly on the GenerativeModel.
  if (typeof c.generateContent === "function") {
    return "google";
  }

  // Anthropic: messages.create (also matches other messages.create shapes, but
  // those are wrapped through dedicated modules, not the core proxy).
  const messages = c.messages as Record<string, unknown> | undefined;
  if (typeof messages?.create === "function") {
    return "anthropic";
  }

  // Fallback: class name (covers clients where methods are lazily defined).
  const constructor = (client as object).constructor;
  if (constructor) {
    const name = constructor.name.toLowerCase();
    if (name.includes("openai")) return "openai";
    if (name.includes("anthropic")) return "anthropic";
    if (
      name.includes("google") ||
      name.includes("gemini") ||
      name.includes("genai") ||
      name.includes("generativemodel")
    )
      return "google";
  }

  return "unknown";
}

/**
 * Determine error type from error object
 */
function classifyError(error: unknown): AuditEvent["error_type"] {
  if (!(error instanceof Error)) return "api_error";

  const message = error.message.toLowerCase();
  const name = error.name.toLowerCase();

  if (
    message.includes("rate limit") ||
    message.includes("429") ||
    name.includes("ratelimit")
  ) {
    return "rate_limit";
  }
  if (
    message.includes("timeout") ||
    name.includes("timeout") ||
    message.includes("timed out")
  ) {
    return "timeout";
  }
  if (
    message.includes("auth") ||
    message.includes("401") ||
    message.includes("403") ||
    message.includes("unauthorized")
  ) {
    return "auth_error";
  }
  return "api_error";
}

/**
 * Extract all visible prompt text from request args for PII scanning.
 * Handles OpenAI (messages), Anthropic (messages + system), and Gemini (contents).
 */
function extractPromptTextFromArgs(args: unknown): string {
  // Gemini accepts a plain string: generateContent('text')
  if (typeof args === "string") return args;
  if (!args || typeof args !== "object") return "";
  const req = args as Record<string, unknown>;
  const parts: string[] = [];

  if (typeof req.system === "string") {
    parts.push(req.system);
  }

  if (Array.isArray(req.messages)) {
    for (const msg of req.messages as Record<string, unknown>[]) {
      if (typeof msg.content === "string") {
        parts.push(msg.content);
      } else if (Array.isArray(msg.content)) {
        for (const part of msg.content as Record<string, unknown>[]) {
          const p = part as Record<string, unknown>;
          if (typeof p.text === "string") parts.push(p.text);
        }
      }
    }
  }

  if (Array.isArray(req.contents)) {
    for (const c of req.contents as Record<string, unknown>[]) {
      const cObj = c as Record<string, unknown>;
      if (Array.isArray(cObj.parts)) {
        for (const part of cObj.parts as Record<string, unknown>[]) {
          const p = part as Record<string, unknown>;
          if (typeof p.text === "string") parts.push(p.text);
        }
      }
    }
  }

  // OpenAI Responses API: instructions (system) + input (string or item list)
  if (typeof req.instructions === "string") {
    parts.push(req.instructions);
  }
  if (typeof req.input === "string") {
    parts.push(req.input);
  } else if (Array.isArray(req.input)) {
    for (const item of req.input as Record<string, unknown>[]) {
      if (typeof item.content === "string") {
        parts.push(item.content);
      } else if (Array.isArray(item.content)) {
        for (const part of item.content as Record<string, unknown>[]) {
          const p = part as Record<string, unknown>;
          if (typeof p.text === "string") parts.push(p.text);
        }
      }
    }
  }

  return parts.join(" ");
}

/**
 * Extract only the last user message for PII policy decisions.
 * Avoids false positives from conversation history containing PII from prior turns.
 */
function extractLastUserMessageText(args: unknown): string {
  // Gemini accepts a plain string: generateContent('text')
  if (typeof args === "string") return args;
  if (!args || typeof args !== "object") return "";
  const req = args as Record<string, unknown>;

  // OpenAI / Anthropic: scan messages array in reverse for last user turn
  if (Array.isArray(req.messages)) {
    for (let i = (req.messages as unknown[]).length - 1; i >= 0; i--) {
      const msg = (req.messages as Record<string, unknown>[])[i];
      if (msg.role === "user") {
        if (typeof msg.content === "string") return msg.content;
        if (Array.isArray(msg.content)) {
          return (msg.content as Record<string, unknown>[])
            .map((p) => (typeof p.text === "string" ? p.text : ""))
            .join(" ");
        }
      }
    }
  }

  // Gemini: contents array
  if (Array.isArray(req.contents)) {
    for (let i = (req.contents as unknown[]).length - 1; i >= 0; i--) {
      const c = (req.contents as Record<string, unknown>[])[i];
      if (c.role === "user" && Array.isArray(c.parts)) {
        return (c.parts as Record<string, unknown>[])
          .map((p) => (typeof p.text === "string" ? p.text : ""))
          .join(" ");
      }
    }
  }

  // OpenAI Responses API: a plain-string input IS the user turn; item
  // lists are scanned in reverse for the last user message.
  if (typeof req.input === "string") return req.input;
  if (Array.isArray(req.input)) {
    for (let i = (req.input as unknown[]).length - 1; i >= 0; i--) {
      const item = (req.input as Record<string, unknown>[])[i];
      if (item.role === "user") {
        if (typeof item.content === "string") return item.content;
        if (Array.isArray(item.content)) {
          return (item.content as Record<string, unknown>[])
            .map((p) => (typeof p.text === "string" ? p.text : ""))
            .join(" ");
        }
      }
    }
  }

  return extractPromptTextFromArgs(args);
}

/**
 * Redact PII in-place across all message/prompt content fields.
 * Preserves message structure; replaces only PII text within content strings
 * with typed placeholders (e.g. [REDACTED_EMAIL]).
 */
function redactMessagesInPlace(args: unknown): void {
  if (!args || typeof args !== "object") return;
  const req = args as Record<string, unknown>;

  if (typeof req.system === "string") {
    req.system = redactBuiltinPii(req.system);
  }

  if (Array.isArray(req.messages)) {
    for (const msg of req.messages as Record<string, unknown>[]) {
      if (typeof msg.content === "string") {
        msg.content = redactBuiltinPii(msg.content);
      } else if (Array.isArray(msg.content)) {
        for (const part of msg.content as Record<string, unknown>[]) {
          const p = part as Record<string, unknown>;
          if (typeof p.text === "string") {
            p.text = redactBuiltinPii(p.text);
          }
        }
      }
    }
  }

  if (Array.isArray(req.contents)) {
    for (const c of req.contents as Record<string, unknown>[]) {
      const cObj = c as Record<string, unknown>;
      if (Array.isArray(cObj.parts)) {
        for (const part of cObj.parts as Record<string, unknown>[]) {
          const p = part as Record<string, unknown>;
          if (typeof p.text === "string") {
            p.text = redactBuiltinPii(p.text);
          }
        }
      }
    }
  }

  // OpenAI Responses API: instructions + input (string or item list)
  if (typeof req.instructions === "string") {
    req.instructions = redactBuiltinPii(req.instructions);
  }
  if (typeof req.input === "string") {
    req.input = redactBuiltinPii(req.input);
  } else if (Array.isArray(req.input)) {
    for (const item of req.input as Record<string, unknown>[]) {
      if (typeof item.content === "string") {
        item.content = redactBuiltinPii(item.content);
      } else if (Array.isArray(item.content)) {
        for (const part of item.content as Record<string, unknown>[]) {
          const p = part as Record<string, unknown>;
          if (typeof p.text === "string") {
            p.text = redactBuiltinPii(p.text);
          }
        }
      }
    }
  }
}

/**
 * Build an audit event from the extracted data
 */
function buildAuditEvent(
  ctx: PathContext,
  request: unknown,
  response: unknown,
  auditFields: AuditFields,
  latencyMs: number,
  provider: "openai" | "anthropic" | "google" | "unknown",
  success: boolean = true,
  error?: unknown,
  errorStatusCode?: number,
  modelHint?: string,
  compliance: ComplianceCtx = DEFAULT_COMPLIANCE,
): AuditEvent {
  const { config, options } = ctx;

  // Paths that skipped policy evaluation still stamp the REAL hash of the
  // active rule set, never the placeholder: every event must pin the
  // policy state it ran under (evidence replayability).
  if (compliance === DEFAULT_COMPLIANCE) {
    compliance = {
      ...DEFAULT_COMPLIANCE,
      policyVersion: derivePolicyVersion(config.policyRules ?? []),
    };
  }

  // Determine operation from method path (also selects the extractor for
  // OpenAI-shaped clients: Chat Completions vs Responses API).
  const operation = ctx.path.join(".");

  // Extract prompt/response using the correct provider extractor
  let prompt: string;
  let responseText: string;
  let model: string;
  let tokenUsage: ReturnType<typeof extractOpenAITokenUsage>;

  if (provider === "anthropic") {
    prompt = extractAnthropicPrompt(request as AnthropicMessagesRequest);
    responseText = response
      ? extractAnthropicResponse(response as AnthropicMessagesResponse)
      : "";
    model = extractAnthropicModel(request as AnthropicMessagesRequest);
    tokenUsage = response
      ? extractAnthropicTokenUsage(response as AnthropicMessagesResponse)
      : undefined;
  } else if (provider === "google") {
    prompt = extractGeminiPrompt(request as GeminiRequest);
    responseText = response
      ? extractGeminiResponse(response as GeminiResponse)
      : "";
    model = extractGeminiModel(request as GeminiRequest, modelHint);
    tokenUsage = response
      ? extractGeminiTokenUsage(response as GeminiResponse)
      : undefined;
  } else if (operation === "responses.create") {
    prompt = extractResponsesPrompt(request as OpenAIResponsesRequest);
    responseText = response
      ? extractResponsesText(response as OpenAIResponsesResponse)
      : "";
    model = extractResponsesModel(request as OpenAIResponsesRequest);
    tokenUsage = response
      ? extractResponsesTokenUsage(response as OpenAIResponsesResponse)
      : undefined;
  } else {
    prompt = extractOpenAIPrompt(request as OpenAIChatRequest);
    // Guard the null response the same way the anthropic/google/responses
    // branches above do: on a FAILED call the error path builds the audit event
    // with response=null, and extractOpenAIResponse dereferences response.choices
    // (throwing on null). Unguarded, that throw was swallowed by the error
    // path's try/catch, dropping the forensic record for every failed
    // OpenAI/Azure/Together/openai-compat call — the exact events an auditor
    // most needs. Guarding restores audit-on-error for the OpenAI family.
    responseText = response
      ? extractOpenAIResponse(response as any)
      : "";
    model = extractOpenAIModel(request as OpenAIChatRequest);
    tokenUsage = response
      ? extractOpenAITokenUsage(response as any)
      : undefined;
  }

  // Provider-RESOLVED model snapshot from the response body (temporal
  // provenance): OpenAI/Anthropic put it in `model`, Gemini in `modelVersion`.
  // The Gemini SDK wraps its result as `{ response: GenerateContentResponse }`;
  // modelVersion lives on the INNER object, so it must be unwrapped the same
  // way the prompt/response/token extractors already do — reading it off the
  // raw wrapper directly always returned undefined.
  const rawResolvedModel =
    provider === "google"
      ? (response ? unwrapGeminiResponse(response) : undefined)?.modelVersion
      : (response as { model?: unknown } | undefined)?.model;
  const modelResolved =
    typeof rawResolvedModel === "string" && rawResolvedModel.trim().length > 0
      ? rawResolvedModel.trim()
      : undefined;

  // Curated call telemetry (DASHBOARD_TELEMETRY.md M1): request shape,
  // response metadata, cost-detail tokens. Rides in metadata under the
  // reserved key so the signed event schema is untouched.
  const callTelemetry = extractCallTelemetry(provider, request, response);

  // M3: every governed LLM call is a graph node (span), linked to the
  // enclosing withSpan scope when one is active. Rides metadata like M1.
  const spanEnv = spanEnvelopeFor("llm_call", operation);

  // Build event with proper precedence: auditFields > options > config
  const event: AuditEvent = {
    // Core fields
    request_id: auditFields.request_id || generateUUID(),

    // Environment fields
    environment: config.environment,
    service_name:
      auditFields.service_name ||
      options.service_name ||
      config.default_service_name ||
      undefined,
    region:
      auditFields.region ||
      options.region ||
      config.default_region ||
      "unknown",

    // Identity fields
    user_id: auditFields.user_id || options.user_id || undefined,

    // Network fields (passed through to server for masking)
    client_ip: auditFields.client_ip || undefined,
    user_agent: auditFields.user_agent || undefined,

    // LLM Call fields
    provider,
    model,
    model_resolved: modelResolved,
    // Read directly from the native provider response → highest-trust capture.
    // Present iff model_resolved is (the honesty contract).
    provenance_source: modelResolved ? "provider_response" : undefined,
    operation,
    source:
      auditFields.source ||
      options.source ||
      config.default_source ||
      "proxy_wrapper",

    // Content fields
    prompt: truncate(prompt, config.max_payload_chars),
    response: truncate(responseText, config.max_payload_chars),
    user_input: truncate(extractLastUserMessageText(request), config.max_payload_chars),

    // Usage fields (V2)
    input_tokens: tokenUsage?.input_tokens,
    output_tokens: tokenUsage?.output_tokens,
    total_tokens: tokenUsage?.total_tokens,

    // Performance fields
    latency_ms: latencyMs,
    time_to_first_token_ms: undefined, // non-streaming call: no distinct first token (TTFT is captured on the streaming path, see wrapStreamingIterator)

    // Success/Status fields
    success,
    status_code: success ? 200 : (errorStatusCode ?? 500),
    error_type: error ? classifyError(error) : null,
    error_message: (() => {
      const m =
        error instanceof Error
          ? error.message
          : error
            ? String(error)
            : undefined;
      return m && m.length > 500 ? m.slice(0, 500) : m;
    })(),

    // Metadata (call telemetry + span envelope merged under reserved keys).
    // withRunMetadata stamps agent_run_id when this call runs inside an
    // `agentRun(...)` scope, so raw proxied provider calls join the run too.
    metadata: withRunMetadata(
      withSpanMetadata(
        withTelemetryMetadata(auditFields.metadata, callTelemetry),
        spanEnv,
      ),
    ),

    // Compliance fields
    event_type: compliance.eventType,
    policy_version: compliance.policyVersion,
    action_taken: compliance.actionTaken,
    action_reason: compliance.actionReason,
    action_source: compliance.actionSource,
    redacted_types: compliance.redactedTypes,
    blocked_types: compliance.blockedTypes,
    rule_id: compliance.ruleId,
    policy_reason: compliance.policyReason,
    ...(compliance.shadowOutcome ? { shadow_outcome: compliance.shadowOutcome } : {}),
    // Canonical decision record (ADR-2, additive — not in the chain preimage)
    decision_input_hash: compliance.decisionInputHash,
    engine_version: compliance.engineVersion,
    // External policy backend provenance (ADR-4, additive)
    external_backend: compliance.externalBackend,
  };

  // M-5: PII-scan error messages when pii_policy is configured
  if (error && event.error_message && config.pii_policy) {
    event.error_message = redactBuiltinPii(event.error_message);
  }

  // Cost governance: record this call's token usage against any token-unit
  // quota rules so their pre-call budget checks reflect consumption.
  // (Tokens are only known post-call; budgets are approximate by design.)
  if (success && event.total_tokens) {
    recordTokenUsageForRules(config, event);
  }

  return event;
}

/**
 * EV-1: governance runs in two phases, pre_call AND
 * post_call. This runs the post-call phase (response-side policy rules, the
 * onPostCall hook, and the built-in response PII scan) and merges the
 * outcome onto the event — mirroring sdk-python wrap.py exactly: the STORED
 * copy is governed (redacted response, policy_flag, response_pii_* telemetry);
 * the response returned to the caller is never modified. Skipped on error
 * events (parity: python runs post-call only when error is None). Never
 * throws: post-call governance must never affect the LLM flow.
 */
async function applyPostCallGovernance(
  event: AuditEvent,
  config: ResolvedConfig,
): Promise<void> {
  try {
    if (event.success === false) return;
    const post = await applyPostCallPolicy(event.response ?? "", event, config);
    mergePostCallOutcome(event, post);
  } catch {
    /* swallow - never affect the audit path */
  }
}

/**
 * Feed provider-reported token usage into every enabled token-unit quota
 * rule's budget bucket. Scope value resolution mirrors rule evaluation
 * (metadata[scope], falling back to event user_id for user_id scope).
 */
function recordTokenUsageForRules(config: ResolvedConfig, event: AuditEvent): void {
  const rules = config.policyRules;
  if (!rules?.length) return;
  for (const rule of rules) {
    if (!rule.enabled || rule.type !== 'quota') continue;
    const c = rule.conditions;
    if (c.quota_unit !== 'tokens' || !c.quota_limit || !c.quota_window_ms || !c.quota_scope) continue;
    const meta = (event.metadata ?? {}) as Record<string, unknown>;
    const scopeValue = c.quota_scope === 'project'
      ? 'project'
      : String(
          meta[c.quota_scope]
            ?? (c.quota_scope === 'user_id' ? event.user_id : undefined)
            ?? 'default',
        );
    recordTokenUsage(c.quota_scope, scopeValue, event.total_tokens ?? 0, c.quota_window_ms);
  }
}

/**
 * Wraps an async-iterable stream, yielding each chunk unchanged while
 * accumulating content. Fires a single audit event when the stream ends.
 */
function wrapStreamingIterator(
  iter: AsyncIterable<unknown>,
  request: unknown,
  auditFields: AuditFields,
  ctx: PathContext,
  provider: "openai" | "anthropic" | "google" | "unknown",
  startTime: number,
  modelHint?: string,
  compliance: ComplianceCtx = DEFAULT_COMPLIANCE,
): AsyncGenerator<unknown, void, unknown> {
  if (compliance === DEFAULT_COMPLIANCE) {
    compliance = {
      ...DEFAULT_COMPLIANCE,
      policyVersion: derivePolicyVersion(ctx.config.policyRules ?? []),
    };
  }
  return (async function* () {
    const chunks: unknown[] = [];
    let streamError: unknown = null;
    let firstChunkTime: number | null = null;
    try {
      for await (const chunk of iter) {
        if (firstChunkTime === null) {
          firstChunkTime = performance.now();
        }
        chunks.push(chunk);
        yield chunk;
      }
    } catch (err) {
      streamError = err;
      throw err;
    } finally {
      const latencyMs = Math.round(performance.now() - startTime);
      try {
        let accText = "";
        let tokenUsage: ReturnType<typeof extractOpenAITokenUsage> = undefined;
        let model: string;
        // Provider-RESOLVED model snapshot from the stream body (temporal
        // provenance): Anthropic emits it on message_start, Gemini as
        // modelVersion per chunk, OpenAI as chunk.model.
        let modelResolved: string | undefined;

        if (provider === "anthropic") {
          const result = extractStreamingResponse(
            chunks as AnthropicStreamEvent[],
          );
          accText = result.text;
          tokenUsage = result.usage;
          model = extractAnthropicModel(request as AnthropicMessagesRequest);
          for (const chunk of chunks as Record<string, any>[]) {
            const m = chunk?.message?.model;
            if (typeof m === "string" && m.trim().length > 0) {
              modelResolved = m.trim();
              break;
            }
          }
        } else if (provider === "google") {
          // Gemini streaming: each chunk has candidates[0].content.parts[0].text
          for (const chunk of chunks as Record<string, any>[]) {
            const text = chunk.candidates?.[0]?.content?.parts?.[0]?.text;
            if (typeof text === "string") accText += text;
            if (chunk.usageMetadata) {
              tokenUsage = {
                input_tokens: chunk.usageMetadata.promptTokenCount ?? 0,
                output_tokens: chunk.usageMetadata.candidatesTokenCount ?? 0,
                total_tokens: chunk.usageMetadata.totalTokenCount ?? 0,
              };
            }
            if (typeof chunk.modelVersion === "string" && chunk.modelVersion.trim().length > 0) {
              modelResolved = chunk.modelVersion.trim();
            }
          }
          model = extractGeminiModel(request as GeminiRequest, modelHint); // uses modelHint from target.model if available
        } else if (ctx.path.join(".") === "responses.create") {
          const result = accumulateResponsesStream(chunks);
          accText = result.text;
          tokenUsage = result.usage;
          model =
            result.model !== "unknown"
              ? result.model
              : extractResponsesModel(request as OpenAIResponsesRequest);
          modelResolved = result.model !== "unknown" ? result.model : undefined;
        } else {
          const result = accumulateOpenAIStream(chunks);
          accText = result.text;
          tokenUsage = result.usage;
          model =
            result.model !== "unknown"
              ? result.model
              : extractOpenAIModel(request as OpenAIChatRequest);
          modelResolved = result.model !== "unknown" ? result.model : undefined;
        }

        const { config, options } = ctx;
        const operation = ctx.path.join(".");

        let promptText: string;
        if (provider === "anthropic") {
          promptText = extractAnthropicPrompt(
            request as AnthropicMessagesRequest,
          );
        } else if (provider === "google") {
          promptText = extractGeminiPrompt(request as GeminiRequest);
        } else if (operation === "responses.create") {
          promptText = extractResponsesPrompt(request as OpenAIResponsesRequest);
        } else {
          promptText = extractOpenAIPrompt(request as OpenAIChatRequest);
        }

        const streamAuditEvent: AuditEvent = {
          request_id: auditFields.request_id || generateUUID(),
          environment: config.environment,
          service_name:
            auditFields.service_name ||
            options.service_name ||
            config.default_service_name ||
            undefined,
          region:
            auditFields.region ||
            options.region ||
            config.default_region ||
            "unknown",
          user_id: auditFields.user_id || options.user_id || undefined,
          client_ip: auditFields.client_ip || undefined,
          user_agent: auditFields.user_agent || undefined,
          provider,
          model,
          model_resolved: modelResolved,
          // Native provider stream snapshot → highest-trust capture (present iff model_resolved).
          provenance_source: modelResolved ? "provider_response" : undefined,
          operation,
          source:
            auditFields.source ||
            options.source ||
            config.default_source ||
            "proxy_wrapper",
          prompt: truncate(promptText, config.max_payload_chars),
          response: truncate(accText, config.max_payload_chars),
          input_tokens: tokenUsage?.input_tokens,
          output_tokens: tokenUsage?.output_tokens,
          total_tokens: tokenUsage?.total_tokens,
          latency_ms: latencyMs,
          time_to_first_token_ms:
            firstChunkTime !== null
              ? Math.round(firstChunkTime - startTime)
              : undefined,
          success: streamError === null,
          status_code:
            streamError === null
              ? 200
              : ((streamError as any)?.status ??
                (streamError as any)?.statusCode ??
                500),
          error_type: streamError ? classifyError(streamError) : null,
          error_message: (() => {
            const m =
              streamError instanceof Error
                ? streamError.message
                : streamError
                  ? String(streamError)
                  : undefined;
            return m && m.length > 500 ? m.slice(0, 500) : m;
          })(),
          // Streamed calls carry the same reserved metadata as non-streaming
          // ones: withRunMetadata stamps agent_run_id (so a streamed LLM call
          // inside agentRun(...) joins the run), withSpanMetadata attaches the
          // span envelope (trace linkage), and withTelemetryMetadata the call
          // telemetry. Previously the stream path set `auditFields.metadata`
          // bare, orphaning every streamed step from its run/trace.
          metadata: withRunMetadata(
            withSpanMetadata(
              withTelemetryMetadata(
                auditFields.metadata,
                extractCallTelemetry(provider, request, undefined),
              ),
              spanEnvelopeFor("llm_call", operation),
            ),
          ),

          // Compliance fields
          event_type: compliance.eventType,
          policy_version: compliance.policyVersion,
          action_taken: compliance.actionTaken,
          action_reason: compliance.actionReason,
          action_source: compliance.actionSource,
          redacted_types: compliance.redactedTypes,
          blocked_types: compliance.blockedTypes,
          rule_id: compliance.ruleId,
          policy_reason: compliance.policyReason,
          ...(compliance.shadowOutcome ? { shadow_outcome: compliance.shadowOutcome } : {}),
          // Canonical decision record (ADR-2, additive)
          decision_input_hash: compliance.decisionInputHash,
          engine_version: compliance.engineVersion,
          // External policy backend provenance (ADR-4, additive)
          external_backend: compliance.externalBackend,
        };

        // M-5: PII-scan error messages when pii_policy is configured
        if (streamError && streamAuditEvent.error_message && config.pii_policy) {
          streamAuditEvent.error_message = redactBuiltinPii(streamAuditEvent.error_message);
        }

        // EV-1 post_call phase on the accumulated stream text (skips itself
        // on error events; parity with the Python streaming wrap).
        await applyPostCallGovernance(streamAuditEvent, config);

        // Meter streamed token usage against token-unit quota rules. Without
        // this, quota rules with quota_unit:"tokens" under-count by exactly the
        // streaming traffic (buildAuditEvent — which meters non-streaming calls
        // — is not used on the streaming completion path).
        recordTokenUsageForRules(config, streamAuditEvent);

        sendAuditAsync(config, streamAuditEvent);
        debugLog(
          config,
          "info",
          `Audit event queued (streaming): ${streamAuditEvent.request_id}`,
        );
      } catch (auditErr) {
        debugLog(
          ctx.config,
          "error",
          "Failed to audit streaming response:",
          auditErr instanceof Error ? auditErr.message : String(auditErr),
        );
      }
    }
  })();
}

/**
 * Create an audited version of a method
 */
function createAuditedMethod(
  originalMethod: Function,
  target: object,
  ctx: PathContext,
  provider: "openai" | "anthropic" | "google" | "unknown",
): Function {
  const { config } = ctx;
  const methodPath = ctx.path.join(".");

  return async function auditedMethod(...args: unknown[]): Promise<unknown> {
    // Always filter audit fields from args (even if not auditing)
    // This ensures audit fields never reach the LLM provider
    const { cleaned_args, audit_fields } = filterArgs(args);

    // For Google providers, extract the model name from the GenerativeModel instance.
    // target.model contains the full path e.g. "models/gemini-1.5-pro".
    const modelHint =
      provider === "google"
        ? String((target as any).model ?? "") || undefined
        : undefined;

    // Sampling gates ONLY the emission of allowed-call audit events (below),
    // NEVER enforcement. The compliance boundary must run for EVERY call, or a
    // sub-1.0 sample_rate would silently disable PII/policy blocking on a
    // fraction of traffic (a governance SDK that stops governing). Blocked,
    // redacted, and error events are always emitted (enforcement evidence),
    // mirroring the Python sender's posture (wrap.py `_emit_audit`).
    const shouldAudit = shouldSample(config.sample_rate);

    // Derive policy version from active rules - stamped on every event emitted for this call.
    const policyVersion = derivePolicyVersion(config.policyRules ?? []);

    // Canonical decision record (ADR-2): capture the evaluated text ONCE,
    // before any redaction the pipeline may apply in place, so the sealed
    // digest commits the text as presented to the decision pipeline.
    const decisionEvaluatedText = extractLastUserMessageText(cleaned_args[0]) ?? "";

    // Compliance boundary - runs for ALL calls, including streaming, before any LLM contact.
    // Builds one ComplianceCtx that is stamped on every audit event for this call.
    let actionTaken: ComplianceCtx["actionTaken"] = "allowed";
    let actionReason: ComplianceCtx["actionReason"] = "none";
    let actionSource: ComplianceCtx["actionSource"] = "unknown";
    let redactedTypes: string[] = [];
    let blockedTypes: string[] = [];
    let ruleIdOverride: string | undefined;
    let policyReasonOverride: string | undefined;
    // Which de-obfuscation view surfaced the PII/injection hit (absent for an
    // overt raw-text match, and always absent with deobfuscation disabled).
    // Present ⟹ the raw text is clean ⟹ span redaction cannot locate the
    // payload — storage/redaction paths below must use redactForStorage.
    let piiScanVia: DeobfuscationView["method"] | undefined;
    // A canary-leak block is unsuppressible — the customer hook can never
    // downgrade it (checked in the hook-override branches below).
    let canaryFloor = false;

    // 0. Enforcement-integrity gate. Blocks when the project is paused / the
    //    key is revoked (SDK kill switch), or when failMode="closed" and the
    //    policy sync has gone stale beyond the staleness budget.
    const degraded = isPolicyEnforcementDegraded(config);
    if (degraded.degraded) {
      actionTaken = "blocked";
      actionReason = "policy_violation";
      actionSource = "policy_rules";
      ruleIdOverride = `sdk:${degraded.reason}`;
      policyReasonOverride =
        degraded.reason === "project_paused_or_key_revoked"
          ? "Project paused or API key revoked (SDK kill switch)"
          : `Policy sync unavailable with failMode=closed (${degraded.reason})`;
      debugLog(config, "warn", `Call blocked: ${policyReasonOverride}`);
    }

    // 0.5 Session taint latch: a session compromised on an earlier turn has
    //     its later egress (this LLM call) escalated. ENFORCE runs on PRIOR
    //     taint; SET happens at this call's detection points below. The taint
    //     key folds in the SAME identity channels the integrations path uses
    //     (per-call metadata, then wrap-level options.user_id, then the
    //     ambient useSubject() subject) so a session tainted on wrap() and one
    //     tainted on MCP/tools share a key — otherwise the cross-egress
    //     escalation silently no-ops for useSubject-identified sessions.
    const taintCfg = resolveSessionTaint(config);
    const ambientSubject = getCurrentSubject();
    const rawTaintMeta = (audit_fields.metadata ?? {}) as Record<string, unknown>;
    const resolvedTaintUser =
      rawTaintMeta.user_id ?? audit_fields.user_id ?? ctx.options.user_id ?? ambientSubject?.user_id;
    const resolvedTaintTenant = rawTaintMeta.tenant_id ?? ambientSubject?.tenant_id;
    const taintKey = deriveSessionKey({
      ...rawTaintMeta,
      ...(resolvedTaintUser !== undefined ? { user_id: resolvedTaintUser } : {}),
      ...(resolvedTaintTenant !== undefined ? { tenant_id: resolvedTaintTenant } : {}),
    });
    if (taintCfg && sessionTaintSize() > 0 && actionTaken !== "blocked") {
      const verdict = evaluateSessionTaint(taintKey, taintCfg);
      if (verdict.enforcement !== "none") {
        touchTaint(taintKey, Date.now()); // LRU: keep an enforced victim alive
        ruleIdOverride = "sdk:session_tainted";
        policyReasonOverride = `Session previously compromised (${verdict.reason}); egress escalated`;
        if (verdict.enforcement === "block") {
          actionTaken = "blocked";
          actionReason = "policy_violation";
          actionSource = "policy_rules";
          debugLog(config, "warn", `Call blocked: ${policyReasonOverride}`);
        } else {
          if (actionReason === "none") actionReason = "policy_violation";
          actionSource = "policy_rules";
        }
      }
    }

    // 0.75 Canary-leak scan (unsuppressible). A planted honeytoken echoed back
    //      in the user's message is a CRITICAL leak signal — block before the
    //      provider is contacted. Scans the last user turn (never the app's
    //      planted system prompt), and only when a canary was minted.
    if (canaryRegistrySize() > 0 && actionTaken !== "blocked") {
      const leak = scanForCanary(extractLastUserMessageText(cleaned_args[0]) ?? "");
      if (leak.leaked) {
        actionTaken = "blocked";
        actionReason = "policy_violation";
        actionSource = "builtin";
        canaryFloor = true;
        ruleIdOverride = "sdk:canary_leak";
        policyReasonOverride = `Canary token leaked in request (${leak.hits.map((h) => h.id).join(", ")})`;
        audit_fields.metadata = {
          ...((audit_fields.metadata as Record<string, unknown>) ?? {}),
          obsvr_telemetry: {
            ...(((audit_fields.metadata as Record<string, unknown>)?.obsvr_telemetry as Record<string, unknown>) ?? {}),
            ...canaryLeakTelemetry(leak.hits, "request"),
          },
        };
        debugLog(config, "warn", `Call blocked: ${policyReasonOverride}`);
        if (taintCfg) markTainted(taintKey, "canary_leak", Date.now());
      }
    }

    // 1. Built-in PII scan (runs before customer hook; skipped when the
    //    integrity gate already blocked the call)
    if (config.pii_policy && actionTaken !== "blocked") {
      const promptText = extractLastUserMessageText(cleaned_args[0]);

      // Builtin regex scan (always runs, fast). With deobfuscation enabled
      // the scanner also sees decoded/stripped views of the text (the server-side normalizer
      // mirror); `via` records which view surfaced a hit that the raw text hid.
      const piiScan = runConfiguredPiiScan(promptText, config.deobfuscation);
      const regexTypes = piiScan.detected_types;
      piiScanVia = piiScan.via;

      // Presidio NLP scan - always runs when configured, merged with regex results
      let allTypes = regexTypes;
      if (config.presidio_analyzer_url) {
        const { detected_types: nlpTypes } = await presidioScan(
          promptText, config.presidio_analyzer_url,
        );
        allTypes = [...new Set([...regexTypes, ...nlpTypes])];
      }

      if (allTypes.length > 0) {
        actionReason = "pii_detected";
        actionSource = config.presidio_analyzer_url ? "builtin+presidio" : "builtin";
        // A detected prompt-injection taints the session (later egress escalated).
        if (taintCfg && allTypes.includes("prompt_injection")) {
          markTainted(taintKey, "prompt_injection", Date.now());
        }
        // Server-side normalizer mirror: seal which view defeated the obfuscation, so
        // "detection survived obfuscation" is itself on the audit record.
        if (piiScanVia !== undefined) {
          audit_fields.metadata = {
            ...((audit_fields.metadata as Record<string, unknown>) ?? {}),
            security_normalized: piiScanVia,
          };
        }
        const resolved = resolvePiiPolicy(allTypes, config.pii_policy);
        // A view-only hit has no locatable span in the raw text, so "redact"
        // would no-op while the record claims "redacted" — escalate to block.
        const piiAction = escalateViewOnlyAction(resolved.action, piiScanVia);
        if (piiAction === "block") {
          actionTaken = "blocked";
          blockedTypes = resolved.blockedTypes;
          redactedTypes = resolved.redactedTypes; // medium-risk types present alongside block-level types
        } else if (piiAction === "redact") {
          if (typeof cleaned_args[0] === 'string') {
            if (config.presidio_analyzer_url && config.presidio_anonymizer_url) {
              cleaned_args[0] =
                (await presidioRedactText(
                  cleaned_args[0],
                  config.presidio_analyzer_url,
                  config.presidio_anonymizer_url,
                )) ?? redactBuiltinPii(cleaned_args[0]);
            } else {
              cleaned_args[0] = redactBuiltinPii(cleaned_args[0]);
            }
          } else {
            if (config.presidio_analyzer_url && config.presidio_anonymizer_url) {
              await presidioRedactArgs(
                cleaned_args[0],
                config.presidio_analyzer_url,
                config.presidio_anonymizer_url,
              );
            } else {
              redactMessagesInPlace(cleaned_args[0]);
            }
          }
          redactedTypes = resolved.redactedTypes;
          actionTaken = "redacted";
        }
        // detect_only: reason/source set; action stays "allowed"
      }
    }

    // 1.2. Multi-turn injection scoring - catches injection payloads split
    //      across turns that no single message would trip. Sessions are keyed
    //      by metadata user_id (falling back to a process-wide bucket) and
    //      the score decays with a half-life, so sustained probing trips the
    //      gate while normal traffic never accumulates.
    if (config.multiTurnInjection?.enabled && actionTaken !== "blocked") {
      // Score only THIS turn's new text (the last user message), not the whole
      // joined history — otherwise a benign phrase in an early turn is re-counted
      // on every subsequent call and inflates the decayed score into a false trip
      // (the gate is designed to accumulate per-turn deltas).
      const promptText = extractLastUserMessageText(cleaned_args[0]) ?? "";
      const meta = (audit_fields.metadata ?? {}) as Record<string, unknown>;
      const sessionKey = String(meta.user_id ?? meta.session_id ?? meta.tenant_id ?? "global");
      // RAW scan only — deliberately NOT the deobfuscation-aware scan. The
      // gate below fires on `tripped && !hadFullMatch` ("a full match is
      // already handled by the single-turn scan"), but the single-turn scan
      // only enforces when pii_policy is configured. A view-aware hadFullMatch
      // here let an ENCODED injection suppress the accumulation block while
      // nothing else enforced it — enabling deobfuscation weakened this gate
      // (caught by adversarial review). With pii_policy set, the view-aware
      // step-1 scan above already blocks encoded injections.
      const hadFullMatch = runBuiltinPiiScan(promptText).detected_types.includes("prompt_injection");
      const mt = scoreTurn(sessionKey, promptText, hadFullMatch, {
        threshold: config.multiTurnInjection.threshold ?? 1.0,
        halfLifeMs: config.multiTurnInjection.halfLifeMs ?? 600_000,
      });
      // A full match is already handled by the single-turn scan above; the
      // multi-turn gate exists for the accumulation case.
      if (mt.tripped && !hadFullMatch) {
        const mtAction = config.multiTurnInjection.action ?? "block";
        ruleIdOverride = "sdk:multi_turn_injection";
        policyReasonOverride = `Multi-turn injection score ${mt.score.toFixed(2)} reached threshold over ${mt.turns} turn(s); this turn's signals: ${mt.signals.join(", ") || "none"}`;
        // Accumulated injection taints the session (later egress escalated).
        if (taintCfg) markTainted(taintKey, "multi_turn_injection", Date.now());
        if (mtAction === "block") {
          actionTaken = "blocked";
          actionReason = "policy_violation";
          actionSource = "policy_rules";
          debugLog(config, "warn", `Call blocked: ${policyReasonOverride}`);
        } else {
          if (actionReason === "none") actionReason = "policy_violation";
          actionSource = "policy_rules";
          debugLog(config, "warn", `Call flagged: ${policyReasonOverride}`);
        }
      }
    }

    // 1.4. Anti-tamper policy FLOOR — non-overridable rules evaluated BEFORE
    //      customer rules and excluded from the hook-override branches below.
    let floorBlock = false;
    let floorOverrideIgnored: { rule_id?: string; attempted: "allow" | "redact" } | undefined;
    const floorActive = !!(config.policyFloor && config.policyFloor.length > 0);
    if (floorActive && actionTaken !== "blocked") {
      const promptText = extractLastUserMessageText(cleaned_args[0]) ?? "";
      // The floor's authoritative context (environment, model, provider) is
      // pinned AFTER the caller-metadata spread, so a caller cannot set
      // metadata.model / metadata.currentEnvironment / metadata.provider to
      // spoof the values a floor model_gate / environment_gate rule reads and
      // dodge it. Other caller metadata (quota scope, namespaces) is preserved.
      const floorCtx: PolicyEvalContext = {
        ...(audit_fields.metadata as Record<string, unknown> ?? {}),
        currentEnvironment: config.environment,
        model: String((cleaned_args[0] as { model?: unknown })?.model ?? modelHint ?? ""),
        provider,
      };
      const floorResult = evaluateFloor(config.policyFloor, promptText, "prompt", floorCtx);
      if (floorResult.decision === "block" || floorResult.decision === "redact") {
        // A floor is the non-overridable security baseline: it must never
        // forward content it cannot GUARANTEE was redacted. The wrapper has no
        // span-level redaction for an arbitrary floor-rule match (only the PII
        // scanner and the hook-redact branch mutate the outgoing prompt), so a
        // floor 'redact' FAILS CLOSED to a block rather than send the prompt
        // verbatim under a false "redacted" record. Parity with the governance
        // surface. floorBlock=true so the hook-override exclusion and the
        // floor_override_ignored record below also cover the redact case.
        floorBlock = true;
        ruleIdOverride = floorResult.rule_id;
        policyReasonOverride = floorResult.reason ?? "Blocked by policy floor";
        actionTaken = "blocked";
        actionReason = "policy_violation";
        actionSource = "policy_rules";
        debugLog(config, "warn", `Floor block (${floorResult.decision} → block): ${policyReasonOverride}`);
      }
    }

    // 1.5. Structured policy rules - runs before the customer hook so that
    //      rules fetched by the polling loop can block calls before the hook fires.
    let ruleId: string | undefined = ruleIdOverride;
    let policyReason: string | undefined = policyReasonOverride;
    if (config.policyRules?.length && actionTaken !== "blocked") {
      const promptText = extractLastUserMessageText(cleaned_args[0]) ?? "";
      // Build PolicyEvalContext from audit_fields metadata and config environment
      const evalCtx: PolicyEvalContext = {
        currentEnvironment: config.environment,
        // model_gate context: model from the request (or Gemini instance hint)
        model: String((cleaned_args[0] as { model?: unknown })?.model ?? modelHint ?? ""),
        provider,
        ...(audit_fields.metadata as Record<string, unknown> ?? {}),
      };
      const result = evaluatePolicyRules(config.policyRules, promptText, "prompt", evalCtx);
      ruleId = result.rule_id;
      policyReason = result.reason;
      if (result.decision === "block") {
        actionTaken = "blocked";
        actionReason = "policy_violation";
        actionSource = "policy_rules";
        // require_approval rule without a grant: file a request so the
        // dashboard Approvals queue can grant a time-boxed pass; the retry
        // succeeds once the grant arrives on a policy poll.
        if (result.approval_required) {
          const meta = (audit_fields.metadata ?? {}) as Record<string, unknown>;
          requestApproval(config, {
            rule_id: result.rule_id,
            rule_name: result.reason,
            operation: methodPath,
            user_id: typeof meta.user_id === "string" ? meta.user_id : undefined,
            rule_hash: result.rule_hash,
          });
        }
      }
    }

    // 2. Customer hook - fires according to hookTrigger config.
    //    Allows customers to escalate OR explicitly override a builtin decision.
    //    Enforces configured hookTimeoutMs (default 2000ms) to prevent indefinite hangs.
    // Hook disposition for the decision record (ADR-2): configured-but-not-run
    // is "skipped"; outcomes overwrite it below.
    let hookDisposition: HookDisposition = config.on_pre_call ? "skipped" : "not_configured";
    const hookTrigger = config.hookTrigger ?? 'always';
    const shouldRunHook =
      !degraded.degraded && // integrity-gate blocks are not customer-overridable
      config.on_pre_call &&
      (hookTrigger === 'always' ||
        (hookTrigger === 'on_pii' && actionReason === 'pii_detected') ||
        (hookTrigger === 'on_block' && actionTaken === 'blocked'));
    if (shouldRunHook) {
      const preEvent: Partial<AuditEvent> = {
        provider,
        operation: methodPath,
        environment: config.environment,
        // Give the hook the full provider-agnostic prompt text so it can decide
        // for Gemini (contents), Responses (input/instructions), and string
        // prompts too — not only OpenAI/Anthropic `.messages`. Previously those
        // shapes passed the hook `prompt: undefined`, silently degrading a
        // content-inspecting hook to allow.
        prompt: extractPromptTextFromArgs(cleaned_args[0]),
      };
      let hookDecision: string;
      try {
        const hookResult = await evaluatePolicyHook(
          config.on_pre_call!,
          preEvent,
          config.hookTimeoutMs ?? 2000,
        );
        if (hookResult === "hook_timeout") {
          hookDisposition = "timeout";
          if (config.failMode === "closed") {
            debugLog(config, "warn", "onPreCall hook timed out - failMode=closed, blocking call");
            hookDecision = "block";
            policyReason = "hook_timeout (fail_closed)";
          } else {
            debugLog(config, "warn", "onPreCall hook timed out, defaulting to allow");
            hookDecision = "allow";
          }
        } else {
          hookDecision = hookResult.decision;
          hookDisposition =
            hookDecision === "block" || hookDecision === "redact" ? hookDecision : "allow";
          // H-3: Capture rule_id/reason from hook result
          const hr = hookResult as { decision: string; rule_id?: string; reason?: string };
          if (hr.rule_id) ruleId = hr.rule_id;
          if (hr.reason) policyReason = hr.reason;
        }
      } catch (hookErr) {
        hookDisposition = "error";
        if (config.failMode === "closed") {
          debugLog(
            config,
            "error",
            "onPreCall hook threw - failMode=closed, blocking call:",
            hookErr instanceof Error ? hookErr.message : String(hookErr),
          );
          hookDecision = "block";
          policyReason = "hook_error (fail_closed)";
        } else {
          debugLog(
            config,
            "error",
            "onPreCall hook threw, defaulting to allow:",
            hookErr instanceof Error ? hookErr.message : String(hookErr),
          );
          hookDecision = "allow";
        }
      }
      if (hookDecision === "block") {
        actionTaken = "blocked";
        actionReason = "policy_violation";
        actionSource = "customer_hook";
      } else if (
        hookDecision === "allow" &&
        hookDisposition === "allow" &&
        actionTaken === "blocked" &&
        !canaryFloor
      ) {
        if (floorBlock) {
          // The hook tried to un-block a FLOOR rule. Refused + recorded on the
          // tamper-evident event; the block stands.
          floorOverrideIgnored = { rule_id: ruleIdOverride, attempted: "allow" };
        } else {
          // Only an EXPLICIT hook allow overrides a builtin block (logged
          // transparently). A fail-open timeout/error default (disposition
          // "timeout"/"error") must NOT un-block builtin PII/rules enforcement.
          // A canary-leak block is unsuppressible (canaryFloor).
          actionTaken = "allowed";
          actionReason = "customer_override";
          actionSource = "customer_hook";
        }
      } else if (
        hookDecision === "redact" &&
        actionTaken !== "redacted" &&
        !canaryFloor &&
        floorBlock
      ) {
        floorOverrideIgnored = { rule_id: ruleIdOverride, attempted: "redact" };
      } else if (hookDecision === "redact" && actionTaken !== "redacted" && !canaryFloor) {
        if (piiScanVia !== undefined) {
          // View-only detection: the raw text is clean, so the redactors below
          // are a guaranteed no-op — honoring the hook's "redact" would send
          // the encoded payload to the provider while the event says
          // "redacted" (and would DOWNGRADE the escalated builtin block).
          // Same clamp as escalateViewOnlyAction: block instead.
          actionTaken = "blocked";
          actionReason = "policy_violation";
          actionSource = "customer_hook";
        } else {
          // Redact across ALL provider shapes (system / messages / contents /
          // instructions / input / bare string), mirroring the builtin PII redact
          // path. The old code cleared only OpenAI's `.messages`, so a hook redact
          // on a Gemini (`contents`), Responses (`input`/`instructions`), or
          // string prompt sent the content to the provider UNREDACTED while the
          // event was stamped "redacted" — a false compliance record and a real
          // leak. (A hook that must suppress non-PII content should return
          // "block": redact applies the SDK's structure-aware PII redaction.)
          if (typeof cleaned_args[0] === "string") {
            cleaned_args[0] = redactBuiltinPii(cleaned_args[0]);
          } else {
            redactMessagesInPlace(cleaned_args[0]);
          }
          redactedTypes = ["all"]; // customer-driven; exact types are unknown
          actionTaken = "redacted";
          actionReason = "policy_violation";
          actionSource = "customer_hook";
        }
      }
    }

    // Seal the floor evidence on every event under an active floor: the
    // floor-definition hash (so a change to the floor is on the audit chain)
    // and, when the hook tried to override a floor block, a first-class
    // floor_override_ignored record (the differentiator over a swallowed log).
    if (floorActive) {
      const md = (audit_fields.metadata ?? {}) as Record<string, unknown>;
      audit_fields.metadata = {
        ...md,
        obsvr_telemetry: {
          ...((md.obsvr_telemetry as Record<string, unknown>) ?? {}),
          floor_version: deriveFloorVersion(config.policyFloor),
          ...(floorOverrideIgnored !== undefined
            ? { floor_override_ignored: floorOverrideIgnored }
            : {}),
        },
      };
    }

    // 2.5. Inbound external policy backend (ADR-4): consult the customer's
    //      OPA/Cedar engine and merge DENY-WINS with the local decision (a deny
    //      from EITHER side blocks). Only runs when the call is not already
    //      blocked — a local block cannot be downgraded, so the deny-wins
    //      outcome is already settled and a network round-trip would be pure
    //      overhead. A backend error/timeout is a DENY (fail-closed) unless the
    //      backend is in shadow (observe-only) mode. The backend's identity and
    //      effective-policy hash are recorded on the event for provenance.
    let externalBackend: ExternalBackendRecord | undefined;
    if (config.external_policy_backend && actionTaken !== "blocked") {
      const localDecision = actionTaken === "redacted" ? "redact" : "allow";
      try {
        const step = await runExternalBackendStep(
          config.external_policy_backend,
          localDecision,
          buildBackendInput({
            operation: methodPath,
            provider,
            model: String((cleaned_args[0] as { model?: unknown })?.model ?? modelHint ?? ""),
            environment: config.environment,
            userId: audit_fields.user_id || ctx.options.user_id || undefined,
            serviceName:
              audit_fields.service_name || ctx.options.service_name || config.default_service_name || undefined,
            tenantId:
              typeof (audit_fields.metadata as Record<string, unknown> | undefined)?.tenant_id === "string"
                ? ((audit_fields.metadata as Record<string, unknown>).tenant_id as string)
                : undefined,
            localDecision,
            rulesHash: policyVersion,
            promptSha256: sha256Hex(decisionEvaluatedText),
          }),
        );
        externalBackend = step.record;
        if (step.blocked_by_backend) {
          actionTaken = "blocked";
          actionReason = "policy_violation";
          actionSource = "external_backend";
          ruleId = `backend:${step.record.type}`;
          policyReason =
            step.record.reasons && step.record.reasons.length > 0
              ? step.record.reasons.join("; ")
              : `Denied by external ${step.record.type} policy backend`;
          debugLog(config, "warn", `Call blocked by external ${step.record.type} backend: ${policyReason}`);
        }
      } catch {
        // runExternalBackendStep maps every failure to an outcome; this catch
        // is defensive. Fail closed unless the backend is observe-only.
        if (!config.external_policy_backend.shadow) {
          actionTaken = "blocked";
          actionReason = "policy_violation";
          actionSource = "external_backend";
          ruleId = `backend:${config.external_policy_backend.type}`;
          policyReason = `Denied by external ${config.external_policy_backend.type} policy backend (evaluation error, fail-closed)`;
        }
      }
    }

    // Shadow rules (EV-20/21): evaluated AFTER the active decision is
    // final, check-only, recorded on the event, never decision-affecting.
    let shadowOutcome: ComplianceCtx["shadowOutcome"] = null;
    if (config.policyRules?.some((r) => r.enabled && r.mode === "shadow")) {
      const promptText = extractLastUserMessageText(cleaned_args[0]) ?? "";
      const evalCtx: PolicyEvalContext = {
        currentEnvironment: config.environment,
        model: String((cleaned_args[0] as { model?: unknown })?.model ?? modelHint ?? ""),
        provider,
        ...(audit_fields.metadata as Record<string, unknown> ?? {}),
      };
      shadowOutcome = evaluateShadowRules(config.policyRules, promptText, "prompt", evalCtx);
    }

    // Canonical decision record (ADR-2): commit exactly what this decision
    // ran over — rules hash, gate state, evaluated-text digest, scope ids,
    // hook disposition. Additive fields; never part of the chain preimage.
    const decisionInput = buildDecisionInput({
      rulesHash: policyVersion,
      degraded: degraded.degraded,
      degradedReason: degraded.reason,
      target: "request",
      evaluatedText: decisionEvaluatedText,
      userId: audit_fields.user_id || ctx.options.user_id || undefined,
      serviceName:
        audit_fields.service_name || ctx.options.service_name || config.default_service_name || undefined,
      hook: hookDisposition,
    });

    // Build compliance context - shared by all events in this call
    const compliance: ComplianceCtx = {
      eventType: "llm_call",
      policyVersion,
      actionTaken,
      actionReason,
      actionSource,
      redactedTypes,
      blockedTypes,
      ruleId,
      policyReason,
      shadowOutcome,
      decisionInputHash: computeDecisionInputHash(decisionInput),
      engineVersion: ENGINE_VERSION,
      externalBackend,
    };

    // Emit this call's audit event? Enforcement already ran unconditionally
    // above; sampling only thins the record of *allowed* calls. Blocked/redacted
    // (enforcement actions) and errors are always recorded, so a low sample_rate
    // never hides a policy action.
    const auditThisCall = shouldAudit || compliance.actionTaken !== "allowed";

    // 3. Block: emit a forensic audit record, then throw.
    //    Prompt is stored in redacted form (typed placeholders, not raw PII).
    if (actionTaken === "blocked") {
      let blockedModel = "unknown";
      try {
        if (provider === "anthropic") {
          blockedModel = extractAnthropicModel(cleaned_args[0] as AnthropicMessagesRequest);
        } else if (provider === "google") {
          blockedModel = extractGeminiModel(cleaned_args[0] as GeminiRequest, modelHint);
        } else {
          blockedModel = extractOpenAIModel(cleaned_args[0] as OpenAIChatRequest);
        }
      } catch { /* model is best-effort for blocked events */ }

      // A canary leak must never persist the raw token (redactBuiltinPii does
      // not know the canary format, so the whole stored copy is a placeholder).
      const redactedPrompt = canaryFloor
        ? CANARY_REDACTION_PLACEHOLDER
        : actionReason === "pii_detected"
          ? redactForStorage(extractPromptTextFromArgs(cleaned_args[0]), piiScanVia)
          : "[BLOCKED_BY_POLICY]";

      const blockedEvent: AuditEvent = {
        request_id: audit_fields.request_id || generateUUID(),
        environment: config.environment,
        service_name:
          audit_fields.service_name ||
          ctx.options.service_name ||
          config.default_service_name ||
          undefined,
        region:
          audit_fields.region ||
          ctx.options.region ||
          config.default_region ||
          "unknown",
        user_id: audit_fields.user_id || ctx.options.user_id || undefined,
        client_ip: audit_fields.client_ip || undefined,
        user_agent: audit_fields.user_agent || undefined,
        provider,
        model: blockedModel,
        operation: methodPath,
        source:
          audit_fields.source ||
          ctx.options.source ||
          config.default_source ||
          "proxy_wrapper",
        prompt: redactedPrompt,
        response: "",
        user_input: canaryFloor
          ? CANARY_REDACTION_PLACEHOLDER
          : redactForStorage(extractLastUserMessageText(cleaned_args[0]), piiScanVia),
        latency_ms: 0,
        success: false,
        status_code: 403,
        error_type: null,
        metadata: audit_fields.metadata,
        event_type: "blocked_call",
        policy_version: policyVersion,
        action_taken: "blocked",
        action_reason: actionReason,
        action_source: actionSource,
        redacted_types: redactedTypes,
        blocked_types: blockedTypes,
        rule_id: ruleId,
        policy_reason: policyReason,
        // Canonical decision record (ADR-2, additive)
        decision_input_hash: compliance.decisionInputHash,
        engine_version: compliance.engineVersion,
        // External policy backend provenance (ADR-4, additive)
        external_backend: compliance.externalBackend,
      };
      sendAuditAsync(config, blockedEvent);
      debugLog(
        config,
        "info",
        `Request blocked (${actionReason}): ${blockedEvent.request_id}`,
      );
      throw new Error(
        `[obsvr] Request blocked by policy (${actionReason === "pii_detected" ? "PII detected" : "policy violation"})`,
      );
    }

    // Check for streaming - compliance boundary has already run above.
    const firstArg = cleaned_args[0];
    if (
      typeof firstArg === "object" &&
      firstArg !== null &&
      (firstArg as Record<string, unknown>).stream === true
    ) {
      if (config.streaming_mode === "skip") {
        debugLog(config, "info", `Skipping streaming request: ${methodPath}`);
        return originalMethod.apply(target, cleaned_args);
      }
      // "wrap" mode: call through, wrap the returned AsyncIterable, audit on completion
      const streamStart = performance.now();
      let streamResp: unknown;
      try {
        streamResp = await originalMethod.apply(target, cleaned_args);
      } catch (error) {
        const latencyMs = Math.round(performance.now() - streamStart);
        try {
          const statusCode =
            (error as any)?.status ?? (error as any)?.statusCode ?? 500;
          const auditEvent = buildAuditEvent(
            ctx,
            cleaned_args[0],
            null,
            audit_fields,
            latencyMs,
            provider,
            false,
            error,
            statusCode,
            modelHint,
            compliance,
          );
          sendAuditAsync(config, auditEvent);
          debugLog(
            config,
            "info",
            `Audit event queued (stream-error): ${auditEvent.request_id}`,
          );
        } catch {
          /* swallow */
        }
        throw error;
      }
      if (isAsyncIterable(streamResp)) {
        // Not sampled + no policy action → return the raw stream; enforcement
        // already ran, and post-call scanning is audit-only for streams.
        return auditThisCall
          ? wrapStreamingIterator(
              streamResp,
              cleaned_args[0],
              audit_fields,
              ctx,
              provider,
              streamStart,
              modelHint,
              compliance,
            )
          : streamResp;
      }
      // Unexpected non-iterable response - fall through to normal audit below
      const streamLatency = Math.round(performance.now() - streamStart);
      if (auditThisCall) try {
        const auditEvent = buildAuditEvent(
          ctx,
          cleaned_args[0],
          streamResp,
          audit_fields,
          streamLatency,
          provider,
          true,
          undefined,
          undefined,
          modelHint,
          compliance,
        );
        await applyPostCallGovernance(auditEvent, config);
        sendAuditAsync(config, auditEvent);
        debugLog(
          config,
          "info",
          `Audit event queued: ${auditEvent.request_id}`,
        );
      } catch (auditErr) {
        debugLog(
          config,
          "error",
          "Failed to build audit event:",
          auditErr instanceof Error ? auditErr.message : String(auditErr),
        );
      }
      return streamResp;
    }

    // Time the LLM call
    const startTime = performance.now();
    let response: unknown;

    try {
      // Call the original method with cleaned args
      response = await originalMethod.apply(target, cleaned_args);
    } catch (error) {
      // Calculate latency even on error
      const latencyMs = Math.round(performance.now() - startTime);

      // Attempt to audit the failed request (V2: with error info)
      try {
        const statusCode =
          (error as any)?.status ?? (error as any)?.statusCode ?? 500;
        const auditEvent = buildAuditEvent(
          ctx,
          cleaned_args[0],
          null, // No response on error
          audit_fields,
          latencyMs,
          provider,
          false, // success = false
          error,
          statusCode,
          modelHint,
          compliance,
        );

        sendAuditAsync(config, auditEvent);
        debugLog(
          config,
          "info",
          `Audit event queued (error): ${auditEvent.request_id}`,
        );
      } catch (auditError) {
        // Swallow audit errors - never affect LLM flow
        debugLog(
          config,
          "error",
          "Failed to audit error:",
          auditError instanceof Error ? auditError.message : String(auditError),
        );
      }

      // Re-throw the original error exactly
      throw error;
    }

    const latencyMs = Math.round(performance.now() - startTime);

    // Check for streaming response (user passed stream option without the flag)
    if (isAsyncIterable(response)) {
      if (config.streaming_mode === "wrap" && auditThisCall) {
        return wrapStreamingIterator(
          response,
          cleaned_args[0],
          audit_fields,
          ctx,
          provider,
          startTime,
          modelHint,
          compliance,
        );
      }
      debugLog(
        config,
        "info",
        `Streaming response detected, skipping audit: ${methodPath}`,
      );
      return response;
    }

    // Build and send audit event (fire-and-forget) (V2: with provider and success)
    if (auditThisCall) try {
      const auditEvent = buildAuditEvent(
        ctx,
        cleaned_args[0],
        response,
        audit_fields,
        latencyMs,
        provider,
        true, // success = true
        undefined,
        undefined,
        modelHint,
        compliance,
      );

      await applyPostCallGovernance(auditEvent, config);
      sendAuditAsync(config, auditEvent);
      debugLog(config, "info", `Audit event queued: ${auditEvent.request_id}`);
    } catch (auditError) {
      // Swallow audit errors - never affect LLM flow
      debugLog(
        config,
        "error",
        "Failed to build audit event:",
        auditError instanceof Error ? auditError.message : String(auditError),
      );
    }

    return response;
  };
}

/**
 * Check if a method path should be audited
 */
function isAuditablePath(path: string[]): boolean {
  const pathStr = path.join(".");
  return AUDITABLE_METHODS.has(pathStr);
}

/**
 * Create a recursive proxy for the client
 */
function createRecursiveProxy<T extends object>(
  target: T,
  ctx: PathContext,
): T {
  return new Proxy(target, {
    get(obj, prop: string | symbol) {
      // Check for wrapped marker (symbol)
      if (prop === WRAPPED_MARKER) {
        return true;
      }

      // Handle other symbol properties (like Symbol.toStringTag)
      if (typeof prop === "symbol") {
        return Reflect.get(obj, prop);
      }

      const value = Reflect.get(obj, prop);

      // Non-existent or primitive values pass through
      if (value === undefined || value === null) {
        return value;
      }

      // Track the path
      const newPath = [...ctx.path, prop];

      // If it's a function
      if (typeof value === "function") {
        // Check if this is an auditable method
        if (isAuditablePath(newPath)) {
          debugLog(
            ctx.config,
            "info",
            `Wrapping auditable method: ${newPath.join(".")}`,
          );
          return createAuditedMethod(
            value,
            obj,
            { ...ctx, path: newPath },
            ctx.provider,
          );
        }

        // Return bound function for non-auditable methods
        return value.bind(obj);
      }

      // If it's an object, wrap recursively
      if (typeof value === "object") {
        return createRecursiveProxy(value as object, { ...ctx, path: newPath });
      }

      // Primitives pass through
      return value;
    },

    // Pass through other traps
    set(obj, prop, value) {
      return Reflect.set(obj, prop, value);
    },

    has(obj, prop) {
      if (prop === WRAPPED_MARKER) {
        return true;
      }
      return Reflect.has(obj, prop);
    },

    ownKeys(obj) {
      return Reflect.ownKeys(obj);
    },

    getOwnPropertyDescriptor(obj, prop) {
      return Reflect.getOwnPropertyDescriptor(obj, prop);
    },
  });
}

/**
 * Wrap an LLM client for automatic audit tracking
 *
 * @param client - The LLM client instance (e.g., new OpenAI())
 * @param options - Optional configuration for this wrapped client
 * @returns The wrapped client with the same interface
 */
export function wrap<T extends object>(
  client: T,
  options: WrapOptions = {},
): T {
  const config = getConfig();

  // If disabled, return original client
  if (config.disabled) {
    // L-1: Use console.warn so misconfiguration is visible without debug mode
    console.warn("[obsvr] Audit disabled, returning unwrapped client. No events will be captured.");
    return client;
  }

  // Check for double-wrapping
  if (isWrapped(client) || (client as any)[WRAPPED_MARKER]) {
    debugLog(config, "warn", "Client already wrapped, returning existing");
    return client;
  }

  // Detect provider for logging and V2 event data
  const provider = detectProvider(client);
  debugLog(config, "info", `Wrapping ${provider} client`);

  // Create context with provider (V2)
  const ctx: PathContext = {
    path: [],
    options,
    config,
    provider,
  };

  // Setup exit handlers (once)
  setupExitHandlers(config);

  // Create the proxy
  const wrapped = createRecursiveProxy(client, ctx);

  // Mark as wrapped
  markWrapped(client);
  markWrapped(wrapped);

  return wrapped;
}
