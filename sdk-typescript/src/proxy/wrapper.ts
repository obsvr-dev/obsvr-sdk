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
import { getConfig, isInitialized, isWrapped, markWrapped, isPolicyEnforcementDegraded } from "./config.js";
import { evaluatePolicyHook, redactBuiltinPii, resolvePiiPolicy, runBuiltinPiiScan } from "../policy/hook.js";
import type { PolicyDecisionResult } from "../policy/hook.js";
import {
  applyOutboundRedaction,
  applyOutboundRedactionAsync,
  describeError,
  detectorFailureRecord,
  recordCheckOnlyFailure,
  recordDetectorFailure,
  safeStoredCopy,
  type DetectorFailure,
} from "../policy/detector-guard.js";
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
  scrubCanaryForStorage,
  redactUnscannedForStorage,
} from "../policy/stored-content.js";
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
import { scoreTurn, formatMultiTurnReason } from "../policy/injection-session.js";
import { requestApproval, revalidateApproval } from "../policy/approvals.js";
import { resolveCallCost, resolveCostPolicy, costMetadata } from "../governance/cost.js";
import { recordTokenUsageForRules, stampCost } from "../governance/metering.js";
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
import {
  applyPostCallPolicy,
  mergePostCallOutcome,
  emitIntegrationEvent,
} from "../integrations/core.js";
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
import { readTokenUsage } from "./extractors/token-usage.js";
import { createDeferredRunner, type RunnerLike } from "./runner-wrapper.js";
import { governRunnerTools, type RunnerToolGateReport } from "./runner-tool-gate.js";
import {
  observeOpenAIToolRun,
  driveAnthropicToolRun,
  type ToolRunSink,
} from "./tool-runner-wrapper.js";
import {
  sendAuditAsync,
  shouldSample,
  setupExitHandlers,
} from "./sender/index.js";
import { truncate } from "../utils/truncate.js";
import { debugLog } from "../utils/logger.js";
import { createPolicyError, resolveReasonCode } from "../policy/policy-error.js";
import { ReasonCode } from "../governance/reason-codes.js";
import { generateUUID } from "../utils/uuid.js";
import {
  resolveDestination,
  type CanonicalProvider,
} from "./provider-attribution.js";

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
  /** Registry reason code for the classification the decision rests on; the
   * deciding layer's own fine-grained code, never re-collapsed downstream. */
  reasonCode?: string;
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
  reasonCode: ReasonCode.PERMITTED,
  actionSource: "unknown",
  redactedTypes: [],
  blockedTypes: [],
};

/**
 * The payload shape a method path carries. This is what selects the extractor
 * — the path string never does. Two OpenAI surfaces speak different request
 * and response dialects (`messages[]`/`choices[]` vs `input`/`output[]`), and
 * an entry routed to the wrong one still produces a signed, chain-linked,
 * success:true event whose prompt and response are both the empty string,
 * because each extractor returns "" rather than throwing on a foreign shape.
 * Carrying the shape alongside the path makes that mismatch unrepresentable.
 */
type ApiShape =
  | "openai-chat"
  | "openai-responses"
  | "anthropic-messages"
  | "gemini-generate";

/**
 * Methods that should be audited, keyed by their nested path
 * Format: "namespace.method" -> the payload shape that path carries
 *
 * COVERAGE BOUNDARY. wrap() governs TEXT-generation surfaces, and the boundary
 * has two halves that are different in kind:
 *
 * 1. EXCLUDED — no chat-shaped prompt/response text for the policy engine to
 *    evaluate: embeddings.create, images.generate, audio.*, files.*,
 *    fine_tuning.*, and the moderation/model-listing surfaces. These are
 *    deliberately ungoverned and unaudited; do not assume wrap() covers them.
 *
 * 2. TEXT-BEARING BUT NOT COVERED — chat-shaped, and out of reach of a method
 *    path table rather than out of policy. Recorded here so the gap is a known
 *    one rather than an assumed absence:
 *      - the batch surfaces (messages.batches.create and its beta twin), which
 *        carry N independent prompts per call against an event schema with one
 *        prompt field.
 *      - countTokens / messages.countTokens, which carry full prompt text but
 *        return only an integer, so half the evidence a governed event records
 *        does not exist.
 *      - Gemini generateContentStream, whose result object is not itself an
 *        async iterable, and startChat(), whose ChatSession calls a
 *        module-level generateContent rather than a property on the model —
 *        so no property read on the proxy ever happens and NO path table can
 *        reach it.
 *
 * 3. COVERED, BUT NOT FROM THIS TABLE. The `.stream()` helpers and the tool
 *    runners return a runner object SYNCHRONOUSLY, and createAuditedMethod is
 *    async, so listing them above would hand the caller a Promise and break
 *    `.on(...)` chaining. They are governed through the deferred runner
 *    instead — see STREAM_RUNNER_METHODS and TOOL_RUNNER_METHODS below. A
 *    reader checking whether a surface is covered must consult all three
 *    tables, not this one alone.
 */
const AUDITABLE_METHODS = new Map<string, ApiShape>([
  ["chat.completions.create", "openai-chat"], // OpenAI / Azure OpenAI
  ["chat.completions.parse", "openai-chat"], // OpenAI structured outputs
  ["messages.create", "anthropic-messages"], // Anthropic
  ["messages.parse", "anthropic-messages"], // Anthropic structured outputs
  ["generateContent", "gemini-generate"], // Google Gemini
  ["responses.create", "openai-responses"], // OpenAI Responses API
  ["responses.parse", "openai-responses"], // OpenAI Responses structured outputs
  // The beta namespaces carry exactly the payload their GA twin carries, so
  // they are governed identically. They are enumerated rather than matched by
  // stripping a leading "beta." segment: a strip rule would auto-govern every
  // future beta.* namespace a provider ships without review, which is the
  // inverse of the boundary above, and it reaches only these two of the
  // text-bearing gaps listed in half 2.
  ["beta.messages.create", "anthropic-messages"], // Anthropic beta
  ["beta.responses.create", "openai-responses"], // OpenAI Responses beta
  ["beta.chat.completions.create", "openai-chat"], // OpenAI chat beta
  ["beta.chat.completions.parse", "openai-chat"], // OpenAI chat beta
]);

/**
 * The provider `.stream()` helpers, which return a runner object SYNCHRONOUSLY.
 *
 * Chat-shaped and text-bearing, but they could not go in AUDITABLE_METHODS:
 * createAuditedMethod is async, so listing them there would hand the caller a
 * Promise where the provider's contract promises a stream object, breaking
 * `.on('text', …)` chaining at every call site. They are governed through the
 * deferred runner instead, which satisfies the synchronous contract while still
 * running the full pre-call pipeline BEFORE the provider is reached.
 *
 * `final` names the accessor that yields the completed response once the run
 * ends. It is the same payload the non-streaming extractor for that dialect
 * already reads, so no new extraction is involved.
 */
const STREAM_RUNNER_METHODS = new Map<string, { shape: ApiShape; final: string }>([
  ["messages.stream", { shape: "anthropic-messages", final: "finalMessage" }],
  ["beta.messages.stream", { shape: "anthropic-messages", final: "finalMessage" }],
  ["chat.completions.stream", { shape: "openai-chat", final: "finalChatCompletion" }],
  ["responses.stream", { shape: "openai-responses", final: "finalResponse" }],
]);

/**
 * The provider TOOL RUNNERS, which return their runner object synchronously
 * like the `.stream()` helpers above but drive a LOOP rather than one call.
 *
 * They are listed separately because one event cannot describe them honestly: a
 * single invocation makes N model calls and M tool executions, so a
 * start-to-finish event would record the first prompt and the last answer while
 * hiding every intermediate decision — including which tools ran and what they
 * returned. Each therefore emits one event per model call, one per tool call,
 * and a run-level start/finish pair sharing an `agent_run_id`, following the
 * agent-run precedent the `@openai/agents` integration already established.
 *
 * `thenable` records whether the REAL runner is awaitable, because the stand-in
 * must mirror it and is wrong in a different direction either way — see
 * `DeferredRunnerHooks.thenable`. Anthropic's tool runner documents `await
 * runner` as equivalent to `runUntilDone()`; OpenAI's runner is not a thenable.
 */
const TOOL_RUNNER_METHODS = new Map<
  string,
  { shape: ApiShape; dialect: "openai-chat" | "anthropic-messages"; thenable: boolean }
>([
  ["chat.completions.runTools", { shape: "openai-chat", dialect: "openai-chat", thenable: false }],
  [
    "beta.messages.toolRunner",
    { shape: "anthropic-messages", dialect: "anthropic-messages", thenable: true },
  ],
]);

/**
 * The payload shape for a traversed method path, or undefined when the path is
 * not audited. Callers that need "is this the Responses dialect" must ask this
 * rather than comparing the path string, so beta and structured-output aliases
 * reach the same extractor as the surface they alias.
 */
function apiShapeFor(operation: string): ApiShape | undefined {
  return (
    AUDITABLE_METHODS.get(operation) ??
    STREAM_RUNNER_METHODS.get(operation)?.shape ??
    TOOL_RUNNER_METHODS.get(operation)?.shape
  );
}

/**
 * Symbol to mark wrapped objects
 */
const WRAPPED_MARKER = Symbol("obsvr-wrapped");

/**
 * Track the current method path during proxy traversal
 */
/**
 * One step deeper in the property path.
 *
 * Prototype-linked rather than spread, and that is the whole point: `config` on
 * the root context is a live accessor, and `{ ...ctx }` would evaluate it once
 * and freeze the result into the child. Inheriting keeps every level of a
 * traversal reading the config that is current when the call is made, at any
 * depth, without this having to know which fields a context carries.
 */
function atPath(ctx: PathContext, path: string[]): PathContext {
  const child = Object.create(ctx) as PathContext;
  child.path = path;
  return child;
}

type PathContext = {
  path: string[];
  options: WrapOptions;
  config: ResolvedConfig;
  /**
   * The client's API SHAPE, from duck-typing. Selects the prompt/response
   * extractors and the request-building branches. This is a question about the
   * object, not about the network.
   */
  provider: "openai" | "anthropic" | "google" | "unknown";
  /**
   * The DESTINATION, for the record. Derived from the client's base URL when it
   * can be read; falls back to the shape above when it cannot.
   *
   * Kept separate from `provider` on purpose. One variable was answering two
   * different questions — which extractor to use, and which vendor to name in
   * the audit event — and the second answer was wrong for every client pointed
   * somewhere other than its shape implied. An OpenAI-shaped client against a
   * local server recorded `provider: "openai"`; collapsing these back into one
   * field would also break extraction for an Anthropic-shaped client on a
   * non-vendor host, which is the trap that keeps them apart.
   */
  recordedProvider: CanonicalProvider;
  /** Reserved metadata: where the call goes, and how sure of it we are. */
  providerAttribution: Record<string, unknown>;
};

/**
 * Stamp destination attribution onto event metadata.
 *
 * Applied LAST and deliberately winning: it describes where the call went,
 * which is not a caller-supplied opinion. Letting per-request metadata shadow
 * it would drop the destination evidence exactly when a caller attaches
 * metadata of their own.
 */
function withProviderAttribution(
  md: Record<string, unknown> | undefined,
  ctx: PathContext,
): Record<string, unknown> | undefined {
  const attribution = ctx.providerAttribution;
  if (!attribution || Object.keys(attribution).length === 0) return md;
  return { ...(md ?? {}), ...attribution };
}

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
 * Redact PII across every message/prompt content field of the OUTBOUND request.
 * Preserves message structure; replaces only PII text within content strings
 * with typed placeholders (e.g. [REDACTED_EMAIL]).
 *
 * **It writes only onto objects this SDK owns.** The top-level request handed in
 * is a fresh object built by `filterArgs`, so assigning its own keys is safe —
 * but that copy is SHALLOW, so `req.messages` is the caller's array and each
 * element is the caller's message object. Walking into them and assigning
 * `msg.content` rewrote the caller's data: a conversation history is normally an
 * array the application keeps and appends to, so one redacted turn left the
 * application holding `[REDACTED_SSN]` where it believed it still had the real
 * text, and every later turn sent the placeholder. The shallow copy is what made
 * this easy to miss — `system`, `instructions` and a string `input` land on the
 * new object and were always safe, so the function looked correct on the fields
 * most likely to be spot-checked.
 *
 * Every nested container it modifies is therefore rebuilt rather than written
 * through. Identity of the outbound structures is not observable by the caller,
 * whose own objects are precisely what must not change, and this runs only on
 * the redact path.
 *
 * A consequence worth stating, because it moved a documented fail mode: a FROZEN
 * or otherwise unwritable caller message is no longer an application failure. It
 * used to make the in-place write throw, which resolved closed and refused the
 * call — obsvr blocking a caller for protecting the very object obsvr was about
 * to corrupt. Copying redacts it successfully instead. Application failure still
 * fails closed; what changed is what counts as one.
 */
function redactMessagesInPlace(args: unknown): void {
  if (!args || typeof args !== "object") return;
  const req = args as Record<string, unknown>;

  /** Redact a `{text}` part list into a NEW array of NEW parts. */
  const redactTextParts = (parts: unknown[]): unknown[] =>
    parts.map((part) => {
      if (!part || typeof part !== "object") return part;
      const p = part as Record<string, unknown>;
      if (typeof p.text !== "string") return part;
      return { ...p, text: redactBuiltinPii(p.text) };
    });

  /** Redact a `.content` carrier (string or part list) into a NEW object. */
  const redactContentCarrier = (entry: unknown): unknown => {
    if (!entry || typeof entry !== "object") return entry;
    const e = entry as Record<string, unknown>;
    if (typeof e.content === "string") {
      return { ...e, content: redactBuiltinPii(e.content) };
    }
    if (Array.isArray(e.content)) {
      return { ...e, content: redactTextParts(e.content) };
    }
    return entry;
  };

  if (typeof req.system === "string") {
    req.system = redactBuiltinPii(req.system);
  }

  if (Array.isArray(req.messages)) {
    req.messages = (req.messages as unknown[]).map(redactContentCarrier);
  }

  if (Array.isArray(req.contents)) {
    req.contents = (req.contents as unknown[]).map((c) => {
      if (!c || typeof c !== "object") return c;
      const cObj = c as Record<string, unknown>;
      if (!Array.isArray(cObj.parts)) return c;
      return { ...cObj, parts: redactTextParts(cObj.parts) };
    });
  }

  // OpenAI Responses API: instructions + input (string or item list)
  if (typeof req.instructions === "string") {
    req.instructions = redactBuiltinPii(req.instructions);
  }
  if (typeof req.input === "string") {
    req.input = redactBuiltinPii(req.input);
  } else if (Array.isArray(req.input)) {
    req.input = (req.input as unknown[]).map(redactContentCarrier);
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

  // Determine operation from method path. The extractor for OpenAI-shaped
  // clients (Chat Completions vs Responses API) is selected from the path's
  // recorded shape, not from the path string, so beta and structured-output
  // aliases land on the same extractor as the surface they alias.
  const operation = ctx.path.join(".");
  const shape = apiShapeFor(operation);

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
  } else if (shape === "openai-responses") {
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

  // Curated call telemetry (telemetry design notes, milestone 1): request shape,
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

    // Identity fields — per-call audit fields win, then wrap-time options,
    // then the ambient useSubject() scope (the same resolution the
    // integration event builder and the session-taint key already use).
    user_id: auditFields.user_id || options.user_id || getCurrentSubject()?.user_id || undefined,

    // Network fields (passed through to server for masking)
    client_ip: auditFields.client_ip || undefined,
    user_agent: auditFields.user_agent || undefined,

    // LLM Call fields. `ctx.recordedProvider` is the destination; the local
    // `provider` above is the client's shape and stays with the extractors.
    provider: ctx.recordedProvider,
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
    // ABSENT when the failure carried no HTTP status. A client-side failure —
    // a stream whose payload would not parse, a socket that died mid-response —
    // has no status code, and defaulting to 500 asserted a server error the
    // provider never sent. Measured: a malformed SSE chunk after a 200 response
    // was recorded as a provider 500. `success: false` and `error_type` already
    // carry the failure; the status field says only what the wire said.
    status_code: success ? 200 : errorStatusCode,
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
    metadata: withProviderAttribution(
      withRunMetadata(
        withSpanMetadata(
          withTelemetryMetadata(auditFields.metadata, callTelemetry),
          spanEnv,
        ),
      ) as Record<string, unknown> | undefined,
      ctx,
    ),

    // Compliance fields
    event_type: compliance.eventType,
    policy_version: compliance.policyVersion,
    action_taken: compliance.actionTaken,
    action_reason: compliance.actionReason,
    reason_code: compliance.reasonCode,
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

  // M-5: PII-scan error messages when pii_policy is configured. This builds a
  // STORED field, so a redactor defect resolves the stored-copy way: withhold
  // it under the unscanned marker rather than persist a provider error string
  // nothing scanned. The call has already failed here - there is nothing left
  // to block, and the host must not receive a second error from the audit path.
  if (error && event.error_message && config.pii_policy) {
    const rawErrorMessage = event.error_message;
    event.error_message = safeStoredCopy(() => redactBuiltinPii(rawErrorMessage));
  }

  // Cost governance: record this call's token usage against any token-unit
  // quota rules so their pre-call budget checks reflect consumption.
  // (Tokens are only known post-call; budgets are approximate by design.)
  if (success && event.total_tokens) {
    recordTokenUsageForRules(config, event);
  }

  // Layered cost: the caller's estimate, the operator's declared override, and
  // the metered figure from real usage at the operator's own rates - all three
  // kept, because the gap between the estimate and the correction is the part
  // an auditor can act on. Stamped LAST so a caller metadata key collision
  // cannot overwrite it, and only when a cost policy is configured (absent
  // policy leaves existing events byte-identical).
  stampCost(config, event);

  applyStoredContentNet(event, config, extractLastUserMessageText(request));

  return event;
}

/**
 * The stored-content net, applied in place to a finished event.
 *
 * This is the seam the `wrap()` path did not have and the integration path
 * did. It runs LAST, after truncation, so it vets exactly the bytes that will
 * be signed and shipped — a net upstream of truncation vets text the record
 * never carries and misses text it does.
 *
 * Order is load-bearing: PII first, canary second. `redactBuiltinPii` does not
 * know the canary format, so a token surviving a PII pass must still meet the
 * canary scrub; reversing them would let a placeholder-substituted field be
 * re-expanded by nothing and a real token slip through on the field the PII
 * pass rewrote.
 */
function applyStoredContentNet(
  event: AuditEvent,
  config: ResolvedConfig,
  scannedText: string,
): void {
  const onScanFailure = (err: unknown): void => {
    recordDetectorFailure("canary", err, config);
  };

  // 1. "still stored (and redacted if configured)" — make it true for the
  //    roles the decision scan never reached.
  const unscanned = redactUnscannedForStorage(
    event.prompt,
    scannedText,
    config,
    (err) => recordDetectorFailure("builtin_pii_scan", err, config),
  );
  event.prompt = unscanned.prompt;

  // 2. "the raw secret never lives at rest ... never rides an event" — the one
  //    absolute canary.ts states about storage, on every path and every verdict.
  const scrubbed = scrubCanaryForStorage(
    {
      prompt: event.prompt,
      response: event.response,
      ...(event.user_input !== undefined ? { userInput: event.user_input } : {}),
    },
    onScanFailure,
  );
  event.prompt = scrubbed.content.prompt;
  event.response = scrubbed.content.response;
  if (scrubbed.content.userInput !== undefined) {
    event.user_input = scrubbed.content.userInput;
  }

  const telemetry = {
    ...(unscanned.telemetry ?? {}),
    ...(scrubbed.telemetry ?? {}),
    ...(scrubbed.scanFailed ? { canary_storage_scan_failed: true } : {}),
  };
  if (Object.keys(telemetry).length === 0) return;

  const md = (event.metadata as Record<string, unknown> | undefined) ?? {};
  event.metadata = {
    ...md,
    obsvr_telemetry: {
      ...((md.obsvr_telemetry as Record<string, unknown> | undefined) ?? {}),
      ...telemetry,
    },
  };
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
    // Whether the provider's stream ran out, as opposed to the caller walking
    // away from it. `finally` below runs either way — including on the early
    // `return()` a `break` triggers — so without this the two are
    // indistinguishable and an abandoned stream is recorded as a completed one.
    let drained = false;
    try {
      for await (const chunk of iter) {
        if (firstChunkTime === null) {
          firstChunkTime = performance.now();
        }
        chunks.push(chunk);
        yield chunk;
      }
      drained = true;
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
              tokenUsage = readTokenUsage(chunk.usageMetadata) ?? tokenUsage;
            }
            if (typeof chunk.modelVersion === "string" && chunk.modelVersion.trim().length > 0) {
              modelResolved = chunk.modelVersion.trim();
            }
          }
          model = extractGeminiModel(request as GeminiRequest, modelHint); // uses modelHint from target.model if available
        } else if (apiShapeFor(ctx.path.join(".")) === "openai-responses") {
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
        } else if (apiShapeFor(operation) === "openai-responses") {
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
          user_id: auditFields.user_id || options.user_id || getCurrentSubject()?.user_id || undefined,
          client_ip: auditFields.client_ip || undefined,
          user_agent: auditFields.user_agent || undefined,
          // The destination, not the client's shape — see PathContext.
          provider: ctx.recordedProvider,
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
          // Absent when the stream failed without a status. This is the site
          // that recorded a malformed SSE chunk — a client-side parse failure
          // after a 200 response — as a provider 500.
          status_code:
            streamError === null
              ? 200
              : ((streamError as any)?.status ??
                (streamError as any)?.statusCode ??
                undefined),
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
          metadata: (() => {
            const md = withProviderAttribution(
              withRunMetadata(
                withSpanMetadata(
                  withTelemetryMetadata(
                    auditFields.metadata,
                    extractCallTelemetry(provider, request, undefined),
                  ),
                  spanEnvelopeFor("llm_call", operation),
                ),
              ) as Record<string, unknown> | undefined,
              ctx,
            );
            // An abandoned stream is not a failure — the provider answered and
            // the caller stopped reading — so `success` stays true. But it is
            // not a COMPLETED response either, and an event that says nothing
            // reads as one: the captured text is whatever arrived before the
            // caller walked away, and the token counts (which arrive last)
            // are missing for a reason that is not "the provider omitted
            // them". Same reserved channel and same reason as
            // detector_failure and quota_unmetered.
            if (streamError === null && !drained) {
              const base = (md ?? {}) as Record<string, unknown>;
              return {
                ...base,
                obsvr_telemetry: {
                  ...((base.obsvr_telemetry as Record<string, unknown>) ?? {}),
                  stream_incomplete: {
                    reason: "caller stopped consuming the stream",
                    chunks_captured: chunks.length,
                  },
                },
              };
            }
            return md;
          })(),

          // Compliance fields
          event_type: compliance.eventType,
          policy_version: compliance.policyVersion,
          action_taken: compliance.actionTaken,
          action_reason: compliance.actionReason,
          reason_code: compliance.reasonCode,
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

        // M-5: PII-scan error messages when pii_policy is configured. Same
        // stored-copy rule as the non-streaming path above.
        if (streamError && streamAuditEvent.error_message && config.pii_policy) {
          const rawStreamError = streamAuditEvent.error_message;
          streamAuditEvent.error_message = safeStoredCopy(() =>
            redactBuiltinPii(rawStreamError),
          );
        }

        // EV-1 post_call phase on the accumulated stream text (skips itself
        // on error events; parity with the Python streaming wrap).
        await applyPostCallGovernance(streamAuditEvent, config);

        // Meter streamed token usage against token-unit quota rules. Without
        // this, quota rules with quota_unit:"tokens" under-count by exactly the
        // streaming traffic (buildAuditEvent — which meters non-streaming calls
        // — is not used on the streaming completion path).
        recordTokenUsageForRules(config, streamAuditEvent);

        // Same stored-content net as buildAuditEvent. This path builds its own
        // event literal, so it has to be named here or the whole streaming
        // surface keeps the gap the non-streaming one just closed.
        applyStoredContentNet(
          streamAuditEvent,
          config,
          extractLastUserMessageText(request),
        );

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
/**
 * What the pre-call half hands to the post-call half.
 *
 * Only five values cross the boundary, which is why this split is a refactor
 * rather than a redesign: everything else the governance section computes is
 * consumed inside it.
 */
interface PreCallOutcome {
  /** Args with obsvr's own audit fields removed, and PII redacted in place. */
  cleaned_args: unknown[];
  /** The audit fields that were filtered OUT of the caller's arguments. */
  audit_fields: AuditFields;
  /** Whether an ALLOWED-call event should be emitted (sampling). Enforcement
   *  already ran regardless; this gates emission only. */
  auditThisCall: boolean;
  /** The compliance verdict this call was governed under. */
  compliance: ComplianceCtx;
  /** Google only: the model name read off the GenerativeModel instance. */
  modelHint: string | undefined;
  /**
   * The identity metadata the session-latch key was derived FROM — not the key.
   * A caller that has to key the same latch from a different point (the tool
   * runner gates tool callbacks, which is a separate egress) passes this to the
   * one derivation function rather than reproducing the resolution. Sharing the
   * INPUT is what makes divergence impossible; sharing the rule would not.
   */
  taintIdentity: Record<string, unknown>;
}

/**
 * The pre-call half: everything from filtering the caller's arguments through
 * to the compliance verdict, ending immediately before the provider is
 * reached.
 *
 * Extracted so a caller that CANNOT await before returning — the provider
 * `.stream()` helpers, which hand back a runner object synchronously — can run
 * the identical governance pipeline rather than a reimplementation of it. Two
 * pipelines that must agree are two pipelines that will eventually disagree,
 * and this one decides whether a request is allowed to leave the process.
 *
 * BLOCKS BY THROWING. There is no early return in here and no "blocked" flag to
 * check: a refusal propagates out, so a caller that forgets to inspect a result
 * cannot accidentally proceed. (There is ONE throw at this function's own
 * nesting level, not two — an earlier commit message said two.)
 *
 * TWO ENTRY POINTS, DIFFERENT TIMING. This is called from
 * createAuditedMethod, which awaits it and then calls the provider, and from
 * createAuditedRunnerMethod, which returns a stand-in to the caller FIRST and
 * awaits this afterwards. The governance decision is identical on both; what
 * differs is only when the caller regains control. A change in here therefore
 * lands on both paths — including the one where the caller is already holding
 * an object by the time this resolves.
 */
async function governCall(
  args: unknown[],
  target: object,
  ctx: PathContext,
  provider: "openai" | "anthropic" | "google" | "unknown",
  methodPath: string,
): Promise<PreCallOutcome> {
  const { config } = ctx;
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

    // The last user turn is what every builtin gate decides on, and it was
    // being re-walked from the raw request eight times per governed call. The
    // walk is pure, so it is computed once and memoized — but the request is
    // MUTATED in place by outbound redaction, so the memo is explicitly
    // invalidated at each of those three sites rather than trusted for the
    // life of the call. A memo without that invalidation would hand the
    // post-redaction event builders the pre-redaction text and quietly restore
    // the raw PII this SDK had just removed.
    let lastUserTextMemo: string | undefined;
    const lastUserText = (): string =>
      (lastUserTextMemo ??= extractLastUserMessageText(cleaned_args[0]) ?? "");
    const invalidateLastUserText = (): void => {
      lastUserTextMemo = undefined;
    };

    // Canonical decision record (ADR-2): capture the evaluated text ONCE,
    // before any redaction the pipeline may apply in place, so the sealed
    // digest commits the text as presented to the decision pipeline.
    const decisionEvaluatedText = lastUserText();

    // Compliance boundary - runs for ALL calls, including streaming, before any LLM contact.
    // Builds one ComplianceCtx that is stamped on every audit event for this call.
    let actionTaken: ComplianceCtx["actionTaken"] = "allowed";
    let actionReason: ComplianceCtx["actionReason"] = "none";
    let actionSource: ComplianceCtx["actionSource"] = "unknown";
    // The deciding layer's own registry code. Set wherever a layer knows its
    // classification (the rules engine returns one per rule type); anything
    // still undecided at event-build time falls back to the same derivation
    // the thrown error uses, so the two can never disagree.
    let reasonCode: string | undefined;
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

    // Hoisted above the guard: the code after this section reads these,
    // and a try block would otherwise scope them away.
    let floorBlock = false;
    let floorOverrideIgnored: { rule_id?: string; attempted: "allow" | "redact" } | undefined;
    let floorActive = false;
    let ruleId: string | undefined;
    let policyReason: string | undefined;
    // Same reason, one step earlier: the session-taint key and sub-config are
    // set by the first step INSIDE the guard and read by the canary, PII and
    // multi-turn steps further down it. A throw before the key is derived
    // jumps to the catch, so every later read is unreachable, not empty.
    let taintCfg: ReturnType<typeof resolveSessionTaint>;
    let taintKey = "";
    // The identity metadata the latch key was derived FROM, not the key. The
    // tool-runner path needs to key the same latch from a different call site,
    // and `deriveSessionKey`'s own contract is that SET and ENFORCE must agree
    // or the latch silently no-ops — so what travels is the input to the one
    // derivation rule, never a second copy of the rule.
    let taintIdentity: Record<string, unknown> = {};
    // A redaction that could not be applied. Set by either redact branch (the
    // builtin one inside the span, the hook one below it) and stamped on the
    // event at the end, so the record says the call was blocked because
    // enforcement could not be applied - never that it was redacted.
    let outboundRedactionFailure: DetectorFailure | undefined;
    // The approval claim a live grant satisfied during rule evaluation, if any.
    // Re-checked below, after every layer that can delay the call.
    let approvalClaim: PolicyDecisionResult["approval_granted"];
    // --- guarded detector section ------------------------------------
    // A detector defect resolves here instead of escaping into the
    // caller's own provider call. A closed resolution drives the
    // wrapper's existing block path rather than adding a second throw.
    let layer = "";
    try {
      layer = "session_taint";
      // 0.5 Session taint latch: a session compromised on an earlier turn has
      //     its later egress (this LLM call) escalated. ENFORCE runs on PRIOR
      //     taint; SET happens at this call's detection points below. The taint
      //     key folds in the SAME identity channels the integrations path uses
      //     (per-call metadata, then wrap-level options.user_id, then the
      //     ambient useSubject() subject) so a session tainted on wrap() and one
      //     tainted on MCP/tools share a key — otherwise the cross-egress
      //     escalation silently no-ops for useSubject-identified sessions.
      taintCfg = resolveSessionTaint(config);
      const ambientSubject = getCurrentSubject();
      const rawTaintMeta = (audit_fields.metadata ?? {}) as Record<string, unknown>;
      const resolvedTaintUser =
        rawTaintMeta.user_id ?? audit_fields.user_id ?? ctx.options.user_id ?? ambientSubject?.user_id;
      const resolvedTaintTenant = rawTaintMeta.tenant_id ?? ambientSubject?.tenant_id;
      taintIdentity = {
        ...rawTaintMeta,
        ...(resolvedTaintUser !== undefined ? { user_id: resolvedTaintUser } : {}),
        ...(resolvedTaintTenant !== undefined ? { tenant_id: resolvedTaintTenant } : {}),
      };
      taintKey = deriveSessionKey(taintIdentity);
      // 0.4 Required principal (opt-in): an unattributed call is refused
      //     before any scanning layer runs — the refusal is about
      //     attribution, not content. Runs after the enforcement-integrity
      //     gate so a paused project keeps its own verdict and rule id. The
      //     identity read is `resolvedTaintUser` — the same per-call
      //     metadata → wrap-time option → ambient-subject resolution the
      //     taint key and the signed event use, so the channel that refuses
      //     is the channel that would have attributed. An empty string is a
      //     supplied principal; only an absent one refuses (Python parity).
      if (
        actionTaken !== "blocked" &&
        config.requirePrincipal === true &&
        resolvedTaintUser == null
      ) {
        actionTaken = "blocked";
        actionReason = "policy_violation";
        actionSource = "policy_rules";
        ruleIdOverride = "sdk:principal_required";
        policyReasonOverride =
          "requirePrincipal is set and the call carries no user_id on the enforcing channel";
        reasonCode = ReasonCode.PRINCIPAL_REQUIRED;
        debugLog(config, "warn", `Call blocked: ${policyReasonOverride}`);
      }
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
            // A taint-gated refusal of outbound egress: the session is
            // compromised, so this transmission does not leave the process.
            reasonCode = ReasonCode.TRANSMISSION_BLOCKED;
            debugLog(config, "warn", `Call blocked: ${policyReasonOverride}`);
          } else {
            if (actionReason === "none") actionReason = "policy_violation";
            actionSource = "policy_rules";
          }
        }
      }

      layer = "canary";
      // 0.75 Canary-leak scan (unsuppressible). A planted honeytoken echoed back
      //      in the user's message is a CRITICAL leak signal — block before the
      //      provider is contacted. Scans the last user turn (never the app's
      //      planted system prompt), and only when a canary was minted.
      if (canaryRegistrySize() > 0 && actionTaken !== "blocked") {
        const leak = scanForCanary(lastUserText());
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

      layer = "builtin_pii_scan";
      // 1. Built-in PII scan (runs before customer hook; skipped when the
      //    integrity gate already blocked the call)
      if (config.pii_policy && actionTaken !== "blocked") {
        const promptText = lastUserText();

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
            // The prompt_injection label rides the PII pipeline, but a block
            // it drove is an injection finding, not a PII finding — the
            // classification refines whenever the injection label is among
            // the block-level types.
            reasonCode = resolved.blockedTypes.includes("prompt_injection")
              ? ReasonCode.INJECTION_DETECTED
              : ReasonCode.PII_DETECTED;
          } else if (piiAction === "redact") {
            // Enforcement APPLICATION, not detection: the scan already found
            // something and policy already said remove it, so a failure here
            // blocks regardless of failMode rather than send the prompt on
            // unredacted. The enclosing guard would otherwise resolve it open.
            const notRedacted = await applyOutboundRedactionAsync(async () => {
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
            });
            // Both branches above rewrite the request in place.
            invalidateLastUserText();
            if (notRedacted) {
              actionTaken = "blocked";
              actionReason = "policy_violation";
              actionSource = "builtin";
              redactedTypes = []; // nothing was redacted; the record must not say otherwise
              ruleIdOverride = notRedacted.ruleId;
              policyReasonOverride = notRedacted.policyReason;
              outboundRedactionFailure = notRedacted.failure;
            } else {
              redactedTypes = resolved.redactedTypes;
              actionTaken = "redacted";
            }
          }
          // detect_only: reason/source set; action stays "allowed"
        }
      }

      layer = "multi_turn_injection";
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
        const promptText = lastUserText();
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
        // A QUOTED injection phrase is a weak signal, not a full match: text
        // that quotes an attack (a bug report, a fixture, a policy doc) is not
        // performing one. The detection is untouched — the scan still reports
        // `prompt_injection` and the event still fires — but it no longer
        // counts as the single-turn full match that scores 1.0 and lets turn 1
        // trip on its own. The phrase still accrues weak-signal score below, so
        // an attacker who wraps a payload in quotes gets a quieter line in the
        // log and nothing else.
        const injectionScan = runBuiltinPiiScan(promptText);
        const hadFullMatch = injectionScan.matches.some(
          (m) => m.label === "prompt_injection" && !m.quoted,
        );
        const mt = scoreTurn(sessionKey, promptText, hadFullMatch, {
          threshold: config.multiTurnInjection.threshold ?? 1.0,
          halfLifeMs: config.multiTurnInjection.halfLifeMs ?? 600_000,
        });
        // A full match is already handled by the single-turn scan above; the
        // multi-turn gate exists for the accumulation case.
        if (mt.tripped && !hadFullMatch) {
          const mtAction = config.multiTurnInjection.action ?? "block";
          ruleIdOverride = "sdk:multi_turn_injection";
          // No score in the stored reason — a persisted continuous margin is
          // an evasion oracle (see formatMultiTurnReason).
          policyReasonOverride = formatMultiTurnReason(mt.turns, mt.signals);
          // Accumulated injection taints the session (later egress escalated).
          if (taintCfg) markTainted(taintKey, "multi_turn_injection", Date.now());
          if (mtAction === "block") {
            actionTaken = "blocked";
            actionReason = "policy_violation";
            actionSource = "policy_rules";
            // Accumulated multi-turn injection IS an injection finding.
            reasonCode = ReasonCode.INJECTION_DETECTED;
            debugLog(config, "warn", `Call blocked: ${policyReasonOverride}`);
          } else {
            if (actionReason === "none") actionReason = "policy_violation";
            actionSource = "policy_rules";
            debugLog(config, "warn", `Call flagged: ${policyReasonOverride}`);
          }
        }
      }

      layer = "policy_floor";
      // 1.4. Anti-tamper policy FLOOR — non-overridable rules evaluated BEFORE
      //      customer rules and excluded from the hook-override branches below.
      floorBlock = false;
      floorOverrideIgnored = undefined;
      floorActive = !!(config.policyFloor && config.policyFloor.length > 0);
      if (floorActive && actionTaken !== "blocked") {
        const promptText = lastUserText();
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
          reasonCode = floorResult.reason_code;
          debugLog(config, "warn", `Floor block (${floorResult.decision} → block): ${policyReasonOverride}`);
        }
      }

      layer = "policy_rules";
      // 1.5. Structured policy rules - runs before the customer hook so that
      //      rules fetched by the polling loop can block calls before the hook fires.
      ruleId = ruleIdOverride;
      policyReason = policyReasonOverride;
      if (config.policyRules?.length && actionTaken !== "blocked") {
        const promptText = lastUserText();
        // Build PolicyEvalContext from audit_fields metadata and config environment
        const evalCtx: PolicyEvalContext = {
          currentEnvironment: config.environment,
          // model_gate context: model from the request (or Gemini instance hint)
          model: String((cleaned_args[0] as { model?: unknown })?.model ?? modelHint ?? ""),
          provider,
          ...(audit_fields.metadata as Record<string, unknown> ?? {}),
        };
        const result = evaluatePolicyRules(config.policyRules, promptText, "prompt", evalCtx, {
          failMode: config.failMode,
        });
        approvalClaim = result.approval_granted;
        ruleId = result.rule_id;
        policyReason = result.reason;
        // The engine's own fine-grained code survives to the event and the
        // thrown error — it is not re-derived into a coarse category further
        // down. A no-match PERMITTED (no rule engaged) must not erase an
        // earlier layer's classification, e.g. a detect-only PII finding.
        if (result.decision !== "allow" || result.rule_id) {
          reasonCode = result.reason_code;
        }
        // A quota rule the bounded meter could not count is declared on this
        // call's own event, on the same reserved channel detector_failure and
        // canary evidence take. Without it an unenforced quota rule is
        // indistinguishable from one that was counted and found under limit.
        if (result.quota_unmetered) {
          audit_fields.metadata = {
            ...((audit_fields.metadata as Record<string, unknown>) ?? {}),
            obsvr_telemetry: {
              ...(((audit_fields.metadata as Record<string, unknown>)?.obsvr_telemetry as Record<string, unknown>) ?? {}),
              quota_unmetered: result.quota_unmetered,
            },
          };
        }
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
              // Names the exact call a human is being asked to authorize, so
              // the grant that comes back can be bound to it rather than to
              // "anything that trips this rule".
              action_hash: result.action_hash,
            });
          }
        } else if (result.decision === "redact" && actionTaken !== "redacted") {
          // A rules-engine "redact" verdict used to be dropped here: only the
          // block branch existed, so the call went out untouched and the event
          // recorded "allowed" while the operator's rule said remove it. The
          // same rule redacts through every framework integration and through
          // Python, so this was the wrapper disagreeing with every other door
          // into the same policy.
          //
          // Application is the hook-redact branch's, for the same reason it is
          // that one there: "redact" applies the SDK's structure-aware PII
          // redaction across every provider shape (system / messages /
          // contents / instructions / input / bare string). A rule that must
          // suppress non-PII content should declare action "block".
          //
          // Enforcement APPLICATION, so it fails CLOSED regardless of failMode:
          // policy already decided the content must be removed, and answering
          // a failed removal by forwarding the content under a "redacted"
          // record is the one outcome worse than blocking.
          const notRedacted = applyOutboundRedaction(() => {
            if (typeof cleaned_args[0] === "string") {
              cleaned_args[0] = redactBuiltinPii(cleaned_args[0]);
            } else {
              redactMessagesInPlace(cleaned_args[0]);
            }
          }, "policy_rules");
          // Both branches above rewrite the request in place.
          invalidateLastUserText();
          if (notRedacted) {
            actionTaken = "blocked";
            actionReason = "policy_violation";
            actionSource = "policy_rules";
            redactedTypes = []; // nothing was redacted; the record must not say otherwise
            ruleId = notRedacted.ruleId;
            policyReason = notRedacted.policyReason;
            outboundRedactionFailure = notRedacted.failure;
          } else {
            actionTaken = "redacted";
            actionReason = "policy_violation";
            actionSource = "policy_rules";
          }
        }
      }
    } catch (err) {
      const failClosed = recordDetectorFailure(layer, err, config);
      if (failClosed) {
        actionTaken = "blocked";
        actionReason = "policy_violation";
        actionSource = "builtin";
        ruleId = "sdk:detector_error";
        policyReason = `Detector layer '${layer || "unknown"}' raised ${describeError(err)}`.slice(0, 256);
      }
      // Record WHICH layer was lost on this call's own event, on the reserved
      // telemetry channel - the same route canary and floor evidence take. An
      // open resolution leaves the call looking ordinary otherwise, so without
      // this an operator cannot see that a control silently stopped running.
      audit_fields.metadata = {
        ...((audit_fields.metadata as Record<string, unknown>) ?? {}),
        obsvr_telemetry: {
          ...(((audit_fields.metadata as Record<string, unknown>)?.obsvr_telemetry as Record<string, unknown>) ?? {}),
          detector_failure: detectorFailureRecord(
            layer,
            err,
            failClosed ? "closed" : "open",
            "pre_call",
          ),
        },
      };
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
        // The hook sees the destination, the same value the record will carry.
        provider: ctx.recordedProvider,
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
        // A timeout resolved closed is its own classification; a real hook
        // block derives HOOK_BLOCKED from the source at event build. Either
        // way an earlier layer's code no longer describes this decision.
        reasonCode = hookDisposition === "timeout" ? ReasonCode.HOOK_TIMEOUT : undefined;
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
          reasonCode = undefined; // the overridden block's code no longer applies
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
          // Same application rule as the builtin branch: the hook asserted the
          // content must be removed, so a failed removal blocks rather than
          // forwards it. This branch is outside the detector span entirely.
          const notRedacted = applyOutboundRedaction(() => {
            if (typeof cleaned_args[0] === "string") {
              cleaned_args[0] = redactBuiltinPii(cleaned_args[0]);
            } else {
              redactMessagesInPlace(cleaned_args[0]);
            }
          });
          // Both branches above rewrite the request in place.
          invalidateLastUserText();
          if (notRedacted) {
            actionTaken = "blocked";
            actionReason = "policy_violation";
            actionSource = "customer_hook";
            redactedTypes = [];
            ruleId = notRedacted.ruleId;
            policyReason = notRedacted.policyReason;
            outboundRedactionFailure = notRedacted.failure;
          } else {
            redactedTypes = ["all"]; // customer-driven; exact types are unknown
            actionTaken = "redacted";
            actionReason = "policy_violation";
            actionSource = "customer_hook";
          }
        }
      }
    }

    // A failed outbound redaction rides the same telemetry channel, under its
    // own phase so an auditor can tell "we could not decide" apart from "we
    // decided and could not carry it out". Stamped here because either redact
    // branch can set it - the builtin one inside the span, the hook one above.
    if (outboundRedactionFailure) {
      audit_fields.metadata = {
        ...((audit_fields.metadata as Record<string, unknown>) ?? {}),
        obsvr_telemetry: {
          ...(((audit_fields.metadata as Record<string, unknown>)?.obsvr_telemetry as Record<string, unknown>) ?? {}),
          detector_failure: outboundRedactionFailure,
        },
      };
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
            userId: audit_fields.user_id || ctx.options.user_id || getCurrentSubject()?.user_id || undefined,
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
          reasonCode = undefined; // derives EXTERNAL_BACKEND_DENY from the source
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
          reasonCode = undefined; // derives EXTERNAL_BACKEND_DENY from the source
          ruleId = `backend:${config.external_policy_backend.type}`;
          policyReason = `Denied by external ${config.external_policy_backend.type} policy backend (evaluation error, fail-closed)`;
        }
      }
    }

    // Re-check a spent approval grant. Everything above this point can take
    // real time - the customer hook has a two-second budget by default and an
    // external policy backend has its own - and a grant that expired inside
    // that window authorized nothing by the time the call goes out. The
    // remaining gap is this function's own assembly, which is microseconds; an
    // in-process library cannot make the check and the provider's receipt of
    // the request simultaneous, and this does not pretend to.
    if (approvalClaim && actionTaken !== "blocked" && !revalidateApproval(approvalClaim)) {
      actionTaken = "blocked";
      actionReason = "policy_violation";
      actionSource = "policy_rules";
      reasonCode = ReasonCode.APPROVAL_REQUIRED;
      ruleId = approvalClaim.ruleId;
      policyReason = `approval_expired_before_execution: ${approvalClaim.ruleId}`;
      debugLog(config, "warn", `Call blocked: ${policyReason}`);
    }

    // Shadow rules (EV-20/21): evaluated AFTER the active decision is
    // final, check-only, recorded on the event, never decision-affecting.
    let shadowOutcome: ComplianceCtx["shadowOutcome"] = null;
    if (config.policyRules?.some((r) => r.enabled && r.mode === "shadow")) {
      const promptText = lastUserText();
      const evalCtx: PolicyEvalContext = {
        currentEnvironment: config.environment,
        model: String((cleaned_args[0] as { model?: unknown })?.model ?? modelHint ?? ""),
        provider,
        ...(audit_fields.metadata as Record<string, unknown> ?? {}),
      };
      // Check-only, and structurally always open: a shadow rule is defined as
      // never decision-affecting (it runs AFTER the active decision is final),
      // so a defect in one must not change the outcome in EITHER direction.
      // failMode is deliberately not consulted - honoring "closed" here would
      // let a shadow rule block a call, which is the one thing shadow mode
      // promises it cannot do. The loss is recorded; the outcome stays null.
      try {
        shadowOutcome = evaluateShadowRules(config.policyRules, promptText, "prompt", evalCtx);
      } catch (shadowErr) {
        recordCheckOnlyFailure("policy_rules", shadowErr);
        shadowOutcome = null;
      }
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
      userId: audit_fields.user_id || ctx.options.user_id || getCurrentSubject()?.user_id || undefined,
      serviceName:
        audit_fields.service_name || ctx.options.service_name || config.default_service_name || undefined,
      hook: hookDisposition,
    });

    // One reason-code resolution for the event AND the thrown error: the
    // deciding layer's explicit code wins, a clean or overridden allow is
    // PERMITTED, and anything else derives exactly the way the error
    // constructor derives — so the record and the exception cannot disagree.
    const resolvedReasonCode =
      reasonCode ??
      (actionReason === "none" || actionReason === "customer_override"
        ? ReasonCode.PERMITTED
        : resolveReasonCode({ action_reason: actionReason, action_source: actionSource }));

    // Build compliance context - shared by all events in this call
    const compliance: ComplianceCtx = {
      eventType: "llm_call",
      policyVersion,
      actionTaken,
      actionReason,
      reasonCode: resolvedReasonCode,
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
        user_id: audit_fields.user_id || ctx.options.user_id || getCurrentSubject()?.user_id || undefined,
        client_ip: audit_fields.client_ip || undefined,
        user_agent: audit_fields.user_agent || undefined,
        // The destination, not the client's shape — see PathContext. A blocked
        // call is enforcement evidence, so it needs the same true destination
        // as a completed one.
        provider: ctx.recordedProvider,
        model: blockedModel,
        operation: methodPath,
        source:
          audit_fields.source ||
          ctx.options.source ||
          config.default_source ||
          "proxy_wrapper",
        // Truncated like every other event-build site — this one had drifted.
        // MAX_QUEUE_SIZE bounds the event COUNT and nothing bounds the bytes, so
        // an oversized event is refused by ingest with a 4xx, which the sender
        // classifies `permanent` and dead-letters rather than retrying. That
        // made the BLOCKED event — the enforcement evidence — the class most
        // likely to be silently discarded, and it is the one that must survive.
        // This file builds three of these literals by hand and the other two
        // truncate; the Python twin has one builder and never had the gap.
        prompt: truncate(redactedPrompt, config.max_payload_chars),
        response: "",
        user_input: truncate(
          canaryFloor
            ? CANARY_REDACTION_PLACEHOLDER
            : redactForStorage(lastUserText(), piiScanVia),
          config.max_payload_chars,
        ),
        latency_ms: 0,
        success: false,
        status_code: 403,
        error_type: null,
        metadata: withProviderAttribution(
          audit_fields.metadata as Record<string, unknown> | undefined,
          ctx,
        ),
        event_type: "blocked_call",
        policy_version: policyVersion,
        action_taken: "blocked",
        action_reason: actionReason,
        reason_code: resolvedReasonCode,
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
      // Enforcement evidence goes through the same net as everything else. The
      // block path already redacts the full prompt for a PII block, but a
      // keyword block stores "[BLOCKED_BY_POLICY]" without ever having looked
      // at the roles behind it, and a class closed on four paths out of five is
      // a class that is still open.
      applyStoredContentNet(blockedEvent, config, lastUserText());

      sendAuditAsync(config, blockedEvent);
      debugLog(
        config,
        "info",
        `Request blocked (${actionReason}): ${blockedEvent.request_id}`,
      );
      throw createPolicyError({
        action_taken: actionTaken,
        action_reason: actionReason,
        action_source: actionSource,
        policy_version: policyVersion,
        policy_reason: policyReason,
        rule_id: ruleId,
        reason_code: resolvedReasonCode,
      });
    }

  return { cleaned_args, audit_fields, auditThisCall, compliance, modelHint, taintIdentity };
}

function createAuditedMethod(
  originalMethod: Function,
  target: object,
  ctx: PathContext,
  provider: "openai" | "anthropic" | "google" | "unknown",
): Function {
  const { config } = ctx;
  const methodPath = ctx.path.join(".");

  return async function auditedMethod(...args: unknown[]): Promise<unknown> {
    const { cleaned_args, audit_fields, auditThisCall, compliance, modelHint } =
      await governCall(args, target, ctx, provider, methodPath);


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
          // No `?? 500`: an error without a status did not come from the
          // server, and inventing one attributes a client-side failure to the
          // provider.
          const statusCode =
            (error as any)?.status ?? (error as any)?.statusCode ?? undefined;
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
        // Same reason as the streaming path above: absent, not invented.
        const statusCode =
          (error as any)?.status ?? (error as any)?.statusCode ?? undefined;
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
 * Govern a provider `.stream()` helper without breaking its synchronous return.
 *
 * The caller gets a stand-in immediately — so `.on('text', …)` chains exactly as
 * it did — while the real runner is not constructed until governCall resolves.
 * That ordering is the point: enforcement is asynchronous (the optional NLP
 * scan and the human-in-the-loop hook both await), so calling the provider first
 * and governing afterwards would mean a "block" aborts a stream the model has
 * already answered. That is an apology, not a gate.
 *
 * One event fires when the run finishes, built from the runner's own completed
 * response through the same extractor the non-streaming path uses.
 */
function createAuditedRunnerMethod(
  originalMethod: Function,
  target: object,
  ctx: PathContext,
  provider: "openai" | "anthropic" | "google" | "unknown",
  finalAccessor: string,
): Function {
  const { config } = ctx;
  const methodPath = ctx.path.join(".");

  return function auditedRunnerMethod(...args: unknown[]): unknown {
    const startTime = performance.now();
    let outcome: PreCallOutcome | undefined;

    return createDeferredRunner({
      govern: async () => {
        outcome = await governCall(args, target, ctx, provider, methodPath);
        return outcome.cleaned_args;
      },
      start: (cleanedArgs) =>
        originalMethod.apply(target, cleanedArgs) as RunnerLike,
      finish: ({ runner, error }) => {
        void (async () => {
          try {
            // A refusal before the provider was reached is already recorded by
            // governCall's own blocked-call event; emitting again here would
            // double-count the same decision.
            if (!outcome) return;
            let response: unknown;
            let failure = error;
            if (runner && !failure) {
              try {
                const accessor = (runner as Record<string, unknown>)[finalAccessor];
                if (typeof accessor === "function") {
                  response = await (accessor as () => Promise<unknown>).call(runner);
                }
              } catch (e) {
                failure = e;
              }
            }
            const auditEvent = buildAuditEvent(
              ctx,
              outcome.cleaned_args[0],
              failure ? null : response,
              outcome.audit_fields,
              Math.round(performance.now() - startTime),
              provider,
              !failure,
              failure ?? undefined,
              failure
                ? ((failure as { status?: number })?.status ??
                   (failure as { statusCode?: number })?.statusCode ??
                   undefined)
                : undefined,
              outcome.modelHint,
              outcome.compliance,
            );
            // Sampling gates emission of ALLOWED events only; a failed run is
            // enforcement evidence and is always recorded.
            if (!outcome.auditThisCall && !failure) return;
            await applyPostCallGovernance(auditEvent, config);
            sendAuditAsync(config, auditEvent);
          } catch (e) {
            debugLog(
              config,
              "error",
              "Failed to build streaming-runner audit event:",
              e instanceof Error ? e.message : String(e),
            );
          }
        })();
      },
    });
  };
}

/**
 * Govern a provider TOOL RUNNER, emitting the run as a sequence rather than as
 * a single call.
 *
 * The synchronous-return problem is the same one the `.stream()` helpers posed
 * and is solved the same way, by the deferred runner: the caller gets a stand-in
 * immediately and the real runner is not constructed until `governCall`
 * resolves, so a refused run never reaches the provider. What differs is what
 * happens after that — the loop is observed turn by turn and emits one event per
 * model call, one per tool call, and a run-level start/finish pair carrying a
 * shared `agent_run_id`.
 *
 * The intermediate events go through the integration-event path rather than
 * `buildAuditEvent` because their content is not a chat payload for an extractor
 * to read: a tool event's prompt is the arguments the model chose and its
 * response is what the tool returned. Routing those through a chat extractor
 * would mean synthesising a fake `messages`/`choices` wrapper around them, and a
 * fabricated shape in a governance record is exactly the failure this work keeps
 * finding. The integration path takes both as text, which is what they are.
 */
function createAuditedToolRunnerMethod(
  originalMethod: Function,
  target: object,
  ctx: PathContext,
  provider: "openai" | "anthropic" | "google" | "unknown",
  spec: { dialect: "openai-chat" | "anthropic-messages"; thenable: boolean },
): Function {
  const { config, options } = ctx;
  const methodPath = ctx.path.join(".");

  return function auditedToolRunnerMethod(...args: unknown[]): unknown {
    const startTime = performance.now();
    const runId = generateUUID();
    let outcome: PreCallOutcome | undefined;
    let modelCalls = 0;
    let toolCalls = 0;
    // Set in `govern`, read in the tool sink. Defaults to not-installed so a
    // tool event arriving before governance could not have run reports the
    // absence rather than inheriting a claim.
    let toolGate: RunnerToolGateReport = {
      installed: false,
      gated: [],
      ungatable: [],
    };

    const source = options.source || config.default_source || "proxy_wrapper";
    const anthropic = spec.dialect === "anthropic-messages";

    /** The model as the caller asked for it, read once off the invocation. */
    const requestedModel = (() => {
      try {
        const body = args[0] as { model?: unknown } | undefined;
        return typeof body?.model === "string" ? body.model : "unknown";
      } catch {
        return "unknown";
      }
    })();

    const emit = (
      suffix: string,
      fields: Partial<Parameters<typeof emitIntegrationEvent>[0]>,
    ): void => {
      try {
        emitIntegrationEvent({
          config,
          // The destination, like every other record this wrapper emits. A tool
          // event from a run pointed at a local server must not name a vendor
          // either — the shape decided the dialect, not where the bytes went.
          provider: ctx.recordedProvider,
          model: requestedModel,
          operation: `${methodPath}.${suffix}`,
          source,
          prompt: "",
          metadata: { agent_run_id: runId },
          options: options as never,
          ...fields,
        });
      } catch (e) {
        debugLog(
          config,
          "error",
          `Failed to emit tool-runner ${suffix} event:`,
          e instanceof Error ? e.message : String(e),
        );
      }
    };

    const sink: ToolRunSink = {
      modelCall({ request, response }) {
        modelCalls += 1;
        const prompt = anthropic
          ? extractAnthropicPrompt(request as AnthropicMessagesRequest)
          : extractOpenAIPrompt(request as OpenAIChatRequest);
        const text = anthropic
          ? extractAnthropicResponse(response as AnthropicMessagesResponse)
          : extractOpenAIResponse(response as never);
        const usage = anthropic
          ? extractAnthropicTokenUsage(response as AnthropicMessagesResponse)
          : extractOpenAITokenUsage(response as never);
        const resolved = (response as { model?: unknown } | undefined)?.model;
        emit("llm", {
          prompt,
          response: text,
          inputTokens: usage?.input_tokens,
          outputTokens: usage?.output_tokens,
          totalTokens: usage?.total_tokens,
          model_resolved: typeof resolved === "string" ? resolved : undefined,
          provenance_source: typeof resolved === "string" ? "provider_response" : undefined,
          metadata: { agent_run_id: runId, turn: modelCalls },
        });
      },
      toolCall({ name, args: toolArgs, result, toolCallId }) {
        toolCalls += 1;
        // Whether THIS call's callback was one the gate reached. A run can mix
        // gated tools with hosted ones the provider executes itself, so the
        // answer is per tool and not per run.
        const wasGated = toolGate.installed && toolGate.gated.includes(name);
        // The result is text a tool produced, not text the model or the user
        // wrote. Saying so is the whole point of the field: it is the marker a
        // downstream injection review keys on, and this path is one of the few
        // that genuinely knows.
        emit("tool", {
          prompt: toolArgs,
          response: result,
          contentProvenance: "tool_result",
          // THIS RECORD CARRIES NO VERDICT OF ITS OWN, and which absence it is
          // reporting depends on whether the gate reached this tool.
          //
          // Gated: the tool's callback ran behind the same gate the documented
          // wrapper applies, and that gate emitted its own `tool.call` event
          // with the verdict. This event is the runner's OBSERVATION of the
          // turn, so it points at the decision rather than restating it — an
          // observation that claimed `allowed` would be asserting a second
          // decision nobody made, and one that claimed `not_evaluated` for the
          // tool gate would now be false.
          //
          // Not gated: no tool-level control reached this call, and the
          // destructive-capability set and denied-tool rules are absent here
          // rather than permissive. Measured before the gate existed: a session
          // obsvr had already marked tainted executed a tool named in
          // `destructiveTools`, and the record called it allowed.
          compliance: {
            event_type: "tool_call",
            policy_version: derivePolicyVersion(config.policyRules ?? []),
            // Omitting the field would not have helped either way: the ingest
            // schema defaults an absent action_taken, so the server would mint
            // "allowed" one layer down.
            action_taken: "not_evaluated",
            action_reason: "none",
            action_source: "unknown",
            redacted_types: [],
            blocked_types: [],
            policy_not_evaluated: {
              surface: `${methodPath}.tool`,
              gate: wasGated ? "runner_observation" : "tool_gate",
              reason: wasGated
                ? "the tool gate ran at this tool's callback and its verdict is on that call's own tool.call event; this record observes the runner's turn and decides nothing"
                : "this tool's callback is invoked by the provider's runner and obsvr is not on that boundary",
            },
          },
          metadata: {
            agent_run_id: runId,
            tool_name: name,
            tool_call_id: toolCallId,
            tool_index: toolCalls,
            tool_gate: wasGated ? "callback" : "absent",
            ...(wasGated || !toolGate.reason
              ? {}
              : { tool_gate_absent_reason: toolGate.reason }),
          },
        });
      },
    };

    return createDeferredRunner({
      thenable: spec.thenable,
      govern: async () => {
        outcome = await governCall(args, target, ctx, provider, methodPath);
        // THE ONLY SEAM THERE IS. Both runners snapshot their tool set when the
        // method is applied, so the gate has to land on the arguments before
        // that and cannot be installed afterwards. The identity metadata the
        // latch key was derived from travels with it, because SET and ENFORCE
        // must key the same latch or the escalation silently no-ops.
        const gate = governRunnerTools(outcome.cleaned_args, config, {
          ...options,
          metadata: outcome.taintIdentity,
        });
        toolGate = gate.report;
        // Emitted only once the run is actually going to happen. A refused run
        // has its own blocked-call event from governCall and must not also
        // appear to have started.
        emit("start", {
          metadata: {
            agent_run_id: runId,
            tool_gate: toolGate.installed ? "callback" : "absent",
            ...(toolGate.installed ? { tool_gate_tools: toolGate.gated } : {}),
            ...(toolGate.ungatable.length > 0
              ? { tool_gate_ungated_tools: toolGate.ungatable }
              : {}),
            ...(toolGate.reason ? { tool_gate_absent_reason: toolGate.reason } : {}),
          },
          compliance: undefined,
        });
        return gate.args;
      },
      start: (cleanedArgs) => {
        const runner = originalMethod.apply(target, cleanedArgs) as RunnerLike;
        if (!anthropic) observeOpenAIToolRun(runner, sink);
        return runner;
      },
      // Anthropic's runner has no event emitter and advances only while it is
      // consumed, so observation and completion are the same act.
      complete: anthropic
        ? (runner) => driveAnthropicToolRun(runner as never, sink)
        : undefined,
      finish: ({ error }) => {
        if (!outcome) return; // refused before the provider was reached
        emit("finish", {
          success: !error,
          error: error ?? undefined,
          statusCode: error
            ? ((error as { status?: number })?.status ??
              (error as { statusCode?: number })?.statusCode ??
              undefined)
            : undefined,
          latencyMs: Math.round(performance.now() - startTime),
          metadata: {
            agent_run_id: runId,
            model_calls: modelCalls,
            tool_calls: toolCalls,
          },
        });
      },
    });
  };
}

/**
 * Check if a method path should be audited
 */
function isAuditablePath(path: string[]): boolean {
  return AUDITABLE_METHODS.has(path.join("."));
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
      const stepCtx = () => atPath(ctx, newPath);

      // If it's a function
      if (typeof value === "function") {
        // Provider tool runners: same synchronous-return mechanism as the
        // stream helpers, but the run is emitted as a sequence of events
        // rather than one.
        const toolRunnerSpec = TOOL_RUNNER_METHODS.get(newPath.join("."));
        if (toolRunnerSpec) {
          debugLog(
            ctx.config,
            "info",
            `Wrapping tool-runner method: ${newPath.join(".")}`,
          );
          return createAuditedToolRunnerMethod(
            value,
            obj,
            stepCtx(),
            ctx.provider,
            toolRunnerSpec,
          );
        }

        // Provider `.stream()` helpers: governed, but through the deferred
        // runner so the synchronous return contract survives.
        const runnerSpec = STREAM_RUNNER_METHODS.get(newPath.join("."));
        if (runnerSpec) {
          debugLog(
            ctx.config,
            "info",
            `Wrapping streaming-runner method: ${newPath.join(".")}`,
          );
          return createAuditedRunnerMethod(
            value,
            obj,
            stepCtx(),
            ctx.provider,
            runnerSpec.final,
          );
        }

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
            stepCtx(),
            ctx.provider,
          );
        }

        // Return bound function for non-auditable methods
        return value.bind(obj);
      }

      // If it's an object, wrap recursively
      if (typeof value === "object") {
        return createRecursiveProxy(value as object, stepCtx());
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

  // The client's SHAPE, which selects the extractors.
  const provider = detectProvider(client);

  // WHERE the calls will go, which is what the record must name. Resolved ONCE,
  // at wrap time: a client's base URL is fixed when it is constructed, so
  // re-deriving it per call would buy nothing and cost a URL parse on the hot
  // path. Same resolver the compat integrations use — one endpoint table.
  const { provider: recordedProvider, attribution: providerAttribution } =
    resolveDestination(client, provider);
  debugLog(
    config,
    "info",
    `Wrapping ${provider}-shaped client; recording provider=${recordedProvider}`,
  );

  // Create context with provider (V2)
  const ctx: PathContext = {
    path: [],
    options,
    /**
     * Read through to the live config rather than holding the object that was
     * current at wrap time.
     *
     * `init()` REPLACES `state.config` while a `/policies` poll MUTATES the
     * same object in place. A captured reference therefore saw every poll and
     * no re-`init()`, which is precisely why the two behaved differently — and
     * it stranded every already-wrapped client on the policy it was wrapped
     * under, in both directions: still refusing on a rule that had been
     * removed, and reaching the provider under a rule that had been added.
     *
     * The fallback covers teardown only. `getConfig()` throws once the SDK is
     * no longer initialised, where reading the captured object used to return,
     * and turning a torn-down client's call into a throw is a different change
     * from the one being made here.
     */
    get config(): ResolvedConfig {
      return isInitialized() ? getConfig() : config;
    },
    provider,
    recordedProvider,
    providerAttribution,
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
