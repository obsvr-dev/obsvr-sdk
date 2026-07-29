/**
 * LlamaIndex TS Integration
 *
 * Registers `llm-start` / `llm-end` / `llm-stream` handlers on a LlamaIndex
 * `CallbackManager` (typically `Settings.callbackManager`). Duck-typed -
 * no hard dependency on the `llamaindex` package.
 *
 * Observe-only: PII policy applies to the *stored* copy ("block" is
 * downgraded to redact-in-event with action_reason "pii_detected").
 *
 * @example
 * ```ts
 * import { Settings } from "llamaindex";
 * import { obsvr } from "@obsvr/sdk";
 * import { obsvrLlamaIndexHandler } from "@obsvr/sdk/llamaindex";
 *
 * obsvr.init({ apiKey: "..." });
 * obsvrLlamaIndexHandler(Settings.callbackManager);
 * ```
 *
 * @packageDocumentation
 */

// Interception: LlamaIndex CallbackManager .on() API (non-mutating). Handlers are registered via the framework API; no internals are modified.

import {
  applyObservePolicy,
  emitIntegrationEvent,
  redactForStorage,
  type DeobfuscationView,
  setupExitHandlers,
  shouldSample,
  tryGetConfig,
  type ComplianceInfo,
  type IntegrationOptions,
  inferProviderFromModel,
} from "./core.js";
import { readTokenUsage } from "../proxy/extractors/token-usage.js";
import type { TokenUsage } from "../proxy/extractors/types.js";

const SOURCE = "llamaindex_ts";

/** Duck-typed CallbackManager shape (LlamaIndex TS) */
export interface CallbackManagerLike {
  on(
    event: string,
    handler: (event: { detail?: unknown } | unknown) => void,
  ): unknown;
}

interface LlmRunState {
  prompt: string;
  userText: string;
  model: string;
  startTime: number;
  compliance: ComplianceInfo;
  shouldRedactStored: boolean;
  /** View-only detection: stored copies use a whole-text placeholder. */
  storedRedactionVia?: DeobfuscationView["method"];
  streamText: string;
}

function messageText(msg: unknown): string {
  if (!msg || typeof msg !== "object") return "";
  const m = msg as Record<string, unknown>;
  if (typeof m.content === "string") return m.content;
  if (Array.isArray(m.content)) {
    return (m.content as Record<string, unknown>[])
      .map((p) => (typeof p.text === "string" ? p.text : ""))
      .filter((t) => t.length > 0)
      .join(" ");
  }
  return "";
}

function payloadOf(event: unknown): Record<string, unknown> {
  if (!event || typeof event !== "object") return {};
  const e = event as Record<string, unknown>;
  // LlamaIndex TS dispatches CustomEvent-like objects with `.detail`
  if (e.detail && typeof e.detail === "object") {
    return e.detail as Record<string, unknown>;
  }
  return e;
}

function extractMessagesPrompt(payload: Record<string, unknown>): {
  prompt: string;
  userText: string;
} {
  const messages = payload.messages;
  if (Array.isArray(messages)) {
    const prompt = (messages as Record<string, unknown>[])
      .map((m) => {
        const role = typeof m.role === "string" ? m.role : "unknown";
        return `${role}: ${messageText(m)}`;
      })
      .join("\n");
    let userText = "";
    for (let i = messages.length - 1; i >= 0; i--) {
      const m = (messages as Record<string, unknown>[])[i];
      if (m.role === "user") {
        userText = messageText(m);
        break;
      }
    }
    return { prompt, userText: userText || prompt };
  }
  if (typeof payload.prompt === "string") {
    return { prompt: payload.prompt, userText: payload.prompt };
  }
  return { prompt: "", userText: "" };
}

function extractResponseText(payload: Record<string, unknown>): string {
  const response = payload.response;
  if (typeof response === "string") return response;
  if (response && typeof response === "object") {
    const r = response as Record<string, unknown>;
    if (r.message) return messageText(r.message);
    if (typeof r.text === "string") return r.text;
  }
  return "";
}

/**
 * The underlying provider response LlamaIndex keeps on `response.raw`.
 *
 * This is the provider's own wire payload, not a LlamaIndex abstraction over
 * it, which is why the model snapshot and the token counts can both be read
 * from it with the same readers every other integration uses.
 */
function rawProviderResponse(
  payload: Record<string, unknown>,
): Record<string, unknown> | undefined {
  const response = payload.response as Record<string, unknown> | undefined;
  const raw = response?.raw;
  return raw && typeof raw === "object" ? (raw as Record<string, unknown>) : undefined;
}

/**
 * Provider-RESOLVED model snapshot for temporal provenance. OpenAI puts the
 * serving model on the raw response as `model`, Gemini as `modelVersion`.
 * Undefined when absent.
 */
function extractResolvedModel(payload: Record<string, unknown>): string | undefined {
  const raw = rawProviderResponse(payload);
  const candidate = raw?.model ?? raw?.modelVersion;
  return typeof candidate === "string" && candidate.trim().length > 0
    ? candidate.trim()
    : undefined;
}

/**
 * Token counts for a LlamaIndex LLM call.
 *
 * There was no token-reading code on this path at all — not a reader that
 * broke, one that was never written — so LlamaIndex traffic could never be
 * metered or counted against a token budget, at any version, in either
 * language. The counts are on the provider's raw response in its own wire
 * format, and `usage_metadata` covers the Gemini spelling.
 */
function extractUsage(payload: Record<string, unknown>): TokenUsage | undefined {
  const raw = rawProviderResponse(payload);
  if (!raw) return undefined;
  return readTokenUsage(raw.usage ?? raw.usageMetadata ?? raw.usage_metadata);
}

function extractChunkText(payload: Record<string, unknown>): string {
  const chunk = payload.chunk;
  if (typeof chunk === "string") return chunk;
  if (chunk && typeof chunk === "object") {
    const c = chunk as Record<string, unknown>;
    if (typeof c.delta === "string") return c.delta;
    if (typeof c.text === "string") return c.text;
  }
  return "";
}

/**
 * Register obsvr audit handlers on a LlamaIndex CallbackManager.
 * Returns the manager for chaining.
 */
export function obsvrLlamaIndexHandler<T extends CallbackManagerLike>(
  callbackManager: T | undefined,
  opts: IntegrationOptions = {},
): T {
  if (!callbackManager || typeof callbackManager.on !== "function") {
    throw new Error(
      "[obsvr] obsvrLlamaIndexHandler requires a CallbackManager " +
        "(e.g. pass Settings.callbackManager from llamaindex)",
    );
  }

  const initialConfig = tryGetConfig();
  if (initialConfig) setupExitHandlers(initialConfig);

  const runs = new Map<unknown, LlmRunState>();

  callbackManager.on("llm-start", (event) => {
    try {
      const config = tryGetConfig();
      if (!config) return;
      if (!shouldSample(config.sample_rate)) return;

      const payload = payloadOf(event);
      const { prompt, userText } = extractMessagesPrompt(payload);
      const { shouldRedactStored, compliance, storedRedactionVia } = applyObservePolicy(
        prompt,
        config,
      );

      runs.set(payload.id ?? "default", {
        prompt,
        userText,
        model: typeof payload.model === "string" ? payload.model : "unknown",
        startTime: performance.now(),
        compliance,
        shouldRedactStored,
        storedRedactionVia,
        streamText: "",
      });
    } catch {
      // Never throw inside a framework callback
    }
  });

  callbackManager.on("llm-stream", (event) => {
    try {
      const payload = payloadOf(event);
      const state = runs.get(payload.id ?? "default");
      if (!state) return;
      state.streamText += extractChunkText(payload);
    } catch {
      // Never throw inside a framework callback
    }
  });

  callbackManager.on("llm-end", (event) => {
    try {
      const payload = payloadOf(event);
      const id = payload.id ?? "default";
      const state = runs.get(id);
      if (!state) return;
      runs.delete(id);

      const config = tryGetConfig();
      if (!config) return;

      const responseText = extractResponseText(payload) || state.streamText;

      const resolvedModel = extractResolvedModel(payload);
      // The current LlamaIndex.TS `llm-start` payload carries only
      // { id, messages } — no model field — so state.model is always
      // "unknown" at capture time. The real model only appears at
      // `llm-end` (payload.response.raw.model). Backfill from the
      // resolved snapshot rather than emitting a knowably-wrong "unknown".
      const model = state.model !== "unknown" ? state.model : (resolvedModel ?? state.model);
      // `provider` was a hardcoded "unknown" literal at every version — never
      // implemented rather than drifted — so LlamaIndex traffic could not be
      // attributed to a provider in any report, and a per-provider spend or
      // policy breakdown silently excluded it or bucketed it under unknown.
      // The model string the backfill above already recovers is enough to
      // infer it; "unknown" now means genuinely undetermined.
      const provider = inferProviderFromModel(model);
      const usage = extractUsage(payload);
      // When `model` had to be backfilled it holds the SERVED SNAPSHOT, not the
      // configured alias — the llm-start payload carries no model to record.
      // Say so, rather than leaving a reader to infer it from model equalling
      // model_resolved, which is also what a caller who pinned an exact
      // snapshot would produce.
      const aliasUnavailable = state.model === "unknown" && model !== "unknown";
      emitIntegrationEvent({
        config,
        provider,
        model,
        inputTokens: usage?.input_tokens,
        outputTokens: usage?.output_tokens,
        totalTokens: usage?.total_tokens,
        model_resolved: resolvedModel,
        // Read from LlamaIndex's response.raw abstraction (framework-mediated) → framework_reported.
        provenance_source: resolvedModel ? "framework_reported" : undefined,
        operation: "llm",
        source: SOURCE,
        prompt: state.shouldRedactStored
          ? redactForStorage(state.prompt, state.storedRedactionVia)
          : state.prompt,
        response: state.shouldRedactStored
          ? redactForStorage(responseText, state.storedRedactionVia)
          : responseText,
        userInput: state.shouldRedactStored
          ? redactForStorage(state.userText, state.storedRedactionVia)
          : state.userText,
        latencyMs: Math.round(performance.now() - state.startTime),
        metadata: aliasUnavailable ? { model_alias_unavailable: true } : undefined,
        options: opts,
        compliance: state.compliance,
      });
    } catch {
      // Never throw inside a framework callback
    }
  });

  return callbackManager;
}
