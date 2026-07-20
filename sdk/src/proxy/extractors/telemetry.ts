/**
 * Call telemetry extractor (DASHBOARD_TELEMETRY.md, Milestone 1).
 *
 * Pulls high-value, provider-tolerant scalar telemetry off the request and
 * response objects the wrapper already has in hand: request shape params,
 * response metadata, and cost-detail token counts. These are additive and
 * best-effort. Every field is optional; anything not present on a given
 * provider is simply omitted.
 *
 * Transport: this object is attached to the event's metadata under the
 * reserved `obsvr_telemetry` key rather than added as top-level event fields,
 * so the signed raw/canonical event schema (and its conformance fixtures)
 * stays untouched. Ingest lifts it back out and persists the fields
 * first-class on the dashboard event summary.
 *
 * @packageDocumentation
 */

/** Curated, chartable scalar telemetry for one governed call. */
export interface CallTelemetry {
  /** Sampling temperature the request asked for (reproducibility). */
  request_temperature?: number;
  /** top_p the request asked for. */
  request_top_p?: number;
  /** max output tokens the request allowed. */
  request_max_tokens?: number;
  /** Whether the call was streamed. */
  request_stream?: boolean;
  /** Why generation stopped (stop / length / tool_calls / content_filter). */
  finish_reason?: string;
  /** Provider response id, for correlating a disputed call with the provider. */
  response_id?: string;
  /** Model build fingerprint; a change means the provider swapped the model. */
  system_fingerprint?: string;
  /** Reasoning/thinking tokens billed (cost driver). */
  reasoning_tokens?: number;
  /** Prompt tokens served from cache (cost saver). */
  cache_read_tokens?: number;
  /** Prompt tokens written to cache (cost driver). */
  cache_write_tokens?: number;
}

const RESERVED_TELEMETRY_KEY = "obsvr_telemetry";

function num(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

function str(v: unknown): string | undefined {
  if (typeof v !== "string") return undefined;
  const s = v.trim();
  return s.length > 0 ? s.slice(0, 128) : undefined;
}

/** Drop undefined keys so the metadata payload stays minimal. */
function compact(t: CallTelemetry): CallTelemetry {
  const out: CallTelemetry = {};
  for (const [k, v] of Object.entries(t)) {
    if (v !== undefined) (out as Record<string, unknown>)[k] = v;
  }
  return out;
}

/**
 * Extract call telemetry from a request/response pair. Provider-tolerant:
 * unknown shapes yield an empty object, never a throw. Covers OpenAI-shaped
 * (and OpenAI-compatible), Anthropic, and Gemini providers; the OpenAI branch
 * is the default and also serves together/cloudflare/azure/vertex-openai.
 */
export function extractCallTelemetry(
  provider: string,
  request: unknown,
  response: unknown,
): CallTelemetry {
  try {
    const req = (request ?? {}) as Record<string, any>;
    const res = (response ?? {}) as Record<string, any>;

    if (provider === "anthropic") {
      const usage = res.usage ?? {};
      return compact({
        request_temperature: num(req.temperature),
        request_top_p: num(req.top_p),
        request_max_tokens: num(req.max_tokens),
        request_stream: req.stream === true ? true : undefined,
        finish_reason: str(res.stop_reason),
        response_id: str(res.id),
        cache_read_tokens: num(usage.cache_read_input_tokens),
        cache_write_tokens: num(usage.cache_creation_input_tokens),
      });
    }

    if (provider === "google") {
      const gen = req.generationConfig ?? req.generation_config ?? {};
      const meta = res.usageMetadata ?? res.usage_metadata ?? {};
      const finish = res.candidates?.[0]?.finishReason ?? res.candidates?.[0]?.finish_reason;
      return compact({
        request_temperature: num(gen.temperature),
        request_top_p: num(gen.topP ?? gen.top_p),
        request_max_tokens: num(gen.maxOutputTokens ?? gen.max_output_tokens),
        request_stream: req.stream === true ? true : undefined,
        finish_reason: str(finish),
        response_id: str(res.responseId ?? res.response_id),
        reasoning_tokens: num(meta.thoughtsTokenCount),
        cache_read_tokens: num(meta.cachedContentTokenCount),
      });
    }

    // OpenAI and OpenAI-compatible (default).
    const usage = res.usage ?? {};
    const promptDetails = usage.prompt_tokens_details ?? {};
    const completionDetails = usage.completion_tokens_details ?? {};
    return compact({
      request_temperature: num(req.temperature),
      request_top_p: num(req.top_p),
      request_max_tokens: num(req.max_tokens ?? req.max_completion_tokens),
      request_stream: req.stream === true ? true : undefined,
      finish_reason: str(res.choices?.[0]?.finish_reason),
      response_id: str(res.id),
      system_fingerprint: str(res.system_fingerprint),
      reasoning_tokens: num(completionDetails.reasoning_tokens),
      cache_read_tokens: num(promptDetails.cached_tokens),
    });
  } catch {
    return {};
  }
}

/**
 * Merge extracted telemetry into an event's metadata under the reserved key.
 * Returns the metadata unchanged when there is nothing to add, and never
 * overwrites caller-provided metadata keys.
 */
export function withTelemetryMetadata(
  metadata: Record<string, unknown> | undefined,
  telemetry: CallTelemetry,
): Record<string, unknown> | undefined {
  if (Object.keys(telemetry).length === 0) return metadata;
  return { ...(metadata ?? {}), [RESERVED_TELEMETRY_KEY]: telemetry };
}
