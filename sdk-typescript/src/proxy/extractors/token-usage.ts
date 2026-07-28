/**
 * The one place token counts are read out of a usage payload.
 *
 * WHY THIS EXISTS. Fourteen sites used to read tokens independently, and they
 * disagreed about how to say "I don't know". Two conventions were in use:
 *
 *   A.  typeof v === "number" ? v : undefined     -> the field is ABSENT
 *   B.  usage.prompt_tokens || 0                  -> the field is ZERO
 *
 * Eleven sites used B, and B is the wrong answer for a governance product. When
 * an upstream field is renamed or removed while the usage container survives,
 * `undefined || 0` records `input_tokens: 0` — a measurement that never
 * happened, indistinguishable in the evidence from a call that genuinely
 * consumed nothing. And when a field becomes a nested object, `{...} || 0` is
 * truthy and returns the object, so the event carries an object where a number
 * belongs and no schema check rejects it. Both failures look like data.
 *
 * A missing count and a zero count are different facts. Only one is a bug, and
 * a reader of the audit trail must be able to tell them apart. So: this
 * normaliser NEVER fabricates. Absent stays absent.
 *
 * WHAT IT ACCEPTS. The union of the shapes the supported providers and
 * frameworks actually emit, which is wider than any one site knew about:
 *
 *   snake_case wire      prompt_tokens / completion_tokens / total_tokens
 *                        input_tokens / output_tokens / total_tokens
 *   camelCase flat       inputTokens / outputTokens / totalTokens
 *   camelCase legacy     promptTokens / completionTokens / totalTokens
 *   Gemini               promptTokenCount / candidatesTokenCount / totalTokenCount
 *   Bedrock Titan        inputTextTokenCount / results[].tokenCount
 *   NESTED               inputTokens: { total, noCache, cacheRead, cacheWrite }
 *                        outputTokens: { total, text, reasoning }
 *
 * The nested form is the one that broke: a framework turned `inputTokens` from
 * a number into an object and deleted `totalTokens`, and every guard that asked
 * `typeof v === "number"` quietly answered "no tokens" for both counts and the
 * total derived from them. Reading `.total` out of an object slot is therefore
 * not a special case bolted on for one framework — it is the shape a version
 * bump can turn any of these into.
 *
 * SAYING SO WHEN NOTHING MATCHES. A usage container that is present but carries
 * no field this module recognises is a different fact from a provider that
 * reported no usage at all: the first means obsvr cannot read the payload (a
 * defect to fix), the second means there is nothing to read (normal). The
 * returned `shape` distinguishes them, and callers stamp `usage_shape` into
 * reserved telemetry metadata for the unrecognised case only — so an
 * unparseable payload is visible in the evidence rather than silently
 * indistinguishable from an honest absence.
 *
 * @packageDocumentation
 */
import type { TokenUsage } from "./types.js";

/**
 * What was found in the usage container.
 *
 * - `absent` — no usage container at all. The provider reported nothing; there
 *   is no defect here and nothing is stamped.
 * - `recognized` — at least one known field matched.
 * - `unrecognized` — a container was present and no known field matched. This
 *   is the one worth surfacing: it means a shape moved underneath obsvr.
 */
export type UsageShape = "absent" | "recognized" | "unrecognized";

export interface NormalizedUsage {
  /** Omitted entirely unless at least one count was actually read. */
  usage?: TokenUsage;
  shape: UsageShape;
}

/** The reserved-telemetry key carrying the reason, stamped only when a usage
 *  container could not be read. Reserved metadata rather than a top-level event
 *  field: the signed event schema and its conformance fixtures stay untouched,
 *  and ingest already lifts this channel out first-class. */
export const USAGE_SHAPE_TELEMETRY_KEY = "usage_shape";

const INPUT_ALIASES = [
  "input_tokens",
  "prompt_tokens",
  "inputTokens",
  "promptTokens",
  "promptTokenCount",
  "inputTextTokenCount",
] as const;

const OUTPUT_ALIASES = [
  "output_tokens",
  "completion_tokens",
  "outputTokens",
  "completionTokens",
  "candidatesTokenCount",
] as const;

const TOTAL_ALIASES = ["total_tokens", "totalTokens", "totalTokenCount"] as const;

function finite(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

/**
 * One token slot: a bare number, or an object carrying a numeric `total`.
 *
 * Only `total` is read out of the nested form. The siblings (`cacheRead`,
 * `reasoning`, …) are real data but they are cost DETAIL, not the count itself,
 * and they already have a home in the telemetry extractor — folding them in
 * here would make one number mean two things.
 */
function slot(v: unknown): number | undefined {
  const direct = finite(v);
  if (direct !== undefined) return direct;
  if (v && typeof v === "object") {
    return finite((v as Record<string, unknown>).total);
  }
  return undefined;
}

function firstAlias(
  container: Record<string, unknown>,
  aliases: readonly string[],
): number | undefined {
  for (const key of aliases) {
    // `in` rather than truthiness: a genuine 0 is a real measurement and must
    // not fall through to the next alias and end up absent.
    if (key in container) {
      const v = slot(container[key]);
      if (v !== undefined) return v;
    }
  }
  return undefined;
}

/**
 * Read token counts out of a provider or framework usage container.
 *
 * `total` is derived from input + output when the payload does not state it —
 * that is arithmetic over two known values, not a fabricated measurement, and
 * it is the only source of a total since the nested shape dropped `totalTokens`
 * outright.
 */
export function normalizeTokenUsage(container: unknown): NormalizedUsage {
  if (!container || typeof container !== "object") {
    return { shape: "absent" };
  }

  const c = container as Record<string, unknown>;
  const input = firstAlias(c, INPUT_ALIASES);
  const output = firstAlias(c, OUTPUT_ALIASES);
  const statedTotal = firstAlias(c, TOTAL_ALIASES);

  if (input === undefined && output === undefined && statedTotal === undefined) {
    // Present but unreadable. An empty object is the one benign case: a
    // provider that sent `usage: {}` reported nothing, same as sending nothing.
    return { shape: Object.keys(c).length === 0 ? "absent" : "unrecognized" };
  }

  const total =
    statedTotal ??
    (input !== undefined && output !== undefined ? input + output : undefined);

  const usage: TokenUsage = {};
  if (input !== undefined) usage.input_tokens = input;
  if (output !== undefined) usage.output_tokens = output;
  if (total !== undefined) usage.total_tokens = total;

  return { usage, shape: "recognized" };
}

/**
 * The common case: the counts, or `undefined` when there is nothing readable.
 * Callers that need to distinguish "unreadable" from "not reported" — the ones
 * that stamp `usage_shape` — should call {@link normalizeTokenUsage} instead.
 */
export function readTokenUsage(container: unknown): TokenUsage | undefined {
  return normalizeTokenUsage(container).usage;
}
