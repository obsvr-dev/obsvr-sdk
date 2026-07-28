/**
 * Layered call cost.
 *
 * Three layers, each overriding the one before it, and ALL of them retained:
 *
 *   1. **Caller/tool estimate** — what the caller said the call would cost.
 *   2. **Policy mapping** — what the operator declares it costs, which
 *      overrides layer 1. A tool's own claim about its cost is a claim by the
 *      party being governed, so an operator who has written a number wins.
 *   3. **Runtime metering** — actual provider-reported usage priced at the
 *      operator's own rates, available only after the call answers.
 *
 * The reason to keep all three rather than collapse to the best one is the
 * whole reason this belongs in an evidence product: **the gap between what was
 * expected and what was spent is itself a finding.** A tool that consistently
 * estimates an order of magnitude under its metered cost is either broken or
 * lying, and a record that kept only the corrected figure cannot tell you
 * which. So the event carries the estimate, the metered value, and their
 * signed difference.
 *
 * ## No price list ships here
 *
 * There is no vendored table of provider prices, and there will not be. Prices
 * change on the vendor's schedule, not this package's, and a stale rate baked
 * into a released SDK produces a *sealed* wrong number — worse than no number
 * at all, because sealed evidence cannot be reissued. Rates are declared by the
 * operator, in their own configuration, and the rate set that priced a call is
 * hashed onto the event so an auditor can tell which rates were in force.
 *
 * ## Integer micro-units, not floating point
 *
 * Every amount here is an INTEGER count of millionths of a currency unit.
 * Money computed in binary floating point does not agree between two runtimes
 * at the edges, and "the two SDKs seal amounts that differ in the last place"
 * is not a defect an evidence product can carry. Integer arithmetic with a
 * stated rounding rule (half-up on the final division, applied once) is
 * identical in both languages and is fixture-pinnable to the unit.
 *
 * Cost resolution is arithmetic over numbers the caller already holds — no
 * I/O, no allocation beyond the result — and runs once per call.
 *
 * @packageDocumentation
 */

/** Operator-declared rates, in integer micro-units per 1,000 tokens. */
export interface CostRate {
  /** Micro-units per 1,000 input (prompt) tokens. */
  input_micros_per_1k?: number;
  /** Micro-units per 1,000 output (completion) tokens. */
  output_micros_per_1k?: number;
}

/** The cost sub-config. All fields optional; absent means cost is not resolved. */
export interface CostPolicyConfig {
  /**
   * ISO 4217 code recorded alongside every amount. Never used in arithmetic —
   * the SDK does not convert currencies, and an amount whose unit is implicit
   * is not evidence.
   */
  currency?: string;
  /**
   * Model rates, keyed by model name or a PREFIX of one ("gpt-4" covers
   * "gpt-4o-mini"). Longest matching prefix wins, which is unique: two
   * distinct keys cannot both be the longest prefix of one model string.
   */
  rates?: Record<string, CostRate>;
  /**
   * Layer 2: operator-declared flat cost per action or model, in micro-units.
   * Overrides whatever the caller declared. Keyed the same way as `rates`,
   * matched first against the action name and then against the model.
   */
  declared?: Record<string, number>;
}

/** Where a resolved estimate came from. */
export type CostEstimateSource = "policy" | "caller";

/** The resolved cost of one call. Every amount is integer micro-units. */
export interface ResolvedCost {
  currency?: string;
  /** Layer 1 or 2, whichever applied. Absent when neither declared anything. */
  estimate_micros?: number;
  /** Which layer produced the estimate. */
  estimate_source?: CostEstimateSource;
  /** Layer 3: actual usage priced at the operator's rates. */
  metered_micros?: number;
  /**
   * metered - estimate, present only when BOTH are. This is the auditable
   * quantity: a persistent one-sided gap is a finding about the estimator,
   * and it exists on the record whether or not anyone looks.
   */
  delta_micros?: number;
}

/** A finite, non-negative integer, or undefined. Everything else is rejected. */
function asMicros(value: unknown): number | undefined {
  if (typeof value !== "number" || !Number.isFinite(value)) return undefined;
  if (!Number.isSafeInteger(value)) return undefined;
  if (value < 0) return undefined;
  return value;
}

/** A finite, non-negative token count, or undefined. */
function asTokens(value: unknown): number | undefined {
  if (typeof value !== "number" || !Number.isFinite(value)) return undefined;
  if (!Number.isSafeInteger(value) || value < 0) return undefined;
  return value;
}

/**
 * The longest key of `table` that `subject` starts with, or undefined.
 * Deterministic: the longest prefix of a given string is unique among distinct
 * keys, so no tie-break is needed and none is invented.
 */
export function longestPrefixKey(
  table: Record<string, unknown> | undefined,
  subject: string,
): string | undefined {
  if (!table || !subject) return undefined;
  let best: string | undefined;
  for (const key of Object.keys(table)) {
    if (key.length === 0) continue;
    if (!subject.startsWith(key)) continue;
    if (best === undefined || key.length > best.length) best = key;
  }
  return best;
}

/**
 * Price a token count at a per-1,000 rate, in integer micro-units.
 *
 * Rounding is HALF-UP on the single final division, applied once, so the two
 * languages cannot drift: `floor((tokens * rate + 500) / 1000)` over
 * non-negative integers. Python's `round()` is banker's rounding and
 * JavaScript's `Math.round` is half-up-toward-positive-infinity, so neither
 * built-in is used on either side.
 */
export function priceTokens(tokens: number, microsPer1k: number): number {
  return Math.floor((tokens * microsPer1k + 500) / 1000);
}

/** Inputs to {@link resolveCallCost}. */
export interface CostInputs {
  policy?: CostPolicyConfig;
  /** The model this call used, for rate and declared-cost lookup. */
  model?: string;
  /** The action name, tried before the model for a declared cost. */
  actionName?: string;
  /** Layer 1: what the caller or tool said this would cost, in micro-units. */
  callerEstimateMicros?: unknown;
  /** Layer 3 inputs: provider-reported usage. Absent pre-call. */
  inputTokens?: unknown;
  outputTokens?: unknown;
}

/**
 * Resolve the layered cost of one call. Pure: no clock, no I/O, no per-process
 * state, so the same inputs always yield the same result. Pinned by
 * conformance/fixtures/cost.json.
 *
 * An absent layer is absent from the result rather than defaulted to zero: a
 * cost of zero and an unknown cost are different facts, and an evidence
 * product that renders the second as the first is lying quietly.
 */
export function resolveCallCost(inputs: CostInputs): ResolvedCost {
  const policy = inputs.policy;
  const out: ResolvedCost = {};
  if (typeof policy?.currency === "string" && policy.currency.length > 0) {
    out.currency = policy.currency;
  }

  // Layers 1 and 2. Later overrides earlier: the operator's declared number
  // beats whatever the caller claimed, because the caller is the party being
  // governed and its own cost claim is not evidence about itself.
  const callerEstimate = asMicros(inputs.callerEstimateMicros);
  if (callerEstimate !== undefined) {
    out.estimate_micros = callerEstimate;
    out.estimate_source = "caller";
  }
  const declaredKey =
    longestPrefixKey(policy?.declared, inputs.actionName ?? "") ??
    longestPrefixKey(policy?.declared, inputs.model ?? "");
  if (declaredKey !== undefined) {
    const declared = asMicros(policy?.declared?.[declaredKey]);
    if (declared !== undefined) {
      out.estimate_micros = declared;
      out.estimate_source = "policy";
    }
  }

  // Layer 3: what it actually cost, at the operator's own rates.
  const rateKey = longestPrefixKey(policy?.rates, inputs.model ?? "");
  const rate = rateKey === undefined ? undefined : policy?.rates?.[rateKey];
  if (rate !== undefined) {
    const inTokens = asTokens(inputs.inputTokens);
    const outTokens = asTokens(inputs.outputTokens);
    const inRate = asMicros(rate.input_micros_per_1k);
    const outRate = asMicros(rate.output_micros_per_1k);
    let metered: number | undefined;
    if (inTokens !== undefined && inRate !== undefined) {
      metered = priceTokens(inTokens, inRate);
    }
    if (outTokens !== undefined && outRate !== undefined) {
      metered = (metered ?? 0) + priceTokens(outTokens, outRate);
    }
    if (metered !== undefined) out.metered_micros = metered;
  }

  if (out.estimate_micros !== undefined && out.metered_micros !== undefined) {
    out.delta_micros = out.metered_micros - out.estimate_micros;
  }
  return out;
}

/** Reserved-metadata key the resolved cost rides on. */
export const COST_METADATA_KEY = "obsvr_cost";

/**
 * The metadata fragment carrying the resolved cost, empty when nothing
 * resolved. Spread it LAST at every emission site, after caller-supplied
 * metadata, so a key collision cannot overwrite it — the same precedence the
 * tool-content and pin stamps already use.
 *
 * It rides reserved `obsvr_*` metadata rather than a top-level field for the
 * reason the tool-content hash does: the ingest wire schema has no column for
 * it yet, and an unknown top-level field is stripped, so emitting it there
 * would lose it silently.
 */
export function costMetadata(cost: ResolvedCost | undefined): Record<string, unknown> {
  if (cost === undefined) return {};
  const keys = Object.keys(cost);
  if (keys.length === 0) return {};
  // A currency alone says nothing about this call; it is a unit with no value.
  if (keys.length === 1 && keys[0] === "currency") return {};
  return { [COST_METADATA_KEY]: cost };
}

/** Resolve the cost sub-config (absent => undefined). */
export function resolveCostPolicy(
  config: { costPolicy?: CostPolicyConfig } | undefined,
): CostPolicyConfig | undefined {
  const c = config?.costPolicy;
  if (!c) return undefined;
  const hasRates = !!c.rates && Object.keys(c.rates).length > 0;
  const hasDeclared = !!c.declared && Object.keys(c.declared).length > 0;
  if (!hasRates && !hasDeclared) return undefined;
  return c;
}
