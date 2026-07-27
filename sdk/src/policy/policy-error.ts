/**
 * The typed error a policy block throws.
 *
 * A blocked call has to be distinguishable from a provider outage, a bad API
 * key, or a network failure - the caller's fallback behavior is different for
 * each, and "the request was refused on purpose" is the one case where
 * retrying is pointless. Until now the block threw a plain `Error` whose only
 * distinguishing feature was its message, so the de facto contract was string
 * matching on prose. That breaks the first time the wording improves.
 *
 * ```ts
 * try {
 *   await client.chat.completions.create({ ... });
 * } catch (err) {
 *   if (err instanceof ObsvrPolicyError) {
 *     // refused by policy: err.reason_code, err.rule_id, err.decision
 *   } else {
 *     // provider or transport failure: retry, fall back, surface
 *   }
 * }
 * ```
 *
 * Design rules this file exists to enforce:
 *
 * - **One construction point.** Every block-throw site calls
 *   {@link createPolicyError}. Classification never gets scattered across call
 *   sites, because that is how two call sites come to classify the same
 *   failure differently.
 * - **Explicit type strings.** `type` is set literally per class, never derived
 *   from `constructor.name`, so it survives minification and cross-realm
 *   boundaries where `instanceof` does not.
 * - **A fallback class, never a raw throw.** A reason category this version
 *   does not know still produces a typed error ({@link ObsvrUnknownPolicyError})
 *   rather than degrading to a plain Error. Forward compatibility with a
 *   control plane that can introduce categories faster than SDKs ship.
 * - **The message is unchanged.** Existing code that string-matches the old
 *   message keeps working; this is additive.
 *
 * Cross-language parity is asserted on the serialized fields, not the class
 * hierarchy (Python's twin is obsvr/errors.py), and pinned by
 * conformance/fixtures/error_parity.json.
 *
 * @packageDocumentation
 */

import { ReasonCode } from "../governance/reason-codes.js";

/** Decision metadata carried on the error, mirroring the emitted event. */
export interface ObsvrPolicyDecision {
  /** Always "blocked" for a thrown policy error; present for symmetry with the event. */
  action_taken: string;
  /** Why: "pii_detected", "policy_violation", ... */
  action_reason: string;
  /** Which layer decided: "builtin", "policy_rules", "customer_hook", "external_backend", ... */
  action_source: string;
  /** Canonical rules hash in force at decision time, when known. */
  policy_version?: string;
  /** Free-form detail from the deciding layer, when it supplied one. */
  policy_reason?: string;
}

/** What {@link createPolicyError} needs to classify and construct. */
export interface PolicyErrorInput {
  action_reason?: string;
  action_source?: string;
  action_taken?: string;
  policy_version?: string;
  policy_reason?: string;
  rule_id?: string;
  /** Set when the deciding layer already resolved a reason code. */
  reason_code?: string;
}

/**
 * Thrown when a call is refused by policy. Carries the same facts the audit
 * event carries, so a caller can branch on the decision without parsing text.
 */
export class ObsvrPolicyError extends Error {
  /** Stable wire string, set explicitly per class. */
  readonly type: string = "obsvr_policy_error";
  /** Reason code from the closed registry (conformance/fixtures/reason_codes.json). */
  readonly reason_code: string;
  /** The rule that decided, when a rule decided. */
  readonly rule_id?: string;
  /** Decision metadata mirroring the emitted event. */
  readonly decision: ObsvrPolicyDecision;

  constructor(message: string, reasonCode: string, decision: ObsvrPolicyDecision, ruleId?: string) {
    super(message);
    // Set explicitly rather than via constructor.name: minifiers rename
    // classes, and `name` is what most logging pipelines print.
    this.name = "ObsvrPolicyError";
    this.reason_code = reasonCode;
    this.decision = decision;
    if (ruleId !== undefined) this.rule_id = ruleId;
    // Restore the prototype chain so `instanceof` works when this file is
    // transpiled to a target that breaks subclassing of built-ins.
    Object.setPrototypeOf(this, new.target.prototype);
  }

  /** Serialized shape asserted for cross-language parity. */
  toJSON(): Record<string, unknown> {
    return {
      type: this.type,
      reason_code: this.reason_code,
      ...(this.rule_id !== undefined ? { rule_id: this.rule_id } : {}),
      decision: this.decision,
      message: this.message,
    };
  }
}

/**
 * A block whose reason category this SDK version does not recognize - most
 * likely a newer control plane. Still a policy error, still catchable the same
 * way, still carrying whatever the server said; only the classification is
 * unknown.
 */
export class ObsvrUnknownPolicyError extends ObsvrPolicyError {
  readonly type: string = "obsvr_unknown_policy_error";

  constructor(message: string, reasonCode: string, decision: ObsvrPolicyDecision, ruleId?: string) {
    super(message, reasonCode, decision, ruleId);
    this.name = "ObsvrUnknownPolicyError";
  }
}

/** The block reason categories this version knows how to classify. */
const KNOWN_REASONS = new Set(["pii_detected", "policy_violation", "customer_override", "none"]);

/**
 * The message a policy block has always produced. Preserved byte-for-byte
 * (including for unknown categories, which fall to the "policy violation"
 * wording exactly as the old ternary did) so existing string matches survive.
 */
export function policyBlockMessage(actionReason: string | undefined): string {
  const detail = actionReason === "pii_detected" ? "PII detected" : "policy violation";
  return `[obsvr] Request blocked by policy (${detail})`;
}

/**
 * Resolve the reason code for a block from what the deciding layer recorded.
 * An explicit code from the layer always wins; otherwise it is derived from
 * the reason and the deciding source.
 *
 * Exported so the event-assembly paths stamp the SAME resolution on the
 * audit event that the thrown error carries — one derivation, two consumers,
 * no way for the record and the error to disagree.
 */
export function resolveReasonCode(input: PolicyErrorInput): string {
  if (input.reason_code) return input.reason_code;
  if (input.action_reason === "pii_detected") return ReasonCode.PII_DETECTED;
  if (!KNOWN_REASONS.has(input.action_reason ?? "")) return ReasonCode.UNKNOWN_BLOCKED;
  switch (input.action_source) {
    case "customer_hook":
      return ReasonCode.HOOK_BLOCKED;
    case "external_backend":
      return ReasonCode.EXTERNAL_BACKEND_DENY;
    default:
      return ReasonCode.POLICY_VIOLATION;
  }
}

/**
 * The single construction choke point. Every block-throw site in the SDK calls
 * this; nothing else constructs a policy error.
 */
export function createPolicyError(input: PolicyErrorInput): ObsvrPolicyError {
  const decision: ObsvrPolicyDecision = {
    action_taken: input.action_taken ?? "blocked",
    action_reason: input.action_reason ?? "policy_violation",
    action_source: input.action_source ?? "unknown",
    ...(input.policy_version !== undefined ? { policy_version: input.policy_version } : {}),
    ...(input.policy_reason !== undefined ? { policy_reason: input.policy_reason } : {}),
  };
  const message = policyBlockMessage(input.action_reason);
  const reasonCode = resolveReasonCode(input);
  const known = KNOWN_REASONS.has(input.action_reason ?? "");

  return known
    ? new ObsvrPolicyError(message, reasonCode, decision, input.rule_id)
    : new ObsvrUnknownPolicyError(message, reasonCode, decision, input.rule_id);
}
