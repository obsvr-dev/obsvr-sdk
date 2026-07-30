/**
 * The one place a detector exception becomes a decision (TypeScript side).
 *
 * Eight in-process detector layers have no error channel of their own, so an
 * exception inside one used to propagate out of the host's own LLM call -
 * neither fail-open nor fail-closed, but the absence of a decision. Every
 * guarded call site funnels here so the rule exists once instead of per path.
 *
 * The rule: every internal failure resolves by failMode, except where the act
 * itself forecloses the choice. The floor class is one such case, by definition
 * the thing failMode cannot move. It is NOT the only one, and stating it as the
 * sole exception was wrong: `applyOutboundRedaction` also resolves closed at
 * failMode "open" (argued at :128-131 — a redaction that cannot be guaranteed
 * must not be forwarded), and `recordCheckOnlyFailure` is a third. The
 * behaviour in each case is deliberate; the absolute in this header was what
 * did not match it.
 *
 * The response phase over the MODEL's answer is different and deliberately so:
 * once the provider has answered, "closed" is not an available action. Blocking
 * cannot undo the answer, and the published contract is that a response-side
 * control over that surface never withholds the value returned to the caller.
 * So THAT phase never raises and never withholds - it fails closed only on the
 * STORED audit copy, which is the one thing still in the SDK's hands.
 *
 * That is NOT true of every surface this phase label covers, and the header
 * used to read as if it were. The MCP tool-RESULT gate runs in the response
 * phase and is PRE-DELIVERY - the value has not reached the caller yet - so it
 * both raises and withholds, deliberately, and `mcp.ts` says so forty lines
 * from here. Measured: a response-target block rule, a PII block, and a planted
 * canary each raise out of `obsvrGovernMCP`, and a PII `redact` rewrites the
 * value the caller receives. The distinction is whether the surface is still
 * pre-delivery, not whether the label says "response".
 *
 * Twin: sdk-python/obsvr/policy.py (`record_detector_failure`).
 *
 * @packageDocumentation
 */

import type { ResolvedConfig } from "../proxy/types.js";

/**
 * Layers whose disposition failMode cannot move. A floor is the operator's
 * non-overridable baseline, so a floor that CANNOT RUN is the strongest form
 * of "cannot guarantee" - it fails closed, exactly as a floor redact that
 * cannot be guaranteed already fails closed to a block.
 */
export const FLOOR_CLASS_LAYERS: ReadonlySet<string> = new Set(["policy_floor", "canary"]);

/**
 * Stored-copy marker for content NOTHING scanned, because the scanner that
 * would have vetted it raised. Deliberately NOT a "[REDACTED..." token: every
 * other placeholder here means "a scan ran and removed something", and an
 * auditor who cannot tell that apart from "we never looked" has to treat every
 * redaction as possibly the second.
 */
export const UNSCANNED_PLACEHOLDER = "[UNSCANNED:detector_error]";

/** Detector exceptions this process has resolved (fleet-poll counter). */
let detectorErrors = 0;

export function getDetectorErrorCount(): number {
  return detectorErrors;
}

/** Reset the counter (tests only). */
export function _resetDetectorErrors(): void {
  detectorErrors = 0;
}

/** Per-event record of which layer was lost and how it resolved. */
export interface DetectorFailure {
  layer: string;
  error: string;
  resolution: "open" | "closed";
  floor_class: boolean;
  phase: "pre_call" | "response" | "event_build" | "enforcement_application";
  stored_unscanned?: boolean;
}

/**
 * Count and log one detector failure; return true if it resolves CLOSED.
 * Never re-raises - an SDK defect must not surface as an unhandled error in
 * the calling application.
 */
export function recordDetectorFailure(
  layer: string,
  err: unknown,
  config: Pick<ResolvedConfig, "failMode"> | undefined,
): boolean {
  detectorErrors += 1;
  const failClosed =
    FLOOR_CLASS_LAYERS.has(layer) || (config?.failMode ?? "open") === "closed";
  // eslint-disable-next-line no-console
  console.error(
    `[obsvr] detector layer "${layer || "unknown"}" failed (${describeError(err)}); ` +
      `resolving ${failClosed ? "closed" : "open"}. The call was ` +
      `${failClosed ? "BLOCKED" : "allowed with this layer's enforcement lost"}. ` +
      `This is an SDK defect - please report it.`,
  );
  return failClosed;
}

/**
 * What a caller must do when an outbound redaction could not be applied.
 * Present ⟹ block; absent ⟹ the redaction completed.
 */
export interface OutboundRedactionFailure {
  failure: DetectorFailure;
  ruleId: string;
  policyReason: string;
}

function outboundFailure(layer: string, err: unknown): OutboundRedactionFailure {
  detectorErrors += 1;
  // eslint-disable-next-line no-console
  console.error(
    `[obsvr] detector layer "${layer || "unknown"}" failed while APPLYING a ` +
      `redaction (${describeError(err)}); resolving closed. The call was BLOCKED - ` +
      `the SDK does not forward content it cannot guarantee was redacted. ` +
      `This is an SDK defect - please report it.`,
  );
  const why =
    `Redaction could not be applied: detector layer '${layer || "unknown"}' raised ` +
    `${describeError(err)}; blocked rather than forwarded unredacted`;
  return {
    failure: detectorFailureRecord(layer, err, "closed", "enforcement_application"),
    ruleId: "sdk:detector_error",
    policyReason: why.slice(0, 256),
  };
}

/**
 * Apply a redaction to OUTBOUND content, reporting failure instead of throwing.
 *
 * This is the enforcement-APPLICATION phase, and it is deliberately not the
 * pre-call rule. Pre-call resolves by failMode because a DETECTION failure
 * means the SDK does not know whether sensitive content is present, and
 * proceeding is a bounded risk. Here the scan already ran, already found
 * something, and policy already said remove it: the uncertainty is resolved
 * against us, so failing open would transmit to a third party exactly the
 * content the SDK was told to strip.
 *
 * So it fails CLOSED regardless of failMode, on the same reasoning the floor
 * already uses one step away - a floor redact that cannot be guaranteed blocks
 * because the SDK must never forward content it cannot guarantee was redacted.
 * That rule is about the act of forwarding, not about the rule being a floor.
 *
 * The in-place redactors walk message structures field by field, so a throw
 * mid-walk leaves a PARTIALLY redacted request. Forwarding that is the worst
 * of the three outcomes: it still carries unredacted content while looking, to
 * every downstream reader, like a redaction that succeeded.
 *
 * Callers must also drop any "redacted" claim from the event: an audit record
 * asserting a redaction that did not happen is worse than none, because it
 * tells an auditor the content was cleaned.
 *
 * Twin: sdk-python/obsvr/policy.py (`apply_outbound_redaction`).
 */
export function applyOutboundRedaction(
  redact: () => void,
  layer = "builtin_pii_scan",
): OutboundRedactionFailure | undefined {
  try {
    redact();
    return undefined;
  } catch (err) {
    return outboundFailure(layer, err);
  }
}

/** Async twin, for the paths whose redactors await an external anonymizer. */
export async function applyOutboundRedactionAsync(
  redact: () => Promise<void> | void,
  layer = "builtin_pii_scan",
): Promise<OutboundRedactionFailure | undefined> {
  try {
    await redact();
    return undefined;
  } catch (err) {
    return outboundFailure(layer, err);
  }
}

/**
 * Count and log a failure on a surface that is STRUCTURALLY always open, so
 * the log does not assert a resolution the caller will not apply.
 *
 * `recordDetectorFailure` reports "resolving closed / the call was BLOCKED"
 * whenever failMode says so. That message is wrong for a unit that cannot
 * block by construction: a shadow rule runs after the active decision is final
 * and is defined as never decision-affecting, and the policy-version hash is a
 * provenance field. Honouring failMode at either would let a check-only unit
 * stop a call, which is the one thing shadow mode promises it cannot do.
 *
 * Twin: sdk-python/obsvr/policy.py (`record_check_only_failure`).
 */
export function recordCheckOnlyFailure(layer: string, err: unknown): void {
  detectorErrors += 1;
  // eslint-disable-next-line no-console
  console.error(
    `[obsvr] detector layer "${layer || "unknown"}" failed on a check-only ` +
      `surface (${describeError(err)}). The call is UNAFFECTED - this unit ` +
      `never decides anything - and only its own output was lost. ` +
      `This is an SDK defect - please report it.`,
  );
}

/** Short, bounded description of a thrown value for the audit record. */
export function describeError(err: unknown): string {
  if (err instanceof Error) return `${err.name}: ${err.message}`.slice(0, 200);
  return String(err).slice(0, 200);
}

/** The telemetry object stamped on the call's own event. */
export function detectorFailureRecord(
  layer: string,
  err: unknown,
  resolution: "open" | "closed",
  phase: DetectorFailure["phase"],
  storedUnscanned = false,
): DetectorFailure {
  return {
    layer: layer || "unknown",
    error: describeError(err),
    resolution,
    floor_class: FLOOR_CLASS_LAYERS.has(layer),
    phase,
    ...(storedUnscanned ? { stored_unscanned: true } : {}),
  };
}

/**
 * Resolve a RESPONSE-phase failure: never raises, never withholds the caller's
 * value, and reports that the stored copy must be withheld instead.
 */
export function resolveResponsePhaseFailure(
  layer: string,
  err: unknown,
  config: Pick<ResolvedConfig, "failMode"> | undefined,
): { storedCopy: string; failure: DetectorFailure } {
  recordDetectorFailure(layer, err, config);
  return {
    storedCopy: UNSCANNED_PLACEHOLDER,
    failure: detectorFailureRecord(layer, err, "open", "response", true),
  };
}

/** Compliance block for a failed detector layer. Structurally compatible with
 *  ComplianceInfo; typed locally so this module stays free of an import cycle
 *  back into the integrations layer. */
export interface DetectorFailureCompliance {
  event_type: string;
  policy_version: string;
  action_taken: string;
  action_reason: string;
  action_source: string;
  redacted_types: string[];
  blocked_types: string[];
  rule_id: string;
  policy_reason: string;
  detector_failure: DetectorFailure;
}

/**
 * The compliance block a guarded pre-call site returns. `action_taken` stays
 * inside the closed wire enum - a detector failure never mints a new value.
 */
export function preCallFailureCompliance(
  layer: string,
  err: unknown,
  failClosed: boolean,
  policyVersion: string,
): DetectorFailureCompliance {
  const floorClass = FLOOR_CLASS_LAYERS.has(layer);
  const why = floorClass
    ? "resolved closed (floor class cannot fail open)"
    : failClosed
      ? "resolved closed (failMode)"
      : "resolved open, enforcement lost for this call";
  return {
    event_type: failClosed ? "blocked_call" : "policy_flag",
    policy_version: policyVersion,
    action_taken: failClosed ? "blocked" : "allowed",
    action_reason: failClosed ? "policy_violation" : "none",
    action_source: "builtin",
    redacted_types: [],
    blocked_types: [],
    rule_id: "sdk:detector_error",
    policy_reason: `Detector layer '${layer || "unknown"}' raised ${describeError(err)}; ${why}`.slice(0, 256),
    detector_failure: detectorFailureRecord(layer, err, failClosed ? "closed" : "open", "pre_call"),
  };
}

/**
 * The compliance block a guarded RESPONSE-phase site returns.
 *
 * `action_taken` stays "allowed" and the resolution stays "open" even for the
 * floor class: once the provider has answered, "closed" is not an available
 * action, and the published contract is that a response-side control never
 * withholds the value returned to the caller. The one thing that DID fail
 * closed - the stored audit copy - is recorded by `stored_unscanned`, so an
 * auditor can find it without string-matching content.
 */
export function responsePhaseFailureCompliance(
  layer: string,
  err: unknown,
  policyVersion: string,
): DetectorFailureCompliance {
  const why =
    `Response-phase detector layer '${layer || "unknown"}' raised ${describeError(err)}; ` +
    "response delivered unchanged, stored copy withheld";
  return {
    event_type: "policy_flag",
    policy_version: policyVersion,
    action_taken: "allowed",
    action_reason: "none",
    action_source: "builtin",
    redacted_types: [],
    blocked_types: [],
    rule_id: "sdk:detector_error",
    policy_reason: why.slice(0, 256),
    detector_failure: detectorFailureRecord(layer, err, "open", "response", true),
  };
}

/**
 * Derive the policy version for a failure record WITHOUT trusting the inputs
 * that just failed.
 *
 * The version is a hash over the same rules a detector may have choked on, so
 * a resolver that recomputed it naively throws out of its own catch block -
 * turning the guard back into the unguarded propagation it exists to replace.
 * Same lesson as `safeStoredCopy`: nothing on the failure path may re-run the
 * code that failed and assume it works this time.
 */
export function safePolicyVersion(derive: () => string): string {
  try {
    return derive();
  } catch {
    return "unknown";
  }
}

/**
 * Redact a stored copy without trusting the redactor: the scan that would have
 * produced it may be exactly what just failed. Falls back to the unscanned
 * marker rather than persisting text nothing vetted.
 */
export function safeStoredCopy(redact: () => string): string {
  try {
    return redact();
  } catch {
    return UNSCANNED_PLACEHOLDER;
  }
}
