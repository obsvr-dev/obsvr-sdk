/**
 * Central failure-disposition registry.
 *
 * One question, answered in exactly one place: when a governance layer cannot
 * render a verdict - because it timed out, threw, or is running degraded -
 * does the call proceed or does it stop?
 *
 * Answering that per code path is how enforcement products rot. The same
 * detector ends up fail-open on one surface and fail-closed on another, a
 * reviewer reading either one draws the wrong conclusion about the other, and
 * nobody can state the product's failure posture without reading every branch.
 * So every layer declares its disposition here, the declarations are pinned by
 * conformance/fixtures/fail_mode.json, and both SDKs are asserted against that
 * one file.
 *
 * This registry DESCRIBES shipped behavior; it does not implement it. Nothing
 * on the call path reads it. Its jobs are (1) to make the posture reviewable
 * in one place, (2) to force any new detector to state its disposition before
 * it can land, and (3) to make a silent change of posture fail a test.
 *
 * Reading the table honestly matters more than making it look tidy - which is
 * why `unguarded` exists as a value. Several in-process detectors have no
 * error channel at all today: an unexpected exception inside them propagates
 * out to the host application. That is neither fail-open nor fail-closed, it
 * is the absence of a decision, and it is recorded as such (verified, not
 * assumed: injecting a throw into the builtin scanner surfaces the exception
 * at the caller in both languages). The MCP tool-call path, by contrast, does
 * guard its policy evaluation and resolves it by the configured fail mode. Same failure class,
 * different answers, one table that says so.
 *
 * Vocabulary:
 *   open            the call proceeds; the failure is logged and counted, and
 *                   that layer's enforcement is lost for this call
 *   closed          the call is blocked
 *   fail_mode       resolved by the configured fail mode: open by default,
 *                   closed when the operator opts in
 *   unguarded       no error channel: an exception propagates to the host
 *   not_applicable  the state cannot arise for this layer
 *
 * Qualifiers narrow a value without multiplying it:
 *   shadow_exempt     closed, unless that unit is observe-only (shadow)
 *   warn_mode_flags   closed in block mode, flags in warn mode; never silent
 *
 * @packageDocumentation
 */

/** The failure states a layer can be in. */
export type FailureState = "timeout" | "error" | "degraded";

/** What happens to the call in a given failure state. */
export type Disposition = "open" | "closed" | "fail_mode" | "unguarded" | "not_applicable";

/** Narrows a disposition without adding a value to the vocabulary. */
export type DispositionQualifier = "shadow_exempt" | "warn_mode_flags";

export interface StateDisposition {
  disposition: Disposition;
  qualifier?: DispositionQualifier;
}

export interface FailureDispositionEntry {
  /** Stable identifier for the layer; wire-visible in the fixture. */
  id: string;
  /** Source module that owns the layer, so a reviewer can check the claim. */
  module: string;
  timeout: StateDisposition;
  error: StateDisposition;
  degraded: StateDisposition;
  /**
   * Whether an EXPLICIT customer-hook allow can downgrade this layer's block.
   * A hook timeout or error never can, on any layer: only a hook that actually
   * rendered an allow verdict overrides builtin enforcement.
   */
  hookOverridable: boolean;
  /** Why the disposition is what it is. Kept short and checkable. */
  notes: string;
}

const s = (disposition: Disposition, qualifier?: DispositionQualifier): StateDisposition =>
  qualifier ? { disposition, qualifier } : { disposition };

/**
 * The declarations. Ordered by pipeline position, then by tool-surface layers,
 * so the table reads in the order a call meets them.
 */
export const FAILURE_DISPOSITIONS: readonly FailureDispositionEntry[] = Object.freeze([
  {
    id: "enforcement_integrity_gate",
    module: "sdk/src/proxy/config.ts",
    timeout: s("not_applicable"),
    error: s("open"),
    degraded: s("closed"),
    hookOverridable: false,
    notes:
      "A failed policy poll does not block by itself; it counts toward staleness. Degraded state blocks: a revoked key or paused project always, and stale sync when the fail mode is closed. Not overridable by any means - the server has withdrawn authorization.",
  },
  {
    id: "policy_signature",
    module: "sdk/src/proxy/policy-verify.ts",
    timeout: s("not_applicable"),
    error: s("open"),
    degraded: s("open"),
    hookOverridable: false,
    notes:
      "Runs on the poll path, not the call path, so its failure is closed for the POLICY and open for the CALL: an unsigned, tampered, forged, or rolled-back payload is never applied and the last-good policy keeps governing, while in-flight calls proceed under it. Degraded means the signature could not be checked at all (Python without an Ed25519 backend); the policy is refused the same way and events carry policy_verification_unavailable. Either way the sync did not succeed, so staleness accrues and the integrity gate turns it into a block when the fail mode is closed.",
  },
  {
    id: "session_taint",
    module: "sdk/src/policy/session-taint.ts",
    timeout: s("not_applicable"),
    error: s("unguarded"),
    degraded: s("not_applicable"),
    hookOverridable: true,
    notes: "Pure in-process latch over a bounded store. No timeout channel, no error channel.",
  },
  {
    id: "canary",
    module: "sdk/src/policy/canary.ts",
    timeout: s("not_applicable"),
    error: s("unguarded"),
    degraded: s("not_applicable"),
    hookOverridable: false,
    notes:
      "A canary leak is unsuppressible: the hook-override branch excludes it explicitly, because a leaked canary is proof of exfiltration in progress.",
  },
  {
    id: "builtin_pii_scan",
    module: "sdk/src/policy/hook.ts",
    timeout: s("not_applicable"),
    error: s("unguarded"),
    degraded: s("not_applicable"),
    hookOverridable: true,
    notes:
      "Regex tier, bounded by the ReDoS-checked matcher rather than a timeout. An explicit hook allow can override its block; a hook timeout or error cannot.",
  },
  {
    id: "presidio_merge",
    module: "sdk/src/policy/presidio.ts",
    timeout: s("open"),
    error: s("open"),
    degraded: s("open"),
    hookOverridable: true,
    notes:
      "Out-of-process NER sidecar. Timeout or transport error yields no findings and the builtin regex tier still decides, so the layer degrades rather than disappears.",
  },
  {
    id: "deobfuscation_views",
    module: "sdk/src/policy/deobfuscate.ts",
    timeout: s("not_applicable"),
    error: s("unguarded"),
    degraded: s("not_applicable"),
    hookOverridable: true,
    notes:
      "Findings-only view producer; malformed encodings are handled internally (an undecodable view is simply not produced) rather than raised.",
  },
  {
    id: "multi_turn_injection",
    module: "sdk/src/policy/injection-session.ts",
    timeout: s("not_applicable"),
    error: s("unguarded"),
    degraded: s("not_applicable"),
    hookOverridable: true,
    notes: "In-process accumulator over a bounded store; scoring is arithmetic with no failure channel.",
  },
  {
    id: "policy_floor",
    module: "sdk/src/policy/rules.ts",
    timeout: s("not_applicable"),
    error: s("unguarded"),
    degraded: s("not_applicable"),
    hookOverridable: false,
    notes:
      "The non-overridable baseline. A floor redact the pipeline cannot guarantee fails CLOSED to a block rather than forward content under a false redacted record. Hook attempts to override are refused and recorded on the event.",
  },
  {
    id: "policy_rules",
    module: "sdk/src/policy/rules.ts",
    timeout: s("not_applicable"),
    error: s("unguarded"),
    degraded: s("not_applicable"),
    hookOverridable: true,
    notes: "Deterministic rule evaluation; regex conditions are ReDoS-checked rather than timed out.",
  },
  {
    id: "customer_hook",
    module: "sdk/src/proxy/wrapper.ts",
    timeout: s("fail_mode"),
    error: s("fail_mode"),
    degraded: s("not_applicable"),
    hookOverridable: false,
    notes:
      "The one layer whose disposition the operator chooses: open by default, closed on opt-in. A timeout or error is recorded as its own hook disposition and can never un-block builtin enforcement - only an explicit allow verdict does that.",
  },
  {
    id: "external_backend",
    module: "sdk/src/policy/external-backend.ts",
    timeout: s("closed", "shadow_exempt"),
    error: s("closed", "shadow_exempt"),
    degraded: s("not_applicable"),
    hookOverridable: false,
    notes:
      "An external decision point that cannot answer is a deny, because the operator asked for its verdict on every call. Observe-only (shadow) backends are exempt: they were never load-bearing.",
  },
  {
    id: "mcp_tool_policy",
    module: "sdk/src/integrations/mcp.ts",
    timeout: s("not_applicable"),
    error: s("fail_mode"),
    degraded: s("closed"),
    hookOverridable: false,
    notes:
      "The tool-call path guards its own policy evaluation and resolves failure by the configured fail mode - the posture the provider pipeline states but does not yet implement. Degraded enforcement blocks tool calls like any other governed call.",
  },
  {
    id: "tool_pinning",
    module: "sdk/src/policy/tool-pinning.ts",
    timeout: s("not_applicable"),
    error: s("closed", "warn_mode_flags"),
    degraded: s("not_applicable"),
    hookOverridable: false,
    notes:
      "A descriptor that cannot be hashed is treated as a mismatch, never as a pass. Enforcement follows the configured pinning mode (block blocks, warn flags); neither is silent. Contained per tool so one unhashable entry cannot abort discovery.",
  },
  {
    id: "tool_result_scan",
    module: "sdk/src/policy/response-scan.ts",
    timeout: s("not_applicable"),
    error: s("unguarded"),
    degraded: s("not_applicable"),
    hookOverridable: false,
    notes:
      "Response-side scan of tool results, the exfiltration channel. Runs outside the tool-call path's policy guard, so an exception here reaches the caller.",
  },
]);

/** Every declared layer id. */
export const DECLARED_LAYER_IDS: readonly string[] = Object.freeze(
  FAILURE_DISPOSITIONS.map((e) => e.id),
);

/** Look up one layer's declaration. */
export function getFailureDisposition(id: string): FailureDispositionEntry | undefined {
  return FAILURE_DISPOSITIONS.find((e) => e.id === id);
}

/** The declared disposition of one layer in one failure state. */
export function dispositionFor(id: string, state: FailureState): StateDisposition | undefined {
  return getFailureDisposition(id)?.[state];
}

/**
 * Layers whose failure currently escapes to the host rather than resolving to
 * a decision. Exposed so the gap is countable and can be watched rather than
 * rediscovered.
 */
export function unguardedLayerIds(): string[] {
  return FAILURE_DISPOSITIONS.filter(
    (e) =>
      e.timeout.disposition === "unguarded" ||
      e.error.disposition === "unguarded" ||
      e.degraded.disposition === "unguarded",
  ).map((e) => e.id);
}
