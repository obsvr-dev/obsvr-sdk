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
export type DispositionQualifier =
  | "shadow_exempt"
  | "warn_mode_flags"
  | "redaction_application_closed";

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
    module: "sdk-typescript/src/proxy/config.ts",
    timeout: s("not_applicable"),
    error: s("open"),
    degraded: s("closed"),
    hookOverridable: false,
    notes:
      "A failed policy poll does not block by itself; it counts toward staleness. Degraded state blocks: a revoked key or paused project always, and stale sync when the fail mode is closed. Not overridable by any means - the server has withdrawn authorization.",
  },
  {
    id: "policy_signature",
    module: "sdk-typescript/src/proxy/policy-verify.ts",
    timeout: s("not_applicable"),
    error: s("open"),
    degraded: s("open"),
    hookOverridable: false,
    notes:
      "Runs on the poll path, not the call path, so its failure is closed for the POLICY and open for the CALL: an unsigned, tampered, forged, or rolled-back payload is never applied and the last-good policy keeps governing, while in-flight calls proceed under it. Degraded means the signature could not be checked at all (Python without an Ed25519 backend); the policy is refused the same way and events carry policy_verification_unavailable. Either way the sync did not succeed, so staleness accrues and the integrity gate turns it into a block when the fail mode is closed.",
  },
  {
    id: "session_taint",
    module: "sdk-typescript/src/policy/session-taint.ts",
    timeout: s("not_applicable"),
    error: s("fail_mode"),
    degraded: s("not_applicable"),
    hookOverridable: true,
    notes: "Guarded at the pre-call span in both languages and at the tool-execution path. An exception resolves by failMode: open loses this layer's escalation for the call, closed refuses it.",
  },
  {
    id: "canary",
    module: "sdk-typescript/src/policy/canary.ts",
    timeout: s("not_applicable"),
    error: s("closed"),
    degraded: s("not_applicable"),
    hookOverridable: false,
    notes: "Floor class: resolves CLOSED regardless of failMode, because a layer that cannot run is the strongest form of 'cannot guarantee' and a canary block is unsuppressible by construction. The response phase is the exception - once an answer exists it is never withheld, so there the failure falls closed only on the stored copy.",
  },
  {
    id: "builtin_pii_scan",
    module: "sdk-typescript/src/policy/hook.ts",
    timeout: s("not_applicable"),
    error: s("fail_mode", "redaction_application_closed"),
    degraded: s("not_applicable"),
    hookOverridable: true,
    notes: "Guarded at every pre-call span. Detection resolves by failMode; APPLYING a resolved redaction to outbound content resolves closed - see the redaction_application_closed qualifier.",
  },
  {
    id: "presidio_merge",
    module: "sdk-typescript/src/policy/presidio.ts",
    timeout: s("open"),
    error: s("open"),
    degraded: s("open"),
    hookOverridable: true,
    notes:
      "Out-of-process NER sidecar. Timeout or transport error yields no findings and the builtin regex tier still decides, so the layer degrades rather than disappears.",
  },
  {
    id: "deobfuscation_views",
    module: "sdk-typescript/src/policy/deobfuscate.ts",
    timeout: s("not_applicable"),
    error: s("fail_mode", "redaction_application_closed"),
    degraded: s("not_applicable"),
    hookOverridable: true,
    notes: "Guarded with the scan it feeds. Detection resolves by failMode; the stored-copy redactor fails closed to [UNSCANNED:detector_error] rather than persist text nothing vetted, and outbound application resolves closed - see the redaction_application_closed qualifier.",
  },
  {
    id: "multi_turn_injection",
    module: "sdk-typescript/src/policy/injection-session.ts",
    timeout: s("not_applicable"),
    error: s("fail_mode"),
    degraded: s("not_applicable"),
    hookOverridable: true,
    notes: "Guarded at the pre-call span in both languages. Resolves by failMode; a lost score costs this call's accumulated-probing signal only.",
  },
  {
    id: "policy_floor",
    module: "sdk-typescript/src/policy/rules.ts",
    timeout: s("not_applicable"),
    error: s("closed"),
    degraded: s("not_applicable"),
    hookOverridable: false,
    notes: "Floor class: resolves CLOSED regardless of failMode. The non-overridable baseline that cannot run must not wave a call through ungoverned, exactly as a floor redact it cannot guarantee already fails closed to a block. The response phase never withholds the caller's value, so there it falls closed only on the stored copy.",
  },
  {
    id: "policy_rules",
    module: "sdk-typescript/src/policy/rules.ts",
    timeout: s("not_applicable"),
    error: s("fail_mode"),
    degraded: s("not_applicable"),
    hookOverridable: true,
    notes: "Guarded at every span that evaluates rules. Resolves by failMode. Two units of this layer are structurally always OPEN and cannot block whatever failMode says: shadow evaluation, which is defined as never decision-affecting, and the policy-version hash, which is provenance rather than a control.",
  },
  {
    id: "customer_hook",
    module: "sdk-typescript/src/proxy/wrapper.ts",
    timeout: s("fail_mode"),
    error: s("fail_mode"),
    degraded: s("not_applicable"),
    hookOverridable: false,
    notes:
      "The request-phase hook, and the one layer whose disposition the operator chooses: open by default, closed on opt-in. A timeout or error is recorded as its own hook disposition and can never un-block builtin enforcement - only an explicit allow verdict does that. The response-phase hook is a separate row: its failure states resolve differently.",
  },
  {
    id: "customer_hook_post_call",
    module: "sdk-typescript/src/integrations/core.ts",
    timeout: s("open"),
    error: s("open"),
    degraded: s("not_applicable"),
    hookOverridable: false,
    notes:
      "The response-phase hook. The provider has already answered when it runs, so a hook that times out or throws leaves standing whatever decision the response layers already rendered; only this hook's own verdict is lost for the call, which is 'open' in both states. fail_mode is not consulted on this path - the request-phase row is the one whose disposition the operator chooses.",
  },
  {
    id: "external_backend",
    module: "sdk-typescript/src/policy/external-backend.ts",
    timeout: s("closed", "shadow_exempt"),
    error: s("closed", "shadow_exempt"),
    degraded: s("not_applicable"),
    hookOverridable: false,
    notes:
      "An external decision point that cannot answer is a deny, because the operator asked for its verdict on every call. Observe-only (shadow) backends are exempt: they were never load-bearing.",
  },
  {
    id: "mcp_tool_policy",
    module: "sdk-typescript/src/integrations/mcp.ts",
    timeout: s("not_applicable"),
    error: s("fail_mode"),
    degraded: s("closed"),
    hookOverridable: false,
    notes:
      "The tool-call path guards its own policy evaluation and resolves failure by the configured fail mode - the posture the provider pipeline states but does not yet implement. Degraded enforcement blocks tool calls like any other governed call.",
  },
  {
    id: "tool_pinning",
    module: "sdk-typescript/src/policy/tool-pinning.ts",
    timeout: s("not_applicable"),
    error: s("closed", "warn_mode_flags"),
    degraded: s("not_applicable"),
    hookOverridable: false,
    notes:
      "A descriptor that cannot be hashed is treated as a mismatch, never as a pass. Enforcement follows the configured pinning mode (block blocks, warn flags); neither is silent. Contained per tool so one unhashable entry cannot abort discovery.",
  },
  {
    id: "protocol_facets",
    module: "sdk-typescript/src/policy/protocol-facets.ts",
    timeout: s("not_applicable"),
    error: s("fail_mode"),
    degraded: s("not_applicable"),
    hookOverridable: true,
    notes:
      "Lexical decomposition of a protocol statement into facets a rule can address. Runs inside the policy_rules span, so an exception resolves the way that layer does. Its own decision on input it CANNOT decompose is separate from an exception and is closed: unparseable text matches the rule, so a facet rule refuses rather than permitting what it could not read. That distinction is why this has its own row.",
  },
  {
    id: "destructive_capability_hints",
    module: "sdk-typescript/src/policy/capability-hints.ts",
    timeout: s("not_applicable"),
    error: s("closed"),
    degraded: s("not_applicable"),
    hookOverridable: false,
    notes:
      "Reads a tool descriptor's own destructiveHint at discovery and adds the tool to the destructive-capability set. A descriptor the SDK cannot read resolves to destructive, never to safe: an unreadable field is the same escape as a lying one, so 'closed' here means the capability is restricted rather than the call refused. Restriction only bites a session that is already tainted, and the hint can only ever ADD - an operator's own list entry is never removed by anything a server says.",
  },
  {
    id: "tool_result_scan",
    module: "sdk-typescript/src/policy/response-scan.ts",
    timeout: s("not_applicable"),
    error: s("fail_mode"),
    degraded: s("not_applicable"),
    hookOverridable: false,
    notes: "Guarded at its own call site, scan and sanitizer alike. Resolves by failMode with the default open even though it sees canary tokens, because the tool has ALREADY RUN: blocking cannot undo the side effect, it only withholds the result from the model.",
  },
  {
    id: "loop_detection",
    module: "sdk-typescript/src/policy/industry/devops.ts",
    timeout: s("not_applicable"),
    error: s("open"),
    degraded: s("not_applicable"),
    hookOverridable: false,
    notes: "Sliding-window iteration counter, driven once per agent step by the framework integration. The integration's callback swallows every non-policy throw so a detector defect cannot break the host's agent run, which makes an internal error fail OPEN: the step proceeds and this layer's enforcement is lost for it. Off unless agentPolicy.loopDetection / agent_policy['loop_detection'] is configured, so the disposition only describes a run that opted in.",
  },
  {
    id: "delegation_tracking",
    module: "sdk-typescript/src/policy/industry/agentic.ts",
    timeout: s("not_applicable"),
    error: s("open"),
    degraded: s("not_applicable"),
    hookOverridable: false,
    notes: "Depth / circularity / allowlist checks over an in-process delegation chain, driven once per delegation. Same guard and therefore the same open posture as loop_detection. No framework integration drives it in either SDK today; it is a public API a caller wires into its own handoff path, which is why its verdict semantics are fixture-pinned rather than integration-pinned.",
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
