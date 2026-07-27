# Obsvr Evaluation Semantics Specification

Spec version: 1.0 (2026-07-07)
Status: normative. Both SDKs (TypeScript, Python) MUST implement these
semantics identically. Every normative statement carries an ID (EV-n)
and is pinned by conformance fixtures in `conformance/fixtures/`
executed by both SDK test suites. A behavioral change to any EV
statement requires a spec version bump and a fixture update in the
same commit.

This file is the canonical copy. It lives beside the fixtures that pin it
because a contract of record that lives away from its evidence drifts from it:
any other copy is a mirror, and where a mirror disagrees with this file, this
file is right.

## 1. Phases

- EV-1: Governance runs in two phases relative to the provider call:
  `pre_call` (before the request leaves the process) and `post_call`
  (after the full response is available; for streams, at stream end).
- EV-2: Every governed call emits exactly one audit event, stamped
  with the outcome of both phases.

## 2. Pre-call evaluation order

Steps run in this exact order. Numbering matches the code sections in
`sdk/src/proxy/wrapper.ts` and `sdk-python/obsvr/policy.py`.

- EV-3 (Step 0, enforcement-integrity gate): if policy enforcement is
  degraded (stale policy beyond the staleness budget with fail_closed,
  project paused / kill switch, remote disabled after auth failure),
  the call is decided by the gate BEFORE any content scanning. Gate
  blocks are not overridable by any later step, including the
  customer hook.
- EV-4 (Step 1, built-in PII/content scan): the builtin regex scanner
  runs, merged with Presidio results when configured
  (action_source "builtin+presidio"). Presidio failure falls back to
  builtin-only; failure never blocks the call by itself.
- EV-5 (Step 1.2, multi-turn injection): when enabled and the call is
  not already blocked, the per-session decayed score is updated and
  may block or flag (rule_id "sdk:multi_turn_injection"). A single
  weak signal on a session's first turn never trips the gate.
- EV-6 (Step 1.5, structured policy rules): when the call is not
  already blocked, rules are evaluated with FIRST-MATCH semantics in
  stored order (see section 3). The fired rule's id and reason are
  recorded.
- EV-7 (Step 2, customer hook): the hook runs according to
  hook-trigger configuration and MAY escalate (allow -> block/redact)
  or explicitly override a builtin content decision. It MUST NOT
  override an enforcement-integrity gate block (EV-3). Hook timeout
  or error leaves the pre-hook decision unchanged.

## 3. Rule evaluation semantics

- EV-8: Rules are evaluated in stored order; the first matching rule
  decides (first-match). There is no cross-rule severity merging;
  ordering IS the priority mechanism.
- EV-9: A rule whose `applies_to` excludes the current target
  (prompt/response) is skipped. A disabled rule is skipped.
- EV-10: Action semantics on match: `block` denies the call;
  `redact` allows the call with redacted content; `flag` allows and
  records the rule. `topic_allow` match allows immediately.
- EV-11 (require_approval): a matching block rule with
  `require_approval: true` passes only when an unexpired grant covers
  (rule_id, optional user_id) AND, when both carry a rule hash, the
  grant's rule_hash equals the CURRENT rule's canonical hash. A grant
  minted under an edited rule definition is void. Grants without a
  hash (legacy) are honored. Without a valid grant the rule blocks,
  the result carries approval_required plus the rule_hash, and the
  SDK files an approval request.
- EV-12 (malformed rules): a rule that fails validation (unknown
  type, missing id, malformed conditions, pathological regex) is
  SKIPPED, never partially applied; the decision is computed as if
  the rule did not exist (Cedar-style skip semantics), and the SDK
  emits a rejected-rule signal naming the rule id and reason.
- EV-13: rule conditions are pure data. No condition may perform IO,
  consult the clock (other than the engine-supplied time_window
  check), or execute user-supplied code. Regex conditions are
  compiled through the safe-regex guard in both SDKs.

## 4. Decision composition

- EV-14: Outcome precedence within a phase, most restrictive wins
  when steps disagree: block > redact > flag > allow. A later step
  never weakens an earlier block except the explicit customer-hook
  override in EV-7 (which cannot weaken EV-3 gates).
- EV-15: The audit event records the DETERMINING step: rule_id (or
  sdk: pseudo-rule id), action_taken, action_reason, action_source.

## 5. Policy state pinning

- EV-16: Every audit event's policy_version field carries the
  canonical rules hash: the 16-hex-char SHA-256 prefix over the
  enabled rules' canonical projections sorted by id, "none" when no
  rules are enabled. The canonical projection contains exactly
  {action, applies_to?, conditions, enabled, id, name, type} with
  recursively sorted keys and compact separators. Both SDKs MUST
  produce byte-identical hashes (fixture: rules_hash.json).
- EV-17: The per-rule hash (same canonicalization over one rule) pins
  approvals (EV-11) and is included on approval requests.

## 6. Post-call evaluation order

- EV-18: post_call runs (1) structured rules against the response
  text, then (2) the onPostCall hook with timeout. Post-call rules
  cannot un-send the request; their actions apply to the stored
  record and the returned/streamed content per action semantics.
- EV-19 (streams): stream chunks pass through unmodified; the
  accumulated text is evaluated at stream end and exactly one event
  is emitted (EV-2). (Mid-stream interval checking is reserved for a
  future spec version; when added it will be opt-in and specified
  here first.)

## 7. Shadow rules

- EV-20: a rule with `mode: "shadow"` NEVER affects the decision,
  the returned content, quota consumption, or approval requests. The
  active decision MUST be byte-identical with shadow rules present
  or absent (pinned by fixture).
- EV-21: shadow evaluation runs after the active decision using the
  same semantics (EV-8..EV-14) over the shadow rules alone; its
  outcome is recorded on the event's compliance block as
  shadow_outcome { rule_id, would: block|redact|flag, reason } for
  the first-matching shadow rule, absent when none matched.

## 8. Check-only (explain) mode

- EV-22: explain() runs the pre-call evaluation in check-only mode:
  identical decision logic for built-in scanning and structured rules,
  but it consumes no quota, updates no injection-session state, files
  no approval requests, and emits no audit events. Customer hooks are
  NOT invoked (they may have side effects), and multi-turn session
  scoring is not advanced; both exclusions are reported in the result
  so callers know explain() is advisory for those steps. The result
  reports the decision plus determining rule, the current rules_hash,
  and any shadow outcome.

## 9. Failure posture summary

- EV-23: scanner infrastructure failure (Presidio down) degrades to
  builtin scanning, recorded via action_source; policy STALENESS
  beyond budget is an EV-3 gate matter governed by fail mode
  configuration; audit DELIVERY failure never affects decisions.

## Fixture map

Every row names cases that exist. A statement with no case is listed as
uncovered rather than left to look covered - an over-claimed coverage table is
worse than an honest gap, because it stops anyone from closing the gap.

| EV | Pinned by | Cases |
|----|-----------|-------|
| EV-3 | eval_semantics.json, fail_mode.json | `ev3_gate_paused` (gate decides before content scanning and is not hook-overridable) |
| EV-6, EV-8 | eval_semantics.json | `ev6_first_match_block`, `ev8_stored_order_decides` |
| EV-9 | eval_semantics.json | `ev9_disabled_skipped`, `ev9_applies_to_skipped` |
| EV-10 | eval_semantics.json | `ev10_redact`, `ev10_flag_allows_with_rule`, `ev10_topic_allow_short_circuits` |
| EV-11 | eval_semantics.json | `ev11_approval_required_block_shape` |
| EV-12 | eval_semantics.json | `ev12_malformed_rule_skipped` |
| EV-13 | eval_semantics.json | `ev13_pathological_regex_never_matches` |
| EV-14 | eval_semantics.json | `ev14_composition` (most restrictive wins; a later step never weakens an earlier block) |
| EV-20, EV-21 | eval_semantics.json | `ev20_shadow_inert_active_allow`, `ev20_shadow_beside_active_block` |
| EV-16, EV-17 | rules_hash.json | canonical projection and hash vectors |
| EV-22 | eval_semantics.json | `ev22_explain_pure` (check-only evaluation consumes no quota) |
| EV-7 (hook failure), EV-23 (failure posture) | fail_mode.json | per-layer failure dispositions for timeout, error, and degraded states |

Namespace cases (`ns_*`) in eval_semantics.json pin cross-tenant and
namespace-asymmetry behavior, which the EV statements above do not yet
describe; treat the fixture as normative there until a spec version adds them.

Cases run in one of three modes: `rules` (the default, driving the rules
engine), `pipeline` (driving the full pre-call pipeline, which is the only way
to pin statements about step composition and the integrity gate), and `explain`
(check-only evaluation).

Not yet covered by a dedicated case: EV-1, EV-2, EV-4, EV-5, EV-15, EV-18,
EV-19. Their behavior is exercised indirectly by the SDK suites but is not
pinned cross-language, so a divergence there would not fail CI. This list is
recorded as DATA in `eval_semantics.json` (`ev_coverage.uncovered`), and both
suites check the whole coverage map against the actual cases: covered and
uncovered must partition EV-1..EV-23 exactly, and a case pinning a statement
(or a statement losing its case) without a matching map edit fails CI in both
languages. Closing one of these gaps means adding the case AND moving the
statement out of `uncovered` in the same change.

Divergences discovered between SDKs are release blockers unless
recorded in conformance/known-divergences.json with a tracking entry.
