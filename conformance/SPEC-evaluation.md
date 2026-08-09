# Obsvr Evaluation Semantics Specification

Spec version: 1.2 (2026-08-09)
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

Scope: these rules govern the shared single-call evaluation pipeline when a
surface invokes it. They do not turn an observe-only framework callback into a
pre-call enforcement point, require an unsupported integration to intercept a
call, or override an explicitly documented provider-adapter response contract.

## 1. Phases

- EV-1: Governance runs in two phases relative to the provider call:
  `pre_call` (before the request leaves the process) and `post_call`
  (after the full response is available; for streams, at stream end).
- EV-2: Every governed call selected by sampling emits exactly one audit event,
  stamped with the outcome of both phases. Any non-clean outcome (including a
  block, redaction, error, monitor-converted block, or detector failure) emits
  regardless of sampling; only clean allowed calls may be sampled out.

## 2. Pre-call evaluation order

Steps run in this exact order. Numbering matches the code sections in
`sdk-typescript/src/proxy/wrapper.ts` and `sdk-python/obsvr/policy.py`.

- EV-3 (Step 0, enforcement-integrity gate): if policy enforcement is
  degraded (stale policy beyond the staleness budget with fail_closed,
  project paused / kill switch, remote disabled after auth failure),
  the call is decided by the gate BEFORE any content scanning. Gate
  blocks are not overridable by any later step, including the
  customer hook.
- EV-4 (Step 1, built-in PII/content scan): when content scanning is enabled by
  a PII policy or the session-taint injection latch, the built-in regex scanner
  runs. When a configured PII policy also names a Presidio analyzer and it
  answers, its NLP findings
  are merged with the built-in findings. Analyzer timeout, transport error, or
  an unusable response contributes no NLP findings; the built-in result still
  decides, and this detection-stage degradation does not block by itself.
  Applying a resolved redaction is a separate enforcement-application step:
  once an NLP-only type has been detected and resolves to `redact`, failure to
  obtain or apply an anonymized outbound value blocks regardless of fail mode.
  The SDK MUST NOT fall back to the regex redactor for a type that the regex
  tier cannot locate.
- EV-5 (Step 1.2, multi-turn injection): when enabled and the call is
  not already blocked, the per-session decayed score is updated and
  may block or flag (rule_id "sdk:multi_turn_injection"). A single
  weak signal on a session's first turn never trips the gate.
- EV-6 (Step 1.5, structured policy rules): when the call is not already
  blocked, rules are evaluated under the configured resolution semantics in
  EV-8. The determining rule's id and reason are recorded.
- EV-7 (Step 2, customer hook): the hook runs according to
  hook-trigger configuration and MAY escalate (allow -> block/redact),
  but MUST NOT weaken a decision made by any earlier enforcement layer.
  In particular, an explicit hook allow cannot erase a builtin, floor,
  structured-rule, canary, or enforcement-integrity block. Hook timeout
  or error follows the configured fail mode: open keeps the pre-hook
  decision, while closed blocks.

## 3. Rule evaluation semantics

- EV-8: An absent resolution declaration behaves as `first_match`. A declared
  `first_match` also evaluates in stored order and stops at the first rule that
  renders an outcome; ordering is the priority mechanism. A declared
  `deny_wins` evaluates every enforcing rule and selects the strongest rendered
  outcome: block > redact > flag > permit. A matched `topic_allow` and a block
  rule satisfied by an approval are permits. Equal-strength outcomes are
  resolved by the smallest rule id in UTF-16 code-unit order, so verdict and
  determining `rule_id` are independent of list order. Because `deny_wins`
  evaluates the complete set, every quota rule meters every evaluated call,
  including a call whose final outcome is block. Unknown resolution values are
  rejected at configuration boundaries.
- EV-9: A rule whose `applies_to` excludes the current target
  (prompt/response) is skipped. A disabled rule is skipped.
- EV-10: Action semantics on match: `block` denies the call;
  `redact` allows the call with redacted content; `flag` allows and
  records the rule. `topic_allow` match allows immediately.
- EV-11 (require_approval): a matching block rule with
  `require_approval: true` constructs an `action_hash` over the canonical
  `obsvr-action/1` document: current `rule_id` and `rule_hash`, plus any present
  action name, amount, caller namespace, target namespace, and subject
  (`user_id`). Free-text prompt content is not part of this document. An
  unexpired grant covers the call only when `rule_id` matches and every binding
  carried by both grant and claim matches: `user_id`, `rule_hash`, and
  `action_hash` narrow independently. If either side omits one of those optional
  bindings, that comparison does not apply, preserving legacy unbound grants.
  An action that cannot be hashed omits `action_hash` and therefore cannot be
  narrowed by it. Without a covering grant the rule blocks, the result carries
  `approval_required`, `rule_hash`, and the computed `action_hash`, and the SDK
  files an approval request carrying the same bindings.
- EV-12 (malformed rules): validation applies at the boundary that receives a
  rule. `init()` or another local configuration boundary rejects the complete
  configuration if any declared rule is malformed. A remote policy poll drops
  malformed entries individually, applies the valid subset, logs the rejected
  rule ids and reasons, and attempts one signed `sdk:rule_rejected` policy flag
  per distinct rejected set; signal delivery is best-effort. If a malformed
  rule bypasses both boundaries and reaches the evaluator, it resolves closed
  as an unreadable control regardless of fail mode; it is never partially
  applied or silently treated as a non-match.
- EV-13: rule conditions are pure data. No condition may perform IO,
  consult the clock (other than the engine-supplied time_window
  check), or execute user-supplied code. Regex conditions are
  compiled through the safe-regex guard in both SDKs.

## 4. Decision composition

- EV-14: Outcome precedence within a phase, most restrictive wins
  when steps disagree: block > redact > flag > allow. A later step
  never weakens an earlier decision.
- EV-15: The audit event records the DETERMINING step: rule_id (or
  sdk: pseudo-rule id), action_taken, action_reason, action_source.

## 5. Policy state pinning

- EV-16: Every audit event's `policy_version` carries the 16-hex-character
  SHA-256 prefix over the enabled rules' canonical hash document, `none` when
  none are enabled, and `unknown` only when provenance derivation itself fails.
  Each rule projection contains exactly `{action, conditions, enabled, id,
  name, type}`, plus `applies_to` when present and `mode: "shadow"` only for a
  shadow rule; keys are recursively sorted and JSON is compact. With no
  resolution declaration, the historical document is the projections sorted
  by rule id in UTF-16 code-unit order and contains no resolution field. A
  declared mode hashes `{resolution, rules}`: `first_match` preserves evaluation
  order, while `deny_wins` sorts rules by id because reordering cannot change
  its verdict. Thus changes to declared semantics or to decision-relevant order
  change the version, while a pure `deny_wins` reorder does not. Both SDKs MUST
  produce byte-identical hashes (fixture: `rules_hash.json`).
- EV-17: The per-rule hash (same canonicalization over one rule) pins
  approvals (EV-11) and is included on approval requests.

## 6. Post-call evaluation order

- EV-18: post_call runs (1) structured rules against the response
  text, then (2) the onPostCall hook with timeout. Post-call rules
  cannot un-send the request; their actions apply to the stored audit
  record. The base wrapper contract does not modify the response value
  returned to the caller. A provider-specific adapter may explicitly
  document and test caller-visible non-streaming redaction, but that is
  outside this cross-SDK base contract.
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
- EV-21: shadow evaluation runs after the active decision over the shadow rules
  alone. It always uses first-match stored order, regardless of the active
  ruleset's declared resolution, and remains check-only; it cannot consume
  quota or affect the active decision. Its outcome is recorded on the event's compliance block as
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

- EV-23: Presidio analyzer failure is detection-stage degradation: it yields no
  NLP findings, leaves built-in scanning in force, and does not block by itself.
  Failure after policy has resolved an outbound redaction is
  enforcement-application failure and blocks regardless of fail mode; this
  includes an anonymizer or rewrite failure for an NLP-only type. Policy
  staleness beyond budget is an EV-3 gate matter governed by fail-mode
  configuration. Audit delivery failure never affects governance decisions.

## Fixture map

Every row names cases that exist. A statement with no case is listed as
uncovered rather than left to look covered; an over-claimed coverage table can
conceal an unpinned gap and stop it from being closed.

| EV | Pinned by | Cases |
|----|-----------|-------|
| EV-3 | eval_semantics.json, fail_mode.json | `ev3_gate_paused` (gate decides before content scanning and is not hook-overridable) |
| EV-4, EV-23 | fail_mode.json | `builtin_pii_scan`, `presidio_merge` (detection degradation vs. enforcement-application closure) |
| EV-6, EV-8 | eval_semantics.json | `ev6_first_match_block`, `ev8_stored_order_decides`, `ev8_declared_deny_wins` |
| EV-9 | eval_semantics.json | `ev9_disabled_skipped`, `ev9_applies_to_skipped` |
| EV-10 | eval_semantics.json | `ev10_redact`, `ev10_flag_allows_with_rule`, `ev10_topic_allow_short_circuits` |
| EV-11 | eval_semantics.json, approvals.json | `ev11_approval_required_block_shape`; canonical action and grant-match vectors |
| EV-12 | eval_semantics.json | `ev12_remote_malformed_rules_rejected`, `ev12_init_malformed_rule_refused` |
| EV-13 | eval_semantics.json | `ev13_pathological_regex_never_matches` |
| EV-7, EV-14 | eval_semantics.json | `ev14_composition` (most restrictive wins; an explicit hook allow cannot weaken an earlier builtin block) |
| EV-20, EV-21 | eval_semantics.json | `ev20_shadow_inert_active_allow`, `ev20_shadow_beside_active_block` |
| EV-16, EV-17 | rules_hash.json | canonical projection and hash vectors |
| EV-22 | eval_semantics.json | `ev22_explain_pure` (check-only evaluation consumes no quota) |
| EV-7 (hook failure) | fail_mode.json | per-layer failure dispositions for timeout, error, and degraded states |

Namespace cases (`ns_*`) in eval_semantics.json pin cross-tenant and
namespace-asymmetry behavior, which the EV statements above do not yet
describe; treat the fixture as normative there until a spec version adds them.

Cases run in one of four modes: `rules` (the default, driving the rules
engine), `pipeline` (driving the full pre-call pipeline, which is the only way
to pin statements about step composition and the integrity gate), and `explain`
(check-only evaluation). `config` drives local configuration validation without
filtering the fixture's raw rule list first.

Not yet covered by a dedicated case: EV-1, EV-2, EV-5, EV-15, EV-18,
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
