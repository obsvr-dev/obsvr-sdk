# Known Cross-SDK Divergences

Behavioral differences between the TypeScript and Python SDKs that are
currently accepted, each with an owner and a tracking note. A fixture
failing on ONE SDK requires either a fix in the same change or a row
here; silent divergence is never acceptable
(conformance discipline).

| ID | Area | Divergence | Reason accepted | Tracking |
|----|------|------------|-----------------|----------|
| KD-3 | MCP tool pinning (mode "block" discovery strip) | TS always returns a NEW result object with the offending tools filtered out; Python mutates `result.tools = kept` inside a try/except, so if the upstream `ListToolsResult` model forbids assignment (frozen / `validate_assignment`) the swapped tool remains in the listing the model sees. | The call-time gate still REFUSES execution of the tool on both SDKs (identity defense holds); only the discovery-time strip is best-effort in Python, and rebuilding an arbitrary upstream model object risks breaking the caller's type contract. | `sdk-python/obsvr/integrations/mcp.py` (`governed_list_tools`). Revisit if a real MCP result type is found frozen. |
| KD-4 | `floor_version` numeric canonicalization | `deriveFloorVersion` / `derive_floor_version` reuse the rules-hash canonicalizer (`stableStringify` / `_canonical_json`), which agrees across SDKs for strings, unicode, and ordinary integers / simple decimals (verified) but can diverge on exotic numbers (integers beyond the JS safe range, scientific-notation floats) — `JSON.stringify` vs `json.dumps`. | Identical to the SHIPPING `policy_version` / frozen `rules_hash` canonicalization, which this deliberately reuses; floor rule conditions are operator-authored (not attacker-controlled arbitrary JSON like MCP tool descriptors, which DID get a dedicated number-safe canonicalizer). A floor whose `floor_version` differs across SDKs would still enforce identically; only the audit-seal hash string would differ for such exotic values. | `rules.ts` `deriveFloorVersion` / `rules.py` `derive_floor_version`. Adversarially reviewed 2026-07-20 (isReal=false — not a floor defect). |
| KD-5 | Customer `policyRules` eval context on the TS integration path | On the TS integration path (`integrations/core.ts` `applyPreCallPolicy`) a **customer** `policyRules` rule receives `{provider, metadata}` — no top-level `model` / `currentEnvironment` — so a customer `model_gate` / `environment_gate` rule is inert there, while the Python shared pre-call and the TS proxy wrapper source both. (The anti-tamper **floor** is NOT affected: as of 2026-07-20 the floor threads `model` + `currentEnvironment` on all three paths.) | Enriching the customer-rules context on integrations would newly fire previously-inert `model_gate` / `environment_gate` customer rules — a behavior change for existing users, out of scope for the additive floor slice. The floor (the security baseline) is consistent; a customer who needs model/env gating on integrations can promote the rule into `policyFloor`. | `integrations/core.ts` `applyPreCallPolicy` rules context. Revisit as its own slice with a migration note. |

History:
- 2026-07-11 (wave 2): the two remaining divergences were FIXED. KD-1 (scan
  scope): Python now scans the last user turn for the PII/rules DECISION via a
  new `scan_text` parameter (`policy.py`) fed by `_last_user_message_text`
  (`wrap.py`), matching TS `extractLastUserMessageText`; the full prompt is
  still stored/redacted and is still what multi-turn injection accumulates over
  (tests in `test_policy.py`). KD-2 (token quotas): Python now meters
  `quota_unit: "tokens"` via a token-budget path with post-call
  `record_token_usage`, matching TS (`rules.py`, `quota.py`, `wrap.py`).
- 2026-07-11 (wave 1): several previously-silent divergences were FIXED (not
  accepted) during the production-review remediation: Python customer hook
  could override the enforcement-integrity gate / kill switch (now guarded,
  `policy.py`); Python `model_gate` rules never fired (now implemented,
  `rules.py`); Python quota `scope` fell back to `user_id` for any scope (now
  user_id-only, matching TS); Python sampled out blocked/error audit events
  (now never sampled, EV-2, `wrap.py`); the TS infra-integration path
  (`integrations/core.ts`) skipped the kill-switch gate entirely (now gated,
  mirroring the wrapper).
- 2026-07-07: table established empty after the parity build. Two
  divergences were FIXED (not accepted) while wiring the conformance
  suite: Python labeled structured-rule outcomes action_source
  "builtin" (TS: "policy_rules"), and ingest's wire enum rejected
  "policy_rules"/"builtin+presidio" events entirely. See
  ingest/tests/unit/event-schema-contract.test.ts.
