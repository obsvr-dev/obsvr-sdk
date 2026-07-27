# Known Cross-SDK Divergences

Behavioral differences between the TypeScript and Python SDKs that are
currently accepted, each with an owner and a tracking note. A fixture
failing on ONE SDK requires either a fix in the same change or a catalog
entry; silent divergence is never acceptable (conformance discipline).

**The live entries moved to `known-divergences.json`** — a machine-readable
catalog whose structure (exact key set, `status` restricted to `intended`,
`sdk`/`category` vocabularies) is validated by BOTH test suites
(`sdk/tests/unit/fixture-bookkeeping.test.ts`,
`sdk-python/tests/test_fixture_bookkeeping.py`), so a malformed or
vocabulary-expanding entry fails CI in either language. Prose could only
describe the discipline; the catalog lets CI hold it. This file keeps what a
catalog cannot: the History below — the narrative of divergences that were
FIXED rather than accepted, which the table never carried and which is the
better half of the record.

History:
- 2026-07-28: KD-7 (CSS-hidden / aria-hidden stripping) was FIXED by porting
  the pass, and the row is gone. The row had always described itself as
  temporary: `stripHiddenHtml` landed in TypeScript with the Python twin
  scheduled, and the three `hidden_html_*` cases in
  `conformance/fixtures/deobfuscation.json` carried `sdk_support py:skip` so
  the gap failed loudly rather than quietly. `strip_hidden_html` in
  `sdk-python/obsvr/deobfuscate.py` is a line-for-line port sitting at the same
  pipeline position (after HTML-comment stripping, before whitespace collapse),
  and those three cases now run required in both suites. One parity detail the
  port had to decide rather than copy: TypeScript tests a self-closing tag with
  `String.prototype.trimEnd`, whose whitespace set is not Python's — Python also
  strips `\x1c`-`\x1f` and NEL, and does not strip U+FEFF — so the Python side
  spells the ECMAScript set out (`_JS_TRIM_WS`) instead of calling bare
  `rstrip()`. The documented limits are shared too: first-matching-closer (so
  same-name nesting leaves a tail, failing toward keeping content), an
  unterminated hidden element drops the remainder, and only the `style`
  attribute carries the CSS forms.
- 2026-07-27: KD-4 (numeric canonicalization) was FIXED, not re-argued, and
  the row is gone. It had been an accepted risk pinned by hand-written
  vectors, scoped to "exotic numbers" — integers past the JS safe range and
  scientific-notation floats. A differential property test
  (`scripts/check-canonical-json-parity.mjs`: fast-check generating on the TS
  side, hypothesis on the Python side, both canonicalizing the same JSON TEXT)
  showed the real scope was far wider — about a third of randomly generated
  documents diverged — and named classes the row did not: every whole-valued
  float (`1.0`), negative zero, both exponent thresholds and exponent
  zero-padding, unpaired surrogates (where Python produced a string with no
  UTF-8 encoding, so hashing raised rather than returning a hash), and the
  sort order of astral object keys (JS compares UTF-16 code units, Python
  compares code points). `_canonical_json` is now a faithful port of
  `stableStringify` rather than a `json.dumps` call, and all of those are
  closed; 22,000 generated documents across four seeds now agree byte for
  byte. Every pinned vector in `rules_hash.json` is unmoved, which is the
  evidence that the change only touched inputs the two SDKs already hashed
  differently. The one case with no format-only fix — an integer past 2^53,
  which JS rounds while PARSING, before any serializer runs — is closed by
  Python taking the same rounding; that accepts a collision above 2^53 which
  the TS SDK had regardless, in exchange for one policy no longer stamping two
  policy_versions across a mixed fleet. The attacker-facing hashers
  (`tool-pinning`, `tool-content-hash`) deliberately do NOT normalize and
  still refuse those values. Pinned by `conformance/fixtures/canonical_json.json`.
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
