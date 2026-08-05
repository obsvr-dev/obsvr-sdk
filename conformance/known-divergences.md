# Known Cross-SDK Divergences

Behavioral differences between the TypeScript and Python SDKs that are
currently accepted, each with an owner and a tracking note. A fixture
failing on ONE SDK requires either a fix in the same change or a catalog
entry; silent divergence is never acceptable (conformance discipline).

**The live entries moved to `known-divergences.json`** — a machine-readable
catalog whose structure (exact key set, `status` restricted to `intended`,
`sdk`/`category` vocabularies) is validated by BOTH test suites
(`sdk-typescript/tests/unit/fixture-bookkeeping.test.ts`,
`sdk-python/tests/test_fixture_bookkeeping.py`), so a malformed or
vocabulary-expanding entry fails CI in either language. Prose could only
describe the discipline; the catalog lets CI hold it. This file keeps what a
catalog cannot: the History below — the narrative of divergences that were
FIXED rather than accepted, which the table never carried and which is the
better half of the record.

**Ids are allocated once and never reused.** A `KD-` number that appears in the
History below is spent: the divergence it named was fixed, and that record is
what the History is for. The next live entry takes the next free number, which
is why the catalog currently holds KD-6, KD-9, KD-10 and KD-11 with gaps
between them.

**A row is added only after the divergence is re-measured, never transcribed
from prose.** KD-10 was proposed alongside a second capability gap described in
the same terms. Driving both against one server showed the second was **already
closed** — the other SDK's provider attribution had been made endpoint-derived
and the prose describing it had not caught up — so filing both would have
catalogued a divergence that no longer existed. Only the one that still
reproduces is here.

History:
- 2026-08-06: a customer `regex` rule now means one thing on both SDKs. The
  SYNTAX half of the dialect split had already been closed by rejection in both
  validators; the SEMANTIC half — `\d` `\w` `\s` `\b` `$` `.`, which read
  differently in `re` and `RegExp` and carry no syntactic marker — was open and
  enumerated, because rejecting them would have meant rejecting the most common
  constructs in the language. It was an enforcement-verdict difference and
  therefore never eligible for the catalog above: measured, a rule
  `^\d{3}-\d{2}-\d{4}$` matched Arabic-Indic digits in Python and not in
  TypeScript, so the same rule blocked a call on one SDK and allowed it on the
  other. It was carried in `SECURITY.md` as an open defect while it existed.
  **ECMAScript's meaning wins, and the Python side is rewritten to it** at that
  SDK's one compile call. The direction is forced rather than preferred: Python
  can express ECMAScript's semantics exactly (`re.ASCII` plus a mechanical
  pattern rewrite) while the reverse is not true — a Unicode-aware `\b` has no
  JavaScript spelling short of lookaround built from `\p{...}` escapes, which
  need the `u` flag, and `u` mode changes which SYNTAX the engine accepts. The
  TypeScript engine is untouched, so nothing already measured there moves.
  Two measurements shaped the fix and are worth keeping. `re.ASCII` alone closes
  `\d` `\w` `\b` EXACTLY and makes `\s` WORSE — 6 disagreeing codepoints across
  the BMP become 19, because the ECMAScript whitespace set is neither of
  Python's — so `\s` is rewritten to an explicit class rather than left to the
  flag. And the enumeration in `SECURITY.md` named U+000D and U+2028 for the `.`
  row: U+2029 PARAGRAPH SEPARATOR diverged just as far and was missing.
  **Two residuals, both named rather than folded in.** `\S` inside a character
  class is REFUSED in both languages instead of aligned, because a negated
  shorthand is not expressible inside a positive class without class
  subtraction, which Python `re` lacks; `[\s\S]` is exempt and provably so, so
  the dotall idiom stays legal. And the code-unit / code-point model — JS
  `RegExp` without `u` matches UTF-16 code units, Python `re` matches code
  points — is a SEVENTH family that no escape rewrite reaches; closing it means
  `u` mode, which changes syntax acceptance in the other direction. Neither is a
  catalog entry: the first is not a divergence (both SDKs refuse the same
  patterns) and the second is an open defect stated in the open.
  Pinned by `conformance/fixtures/regex_dialect.json` (`semantic_cases`) and by
  `scripts/check-regex-dialect-parity.mjs`, which drives 3,000 pattern/input
  pairs through both real matchers. Without the fix that script reports 43
  divergences across all six families.
- 2026-08-06: the Python sender installs `SIGTERM`/`SIGINT` handlers, closing the
  shutdown divergence. It flushed only from `atexit`, which a default-disposition
  `SIGTERM` does not reach, so every container stop dropped whatever the bounded
  queue still held — on an evidence product, a hole in the chain on every rolling
  deploy, in the SDK half regulated buyers are most likely to run. TypeScript was
  the reference and its ownership rules were ported rather than reinvented: chain
  to any prior handler, flush within the SDK's existing shutdown budget, and
  restore the default disposition only when the prior handler was `SIG_DFL`.
  This was a coverage difference rather than an enforcement-verdict one — a lost
  event, never a wrong one — and it was recorded in both READMEs while it existed
  rather than held silently.
  **The residual is ordering, and it is the platform, not a decision.** Node
  keeps a listener LIST, so TypeScript can ask at signal time whether the host's
  handler arrived after `wrap()`. A POSIX disposition is a single SLOT: a host
  installing its handler after `obsvr.init()` replaces obsvr's, and obsvr's flush
  never runs. Python therefore decides ownership at install time. Two smaller
  consequences of the same slot model: `SIG_IGN` is left alone entirely rather
  than taken over, and a disposition installed from outside Python cannot be
  called, so obsvr keeps the exit there — a swallowed signal hangs a process
  forever where a truncated one merely ends it early. Not a catalog entry: the
  contract ("obsvr flushes at shutdown and does not seize termination from the
  host") holds on both sides, and what differs is which instant the question is
  asked. Both are documented in the READMEs and driven by
  `sdk-python/tests/test_signal_handler_ownership.py`, whose SIG_DFL rows are
  real interpreters sent real signals and graded on their exit status.
  One deliberate difference is an improvement rather than a gap: TypeScript can
  only `process.exit(143)`, while Python restores `SIG_DFL` and re-delivers, so
  the process dies BY the signal — the wait status a supervisor reads.
- 2026-08-05: the TypeScript generic tool governor now evaluates policy, closing
  the largest functional difference between the two SDKs. `obsvrGovernTool`
  reached its audit step without consulting the shared pre-call pipeline, so on
  that surface the anti-tamper floor, the customer rule set, the PII policy, the
  pre-call hook and the external policy backend were all inert, while Python's
  `govern_tool` consulted its pipeline for every one of them. This was an
  enforcement-verdict difference and therefore never eligible for the catalog
  above: measured on one rule set, a tool call whose arguments matched a block
  rule was refused in Python and executed in TypeScript. It was carried in
  neither the catalog nor this History while it existed, which is the gap the
  preamble's "silent divergence is never acceptable" names.
  The repair makes the TypeScript gate `async` and routes it through the same
  `applyPreCallPolicy` every other TypeScript surface uses. A synchronous entry
  point was measured as the alternative and rejected: every `await` in that
  function sits behind an opt-in (Presidio, the approval wait, the customer
  hook, the external backend), but they are interleaved with the deterministic
  layers rather than bookending them, so a synchronous path would have to carry
  a second copy of the orchestration — precedence, floor-over-rules, monitor
  conversion, reason-code resolution — and two copies of that rule drifting
  apart is the defect class this file exists to record. The cost is a breaking
  contract on one public API: a wrapped tool hands back a Promise even around a
  synchronous tool, and a refusal rejects rather than throwing. Every framework
  whose tool shape the wrapper resolves awaits that value (LangChain, Vercel AI,
  the OpenAI tool runner, `@openai/agents`, MCP, and LlamaIndex, whose tool
  return type is declared `JSONValue | Promise<JSONValue>`), so the change is
  invisible through a framework and reaches only direct callers.
  Two record-level repairs landed with it, on both SDKs: a tool permit no longer
  reports `action_source: "policy_rules"` when no policy layer judged it, and an
  MCP call whose policy engine raised under `fail_mode: "open"` records
  `not_evaluated` naming the layer instead of `allowed`. The permit side is
  pinned by `allowed-implies-evaluated` in both languages — an `allowed` verdict
  must carry the decision-input hash that evidences an evaluation.
- 2026-08-03: KD-11's substantive divergence was FIXED and the entry NARROWED.
  Python's ambient `use_subject()` subject now reaches the ENFORCING channel —
  the `require_principal` verdict, the user-scoped quota bucket, the
  session-taint key and the decision-input hash — on every surface that
  evaluates policy, via a single fold at the head of `apply_pre_call_policy`
  (the choke point every governed surface calls, which also covers the wrap
  path that `_identity_meta` folds never reached). This closed a verdict-level
  defect, not just a bucketing one: an ambient-only principal under
  `require_principal` was refused as absent while the same call's signed event
  named that principal — a record contradicting its own reason. KD-11 is
  retained, narrowed to the one residual edge (an explicit empty-string
  `user_id` alongside an active ambient subject resolves to the ambient
  subject in Python's enforcing channel and to the empty string in
  TypeScript's), which changes no verdict.
- 2026-07-28: KD-5 (customer-rule eval context on the TypeScript integrations
  path) was FIXED, and the row is gone. `applyPreCallPolicy` built the
  customer-rules context as `{provider, metadata}` while handing the floor,
  three lines above it, `{currentEnvironment, model, provider, metadata}` — so
  a customer `model_gate` or `environment_gate` rule was inert on that path
  and fired everywhere else. It now gets the floor's context, which is the
  same one the proxy wrapper and the Python shared pre-call build. The
  equivalence is pinned by `conformance/fixtures/eval_context.json`: ten cases
  of (rule, model, provider, environment, prompt) → verdict, asserted through
  BOTH TypeScript doors (`wrap()` and `applyPreCallPolicy`) and through
  Python's single shared pre-call. **Writing that fixture immediately found a
  second break in the same equivalence, in the opposite direction:** the proxy
  wrapper handled only the rules engine's `block` verdict, so a rule declaring
  action `redact` let the call out untouched and stamped the event `allowed`,
  while the same rule redacted through every integration and through Python.
  The wrapper now applies it, failing closed to a block when the removal
  cannot be carried out — pinned in `policy-rules-redact-wiring.test.ts`. That
  one was never in the catalog, which is the argument for the fixture: a
  divergence nobody wrote down is not smaller than one that was, only quieter.
  Both changes are behavioural for existing users and are recorded BREAKING in
  the CHANGELOG.
- 2026-07-28: KD-8 (LOOP_DETECTED / DELEGATION_BLOCKED) was FIXED by porting
  the owning controls, and the row is gone. `obsvr/agent_policy.py` is the
  Python twin of `policy/industry/devops.ts` + `policy/industry/agentic.ts`
  plus the emitting halves from `integrations/core.ts`, decision semantics
  pinned by the new `conformance/fixtures/agent_controls.json` (17 cases per
  suite, message strings included - the circular-chain separator is U+2192 in
  both). Loop detection is wired into the Python LangChain and OpenAI-Agents
  paths at the same positions TypeScript wires it, so `RESERVED_REASON_CODES`
  is now empty and both languages' reachability tests exempt nothing.
  **One thing the row got wrong, verified in the source:** it said both codes
  have a live TypeScript emission site, and for LOOP_DETECTED that is true
  (`integrations/core.ts` `applyLoopDetection`, called from langchain.ts and
  openai-agents.ts). `applyDelegationPolicy` is imported by both integrations
  but called by NEITHER - the tracker is constructed from
  `agentPolicy.delegationPolicy` and then nothing records a delegation, so no
  framework path emits DELEGATION_BLOCKED in either SDK. It reaches the TS
  reachability test only because that test drives the exported function
  directly. So the real gap that closed here was a public API a caller wires
  into its own handoff path, present in one language and not the other; the
  fixture pins its verdicts in both, and the disposition registry now records
  in `delegation_tracking`'s notes that no integration drives it. Wiring one is
  a design decision, not a port, and was left alone.
- 2026-07-28: KD-3 (block-mode discovery strip) was FIXED, and the row is gone.
  The row accepted a best-effort strip because Python cannot spread an
  arbitrary upstream listing model the way TypeScript spreads a plain object:
  `result.tools = kept` sat in a bare try/except, so a frozen model swallowed
  the strip and the model still read the swapped descriptor. The rebuild is now
  a declared chain — assignment, `model_copy(update=...)`, `copy(update=...)`,
  `dataclasses.replace`, then a shallow copy written through
  `object.__setattr__` — every step of which returns the listing's OWN class,
  which is what the row's stated objection (breaking the caller's type
  contract) was really about. The contract is pinned cross-language by
  `discovery_strip_cases` in `conformance/fixtures/tool_pinning.json`, and the
  Python harness runs all five cases against five listing shapes, four of which
  refuse assignment. Verified against real pydantic 2.13.4 as well as the
  stand-ins: a frozen model raises on assignment, `model_copy` rebuilds it, and
  the governed listing comes back as the same class with the offender gone. The
  one shape nothing can rebuild — a read-only `tools` property — now warns
  instead of reporting a strip that did not happen; the call-time gate refuses
  the tool either way, as it always did.
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
  `record_token_usage`, matching TS (`rules.py`, `metering.py`, `wrap.py`).
- 2026-07-11 (wave 1): several previously-silent divergences were FIXED (not
  accepted): Python customer hook
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
  "policy_rules"/"builtin+presidio" events entirely.
