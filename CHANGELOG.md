# Changelog

All notable changes to `@obsvr/sdk` (npm) and `obsvr-sdk` (PyPI) are documented
here. Both packages ship from this repository on one release train and share a
version number.

Breaking changes are marked **BREAKING** and carry a migration note. Additive
changes to closed enums count as breaking, because they break exhaustive
switches in consumer code. Entries are kept short by default; the long ones are
the ones that change something you depend on.

Each entry links the commit that made the change. This repository takes direct
pushes rather than pull requests, so a commit is the smallest reviewable unit
there is to link.

## [Unreleased]

Changes landed since 0.10.0. This section accumulates until the next release
cut, when it is renamed to that version.

### Removed

- **BREAKING: the manual-tracking client is gone.** `ObsvrClient`,
  `trackCompletion`, `trackBatch`, the deprecated `LLMAuditClient` alias, their
  parameter types, and the `@obsvr/sdk/client` subpath export are removed. That
  path posted events straight to ingest with no PII scan, no policy evaluation,
  and no chain signature — a second ingestion path in a package whose whole
  claim is that there is one, and the weaker of the two was a root export.
  **Migration:** use `obsvr.wrap()` around your provider client, which produces
  the same events with the controls applied and the chain signed. There is no
  supported way to enqueue an unsigned event, which is the point.
  ([`ebd2b33`](https://github.com/obsvr-dev/obsvr-sdk/commit/ebd2b33))

### Changed

- **Rules claiming the SDK's verdict namespace are rejected.** A policy rule
  whose `id` starts with `sdk:` or `backend:` is now invalid — those prefixes
  identify verdicts minted by the SDK's own governance layers, and an
  operator- or server-supplied rule wearing one was indistinguishable from
  the SDK's own records on the audit trail. **If you have a rule with such an
  id, rename it**; it will otherwise be rejected (with the `rule_rejected`
  signal on the sync path). Pinned by the `reserved_rule_id_rejected` case in
  `eval_semantics.json`.
  ([`ef1f49b`](https://github.com/obsvr-dev/obsvr-sdk/commit/ef1f49b))
- **The multi-turn injection reason no longer carries the score.** The stored
  `policy_reason` for a tripped multi-turn gate persisted the decayed score —
  a continuous margin an audit-log reader could watch across attempts and use
  to tune a payload under the threshold. The stored copy now carries only the
  turn count and which signals fired (byte-identical across SDKs, pinned by
  `conformance/fixtures/injection_reason.json`); full precision stays
  in-process. **Monitoring that string-matched the old wording must update.**
  ([`b82206e`](https://github.com/obsvr-dev/obsvr-sdk/commit/b82206e))
- **BREAKING: the audit-chain content hash is length-prefixed and domain-tagged
  (chain format 2).** The signature previously hashed `sha256(prompt +
  response)`, which does not bind where the prompt ends and the response begins
  — `("AB","C")` and `("A","BC")` hash identically — so a stored event's
  content could be re-split at a different attribution boundary and still
  verify. Events now carry `chain_format: 2` and are signed over
  `sha256("obsvr:content/2" || 0x00 || u64be(len(prompt)) || prompt ||
  u64be(len(response)) || response)`, with the format number leading the HMAC
  payload so the format claim is itself signed. **Migration:** nothing is
  required for existing exports — chains signed before this change verify
  exactly as before, and both verifiers now report `chainFormat: 1` for them
  (a format-1 chain attests content-in-order, not the prompt/response
  boundary). Verifiers older than this change cannot verify newly signed
  chains, so upgrade verifiers before producers. Within one session a chain
  must be format-uniform: a mixed, stripped, or unrecognized `chain_format`
  fails verification closed. External consumers of
  `conformance/fixtures/signing_vectors.json` must adopt the new layout —
  `events` is format-2, and the old vectors are frozen under
  `legacy_v1_events`.
  ([`763b5ef`](https://github.com/obsvr-dev/obsvr-sdk/commit/763b5ef))

### Added

- **Python agent-run controls: loop detection and delegation tracking.**
  `obsvr.LoopDetector` / `obsvr.DelegationTracker` (and their `create_*`
  factories) are the twins of the TypeScript controls, with identical
  thresholds, check order, and violation messages, pinned by the new
  `conformance/fixtures/agent_controls.json`. Loop detection is driven for you
  by the LangChain and OpenAI-Agents integrations when
  `agent_policy={"loop_detection": {"max_iterations": N, "window_ms": M,
  "action": "block"}}` is configured; a run past the limit emits a
  `LOOP_DETECTED` event and stops. Opt-in: with no `loop_detection` block, an
  agent run behaves exactly as before. Delegation tracking is a library you
  drive from your own handoff path, as in TypeScript.
  ([`36696bc`](https://github.com/obsvr-dev/obsvr-sdk/commit/36696bc))
- **`sessionTaint.destructiveTools`: a tainted session loses its dangerous
  capabilities.** An exact-name tool set a tainted session may never invoke,
  enforced at every tool boundary (governed tools, MCP, framework wrappers)
  even under the default `action: "flag"` — ordinary egress stays merely
  flagged while `send_money`-class capabilities go dark, which is the
  composition that actually stops indirect injection. One set-membership test
  at the tool gate; decisions pinned as `(tool_name, taint_state) → decision`
  in `conformance/fixtures/session_taint.json`.
  ([`e350ab9`](https://github.com/obsvr-dev/obsvr-sdk/commit/e350ab9))
- **Every audit event carries a `reason_code`.** The registry code for the
  classification the decision rests on — the deciding layer's fine-grained
  code (the rules engine's `KEYWORD_BLOCKED`, `MODEL_GATE_BLOCKED`, ...),
  `PERMITTED` on a clean allow — and always the same code the thrown
  `ObsvrPolicyError` carries, resolved once for both. Previously the engine's
  code was discarded at the throw site and re-derived as one of four coarse
  categories, and the event had no such field at all.
  ([`b8848a1`](https://github.com/obsvr-dev/obsvr-sdk/commit/b8848a1))
- **The seven dormant reason codes are emitted.** `INJECTION_DETECTED` (single-
  and multi-turn injection blocks, which previously surfaced as `PII_DETECTED`
  or `POLICY_VIOLATION`), `TRANSMISSION_BLOCKED` (taint-gated egress refusals),
  `TOOL_DENIED` (agent-policy tool refusals on every integration),
  `MCP_TOOL_DENIED` / `MCP_RESULT_BLOCKED` (the MCP gates), and
  `LOOP_DETECTED` / `DELEGATION_BLOCKED`. Both suites now run a
  reachability gate: every registry code must be emitted by an exercised path,
  pinned in a named suite, or explicitly reserved — and as of the Python
  agent-run controls below, nothing is reserved in either language.
  ([`2f3b5a4`](https://github.com/obsvr-dev/obsvr-sdk/commit/2f3b5a4))
- **MCP tool descriptors are content-inspected at discovery.** The poisoning
  scan now also reads JSON Schema `description` / `default` strings at any
  depth, matches over a comment-stripped view (a directive split by HTML
  comments reads whole to the model and fragmented to a scanner) and — with
  `deobfuscation` enabled — the decoded views; bidi controls are flagged on
  presence, concealment is its own signal, and a truncated schema walk says
  so. Reasons pinned exactly by `conformance/fixtures/tool_descriptor_scan.json`.
  ([`ca0c209`](https://github.com/obsvr-dev/obsvr-sdk/commit/ca0c209))
- **Cross-SDK bookkeeping is validated data.** Fixture cases carry per-language
  `sdk_support` (a gap shows as a recorded skip, not a missing test — first
  used by the hidden-markup cases, since closed), fixtures carry `claimable` enforced
  bidirectionally against the public docs, the known-divergences table became
  the schema-checked `conformance/known-divergences.json`, and the spec's
  seven uncovered EV statements are a checked partition in
  `eval_semantics.json` rather than a prose admission.
  ([`2585ce0`](https://github.com/obsvr-dev/obsvr-sdk/commit/2585ce0),
  [`97d82dd`](https://github.com/obsvr-dev/obsvr-sdk/commit/97d82dd))
- **Dropped events are declared in the signed chain.** A bounded-queue overflow
  now signs a **gap marker** at the chain position where events were lost,
  stating how many. The count lives in the signature preimage, so editing it
  down breaks verification. Previously drops preceded sequence assignment, so a
  burst that lost most of its events still verified clean. Both verifiers gained
  `gapMarkers` / `eventsDeclaredLost` (`gap_markers` / `events_declared_lost`),
  and the format is pinned by `conformance/fixtures/audit_gap.json`.
  ([`6e824fc`](https://github.com/obsvr-dev/obsvr-sdk/commit/6e824fc))
- **`obsvr-verify` exit code 3: valid but incomplete.** A chain declaring
  dropped events now exits `3` rather than `0`, so `obsvr-verify chain.json &&
deploy` no longer passes on a record missing most of its events. **If you gate
  on the exit status, a previously passing chain that declares loss will now
  fail**; `--allow-gaps` maps `3` back to `0`, suppressing the status only and
  never the printed disclosure.
  ([`d5db27f`](https://github.com/obsvr-dev/obsvr-sdk/commit/d5db27f))
- **Typed policy-block error.** A refused call now raises `ObsvrPolicyError` in
  both SDKs with a stable `type`, a registry `reason_code`, the deciding
  `rule_id`, and decision metadata, so a deliberate refusal is distinguishable
  from a transport failure. An unrecognized reason category yields
  `ObsvrUnknownPolicyError` rather than an untyped error. Message text is
  unchanged; Python still subclasses `RuntimeError`.
  ([`6dfa8c7`](https://github.com/obsvr-dev/obsvr-sdk/commit/6dfa8c7))
- **Duplicate-instance guard.** With the SDK installed twice in one process, the
  first copy to `init()` governs and the second stands down with a warning. A
  copy that stood down passes clients through unwrapped, so the warning names
  the fix: deduplicate the dependency.
  ([`71caea2`](https://github.com/obsvr-dev/obsvr-sdk/commit/71caea2))
- **Python chain verification.** `obsvr.verify_chain(events, api_key)` verifies
  an exported chain offline, checking every signature plus sequence continuity,
  linkage, session consistency, and timestamp monotonicity, with the same
  verdicts as the TypeScript `verifyAuditChain`.
  ([`fea31b3`](https://github.com/obsvr-dev/obsvr-sdk/commit/fea31b3))
- **`dropped_rejected` delivery counter.** Events a server refuses individually
  inside a 2xx batch now get their own counter and poll-header key; they were
  previously counted as sent. The `dropped` aggregate still means
  never-delivered.
  ([`5b9a941`](https://github.com/obsvr-dev/obsvr-sdk/commit/5b9a941),
  [`8d9066e`](https://github.com/obsvr-dev/obsvr-sdk/commit/8d9066e))
- **`tool_content_hash` is pinned by a shared fixture.**
  `conformance/fixtures/tool_content_hash.json` fixes the canonical document and
  digest for sixteen cases, including the numbers that must refuse to hash
  rather than seal a value the two languages format differently, and pins that
  this hash is not the descriptor-pinning hash.
  ([`cf6c958`](https://github.com/obsvr-dev/obsvr-sdk/commit/cf6c958))
- **`obsvr-verify` ships for Python.** `pip install obsvr-sdk` installs a console
  script with the same tiers, exit codes, bundle shapes, and verdicts as the npm
  CLI, so a Python-only team can verify its own evidence without a Node
  toolchain. CI drives both binaries over one export so they cannot drift.
  ([`1756930`](https://github.com/obsvr-dev/obsvr-sdk/commit/1756930))
- **Tool-call events carry `tool_content_hash`.** Events from an MCP tool
  boundary (both SDKs) or `obsvrGovernTool` (TypeScript) carry a digest binding
  the tool name, the descriptor the caller held, and the call arguments, so a
  descriptor swap is attributable after the fact. Blocked tool calls are
  stamped too, and the digest is omitted rather than guessed when a value
  cannot be canonicalized identically in both languages.
  ([`407186f`](https://github.com/obsvr-dev/obsvr-sdk/commit/407186f),
  [`5ab19ec`](https://github.com/obsvr-dev/obsvr-sdk/commit/5ab19ec),
  [`fd05442`](https://github.com/obsvr-dev/obsvr-sdk/commit/fd05442))
- **HTTP 409 `duplicate_event` counts as a delivery, not a drop.** A retry that
  raced a lost 2xx was dead-lettered, fabricating a coverage gap for an event
  the server had already sealed. Only that code: `409 sequence_fork` stays a
  failure, and an unreadable 409 body is never absorbed.
  ([`4dd99b4`](https://github.com/obsvr-dev/obsvr-sdk/commit/4dd99b4))
- **The Python sender reads batch responses.** It previously discarded the body,
  so events a server refused inside a 2xx batch counted as sent. Per-event
  rejects now increment `dropped_rejected`, are excluded from `sent`, and arm no
  backoff. An unparseable body means "no rejects reported", never a failed
  delivery.
  ([`8d9066e`](https://github.com/obsvr-dev/obsvr-sdk/commit/8d9066e))
- **The shared conformance corpus is hash-pinned.** `conformance/MANIFEST.sha256`
  hashes every file, and each package pins the corpus its suite was written
  against. CI fails on an unregenerated pin, disagreeing pins, or a fixture with
  no consumer. What this closes is a forked fixture: a copy drifts, both suites
  keep passing, and the shared contract stops being shared.
  ([`7a329ef`](https://github.com/obsvr-dev/obsvr-sdk/commit/7a329ef))
- **CSS-hidden and aria-hidden content is stripped from the scan view, in both
  SDKs.** Hidden markup could break a phrase apart so it read as an injection
  to the model and as unrelated fragments to a scanner. Elements hidden via
  `display:none`, `visibility:hidden`, or `aria-hidden="true"` are now removed
  from the canonical view, tag and content. Raw text is still scanned first, so
  a payload hidden whole was always caught; this closes the split-phrase case.
  Detection-only, and off unless `deobfuscation: { enabled: true }`.
  ([`9916800`](https://github.com/obsvr-dev/obsvr-sdk/commit/9916800),
  [`ad34f66`](https://github.com/obsvr-dev/obsvr-sdk/commit/ad34f66))
- **Python signed-policy verification.** `obsvr.init(policy_public_key=...)` pins
  an Ed25519 key and `policy_verify.py` checks a fetched policy's signature with
  the same checks and refusal reasons TypeScript used. The backend is optional
  (`pip install "obsvr-sdk[crypto]"`); with a key pinned and none installed the
  policy is refused and the events say so.
  ([`6783b26`](https://github.com/obsvr-dev/obsvr-sdk/commit/6783b26),
  [`9c479d5`](https://github.com/obsvr-dev/obsvr-sdk/commit/9c479d5))
- **Failure-disposition registry.** Every governance layer declares what it does
  in each failure state (timeout, error, degraded) in one table per language,
  pinned by `conformance/fixtures/fail_mode.json`. Descriptive when it landed:
  no call path read it and no behavior changed.
  ([`b1a33dd`](https://github.com/obsvr-dev/obsvr-sdk/commit/b1a33dd))

### Fixed

- **Python MCP discovery could fail to strip a tool it had refused.** Under
  `pinning: {mode: "block"}` (or `block_poisoned_tools`), the offending tools
  are removed from the listing the model reads. Python performed that by
  assigning to `result.tools` inside a bare `try`/`except`, so a listing model
  that forbids assignment — a frozen pydantic result, for instance — kept the
  swapped descriptor visible while the code reported success. The listing is
  now rebuilt through whichever of `model_copy` / `copy(update=…)` /
  `dataclasses.replace` / a shallow copy the type supports, each returning the
  listing's own class; the one shape that can be rebuilt no way at all warns
  instead of staying silent. The call-time gate refused the tool before this
  change and still does — this closes the discovery half.
  ([`1c5d9d8`](https://github.com/obsvr-dev/obsvr-sdk/commit/1c5d9d8))
- **An explicit `timeout_ms: 0` on the Python external policy backend was
  silently replaced by the 2-second default.** The value was read with an
  `or`-default, so the strictest configurable budget — zero, which fails
  closed as a timeout — was the one value the code could not express, while
  the TypeScript twin honored it. The default now applies only when the field
  is absent.
  ([`00b5dd1`](https://github.com/obsvr-dev/obsvr-sdk/commit/00b5dd1))
- **The two SDKs could derive different `policy_version` values from the same
  policy.** Python's canonical form came from `json.dumps`, which disagrees with
  `JSON.stringify` on whole-valued floats, negative zero, exponent form,
  unpaired surrogates, and astral key order. A differential property test
  (fast-check against hypothesis) found roughly a third of generated documents
  diverging; `_canonical_json` is now a faithful port. See Changed for the
  effect on approvals.
  ([`87c593d`](https://github.com/obsvr-dev/obsvr-sdk/commit/87c593d))
- **A bug inside a detector layer could break the calling application.** Eight
  in-process detector layers had no error channel, so an exception inside one
  propagated out of your own LLM call rather than resolving to allow or block.
  Every path is now guarded in both SDKs, resolving by `failMode` for the
  scanning layers and closed for the policy floor and canary. Failures are
  counted under `detector_errors` on the fleet poll and recorded on the call's
  own signed event under `obsvr_telemetry.detector_failure`.
  ([`201a062`](https://github.com/obsvr-dev/obsvr-sdk/commit/201a062),
  [`2825333`](https://github.com/obsvr-dev/obsvr-sdk/commit/2825333),
  [`e5f845d`](https://github.com/obsvr-dev/obsvr-sdk/commit/e5f845d),
  [`7a314e0`](https://github.com/obsvr-dev/obsvr-sdk/commit/7a314e0),
  [`9441702`](https://github.com/obsvr-dev/obsvr-sdk/commit/9441702),
  [`04cbf38`](https://github.com/obsvr-dev/obsvr-sdk/commit/04cbf38),
  [`2c80466`](https://github.com/obsvr-dev/obsvr-sdk/commit/2c80466))
- **A failed redaction could send the content it was told to remove.** Applying
  a `redact` decision to the outbound arguments was unguarded, so a defect could
  forward a partially-redacted request. It now fails **closed** regardless of
  `failMode`, and the event drops any `redacted` claim.
  ([`9f738ce`](https://github.com/obsvr-dev/obsvr-sdk/commit/9f738ce))
- **A stored audit copy could be written by a broken redactor.** Every stored
  copy now goes through one guarded point per language, falling back to
  `[UNSCANNED:detector_error]`, deliberately unlike the `[REDACTED…]` markers,
  rather than persisting content nothing scanned.
  ([`04fbf08`](https://github.com/obsvr-dev/obsvr-sdk/commit/04fbf08))
- **The GitHub Action installed a stale SDK.** Its `version` input defaulted to
  0.9.0 against a 0.10.0 repository, so a default CI job verified evidence with
  an older SDK than the one that produced it. The default now tracks the package
  version, and the version-consistency check covers `action/action.yml`.
  ([`bb2125a`](https://github.com/obsvr-dev/obsvr-sdk/commit/bb2125a))

### Changed

- **A Python-computed `policy_version` changes value for rule sets containing
  certain numbers.** The canonicalizer fix described under Fixed is listed here
  as well because of what depends on that hash. Approvals are pinned to the rule
  hash, and the `/policies` poll sends `X-Obsvr-Rules-Hash`, so a rule set
  containing a whole-valued float, negative zero, an exponent-form number, an
  unpaired surrogate, or an astral object key hashes to a different value in
  Python than it did before — to the value TypeScript was already producing. No
  hash the two SDKs agreed on has changed. _Migration: if a Python process holds
  outstanding approvals for such a rule set, they are void and must be
  re-granted; a mixed-language fleet stops reporting two different versions for
  one policy._
  ([`87c593d`](https://github.com/obsvr-dev/obsvr-sdk/commit/87c593d))

- **BREAKING: `QUOTA_UNMETERED` added to the closed `ReasonCode` registry.**
  A quota rule whose scope the bounded meter has no counter slot for is not
  enforced on that call, and now says so: the verdict carries
  `metered: false`, the call's event carries
  `metadata.obsvr_telemetry.quota_unmetered` (the channel `detector_failure`
  and canary evidence already use), and `failMode` decides whether the call
  proceeds — `open` (the default) allows it, `closed` blocks it with the new
  code. Previously such a call was allowed with no signal at all and was
  byte-identical on the wire to one that had been counted and found under
  limit, so an auditor replaying it read a quota rule that was in force and
  never exceeded. The `policyFloor` always resolves closed here, floor-class
  rules being non-overridable; shadow rules never do, being non-decisional.
  _Migration: this is additive to a closed enum, so an exhaustive `switch` over
  `ReasonCode` in consumer code needs a `QUOTA_UNMETERED` arm. Operators
  running `failMode: "closed"` should note that a saturated quota store now
  blocks new scopes rather than admitting them unmetered._
  ([`750e5f9`](https://github.com/obsvr-dev/obsvr-sdk/commit/750e5f9),
  [`7e22b4b`](https://github.com/obsvr-dev/obsvr-sdk/commit/7e22b4b))

- **BREAKING (Python): `ingest_url` no longer defaults to
  `http://localhost:3000`.** Unset, it is now empty: the SDK logs a loud
  no-delivery warning at `init()` and delivers nothing, matching the TypeScript
  SDK on the same misconfiguration. Previously a Python process with no
  `ingest_url` streamed governed events - including redacted prompt text on
  blocked calls - to whatever was listening on local port 3000. _Migration: if
  you relied on the localhost default in development, pass
  `ingest_url="http://localhost:3000"` explicitly._ Governance itself is
  unaffected either way; only delivery stops.
  ([`07413f7`](https://github.com/obsvr-dev/obsvr-sdk/commit/07413f7))
- An unusable ingest URL is now a delivery failure in Python rather than an
  exception: the sender and the policy poll both count it as retryable instead
  of raising inside their background threads.
  ([`07413f7`](https://github.com/obsvr-dev/obsvr-sdk/commit/07413f7))
- The normative evaluation-semantics specification (EV-1 through EV-23) now
  lives at `conformance/SPEC-evaluation.md`, beside the fixtures that pin it.
  Semantics are unchanged.
  ([`3b0f13d`](https://github.com/obsvr-dev/obsvr-sdk/commit/3b0f13d))
- `conformance/fixtures/signing_vectors.json` gained a `chain_verification`
  block: thirteen tamper cases with the verdict both verifiers must produce.
  Consumers of the existing `events` and key material are unaffected.
  ([`9c479d5`](https://github.com/obsvr-dev/obsvr-sdk/commit/9c479d5))

## [0.10.0] - 2026-07-20

Security engine and integrity hardening. Private beta. The first commit in this
repository, [`e90caf0`](https://github.com/obsvr-dev/obsvr-sdk/commit/e90caf0),
squashes the work below. Nothing was published to npm or PyPI before it, so the
record starts here.

### Added

- De-obfuscation scan views, so detection sees through encodings that hide
  payloads from a naive scan.
- MCP and tool-descriptor content-hash pinning (trust-on-first-use plus
  operator-declared pins), defending against rug-pull descriptor swaps.
- Canary honeytokens and a session-taint latch: a session compromised on an
  earlier turn has its later egress escalated.
- A non-overridable anti-tamper policy floor, evaluated before customer rules
  and excluded from customer-hook override.
- SSRF-guarded outbound endpoints for the external policy backend and Presidio,
  validated at init.
