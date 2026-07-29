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

- **Four framework integrations withdrawn before first publish.** The modules
  (`obsvr/integrations/{agent_framework,semantic_kernel,adk,smolagents}.py`),
  their extras (`agent-framework`, `semantic-kernel`, `adk`, `smolagents`),
  their tests, and every reference to them in this repository are gone in one
  change — a documented integration whose module does not exist is worse than
  either state alone.
  **Not marked BREAKING:** none of these shipped in a release, so nothing
  depended on them.

  **The basis is breadth versus evidence, not brokenness.** Each was verified
  only far enough to prove it binds and blocks, and the supported surface is
  being narrowed to what is backed by live evidence rather than widened to what
  compiles. Worth stating plainly, though: three of the four also had floors
  that no ordinary install could reach — every `agent-framework` release below
  1.11.0 fails dependency resolution outright, every `google-adk` release below
  1.2.0 installs but cannot import, and `semantic-kernel` has no candidate at
  all below 1.14.0 on CPython 3.13.

  The code is preserved on a local branch and can return with the evidence
  behind it.


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

- **BREAKING: `action_taken` gains `not_evaluated`.** It means **no gate ran for
  this event's subject** — the absence of a decision, not a permissive one. It
  is emitted today by the tool events a provider tool runner produces
  (`chat.completions.runTools`, `beta.messages.toolRunner`), which invoke their
  tools directly, so obsvr is not on that boundary and no tool-level control —
  including `sessionTaint.destructiveTools` — is consulted. Those events
  previously read `action_taken: "allowed"`, which asserts that a gate evaluated
  the call and permitted it.

  **Breaking because it widens a closed enum**, per this file's own rule:
  exhaustive switches over `action_taken` will not have a branch for it. **The
  migration is one question — does your code treat "not allowed" as "blocked"?**
  If a consumer branches `action_taken === "allowed" ? … : blocked`, a
  `not_evaluated` event will now fall into the blocked branch and be counted as
  a refusal that never happened. Treat it as its own state: not permitted, not
  refused, not evaluated.

  **Omitting the field was not an alternative.** The ingest schema defaults an
  absent `action_taken`, so a missing verdict was minted as `"allowed"` on
  arrival — the same false claim, one layer down and harder to see. That default
  is now `not_evaluated` too, so an event that never carried a verdict no longer
  acquires one by transit.

  Both SDKs also extend the canary-leak escalation, which fired only on
  `"allowed"`: a leaked canary on a `not_evaluated` event now escalates to
  `policy_flag` as it always did on an allowed one. Deliberately not widened to
  "anything that is not blocked" — that would newly escalate `redacted` and
  `hook_*` events, which is a separate behaviour change.


- **Text that only quotes an injection phrase is no longer rewritten.** The
  built-in scanner and the redactor iterate the same pattern table, so a bug
  report, a test fixture or a policy document reproducing an attack string was
  flagged and then had that string replaced with `[BLOCKED_INJECTION]` in the
  stored copy — an audit record committed to content the model was never shown.
  A `prompt_injection` match whose span is immediately enclosed by a matching
  quote, apostrophe or backtick pair is now marked quoted: **the stored text is
  left byte-for-byte as sent**, and the match no longer counts as the
  single-turn full match handed to the multi-turn scorer. **This is a downgrade,
  not a suppression** — `pii_detected` and `detected_types` are unchanged, so
  the detection event still fires, any configured `pii_policy` action still
  applies, and the phrase still accrues weak-signal score toward the multi-turn
  gate. **One consequence to expect when tuning:** that gate fires on
  `tripped && !hadFullMatch`, so a quoted phrase — no longer a full match — no
  longer short-circuits it, and **multi-turn trips can now fire on quoted text
  where they previously did not**. Quoting is consulted for `prompt_injection`
  only; a quoted credential is still a leaked credential and is still scrubbed. The delimiter test is strict
  adjacency and deliberately narrow: punctuation inside the quotation
  (`"…instructions."`) and a quotation wider than the matched phrase both still
  redact, because every relaxation classifies more text as quoted. Additive API:
  `runBuiltinPiiScan` / `run_builtin_pii_scan` now also return `matches`
  (`label`, `confidence`, `quoted`); existing readers of `pii_detected` and
  `detected_types` are unaffected. Pinned by
  `conformance/fixtures/pii_scan.json`.
  ([`9f164a2`](https://github.com/obsvr-dev/obsvr-sdk/commit/9f164a2))
- **Approval grants are bound to the action they were granted for, and
  re-checked before the call goes out.** A grant may now carry an
  `action_hash` — a canonical digest of the rule, the rule's definition hash,
  the action name, the amount, the caller and target namespaces, and the
  subject — and a grant carrying one satisfies only a call that hashes the
  same. Previously a grant was scoped to a rule id, so one human approving a
  small transfer left a live grant that satisfied a large one, because both
  tripped the same rule. **Not breaking for existing deployments:** each pin
  only narrows, so a grant with no `action_hash` still satisfies exactly as
  before, and an issuer can start binding without voiding outstanding grants.
  The digest deliberately excludes the free-text prompt (an approved request
  and its retry rarely reproduce it byte for byte). Separately, a grant is now
  re-checked after every layer that can delay a call — the customer hook's
  timeout budget, an external policy backend — so **a grant revoked or expired
  mid-call now blocks where it previously proceeded**, reported as
  `approval_expired_before_execution`. Two related fixes: the framework-
  integration path could reach `approval_required` and then file no approval
  request, leaving the block permanent rather than pending — it now files one;
  and the request carries the action hash so the granting party can mint a
  bound grant at all. Pinned by `conformance/fixtures/approvals.json`.
  ([`4836c6d`](https://github.com/obsvr-dev/obsvr-sdk/commit/4836c6d))
- **BREAKING: an MCP tool that declares `destructiveHint: true` is now in the
  destructive-capability set by default.** With `sessionTaint` enabled, a
  tainted session's calls to destructive tools are refused even under the
  default `flag` action — but membership used to come only from an
  operator-written `destructiveTools` list, so a deployment that configured no
  list got no capability gate at all and no indication of it. Tool descriptors
  seen at `tools/list` are now read for `annotations.destructiveHint`, and a
  tool that affirmatively declares itself destructive joins the set. **This
  changes behavior for anyone using MCP with taint enabled and no
  `destructiveTools` configured: calls a tainted session previously made now
  block.** Set `sessionTaint.honorDestructiveHints: false`
  (`honor_destructive_hints` in Python) to restrict the set to your configured
  list. The hint can only ever ADD — a server cannot describe itself out of the
  set, an operator entry applies regardless of what a descriptor claims, and a
  later listing that drops the hint does not un-declare the tool. An absent
  hint means non-destructive; a descriptor the SDK cannot read at all resolves
  to destructive. Discovery-time only, no hot-path cost. Blocked events name
  which source decided (`operator list` / `tool descriptor hint`) and the
  discovery event carries `destructive_hinted_tools`. Pinned by
  `tool_gate_cases` and `descriptor_hint_cases` in
  `conformance/fixtures/session_taint.json`.
  ([`fcfdc3a`](https://github.com/obsvr-dev/obsvr-sdk/commit/fcfdc3a))
- **BREAKING: `model_gate` and `environment_gate` rules now fire on the
  framework-integration path.** `applyPreCallPolicy` built the customer-rules
  evaluation context without the request model or the environment, so a rule of
  either type could not evaluate there and silently permitted every call —
  while the same rule enforced through `wrap()` and through the Python SDK. The
  context is now the one the anti-tamper floor already got on that path, which
  is also the one the proxy wrapper and Python build. **Migration: before
  upgrading, review your `model_gate` and `environment_gate` rules.** If any of
  your traffic reaches the SDK through an MCP, Bedrock, Vertex, Vercel AI,
  Cloudflare, Azure OpenAI, Together, or OpenAI-compatible integration, those
  rules were not enforcing on it and will start to. A tool boundary has no
  request model, so a `model_gate` rule keyed on `allowed_models` /
  `denied_models` still cannot evaluate there and continues to permit; one
  keyed on `allowed_providers` evaluates everywhere. Pinned by the new
  `conformance/fixtures/eval_context.json`, whose ten cases are asserted
  through both TypeScript entry points and through Python's shared pre-call.
  ([`2094f08`](https://github.com/obsvr-dev/obsvr-sdk/commit/2094f08))
- **BREAKING: a rule with `action: "redact"` now redacts on the `wrap()`
  path.** The wrapper's rules step acted only on a `block` verdict, so a redact
  rule forwarded the prompt unmodified and recorded `action_taken: "allowed"` —
  an audit record contradicting the policy in force. The same rule already
  redacted through every framework integration and through Python. **Migration:
  review any rule declaring `action: "redact"`.** Matching calls now have the
  SDK's structure-aware PII redaction applied to the outgoing request and are
  recorded `redacted` with the deciding `rule_id`; if the redaction cannot be
  applied the call is blocked rather than sent, regardless of `failMode`. A
  rule that needs to suppress non-PII content should declare `action: "block"`
  — `redact` has always meant PII redaction on the other paths.
  ([`df8a326`](https://github.com/obsvr-dev/obsvr-sdk/commit/df8a326))
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

- **Known limitation, stated rather than left to be discovered: blocked-call
  attribution on `ai` below 5.0.0.** Enforcement is fully correct across the
  supported range — the call is blocked, `status_code` is 403, the reason code
  and blocked types are right. On `ai` 3.3.28–4.x the blocked *event* carries
  `provider: "unknown"` and `model: "unknown"`, so per-provider or per-model
  reporting **over blocked calls** is unavailable there. Every other event is
  unaffected, and from `ai` 5.0.0 blocked events are fully attributed.

  This is upstream and not recoverable inside the SDK: at language-model spec v1
  `transformParams` receives `{ params, type }` and no model, the middleware
  object exposes no wrap-time hook that could supply one, and obsvr never calls
  `wrapLanguageModel` itself — the caller does. A block is thrown from
  `transformParams` before `wrapGenerate` runs, so a cached model would still
  leave the first call unattributed. Fixing it would mean adding a public option
  for the caller to declare the model, which is not worth new API surface for a
  version range where enforcement already works.

- **Declared peer floors now name releases the code can actually work with.**
  Every floor below was checked by building a throwaway environment per
  candidate version, installing that version alone, and importing the exact
  symbol the integration binds — not by reading a changelog. A floor that is
  merely *safe* was rejected the same as one that is wrong, so these are the
  lowest working versions rather than the lowest convenient ones.

  | Package | Was | Now | Why the old floor was false |
  | --- | --- | --- | --- |
  | `ai` | `>=3.0.0` | `>=3.3.28` | the middleware API `obsvrMiddleware()` attaches to does not exist below 3.3.28 — roughly 130 advertised releases where the integration cannot be constructed at all |
  | `llamaindex` | `>=0.5.0` | `>=0.5.9` | 0.5.0 and 0.5.8 register the handler and emit **no audit events at all**: the call succeeds, the provider returns usage, and nothing is recorded |
  | `@aws-sdk/client-bedrock-runtime` | `>=3.422.0` | `>=3.586.0` | `ConverseCommand` / `ConverseStreamCommand` — two of the four commands the integration dispatches on — do not exist below 3.586.0 |
  | `pydantic-ai-slim` | `>=0.0.14` | `>=0.4.4` | `pydantic_ai.toolsets.WrapperToolset` does not exist below 0.4.4; below it `govern_toolset()` still returns an object, so denied-tool policy, per-tool auditing and step limits are silently inert |
  | `google-adk` | `>=0.1.0` | `>=1.2.0` | all thirteen releases below 1.2.0 install but cannot import (`google.adk.models` raises `ModuleNotFoundError: deprecated`, reached through the OpenTelemetry stack) |
  | `semantic-kernel` | `>=1.0.0` | `>=1.16.0` | 1.14.0 and 1.15.0 install but cannot import against any modern pydantic; below 1.14.0 CPython 3.13 has no candidate at all |
  | `llama-index-core` | `>=0.10.0` | `>=0.11.23` | the declared floor emits no audit event at all; **this floor is the lowest release VERIFIED working live rather than the first known-good one** — the 0.10.x line could not be measured, so versions below are excluded for being unverifiable, not for being proven broken ([`0bdfbc1`](https://github.com/obsvr-dev/obsvr-sdk/commit/0bdfbc1)) |
  | `agent-framework` | `>=1.0.0` | `>=1.11.0` | all sixteen releases below 1.11.0 fail dependency resolution outright — the meta-package pins `agent-framework-core` to its own version exactly, while a sibling reached through that package's `all` extra requires `>=1.11.0` — so the extra named sixteen releases a plain install cannot produce ([`dc0f1bf`](https://github.com/obsvr-dev/obsvr-sdk/commit/dc0f1bf)) |
  | `smolagents` | `>=1.0.0` | `>=1.4.0,!=1.5.0` | below 1.4.0 the import fails against a current `transformers`; 1.5.0 does not pull `transformers` in at all, and 1.5.1 restored it. The hole is excluded rather than rounded up, because 1.4.x genuinely works |

  Most of these are upstream packaging problems rather than obsvr renames, but
  a declaration that advertises a release the integration cannot bind on is
  obsvr's to correct either way. **Migration:** none, unless you pinned a
  version inside one of the removed ranges — in which case the integration was
  not working there, silently, and the resolver error is the first honest
  signal you have had.
  ([`5342720`](https://github.com/obsvr-dev/obsvr-sdk/commit/5342720))

- **The two direct-provider floors now name releases that carry an auditable
  method.** The floors above were corrected for failing to *bind*; these two
  bound perfectly well and governed nothing, which is the quieter failure and
  the harder one to notice from outside. Both were re-established by an
  exhaustive walk — one throwaway environment per published release, 326 for
  `openai` and 197 for `anthropic`, no bisect anywhere — so every boundary
  named is an adjacent tested pair rather than an interpolation, and each
  boundary was then re-run live and graded on the captured event.

  | Package | Was | Now | Why the old floor was false |
  | --- | --- | --- | --- |
  | `anthropic` | `>=0.3.0` | `>=0.16.0` | the declared floor governs **nothing**. 0.3.x exposes only `completions.create`, which is not an auditable method, so an operator who resolved that floor built a client, wired obsvr, sent traffic and got **zero audit events with nothing raising**. Confirmed live rather than read off a shape: 0.7.8 grades `NO_AUDIT` because no auditable path exists on the client at all. `beta.messages.create` arrives at 0.8.0, and `messages.create` — the path the support table is about — at 0.16.0 |
  | `openai` | `>=1.0.0` | `>=1.66.0` | honest for exactly **one of the seven** declared auditable paths. 1.0.0 through 1.65.5 carry `chat.completions.create` and nothing else; `responses.create` and `responses.parse` both arrive at 1.66.0 |

  **`>=1.66.0` still does not promise every path, and the manifest now states
  the reality per path rather than per range.**
  `beta.chat.completions.parse` arrives at 1.40.0, `chat.completions.parse` and
  `beta.chat.completions.create` at 1.92.0, and `beta.responses.create` only at
  2.45.0 — six releases out of the 326 walked. The floor was deliberately not
  raised to 2.45.0 to cover that last path, because a range standing for six
  releases would misdescribe the 141 on which the `responses` paths do work.
  For `anthropic`, `messages.parse` arrives at 0.77.0 and is likewise not
  promised by the range.

  Two non-monotonic rows in the walks are upstream history, not obsvr
  regressions, and are recorded that way: `openai` 1.99.0 ships a broken
  `openai.types.responses`, so both `responses` paths read absent for a single
  day until 1.99.1; and `anthropic`'s `beta.messages` is absent from 0.16.0
  through 0.35.0 because the beta namespace was removed outright when that API
  graduated, returning at 0.36.0. **Raise the floor to `>=0.36.0` if the beta
  namespace has to be covered too.**

  **Not marked BREAKING, and the reason is that nothing has been published
  from this repository yet** — no installed consumer can be depending on the
  old floors. **Migration:** none, unless you pinned a version inside a removed
  range, in which case the extra was advertising governance you were not
  receiving.

- **`content_provenance` on audit events: where inside the payload the content
  came from.** `source` names the integration that emitted an event ("mcp",
  "langchain"); this names the position the text occupied within the call —
  `user_turn`, `system`, `retrieved`, `tool_result`, `memory`, `unknown`. It
  exists for triage: a `prompt_injection` found in a user turn is someone
  probing your bot, and the identical finding in a tool result means an upstream
  data source is already compromised. Set **only where an integration genuinely
  knows** and absent everywhere else — today that is the MCP tool-result events
  and LangChain's `tool.result`, all as `tool_result`. Never inferred from the
  operation name or the payload shape, because a wrong value gets read as
  evidence in exactly the incident where being wrong costs the most.
  **Audit-record completeness only, deliberately not a policy input:** nothing
  in detection, scoring, or gating reads it, since obsvr gates on session-taint
  reachability rather than on classifying how far to trust a source. **Not
  sealed:** the Merkle leaf, the `sdk_sig` preimage and the decision-input
  document are each closed lists of named fields and this is in none of them, so
  it sits outside the integrity proof and can be altered without breaking chain
  or root verification — treat it as a triage hint, not as evidence. Optional
  and absent by default; callers that ignore it see no change. Because ingest
  has no column for the name yet, it also rides reserved
  `metadata.obsvr_content_provenance`, the route `obsvr_tool_content_hash`
  already takes.
- **BREAKING: a 14th rule type, `protocol_facet`, matching parsed statement
  structure.** A rule can now address `sql.verb`, `sql.target`, `sql.tables`,
  `sql.functions` and `sql.multiple_statements` instead of matching characters:
  `{ type: "protocol_facet", conditions: { facet: "sql.verb", facet_not_in:
  ["select"] } }`. A comment between `DROP` and `TABLE` defeats a regex and
  does not defeat this, and it does not fire on prose that merely mentions the
  word. **Read this before adopting it: the failure direction is the opposite
  of every other rule type.** Text the decomposer cannot decompose MATCHES, so
  a facet rule refuses rather than permits what it could not read — an attacker
  who can make a statement unparseable would otherwise have found the bypass.
  The decomposition is stdlib-only and lexical rather than a full grammar (this
  package ships no runtime dependencies), and is explicit about what it does
  not handle: subquery scopes, CTEs, dialect syntax, precedence. Bounded at 8
  KiB and 2,048 tokens, beyond which it reports unparseable. BREAKING only in
  that the new reason code `PROTOCOL_FACET_MATCHED` is an addition to a closed
  enum; nothing existing changes meaning. Pinned by
  `conformance/fixtures/protocol_facets.json`. **Migration:** nothing is
  required to keep working — no existing rule changes behavior, and the new
  type only applies to rules that ask for it. If you exhaustively switch over
  the rule-type union or the reason-code registry in TypeScript, add a
  `protocol_facet` / `PROTOCOL_FACET_MATCHED` case; a JavaScript or Python
  consumer needs no change.
  ([`13b71dc`](https://github.com/obsvr-dev/obsvr-sdk/commit/13b71dc))
- **BREAKING: rot13 is decoded before the scanners run.** With `deobfuscation`
  enabled, a `rot13` view is now derived from any text carrying at least eight
  ASCII letters, so an injection payload the scanners already recognise no
  longer walks past them rotated. The view is derived last and outside the
  decoded-candidate cap, so it displaces nothing and never changes an existing
  detection's `via` attribution. BREAKING only in that `"rot13"` is an addition
  to the closed `via` / `CanaryVia` value sets, which breaks an exhaustive
  switch over them. **Note the cost, which is deliberate:** rot13 is applied
  speculatively rather than gated on the text looking encoded, because deciding
  that first would be a heuristic in front of a deterministic decision path — so
  every scanned text pays one extra linear pass. Character substitution (leet)
  is deliberately not decoded; the reasoning is in the deobfuscation module in
  both SDKs. **Migration:** nothing is required unless you exhaustively switch
  over `via` or `CanaryVia` in TypeScript, where a `"rot13"` case must be
  added. Detections that already fired keep their existing `via` attribution
  unchanged; a JavaScript or Python consumer needs no change. To opt out of the
  extra pass, disable `deobfuscation` — there is no rot13-specific switch,
  because a per-transform opt-out is a bypass an attacker can aim for.
  ([`f5a5583`](https://github.com/obsvr-dev/obsvr-sdk/commit/f5a5583))
- **Layered call cost (`costPolicy` / `cost_policy`), off by default.** Three
  layers, each overriding the one before and all three retained on the record:
  what the caller said a call would cost (`metadata.cost_estimate_micros`),
  what you declare it costs, and the metered figure from provider-reported
  usage at your own rates. The signed gap between the estimate and the metered
  value rides `metadata.obsvr_cost`, because an estimator that is persistently
  an order of magnitude out is only visible if both numbers survive. **No
  provider price list ships in this package** — prices change on the vendor's
  schedule and a stale rate baked into a release seals a wrong number, which
  cannot be reissued — so rates are yours to declare. Every amount is an
  integer count of millionths of a currency unit with a half-up rounding rule
  written out in both languages, because money in binary floating point does
  not agree between two runtimes at the edges. With no cost policy configured,
  events are unchanged. Pinned by `conformance/fixtures/cost.json`.
  ([`34659b2`](https://github.com/obsvr-dev/obsvr-sdk/commit/34659b2))
- **CloudEvents v1.0 export.** `toCloudEvent` / `to_cloud_event` project an
  audit event onto a CloudEvents envelope, and `serializeCloudEvent` /
  `serialize_cloud_event` produce its canonical string form, byte-identical
  across both SDKs and pinned by `conformance/fixtures/cloudevents.json`. The
  envelope's dedup key `(source, id)` is mapped onto the audit chain
  coordinate `(sdk_session_id, seq_no)`, so a CNCF-ecosystem sink dedupes on
  the same identity the ledger does; an event that never entered the chain
  falls back to `request_id`. `datacontenttype` is `application/json`,
  `dataschema` is `urn:obsvr:schema:audit-event:1`, and two extension
  attributes (`obsvraction`, `obsvrenv`) let a sink route without opening the
  payload. Purely additive: nothing calls it unless you do, and the event is
  carried verbatim as `data`. The serializer refuses values the two runtimes
  cannot render identically rather than emit bytes that quietly differ; use
  `safeSerializeCloudEvent` / `safe_serialize_cloud_event` to skip those.
  ([`d856c17`](https://github.com/obsvr-dev/obsvr-sdk/commit/d856c17))
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
- **Cross-SDK bookkeeping is validated data.** Every conformance case now
  carries per-language `sdk_support` (`required` / `optional` / `skip`) — 418
  entries across 25 of the 26 fixtures — so a gap shows as a recorded skip
  rather than a missing test. `claimable` is resolved on all 26 and enforced
  bidirectionally against the public docs. The known-divergences table became
  the schema-checked `conformance/known-divergences.json`, and the spec's seven
  uncovered EV statements are a checked partition in `eval_semantics.json`
  rather than a prose admission. **A support level is enforced, not
  decorative:** both suites reject a non-`required` level whose consuming
  harness does not read the field, so a `skip` nothing would act on fails the
  bookkeeping rather than surfacing later as a confusing case-level failure. If
  you consume the corpus, `required` is the level you can assume is exercised
  everywhere; `optional` today means only the two signed-policy vectors that
  need an Ed25519 backend Python resolves optionally.
  ([`2585ce0`](https://github.com/obsvr-dev/obsvr-sdk/commit/2585ce0),
  [`97d82dd`](https://github.com/obsvr-dev/obsvr-sdk/commit/97d82dd),
  [`c9c4040`](https://github.com/obsvr-dev/obsvr-sdk/commit/c9c4040),
  [`dd914c8`](https://github.com/obsvr-dev/obsvr-sdk/commit/dd914c8),
  [`aff2949`](https://github.com/obsvr-dev/obsvr-sdk/commit/aff2949),
  [`662d63e`](https://github.com/obsvr-dev/obsvr-sdk/commit/662d63e),
  [`f00e883`](https://github.com/obsvr-dev/obsvr-sdk/commit/f00e883))
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
  block: tamper cases with the verdict both verifiers must produce. It landed
  with thirteen and now holds twenty, the chain-format change above having
  added the format-1, format-2, and mixed-chain cases. Consumers of the
  existing `events` and key material are unaffected.
  ([`9c479d5`](https://github.com/obsvr-dev/obsvr-sdk/commit/9c479d5),
  [`763b5ef`](https://github.com/obsvr-dev/obsvr-sdk/commit/763b5ef))
- `conformance/fixtures/eval_semantics.json` gained dedicated cases for EV-3,
  EV-14, and EV-22 — statements `conformance/SPEC-evaluation.md` listed as
  covered but which no fixture actually pinned — shrinking the uncovered list
  from nine to seven. Cases now declare a `mode`: `rules` (the default),
  `pipeline`, or `explain`. Semantics are unchanged; this pins behavior that
  was already specified.
  ([`4d1c423`](https://github.com/obsvr-dev/obsvr-sdk/commit/4d1c423))
- **The conformance corpus hash changed — re-pin if you pinned it.**
  `conformance/MANIFEST.sha256` moved from `corpus_sha256 = 1120116f…` to
  `8c48c249…`, and both `conformance.pin` files with it. What moved is
  bookkeeping and prose only: the per-case `sdk_support` and per-fixture
  `claimable` keys described under Added, one divergence entry's `tracking`
  text, and one fixture's `description`. **No vector, digest, canonical form,
  or expected value changed** — with those two keys stripped, the only
  remaining differences anywhere in the corpus are those two prose fields, so
  your expected values are unmoved and only the pin needs updating.
  ([`c9c4040`](https://github.com/obsvr-dev/obsvr-sdk/commit/c9c4040),
  [`dd914c8`](https://github.com/obsvr-dev/obsvr-sdk/commit/dd914c8),
  [`f3947d9`](https://github.com/obsvr-dev/obsvr-sdk/commit/f3947d9),
  [`6767aa4`](https://github.com/obsvr-dev/obsvr-sdk/commit/6767aa4))
- **The published GitHub Action pins its own dependency to a commit.** Its
  `setup-node` step used a mutable tag, which every consumer's CI inherited
  with no way to see or override it. It is now pinned to a commit SHA with the
  version in a trailing comment.
  ([`030dc8c`](https://github.com/obsvr-dev/obsvr-sdk/commit/030dc8c))

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
