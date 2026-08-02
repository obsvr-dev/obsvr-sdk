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

- **Haystack: two limits of the tool gate are now measured and stated rather
  than left to be inferred.** Neither is a behaviour change and neither is
  fixable from obsvr's side; both are asserted as PRESENT by live legs so they
  cannot decay into a silent pass. **A serialization round-trip keeps the hook
  and drops a governed tool:** an Agent saved with `to_dict` and rebuilt with
  `from_dict` comes back with the `before_tool` hook and still refuses at zero
  executions, against a control reload with no mechanism that runs the denied
  tool and returns its payload — while a `govern_tool`-wrapped tool reloads
  successfully and ungoverned, because serialization records the tool's own
  `function` and the governor sits on `invoke`. The cycle does not raise, which
  is what makes it worth stating. **And a `ComponentTool` keeps the component it
  wraps as a live attribute:** a denied `ComponentTool` runs zero times through
  the Agent, and the same component invoked directly off the tool — or added to
  a Pipeline of its own — runs once and returns its payload, with nothing
  claiming to have blocked either route. That is the object-scope limit every
  tool gate in this SDK has; it is stated for this surface because a component
  is an unusually easy second reference to hold.
  ([`874bc28`](https://github.com/obsvr-dev/obsvr-sdk/commit/874bc28))
- **The LlamaIndex extra now declares the current major, measured at both ends:
  `llama-index-core>=0.14.5,<0.15.0` (was `>=0.11.23`, uncapped).** The old
  range spanned the 0.13.0 release where the framework stopped dispatching tool
  events altogether, claiming versions on both sides of a behaviour change
  nothing had measured. **Raising a floor withdraws no working version — it ends
  a claim that was never measured.** The floor is 0.14.5 rather than 0.14.0
  because that is the oldest release the gate can be DRIVEN on: the seam is
  present at 0.14.0, but no current provider adapter pairs with it
  (`llama-index-llms-openai` from 0.6.5 up requires core `>=0.14.5`, and 0.6.0
  imports a type core does not define until 0.14.4), and a core with no LLM
  adapter cannot run an agent. Both ends are driven live. One release inside the
  range is worth knowing about if you version-gate anything yourself: core
  0.14.0 ships `llama_index.core.__version__ == "0.13.6"`. obsvr reads no
  version string on this surface — every capability is probed by attribute
  presence.

- **The MCP and PydanticAI extras now declare the current major, measured at
  both ends: `mcp>=2.0.0,<3.0.0` (was `>=1.0.0,<2.0.0`) and
  `pydantic-ai-slim>=2.0.0,<3.0.0` (was `>=0.4.4`, uncapped).** The `mcp` cap
  existed because protocol major 2 renamed the descriptor fields the
  integration reads; those reads now resolve both spellings, so the range moves
  onto the current major rather than around it. The PydanticAI specifier had a
  floor at the release that first ships `WrapperToolset` and no ceiling at all,
  claiming two majors nothing had ever run against. **Raising a floor withdraws
  no working version — it ends a claim that was never measured.** Both ranges
  are now driven end to end: MCP over real JSON-RPC against a real server on
  both protocol majors, every client route into `tools/call` at zero executions
  for a denied tool; PydanticAI at `2.0.0` and `2.22.0` per tool-registration
  style, with the latest additionally driven against a real provider whose
  model chose to call the denied tool. **Not marked BREAKING:** the package has
  not shipped a release, so nothing depended on the wider claim. The `dev`
  extra tracks the `mcp` extra as before, so the SDK's own MCP test now
  resolves its server class and session helper by capability rather than by the
  names one major used.
  ([`7b9a967`](https://github.com/obsvr-dev/obsvr-sdk/commit/7b9a967))
- **The openai-agents extra's range is now a measurement:
  `openai-agents>=0.19.0,<1.0.0` (was `>=0.0.2`, uncapped).** Every release
  from 0.4.0 through 0.18.0 fails to construct its own `Usage` container
  under the current `openai` client — `Runner.run` dies before any tool is
  reached — so 0.19.0 is the oldest release that completes a live run at all,
  measured per release rather than asserted. The tool gate is live-proven at
  0.19.0 and 0.19.2. A version the gate never ran on was never supported,
  only claimed; this narrows the claim to what the runs stand behind and caps
  the untested next major. **Not marked BREAKING:** the package has not
  shipped a release, so nothing depended on the wider claim.
  ([`019cd7e`](https://github.com/obsvr-dev/obsvr-sdk/commit/019cd7e))
- **The CrewAI extra's range is now a measurement: `crewai>=1.0.0,<2.0.0`
  (was `>=0.30.0`, uncapped).** Nothing below 1.0.0 was ever driven, so
  nothing below 1.0.0 was ever supported — it was only claimed; this narrows
  the claim to the versions a per-release capability matrix and live
  boundary runs actually stand behind, and caps the untested next major.
  **Not marked BREAKING:** the package has not shipped a release, so nothing
  depended on the wider claim. The hook gate is a 1.15.3+ capability inside
  that range (adjacent tested pair; 1.8.0–1.15.2 accept hook registrations
  they never consult, which the installer detects and refuses loudly); the
  tool governor covers the whole range.
  ([`406da3e`](https://github.com/obsvr-dev/obsvr-sdk/commit/406da3e))
- **The conformance corpus hash changed — re-pin if you pinned it.**
  `conformance/MANIFEST.sha256` moved from `corpus_sha256 = be5d1238…` to
  `fdb4579d…`, and both `conformance.pin` files with it. No fixture content,
  case, verdict or divergence entry changed: the two `known-divergences` files
  carried a provenance sentence citing a repository path that is no longer part
  of this repository, and that sentence now describes the source without naming a
  file a reader cannot open. The corpus is still 36 files.

- **Decided: the LlamaIndex integration is observability-only and will not get a
  tool gate.** It was previously described as having none, which reads as pending
  work; it is now stated as a decision. `agent_policy` has no effect there,
  nothing is refused, and no policy event is emitted — so its events must not be
  read as evidence that a gate permitted a tool.

  The reason is the one the rest of this release documents: a callback handler
  fires *around* an operation, not at its boundary, so a check hung off one either
  arrives too late to prevent anything or is never delivered. Adding a gate that
  could not refuse would manufacture exactly the false record this release removes
  in three places. To refuse a LlamaIndex tool, put the capability behind MCP;
  TypeScript can also gate the tool itself with `obsvrGovernTool`, which Python
  has no equivalent of.
- **Both front doors now carry per-integration, per-language tool-policy
  grading.** It existed in exactly one of three READMEs, and that was the
  least-read of them: a reader arriving at the repository or at the npm package
  saw an unqualified, SDK-wide guarantee. The root README and the TypeScript
  README now each carry a table of which surfaces refuse a denied tool, which
  record only, which are not wired, and which are not on obsvr's boundary at all
  — with the two languages graded separately, because they disagree.

  The `destructiveTools` "even in flag mode" claim is qualified to the surfaces
  where it holds. It was true on MCP alone while reading as SDK-wide, which by
  this project's severity axis is a lie rather than an omission. The
  "intercept/govern **every** model and tool call" claims in the root README —
  including the architecture diagram's alt text, which is the version a screen
  reader gets — now describe the interception boundary instead of promising
  totality that a provider tool runner defeats.
- **The TypeScript LangChain integration enforces tool policy; the Python one
  does not.** Measured on both sides rather than assumed to match, and the two
  genuinely differ: the TypeScript handler implements a pre-execution
  `handleToolStart` that the Python handler has no equivalent of, and it sets
  `awaitHandlers` with `raiseError` so a refusal inside a callback aborts the
  tool instead of being logged and ignored. Verified live against a real
  LangGraph agent: a denied tool's own callback never ran, and the control with
  no policy shows the same model calling the same tool. The Python handler gates
  on `on_agent_action`, which current runtimes do not deliver, and has no
  `on_tool_start` at all — so it refuses nothing and emits no block event.

  Stated here because the per-integration grading in the READMEs is now
  per-integration **and per language**, and a reader who assumed the two halves
  behaved alike would be wrong in both directions.
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
  ([`9f164a2`](https://github.com/obsvr-dev/obsvr-sdk/commit/9f164a2),
  [`dc86ebb`](https://github.com/obsvr-dev/obsvr-sdk/commit/dc86ebb))
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
- **The Haystack component is stated as 2.x / 3.x, and its usage example now
  works on the version the extra installs.** The `haystack` extra declares
  `haystack-ai>=2.0.0` with no ceiling, so an install today resolves 3.x — and
  3.0 removed the text `OpenAIGenerator` the documented example imported, along
  with the `prompt` socket the documented wiring connected to. Following the
  example on a fresh install therefore raised `ImportError`. Both forms are now
  shown, and the guard component itself needed no change: it was already
  version-independent, which is why this was only ever a documentation defect.

  Behind the restatement is the first measurement this integration has ever
  had. It shipped credited with enforcement in both READMEs and had never been
  driven by anything but a shim — the in-repo test constructs the node without
  Haystack installed, so it could show that `run()` raises and could not show
  what a real `Pipeline` does with that raise. Driven out of tree against a real
  pipeline and a real generator at both ends of the declared range, graded on
  the bytes the provider received: a block reaches the provider zero times where
  the same pipeline allowed reaches it once, a redact puts scrubbed text on the
  wire where the same prompt under no policy puts the raw value there, and each
  case records one event whose verdict matches. The ASGI middleware was measured
  the same way, under a real server over a real socket. **Both claims survived**
  — the entries here are the evidence arriving, not a correction.
- **Wrapping a client no longer takes ownership of process termination.**
  `wrap()` installs `SIGTERM`/`SIGINT` handlers to flush the audit queue, and
  they called `process.exit()` unconditionally once the flush settled. Measured
  against a real host under a real signal: a service committing a transaction
  over 600ms was terminated **4ms** after the signal with nothing queued to
  flush, and with events pending against an unreachable ingest it was terminated
  at the 2s budget — so any drain longer than that died too. Draining
  connections, committing transactions and closing pools are exactly the work a
  `SIGTERM` handler exists to do, and wrapping a client is not consent to lose
  it.

  The exit is now taken **only when nothing else is listening for that signal**.
  That condition is the point: attaching a listener replaces the runtime's
  default disposition, so simply not exiting would swallow the signal and leave a
  process that ignores `SIGTERM` forever — a worse failure than exiting early.
  Ownership is resolved when the signal fires rather than when the handler
  registered, so a host that installs its shutdown after `wrap()` still keeps it.
  The trade is stated in both READMEs: a host that exits before the flush
  finishes drops the queue tail, which is the cheaper of the two losses.

  **Not marked BREAKING**, but read it if you relied on the old behaviour: a host
  with no shutdown of its own is unaffected and still exits 143 / 130, and a host
  with one now completes it. Nothing in this repository documented the old
  behaviour — no document mentioned signal handling at all, which is part of why
  it shipped.
- **A second `init()` now reaches clients wrapped before it (TypeScript).** The
  wrapper held the config object it was handed at wrap time, so an already-
  wrapped client stayed on the policy that was current when it was wrapped.
  Measured live in both directions: a client wrapped under a permissive policy
  reached the provider with the payload a later `init()` had declared blocked,
  and a client wrapped under a strict one kept refusing on a rule a later
  `init()` had removed — while a freshly wrapped client honoured the new policy
  in both cases. The asymmetry underneath is worth stating, because it made the
  pair look unrelated: `init()` REPLACES the resolved config while a
  `/policies` poll MUTATES it in place, so a captured reference saw every poll
  and no re-`init()`. The context now reads the config through, at every step of
  the proxy traversal — a caller holding `client.chat.completions` across a
  re-`init()` gets the new policy too. **Python was already correct here** and
  is now pinned so it stays that way.
- **A policy poll no longer deletes rules you declared in `init()`.** Both
  languages. A `200` from `/policies` replaced the whole rule set, so a response
  carrying `{"rules":[]}` erased locally declared `policyRules` **and** advanced
  the last-success timestamp — meaning `failMode: "closed"` never tripped, and a
  deployment was silently disarmed by a response its operator never sees. Wider
  than that, as the measurement showed: **any** successful poll erased them, not
  only an empty one.

  Rule precedence is now three tiers with three lifetimes. `policyFloor`
  survives everything, as it always has. Rules declared in `init()` survive a
  poll and are replaced only by another `init()`. The server's own set is the
  poll's to manage, and an empty ruleset is a valid server state that
  legitimately clears it. Local rules being deletable-by-poll was the odd one
  out — the floor already had its own field for exactly this reason — and a
  server rule carrying the id of a locally declared one does not take it over,
  because that is the same disarming edit wearing a matching id. Collisions are
  logged rather than absorbed. Verified live in both languages, with a dead
  `/policies` endpoint and a fail-closed staleness budget as the control that
  the repair did not disarm fail-closed.
- **The OpenAI Agents tracing processor now scans what its events store.** It
  ran **no policy pipeline of any kind** — not the PII scan, not rules, not the
  floor — so at any sample rate it wrote raw prompt and response text straight
  into signed events, while its three observe-only siblings on the same side
  have always stored a redacted copy. The canary half was already covered (that
  net lives in the event builder and fires on every path), so the gap was the
  PII half alone. It now runs the same observe-only net LangChain and LlamaIndex
  run, over the tool-span input and both halves of an LLM span.

  **This is not enforcement and the record does not pretend it is.** A
  `TracingProcessor` cannot refuse anything, and a span ends after its call has
  completed, so the verdict on these events is `redacted` — never `blocked`.
  `detect_only` deliberately leaves the record readable, because that mode
  exists to baseline what actually flows. Verified through a real agent run
  against a real provider, both directions, with `detect_only` and no-policy as
  the controls that make a clean record attributable to the policy rather than
  to an SDK that always redacts.
- **An approval whose expiry cannot be read as a date no longer authorizes
  anything, and no longer hides.** `Date.parse` returns NaN for a string it
  cannot read, and every comparison with NaN is false — so the gate's
  `Date.parse(expires_at) <= now` fell straight through and the grant matched
  forever, while the inspection API's mirrored `> now` was **also** false, so
  the same permanent grant was invisible in the listing. Live in the gate,
  absent from the audit: an operator reviewing grants saw nothing.

  Measured: `"never"`, `""`, `"forever"` and `"not-a-date"` each satisfied a
  claim at the current time and still satisfied it at the year 9999, and none of
  the four was listed. The `/policies` poll accepted them because its filter
  only required `expires_at` to be a **string**, so any response could mint a
  permanent grant on a human-in-the-loop rule — and with no `policyPublicKey`
  pinned, nothing authenticates that response. Unparseable now means expired, at
  the gate and at the door, and one predicate serves both the gate and the
  listing so they cannot disagree again.

  The module has always documented that approvals **always expire** and that
  there are no permanent grants. That was true of the intent and false of the
  code, so the code moved rather than the sentence.
- **The divergence catalog now names the two network attribution fields
  (`KD-9`).** TypeScript accepts `client_ip` and `user_agent` on a call, strips
  them from the provider request and writes them onto the audit event; Python
  has no capture path for either — no per-call keyword argument, no config
  default — and emits a hardcoded null. That was recorded only in a source
  comment, while `known-divergences.json` is read as the complete
  machine-readable inventory of accepted divergences, so a reader treating it
  as complete would not have found this one.

  It is a **capability** divergence, not a verdict one, which is what makes it
  eligible: the catalog's own policy invalidates an entry whose allowed
  difference would cover an enforcement-verdict difference — the reason the
  regex-dialect splits stay enumerated in `SECURITY.md` instead. Corpus re-pinned
  (36 files) with both `conformance.pin` files regenerated.

  Ids are allocated once and never reused, which `known-divergences.md` now
  says: `KD-7` and `KD-8` name divergences that were FIXED and are recorded in
  its History, so the next live entry is `KD-9`.
- **A policy block on a stream now reaches `.on('error')` callers.** The gate
  was never the problem: `governCall` throws before the provider is reached and
  the blocked event is recorded. But it throws inside the ready-box, so the real
  runner is never constructed — and the queued `.on()` registrations are
  replayed inside that box only *after* the runner is built, which a refusal
  never reaches. The registrations were discarded, `error` never fired, and an
  application using the event API observed a stream that produced nothing,
  forever.

  Measured live: with `.on('error')` registered on a policy-blocked stream, the
  callback did not fire in six seconds; it now fires in under thirty
  milliseconds, including when it is registered *after* the refusal has already
  happened. `for await` always saw the rejection, because that path awaits the
  box — it is the event surface that had nothing to await, and it still rejects,
  as the control asserts.

  Two things the delivery deliberately does not do: it does not throw when
  nobody is listening, because an unhandled `error` would turn a refusal the SDK
  handled correctly into a crash of the host process; and one listener throwing
  does not stop the next from being told.
- **The Vertex async method is awaited before its answer is governed.**
  `generate_content_async` is in the governed set, and the governed wrapper was
  a plain `def` — the module contained no `await` anywhere, which is how one
  function came to cover both a sync and an async provider method. The coroutine
  went straight to the response extractor, so the event recorded an empty
  response and null token counts, the response-side policy ran over `""` and
  never saw the answer, and the event claimed **success for a call that had not
  happened yet**; the caller then awaited the coroutine themselves and got an
  ungoverned answer.

  Pre-call enforcement always survived — a block is decided before the provider
  is called at all — so this was a record defect rather than an enforcement one.
  The awaited path now governs the resolved response, records the failure a
  coroutine raises only at await time (which the synchronous `try`/`except`
  could never see), and an async stream gets an async twin of the streaming
  accounting rather than a `for` loop an async iterator does not answer to.

  **NOT LIVE-VERIFIED, and the reason is the host rather than the fix.** Vertex
  needs GCP service-account credentials, which were not available; a Gemini API
  key authenticates a different product and would not exercise this path.
  Substituting a different SDK to manufacture a live run would have produced a
  verification that did not happen, so the evidence here is offline: six cases,
  of which four fail when the change is reverted and the two that survive are
  the controls — the sync path, which never broke, and pre-call enforcement,
  which must not change.
- **The zero-code interceptor no longer claims to govern every client in the
  process, because it does not.** The register module said *"Every client
  instance created anywhere in the process is then governed"*, and both READMEs
  said the same in their own words. Three things escape, each reproduced live
  against a real provider with a governed control in the same run:

  - a `require()` entry point — `module.register()` hooks do not intercept
    CommonJS at all, so interception never activates
  - subpath imports — the specifier table is exact-match, so `openai/index.mjs`,
    `openai/index`, `openai/client`, `openai/client.mjs`, `openai/client.js` and
    `openai/azure` all reach the untouched module
  - other client classes on a governed package — the shim overrides `default`
    and `OpenAI`, while `AzureOpenAI` and `BedrockOpenAI` ride the `export *`
    through

  **No behaviour changed and none of these puts a false record in the trail**:
  an escaped client emits no event rather than a wrong one, which is a coverage
  gap rather than a lie, and `obsvr.wrap(client)` governs every one of them
  including a CommonJS caller's. What changed is that the three are now written
  where the feature is advertised instead of being discoverable only by
  measuring. The CommonJS row is structural; the other two are open gaps, and
  closing them means widening the interception path across the whole declared
  version range of each provider package rather than editing a table.
- **Resolved-model provenance is now catalogued as `KD-10`, and a second claimed
  divergence was measured and found already closed.** An internal remediation
  inventory carried two adjacent capability gaps as prose rows in a still-open
  table.
  Both were driven against one server rather than transcribed, and they split.

  `model_resolved` / `provenance_source` **reproduces**: with a provider
  answering under an identifier different from the one requested, TypeScript
  records the served identifier and how it learned it, while the Python event
  builder has no parameter for either, so no Python surface can carry them. It
  is a capability divergence and not a verdict one — the model the caller
  requested is captured identically on both sides and is what every rule
  evaluates — which is what makes it eligible for that catalog at all.

  Python provider detection was **already fixed** and the row was stale. It now
  records the same attribution as its twin on every scenario, distinguishing a
  loopback server from a vendor host from an unrecognised gateway, each with the
  endpoint beside it. The claim was true when written and was made false by the
  provider-label repair, which moved both SDKs rather than one. The row is gone
  and the reason is recorded, because the correction runs the safe direction —
  the document was understating the code, which is the kind of stale claim
  nobody is harmed by and therefore nobody checks.

  Corpus re-pinned, 36 files, both `conformance.pin` files regenerated and
  agreeing.
- **The TypeScript package being ESM-only is now stated where installation is
  documented, in all three places a reader arrives.** `"type": "module"` with
  only `import` export conditions, so `require("@obsvr/sdk")` fails and a
  CommonJS service cannot consume the package at any version. Nothing in the
  repository said so — not the root README, not the TypeScript README, not
  `COMPATIBILITY.md` — so the first sign of it was a runtime failure after
  install.

  The disclosure covers the part that a CommonJS build would **not** fix: the
  zero-code `--import` path does not intercept `require()` at all, because
  `module.register()` hooks do not. Measured with a control — under `--import`
  with an ESM entrypoint the policy-violating call is refused and one event is
  written; from a `require()` entrypoint the same call reaches the provider,
  nothing is recorded, and `interception_active` reads false. `obsvr.wrap()` and
  the named compatibility wrappers are unaffected, and that is said too, because
  "ESM-only" alone would over-state the loss.

  **Dual-publishing is scoped as future work with the reason named**, rather
  than left as an implied someday. A dual build invites the dual-package hazard,
  and this SDK holds the audit chain in module-level state — session id,
  sequence number and previous signature are all bindings in one module — so two
  resolved copies in one process means two session ids and two sequence
  counters writing one claimed session, which the ingest service classifies as a
  `sequence_fork`. Shipping that would trade a documented limitation for a
  corrupted record, so the prerequisite is moving chain state out of module
  scope, not adding a build target.
- **The unmetered-by-default posture for integration events is now stated where
  metering is documented.** `meterIntegrationEvents` / `meter_integration_events`
  default to false, so framework-integration events carry no cost fragment and
  never increment a token-unit quota. That is a **decision, not a defect**, and
  the reasoning existed only in a TypeScript config docstring: turning it on is
  not a neutral correction, because a token budget that has never bound on
  framework traffic begins binding and calls that previously succeeded start
  being refused — an outage rather than a fix for anyone already running one. It
  now appears in the root README's cost section and in both SDK READMEs, which
  mentioned it only inside a per-integration table or not at all.
- **`GET /v2/quota/:scope/:value` no longer allocates a counter.**
  `getQuotaStatus` called the same `getOrCreate` the enforcement path uses,
  which INSERTS — and the governance server exposes it as a read with the scope
  value supplied by the caller. Measured against the real server over a real
  socket: **12,000 GET requests took the store from 1 entry to its 10,000-scope
  bound and saturated it**, after which a scope that metered before the sweep
  did not meter after. Under the default `failMode: "open"` those calls then
  proceed with no quota enforcement at all.

  Worse than "new scopes stop being metered", which is how it reads from the
  code: a scope incremented twice *during* the saturation reported `used: 0`,
  because those increments could not get a slot either. An actively-used scope
  reported no usage.

  The store's refuse-rather-than-evict policy is right — evicting a live counter
  hands anyone who can mint scope values a free quota — and a read endpoint that
  allocates inverted the reasoning it was designed around. The read is now a
  lookup: a scope with no live window gets the same fresh-window answer as
  before, minus the slot, and the control is that a live scope's real
  consumption is still reported exactly.

### Added

- **`install_tool_gate_hook` — Haystack refuses a denied tool before its Agent
  dispatches the batch.** Haystack ships a `Tool` abstraction and an `Agent`,
  and obsvr governed neither: its component gates the prompt flowing through a
  pipeline, and nothing looked at tool calls at all, so a policy naming a
  denied tool refused nothing on this framework. The installer registers
  obsvr's gate as the Agent's own `before_tool` hook, which the Agent runs
  before it resolves the pending tool calls and before it builds the executor
  that dispatches them in parallel — so a refusal removes the denied call and
  leaves its siblings pending, with no sibling already in flight to race.
  Measured with a denied call and a benign one in a single reply: the denied
  tool executes zero times, the benign one once. The gate rules on the CALL
  rather than on a tool object, which is what makes it total here — tools
  handed to `run(tools=...)`, tools inside a `Toolset` that respawns per run,
  and tools rebuilt by a serialization round-trip all still arrive as a named
  call in the Agent's own state. Refusal answers the model and the run
  continues; `on_denial="abort"` raises instead, and `govern_tool` remains the
  second mechanism carrying the full pre-call net. Driven live at
  `haystack-ai` 3.0.0 through `Agent.run` and `Agent.run_async`, with the
  payload asserted absent from what the caller received; the `before_tool`
  hook point does not exist at 2.0.0, where the installer feature-detects the
  dispatch half and refuses loudly rather than arming a gate nothing would
  consult.
  ([`f0de20c`](https://github.com/obsvr-dev/obsvr-sdk/commit/f0de20c))

- **`is_obsvr_block(exc)` — recognising a Haystack refusal after the pipeline
  has rewrapped it.** At haystack-ai 3.x a component's exception reaches the
  caller of `pipeline.run()` as the host's `PipelineRuntimeError` with the
  original demoted to `__cause__`, and an async pipeline wraps a second time,
  so `except ObsvrHaystackBlocked` around `pipeline.run()` catches nothing.
  The refusal is still there and the run still stopped; only the type at the
  top changed. The helper walks the cause chain so one branch covers both that
  shape and the unwrapped error an Agent raises directly.
  ([`f0de20c`](https://github.com/obsvr-dev/obsvr-sdk/commit/f0de20c))
- **`govern_agent` — LlamaIndex refuses a denied tool before it runs (Python).**
  This surface carried no tool gate of any kind, and the documented reason was
  wrong: it said a callback is the wrong place for a gate, when the operative
  fact is that no tool callback is dispatched here at all —
  `CBEventType.FUNCTION_CALL` has zero dispatch sites at any current version,
  and the instrumentation dispatcher that replaced those events swallows every
  handler exception, so nothing raised from one reaches the run. The gate
  therefore lives on the tools. `govern_agent(agent)` binds to `get_tools`,
  where a workflow agent assembles the tools for a turn, and governs each
  through `govern_tool` with the full pre-call net. Binding at ASSEMBLY rather
  than to the caller's list is what makes it complete: measured live with the
  tool denied, a tool supplied per turn by a `tool_retriever` and a tool whose
  governed copy was discarded while the agent kept the original both RAN under
  a hand-applied wrapper and are refused here. Driven live at llama-index-core
  0.14.5 and 0.14.23 on the plain, ReAct, tool-retriever and
  multi-agent-handoff routes: zero side-effect writes on every deny leg, the
  payload absent from the `ToolCallResult` the caller received, paired allow
  controls at exactly one. The framework converts the refusal into an error
  tool result rather than raising, so the run continues and the signed record
  is what reports the refusal — below core 0.14.8 it is the only thing that
  can, because `ToolOutput` carries no exception there and a refusal is
  indistinguishable from a crash to the caller. Two routes are out of scope and
  say so: `CodeActAgent`'s generated code, and tools invoked outside an agent.

- **`install_tool_gate()` — AutoGen refuses a denied tool on the routes that
  never send a message (Python).** The existing send hook enforces and keeps
  doing so, but it governs the outgoing MESSAGE, and
  `_process_message_before_send` has exactly two call sites in the framework.
  Measured live with the hook installed, three public routes reached the tool
  without either — a tool-call dict handed to `generate_reply`, to `receive`,
  or to `execute_function` — and two of them returned the tool's payload to the
  caller. So does an agent the caller never constructs: `run()` builds a hidden
  executor holding every callable and no hooks, and group and swarm chats build
  their own. The new gate wraps `ConversableAgent.execute_function` /
  `a_execute_function` on the class, which is the only scope that reaches those
  internal executors, and governs the `_function_map` entry the call is about
  to run — read fresh at call time at every version in the supported range.
  Refusal is the framework's own failed-tool contract: the raise happens inside
  the callable, `execute_function` reports `is_exec_success=False`, and the
  conversation continues, where the send hook instead stops the chat. Driven
  live at ag2 0.3.2 and 0.9.9, zero side-effect writes on every deny leg with
  paired allow controls at one. `RealtimeAgent` (a separate tool registry no
  executor reads) and code-execution replies (code from message content, not a
  `tool_calls` array) are out of scope and say so.

- **`attach_tool_gate` / `attachToolGate` — OpenAI Agents now refuses a denied
  tool before it runs, in both languages.** The framework consults each
  function tool's own input guardrails BEFORE invoking it, and the new
  installer puts obsvr's guardrail there, walking every function tool
  reachable from an agent (handoff targets included, by tool object). A
  denied tool is refused by the guardrail contract's returned sentinel
  (`reject_content` / `rejectContent`) — the model receives the block message
  as the tool's result, the run continues, and the `blocked`/`TOOL_DENIED`
  record is true at the point it is written. The tool governor
  (`govern_tool` / `obsvrGovernTool`) is the second, independent mechanism on
  this surface with the opposite run semantics: its refusal raises out of the
  tool's own callable, which the framework converts to a run abort
  (`UserError` in Python, `ToolCallError` in TypeScript) carrying obsvr's
  typed denial. Both mechanisms driven live with a side-effect-counting tool
  and the payload asserted absent from what the caller received — Python at
  openai-agents 0.19.0 and 0.19.2 on the plain, streamed and handoff routes;
  TypeScript at @openai/agents 0.13.0, 0.13.4 and 0.14.2 on the plain and
  streamed routes — with paired allow controls at exactly one write and the
  two mechanisms reddening independently under mutation. Installation
  feature-detects the framework's guardrail surface by attribute presence and
  refuses loudly where no executor would consult it; the tracing processor
  defers to any gate governing a name instead of stamping `not_evaluated`
  beside the gate's own verdict.
  ([`9e1d085`](https://github.com/obsvr-dev/obsvr-sdk/commit/9e1d085),
  [`f84d838`](https://github.com/obsvr-dev/obsvr-sdk/commit/f84d838),
  [`703e3d2`](https://github.com/obsvr-dev/obsvr-sdk/commit/703e3d2))
- **`govern_tool` / `govern_tools` — framework-agnostic tool governance,
  the Python twin of `obsvrGovernTool`.** Wraps a tool object's own execute
  callable (resolved across `on_invoke_tool`, `_run`/`_arun` with `func`
  co-gated, `execute`, `call`/`acall`, `invoke`/`ainvoke`, `run`/`arun`, and
  bare callables; sync and async as a pair, one verdict and one audit event
  per invocation) so a denied tool raises the typed `ObsvrPolicyError` before
  its body runs on any framework, whatever hook APIs it has or lacks. The
  gated call runs the FULL pre-call pipeline — rules, floor, PII, canary,
  session-taint destructive gate — and every event carries the sealed
  tool-content digest. Exported from the package root, matching the
  TypeScript entry point. CrewAI dispatch driven live on both executor paths
  and measured per version across the supported range; the other frameworks'
  shapes are pinned offline.
  ([`46946c4`](https://github.com/obsvr-dev/obsvr-sdk/commit/46946c4))
- **The MCP tool gate is now driven against the real `mcp` package in CI, in
  both languages — and every other integration test is labelled as what it is.**
  This is a decision about which asymmetry to keep, so both halves are stated.

  No integration test in either language had ever run against a real upstream
  framework. They drive hand-written fakes, which pin this SDK's own logic and
  its assumptions about a shape, but cannot see an upstream release that renames
  the method being wrapped or stops delivering a callback. Every finding of that
  kind in this project's history came from a live probe, never from the suites.

  `mcp` is now the one exception, because `SECURITY.md` names that gate as the
  surface to put a destructive capability behind. A real client, a real server
  and the package's own in-memory transport, with the refusal graded on whether
  the SERVER executed the tool body rather than on the caller's exception.
  Python gains `mcp` in its `dev` extra at the same specifier the `mcp` extra
  already declares; TypeScript needed no new dependency at all — the package was
  already a devDependency that no test imported. Runtime dependencies stay at
  zero in both packages, and the blocking dependency audit is unaffected: it
  covers declared runtime dependencies, and the audit that sees test
  dependencies is report-only.

  **What prompted it, measured rather than argued.** With the real deny check
  replaced by "allow everything", `sdk-typescript/tests/unit/mcp-integration.test.ts`
  still passes 18 of 18 — it carries its own copy of the policy check, annotated
  *"mirrors mcp.ts logic"*, and drives the copy instead of the module. Across
  that whole suite only three pre-existing tests notice; in Python, six do. The
  new files add four and three more.

  The rest of the asymmetry is not being closed, and `tests/README.md` in each
  SDK now says so plainly: which upstream packages are real in CI, which
  surfaces are fakes, and what a green run on a faked surface does and does not
  establish. A reader who assumed the integration suites exercised the
  frameworks they name was previously left to discover otherwise.
- **The severity axis is now stated where the limitations are.** A reader could
  see a handful of itemised defects disclosed in `SECURITY.md` without the rule
  that decides which of them would block a release at all. The README's
  known-limitations section now leads with it: a record asserting an enforcement
  that did not happen blocks a release, while a control that does not fire and
  emits nothing gets documented and ships. A documented non-enforcing gate is
  honest; a fabricated denial is not.
- **The enforcement-reporting invariant now covers TypeScript as well.** A table
  over the TypeScript tool gates, written against those implementations rather
  than translated from the Python results — which matters, because the two SDKs
  do not agree. Offline and deterministic, same as the Python half, and it went
  red on a real defect on its first run.
- **An invariant binding what the audit trail claims to what actually
  happened.** For every event where `action_taken == "blocked"`, the governed
  operation did not execute. Nothing in the tree asserted that, and two separate
  false-record defects reached `main` as a result — both found by hand against
  live providers, which is to say found once. The check is a table over all six
  Python surfaces that carry a tool gate: a spy tool records whether it was
  entered, each driver models the framework's real invocation ordering rather
  than a convenient one, and both halves are asserted — the tool did not run AND
  the record says so. Every row declares its grade, so a surface that quietly
  stops enforcing fails its row, and one that starts enforcing also fails and
  has to be regraded on purpose. Table coverage is itself a test: a new
  integration that ships a tool gate without a row fails the suite.

  Offline and deterministic by design — no provider, no key, no network — and
  wired into CI as its own named step. Its ability to fail is tested on every
  run rather than demonstrated once: one test points an enforcing gate at a
  no-op and requires the assertion to break, and two more require it to reject a
  fabricated denial and a silent refusal. Written before the fixes it prompted,
  and it went red on both of them first.
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
  | `@aws-sdk/client-bedrock-runtime` | `>=3.422.0` | `>=3.587.0` | `ConverseCommand` / `ConverseStreamCommand` — two of the four commands the integration dispatches on — are **absent at 3.422.0 and present at 3.1096.0** by introspection, and that is the whole of the evidence. **This floor is a position taken, not a located edge:** nothing between those two points was tested, so the real boundary is unknown across the 386 published releases that sit between them. It is stated at a release that exists — the line has gaps, and a floor naming a version the registry never carried would assert a boundary nobody could have tested ([`bc3970c`](https://github.com/obsvr-dev/obsvr-sdk/commit/bc3970c)) |
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
- **Python signed-policy VERIFIER.** `policy_verify.py` implements the same
  checks and refusal reasons TypeScript uses, against the same shared vectors.
  The backend is optional (`pip install "obsvr-sdk[crypto]"`); with a key pinned
  and none installed the policy is refused and the events say so.
  **This entry originally said `obsvr.init(policy_public_key=...)` pins a key
  and the SDK checks a fetched policy's signature. It did not: these two commits
  added the verifier and nothing called it.** See the Fixed entry below for when
  it was actually wired to the poll.
  ([`6783b26`](https://github.com/obsvr-dev/obsvr-sdk/commit/6783b26),
  [`9c479d5`](https://github.com/obsvr-dev/obsvr-sdk/commit/9c479d5))
- **Failure-disposition registry.** Every governance layer declares what it does
  in each failure state (timeout, error, degraded) in one table per language,
  pinned by `conformance/fixtures/fail_mode.json`. Descriptive when it landed:
  no call path read it and no behavior changed.
  ([`b1a33dd`](https://github.com/obsvr-dev/obsvr-sdk/commit/b1a33dd))

### Fixed

- **LangChain (TypeScript): one legacy-callback dispatch disarmed the tool gate
  for every later run on the same handler.** The Python twin of this was fixed
  earlier in this section; the TypeScript half was present and wider. Both
  pre-tool callbacks reach one gate and a runtime delivering both for one tool
  call has to be discounted, but the discount was a per-handler flag set the
  first time `handleAgentAction` fired and read forever after — and `copy()`
  returns the same instance to every child callback manager, so the flag was
  not even per handler in practice. Driven against a real LangGraph agent with
  the shipped build: after one `handleAgentAction` dispatch through the
  framework's own callback manager, a denied tool EXECUTED and only the
  warm-up's refusal was recorded. The credit is now granted and spent per call,
  walking the chain ancestry the handler records, because a tool's immediate
  parent is the node that dispatched it rather than the run. Nothing in the
  shipped JavaScript agent stack dispatches the legacy callback any more —
  `langchain` 1.5.3 ships no `AgentExecutor` and its agents are graphs — which
  is why no published claim depended on this; the core callback manager still
  exposes the dispatch to any caller.
  ([`874bc28`](https://github.com/obsvr-dev/obsvr-sdk/commit/874bc28))

- **LangChain (Python): the per-run step budget allowed every call, on both
  runtimes.** `max_steps` counts tool calls per agent run, and the run it
  counted against was never created. The helper that recognised an agent chain
  read the `serialized` argument of `on_chain_start`, and neither runtime fills
  it in: the graph runtime passes a literal `None` at the graph root and at
  every node, and the classic executor passes `None` from its own
  `Chain.invoke`, with the identity carried in a separate `name` keyword. With
  no run state the budget saw a count of zero on every call and allowed all of
  them, `agent_run_id` was empty on every event, and loop detection and the
  output-topic check never ran either. Measured before the repair with a model
  asking for four calls under a budget of two: four executions and no
  step-limit record, on the graph runtime AND the classic executor — the
  published claim named both. A run is now recognised from the `name` keyword
  and the graph metadata the framework does populate, and a tool call walks the
  chain ancestry this handler records to reach it, because a callback is handed
  only its immediate parent and under the graph runtimes that parent is the
  node that dispatched the tool rather than the run. Driven at `langchain-core`
  1.0.0 and 1.5.3 on both runtimes: a budget of two against three requested
  calls now stops at two, and the same run without a budget still goes the
  distance. The allow/deny tool gate was never affected and is unchanged.
  ([`1e459a6`](https://github.com/obsvr-dev/obsvr-sdk/commit/1e459a6))

- **LangChain (Python): one run on the classic executor disarmed the tool gate
  for every later run on the same handler.** The two runtimes deliver different
  pre-tool callbacks and the classic executor delivers BOTH for one tool call,
  so the second delivery has to be discounted or the tool is charged two steps
  and audited twice. That discount was a latch — set the first time the legacy
  callback arrived and read forever after — so every subsequent `on_tool_start`
  returned before reaching the gate, including every tool call of every later
  graph run, which deliver no other pre-tool callback. The credit is now
  granted and spent per call. Pinned by a test that drives a classic run and
  then a graph run on one handler, and by a live leg that does the same.
  ([`1e459a6`](https://github.com/obsvr-dev/obsvr-sdk/commit/1e459a6))

- **`govern_tool`: a framework spelling its async entry point `invoke_async`
  had that half ungoverned.** The exec-attr table paired `invoke` with
  `ainvoke` alone, so on Haystack the same governed tool refused under
  `Agent.run` and executed under `Agent.run_async`, returned its payload to the
  caller, and recorded no event at all. Resolution now also co-gates a small
  table of async aliases; it is additive, and a tool carrying none of them
  resolves to exactly the attributes it did before. Same lesson the `func`
  co-gate already carries: one logical entry point can have more than one
  spelling.
  ([`b36b355`](https://github.com/obsvr-dev/obsvr-sdk/commit/b36b355))

- **LangChain (Python): the tool gate no longer falls back to the RUN name.**
  The tool's own name arrives in `serialized["name"]`, which both dispatch
  sites fill in from the tool instance; the `name` keyword is the run name, and
  under the graph runtimes every tool in a graph arrives as `name="tools"`.
  Matching that against the policy would have compared the node's name and
  refused nothing, so it is no longer read. A call that carries no name at all
  now records `not_evaluated` with the reason instead of passing silently.
  ([`1e459a6`](https://github.com/obsvr-dev/obsvr-sdk/commit/1e459a6))
- **`govern_tool` raised out of the caller's program on a tool whose callable
  is exposed as a property (Python).** The gate installs by SHADOWING — an
  instance attribute that wins at lookup over the class one — and
  `object.__setattr__` honours data descriptors, so a property could never be
  shadowed however callable it looked. ag2's `autogen.tools.Tool` exposes its
  callable as `func`, a property with no setter, and the write raised
  `AttributeError` at the caller rather than degrading; a property WITH a setter
  was quieter and worse, accepting the write, running the setter and installing
  nothing. Such an attribute is no longer treated as an entry point, and a
  recognized tool whose entry points are all ungateable comes back exactly as it
  was passed — never converted into a bare function, and never entered in the
  governed-name registry, since the audit rails on other surfaces stand down for
  a registered name and would otherwise turn a coverage gap into their silence.
  Verified live: after the fix the tool registers on a real agent and its side
  effect still runs. Slots are unaffected and still gated (they are storage, not
  behaviour), and the install site now confirms the write reached lookup rather
  than trusting it, which is what catches a read-only C-level attribute such as
  `functools.partial.func` and a lookup-forwarding proxy.

- **`govern_tool` gated one half of a two-spelling entry point (Python).** The
  table paired `invoke` with `ainvoke` alone, so a framework spelling the async
  half `invoke_async` had one entry point governed and the other untouched:
  measured on a real agent, the same governed tool refused on the synchronous
  run and executed on the asynchronous one, returned its payload to the caller,
  and recorded nothing at all. Resolution now co-gates a small table of async
  aliases, which is additive — a tool carrying none of them resolves to exactly
  the attributes it did before.

  Both fixes ship with a sweep behind them rather than a third instance of the
  same surprise. Every supported framework's real tool object was resolved
  through the table and the result pinned per framework, so an addition that
  moved an existing shape onto a different entry point now fails a test instead
  of reaching a customer. Measured against the table as it previously stood, six
  of the eight tool shapes resolve identically and the only two that move are
  the two above.

- **MCP (Python): two client routes into `tools/call` reached a denied tool's
  body.** `ClientSession.call_tool` is a convenience over `send_request`, and
  the gate bound only to the convenience. Anything that built the frame itself
  went around it — including the package's own task API,
  `session.experimental.call_tool_as_task`, which sends a `CallToolRequest`
  and never touches `call_tool`. Measured against a real server over real
  JSON-RPC with the tool denied: both routes executed it, and the hand-built
  route additionally handed the caller the tool's payload. The gate now also
  binds at `send_request` and inspects the frame, so a `tools/call` runs the
  same sequence whichever route built it while every other request passes
  through untouched, and a reentrancy guard keeps the delegated call the gate
  itself issues from being judged twice. One route remains uncovered and is
  measured rather than described: a `ClientSessionGroup` handed the raw session
  from underneath an instance wrapper dispatches through that object, so
  `govern_mcp` never sees it and only the class-level `patch_mcp` reaches it.
  ([`2cc6910`](https://github.com/obsvr-dev/obsvr-sdk/commit/2cc6910))

- **MCP (Python): on protocol major 2 the descriptor controls read every field
  as absent.** `mcp` 2.0 moved the protocol types onto a snake_case base with
  `alias_generator=to_camel`, so `Tool.inputSchema`, `PaginatedResult.nextCursor`
  and `ToolAnnotations.destructiveHint` became `input_schema`, `next_cursor` and
  `destructive_hint` while the wire form stayed identical. A `getattr` for one
  spelling reads as absent against the other rather than raising, which is the
  quiet shape: the schema-surface poisoning scan finds no schema to scan, the
  descriptor pin hash commits to a document with the schema missing from it,
  and the destructive-capability gate finds no hint to gate on — three controls
  going silent while reporting success. One reader now resolves both spellings
  for every caller. Measured: with a directive placed only in a parameter's
  JSON Schema, a 2.0.0 server's poisoned tool is flagged and stripped from the
  listing the model is shown.
  ([`e27a33b`](https://github.com/obsvr-dev/obsvr-sdk/commit/e27a33b))

- **PydanticAI (Python): a tool registered with `@agent.tool` ran under a
  policy that denied it.** `ObsvrToolset` governs the toolset it wraps, and an
  agent's own function toolset — where `@agent.tool`, `@agent.tool_plain` and
  `Agent(tools=[...])` put their tools — is a SIBLING of it. A combined toolset
  dispatches each call to whichever sibling owns the tool, so the wrapper never
  saw those calls. Measured on a real agent graph with one policy and one tool
  name: refused through `Agent(toolsets=[ObsvrToolset(...)])`, and executed with
  its payload returned to the caller through `@agent.tool`. This was a coverage
  gap rather than a false record — nothing claimed to have refused the call that
  ran. `govern_agent(agent)` binds to the toolset the agent assembles for its
  tool manager, the one object every dispatch crosses, so the registration style
  stops deciding whether the policy applies.
  ([`044abcb`](https://github.com/obsvr-dev/obsvr-sdk/commit/044abcb))

- **PydanticAI (Python): audit events named no caller principal.** PydanticAI
  rebuilds an agent's toolset tree with `dataclasses.replace`, which
  reconstructs each node from its declared fields, and the `user_id` /
  `service_name` / `metadata` options `ObsvrToolset` held outside those fields
  did not survive: a rebuilt wrapper came back with its options at `{}`.
  Enforcement was never affected, which is why this went unnoticed — a denied
  tool was still refused, the record just stopped saying on whose behalf, and
  any user- or tenant-scoped quota rule metered the wrong bucket. The options
  are now a declared field and survive the rebuild.
  ([`f4726c3`](https://github.com/obsvr-dev/obsvr-sdk/commit/f4726c3))
- **OpenAI Agents (TypeScript): each function span is processed once, not once
  per hook delivery.** `onSpanStart` and `onSpanEnd` both fed `processSpan`,
  and the function and generation branches carried no end guard — so every
  tool call emitted two `tool.call` events and two policy verdicts, and the
  step counter was charged twice, tripping `maxSteps` at half its configured
  budget. The span payload for those branches is complete only at END, so
  that is now the one delivery they process; the agent span still derives
  `run.start` from its start delivery.
  ([`37ff9e8`](https://github.com/obsvr-dev/obsvr-sdk/commit/37ff9e8))

- **CrewAI (Python): a policy naming a tool the way CrewAI does refused
  nothing.** CrewAI sanitizes every tool name before dispatch — lowercased,
  camelCase split, non-alphanumerics to underscore — so the tool gate hook was
  asked about `delegate_work_to_coworker` while `denied_tools` held
  "Delegate work to coworker", the spelling CrewAI's own documentation, the
  agent's prompt and therefore the caller use. The strings were compared raw,
  so they matched nothing: the denied tool ran, and no event recorded that a
  policy had been consulted at all. Both sides are now normalized, so either
  spelling works. This was never delegation-specific — it affected any tool
  whose name was not already lowercase-with-underscores, `searchWeb` and
  `Search Web` included. Found live by denying CrewAI's auto-injected
  delegation tool by name and watching the marker file gain a line.
  ([`7d093d2`](https://github.com/obsvr-dev/obsvr-sdk/commit/7d093d2))

- **The tool governor (Python): a framework result-cache hit bypassed the gate
  and looked like a clean block.** `govern_tool` gates the tool's own
  callable, and a cache hit answers a repeat call from the framework's memory
  without entering it. So a tool executed while allowed and re-requested after
  the policy denied it returned the cached payload to the caller at ZERO new
  executions — zero being exactly the number a correct refusal produces, which
  is what made it invisible to a side-effect instrument. A governed tool now
  declines caching wherever the framework offers a say (`cache_function`), so
  the call reaches the callable every time and the gate rules every time.
  Measured on CrewAI through its own dispatch on both executor paths.
  CrewAI's hook gate was never affected: it is consulted after the cache read
  and its refusal replaces the cached result.
  ([`a2dbbdf`](https://github.com/obsvr-dev/obsvr-sdk/commit/a2dbbdf))

- **CrewAI (Python): a denied tool now never runs, and where nothing can bind,
  the call records `not_evaluated` rather than a block.**

  CrewAI delivers the step callback only after the step it reports: on the
  ReAct text path (any model whose `supports_function_calling()` is False)
  the executor runs the tool and then hands over the `AgentAction`; on the
  native function-calling path the callback carries no tool name at all. The
  old gate hung there anyway — it emitted `action_taken: "blocked"` with
  `TOOL_DENIED` for calls that had already executed, and the bare
  `RuntimeError` it raised was retried by the executor (only its own
  `ToolExecutionFailedError` passes through), re-running the whole task.
  Measured live: one denied call's side effect written three times under the
  default `max_retry_limit` of 2.

  Enforcement moved AHEAD of execution, on two independent mechanisms —
  CrewAI's own `before_tool_call` hook via `install_tool_gate_hook()`
  (returned-sentinel refusal, both executor paths, feature-detected dispatch,
  loud refusal on builds that register hooks but never consult them) and the
  new tool governor (below). Driven live on both paths with a
  side-effect-counting tool: a denied tool writes ZERO marker lines under
  either mechanism, exactly one on every paired allow control, and the two
  mechanisms redden independently under mutation. With neither installed the
  step callback is an audit rail and says so: `not_evaluated` with the reason
  in `metadata.obsvr_telemetry.policy_not_evaluated`, no raise, no retry.

  The kickoff callbacks are corrected on the same contract-reading: current
  Crew takes `before_kickoff_callbacks` / `after_kickoff_callbacks` (plural,
  list-valued; the singular kwargs the docstrings showed are silently
  discarded by Crew's `extra="ignore"` config), and Crew assigns each
  callback's return over its inputs and result, so obsvr's callbacks now
  return what they receive instead of `None`.
  ([`403c4da`](https://github.com/obsvr-dev/obsvr-sdk/commit/403c4da))
- **Mixing camelCase and snake_case config keys silently dropped half a
  configuration. `init()` now warns and names every key it ignored.**

  `init()` decides the naming convention for the WHOLE object from one key —
  whether `apiKey` is present. So `api_key` beside `piiPolicy` took the
  snake_case path, `piiPolicy` was never read, and the PII policy did not
  exist. No error, no warning, and an audit event that was honest, because the
  SDK never saw a policy to enforce. The SSN went to the provider. The same held
  for `policyRules`, the Presidio URLs, and every other key the converter maps.

  The posture is **warn and continue**, in that order and for stated reasons.
  Rejecting would turn a stray field into an outage for a caller who meant no
  harm; accepting both spellings would hide the mistake and keep two conventions
  alive forever. The warning names the convention that was chosen, why it was
  chosen, every key that was dropped, and the spelling that would have been read
  — `piiPolicy -> pii_policy`, because "unrecognised key" is not something a
  caller can act on. A key belonging to neither convention gets its own warning,
  so a typo surfaces instead of vanishing.

  The converter and the warning now read one shared key table. Two
  hand-maintained lists would drift, and the failure mode of that drift is a
  silently dropped key — the very defect being fixed.

  **The other SDK never had this and needed no change**, which is worth stating
  rather than leaving as an apparent omission. Its `init()` declares explicit
  keyword-only parameters, so a wrong-style or misspelled key raises
  `TypeError` at the call and names the key that was meant — strictly louder
  than a warning. That immunity is a property of the signature rather than a
  decision anyone had written down, so it is now pinned by a test that fails if
  `init()` ever grows a `**kwargs` catch-all.
- **Outbound PII redaction rewrote the caller's own message objects, and a
  frozen message was refused rather than redacted.** Both halves came from one
  cause, in both SDKs.

  The argument filter builds a fresh TOP-LEVEL request object but copies its
  entries by reference, so the messages array and every message in it are still
  the caller's. Redaction then walked into them and assigned. A conversation
  history is normally an array the application keeps and appends to, so one
  redacted turn rewrote the application's own history and every later turn sent
  `[REDACTED_SSN]` where it believed it still held the real text. The top-level
  scalars — `system`, `instructions`, a string `input` — land on the new object
  and were always safe, which is why this survived: the function looked correct
  on exactly the fields most likely to be spot-checked. The Python side was
  worse on one shape, calling `setattr` on the caller's model instance and
  swallowing the failure, so the only objects it did not corrupt were the ones
  that refused to be corrupted.

  Redaction now rebuilds every container it modifies instead of writing through
  it. A message object is copied with the provider's own type preserved, because
  substituting a plain dict would be rejected by a client that validates its
  argument.

  **BEHAVIOUR CHANGE, stated because it moves a documented fail mode.** An
  unwritable caller message — frozen, or refusing assignment — used to make the
  redaction walk throw. That resolved CLOSED and refused the call. It now
  succeeds: the message is copied, redacted, and sent. The refusal was obsvr
  punishing a caller for protecting the very object obsvr was about to corrupt,
  and it was only ever reachable because the walk wrote to the caller in the
  first place.

  **The fail-closed rule itself is unchanged.** A redaction that genuinely
  cannot be carried out still blocks, still regardless of `failMode`, still
  records `blocked` with the `enforcement_application` phase and never claims a
  redaction that did not happen. `conformance/fixtures/fail_mode.json` needed no
  edit for the same reason — its `redaction_application_closed` qualifier
  describes the disposition, and only what counts as a failure moved. The
  end-to-end tests that used to reach that path through a frozen message now
  reach it through a redactor that raises, and the frozen message has become a
  test that the call SUCCEEDS and the caller's object is unchanged — a strictly
  stronger assertion than the one it replaced.
- **The evidence-verification Action failed a consumer's CI on exit `3` with no
  documented remedy — the gap-marker feature defeating its own tooling.** The
  SDK signs a gap marker at the position of any dropped events so a lossy run
  declares its own loss, and `obsvr-verify` reports that as *valid but
  incomplete*: exit `3`, distinct from both a pass and a broken chain. The
  Action's README documented `0`, `1` and `2` only, and its script carried a
  comment listing the same three, so a bundle whose chain is perfectly intact
  could turn a consumer's check red with nothing anywhere explaining why. The
  remedy existed as the CLI's `--allow-gaps` and was not reachable from the
  Action at all. Exit `3` is now documented, and an `allow-gaps` input exposes
  the flag. It defaults to `false`: a bundle missing events should stop a check
  that exists to establish what happened.
- **The Node version badge pointed at a path that no longer exists.** It read
  `main/sdk/package.json`; that directory was renamed to `sdk-typescript/`, so
  the badge had been resolving against a 404.
- **`sender.py`'s module docstring advertised a queue ten times smaller than the
  one it builds** — `queue.Queue(100)` against `MAX_QUEUE_SIZE = 1000`. Already
  disclosed in `BENCHMARKS.md` and still wrong at the source a reader of that
  module sees first.
- **The industry modules read as compliance packages and are not.** `healthcare`,
  `fintech` and `legal` are exported from the package root and their docstrings
  name HIPAA, so a reader arriving through the public exports can reasonably
  expect a ready ruleset. They are evaluators and primitives — a
  namespace-isolation predicate, a threshold comparator, a cross-tenant check —
  which decide nothing until composed into `policyRules`. The barrel now says
  so, and says that they are TypeScript-only so nothing built from them is
  portable to the other SDK. That export surface is the only place they are
  advertised: no public document mentions them at all.
- **The blocking benchmark-integrity CI job was red, on a memory check that was
  measuring warm-up.** `bench/run-all.sh --quick` exited 1 and aborted at step 2
  of 4. Nothing was corrupt: the chain verified, signatures matched, the
  cross-check agreed, every accounting invariant held and there were no errors.
  What failed was the leak assertion, `RSS(end) − RSS(25%)` against a 30 MB
  threshold.

  It was not a leak. `--quick` runs 5,000 calls, and on that runtime RSS is
  still climbing at the last sample, so the 25% baseline lands inside warm-up
  and the difference measures the climb. The same build measured **30.3 MB at
  5,000 calls and 21.8 MB at 25,000** — five times the work producing a smaller
  number, which is the opposite of what a leak does. Across the four tiers of a
  single run it read 29.9, 32.0, 28.2 and 29.3, straddling the threshold at
  random. The other SDK's harness uses the same 25% rule and reports 0.1–0.8 MB,
  because its RSS settles almost immediately.

  The number is still computed, still printed and still in the JSON at every
  size; it now only *fails* a run where the baseline can clear warm-up, and a
  short run prints an explicit note saying the value was reported and not
  asserted, so a skipped assertion cannot read as a passing one. Verified in
  both directions: with an impossible threshold the gate still fails a
  25,000-call run, and the correctness invariants are untouched.

  **Why it went unnoticed is the same shape as the drifted bench verifier.**
  `BENCHMARKS.md` publishes the full run, which is past warm-up and unaffected.
  `--quick` exists only for CI, so the one configuration nobody runs by hand was
  the one that broke.
- **The Python audit chain forked across `os.fork()`.** `_sdk_session_id` and
  `_seq_no` are module state, and `fork()` copies module state — so a
  pre-forking application server, which is the recommended deployment, gave
  every worker the same session id and a sequence continuing from wherever the
  parent had reached. N workers produced N divergent chains all claiming one
  session, each looking like a fork of the others. Ingest already detected that
  shape and named it `sequence_fork`: the detection existed and the prevention
  did not.
  There is now an `os.register_at_fork` handler, and it moves four things rather
  than the obvious two: a fresh session id; `seq_no`/`prev_sig` back to the start,
  because the child's first event heads a NEW chain; the sender queue replaced
  rather than inherited, since the child would otherwise re-send events the
  parent had signed but not delivered — a replay under the parent's session and
  sequence, not a rescue; and every lock rebuilt, because only the forking thread
  survives a fork and the sender runs a worker thread, so a lock held at that
  instant would be held forever in the child. The chain lock is also held across
  the fork itself so the head cannot be observed mid-advance.
  Verified by actually forking: before the change two children share the
  parent's session id, three `(session_id, seq_no)` pairs collide, and both
  children re-send the parent's queued events; after it every pair is unique,
  each child's chain verifies independently under the SDK's own verifier, and the
  parent's chain is unchanged. The sign-and-enqueue atomicity this rests on is
  deliberately untouched.

- **Blocked events skipped payload truncation, so enforcement evidence was the
  likeliest thing to be dropped.** The TypeScript wrapper builds three
  `AuditEvent` literals by hand; the allowed and streaming ones truncate to
  `max_payload_chars` and the blocked one had drifted, on two fields — `prompt`
  whenever the block reason is `pii_detected`, and `user_input` for **every**
  block reason. `MAX_QUEUE_SIZE` bounds the event COUNT and nothing bounds the
  bytes, so an oversized event is refused by ingest with a 4xx, which the sender
  classifies `permanent` and dead-letters rather than retrying. Measured through
  the real sender against a collector with a byte ceiling: a PII-blocked call
  carrying a 60 KB prompt produced a 121 KB batch, was refused, and was dropped;
  the same call now produces a 5 KB batch and is delivered. The allowed call
  with the same payload was delivered in both phases, which is what shows the
  cap was being applied and only the blocked literal had lost it. Python is
  unaffected: it has one `build_audit_event` that every path goes through, and
  truncation lives there.

- **SECURITY: the zero-code `load` hook served a shim for any specifier
  carrying `?obsvr-intercept`.** The parameter is part of a specifier, and the
  hook never checked that its own `resolve` had put it there — so an import
  written as `./app-module.mjs?obsvr-intercept=openai`, by application code or
  by any dependency that builds a specifier out of data, was answered with a
  generated module that re-exported the target's default binding behind obsvr's
  construct trap and added an `OpenAI` binding to it. That is module
  substitution over an application module, reachable by anyone who can write an
  import, and it is a security finding rather than the coverage gap it was
  first filed as. `resolve` now records the URLs it tags and `load` serves a
  shim only for those; anything else loads exactly as it would with the hook
  absent. An unrecognised provider id is also refused rather than falling
  through to a bare re-export, which would silently drop the module's default
  export. Reproduced in a real child process under `--import`: the substitution
  succeeds before the change and does not after, with the same module imported
  without the parameter and the real provider package still intercepted as
  controls in both phases — the second because the tempting way to close this
  hole is to stop serving shims at all.

- **Four audit fields were forwarded to the provider and recorded nowhere.**
  `user_id`, `client_ip`, `user_agent` and `service_name` are declared on the
  exported `AuditFields` type as customer-provided, and the TypeScript wrapper
  reads all four onto the event — but they were absent from the extraction set,
  which is the only thing that moves a key from the request to the audit side.
  So they were wrong in two directions at once: a caller who typed their
  arguments against the public type had the values passed **verbatim to the
  provider**, which rejects an unknown parameter, while the record they were
  meant to populate carried nothing. Measured against a server that logs the
  raw outbound body: pre-fix all four appear in the request the provider
  received and none appears on the captured event; post-fix that inverts, with
  the real provider parameter `user` reaching the provider in both phases as
  the control. Python is unaffected and diverges by design — its per-call
  channel is the namespaced `obsvr_metadata` kwarg, which is already stripped,
  and it has no capture path for `client_ip` or `user_agent` at all. That is now
  said in the event builder rather than left as two bare `None`s.

- **The ingest URL ran no SSRF guard and no scheme allowlist, in either SDK.**
  It is the URL the SDK POSTs to most — every prompt, every response, and the
  `X-API-Key` header — and it was validated for exactly one thing: whether a
  plaintext `http` URL pointed off-loopback. The Python validator's first
  statement after parsing was `if parts.scheme != "http": return`, so
  `file:///etc/passwd` was accepted, and the TypeScript half checked a
  `http://` prefix and nothing else. Neither ran an address check of any kind,
  so `https://[::169.254.169.254]/` — the cloud-metadata endpoint — was a valid
  audit destination in both. The plaintext spellings of that address *were*
  refused, but by the HTTPS requirement rather than by any address check;
  swapping the scheme to `https` let the same address through.

  Both SDKs now run the same static SSRF guard the external policy backend and
  the presidio endpoints already ran: the scheme must be `http(s)`, the
  cloud-metadata / link-local range is always refused in all four IPv6
  spellings and regardless of the `OBSVR_ALLOW_HTTP` opt-out (which relaxes the
  TLS posture only), and private/reserved literals are refused unless the host
  is loopback — so a local collector keeps working and `https://10.0.0.5:8443`
  does not. The guard is static, matching presidio: a hostname that *resolves*
  to a private or metadata address is not refused, because `init()` is
  synchronous in both languages and the resolving guard needs DNS. That limit
  is now stated in `SECURITY.md` rather than implied.

- **TypeScript accepted `http://localhost.evil.example.com` as a plaintext
  ingest URL.** The loopback exemption was `!url.includes("localhost") &&
  !url.includes("127.0.0.1")` over the whole URL string, so any host merely
  *containing* either token — or any URL with one in its path or query — was
  treated as local and allowed to ship prompts, responses and the API key in
  the clear. It now compares the parsed hostname, which is what the Python twin
  has always done. `SECURITY.md`'s claim that HTTPS is enforced for any
  non-localhost ingest URL was false in TypeScript until this change, and its
  claim that "every URL the SDK is told to POST to" is SSRF-guarded named two
  of the three; both sentences moved with the code.

- **The cloud-metadata address was refused in one IPv6 spelling out of four.**
  The SSRF guard folded IPv4-MAPPED IPv6 (`::ffff:a.b.c.d`) to its v4 address
  and nothing else, so three other forms that route to the same host went
  unrecognised: IPv4-COMPATIBLE (`::169.254.169.254`), NAT64
  (`64:ff9b::169.254.169.254`) and 6to4 (`2002:a9fe:a9fe::`). Measured against
  the real code paths, not the helper: `http://[::169.254.169.254]/` reached
  `fetch` through the external policy backend and was **accepted and stored
  verbatim** by `init()` as a Presidio analyzer URL — the endpoint that sees the
  most sensitive data — while the `::ffff:` spelling of the identical address
  was refused. Two comments asserting the address is "ALWAYS refused, no
  opt-out" were therefore true of one spelling of it. All four forms now fold,
  in both languages, with public addresses in every one of those spellings left
  alone as the control — "everything IPv6 is blocked" is a different bug and a
  worse one.

- **Comments that asserted more than the code delivers.** Four absolutes were
  settled by driving the code rather than reading it, and each is now narrowed
  to what is true, with the measurement in the comment: the Python sender's
  emission gate does **not** mirror TypeScript for allowed-but-flagged events
  (the TS gate keys on `action_taken` alone, so a `detect_only` PII finding is
  sampled out there and kept here); a per-event accept/reject "never costs the
  others" only inside an accepted 2xx batch, since a 4xx dead-letters the whole
  request; "the same bytes will always fail" is not true of auth-class 4xx,
  which are key state rather than a property of the bytes; and the multi-turn
  injection half-life bounds accumulation rather than preventing it — at the
  shipped defaults, benign phrasings that match one weak signal crossed the
  threshold at turn 3. The detector-guard header's response-phase absolute was
  also scoped: it holds for a control over the model's answer and not for the
  MCP tool-result gate, which is pre-delivery and therefore both raises and
  withholds, deliberately.

- **The two SDKs did not enforce the same policy, in three separate places.**
  All three are cross-language divergence, all three moved the conformance
  corpus, and they land together as one re-pin (35 files `a2e27106…` → 36 files
  `1bd939c2…`, both `conformance.pin` files in step).

  - **Unicode-version skew defeated the obfuscation defence in one language.**
    NFKC is not a stable cross-language primitive. Node folds through ICU,
    which tracks the current Unicode release; CPython ships a frozen
    `unicodedata` per minor version. ICU is therefore always ahead, and every
    Unicode release leaves a residue of codepoints one runtime folds to ASCII
    and the other does not. Measured across eight CPython builds against one
    Node: **41** such codepoints at the declared Python floor, **37** at
    3.12/3.13, **1** at 3.14 — narrowing but never zero. All of them fold on
    Node and none on Python, so a `keyword` rule blocking `SECRET` **blocked in
    TypeScript and ALLOWED in Python** when the payload was written in Unicode
    16 Outlined Latin. The residue is now in the curated confusable fold both
    SDKs already vendored for exactly this reason. Each entry is idempotent by
    construction — on a host whose NFKC already folds the codepoint the fold
    never sees it — so the two agree whatever Unicode version they ship, and a
    future CPython that gains the mapping changes nothing. Vendoring the whole
    of NFKC was considered and rejected: it would replace a version-tracking
    gap with a version-frozen table that drifts from both hosts.
  - **Customer `regex` rules diverged across 17 construct families.** A regex
    rule is authored once and run by two engines, so a construct only one
    engine accepts — or that both accept and read differently — enforces in one
    language and is inert in the other, with nothing on the record to say so.
    The validator now **rejects** the syntax-level split in both languages:
    Python-only named groups/backrefs, JS-only named groups/backrefs, inline
    flags, possessive quantifiers, atomic groups, variable-width lookbehind,
    `\A` `\Z` `\z` (anchors in Python, literal characters in JS), any other
    non-shared alphabetic escape, class-set operations, and `{,n}`. Rejection
    is the safe direction: it fires the existing `sdk:rule_rejected` signal and
    names the rule on the audit record, so a rule that stops enforcing is
    visible rather than silently one-sided. **The SEMANTIC splits are NOT
    closed** — `\d` `\w` `\s` `\b` are Unicode-aware in Python and
    ASCII-only in JS, `$` matches before a trailing newline in Python only, `.`
    matches U+000D and U+2028 in Python only — because rejecting them means
    banning the most common constructs in the language. They are enumerated
    construct by construct in `SECURITY.md`, and deliberately **not** in
    `known-divergences.json`, whose own policy forbids an entry covering an
    enforcement-verdict difference.
  - **An astral rule id produced two different `policy_version` values.** Rule
    ids are sorted before hashing, and Python sorted by code point where
    TypeScript sorted by UTF-16 code unit. The orders agree everywhere except
    an astral id meeting a BMP id in U+E000..U+FFFF, where JS sees the leading
    surrogate and sorts it first. `policy_version` is inside the chain preimage
    under chain format 3, so a wrong value is durably wrong. Both sorts now use
    the existing `_utf16_order` helper, which was present and wired only to
    object keys.

  **Why the corpus never caught any of them.** It held 44 `keyword` cases and
  exactly one `regex` case — `(a+)+$`, which both validators reject, so it
  asserted only that a rejected pattern never matches. Every rule id in it was
  ASCII, so both sort orders agreed on all of them. The corpus now carries the
  case that would have caught each: three host-version fold candidates, 23
  regex-dialect cases in both directions, and an astral rule id beside a
  private-use one — the only region where the two sort orders differ, so a pair
  chosen anywhere else would pass whatever the sort key is. A fixed-repetition
  ReDoS case belongs here too and is **not** added: it depends on the
  `repAt` validator gap, which is still open.

- **Documents credited two surfaces with governance they do not run.** Measured
  layer by layer and method by method, in both languages, driven rather than
  read off the code:

  - **The named compatibility wrappers govern one method.** `wrapAzureOpenAI`,
    `wrapTogether`, `wrapCloudflare` and `wrapOpenAICompatible` consult a
    one-entry path table. Counted against real `AzureOpenAI` and `Together`
    clients: `obsvr.wrap()` governs 17 paths on the same client and these
    govern 1. The other 26 text-bearing paths — `responses.*`, `.parse`,
    `.stream`, `runTools`, `completions.create`, the assistants surface — bind
    through with no gate and no event, however new the installed client is.
  - **LangChain and LlamaIndex run the observe-only path.** The PII scan and
    the stored redacted copy, and nothing else: no `policyRules`, no
    `policyFloor`, no `onPreCall` hook, no outbound redaction, no kill-switch
    gate, no response-side scan, no PII **blocking**, and metering only on
    opt-in. A `pii_policy` of `{ssn: "block"}` blocks through `obsvr.wrap()`,
    Bedrock, Vertex, Vercel AI and MCP and does not block through these — the
    call goes out and the event records the stored copy as redacted.

  Both are silences rather than false records: nothing claims a block that did
  not happen. What was false was the documentation, which listed both under
  "supported" beside surfaces that carry the whole pipeline. Every public
  document now states the scope — root README, TypeScript README, Python
  README, `COMPATIBILITY.md` (whose per-method table describes `obsvr.wrap()`,
  not these wrappers) and `SECURITY.md`'s bypass surface — and in both cases the
  repair for a reader is the same one sentence: **wrap with `obsvr.wrap()`
  instead; it accepts the same clients.**

  Pinned so the documents cannot drift back: a test drives the wrapper on the
  governed path and on four ungoverned ones, asserting BOTH halves — the
  provider was reached and nothing was recorded — with `obsvr.wrap()` on the
  same client and the same payload as the control that makes it a statement
  about the wrapper rather than about the client shape. It fails in both
  directions, so widening coverage is a deliberate regrade with a documentation
  change rather than a silent improvement nobody wrote down.

- **Python pinned a policy key and verified nothing.**
  `verify_policy_signature()` had **zero production call sites** — defined,
  correct, covered by the shared vectors, and never invoked. The poll assigned
  `config.policy_rules` straight from the response, and the pinned
  `policy_public_key` was stored and read by nothing. So anyone able to answer
  `/policies` could ship `enabled: false` on every rule to a deployment that
  believed it had pinned a key, and TypeScript — which has verified at that
  point all along — would have refused the same payload.

  The verifier now runs on the Python poll, over the RAW arrays as received and
  before anything is applied, failing closed exactly as TypeScript does: a
  tampered, forged, unsigned, key-mismatched or rolled-back policy is refused
  and the last-good policy stays in force, with one
  `sdk:policy_signature_invalid` event per distinct reason so a deployment
  running last-good rather than latest is visible on the record rather than
  only in a log.

  **Two documents disagreed about this and the CHANGELOG was the wrong one.**
  `README.md` said "TypeScript today", which was honest; the entry above
  announced the Python feature as shipped. Both now describe the same
  behaviour, and the entry above says what it originally got wrong rather than
  being quietly rewritten.

  The gap survived a full verifier test suite because a unit test of a verifier
  proves the verifier works and cannot prove anything reaches it. The new tests
  drive the poll against a fake `/policies` and assert on the rules **in force**
  afterwards, with an unpinned control showing the same payloads applying — so
  the refusals are attributable to the pin rather than to the fixtures.

- **`obsvr.wrap()` stored what it never scanned.** Policy decisions are made on
  the last user turn, deliberately, so a value quoted three turns ago does not
  block today's call. But the event stores the WHOLE concatenated prompt, and on
  the `wrap()` path nothing vetted the difference. Two consequences, one cause:

  - A honeytoken planted where `canary.ts` says to plant it — a system prompt —
    was stored **verbatim**, against that module's own "the raw secret never
    lives at rest, never rides an event". The integration front door redacted
    the same token correctly, so the two entry points the README sells as
    equivalent disagreed, and the flagship was the unsafe one.
  - Both READMEs promised non-last-turn content is "still stored (and redacted
    if configured)". Measured across `block` x `redact` x `flag` x four roles,
    no configuration redacted it. The "still stored" half was true.

  There is now one stored-content net, shared by both front doors and both
  languages. The canary half is unconditional. The PII half runs only over
  content the decision scan did not already cover, only when a detected type
  resolves to `block` or `redact`, and only on the stored copy — a
  `detect_only` policy still records the raw value, because baselining what
  actually flows is the only thing that mode produces. When it fires, the event
  carries `stored_redaction_types` and `stored_redaction_outbound_unmodified`,
  because a scrubbed prompt beside `action_taken: "allowed"` would otherwise
  read as an enforcement that did not happen. **Enforcement scope is
  unchanged:** the request still reaches the provider unmodified, and both
  READMEs now say so in those words.

  Two things the fix uncovered, both fixed here. The first pass closed
  `wrap()` and left `wrapOpenAICompatible()` open, which INVERTED the
  disagreement instead of ending it — caught by a live call, not by the unit
  tests, which were green at the time. And the reserved telemetry channel was
  ASSIGNED rather than merged in both languages, on a helper whose own comment
  said it never overwrites, so any evidence an earlier step had put there was
  discarded.

  The test that should have caught the canary half was vacuous and disguised:
  every plant used `role: "user"` — the one surface the gate already scans and
  the one surface the module's do-NOT-plant list names — while minting with the
  label `'system-prompt'`. Both languages now drive every endorsed plant site
  through both front doors, behind a shape guard that fails when a case is
  removed rather than only when one breaks.

  The redundant traversal shipped in the same change, because scanning more
  text multiplies it: the last user turn was re-walked from the raw request
  eight times per governed call and is now computed once, with explicit
  invalidation at each of the three sites that rewrite the request in place.

- **A user prompt could forge an audit-gap marker, and both verifiers believed
  it.** The verifiers parsed `prompt` for the gap-marker string on EVERY event
  they checked, with no discriminator. A prompt reading exactly
  `obsvr:audit-gap/1 dropped=999999 reason=queue_overflow` therefore produced a
  legitimately-signed event that verification reported as
  `{ valid: true, gapMarkers: 1, eventsDeclaredLost: 999999 }` — a user
  fabricating a million lost events, on a chain that reports valid, by typing a
  string. The reasoning that put the count in the signed content was right,
  because metadata is unsigned; it placed the governance claim in the one field a
  user fully controls and then trusted any event carrying it.

  All four verification sites (both chain verifiers, both `obsvr-verify` CLIs)
  now require the event to BE a marker — `operation` is `audit.gap`, which the
  senders stamp and no user-facing call path produces. `parseAuditGapPrompt` /
  `parse_audit_gap_prompt` are unchanged and still read a claim out of any
  matching string: they are content functions the preimage fixtures depend on.
  What moved is that a matching string is no longer proof of what the event is.

  **Reachability was measured, not assumed, and the first probe was wrong.**
  Driving `obsvr.wrap()` reads zero forged markers in both directions — its
  extractor stores `"user: <content>"` and the pattern is anchored — so a probe
  that stopped there would have cleared a live vulnerability. The LangChain
  integration stores `prompts.join("\n")`: a bare, user-controlled string, which
  is the shape that reaches it.

  **Residual, stated rather than left implicit:** `operation` is not in the
  signature preimage, so a party who can edit a STORED event can still set it to
  `audit.gap` on an event whose prompt already parses. That now needs two
  capabilities where one used to do. Closing it entirely means signing
  `operation`, which is a chain-format change and is not made here.

  The pinned marker event in `conformance/fixtures/audit_gap.json` gained
  `operation` and `source`, which is what both senders actually stamp; neither
  field is in the preimage, so no pinned signature moved.
- **BREAKING (audit chain): the client signature did not cover the verdict.
  Chain format is now 3, and the decision fields are inside the preimage.**
  Under formats 1 and 2 the preimage was
  `format | session | seq | timestamp | content_hash | prev_sig` and carried no
  decision field at all. A party who could edit a stored event before ingest
  could rewrite `action_taken` from `blocked` to `allowed` — inverting the
  enforcement record — and `obsvr-verify`, run **with the correct API key**,
  still reported the chain valid. Measured against a real chain, all eight of
  `action_taken`, `action_reason`, `reason_code`, `rule_id`, `policy_version`,
  `model`, `provider` and `user_id` were rewritable with the chain still
  verifying, while the content and ordering controls broke as they should.

  `SECURITY.md` always stated that the server countersignature was what sealed
  those fields, and that was true. But `obsvr-verify` is shipped as the
  user-facing **offline** verifier, and a compliance officer running it got a
  clean result on a fully rewritten verdict history — a false negative that
  reads exactly like a true one.

  Format 3 adds a `decision_hash` to the preimage:
  `3|session|seq|ts|content_hash|decision_hash|prev`. The digest is framed the
  way the format-2 content hash is, and for the same reason — eight bare
  concatenated fields would re-split at a different boundary — with a presence
  byte per field so an **absent** field stays distinct from a
  present-and-empty one.

  **Migration.** Nothing to do to keep verifying old evidence: formats 1 and 2
  stay implemented forever, chains signed under them verify as those formats,
  and both verifiers report which format they checked. New events sign under 3.
  What does **not** happen is retroactive strengthening — a format-2 chain still
  cannot detect a rewritten verdict, and that is pinned as a fixture case
  (`format2_verdict_rewrite_is_NOT_detected`) rather than left implicit. Marked
  BREAKING because any consumer that re-derives signatures itself must
  implement the new preimage to verify current events; a consumer that only
  calls the shipped verifiers needs no change.

  **Still outside the preimage, deliberately:** `tenant_id`, token counts and
  cost. Those remain sealed by the server countersignature only, and the tamper
  matrix records them as still-rewritable rather than omitting the rows.
- **The root README claimed the client chain detects any edit to a captured
  event. It does not, and this repository's own threat model says so.** The
  sentence read *"Any edit, drop, or reorder of captured events breaks the chain
  detectably"* — but the signature preimage is
  `format | session | seq | timestamp | content_hash | prev_sig`, which carries no
  decision field. `action_taken`, `rule_id` and the rest of the attribution sit
  outside it, so rewriting a verdict from `blocked` to `allowed` breaks nothing a
  client-side verifier can see. `SECURITY.md` has always stated this correctly and
  in detail, and `sdk-typescript/README.md` states it correctly too; the root
  README was the one place that overstated it, which is the place a reader
  arrives first.

  The claim is now narrowed to what the preimage actually covers — content, and
  order once an event is in the chain — and points at the server countersignature
  for the decision fields. **This is a documentation correction, not a change in
  behaviour:** nothing about what the SDK signs moved in this entry. Widening the
  preimage to cover the decision fields is a separate change with its own chain
  format.
- **Python streaming broke `with` on any wrapped client.** The streaming paths are
  generator functions and the call sites returned one directly, so callers got a
  plain generator where the provider's contract promises a stream object. The
  documented and extremely common form —

  ```python
  with client.chat.completions.create(..., stream=True) as stream:
      for chunk in stream: ...
  ```

  — raised `TypeError: 'generator' object does not support the context manager
  protocol` as soon as obsvr was in the path, so calling `obsvr.init()` before
  constructing a client was enough to break every caller written that way,
  LangChain streaming included, since that is the form it uses. **Pre-existing:
  this predates the current work rather than arriving with it.**

  Streaming now returns a governed stream that iterates through the accumulator
  and delegates everything else to the real object, so entering and exiting the
  context manager operate on the provider's stream — which is where the HTTP
  response is closed. `__enter__` deliberately returns the governed object, not
  the provider's: handing back the raw stream would make `with` work and quietly
  stop accumulating, recording an empty response for a stream that produced text,
  which is a worse failure than the exception because it looks like success.

  `close()` is the subtle half. A bare generator has a `close()` of its own, so
  the old return value satisfied `hasattr(stream, "close")` and any duck-typed
  cleanup while closing only the generator and leaving the provider's response
  open. It now delegates. The async path had the same defect for `async with` and
  is fixed the same way.

  Verified with a real streaming call, not only against a fake stream: the `with`
  form completes, and the single audit event's response equals exactly what the
  caller received.
- **A policy floor configured on its own did not reach MCP tool calls, in either
  SDK.** The floor is enforced inside the shared pre-call evaluation, and the MCP
  integration ran that evaluation only when a `pii_policy`, a pre-call hook, a
  minted canary or a tainted session existed — `policyFloor` was not in that list.
  So a deployment that configured the operator baseline and nothing else got no
  floor at all on MCP tool calls, silently, on the surface `SECURITY.md` singles
  out as the one to put a destructive capability behind. Measured live before the
  fix: the tool executed and the record read `allowed`. The floor already worked
  there the moment any other one of those was configured, which is what kept the
  gap invisible.

  Found by driving the "block-before-send on every surface" claim rather than
  trusting it — that claim had **no live evidence of any kind** behind it. It is
  now evidenced on the wrapper, on a framework integration and on MCP; the
  governance `evaluate()`/`explain()` endpoint is covered by unit tests but was
  not in that live pass.

  **A related gap is documented rather than fixed:** the `floor_override_ignored`
  record — the tamper-evident note that a hook tried to weaken the floor and was
  refused — currently lands only on the wrapper path. On the integrations and MCP
  the block stands and the hook is still refused, but the attempt is not recorded
  on the event.
- **OpenAI Agents (TypeScript): tool-gate events record `not_evaluated`.** The
  same defect as the Python one below, on the npm package: the gate emitted
  `action_taken: "blocked"` with `TOOL_DENIED` from a method whose own docstring
  explains that a throw there cannot block anything, because the modern
  `TracingProcessor` hooks are dispatched fire-and-forget — and which says
  enforcement lives in `obsvrGovernTool`. On this project's severity axis a
  recorded refusal from a path that cannot refuse is a false record rather than
  a coverage gap, which is what made it release-blocking. Those events now carry
  `not_evaluated` with the reason, the step limit and loop detection report only
  halts they can perform, and `applyLoopDetection` takes the same `canHalt`
  argument as its Python twin.

  Found by measuring, not by reading across. The TypeScript tool gates had never
  been driven, and the measurement was also the first evidence for the opposite
  result on another surface — see the LangChain note under Changed.
- **The recorded `provider` described the wrapper, not the destination.**
  `wrapTogether` set `provider: "together"` unconditionally, so one wrapper
  pointed at two different servers reported the same destination for both:
  against Groq's API it recorded "together", and against a localhost server it
  recorded "together" as well — filing a local model as served by a US cloud
  vendor, in the field a compliance reviewer reads for data residency. No event
  field anywhere derived from the real endpoint.

  `provider` is now taken from the client's base URL. The wrapper's label is a
  fallback used only when no base URL can be read, and three metadata keys carry
  the destination: `endpoint_host` (host and port only — never credentials, path
  or query), `provider_detail`, and `provider_attribution`, which says whether the
  label was checked against the endpoint or merely declared, borrowing the trust
  vocabulary `provenance_source` already uses for `model_resolved`. Where the host
  is visible but unrecognised, `unknown` is recorded: vague is a lesser fault
  than wrong.

  **The provider union was deliberately NOT widened** to add the OpenAI-compatible
  vendors it lacks. That type mirrors the ingest canonical enum, so emitting a new
  member would move the problem one layer down. A destination the enum cannot name
  records `unknown` and keeps its identity in `provider_detail` — the carriage
  `mcp` already uses — and a test pins that every resolved value stays inside the
  canonical set.

  Verified live through one wrapper against two real endpoints, each now
  recording its own destination.

  **This first pass covered the compat wrappers only, and the front door kept the
  defect.** `obsvr.wrap()` — the documented entry point both READMEs lead with —
  labels through its own duck-typed detector, which never read a base URL at all,
  and it was left on the old behaviour in BOTH languages. Measured live against a
  local server, the front door recorded `provider: "openai"` beside
  `model: "qwen2.5-coder:14b"`, a model that endpoint does not serve. Both front
  doors now resolve through the same endpoint table as the compat wrappers, which
  has moved to one shared module per language rather than being copied.

  The fix keeps the client's **shape** and the call's **destination** in separate
  fields, because one variable had been answering both questions. The shape
  selects the prompt/response extractors and stays duck-typed; only the record
  follows the endpoint. Collapsing them back together would relabel correctly and
  silently break extraction for an Anthropic-shaped client on a non-vendor host,
  so both suites assert that split directly.

  **Not changed, and stated rather than left implicit:** the `PolicyEvalContext`
  a rule sees still carries the shape-derived provider, not the destination. A
  `provider` rule therefore matches on what the client looks like. That is a
  behaviour change to rule evaluation rather than to the record, so it is a
  separate question from this one and is not made here.
- **`action_taken` was a closed enum in name only, and the value that mattered most
  was pinned by nothing.** The field a post-incident reader consults to learn what
  governance did was a string-literal union declared twice in TypeScript and
  enumerated nowhere at all in Python — whose own comments called it a closed enum.
  The shared corpus pinned three of its six values across 31 fixtures, and
  `not_evaluated` appeared in none of them: a live production value in both SDKs,
  emitted from several surfaces, agreeing across languages only because it had been
  widened in the same commit.

  `conformance/fixtures/action_taken.json` now pins the set cross-language, with
  the meaning of each verdict written down beside it — including the three things
  `not_evaluated` must never do, each of which was a real defect here: be read as
  `allowed`, be read as `blocked`, or be omitted so the server defaults it. Each
  SDK carries a frozen mirror and a staleness suite asserting it equals the
  fixture, plus a containment check over a real emission path rather than over the
  helpers alone. In TypeScript the compiler additionally binds the set to **both**
  interfaces that declare the field, in both directions, so a member added to one
  declaration and not the others is a build error rather than a silent divergence.

  **Corpus hash changed** — `9afde624…` to `e093dce7…`, 34 files to 35. Both
  language pins move with it.
- **The LangChain tool gate never fired on the runtime the framework now directs
  people to.** The allow/deny list, step limit and loop detector sat in
  `on_agent_action`, which the classic `AgentExecutor` still fires but the graph
  runtimes never do. So on a current install no tool was refused and no block event
  was emitted, while a complete and plausible audit trail was still produced.

  The gate now also runs in `on_tool_start`. The framework dispatches that before
  the `try` that guards tool execution and outside the error handling that would
  otherwise turn a refusal into a tool result, and the handler already set
  `raise_error` — so the enforcement point was available and unused rather than
  absent. Both pre-tool callbacks reach one shared gate, so a runtime that delivers
  both gates the tool once rather than charging it two steps.

  **Python's LangChain row moves from "not wired" to "enforces"** in both READMEs
  and `SECURITY.md`. Verified live on both runtimes with a policy-off control on
  each, and against the preceding commit, which still lets the denied tool run. On
  the graph runtime the refused cells show the framework's own tool-end callback
  never arriving, which is the framework reporting that the tool body was never
  reached.

  One documentation claim was corrected rather than carried over: `on_agent_action`
  was described as a callback "the current runtime never fires", and the classic
  executor does still fire it. It is the graph runtimes that do not.
- **Tools invoked by a provider tool runner ran outside every tool gate,
  including the destructive-capability gate.** `chat.completions.runTools` and
  `beta.messages.toolRunner` were governed at the invocation, but the runner holds
  the raw provider client and invokes its tools itself — so denied-tool rules,
  allowlists and `sessionTaint.destructiveTools` never reached them. Measured with
  the latch armed and `action: "flag"` (the default): a session already marked
  tainted executed `send_money`.

  Each of the runner's tool callbacks is now wrapped in the same gate
  `obsvrGovernTool` applies, installed before the runner is constructed — the only
  point either runner will accept a substitution, since both snapshot their tool
  set when the method is applied. A refused tool's callback does not run. Verified
  live on both runners, each against a policy-off control, and against a build of
  the preceding commit that reproduces the bypass.

  **Three limits, stated rather than left to be discovered.** The model calls the
  loop makes on turns 2..N are audited but still not gated. A hosted tool the
  provider executes on its own infrastructure has no local callback to gate, and is
  named in `tool_gate_ungated_tools` on the run's start event. And the refusal shape
  differs by provider: one runner guards its tool call, so a refusal returns to the
  model as an error tool result and the loop continues; the other does not, so the
  run ends with the refusal. Both fail closed. Python ships no tool-runner
  integration, so none of this applies there.

  The runner's per-tool event still records `not_evaluated` — it observes the turn
  and is not a second verdict — but `policy_not_evaluated.gate` now separates
  `runner_observation` (the gate ran; the decision is on that tool's own `tool.call`
  event) from `tool_gate` (no gate reached the call), and `metadata.tool_gate`
  carries the same answer as `callback` or `absent`.
- **`obsvrGovernTool` silently did nothing to a provider tool runner's tools.** It
  probes four property names for a tool's executable, and a runner's tool entry uses
  none of them — so it returned the tool unchanged, with no gate, no error and no
  event. That made the mitigation both READMEs point at for that surface a no-op on
  exactly that surface. Three further shapes are now recognised, appended to the
  probe order rather than inserted, so no tool that resolved before resolves
  differently.
- **BREAKING (behaviour): `max_steps` on the AutoGen integration is no longer
  applied when it cannot be scoped to a conversation.** The budget needs a
  conversation boundary and the send hook has none to observe unless
  `patch_initiate_chat` is installed as well — that helper is what zeroes the
  counter when a chat starts. Without it the counter was per thread for the life
  of the process, so a later conversation inherited whatever an earlier one spent,
  and a long-lived process exhausted the budget permanently and then refused every
  tool call. Measured live on two releases of the framework before this change.

  The limit is now skipped in that configuration, and each affected tool call
  records `action_taken: "not_evaluated"` with the reason in
  `metadata.obsvr_telemetry.policy_not_evaluated`, one record per call with the
  same `tool_call_index` / `tool_call_count` the enforcing branch carries.

  **This strictly weakens an enforcement control, and that is the point.** The
  alternative was keeping a limit that denies legitimate work, which ends with the
  control switched off by whoever is on call and no record that it is gone. An
  unenforced limit that says so stays visible and auditable. **Install
  `patch_initiate_chat` whenever `max_steps` is set** and behaviour is unchanged;
  the allow/deny tool gate needs no run scope and is unaffected either way.
  Verified live in both directions on two releases — the unscoped configuration
  records and does not refuse, the scoped one still refuses.

  Also fixed in the same change: the run wrapper zeroed the run context on the way
  out, so a nested conversation returning handed the enclosing one a fresh budget.
  It now restores the scope it suspended, which matters more than it did before —
  clearing it would have dropped the outer conversation's limit for the rest of its
  run.
- **An unrecognised `step_limit_action` silently disabled the step limit.** The
  decision helper returned the configured value verbatim, and each caller then
  tested it against the two dispositions it implements — so a typo, or a
  disposition from a newer config than the installed SDK, matched neither branch
  and the limit did nothing. Nothing was recorded either, so a run that blew
  through its budget looked exactly like one that stayed inside it. Measured
  live before the fix: with `max_steps: 2` and `step_limit_action: "warn"`, a
  tool chain ran five times.

  It now fails closed, and the event names both the value that was ignored and
  the vocabulary it failed to match — blocking without saying why the
  configuration was dropped would trade a silent failure for a mysterious one.
  Re-probed live: the same scenario stops at two, while the no-limit control
  still reaches five (so the halt is real) and `escalate` still reaches five (so
  a valid action is still honoured).

  **There were four identical copies of that helper, one per integration**, which
  is how the defect survived — it was in all four, and each read like an isolated
  local function. There is now one, and a test fails if an integration
  reintroduces a private copy. The CrewAI and LangChain step-limit events also
  had the missing-compliance defect described below and now report refusals as
  refusals; CrewAI's step limit is worth noting because it runs on every step
  callback rather than inside the tool-name branch, so unlike that integration's
  tool gate it does fire on current runtimes.
- **AutoGen tool policy checked only the first call in a message.** The send
  hook read `tool_calls[0]` and nothing else, so enforcement depended on
  POSITION: with `denied_tools: ["send_money"]`, a message carrying
  `[get_weather, send_money]` was checked as `get_weather`, delivered, and the
  recipient executed `send_money` — no event, no exception, nothing in the trail
  to review. The same read let `max_steps` be evaded by batching, because a
  message cost one step however many calls it carried. Every call is now
  checked, the budget is charged per call, and the event records
  `tool_call_index` / `tool_call_count` so a reviewer can see which call in a
  batch was refused. A tool call whose name cannot be read is refused rather
  than skipped.

  Re-probed live against ag2 0.3.2 and 0.14.0. The control matters as much as
  the fix: with no policy the model does batch both calls and both execute, so
  the refusal is not an artefact of a probe that blocks everything.
- **A step-limit refusal was recorded as a permitted call.** The event carried
  no compliance, inherited the default, and landed as `event_type: "llm_call"`
  with `reason_code: PERMITTED` — so every `blocked_call` filter stepped over a
  refusal that had really happened. It now reports `blocked_call` /
  `POLICY_VIOLATION`.

  **Two documented conditions on AutoGen tool policy, both measured rather than
  reasoned.** The send hook fires on the SENDING agent, so registering only on
  the proxy that starts a conversation leaves tool policy inert while still
  producing a complete, plausible audit trail — the docstring's own example did
  exactly that and has been corrected. And `max_steps` is scoped to a
  conversation only when `patch_initiate_chat` is used; without it the counter is
  per thread for the life of the process, so a later conversation inherits what
  an earlier one spent. The first is a documentation fix; the second is now
  repaired in its own entry below.
- **The OpenAI Agents integration recorded `blocked` for tool calls that had
  already completed.** Its tool gate runs in `on_span_end`, and a function span
  does not end until its tool has returned, so a denied tool executed and its
  result reached the caller while the event asserted `action_taken: "blocked"`
  with `TOOL_DENIED`. A post-incident reader would have concluded a capability
  was refused that in fact ran. The event now carries
  `action_taken: "not_evaluated"` and states why there is no verdict in
  `metadata.obsvr_telemetry.policy_not_evaluated`. `max_steps` and loop
  detection on that surface made the same claim and now report the same way;
  `apply_loop_detection` takes a `can_halt` argument, and callers that sit on a
  boundary which can refuse are unchanged.

  **The gate still does not enforce, and cannot.** The framework wraps every
  trace-processor callback in its own `try/except` and only logs, so the
  exception raised to stop the run never reached it — moving the gate to
  `on_span_start` would be swallowed the same way. That inert `raise` is gone.
  Verified against a real provider in both directions: the repaired tree emits
  no `blocked` event for a denied tool, and the same probe run over the previous
  commit reproduces the false record, so the assertion has a demonstrated
  failing state rather than an assumed one.

  Two further defects surfaced while fixing it. The inert `raise` aborted the
  rest of the callback, so whenever policy "blocked" a call the trail also lost
  the `openai_agents.tool.call` record of the call that really happened — the
  false record was suppressing the true one. And `policy_not_evaluated` had no
  route through the Python event builder at all: TypeScript mirrors it onto
  `metadata.obsvr_telemetry` because ingest has no top-level column for it,
  while Python dropped the field silently. Python now carries the twin.
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
  ([`763b5ef`](https://github.com/obsvr-dev/obsvr-sdk/commit/763b5ef))
- `conformance/fixtures/eval_semantics.json` gained dedicated cases for EV-3,
  EV-14, and EV-22 — statements `conformance/SPEC-evaluation.md` listed as
  covered but which no fixture actually pinned — shrinking the uncovered list
  from nine to seven. Cases now declare a `mode`: `rules` (the default),
  `pipeline`, or `explain`. Semantics are unchanged; this pins behavior that
  was already specified.
  ([`4d1c423`](https://github.com/obsvr-dev/obsvr-sdk/commit/4d1c423))
- **The conformance corpus hash changed — re-pin if you pinned it.**
  `conformance/MANIFEST.sha256` moved from `corpus_sha256 = 1120116f…` to
  `9afde624…`, and both `conformance.pin` files with it. That span is no longer
  a single change. The bookkeeping pass described under Added — the per-case
  `sdk_support` and per-fixture `claimable` keys, one divergence entry's
  `tracking` text, one fixture's `description` — moved no vector, digest,
  canonical form, or expected value, and carried the hash only as far as
  `8c48c249…`
  ([`c9c4040`](https://github.com/obsvr-dev/obsvr-sdk/commit/c9c4040),
  [`dd914c8`](https://github.com/obsvr-dev/obsvr-sdk/commit/dd914c8),
  [`f3947d9`](https://github.com/obsvr-dev/obsvr-sdk/commit/f3947d9),
  [`6767aa4`](https://github.com/obsvr-dev/obsvr-sdk/commit/6767aa4)).
  **Everything after that did change expected values**, so re-pinning is not
  the whole of the work: the `protocol_facet`, CloudEvents, cost and
  evaluation-context fixtures are new, `reason_codes.json` gained
  `PROTOCOL_FACET_MATCHED`, `otel_attributes.json` moved to schema 2 with a
  `conditional_keys` set, and the approvals, session-taint, de-obfuscation and
  fail-mode fixtures all grew cases. Each is described in its own entry above;
  re-read the ones whose fixtures you consume.
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
