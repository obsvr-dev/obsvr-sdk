# Security & Threat Model

This document states plainly what the obsvr SDKs' security mechanisms guarantee, what they do not, and how to report vulnerabilities. We believe honest limits build more trust than absolute claims.

## Reporting a vulnerability

Email **hello@obsvr.dev**. We aim to acknowledge within 48 hours. Please do not open public issues for security reports.

## Architecture summary

```
Your app + obsvr SDK   ->   Ingest service        ->   Immutable storage
  (intercept, enforce,       (verify, countersign,       (Merkle roots,
   sign, emit)                canonicalize)               anchoring)
```

This repository contains the client SDKs (TypeScript and Python) and the shared conformance fixtures. The server side (ingest verification, countersigning, Merkle anchoring) is part of the obsvr platform; its behavior is summarized here where it affects what the SDK-side guarantees mean.

## The integrity chain: what it proves

Every event emitted by an SDK carries:

| Field | Meaning |
|---|---|
| `sdk_session_id` | Stable UUID per SDK process lifetime |
| `seq_no` | Monotonic counter within the session |
| `chain_format` | Signing format number (currently `3`; absent on pre-format-2 events) |
| `prev_sig` | Signature of the previous event (chain link) |
| `sdk_sig` | HMAC-SHA256 over `format|session|seq|timestamp|content_hash|prev_sig` |

The content hash inside the signature payload is domain-tagged and **length-prefixed per field** (`sha256("obsvr:content/2" || 0x00 || u64be(len(prompt)) || prompt || u64be(len(response)) || response)`), so the prompt/response boundary is itself under the HMAC: the same bytes re-split at a different boundary produce a different digest. The previous format hashed the bare concatenation `sha256(prompt + response)`, which left the boundary unsigned — text could move between "what the user said" and "what the model said" without breaking verification. Chains signed under that format keep verifying, and the verifiers report `chainFormat: 1` for them so legacy evidence is never mistaken for boundary-bound evidence (see the migration note in `CHANGELOG.md`).

The signing algorithm is byte-for-byte identical in both SDKs, pinned by the shared vectors in `conformance/fixtures/signing_vectors.json` (which also pin the legacy format, frozen, and the boundary-collision pair that motivated the change). The ingest service re-derives the signing key from the stored API key, verifies `sdk_sig` on acceptance, rejects replays and stale/future-dated events, and **countersigns** each accepted event with a key that never leaves the server.

**Guarantees:**

- Modifying or deleting any captured event after acceptance is detectable (chain break).
- Reordering or dropping events within a session is detectable (sequence gaps) once an event has entered the chain. Events the bounded sender queue drops under load never enter it — they are dropped before a sequence number is assigned, so they leave no gap to detect. Those are covered by a different mechanism: the sender signs a **gap marker** into the chain at the position the loss occurred, declaring how many events were dropped there, with the count inside the signature preimage so it cannot be edited down without breaking verification. Both `obsvr-verify` binaries report declared losses alongside the verdict. A chain can therefore be valid and incomplete simultaneously, and that is stated rather than smoothed over.
- A third party can verify the chain independently of obsvr using the exported events and the public verification tooling (`obsvr-verify`, shipped by **both** SDKs with identical modes, exit codes, and verdicts — a Python-only shop needs no Node toolchain to check its own evidence, and CI drives both binaries over one export to keep them from drifting). This offline check attests prompt/response **content** integrity, event **order**, and — since chain format 3 — the **decision fields** (`action_taken`, `action_reason`, `reason_code`, `rule_id`, `policy_version`, `model`, `provider`, `user_id`). `tenant_id`, token counts and cost remain outside the client preimage and are covered by the server countersignature. Chains signed under formats 1 and 2 verify as those formats and do **not** cover the decision fields; the verifier reports which format it checked, so a reader can tell what a given export's verdict actually attests to.
- Every event pins the exact policy state it ran under: `policy_version` carries the canonical hash of the enabled rule set (identical derivation in both SDKs, fixture-pinned in `conformance/fixtures/rules_hash.json`), so any decision can be re-derived against the stored rules.
- Approvals are pinned to the exact rule definition they were granted under (per-rule canonical hash) **and to the exact action** (a canonical digest of the rule, the rule's hash, the action name, the amount, the caller and target namespaces, and the subject). Editing a rule voids outstanding grants for it, and a grant issued for one call cannot be spent on a different call that happens to trip the same rule — one human approving a $50 transfer does not leave a live grant covering a $5,000,000 one. The digest deliberately does **not** cover the free-text prompt: an approved request and its retry differ in it more often than not, and a binding that voided itself on a whitespace change is one operators would switch off. The grant is re-checked after every layer that can delay the call (the customer hook's two-second budget, an external policy backend) and before the request goes out, so a grant revoked or expired mid-call authorizes nothing; the residual window is this library's own final assembly, which no in-process control can remove. Each pin only narrows — a grant that carries no action hash still satisfies — so an unbound grant is exactly as strong as its issuer made it. Pinned by `conformance/fixtures/approvals.json`. An opt-in blocking hold (`approval_wait_ms` / `approvalWaitMs`, default 0 — no waiting) polls the grant channel instead of refusing immediately; only an explicit, still-live grant lifts it, an expired hold blocks as `APPROVAL_TIMEOUT`, and enforcement degradation mid-hold aborts the wait with the block standing. A stated limit of the hold: the grant channel carries grants, not verdicts, so a human **denial** is indistinguishable from indecision client-side and surfaces as the same timeout — a deny cannot short-circuit the wait until a pollable per-request status exists server-side.

**Explicit non-guarantees:**

- **Client signing alone is not non-repudiation against a key-holder.** The SDK signing key is derived from the API key, so a party holding the API key could construct validly-signed *client* chains. This is why ingest adds a server countersignature with a key that never leaves the server: a key-holder cannot forge it, so they cannot fabricate an event that appears to have been accepted. What the client chain still cannot prove is (a) what happened *inside your process before emission*, or (b) the integrity of the fields left outside its preimage — since **chain format 3** the preimage is `format | session | seq | timestamp | content_hash | decision_hash | prev_sig`, and `decision_hash` covers `action_taken`, `action_reason`, `reason_code`, `rule_id`, `policy_version`, `model`, `provider` and `user_id`. **`tenant_id`, token counts and cost are still outside it**, so a party who can alter a stored event before ingest can still rewrite those without breaking the *client* chain; the server countersignature (over the full canonical event) is what seals them once accepted.

  **This non-guarantee used to be much wider, and the narrowing is the point.** Under formats 1 and 2 the decision fields were outside the preimage, which meant `action_taken` could be rewritten from `blocked` to `allowed` and `obsvr-verify` — run with the correct API key — still reported the chain valid. The server countersignature covered it, and this section said so, but the offline verifier is what a compliance officer actually runs, and it returned a clean result on a rewritten verdict history. Format 3 closes that. **Chains signed under formats 1 and 2 are not retroactively strengthened**: they verify as the format they were signed under, the verifier reports which, and on those chains a rewritten verdict remains undetectable — a fact pinned deliberately in `conformance/fixtures/signing_vectors.json` (`format2_verdict_rewrite_is_NOT_detected`) rather than left for a reader to discover.
- **Events the SDK never saw are not in the record.** Coverage requires the SDK to be in the call path; this is an inherent property of an in-process library (see "Bypass surface").

## The same thing in RATS vocabulary (RFC 9334)

Everything above is described in this project's own words. RFC 9334 — the IETF
Remote ATtestation procedureS architecture — already has words for most of it,
and a reader who evaluates attestation systems for a living should not have to
translate. This section is that translation, including the parts where obsvr
does not fit and the roles it does not implement. It adds no behavior; it is
here so the claims above can be checked against a standard rather than against
a vocabulary obsvr invented.

**Roles.**

| RFC 9334 role | obsvr | Notes |
|---|---|---|
| Attester | The SDK, in your process | Produces Evidence about the LLM/tool calls it intercepts. See the isolation caveat below — this is the load-bearing difference. |
| Verifier | `obsvr-verify` (`sdk-typescript/src/cli-verify.ts`, `sdk-python/obsvr/cli_verify.py`) and the chain verifiers behind it; the ingest service, independently | Appraises a chain and produces a verdict. Shipped in this package precisely so a Relying Party can appraise Evidence itself rather than take an Attestation Result on trust. |
| Relying Party | Your auditor, regulator, or security team — anyone consuming an export or an evidence pack | Outside this package. |
| Reference Value Provider | You, when you author policy: the rule set, the anti-tamper floor, operator tool-descriptor pins | Plus the SDK for its own frozen vectors. |
| Verifier Owner | Nobody, deliberately | The offline verifier's appraisal rules are fixed in code, not configurable. A verifier whose rules the audited party can tune is not a verifier. |
| Endorser | **Not implemented.** | See below. |
| Relying Party Owner | Outside this package | An auditor's acceptance criteria — which controls an export must satisfy — are theirs, not the SDK's. |

**Conceptual messages.**

| RFC 9334 message | obsvr |
|---|---|
| Evidence | The signed event chain: `content_hash`, `sdk_sig`, `prev_sig`, `seq_no`, plus `decision_input_hash` and `tool_content_hash` where present |
| Attestation Results | The verifier's verdict; server-side, the countersigned event and the anchored Merkle root |
| Reference Values | `policy_version` (canonical hash of the enabled rule set), `floor_version`, operator descriptor pins, and the pinned conformance corpus (`conformance/MANIFEST.sha256`) — the known-good values a claim is compared against |
| Appraisal Policy for Evidence | The verifier's own rules: signature validity, sequence contiguity, chain-format uniformity, declared gap markers, recomputed digests |
| Appraisal Policy for Attestation Results | Not implemented — the Relying Party's own |
| Endorsements | **None.** No third party vouches for a deployment's attestation key or capabilities. |

**Where obsvr does not satisfy the architecture, stated plainly.**

- **The Attesting Environment is not isolated from the Target Environment.**
  RFC 9334 §3.1 assumes an Attester's measuring environment is "sufficiently
  isolated" from what it measures, "so that the Target Environment cannot forge
  Evidence about itself." obsvr is an in-process library: the two share an
  address space, and the signing key is derived from your own API key. That
  assumption does not hold, and no amount of chain discipline makes it hold.
  What the chain proves is what the "Explicit non-guarantees" above already
  say — that emitted content arrived in order and unmodified, not that it was
  truthful when written. This is the same boundary as "Bypass surface," in the
  standard's terms.
- **There is no Endorser and no Endorsements.** Nothing signs a statement
  binding a particular deployment's attestation key to a vouched capability.
  The published package and the corpus pin let a verifier establish *which
  build* produced an export, which is useful and is not an Endorsement: it
  vouches for the software, not for the instance. Adding a real Endorser role
  is a third-party trust relationship, not a code change, and obsvr does not
  claim one.
- **Evidence freshness is anchor-bounded, not nonce-bound.** RFC 9334 §10 gives
  three mechanisms. obsvr uses none of them in the strict sense. Event
  timestamps come from the Attester's own clock, which the RFC treats as
  untrustworthy absent an endorsed clock — and obsvr endorses no clocks. There
  is no verifier-supplied nonce, because the Verifier is offline and
  after-the-fact rather than in the request path. What obsvr does provide is an
  upper bound from a third-party time source: external anchoring of the daily
  Merkle root (RFC-3161 token, git commit, transparency log) proves the root
  existed unmodified no later than the anchor time. That is stronger than a
  self-asserted timestamp and weaker than a nonce, and the difference matters:
  it bounds when Evidence *existed*, never when it was *created*. Separately,
  `policyStalenessBudgetMs` (a TypeScript-only key) and the enforcement-integrity gate are a freshness
  mechanism for the Reference Values rather than for the Evidence — they bound
  how stale the policy in force may be before enforcement degrades.
- **Topology: passport model, with a background-check escape hatch.** Evidence
  is appraised and turned into a durable artifact that is later *presented* to
  a Relying Party, which is the passport shape (RFC 9334 §5.1) — the auditor is
  never in the request path. The escape hatch is why `obsvr-verify` ships here:
  a Relying Party that does not want to trust the Attestation Result can
  re-appraise the raw Evidence itself, offline, with no obsvr service involved.

## Enforcement semantics: what blocking means

- **Pre-call policies (PII, rules, hooks) are real enforcement.** They run before the provider is contacted; a blocked call never leaves the process.
- **Streaming responses are audit-time, not block-time, for post-call policies.** Once a stream is allowed to open, tokens reach the caller as they arrive. Response scanning runs after stream completion and is recorded, but cannot un-send tokens. Pre-call checks still run before the stream opens.
- **Fail mode is open by default.** If a pre-call hook times out or throws, the call is allowed and the failure is recorded (`hook_timeout` / `hook_error`). Set `failMode: 'closed'` (TypeScript) / `fail_mode="closed"` (Python) for policies that must never fail open. Every governance layer's posture for every failure state (timeout, error, degraded) is declared in one table per language and pinned by `conformance/fixtures/fail_mode.json`, so the posture is reviewable in one place rather than re-derived per code path. That includes the in-process detector layers, whose posture is no longer merely declared but resolved — see "An exception inside any detector layer never reaches your application as an unhandled error" below, which also covers the cases where the answer is deliberately *not* `failMode`.
- **A blocked call raises a typed error.** `ObsvrPolicyError` (both SDKs) carries a stable `type`, a `reason_code` from the closed registry, the deciding `rule_id`, and the decision metadata, constructed at one choke point per language. Callers can distinguish a deliberate refusal from a provider or transport failure without string-matching a message; an unrecognized reason category yields a documented fallback class rather than an untyped throw.
- **Backend outage does not stop enforcement.** Policy rules are cached in the SDK and keep enforcing; only rule *updates* degrade during an outage. Event delivery is queued and retried: transient failures (408/429/5xx/network) retry under jittered exponential backoff; permanent failures (other 4xx) are dead-lettered and counted. Events the server accepts the request for but refuses individually — per-event rejects inside a `2xx` batch response — are counted in their own `dropped_rejected` bucket in **both** SDKs and reported on the fleet-status poll, and are never counted as sent: "we never delivered it" and "the server received it and refused it" are different stories in a coverage report. One 4xx is deliberately **not** a drop: a `409` whose body says `duplicate_event` means a retry raced a lost `2xx` and the event is already durably recorded, so it counts as sent (single-event, whole-batch, and per-event alike) — counting it as lost would fabricate a coverage gap for evidence that exists. Only that exact code: a `409 sequence_fork` means the chain position belongs to a *different* signature and stays a failure, and a `409` whose body cannot be read is never absorbed.
- **Shadow rules are provably inert.** A rule in shadow mode records what it would have done but never affects decisions, content, quotas, or approvals; the active decision is byte-identical with shadow rules present or absent (pinned by `conformance/fixtures/eval_semantics.json`).
- **Prompt-injection detection is pattern-based.** It catches known injection phrasings; it is a detection signal, not a proof of prevention. Structural controls (tool allowlists, action gates) are the reliable defense.
- **The anti-tamper policy floor cannot be silently disabled or downgraded.** Rules placed in `policyFloor` (both SDKs) always enforce: setting `enabled: false` or `mode: "shadow"` on a floor rule is ignored, the customer `onPreCall` hook can never un-block or downgrade a floor block, and because the floor lives in its own config field a remote `/policies` sync cannot delete it. Since the config-lifecycle repair the middle tier is protected too: a poll owns the SERVER rule set and may legitimately empty it, but it does not delete rules the caller declared in `init({policyRules})`, and a server rule carrying the id of a locally declared one does not take it over. Before that, a `200` carrying `{"rules":[]}` erased local rules AND advanced `lastSuccessAt`, so `failMode:"closed"` never tripped. When the hook attempts to override a floor block, the SDK keeps the block **and records `floor_override_ignored` (the rule id and what was attempted) on the signed audit event** — a first-class, tamper-evident record of the suppression attempt, not a log line that a host can swallow. The floor definition is itself sealed: a `floor_version` hash rides **every** event under an active floor (allowed calls included, on every integration path — not only blocks), so a change to the floor is on the audit chain and its removal is detectable from the allowed-event stream. The **prompt** floor blocks-before-send on the proxy wrapper, the framework/infra integrations, MCP tool calls, and the governance `evaluate()`/`explain()` endpoint — **driven live on the first three** (destination never reached, event records `blocked`, `floor_version` stamped), with the governance endpoint covered by unit tests in both languages but not in that live pass. **One gap was found by that measurement and closed:** MCP ran the shared pre-call evaluation — which is where the floor is enforced — only when a `pii_policy`, a pre-call hook, a minted canary or a tainted session existed, and `policyFloor` was not in that list in either SDK. A deployment that configured the operator baseline and nothing else therefore got **no floor at all on MCP tool calls**, silently, on the surface this document singles out as the strongest; the floor already worked there the moment any other one of those was set, which is what kept the gap invisible. Also worth stating rather than leaving to be discovered, and it is a per-language answer: in **Python** the `floor_override_ignored` record described above lands only on the **wrapper** path — on the integrations and MCP the block stands and the hook is still refused, but the attempt to weaken the floor is not recorded on the event. **TypeScript records it wherever a floor runs**: `integrations/core.ts` produces the record and the Bedrock, Vertex, Vercel AI, OpenAI-compatible, Cloudflare and MCP callers each merge it onto the signed event. The **response** floor (`applies_to: "response"` or `"both"`) is a detection/audit control, not a block — it **redacts the stored audit copy and flags the event, but never withholds the response from your application** (the SDK never mutates the value returned to the caller) — and it runs only where the SDK's post-call pass runs: the direct-client proxy wrapper on both SDKs, plus the Python Bedrock/Vertex integrations. The **TS infra integrations (Bedrock/Vertex/Vercel AI/Cloudflare/Azure-OpenAI-compat) and MCP do not run a response-side pass**, so response-target floor rules — like all response-side controls (response PII, response rules, canary-on-output) — do not apply there. A floor rule with `action: "redact"` **fails closed to a block**: the SDK has no reliable span-level redaction for an arbitrary rule match, so rather than forward content it cannot guarantee was redacted, the floor blocks (a floor is the non-overridable baseline). A floor `model_gate` / `environment_gate` rule is evaluated with the request's real model and the configured environment as authoritative context that a caller cannot spoof via `metadata`. Honest limits: the floor is an operator-declared set (there is no hidden built-in floor you cannot inspect), and — like everything the SDK enforces — it only covers calls that actually go through the SDK (an application that never invokes obsvr, or a floor omitted from config, is not protected; see "Bypass surface").
- **Session taint latch escalates a compromised session's later egress.** With `sessionTaint: { enabled: true }` (both SDKs), once a prompt-injection or a canary leak is detected in a session, that session is marked tainted and its subsequent egress — LLM calls, tool-call arguments, MCP calls — is escalated: `action: "flag"` (the default) annotates the events (`rule_id: sdk:session_tainted`) so the compromise is visible without bricking the session; `action: "block"` refuses the tainted session's egress. This is a session-level LATCH, not data-flow label propagation: it does not tag individual values and follow them, it records that a session id is compromised and remembers it (the per-call scanners can miss a staged exfiltration; the latch does not). **`destructiveTools` is a list of EXACT tool names a tainted session may never invoke, and where the SDK is genuinely on the tool boundary it does exactly what the design intends** — ordinary egress in a tainted session stays merely flagged, while the capabilities that could do damage (`send_money`, `delete_records`, ...) go dark, under `action: "flag"` and not only under `block`. **It is on fewer boundaries than that reads, and the honest statement is per surface rather than per SDK — so it is stated per surface:**
  - **Python, per integration that can invoke a tool, measured rather than inferred:**
    - `mcp` — **enforces**, unconditionally and including under `flag`: a denied tool's callback does not run, because the SDK gates the request path itself, the actual boundary, rather than hanging a check off a callback near it. Measured live end to end over real JSON-RPC against a real server, on protocol majors 1 and 2, on every client route into `tools/call`. The gate binds at `send_request`, which `call_tool`, the task API and any hand-built frame all converge on; before it did, the latter two reached a denied tool's body and the raw route returned its payload to the caller.
    - `govern_tool` (the framework-agnostic tool governor, twin of TypeScript's `obsvrGovernTool`) — **enforces at the tool's own boundary**: it runs the same pre-call pipeline as MCP, destructive-capability gate included, before the wrapped callable is entered. The taint gate is pinned by the governor's own tests; the governor's dispatch coverage was driven live on CrewAI, both executor paths. A tool wrapped with it carries this control into ANY framework. A governed tool also declines the framework's RESULT CACHE where the framework offers a say (`cache_function`): a cache hit answers a repeat call from the framework's own memory without entering the gated callable, so it escapes the gate *and* leaves no execution for a side-effect instrument to count — measured on CrewAI, where a tool run while allowed and re-requested after the policy denied it handed the caller the cached payload at zero new executions.
    - `autogen` — **enforces THIS control at its execution gate, and not at its pre-send hook.** `install_tool_gate()` governs the `_function_map` entry through `govern_tool`, so it carries the full pre-call net — destructive-tools set included — on every route that reaches the executor. The `process_message_before_send` hook is the other mechanism and is narrower here: it checks the allow/deny list against the outgoing message and consults no destructive-tools set. It does check every call in a message; it used to read only the first, so a denied name in a parallel batch still executed — fixed, and re-probed live on ag2 0.3.2 and 0.9.9 with the batching control showing both calls running unpoliced. **Install the execution gate for THIS control.**
    - `langchain` and `haystack` — do not enforce THIS control at their own gates. Both have a real pre-execution boundary their runtimes do deliver (`on_tool_start` for langchain, the Agent's `before_tool` hook for haystack, where each one's agent-policy tool gate enforces — see below), but the taint latch's destructive-tools set is not consulted at either. Wrap the tool with `govern_tool` to carry it there.
    - `crewai` — its pre-execution hook gate (`install_tool_gate_hook`) enforces the agent-policy allow/deny list before the tool runs, on both executor paths, but does not consult the destructive-tools set either; the step callback is delivered only after the step it reports and can refuse nothing. For THIS control, wrap the tool with `govern_tool`.
    - `openai_agents` — its pre-execution guardrail gate (`attach_tool_gate`) enforces the agent-policy allow/deny list before the tool runs — the executor consults tool input guardrails ahead of invocation — but does not consult the destructive-tools set; the tracing processor beneath it runs in `on_span_end`, after the tool has returned, and can refuse nothing. For THIS control, wrap the tool with `govern_tool`.
    - `llamaindex` — **enforces THIS control too.** Its gate (`govern_agent`) governs each assembled tool through `govern_tool` rather than through a framework callback, so it inherits the full pre-call net including the destructive-tools set, not the allow/deny subset the callback-gated rows above carry. It and `autogen`'s execution gate are the two agent surfaces that reach this control without a hand-wrapped tool, and they reach it the same way: through `govern_tool`.

    The non-enforcing rows stay listed under "Bypass surface". **Put a destructive capability behind `mcp`, or behind a `govern_tool`-wrapped tool.** Detection quality is still not the lever here and reachability still is — a missed or borderline injection is harmless if it cannot reach a destructive capability, which is why this composition matters more than adding detector patterns — but a reachability argument is only worth what the enforcement points under it are worth, and those are named above rather than assumed.
  - **TypeScript, measured the same way — and it does not read across from Python.** `obsvrGovernTool` **enforces** (it wraps the tool's own execute and gates before delegating), the LangChain handler **enforces** — it gates in the pre-execution `handleToolStart` and sets `awaitHandlers`/`raiseError` so a refusal inside a callback aborts the tool, where Python's `on_tool_start` gate covers agent policy but not this control — and MCP enforces on `callTool`, which is **not** the boundary its Python twin holds and does not read across from it: TypeScript binds `callTool` and `listTools` only, while Python binds `send_request` because `call_tool` is a convenience over it and two other client routes into `tools/call` reached a denied tool without touching it — measured, and closed there. The equivalent routes have not been driven on this SDK, and the integration test drives `governed.callTool` alone, so what is graded here is `callTool` rather than every route into `tools/call`. On openai-agents, `attachToolGate`'s guardrail enforces the agent-policy allow/deny list before invocation but, like its Python twin, does not consult the destructive-tools set — wrap the tool with `obsvrGovernTool` for this control; the tracing-processor surface beneath it **records only**, for the same structural reason as Python's, and it was emitting a false `blocked` until this was measured. `llamaindex` and `vercel-ai` carry no gate of their own and are governed per tool through `obsvrGovernTool`. The LangChain row still differs between the SDKs, so neither column may be read across to the other.
  - **Where the names come from.** Membership is exact names only (a capability set that pattern-matched would be a detector again) and costs one set-membership test at the tool gate. The list is no longer the only source: a discovered MCP tool whose descriptor declares `annotations.destructiveHint: true` joins the set by itself, so a deployment that enabled the latch and configured no list still gets a capability gate rather than silently getting none. The hint is admitted in ONE direction: it can only ADD. A `destructiveHint: false` is a safety claim from the tool server — the untrusted party the latch exists to defend against — so it is ignored, and an ABSENT hint is likewise treated as non-destructive, which is the compatible default and is stated here rather than left implied (most deployed servers publish no annotations, and reading silence as destructive would turn `flag` into a blanket block for them). A descriptor the SDK cannot read at all resolves to destructive, because an unreadable field is the same escape as a lying one. An operator entry always applies regardless of what a descriptor says, hints are recorded per governed client and never un-recorded by a later listing, and `honorDestructiveHints: false` restricts the set to the configured list alone. The whole table — `(descriptor_hint, operator_list, taint_state) → decision`, plus how the hint itself is read — is pinned cross-language in `conformance/fixtures/session_taint.json` (`tool_gate_cases`, `descriptor_hint_cases`).
  - **Honest limits.** The latch is keyed on the **caller-supplied** session identity (`metadata.user_id ?? session_id ?? tenant_id`) — thread a real session id, or every call shares one `"global"` bucket and the latch cannot distinguish sessions; the store is in-process and bounded (10,000 sessions, oldest evicted), so it resets on restart; and the enforcement point is the SDK's own egress path, so it cannot stop egress that bypasses the SDK (see "Bypass surface"). The turn that first taints a session is handled by its own gate and is never double-penalised — only *subsequent* egress is escalated.
  - **A tool boundary the SDK was NOT on, and now is:** a provider tool runner (`chat.completions.runTools`, `beta.messages.toolRunner`) invokes its tools itself, so `destructiveTools` did not reach them — measured, a tainted session executed `send_money` there under `flag`. obsvr now gates each of the runner's tool callbacks through the same wrapper before the runner is constructed, and both directions were re-measured live. The runner's intermediate model turns are still audited rather than gated, and a hosted tool the provider executes on its own infrastructure has no local callback to gate; see "Bypass surface" for both limits.
- **Canary-leak detection is a tripwire, not prevention.** Mint a canary with `mintCanary()` / `mint_canary()` and plant the returned token where only the model should ever see it (a system prompt, a retrieved document, a tool description). If that token later surfaces on a scanned surface — the model's OUTPUT, a tool-call ARGUMENT, a tool RESULT, or echoed back in the USER message — the SDK raises a CRITICAL, **unsuppressible** signal (the customer hook cannot downgrade it) and blocks where the surface is pre-delivery (a tool call, a tool result, or a user turn). On the response surface the tokens were already produced by the provider, so the leak is recorded and the stored copy redacted, but streamed tokens cannot be un-sent. Only the token's SHA-256 hash and a public id ever leave the process — the raw token is never stored, never rides an event, and never hits a log (a stored copy on a leak becomes the whole-text `[REDACTED:canary_leak]` placeholder). Detection matches over the same de-obfuscation views as the injection scanner, so a base64/hex-encoded or zero-width-split exfiltration is still caught. Honest limits: the registry is per-process (canaries reset on restart) and bounded (10,000 active canaries) — past the cap `mintCanary()` returns `registered: false` and logs a loud warning so a dead tripwire is never silently trusted; do NOT plant a canary on a surface the SDK scans (user input, model output, tool args/results) or you create a self-inflicted true positive; and a token mangled outside the recognized encodings evades the tripwire.
- **MCP tool-descriptor pinning is opt-in; TOFU pins are per-process.** With `mcpToolPolicy.pinning.enabled` (both SDKs), every tool descriptor seen at `tools/list` is hashed (a fixed canonical projection — name, title, description, input/output schema, annotations — under the SDK's cross-language canonical JSON, full SHA-256; vectors in `conformance/fixtures/tool_pinning.json`) and checked against operator `pins` first, then a first-seen (TOFU) record. A changed descriptor — the "rug-pull" where a benign tool is redefined after review — is flagged by default; `mode: "block"` strips it at discovery and refuses calls to it, and a TOFU record is never silently re-pinned (`requirePin` disables TOFU entirely — only operator `pins` satisfy strict mode, so a new or aliased tool cannot ratify its own hash). Honest limits: TOFU pins live in-process and reset on restart — a restart is a fresh trust-on-first-use window, so **config `pins` are the durable mechanism** (the per-tool hash rides the signed events precisely so you can copy an observed hash into config). The descriptor is not on the wire at call time, so call-time enforcement acts on the verdict from the most recent listing; a tool called without ever being listed is unverifiable (blocked only under `requirePin`). Descriptor hashing is cross-SDK byte-identical for the JSON both runtimes represent the same way; a descriptor carrying a number the two cannot represent identically (exponent-notation extremes, integers past 2^53) is treated as unverifiable and fails **closed** (flag/block), never a silent pass. **Removal detection** (`missing_pinned_tools`) is an advisory signal, not enforcement: it fires only on an unpaginated listing (a server that always returns a pagination cursor suppresses it), and a dropped tool is simply absent — the defense against a re-introduced tool is the pin check when it returns. Pins bind descriptor *content*, not server identity — the SDK cannot verify which server sent a listing, so two servers reached under one governed client, or the same tool name across servers, should be pinned per deployment.

- **MCP tool descriptors are content-inspected at discovery, not just pinned.** Pinning (above) detects that a descriptor *changed*; the discovery scan reads what it *says* — hostile metadata shipped on first contact would otherwise pass TOFU pinning cleanly. Every `tools/list` scans the description the model ingests **and the JSON Schema `description`/`default` strings** (per property, at any depth) for deterministic instruction-shaped patterns, over normalized text (NFKC, confusable-fold, zero-width strip), the HTML/Markdown-comment-stripped view (a directive split by comments reads whole to the model and fragmented to a scanner), and — when `deobfuscation` is enabled — the decoded views (base64/hex payloads). Bidi control characters are flagged on **presence** (`bidi_controls_present`): they have no legitimate business in a tool descriptor, while zero-width characters are only neutralized because emoji sequences carry them legitimately. A finding that appears only past the first view additionally flags `concealed_content`, and a bounded schema walk that stops early says so (`schema_scan_truncated`) rather than reading as full coverage. Flagged tools emit a `policy_flag` event with per-tool reasons; `mcpToolPolicy.blockPoisonedTools` strips them from the listing before the model sees them. Everything runs at discovery — zero cost on the call path — and the exact reason vocabulary is pinned cross-language in `conformance/fixtures/tool_descriptor_scan.json`. Honest limits: the patterns are a deterministic, enumerable set (they catch instruction-*shaped* text, not novel phrasing — the structural defenses above are the reliable layer), and strings nested inside object-valued schema `default`s are out of scope.
- **Tool calls seal what they saw (`tool_content_hash`).** Every event emitted at an MCP tool boundary (both SDKs) or by the tool governor (`obsvrGovernTool` / `govern_tool`, both SDKs) carries a digest binding the tool name, the descriptor the caller held, and the call arguments (`obsvr-tool-content-v1`, vectors in `conformance/fixtures/tool_content_hash.json`), so a descriptor swap or a rug-pulled server becomes attributable after the fact: disclose the parts, recompute, compare against the anchored root. It is **not** the pinning hash above and neither may be substituted for the other — the projections differ, and the fixtures pin that flipping a behavior hint moves the pin while leaving this digest unchanged. It rides reserved `obsvr_*` metadata until the ingest schema carries a column for it, and is stamped after caller-supplied metadata so a key collision cannot overwrite sealed evidence. Honest limits: MCP `call_tool` carries only `{name, arguments}` and the SDK retains descriptor *hashes* from discovery rather than descriptors, so on that path the descriptor half is the empty digest — the record commits to the name and arguments, which is what the producer actually saw, not to descriptor content it never held. Blocked tool calls are stamped too. A value neither language can canonicalize identically (integers past 2^53, exponent forms) makes the field **absent** rather than wrong, because sealed evidence cannot be reissued.
- **De-obfuscation scanning is opt-in and bounded.** With `deobfuscation: { enabled: true }` (both SDKs), the builtin scanners also see decoded/stripped views of the text — base64/hex/percent decoding, zero-width/bidi stripping, homoglyph folding, HTML-comment stripping, and CSS-hidden / `aria-hidden` markup stripping — mirroring the obsvr gateway's normalizer (shared vectors in `conformance/fixtures/deobfuscation.json`). It is bounded (64 KiB input, ≤6 views, decode depth 1) and defeats *those specific* encodings only: an encoding outside this set (double encoding, compression, novel wrappers) is not decoded, so this strengthens detection without claiming completeness. A hit found only in a view has no locatable span in the raw text, so a `redact` policy **escalates to block** on pre-delivery paths (a "redacted" record whose payload actually went through intact would be a false compliance record), and stored copies become a whole-text `[REDACTED:obfuscated]` placeholder. Events seal which view caught the payload (`security_normalized` / `response_pii_via`). Off by default because enabling it can turn previously-allowed calls into blocks.
- **An exception inside any detector layer never reaches your application as an unhandled error.** Every in-process detector — builtin PII scan, canary, de-obfuscation views, multi-turn injection, policy floor, policy rules, session taint, tool-result scan — resolves its own failures at one declared point per language, on every path that runs them, in both SDKs. The failure is counted in a `detector_errors` key on the fleet-status poll (its own key: a lost enforcement layer and an undelivered event are different operational stories) and recorded on that call's own signed event under reserved `obsvr_telemetry.detector_failure`, naming the layer, the resolution, and the phase — never a second event, so one governed call still means one audit record. What the resolution *is* depends on what was lost, and the differences are deliberate:
  - **A layer that could not DECIDE, or could not RUN at all, resolves by `failMode`** — open by default (the call proceeds with that layer's enforcement lost for it), closed if you opted in. A detection failure means the SDK does not know whether sensitive content is present. The same holds when a layer has nothing left to decide *with*: a quota rule whose counter store is full of live windows cannot say whether that scope is within its limit. Both are the same bounded risk you choose.
  - **The floor class fails CLOSED regardless of `failMode`.** A crashed `policy_floor` or `canary` layer blocks the call rather than waving it through ungoverned — a floor that cannot run is the strongest possible form of "cannot guarantee", and this is a feature worth stating plainly rather than a gap: obsvr can stop a call, because that is the product.
  - **A redaction that could not be APPLIED fails CLOSED regardless of `failMode`.** Once a scan has found something and policy has said remove it, the uncertainty is gone: forwarding would transmit to your provider exactly the content the SDK was told to strip, so the call is refused instead. The event says `blocked`, drops any `redacted` claim, and re-files the detected types as the reason for the refusal — an event asserting a redaction that did not happen would be worse than none.
  - **After the provider has answered, nothing is withheld from your application** — not even for the floor class, because blocking cannot un-produce an answer that already exists, and the SDK never mutates the value returned to the caller. What fails closed there is the *stored audit copy*: it becomes `[UNSCANNED:detector_error]`, deliberately unlike the `[REDACTED…]` markers, with `stored_unscanned: true` on the event, because "we could not scan this" and "we scanned it and removed something" are different facts and storing unvetted content in an evidence record would be fake enforcement.
  - **Check-only surfaces cannot block at all, whatever `failMode` says.** Shadow-rule evaluation is defined as never decision-affecting, and the policy-version hash is provenance rather than a control, so a defect in either is recorded and its own output lost while the call proceeds untouched.

  Every layer's posture for every failure state is declared in one table per language and pinned by `conformance/fixtures/fail_mode.json`; a detector that ships without an error channel, or a guard someone removes, turns a test in each SDK red rather than passing unnoticed. This is the same guarantee mature in-process SDKs make and by the same mechanism, and the generic caveats apply equally to all of them: a hang with no timeout channel, a stack overflow, or process-level OOM are not things any in-process library resolves. One obsvr-specific path is still open and is named rather than buried: the audit sender serializes host-supplied `metadata` with an unguarded `JSON.stringify`, so metadata carrying a throwing property getter, a throwing `toJSON`, or a circular reference can still surface from the sender rather than from a detector. It has its own tracked fix and its own posture decision. *(Until recently these layers had no error channel at all — an exception inside one propagated into the calling application, which was neither fail-open nor fail-closed but the absence of a decision. That gap is closed in both SDKs.)*


## Bypass surface (inherent, read this)

The SDK runs inside your process, under your control. This is a structural property, not a defect: an in-process library cannot force the surrounding code to call it. Anyone who can edit and deploy your application can choose not to invoke obsvr, and no in-process mechanism can prevent that. We do not claim otherwise.

What the SDKs do about it:

- Not calling `obsvr.init()`, or removing the wrap, removes coverage for the code that skipped it. There is no external attestation that the SDK was active for a given call. Assert `obsvr.isInitialized()` (TypeScript) / `obsvr.is_initialized()` (Python) at startup so a missing init fails loudly rather than silently.
- `disabled: true` in a production environment logs a prominent warning and emits a `governance_disabled` audit event, so the bypass is itself on the tamper-evident record.
- Quota and rate-limit rules evaluated in the SDK are per-process. N workers = N times the budget. Treat SDK quotas as soft limits; server-side rate limits at ingest are authoritative. The counter store is also bounded (10,000 scopes per meter, request and token budgets counted separately), and past the cap it refuses a new scope rather than evicting a live one: a counter still inside its window *is* the enforcement state, so evicting it would reset that scope's count, which a caller able to mint scope values could use to buy itself a fresh quota. Scopes already tracked keep counting, and slots free as their windows elapse. A scope the store could not admit is not enforced and never passes as a compliant call: under the default `failMode: 'open'` the call proceeds unmetered, under `'closed'` it is refused with reason code `QUOTA_UNMETERED`, and either way the call's own signed event carries `obsvr_telemetry.quota_unmetered` naming the rule, its scope, and which way it resolved.
- **Provider tool runners: the tools are now gated, the intermediate turns are not.** `chat.completions.runTools` and `beta.messages.toolRunner` are governed at the invocation (a refused run never reaches the provider, and each model call and tool call is audited). The tools themselves are plain callbacks the provider's SDK invokes directly, and the runner holds the raw provider client, so obsvr was not in the path of turns 2..N **or of the tool executions**. Measured, not inferred: with `sessionTaint: { enabled: true, action: "flag", destructiveTools: ["send_money"] }` and the session already tainted (`rule_id: sdk:session_tainted` confirmed on the preceding call's event), a runner invocation executed `send_money`. **Affected versions: none released** — nothing has been published to npm from this repository, so no installed build shipped with the tool executions ungated. **Repaired for tool execution.** obsvr now wraps each of the runner's tool callbacks in the same gate `obsvrGovernTool` applies, at the one point either runner will accept a substitution — before it is constructed, since both snapshot their tool set when the method is applied. Denied tools, allowlists and `destructiveTools` all reach a runner's tools, and a refused tool's callback does not run. Verified live on both runners against real providers, each paired with a policy-off control showing the same tool executing, and against a build of the previous commit that reproduces the bypass — so the assertion has a demonstrated false state rather than an assumed one. **Three limits remain, and they are limits rather than defects.** (1) The model calls the loop makes on turns 2..N are audited but **not** gated; reaching them means substituting the runner's own client, and a refusal arriving on turn 3 lands after earlier tools have had real side effects — a block after money moved is not a block, so that needs a stated position before it ships. (2) A hosted or server-side tool the provider executes on its own infrastructure exposes no local callback, so there is nothing to gate; those are named individually in `tool_gate_ungated_tools` on the run's start event. (3) The refusal shape differs by provider because the runners do: `beta.messages.toolRunner` invokes tools inside a `try`/`catch`, so a refusal returns to the model as an error tool result and the loop continues; `chat.completions.runTools` does not guard its tool call, so a refusal propagates and the run ends. Both fail closed. **Python ships no tool-runner integration at all**, so none of this applies there. The runner's own per-tool event still records `action_taken: "not_evaluated"` — it is an observation of the turn and not a second verdict — and `policy_not_evaluated.gate` distinguishes the two absences: `runner_observation` when the gate ran and the decision is on that tool's own `tool.call` event, `tool_gate` when no gate reached the call. `metadata.tool_gate` says `callback` or `absent`.
- **Python framework tool gates: all nine now refuse, and every one reports on what
  terms.** The tool allow/deny list, `destructiveTools` and the per-run step limit
  are implemented on every Python integration that can invoke a tool — but an implemented
  gate is not a reachable one, and reachability was measured per integration rather than
  inferred from the code being present. Per surface:

  - **`mcp` — enforces.** Binds `send_request`, the request path every client route into `tools/call` converges on, so it sits on the actual boundary rather than on the `call_tool` convenience above it.

  - **`autogen` — enforces** on its pre-send hook, re-probed live on two ag2 releases.
    It inspected only the first tool call in a message, so a denied name in a parallel
    batch executed; it now checks every call and charges the step budget per call. Two
    measured conditions travel with it. The hook fires on the SENDING agent, so
    registering on the initiating proxy alone leaves tool policy inert while still
    emitting a full audit trail. And **`max_steps` applies only when
    `patch_initiate_chat` is also installed** — that helper is what scopes the budget to
    one conversation, and the send hook has no other conversation boundary to observe.
    Without it the counter would be per thread for the life of the process: a second
    conversation would inherit what the first spent, and a long-lived process would
    exhaust the budget permanently, refusing every tool call after that. **The limit is
    therefore not applied when it cannot be scoped**, and each affected call records
    `action_taken: "not_evaluated"` naming the reason in
    `metadata.obsvr_telemetry.policy_not_evaluated`. That is a deliberate weakening: a
    control that decays into a blanket denial gets switched off by whoever is on call,
    leaving neither the control nor a record that it is gone, whereas an unenforced limit
    that says so stays visible and auditable. The allow/deny gate is unaffected and needs
    no run scope — this condition is confined to `max_steps`.

  - **`langchain` — enforces, and did not before.** Its gate sat only in
    `on_agent_action`, a callback the CLASSIC executor still fires but the graph runtimes
    never do, so on a modern install nothing was refused and no block event was emitted
    while a complete audit trail was still produced — the harder failure to notice,
    because it looks configured. The gate now also runs in `on_tool_start`, which the
    framework dispatches before the block guarding tool execution and outside the error
    handling that would otherwise convert a refusal into a tool result; the handler
    already set `raise_error`, so the surface was available and unused rather than
    absent. Re-probed live on **both** runtimes with a policy-off control on each, and
    against the previous commit, which still lets the denied tool run. Both pre-tool
    callbacks reach one shared gate, so a runtime delivering both does not charge the
    tool twice, and the credit for the second delivery is spent per call rather than
    latched for the life of the handler — latched, one run on the classic executor left
    every later `on_tool_start` returning before the gate, including every tool call of
    every later graph run, which deliver no other pre-tool callback.

    Three properties of the host decide what a refusal LOOKS like and none of them
    decides whether it happens. A tool node configured to swallow tool errors, an error
    middleware, or a retry middleware each convert the refusal into a message for the
    model and let the run continue; the tool body is not entered in any of them, because
    the raise happens before it. And the gate is defined synchronously on purpose: the
    framework's sync callback dispatcher logs and discards whatever a COROUTINE handler
    raises without consulting `raise_error` — an asymmetry it documents in its own
    source — and that dispatcher is the one an async agent reaches whenever the tool
    itself is synchronous.

  - **`langchain`'s step budget — enforces, and did not before, on either runtime.**
    `max_steps` counts tool calls per agent run, and the run was never created: the
    helper that recognised one read the `serialized` argument, which the graph runtime
    passes as a literal `None` at the graph root and at every node, and which the classic
    executor passes as `None` from `Chain.invoke`. With no run state, the budget saw a
    count of zero on every call and allowed all of them, while `agent_run_id` was empty
    on every event and loop detection and the output-topic check never ran either. A run
    is now recognised from the `name` keyword and the graph metadata the framework does
    populate, and a tool call walks the recorded chain ancestry to find it, because its
    immediate parent is the node that dispatched it rather than the run. Driven with a
    budget of two against a model asking for three, at `langchain-core` 1.0.0 and 1.5.3,
    on both runtimes: the run stops at two. This budget is not the framework's own
    `recursion_limit`, which counts graph supersteps rather than tool calls and cannot
    be substituted for it.

  - **`haystack` — enforces, on two different things.** `ObsvrGuard` is a pipeline
    `@component` that governs the PROMPT passing through it; a block raises out of
    `run()` and the pipeline stops, so the downstream generator is never reached —
    measured on the bytes the generator received, at `haystack-ai` 2.0.0 and 3.0.0.
    `install_tool_gate_hook()` is the tool gate, registered as the Agent's own
    `before_tool` hook. The Agent runs it before it resolves the pending tool calls and
    before it builds the executor that dispatches them in parallel, so a refusal removes
    the denied call and leaves its siblings pending — there is no sibling already in
    flight to race, which is why the gate is there rather than inside the tools. It rules
    on the CALL and not on a tool object, so tools handed to `run(tools=...)`, tools
    inside a `Toolset` that respawns per run, and tools rebuilt by a serialization
    round-trip are all covered by one registration. Allow/deny only; `govern_tool`
    carries the rest of the pre-call net and aborts the run instead of answering the
    model. Two limits stated rather than implied: the `before_tool` hook point does not
    exist at 2.0.0, where the installer refuses loudly instead of arming a gate nothing
    would consult; and a refusal raised out of a component reaches the caller of
    `pipeline.run()` as the host's own error type with obsvr's demoted to `__cause__`,
    carrying a snapshot of the pipeline inputs — so a prompt obsvr redacted out of its
    own record remains reachable on the exception object the caller holds. Match a
    refusal with `is_obsvr_block(exc)` rather than by catching obsvr's type.

    Two more, both measured rather than reasoned about. **The hook survives being
    written down and loaded back and a governed tool does not:** an Agent saved with
    `to_dict` and rebuilt with `from_dict` comes back with the hook and still refuses at
    zero executions, against a control reload with no mechanism that runs the denied
    tool and returns its payload — while a `govern_tool`-wrapped tool reloads
    successfully and ungoverned, because serialization records the tool's own
    `function` and the governor sits on `invoke`. The cycle does not raise, which is
    what makes it worth stating; a reload that failed loudly would be safe. Put
    `obsvr.integrations.haystack` on Haystack's deserialization allowlist for the hook
    to load back at all. **And a `ComponentTool` keeps the component it wraps as a live
    attribute**, so the gate covers the tool CALL while the wrapped object stays
    reachable: driven, a denied `ComponentTool` runs zero times through the Agent, and
    the same component invoked directly off the tool — or added to a Pipeline of its
    own — runs once and returns its payload, with nothing claiming to have blocked
    either route. That is the object-scope limit every tool gate here has, stated for
    this surface because a component is an unusually easy second reference to hold.

  - **`crewai` — enforces, through two independent pre-execution mechanisms**, because
    nothing hung off its step callback ever could: CrewAI delivers that callback only
    after the step it reports — with the tool name on the ReAct path (any model whose
    `supports_function_calling()` is False), with no tool name at all on the native
    function-calling path.

    **The hook gate** (`install_tool_gate_hook()`) registers on CrewAI's own
    `before_tool_call` hook system, consulted before every tool execution on BOTH
    executor paths. It refuses by that system's returned-sentinel contract (`False`),
    never by raising — the dispatcher swallows a raising hook and RUNS the tool, so the
    sentinel is the only contract that does not fail open — and the refusal reaches the
    agent as a blocked-tool observation while the run continues. Its record says
    `blocked` with `TOOL_DENIED`, which on this path is the truth. It is process-global
    (the only scope CrewAI offers for tool hooks), covers the agent-policy allow/deny
    list, and the installer feature-detects the hook system by attribute presence,
    failing loudly with a pointer at the tool governor on builds that lack it.

    **The wrapped tool** (`govern_tool`) gates inside the tool's own callable and needs
    no CrewAI API at all; a refusal there surfaces to the agent as a failed-tool
    observation.

    Driven live against a real provider on both paths, both mechanisms, with a
    side-effect-counting tool: a denied tool writes its marker ZERO times under either
    mechanism, exactly once on every paired allow control, and the two redden
    independently under mutation.

    **Six routes AROUND those two paths were then driven the same way** — delegation to a
    coworker, the crew's result cache, the hierarchical manager, `kickoff_async` /
    `kickoff_for_each` / a Task's `async_execution`, tools attached to a Task rather than
    an Agent, and streaming — each with a paired allow control proving the route reaches
    the tool, and each asserting the tool's payload is absent from what the caller
    RECEIVED rather than only that nothing executed. Every one is gated. Three findings
    from that sweep are worth stating plainly:

    1. **A result cache hit used to defeat the governed tool and look like a clean
       block.** The cache answers without entering the callable, so the side-effect count
       read zero — the number a perfect refusal produces — while the caller got the
       payload. A governed tool now declines caching. The hook gate was never affected,
       because CrewAI consults it after the cache read and its refusal replaces the
       cached result.
    2. **CrewAI renames tools before dispatch** (lowercased, camelCase split,
       non-alphanumerics to underscore), so a policy naming a tool the way CrewAI's own
       docs and prompts do — "Delegate work to coworker" — matched nothing: the denied
       tool ran and no record said a policy had been consulted. Both sides of the
       comparison are now normalized, so the list can be written either way. This
       affected any tool whose name was not already lowercase-with-underscores, not just
       the injected delegation tools.
    3. **`govern_tool` governs an OBJECT, not a name** — measured, not warned about. When
       only the delegating agent's tools were wrapped and the coworker's list still held
       the original, the coworker ran the denied tool. Wrap the tools every agent
       actually holds, or install the hook gate, which is process-global and has no such
       edge.

    With NEITHER mechanism installed the step callback stays an audit rail and says so: a
    denied tool that already ran on the ReAct path records `action_taken: "not_evaluated"`
    with the reason in `metadata.obsvr_telemetry.policy_not_evaluated`. It once recorded
    `blocked` there and raised, and the raise re-ran the task and the denied tool's side
    effect under the executor's retry loop; both halves were measured live before being
    fixed. The native path records no per-tool verdict at all.

  - **`pydantic_ai` — enforces, and WHICH mechanism you install decides the coverage.**
    `govern_agent(agent)` binds to the toolset the agent assembles for its tool manager,
    the single object every dispatch crosses, so every tool is governed however it was
    registered. `ObsvrToolset` overrides `call_tool`, which is the shape that refuses,
    but it governs only the toolset it wraps: an agent's own function toolset is a
    SIBLING of that one and a combined toolset dispatches each call to whichever sibling
    owns the tool, so a tool registered with `@agent.tool` ran under a policy that named
    it — a coverage gap, not a false record; nothing claimed to have refused it. Driven
    live at both ends of the declared range and, at the latest, against a real provider
    whose model chose to call the tool: zero side-effect writes on the deny legs, exactly
    one on every paired allow control. A refusal raises and is not a `ModelRetry`, so it
    ends the run rather than becoming a retry prompt the model can work around. It
    implements no step limit at all.

  - **`openai_agents` — enforces, as of the guardrail gate; the tracing processor
    beneath it records.** The processor's history is the instructive half and stays
    written down: its gate runs in `on_span_end`, after the tool has returned, and the
    exception it raised to stop the run was swallowed by the framework's
    trace-processor handling — the tool executed, its result reached the caller, and
    the event for that call carried `action_taken: "blocked"` with `TOOL_DENIED`, a
    false record rather than a coverage gap, which is the grade that made it
    release-blocking. That record is **fixed**: with no gate installed the event
    carries `action_taken: "not_evaluated"` and states in
    `metadata.obsvr_telemetry.policy_not_evaluated` that the decision arrives after
    the tool has already returned and cannot bind it. The step limit and loop
    detection on the processor report the same way, for the same reason — no
    tracing-processor hook can refuse a call, structurally. **Refusal now lives on
    the framework's own pre-invocation surface instead:** `attach_tool_gate` appends
    obsvr's `ToolInputGuardrail` to every function tool reachable from the agent
    (handoff targets included), the executor consults tool input guardrails before
    invoking the tool, and a denied tool is refused by the `reject_content` sentinel
    — the model receives the block message as the tool's result, the run continues,
    and the `blocked`/`TOOL_DENIED` record is true at the point it is written.
    `govern_tool` is the second, independent mechanism: its refusal raises and the
    run aborts as `UserError` chained from obsvr's typed error. Both driven live at
    openai-agents 0.19.0 and 0.19.2 — denied tool at zero side-effect writes with
    the payload absent from the run result, on the plain, streamed and handoff
    routes, paired allow controls at one write, the two mechanisms reddening
    independently under mutation — and the installer feature-detects BOTH framework
    halves (guardrail types and the executor's consult site) by attribute presence,
    refusing loudly on a build that would accept a registration no executor asks
    about. Beside either gate the processor defers: no `not_evaluated` beside the
    gate's own verdict.

  - **`llamaindex` — enforces on the TOOLS, and could not enforce anywhere else.**
    `govern_agent` binds to `get_tools`, where a workflow agent assembles the tools
    for a turn, and governs each through `govern_tool`; a denied tool's body is never
    entered. The callback handler is not and cannot be the gate: no tool event is
    dispatched to it at any current version, and the instrumentation dispatcher that
    replaced those events swallows every handler exception, so a refusal raised from
    one is a no-op. The framework then converts the gate's raise into an error tool
    result, so **the run continues and the signed record is what says a refusal
    happened** — below core 0.14.8 it is the ONLY thing that says so, because the
    framework discards the exception object there and a refusal and a crash are
    identical to the caller. No step limit is implemented on this surface.

  The step limit is unreachable wherever the gate's callback never fires. On `crewai` the
  callback does fire and the step check with it, but on the same after-the-fact terms as
  everything else that callback carries.

  **On Python the set is nine: `mcp`, `langchain`, `autogen`, `pydantic_ai`,
  `crewai` (via its hook gate), `haystack` (via its `before_tool` hook),
  `openai_agents` (via its guardrail gate), `llamaindex` (via `govern_agent`),
  and any `govern_tool`-wrapped tool — those are the surfaces on which a
  tool-policy decision means what it says.** On TypeScript the equivalent set is
  five: `mcp`, `obsvrGovernTool`, the LangChain handler, OpenAI Agents (via
  `attachToolGate`) and a provider tool runner's tools;
  `govern_tool` is `obsvrGovernTool`'s Python twin. No Python surface is known to
  emit a false `blocked` any longer — the tracing processor's and CrewAI's ReAct
  path were the two found, and both now record honestly.
- **Three surfaces the READMEs list as supported run far less policy than `obsvr.wrap()` does, and the difference is not a tool-gate question.** Measured layer by layer rather than read off the code, in both languages. **LangChain, LlamaIndex and the OpenAI Agents tracing processor** call the observe-only path: the PII scan runs and the stored copy is redacted, and that is all. The tracing processor joined that set when its model-call path was wired to the same net; before that it ran no policy pipeline whatsoever, so raw PII went into signed events at any sample rate while its two siblings stored a redacted copy. `policyRules`, the non-overridable `policyFloor`, the `onPreCall` hook, outbound redaction, the kill-switch/stale-policy integrity gate, the response-side scan, and PII **blocking** do not run there, and metering is opt-in. So a `pii_policy` of `{ssn: "block"}` refuses the call through `obsvr.wrap()`, Bedrock, Vertex, Vercel AI and MCP, and through any of those three the call goes out with the SSN in it while the event records the stored copy as redacted — the record is honest about what it stored and says nothing false about a block, but the control a reader configured did not fire. **The named compatibility wrappers** (`wrapAzureOpenAI`, `wrapTogether`, `wrapOpenAICompatible`) govern `chat.completions.create` and nothing else: counted against real clients, 17 governed method paths through `obsvr.wrap()` against 1 through these, with `responses.*`, `.parse`, `.stream`, `runTools`, `completions.create` and the whole assistants surface binding through ungoverned and unaudited. Both are silences rather than false records, and both are repairable by wrapping with `obsvr.wrap()` instead — it accepts the same clients. Put an enforcement decision on `obsvr.wrap()` or on MCP.

- **A customer `regex` rule is authored once and run by two engines, and they do not agree everywhere.** Measured, not inferred: 30 diverging verdicts across 17 construct families, driven through both SDKs' real validators and matchers. The split has two halves and only one of them is closable by rejection.

  **Closed — the validator now refuses these in BOTH languages**, so a rule that cannot mean the same thing in both is refused loudly (it fires the existing `sdk:rule_rejected` signal and lands on the audit record naming the id) rather than enforcing on half a fleet: Python-only named groups and backreferences (`(?P<x>…)`, `(?P=x)`), JS-only named groups and backreferences (`(?<x>…)`, `\k<x>`), inline flags (`(?i)`, `(?s)`, `(?m)`, `(?x)`, `(?a)`, and the scoped `(?i:…)`), possessive quantifiers (`a*+`), atomic groups (`(?>…)`), variable-width lookbehind (`(?<=USD\s*)`), the anchors `\A` `\Z` `\z` (anchors in Python, LITERAL characters in JS), any other alphabetic escape outside the shared set (`\h`, `\p{…}`, `\P{…}`), character-class set operations (`[\w--[0-9]]`), and `{,n}` (a quantifier in Python, three literal characters in JS). Pinned cross-language by `conformance/fixtures/regex_dialect.json`, in both directions — the fixture carries portable controls too, because a corpus in which every pattern is rejected would pass while proving nothing.

  **Open, and enumerated rather than allowlisted** — these are SEMANTIC splits with no syntactic marker, so rejecting them would mean banning the most common constructs in the language:

  | Construct | Python | JavaScript |
  |---|---|---|
  | `\d` `\D` | Unicode-aware — matches Arabic-Indic `٠١٢٣`, Devanagari `१२३` | ASCII `[0-9]` only |
  | `\w` `\W` | Unicode-aware — matches `日本語`, `café` | ASCII `[A-Za-z0-9_]` only |
  | `\s` `\S` | matches U+0085 NEXT LINE | does not |
  | `\b` | word boundary is Unicode-aware | ASCII-only, so `x\b` matches in `xé` in JS and not in Python |
  | `$` (no `m` flag) | matches before a trailing `\n` | end of input only |
  | `.` | matches U+000D and U+2028 | matches neither |

  Aligning these means choosing which engine's meaning wins and re-verifying every deployed rule against the change — a breaking change with its own migration, not a validator entry, and it is not made here. **These are deliberately NOT in `known-divergences.json`:** that catalog's own policy is that an entry whose allowed difference would cover an enforcement-verdict difference is invalid, and these are enforcement-verdict differences. They are open defects stated in the open, not accepted divergences.

  Practical consequence: a `regex` rule that must behave identically on both SDKs should stay inside `[a-z]`-style explicit classes, bounded quantifiers, groups, alternation, and fixed-width lookaround. `keyword`, `topic_deny` and the built-in PII scanners are unaffected — they do not use customer regex.

- **A duplicated install costs coverage, loudly.** If the SDK ends up in one process twice (installed directly and again as a transitive dependency), the first copy to `init()` claims a process-global slot and governs; the second logs a warning and stands down rather than both polling, both wrapping, and both emitting duplicate evidence for a single call. The copy that stood down does not wrap, so **clients wrapped only through it are not governed** — the warning says so and names the fix (deduplicate the dependency). Semantics are pinned in `conformance/fixtures/instance_guard.json`.

The durable guarantee is about what *was* captured, not about forcing capture: every event that reaches ingest is signed, verified, and countersigned. Coverage completeness is enforced operationally (deploy review, startup assertions, monitoring the `governance_disabled` signal), not cryptographically.

## Data handling

- PII detection runs in the SDK before transmission; `block` and `redact` modes prevent PII from ever being transmitted.
- Raw prompts/responses are hashed server-side; raw-content retention is optional and redaction can be applied before storage.
- The SDK enforces HTTPS for any non-localhost `ingest_url` (Python: set `OBSVR_ALLOW_HTTP=1` to explicitly opt out, e.g. behind a TLS-terminating proxy on a private network; TypeScript has no such opt-out, because that SDK reads no environment variable anywhere). The exemption is the **parsed hostname** — `localhost`, `127.0.0.1`, `[::1]` — in both SDKs. It used to be a substring test in TypeScript, so `http://localhost.evil.example.com` and `http://evil.example.com/localhost` were both accepted as plaintext audit destinations; that is fixed and pinned in both trees.
- **There is no default audit destination, in either SDK.** An unset `ingest_url` means events go nowhere: the SDK logs a loud no-delivery warning at `init()` and drops them. Governance itself is unaffected — policy still runs on every call — only delivery stops. **This is a change in the Python SDK.** Previously an unset `ingest_url` defaulted to `http://localhost:3000`, so a misconfigured Python process silently streamed governed events — including redacted prompt text on `blocked_call` events — to whatever happened to be listening on that local port, while the TypeScript SDK on the identical misconfiguration warned and delivered nothing. If you relied on that default in development, pass `ingest_url="http://localhost:3000"` explicitly. Both SDKs now also treat an unusable ingest URL as a counted delivery failure rather than an exception raised inside a background thread.
- **Customer-configured outbound endpoints are SSRF-guarded.** Every URL the SDK is told to POST to — the external policy backend (OPA/Cedar), the presidio analyzer/anonymizer endpoints **which receive the prompt/PII content being scanned**, and **`ingest_url`, which receives every prompt, every response and the `X-API-Key` header** — is validated: non-`http(s)` schemes are rejected, and the cloud-metadata / link-local range (`169.254.169.254`, all four IPv6 forms that route to it — IPv4-mapped, IPv4-compatible, NAT64 and 6to4 — plus `fe80::/10` and `fd00:ec2::254`) is **always** refused, closing the crown-jewel SSRF vector. The external backend additionally resolves the hostname and re-checks every resolved address before each call, and blocks private/RFC1918 ranges unless `allowPrivateNetwork` is set. Presidio, which is normally a **local sidecar**, permits private/loopback hosts (so `localhost:5002` works out of the box) while still always refusing the metadata range; its URL is validated statically at `init()`. `ingest_url` is validated statically at `init()` too, and exempts only the parsed loopback hosts from the private-range check, so a local collector works while `https://10.0.0.5:8443` and `https://[::169.254.169.254]/` are both refused.

  **The guard reaches all three endpoints as of the SSRF repair; before it, `ingest_url` was outside it.**

  - **What was wrong.** `ingest_url` ran no scheme allowlist and no address check at all: its validator returned early for any scheme that was not exactly `http`, so `file:///etc/passwd` was accepted, and the cloud-metadata endpoint over `https` was a valid audit destination in both SDKs. The plaintext spellings were refused, but by the HTTPS requirement above rather than by any address check — swap the scheme to `https` and the same address was accepted.
  - **Affected versions: none released.** Nothing has been published to npm or PyPI from this repository (see the beta notice in the [README](README.md)), so no installed build carried this behaviour. It was found and closed in development, before first publish.
  - **What closed it.** `ingest_url` now runs the same static validation as the presidio endpoints at `init()`: scheme allowlist, unconditional refusal of the cloud-metadata and link-local range in every spelling, and the private-range check with only the parsed loopback hosts exempt. Pinned in both trees.

  Honest limit, and it applies to presidio and to ingest alike: both guards are init-time and static (literal-IP + scheme), so neither resolves a hostname per-call — a hostname that later rebinds to a metadata IP is a residual TOCTOU. `init()` is synchronous in both SDKs and the resolving guard needs DNS, so closing this means either an async `init()` or a check on the delivery path; the external policy backend is the only endpoint that gets the resolving check today. Both URLs are operator-configured rather than runtime-attacker-controlled, which is why the static guard is the proportionate one — though on the zero-code Python entry point `ingest_url` comes from the `OBSVR_INGEST_URL` environment variable, so "operator-configured" means whatever set that variable.
- Customer-supplied regex rules pass a ReDoS validator (nested quantifiers, quantified alternation, and backreferences rejected; bounded input length) before they are ever executed.

## Known limitations under active work

- **Cross-instance dedup and rate limits.** Replay protection and rate limiting are per-process today; cross-replica replays are caught at verification time rather than rejected inline.
- **Sequence monotonicity at accept time** (currently detected at verification time).
- **Organization-level RBAC and per-key policy**, including deployment-level controls over `disabled: true`.

## Inherent (not "limitations" — structural properties)

- **SDK bypass.** An in-process library cannot force its host to call it. Coverage is enforced operationally, not cryptographically (see "Bypass surface").
- **Pre-emission process integrity.** Signatures prove order and post-emission immutability; they cannot attest to what happened inside your process before an event was emitted.
