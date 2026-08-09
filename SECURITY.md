# Security & Threat Model

This document states what the obsvr SDKs' security mechanisms guarantee, their exact boundaries, and how to report vulnerabilities.

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
| `sdk_session_id` | UUID for one signed chain segment; terminal post-sign delivery loss starts a fresh segment |
| `seq_no` | Monotonic counter within the session |
| `chain_format` | Signing format number (currently `3`; absent on pre-format-2 events) |
| `prev_sig` | Signature of the previous event (chain link) |
| `sdk_sig` | HMAC-SHA256 over `format|session|seq|timestamp|content_hash|decision_hash|prev_sig` (`decision_hash` present since format 3, the current format; formats 1–2 omit it) |

The content hash inside the signature payload is domain-tagged and **length-prefixed per field** (`sha256("obsvr:content/2" || 0x00 || u64be(len(prompt)) || prompt || u64be(len(response)) || response)`), so the prompt/response boundary is itself under the HMAC: the same bytes re-split at a different boundary produce a different digest. The previous format hashed the bare concatenation `sha256(prompt + response)`, which left the boundary unsigned — text could move between "what the user said" and "what the model said" without breaking verification. Chains signed under that format keep verifying, and the verifiers report `chainFormat: 1` for them so legacy evidence is never mistaken for boundary-bound evidence (see the migration note in `CHANGELOG.md`).

The signing algorithm is byte-for-byte identical in both SDKs, pinned by the shared vectors in `conformance/fixtures/signing_vectors.json` (which also pin the legacy format, frozen, and the boundary-collision pair that motivated the change). The ingest service re-derives the signing key from the stored API key, verifies `sdk_sig` on acceptance, rejects replays and stale/future-dated events, and **countersigns** each accepted event with a key that never leaves the server.

**Guarantees:**

- Modifying or deleting any captured event after acceptance is detectable (chain break).
- Reordering or dropping events within a session is detectable (sequence gaps) once an event has entered the chain. Sender-visible losses are declared by signed **gap markers** whose count and reason are inside the signature preimage. Queue-overflow losses happen before signing, so their marker is linked at the next position in the current session. Ingest rejection, permanent failure, and retry exhaustion happen after signing; the missing signature means that session cannot honestly continue, so the SDK starts a fresh session with the marker at sequence 1 and links future events behind it. Both `obsvr-verify` binaries report markers alongside the verdict. A chain can therefore be valid and incomplete simultaneously. The residual is explicit: markers remain in memory until delivered, and if the process dies or ingest also refuses/exhausts the marker, the remote bundle cannot contain that declaration; local counters and warnings are then the only evidence.
- A third party can verify the chain independently of obsvr using the exported events and the public verification tooling (`obsvr-verify`, shipped by **both** SDKs with identical modes, exit codes, and verdicts — a Python-only shop needs no Node toolchain to check its own evidence, and CI drives both binaries over one export to keep them from drifting). This offline check attests prompt/response **content** integrity, event **order**, and — since chain format 3 — the **decision fields** (`action_taken`, `action_reason`, `reason_code`, `rule_id`, `policy_version`, `model`, `provider`, `user_id`). `tenant_id`, token counts and cost remain outside the client preimage and are covered by the server countersignature. Chains signed under formats 1 and 2 verify as those formats and do **not** cover the decision fields; the verifier reports which format it checked, so a reader can tell what a given export's verdict actually attests to.
- `policy_version` pins the canonical structured-rule set and its declared resolution semantics (identical derivation in both SDKs, fixture-pinned in `conformance/fixtures/rules_hash.json`). It does not attest the complete effective evaluator: PII policy, policy floor, hooks, external-backend state, enforcement mode, and session state are recorded or configured through separate channels. Re-deriving a complete decision therefore requires those inputs as well as the structured rules.
- Approvals are pinned to the exact rule definition they were granted under (per-rule canonical hash) **and to the exact action** (a canonical digest of the rule, the rule's hash, the action name, the amount, the caller and target namespaces, and the subject). Editing a rule voids outstanding grants for it, and a grant issued for one call cannot be spent on a different call that happens to trip the same rule — one human approving a $50 transfer does not leave a live grant covering a $5,000,000 one. The digest deliberately does **not** cover the free-text prompt: an approved request and its retry differ in it more often than not, and a binding that voided itself on a whitespace change is one operators would switch off. The grant is re-checked after every layer that can delay the call (the customer hook's two-second budget, an external policy backend) and before the request goes out, so a grant revoked or expired mid-call authorizes nothing; the residual window is this library's own final assembly, which no in-process control can remove. Each pin only narrows — a grant that carries no action hash still satisfies — so an unbound grant is exactly as strong as its issuer made it. Pinned by `conformance/fixtures/approvals.json`. An opt-in blocking hold (`approval_wait_ms` / `approvalWaitMs`, default 0 — no waiting) polls the grant channel instead of refusing immediately; only an explicit, still-live grant lifts it, an expired hold blocks as `APPROVAL_TIMEOUT`, and enforcement degradation mid-hold aborts the wait with the block standing. A stated limit of the hold: the grant channel carries grants, not verdicts, so a human **denial** is indistinguishable from indecision client-side and surfaces as the same timeout — a deny cannot short-circuit the wait until a pollable per-request status exists server-side.

**Explicit non-guarantees:**

- **Client signing alone is not non-repudiation against a key-holder.** The SDK signing key is derived from the API key, so a party holding the API key could construct validly-signed *client* chains. This is why ingest adds a server countersignature with a key that never leaves the server: a key-holder cannot forge it, so they cannot fabricate an event that appears to have been accepted. What the client chain still cannot prove is (a) what happened *inside your process before emission*, or (b) the integrity of the fields left outside its preimage — since **chain format 3** the preimage is `format | session | seq | timestamp | content_hash | decision_hash | prev_sig`, and `decision_hash` covers `action_taken`, `action_reason`, `reason_code`, `rule_id`, `policy_version`, `model`, `provider` and `user_id`. **`tenant_id`, token counts and cost are still outside it**, so a party who can alter a stored event before ingest can still rewrite those without breaking the *client* chain; the server countersignature (over the full canonical event) is what seals them once accepted.

  **This non-guarantee used to be much wider, and the narrowing is the point.** Under formats 1 and 2 the decision fields were outside the preimage, which meant `action_taken` could be rewritten from `blocked` to `allowed` and `obsvr-verify` — run with the correct API key — still reported the chain valid. The server countersignature covered it, and this section said so, but the offline verifier is what a compliance officer actually runs, and it returned a clean result on a rewritten verdict history. Format 3 closes that. **Chains signed under formats 1 and 2 are not retroactively strengthened**: they verify as the format they were signed under, the verifier reports which, and on those chains a rewritten verdict remains undetectable — a fact pinned deliberately in `conformance/fixtures/signing_vectors.json` (`format2_verdict_rewrite_is_NOT_detected`) rather than left for a reader to discover.
- **Optional client-held device signing (Ed25519), for local non-repudiation.** The HMAC seal above proves integrity, not non-repudiation: it is keyed from the API key, so the customer, obsvr, and anyone who has ever seen the API key can all mint a complete valid chain. Set `device_signing_key_file` / `deviceSigningKeyFile` to an operator-generated Ed25519 private key and every signed event ALSO carries a `device_sig` over the **same** preimage the HMAC covers, plus a `device_key_id` (`sha256(public key)[:16]`, derived). Verify it with `obsvr-verify --device-pubkey <pinned key>`, which pins out of band rather than trusting the inline key id: an event signed by an unpinned key is reported **foreign** ("Device key unknown"), never trusted on first use; a missing seal on a chain you pinned keys for is a **break**, because pinning asserts the expectation and a stripped seal must not read as clean; and the tier runs **without** the API key, so device-only verification attests content, order and the decision fields under the public key alone, sharing no secret. This is the seal that catches the attack the HMAC cannot: an API-key holder who re-mints the whole chain forward from genesis produces a chain that passes HMAC verification and fails the device tier, because he lacks the device key. **What this does and does not buy.** It is real non-repudiation against everyone who does not hold the device key — but the key lives on the same machine as the SDK, so with the agent at the host's uid this is tamper-**evident**, not tamper-proof, and a device tier is opt-in precisely because most deployments' threat model is the third party in transit, which the HMAC already covers. **The SDK never generates the key** — a configured key that cannot be read or cannot sign refuses at init, because a verifier or signer that mints key material would report every genuine record as foreign on a fresh machine. Python needs an Ed25519 backend for signing (`pip install "obsvr-sdk[crypto]"`, or PyNaCl); TypeScript uses `node:crypto` and needs nothing, and the Python verifier reports "device keys pinned but no backend" as its own outcome rather than folding it into valid or tampered. **The server countersignature is still the stronger seal where you trust ingest** — this is the option for deployments that want non-repudiation *without* trusting ingest, and the two compose. Signature bytes are pinned cross-language in `conformance/fixtures/signing_vectors.json` (`device_signatures`, `device_chain`).
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
  An event's `sdk_version` and the package corpus pin are useful provenance
  hints, but `sdk_version` is not in the client signature preimage and therefore
  cannot establish which build produced an export before server countersigning.
  Adding a real Endorser role
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
  `policyStalenessBudgetMs` (`policy_staleness_budget_s` in Python, in seconds) and the enforcement-integrity gate are a freshness
  mechanism for the Reference Values rather than for the Evidence — they bound
  how stale the policy in force may be before enforcement degrades.
- **Topology: passport model, with a background-check escape hatch.** Evidence
  is appraised and turned into a durable artifact that is later *presented* to
  a Relying Party, which is the passport shape (RFC 9334 §5.1) — the auditor is
  never in the request path. The escape hatch is why `obsvr-verify` ships here:
  a Relying Party that does not want to trust the Attestation Result can
  re-appraise the raw Evidence itself, offline, with no obsvr service involved.

## Enforcement semantics: what blocking means

- **Pre-call policies are real enforcement on the documented enforcing surfaces.** The direct-client wrappers, provider/infra adapters, MCP boundary, and explicit tool governors run their applicable PII, rule, and hook layers before dispatch, so a blocked call never leaves that boundary. LangChain, LlamaIndex, and OpenAI Agents tracing callbacks are observe-only on model calls and are not included in this guarantee.
- **Streaming responses are audit-time, not block-time, for post-call policies.** Once a stream is allowed to open, tokens reach the caller as they arrive. Response scanning runs after stream completion and is recorded, but cannot un-send tokens. Pre-call checks still run before the stream opens.
- **Fail mode is open by default.** If a pre-call hook times out or throws, the call is allowed and the failure is recorded (`hook_timeout` / `hook_error`). Set `failMode: 'closed'` (TypeScript) / `fail_mode="closed"` (Python) for policies that must never fail open. Every governance layer's posture for every failure state (timeout, error, degraded) is declared in one table per language and pinned by `conformance/fixtures/fail_mode.json`, so the posture is reviewable in one place rather than re-derived per code path. That includes the in-process detector layers, whose posture is no longer merely declared but resolved — see "An exception inside any detector layer never reaches your application as an unhandled error" below, which also covers the cases where the answer is deliberately *not* `failMode`.
- **A blocked call raises a typed error.** `ObsvrPolicyError` (both SDKs) carries a stable `type`, a `reason_code` from the closed registry, the deciding `rule_id`, and the decision metadata, constructed at one choke point per language. Callers can distinguish a deliberate refusal from a provider or transport failure without string-matching a message; an unrecognized reason category yields a documented fallback class rather than an untyped throw.
- **Backend outage does not stop enforcement.** Policy rules are cached in the SDK and keep enforcing; only rule *updates* degrade during an outage. Event delivery is queued and retried: transient failures (408/429/5xx/network) retry under jittered exponential backoff; permanent failures (other 4xx) are discarded and counted. Ingest rejection, permanent failure, and retry exhaustion each arm a reasoned signed marker in a fresh chain segment. Events the server accepts the request for but refuses individually — per-event rejects inside a `2xx` batch response — are counted in their own `dropped_rejected` bucket in **both** SDKs and reported on the fleet-status poll, and are never counted as sent: "we never delivered it" and "the server received it and refused it" are different stories in a coverage report. One 4xx is deliberately **not** a drop: a `409` whose body says `duplicate_event` means a retry raced a lost `2xx` and the event is already durably recorded, so it counts as sent (single-event, whole-batch, and per-event alike) — counting it as lost would fabricate a coverage gap for evidence that exists. Only that exact code: a `409 sequence_fork` means the chain position belongs to a *different* signature and stays a failure, and a `409` whose body cannot be read is never absorbed. A marker that itself cannot be delivered is counted and warned about but never replaced recursively; there is no durable dead-letter sink in the SDK.
- **Monitor mode cannot disarm the integrity gate.** `enforcement_mode="monitor"` converts a final block into an allow whose `shadow_outcome` carries the would-be verdict, with the whole pipeline still running and every event still emitted — but the enforcement-integrity gate (kill switch / fail-closed staleness) and canary-leak blocks enforce in both modes, and the gate's verdict is **re-derived at the moment of conversion** rather than trusted from an earlier snapshot, so monitor mode is never a way to defeat a revoked key. Converted events are exempt from allowed-call sampling (the would-be verdict is never dropped, even at `sample_rate=0`), and `explain()` keeps predicting enforce-mode behaviour. A policy-**floor** block that came from a floor rule MATCHING is a would-be verdict like any other and converts too — the operator's own `enforcement_mode` flip is not one of the vectors the floor is guaranteed against — so a floor-bearing deployment can still stage a monitor rollout, with the would-be floor block on `shadow_outcome`. What monitor mode does **not** convert is a floor-class layer that could not RUN: a crashed `policy_floor` or `canary` blocks in every mode (see the fail-closed entry below), because "we could not evaluate the floor" is not a verdict to record.
- **TypeScript stream `skip` never skips pre-call policy.** `streamingMode: "skip"` opts an enforce-mode deployment out of wrapping and emitting an allowed stream, after the pre-call block/redaction boundary has run. Monitor mode overrides that evidence opt-out and emits the governed stream event.
- **Shadow rules are provably inert.** A rule in shadow mode records what it would have done but never affects decisions, content, quotas, or approvals; the active decision is byte-identical with shadow rules present or absent (pinned by `conformance/fixtures/eval_semantics.json`). Shadow evaluation is also first-match regardless of a declared `deny_wins` resolution — deliberate and pinned — so a shadow record beside a deny-wins deployment reports the first-match reading of the ruleset, not the active resolution's.
- **Prompt-injection detection is pattern-based.** It catches known injection phrasings; it is a detection signal, not a proof of prevention. Structural controls (tool allowlists, action gates) are the reliable defense.
- **The anti-tamper policy floor cannot be weakened by customer rules, hooks, or remote policy sync.** `policyFloor` / `policy_floor` rules ignore per-rule disable and shadow flags; a customer hook cannot erase their block; and a remote `/policies` response cannot replace the operator-declared floor or locally declared rules. A matching floor block converts to a recorded would-be block in operator-selected monitor mode, while a floor layer that cannot run fails closed in both modes. The floor hash is stamped on every emitted event from a path where the floor ran. Prompt-floor enforcement applies at the direct-client wrapper, the pre-call provider/infra adapters, MCP, and `evaluate()` / `explain()`; it does **not** apply to the observe-only LangChain, LlamaIndex, or OpenAI Agents tracing model callbacks. TypeScript records `floor_override_ignored` wherever its integration pre-call floor runs; Python records that override-attempt detail on the wrapper path, while its other enforcing paths still preserve the block. Response-floor behavior is surface-specific: the base wrapper redacts only the stored audit copy; Python Bedrock and Vertex can also rewrite a non-streaming value returned to the caller; streamed output cannot be recalled; and the TypeScript infra integrations and MCP have no response-side floor pass. A floor rule with `action: "redact"` fails closed to a pre-call block when the SDK cannot guarantee an outbound rewrite. The floor is operator-declared and protects only calls that reach a documented enforcing boundary.
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
  - **TypeScript, measured independently from Python.** `obsvrGovernTool` enforces at the wrapped tool's execute boundary, and the LangChain handler enforces in pre-execution `handleToolStart`. MCP binds the `request` route that `callTool`, hand-built `tools/call` frames, and task-stream calls use; a task facade retained before governance is repaired onto the governed Proxy and is driven at zero executions for a denial. A raw `request` / `requestStream` function explicitly bound and retained before governance cannot be revoked later. On openai-agents, `attachToolGate` enforces the allow/deny list but not the destructive-tools set; use `obsvrGovernTool` for that control. The tracing processor records only. LlamaIndex and Vercel AI carry no tool gate of their own and use `obsvrGovernTool` per tool.
  - **Where the names come from.** Membership is exact names only (a capability set that pattern-matched would be a detector again) and costs one set-membership test at the tool gate. The list is no longer the only source: a discovered MCP tool whose descriptor declares `annotations.destructiveHint: true` joins the set by itself, so a deployment that enabled the latch and configured no list still gets a capability gate rather than silently getting none. The hint is admitted in ONE direction: it can only ADD. A `destructiveHint: false` is a safety claim from the tool server — the untrusted party the latch exists to defend against — so it is ignored, and an ABSENT hint is likewise treated as non-destructive, which is the compatible default and is stated here rather than left implied (most deployed servers publish no annotations, and reading silence as destructive would turn `flag` into a blanket block for them). A descriptor the SDK cannot read at all resolves to destructive, because an unreadable field creates the same escape as a falsified one. An operator entry always applies regardless of what a descriptor says, hints are recorded per governed client and never un-recorded by a later listing, and `honorDestructiveHints: false` restricts the set to the configured list alone. The whole table — `(descriptor_hint, operator_list, taint_state) → decision`, plus how the hint itself is read — is pinned cross-language in `conformance/fixtures/session_taint.json` (`tool_gate_cases`, `descriptor_hint_cases`).
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
  - **After the provider has answered, a detector failure cannot un-produce the answer.** On the base wrapper, the returned value is not mutated and the stored audit copy fails closed to `[UNSCANNED:detector_error]` with `stored_unscanned: true`. Python Bedrock and Vertex have an additional non-streaming response-rewrite capability when scanning succeeds; streamed tokens still cannot be recalled. The failure marker distinguishes unscanned content from content that was successfully redacted.
  - **Check-only surfaces cannot block at all, whatever `failMode` says.** Shadow-rule evaluation is defined as never decision-affecting, and the policy-version hash is provenance rather than a control, so a defect in either is recorded and its own output lost while the call proceeds untouched.

  Every layer's posture for every failure state is declared in one table per language and pinned by `conformance/fixtures/fail_mode.json`; a detector that ships without an error channel, or a guard someone removes, turns a test in each SDK red rather than passing unnoticed. This is the same guarantee mature in-process SDKs make and by the same mechanism, and the generic caveats apply equally to all of them: a hang with no timeout channel, a stack overflow, or process-level OOM are not things any in-process library resolves. The one obsvr-specific path that was open outside a detector is closed: the audit sender measures host-supplied `metadata` against its size budget before deciding whether to trim it, and metadata carrying a throwing property getter, a throwing `toJSON`, a `BigInt` or a circular reference made that measurement raise on the caller's own synchronous emit path. A bag the sender cannot measure is now treated as OVER budget and takes the trim that already exists for an oversized one, so the grouping keys (`trace_id`, `agent_run_id`, the span envelope) survive and the event is still delivered. Both SDKs, same rule; Python's `default=str` had covered a non-serializable value but not a cycle. *(Until recently these layers had no error channel at all — an exception inside one propagated into the calling application, which was neither fail-open nor fail-closed but the absence of a decision. That gap is closed in both SDKs.)*


## Bypass surface (inherent, read this)

The SDK runs inside your process, under your control. This is a structural property, not a defect: an in-process library cannot force the surrounding code to call it. Anyone who can edit and deploy your application can choose not to invoke obsvr, and no in-process mechanism can prevent that. We do not claim otherwise.

What the SDKs do about it:

- Not calling `obsvr.init()`, or removing the wrap, removes coverage for the code that skipped it. There is no external attestation that the SDK was active for a given call. Assert `obsvr.isInitialized()` (TypeScript) / `obsvr.is_initialized()` (Python) at startup so a missing init fails loudly rather than silently.
- `disabled: true` in a production environment logs a prominent warning and emits a `governance_disabled` audit event, so the bypass is itself on the tamper-evident record.
- Quota and rate-limit rules evaluated in the SDK are per-process. N workers = N times the budget. Treat SDK quotas as soft limits; server-side rate limits at ingest are authoritative. The counter store is also bounded (10,000 scopes per meter, request and token budgets counted separately), and past the cap it refuses a new scope rather than evicting a live one: a counter still inside its window *is* the enforcement state, so evicting it would reset that scope's count, which a caller able to mint scope values could use to buy itself a fresh quota. Scopes already tracked keep counting, and slots free as their windows elapse. A scope the store could not admit is not enforced and never passes as a compliant call: under the default `failMode: 'open'` the call proceeds unmetered, under `'closed'` it is refused with reason code `QUOTA_UNMETERED`, and either way the call's own signed event carries `obsvr_telemetry.quota_unmetered` naming the rule, its scope, and which way it resolved.
- **Provider tool runners: local tools are gated; intermediate model turns are not.** The TypeScript `chat.completions.runTools` and `beta.messages.toolRunner` integrations govern the initial invocation and wrap each local callback with `obsvrGovernTool` before the provider snapshots its tool set. Denied tools, allowlists, and `destructiveTools` therefore reach local runner tools, and a refused callback does not execute. The repair was already present in published 0.11.1; Python first adds Anthropic Messages runner coverage in 0.11.2 with its local runnable tools governed before dispatch registration. **Three limits remain.** (1) Model calls the TypeScript runners make on turns 2..N are audited but **not** gated; a refusal after an earlier tool side effect would be too late, so those turns are not described as pre-call enforcement. (2) Hosted or server-side tools expose no local callback to wrap and are named in `tool_gate_ungated_tools`. (3) Refusal shape follows the provider: Anthropic converts a callback refusal to an error tool result and continues, while OpenAI propagates it and ends the run. Both prevent the local callback body from running. The runner's observation event records `action_taken: "not_evaluated"`; the actual decision is on the tool's own `tool.call` event, with `policy_not_evaluated.gate` and `metadata.tool_gate` distinguishing a governed callback from an absent gate.
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
    `@component` that governs the PROMPT passing through it; a block emits only a
    terminal safe branch and omits the connected prompt output, so the downstream
    generator never becomes runnable — measured at `haystack-ai` 2.0.0 sync and
    3.0.0 sync/async with paired controls that do reach the generator.
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
    would consult. The prompt guard deliberately does not raise, because Haystack
    attaches component inputs to `PipelineRuntimeError`; callers inspect the returned
    `blocked` branch instead. The caller-owned input and host-level content tracing
    still exist before an in-graph guard can act. `is_obsvr_block(exc)` remains for
    abort-mode Agent tool governance, which uses an exception boundary.

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
    live at both ends of the declared range and, at the highest tested release, against a real provider
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
- **Three supported framework surfaces are observation rails, not model-call enforcement points.** Measured layer by layer in both languages, **LangChain, LlamaIndex, and the OpenAI Agents tracing processor** run the storage-only PII pass on model calls. They do not run `policyRules`, `policyFloor`, `onPreCall`, outbound redaction, the kill-switch/stale-policy gate, or PII blocking. A configured block therefore does not stop the provider call on those callback/processor paths; the event records `action_taken: "not_evaluated"` and storage provenance under `metadata.obsvr_telemetry`. Use a governed provider wrapper for model-call enforcement and the separately graded tool gates for tool execution.
- **Named TypeScript compatibility wrappers use the generic governed-path table.** `wrapAzureOpenAI`, `wrapTogether`, and `wrapOpenAICompatible` delegate to `obsvr.wrap()`'s method resolver and enforcement pipeline, adding endpoint attribution rather than a narrower one-method gate. The generic exclusions remain: `completions.create` and the assistants surface are still outside the table.

- **A customer `regex` rule is authored once and run by two engines, and they do not agree everywhere.** Measured, not inferred: 30 diverging verdicts across 17 construct families, driven through both SDKs' real validators and matchers. The split has two halves, they close by different mechanisms, and both are now closed.

  **Closed — the SYNTAX half: the validator refuses these in BOTH languages**, so a rule that cannot mean the same thing in both is refused loudly rather than enforcing on half a fleet. What "loudly" means depends on which tier declared it: a `/policies` poll drops it and fires the `sdk:rule_rejected` signal, which lands on the audit record naming the id; a rule declared in `init()` makes `init()` throw, naming the index and the reason. Only the poll tier ran this validator until this release, so a refused pattern declared in code used to enforce nothing in silence: Python-only named groups and backreferences (`(?P<x>…)`, `(?P=x)`), JS-only named groups and backreferences (`(?<x>…)`, `\k<x>`), inline flags (`(?i)`, `(?s)`, `(?m)`, `(?x)`, `(?a)`, and the scoped `(?i:…)`), possessive quantifiers (`a*+`), atomic groups (`(?>…)`), variable-width lookbehind (`(?<=USD\s*)`), the anchors `\A` `\Z` `\z` (anchors in Python, LITERAL characters in JS), any other alphabetic escape outside the shared set (`\h`, `\p{…}`, `\P{…}`), character-class set operations (`[\w--[0-9]]`), `{,n}` (a quantifier in Python, three literal characters in JS), and `\S` inside a character class that does not also hold `\s` (see the residuals below). Pinned cross-language by `conformance/fixtures/regex_dialect.json`, in both directions — the fixture carries portable controls too, because a corpus in which every pattern is rejected would pass while proving nothing.

  **Closed — the second half, by normalization rather than by rejection.** `\d`
  `\w` `\s` `\b` `$` and `.` are SEMANTIC splits with no syntactic marker, so
  refusing them would mean refusing the most common constructs in the language.
  They are aligned instead: **ECMAScript's meaning is the meaning**, and the
  Python SDK rewrites a customer pattern to that meaning at its one compile call.
  ECMAScript wins because Python can express its semantics exactly (`re.ASCII`
  plus a mechanical rewrite) while the reverse is not true — a Unicode-aware
  `\b` has no JavaScript spelling short of lookaround built from `\p{...}`
  escapes. TypeScript compiles in `u` mode so both engines consume astral
  characters as code points; the shared validator rejects the legacy-only
  syntax that mode no longer accepts.

  | Construct | was, in Python | is now, in both |
  |---|---|---|
  | `\d` `\D` | Unicode-aware — matched Arabic-Indic `\u0660\u0661\u0662\u0663`, Devanagari `\u0966\u0967\u0968` | ASCII `[0-9]` |
  | `\w` `\W` | Unicode-aware — matched `\u65e5\u672c\u8a9e`, `caf\u00e9` | ASCII `[A-Za-z0-9_]` |
  | `\s` `\S` | matched U+001C–U+001F and U+0085; did not match U+FEFF | the ECMAScript WhiteSpace + LineTerminator set, exactly |
  | `\b` `\B` | word boundary was Unicode-aware | ASCII word boundary |
  | `$` (no `m` flag) | also matched before a trailing `\n` | end of input only |
  | `.` | matched U+000D, U+2028 and U+2029 | excludes all four ECMAScript LineTerminators |

  Measured per codepoint across the whole BMP in both engines, before and after.
  Two findings are worth stating because they contradict the obvious approach.
  `re.ASCII` alone closes `\d` `\w` `\b` **exactly** and makes `\s` **worse** —
  from 6 disagreeing codepoints to 19 — because the ECMAScript whitespace set is
  neither of Python's; `\s` is therefore rewritten to an explicit class rather
  than left to a flag. And the `.` row above used to name U+000D and U+2028 only:
  U+2029 PARAGRAPH SEPARATOR diverged just as far and is now covered and pinned.

  **The remaining portability restriction is refused, not divergent:**

  - **`\S` inside a character class is REFUSED rather than aligned**, in both
    languages, because a negated shorthand cannot be expressed inside a positive
    class without class subtraction, which Python `re` does not have. `[\s\S]`
    is exempt and provably so — the rewritten `\s` covers exactly the ASCII
    spaces the ASCII `\S` omits, so it denotes every character in both engines —
    which keeps the dotall idiom legal. `[\S]`, `[a\S]` and `[^\S]` are
    refused loudly — by the `sdk:rule_rejected` signal on the poll tier, by an
    `init()` throw on the declared tier; the fix is one character (`[^\s]`).
  The former code-unit/code-point split is closed: TypeScript uses `u` mode,
  and `^.$`, `^[^a]$`, and `^[\s\S]$` now match U+1F600 in both SDKs. The
  validator moved with that change and refuses legacy identity escapes,
  unmatched braces/brackets, braced codepoint escapes, and surrogate escapes
  in both languages. No enforcement-verdict difference is accepted in
  `known-divergences.json`.

  Both halves are pinned cross-language by `conformance/fixtures/regex_dialect.json`
  (`cases` for the syntax verdicts, `semantic_cases` for the match verdicts) and
  by `scripts/check-regex-dialect-parity.mjs`, which runs the cross product of a
  pattern corpus and an input corpus — 3,432 pattern/input pairs, built from the
  codepoints the two engines were measured to disagree on — through both real
  matchers and fails on any divergence.

  Practical consequence: a `regex` rule now behaves identically on both SDKs for every construct either validator accepts. `[a-z]`-style explicit classes, bounded quantifiers, groups, alternation and fixed-width lookaround remain the most predictable way to write one. `keyword`, `topic_deny` and the built-in PII scanners are unaffected — they do not use customer regex.

- **A duplicated install costs coverage, loudly.** If the SDK ends up in one process twice (installed directly and again as a transitive dependency), the first copy to `init()` claims a process-global slot and governs; the second logs a warning and stands down rather than both polling, both wrapping, and both emitting duplicate evidence for a single call. The copy that stood down does not wrap, so **clients wrapped only through it are not governed** — the warning says so and names the fix (deduplicate the dependency). Semantics are pinned in `conformance/fixtures/instance_guard.json`.

The durable guarantee is about what *was* captured, not about forcing capture: every event that reaches ingest is signed, verified, and countersigned. Coverage completeness is enforced operationally (deploy review, startup assertions, monitoring the `governance_disabled` signal), not cryptographically.

## Data handling

- On enforcing surfaces, PII detection runs before transmission: `block` refuses the call and `redact` rewrites what is sent — the outbound message content on the model-call path, and the tool's own ARGUMENTS on `govern_tool`, the MCP `tools/call` gate and the PydanticAI toolset, so a governed tool writes the scrubbed value to its file, row or third-party API. A redaction the SDK cannot carry out blocks the call rather than forwarding what it was told to remove, and the event drops every `redacted` claim in that case (`outbound_redaction_blocked_compliance`); the rewritten values are re-scanned before the call proceeds, so the verdict rests on the content being gone rather than on the attempt having been made. This guarantee does not extend to observe-only integrations, which are graded separately in the README's layer table — there `redact` scrubs the stored copy and the provider receives the original. One further scope note, because it was wrong in Python until this release: six of the nineteen PII types — `name`, `person`, `address`, `location`, `medical`, `national_id` — have no built-in regex pattern and can only be located by the Presidio analyzer. Python ran the analyzer over the STORED copy alone and rewrote the outbound request with the regex tier, so a `redact` verdict on one of those six produced an event reading `redacted` while the value went to the provider intact. The outbound rewrite now asks Presidio when and only when one of those six is what policy named, and refuses the call if the anonymizer does not answer.
- Raw prompts/responses are hashed server-side; raw-content retention is optional and redaction can be applied before storage.
- The SDK enforces HTTPS for any non-localhost `ingest_url` (Python: set `OBSVR_ALLOW_HTTP=1` to explicitly opt out, e.g. behind a TLS-terminating proxy on a private network; TypeScript has no such opt-out, because that SDK reads no environment variable anywhere). The exemption is the **parsed hostname** — `localhost`, `127.0.0.1`, `[::1]` — in both SDKs. It used to be a substring test in TypeScript, so `http://localhost.evil.example.com` and `http://evil.example.com/localhost` were both accepted as plaintext audit destinations; that is fixed and pinned in both trees.
- **There is no default audit destination, in either SDK.** An unset `ingest_url` means events go nowhere: the SDK logs a loud no-delivery warning at `init()` and drops them. Governance on a documented enforcing boundary is unaffected; only delivery stops. Python no longer defaults an unset destination to `http://localhost:3000`; development collectors must be configured explicitly. Both SDKs treat an unusable ingest URL as a counted delivery failure rather than an exception raised inside a background thread.
- **Customer-configured outbound endpoints are SSRF-guarded.** Every URL the SDK is told to send to — the external policy backend (OPA/Cedar), the TypeScript-only `hardDeletion.endpoint`, the Presidio analyzer/anonymizer endpoints, and `ingest_url` — rejects non-`http(s)` schemes and always refuses cloud-metadata and link-local destinations. Both SDKs' external-backend production transports resolve once, reject the complete snapshot if any address is private or metadata, pin a fresh socket to an approved address, preserve Host/SNI, and do not follow redirects; `allowPrivateNetwork` / `allow_private_network` admits ordinary private ranges but never metadata/link-local. The injected transport seams are trusted and must supply equivalent pinning. Presidio normally permits private/loopback sidecars while still refusing metadata. Ingest and hard-deletion URLs are validated statically at configuration time; they do not use the external backend's pinned connector.

  **The guard reaches all four endpoints as of this release; `ingest_url` came inside it at the SSRF repair, and `hardDeletion.endpoint` — a fourth customer-configured URL carrying a DELETE with the `X-API-Key` header — came inside it now.**

  - **What was wrong.** `ingest_url` ran no scheme allowlist and no address check at all: its validator returned early for any scheme that was not exactly `http`, so `file:///etc/passwd` was accepted, and the cloud-metadata endpoint over `https` was a valid audit destination in both SDKs. The plaintext spellings were refused, but by the HTTPS requirement above rather than by any address check — swap the scheme to `https` and the same address was accepted.
  - **Affected versions: none released.** Published 0.11.1 already contains this validation, so no registry build carried the development-only behavior.
  - **What closed it.** `ingest_url` now runs the same static validation as the presidio endpoints at `init()`: scheme allowlist, unconditional refusal of the cloud-metadata and link-local range in every spelling, and the private-range check with only the parsed loopback hosts exempt. Pinned in both trees.

  Documented limit: Presidio, ingest, and the TypeScript hard-deletion endpoint use init-time static guards (literal-IP + scheme), so they do not resolve a hostname per call — a hostname that later rebinds to a metadata IP is a residual TOCTOU. `init()` is synchronous in both SDKs and the resolving guard needs DNS, so closing this means either an async `init()` or a check on each delivery path; only the external policy backend gets a resolving, address-pinned connection today. These URLs are operator-configured rather than runtime-attacker-controlled, which is why the static guard is the proportionate one — though on the zero-code Python entry point `ingest_url` comes from the `OBSVR_INGEST_URL` environment variable, so "operator-configured" means whatever set that variable.
- Customer-supplied regex rules pass a ReDoS validator (nested quantifiers — including a fixed `{n}` repetition applied to a group that itself carries a quantifier or alternation, the `(.*a){20}b` shape — quantified alternation, and backreferences rejected; bounded input length) before they are ever executed.

## The approval-status contract (what ingest must expose before a denial code may exist)

The blocking approval hold can tell that a covering grant **arrived**; it cannot tell that a human **said no**, because neither channel the SDK has carries a verdict. `GET /policies` returns `approvals` as a list of grants — the parser keeps an entry only if it has a `rule_id` and an `expires_at`, so there is no representation a denial could ride in on — and `POST /approvals/request` is fire-and-forget, its response never read. An explicit denial and an unanswered request therefore both surface as the hold expiring: `APPROVAL_TIMEOUT`, with a reason text that says the two are indistinguishable rather than implying nobody answered. The call is blocked either way — the conflation is never a false enforcement — and a distinct denial code is **deliberately not minted**: a registry code whose emission path cannot know the fact it asserts would be a fabricated record.

That changes when the ingest service exposes a per-request status endpoint. The contract, stated here so the SDK and the service cannot drift apart:

```
GET {ingest_url}/approvals/status?rule_id=<id>&action_hash=<hex>
Headers: X-API-Key: <api key>
→ { "status": "pending" | "approved" | "denied" | "expired" | "unknown",
    "decided_at": "<ISO 8601, present for approved/denied>",
    "decided_by": "<opaque reviewer label, optional>",
    "signature": { ...same envelope as /policies, when signing is enabled... } }
```

`action_hash` is the digest the SDK already sends on `/approvals/request`, so status is per-call, not per-rule; `user_id` may be added as a narrowing parameter under the same discipline as grant binding (both sides present ⇒ must match; a silent side does not filter). What the SDK does with each state:

| Status | SDK behaviour |
|---|---|
| `pending` | keep holding, within `approval_wait_ms` |
| `approved` | shorten the next grant-channel poll — **the status answer never lifts the block by itself**; only a grant arriving on the signed `/policies` channel, passing grant-shape validation and end-of-pipeline revalidation, may do that, so a spoofed or replayed `approved` buys nothing |
| `denied` | stop holding immediately and block with a new, distinct registry code (`APPROVAL_DENIED` — added to the closed registry, both languages and the shared fixture, in the same change that consumes this endpoint), recording `decided_at`/`decided_by` on the event's telemetry channel |
| `expired` / `unknown` | treat as `pending` until the local budget expires → `APPROVAL_TIMEOUT` |

Transport failure, a non-200, or an unparseable body: exactly today's behaviour — keep polling the grant channel, resolve by the local budget, never a fabricated denial. Because `denied` is the one state that changes SDK behaviour on the endpoint's word alone, a deployment that pins `policy_public_key` must receive `denied` under the same signature envelope `/policies` uses (covering `status`, `rule_id`, `action_hash`, `decided_at`, with `issued_at` monotonicity), and an unsigned or unverifiable `denied` is treated as `pending` — otherwise anyone who can answer the status URL could convert every hold into an instant denial. `approved` needs no signature because it grants nothing.

## Known limitations under active work

- **Cross-instance dedup and rate limits.** Replay protection and rate limiting are per-process today; cross-replica replays are caught at verification time rather than rejected inline.
- **A human denial is indistinguishable from indecision during an approval hold** — both surface as `APPROVAL_TIMEOUT`, and the record says so. Closes when the approval-status contract above is implemented by ingest.
- **Sequence monotonicity at accept time** (currently detected at verification time).
- **Organization-level RBAC and per-key policy**, including deployment-level controls over `disabled: true`.

## Inherent (not "limitations" — structural properties)

- **SDK bypass.** An in-process library cannot force its host to call it. Coverage is enforced operationally, not cryptographically (see "Bypass surface").
- **Pre-emission process integrity.** Signatures prove order and post-emission immutability; they cannot attest to what happened inside your process before an event was emitted.
