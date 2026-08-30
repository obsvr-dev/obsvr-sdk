# Compatibility

Which versions of each package the obsvr SDK works with.

## Python

| Package                   | Declared                              | Observed                                            | Range evidence |
| ------------------------- | ------------------------------------- | --------------------------------------------------- | -------------- |
| `ag2`                     | `>=0.3.2,<1.0`                        | `0.3.2`, `0.9.9`                                     | **matrix**     |
| `anthropic`               | `>=0.16.0,<1.0.0`                     | `0.8.0` – `0.125.0`                                  | floor located  |
| `boto3`                   | `>=1.34.0,<2.0.0`                     | —                                                    | declared       |
| `crewai`                  | `>=1.0.0,<2.0.0; python_version < '3.14'` | `1.0.0`, `1.8.0`, `1.15.2`, `1.15.3`, `1.15.10` | **matrix**     |
| `cryptography`            | `>=41.0.0`                            | —                                                    | declared       |
| `google-cloud-aiplatform` | `>=1.38.0,<2.0.0`                     | `1.38.0`, `1.165.1`                                 | declared       |
| `google-genai`             | `>=2.0.0,<3.0.0`                     | `2.20.0`                                             | declared       |
| `google-generativeai`      | `>=0.3.0,<1.0.0`                     | `0.3.0`, `0.8.6`                                     | **matrix**     |
| `haystack-ai`             | `>=2.0.0,<4.0.0`                      | `2.0.0`, `3.0.0`                                     | **matrix**     |
| `langchain-core`          | `>=1.0.0,<2.0.0`                      | `1.0.0`, `1.5.3`                                     | **matrix**     |
| `llama-index-core`        | `>=0.14.5,<0.15.0`                    | `0.14.5`, `0.14.23`                                  | **matrix**     |
| `mcp`                     | `>=2.0.0,<3.0.0`                      | `1.29.0`, `2.0.0`                                    | **matrix**     |
| `openai`                  | `>=1.66.0,<3.0.0`                     | `1.0.0` – `2.54.0`                                   | floor located  |
| `openai-agents`           | `>=0.19.0,<1.0.0`                     | `0.19.0`, `0.19.2`                                   | floor located  |
| `opentelemetry-api`       | `>=1.20.0,<2.0.0`                     | —                                                    | declared       |
| `pydantic-ai-slim`        | `>=2.0.0,<3.0.0`                      | `2.0.0`, `2.22.0`                                    | **matrix**     |
| `PyNaCl`                  | `>=1.0.0`                             | —                                                    | declared       |

`google-generativeai` is the legacy line, end-of-life 2025-08. Its real
`GenerativeModel` and `ChatSession` boundaries are package-tested at the first
supported release and the final legacy release. The maintained `google-genai`
adapter was package-tested at 2.20.0; its row is still declared because
releases below that point were not walked to locate a floor.
`cryptography` and `PyNaCl` are the two interchangeable Ed25519 backends behind
the `crypto` / `crypto-nacl` extras — install one, not both.

### What the evidence column means

The **Declared** column is what the package resolver enforces. It is not a
statement that anything in the range was run; the **Range evidence** column is
where that is said, per row.

- **matrix** — the declared range is stood up by a per-version matrix: one
  environment per listed version, the gate driven through each release's own
  dispatch, and a denied tool's side effect measured at zero against a paired
  allow control that reaches exactly one. Rows earn it only when this evidence
  exists, and what supplies
  the "real" half differs by surface. `crewai` and `pydantic-ai-slim` drive
  their range boundaries against a real provider, because on those surfaces
  nothing is proven until a model has CHOSEN to call the tool: crewai's
  boundaries are `1.0.0` and `1.15.10` with `1.15.2`/`1.15.3` the adjacent pair
  locating the `before_tool_call` hook's arrival, and pydantic-ai's are `2.0.0`
  and `2.22.0`. `mcp` needs no provider and is not weaker for it — a real
  client and a real server exchange real JSON-RPC, so the tool call is made
  directly and every client route into `tools/call` is driven rather than
  waited for. Its listed versions span both protocol majors.

  Further rows earn it in the same terms. `langchain-core` lists `1.0.0` and
  `1.5.3`, each driven on BOTH runtimes — the graph runtime and the classic
  executor, which deliver different pre-tool callbacks — with a denied tool at
  zero executions, a paired allow control at three, and a step budget of two
  stopping a run the model asked to take further; the highest tested release is additionally
  driven against a real provider. `haystack-ai` lists `2.0.0` and `3.0.0`, and
  the two are not symmetric on purpose: the prompt guard binds and refuses at
  both, while the Agent, the Tool class and the `before_tool` hook point do not
  exist at 2.0.0 at all, so what is measured there is that the tool-gate
  installer refuses loudly instead of arming a gate nothing would consult. That
  is the same shape as crewai's listed releases below its hook's arrival.

  `ag2` and `llama-index-core` earn it on their own tool gates, each driven
  live at two versions. `ag2` lists `0.3.2` and `0.9.9`, with both mechanisms
  exercised at each — the `process_message_before_send` hook and the
  `execute_function` gate — a denied tool at zero side-effect writes against a
  paired allow control reaching exactly one. `llama-index-core` lists `0.14.5`
  and `0.14.23`, `govern_agent` driven on the plain, ReAct, tool-retriever and
  multi-agent-handoff routes with the denied tool's payload asserted absent
  from the `ToolCallResult` the caller received.
  `google-cloud-aiplatform` lists `1.38.0` and `1.165.1`; both construct official
  model/chat objects and drive block/redaction across stable and preview chat
  sessions, including retained history and stream entry, with provider dispatch
  replaced by a zero-network side-effect counter.
- **floor located** — the FLOOR is an adjacent tested pair established live
  (at the release below, the audited path is absent; at the floor, it is
  audited on a real call), with the reasoning recorded per extra in
  `sdk-python/pyproject.toml`. The open top is not covered by that work.
  `openai-agents` is the sharpest instance: at 0.18.0 and every release back
  to 0.4.0, the framework fails to construct its own `Usage` container under
  the current `openai` client, so `Runner.run` dies before any tool is
  reached — measured per release; at 0.19.0 the full tool-gate suite runs
  live and green, as it does at 0.19.2, so both listed versions are live
  legs, not resolver output.
- **declared** — no range-edge or per-version matrix establishes the claimed
  interval. A row may still have a package test or live probe at one listed
  version; that is point evidence, not evidence for the whole range. Declared
  ranges are deliberately **not** narrowed to whatever happens to be installed:
  guessing a tighter edge would replace an unmeasured claim with a more
  confident unmeasured claim.

The **Observed** column predates this distinction, which is why an entry there
does not by itself promote a row past `declared`.

### How a floor is located

The `floor located` rows are produced by a fixed method. Its full record lives
beside each floor in the `[project.optional-dependencies]` comments of
[`sdk-python/pyproject.toml`](sdk-python/pyproject.toml) — the build file is
the primary source; this section states the method so it can be read without
opening it.

- **A floor is the earliest release with an auditable path, not the earliest
  release that imports.** A client the package can construct but has no
  auditable path on is governed by nothing and stays silent while that
  happens, so "it installs and imports" is not evidence. The `anthropic`
  extra is the instructive case: its 0.3.x releases expose only the
  superseded text-completion path, absent from the audited set, so an
  install resolved against an imports-only floor produces zero audit events
  with nothing raising — confirmed live, not read off a shape.
- **Every boundary is an adjacent tested pair, established by an exhaustive
  walk.** One throwaway environment per published release, no bisect; the
  boundary is then re-run live and graded on the captured event. The release
  below the floor reads ABSENT on the audited path; the floor itself reads
  AUDITED on a real call. `openai` is a located edge in exactly this sense —
  at 1.65.5 both responses paths read absent, at 1.66.0 both are audited —
  as is `anthropic`: at 0.15.1 the client carries no `messages` attribute
  and the provider reads unknown, at 0.16.0 it is detected and audited.
- **Counter-examples inside the range are named, not averaged away.** The
  accurate reading is per path rather than per range: methods arriving after
  the floor are listed under "Version needed per method" below rather than
  folded into a raised floor, because a range narrowed to cover the newest
  path would misdescribe the many releases on which the older paths work.
  The one upstream-broken release inside the `openai` range — 1.99.0, whose
  responses types ship broken and are repaired in 1.99.1 — is recorded
  rather than excluded, for the same reason.

## TypeScript

No TypeScript range has been stood up by a complete per-version matrix. Most
rows are therefore `declared`, even where one observed version has a package or
live test. MCP is the exception: its security floor was measured directly.
The `@openai/agents` observed versions are paired allow/deny legs against a real
provider, described below the table, but they do not establish the full range.

| Package                           | Declared                        | Observed              | Range evidence |
| --------------------------------- | ------------------------------- | --------------------- | -------------- |
| `@anthropic-ai/sdk`               | `>=0.20.0 <1.0.0`               | `0.20.0` – `0.122.0`  | declared       |
| `@aws-sdk/client-bedrock-runtime` | `>=3.587.0 <4.0.0`              | `3.1096.0`            | declared       |
| `@google-cloud/vertexai`          | `>=1.0.0 <2.0.0`                | `1.0.0` – `1.12.0`    | declared       |
| `@google/genai`                   | `>=2.0.0 <3.0.0`                | `2.16.0`              | declared       |
| `@google/generative-ai`           | `>=0.1.0 <1.0.0`                | `0.1.0` – `0.24.1`    | declared       |
| `@langchain/core`                 | `>=0.2.0 <2.0.0`                | `0.2.0` – `1.2.3`     | declared       |
| `@modelcontextprotocol/sdk`       | `>=1.26.0 <2.0.0`               | `1.26.0`, `1.29.0`, `1.30.0` | measured (floor) |
| `@openai/agents`                  | `>=0.13.0 <1.0.0`               | `0.13.0`, `0.13.4`, `0.14.2` | declared  |
| `@opentelemetry/api`              | `>=1.4.0 <2.0.0`                | `1.4.0` – `1.9.1`     | declared       |
| `ai`                              | `>=3.3.28 <8.0.0`               | `3.4.33` – `7.0.41`   | declared       |
| `llamaindex`                      | `>=0.5.9 <1.0.0`                | `0.5.9` – `0.12.1`    | declared       |
| `openai`                          | `>=6.0.0 <8.0.0`                | `6.0.0` – `7.0.0`     | declared       |
| `together-ai`                     | `>=0.6.0 <1.0.0`                | `0.6.0` – `0.44.0`    | declared       |

`@google/generative-ai` is the legacy line, end-of-life 2025-08. The maintained
`@google/genai` adapter was package-tested at 2.16.0; its row is still declared
because releases below that point were not walked to locate a floor.

**The `@modelcontextprotocol/sdk` floor is a security bound, and each end of it
names its reason.** `1.26.0` is the first release clean of all three published
high-severity advisories against that package, which is why the floor sits
above the release this integration would otherwise run on:

| Advisory | Affects | First clean |
| --- | --- | --- |
| `GHSA-w48q-cv73-mx4w` — DNS rebinding protection off by default | `<1.24.0` | `1.24.0` |
| `GHSA-8r9q-7v3j-jr4g` — ReDoS | `>=1.3.0 <1.25.2` | `1.25.2` |
| `GHSA-345p-7cg4-v4c7` — cross-client data leak via shared transport reuse | `>=1.10.0 <=1.25.3` | `1.26.0` |

The upper bound is the next major, per this project's version policy: a major
is a capability boundary and is admitted only once driven. The Observed column
is live: the floor `1.26.0`, the mid-range `1.29.0` and the installed `1.30.0`
each ran the MCP gate suite — denied tool at zero executions with the payload
absent from what the caller received, on every client route into `tools/call`.
The row is `measured (floor)` rather than `matrix` because no release below the
floor was driven; the label is about locating an edge, and the edge here is set
by the advisories rather than by a capability.

The `@openai/agents` row's Observed versions are live tool-gate legs, not
resolver output: the declared floor `0.13.0`, the harness-installed `0.13.4`,
and the highest tested `0.14.2` each ran the full paired allow/deny suite (denied tool
at zero side-effect writes, payload absent from what the caller received)
against a real provider. The row stays `declared` because no release below the
floor was driven — the label is about locating an edge, and that edge has not
been walked.

**Module format: ESM-only API, ESM and CommonJS provider interception.** `@obsvr/sdk` declares `"type": "module"` and every public API export condition is `import`, so a CommonJS consumer cannot `require()` the SDK itself. The `@obsvr/sdk/initialize` and `@obsvr/sdk/register` preloads are ESM; once loaded, they also chain Node's CommonJS module loader for documented provider entry points. OpenAI coverage includes the root plus `openai/index`, `openai/index.mjs`, `openai/client`, `openai/client.mjs`, `openai/client.js`, and `openai/azure` where the module format applies. This does not cover arbitrary subpaths, imports completed before the preload, saved constructor references, or custom transports. `obsvr.wrap()` and named compatibility wrappers remain the explicit boundary. See the [TypeScript README](sdk-typescript/README.md#this-package-is-esm-only).

### Startup automatic bindings

The startup paths bind only upstream surfaces with a construction or
process-global pre-execution point. The version evidence below is the evidence
for the underlying gate plus an automatic-attachment test; it is not a claim
that every API in the framework is intercepted.

| Surface | Runtime | Automatic entry point | Version/evidence boundary |
| --- | --- | --- | --- |
| MCP client | TypeScript | `@modelcontextprotocol/sdk/client` and `/client/index.js` `Client` construction, ESM and CommonJS | real client/server startup tests on the declared `>=1.26.0 <2.0.0` line; the security floor remains 1.26.0 |
| MCP client | Python | future `mcp.ClientSession` / `mcp.client.session.ClientSession` construction | real in-memory client/server test on the installed 1.x line; a denied tool records zero server executions |
| OpenAI Agents model + tools | TypeScript | `@openai/agents` `Agent` construction; concrete model assignment and local tool/handoff list mutations receive pre-call gates | real-runner startup tests on the declared `>=0.13.0 <1.0.0` line; denied model and late-added tool each record zero downstream executions |
| OpenAI Agents model + tools | Python | future `agents.Agent` construction; concrete model assignment and local tool/handoff list mutations receive pre-call gates | real-runner startup tests at 0.19.2; denied model and late-added tool each record zero downstream executions |
| LlamaIndex models | Python | process-global `Settings.callback_manager` model-start handler | real callback boundary tests; block stops before model dispatch and redaction fails closed |
| CrewAI tools | Python | official process-global `before_tool_call` hook | automatic attachment is available only where the executor consult site exists, currently 1.15.3+; earlier supported versions require `govern_tool` |
| AutoGen/ag2 tools | Python | class-level `ConversableAgent.execute_function` / `a_execute_function` gate | automatic attachment follows the supported 0.x range, live-driven at 0.3.2 and 0.9.9 |

LangChain remains an explicit callback binding in both SDKs because supported
versions expose handlers per model or invocation, not a documented
process-global custom pre-call registration point. LlamaIndex agent tool
governance, Python Gemini, already-imported aliases, hosted tools, and unlisted
import paths remain explicit. OpenAI Agents tracing is still observe-only;
automatic Agent interception separately governs concrete model calls and local
tool execution at their pre-call boundaries.

### Coverage attestation compatibility contract

Python and TypeScript emit the same canonical
`obsvr-coverage-attestation-v1` body and
`obsvr-coverage-attestation-envelope-v1` envelope. Shared fixtures pin the body
hash across both implementations.

| Field | Compatibility rule |
| --- | --- |
| `required` | sorted integration requirements with `observe` or `enforce` minimum depth and optional exact symbols |
| `bindings` | sorted process-reported symbols; legacy depth is `unknown` |
| `policy_pack_hashes` | lowercase SHA-256 hashes, sorted and deduplicated |
| `coverage_complete` / `failures` | derived, not caller-controlled; recomputed by verifiers |
| signature | Ed25519 over the domain-separated canonical body, verified under an out-of-band pinned public key |

The schema is closed: unknown body fields and noncanonical derived values are
invalid. Adding fields or changing ordering, depth semantics, or signature
bytes requires a new schema version and new shared fixtures.

### Layered action-context contract

`obsvr-action-context-v2` accepts optional `principal`, `execution`, and
`governance` layers in both languages. The layers use closed fields and enums;
coverage and policy evidence are represented by SHA-256 hashes rather than raw
documents. Existing inputs that omit the layers retain their pinned canonical
bytes and hash. The layered fixture separately pins ordering, deduplication,
target tokenization, enum validation, and the new canonical hash.

`obsvr-remediation-plan-v1` and `obsvr-remediation-retry-v1` are pinned
cross-language. Plans accept only `MODIFY`, `STEP_UP`, and `DEFER`; requirements
are sorted by code-bearing identity and retry evidence must cover every unique
requirement exactly once. Action-context retry linkage is optional, but when a
parent attempt is present the new attempt id and remediation retry hash are
both required.

### Strict approval lifecycle

The profile 2.1 coordinator uses one exact approval lifecycle in both SDKs.

| Property | Contract |
| --- | --- |
| Action binding | `approval_action_hash` and suspended receipt hash must match. |
| Expiry | Verifier expiry cannot exceed suspension expiry; a grant is live at resolution time. |
| Revalidation | The active policy and trusted evaluation evidence run again before authorization. |
| Consumption | One suspended receipt has at most one committed resolution and one execution. |
| Separation of duties | Optional `requester` or `requester_and_initiator`; requires a same-namespace `principal_ref_hash`. |

Separation of duties defaults to `none` for source compatibility. The verifier
result remains compatible without `principal_ref_hash` unless either strict
mode is selected. The resolver hash in new receipts uses the supplied
pseudonymous reference when present; otherwise it retains the legacy derived
hash of `principal_id`.

## Ordinary enforcement boundary

The ordinary wrappers are broader than strict profile 2.1. On every method
listed below, `block` stops transport and `redact` rewrites provider-bound text
or fails closed when the SDK cannot prove the rewrite was applied.

| Surface | TypeScript | Python |
| --- | --- | --- |
| OpenAI | chat create/parse, legacy text completions, Responses create/parse/compact, listed beta/raw-response paths, stream helpers, `runTools` turns/tools | chat create/parse, legacy text completions, Responses create/parse/compact, listed beta/raw/streaming-response paths |
| Anthropic | Messages create/parse, listed beta paths, stream helpers, `toolRunner` turns/tools | Messages create/parse, listed raw/stream helpers, supported Messages/session runner turns and local tools |
| Gemini, legacy and maintained | unary/stream generation and retained chat sessions | sync/async unary/stream generation and retained chat sessions |
| Vertex AI | model unary/stream generation and retained chat sessions through `wrapVertexAI` | sync/async model generation and retained chat sessions through `wrap_vertex` |
| LangChain model callbacks | enforcing model-start boundary; redaction fails closed because callbacks cannot rewrite requests | same |
| LlamaIndex model callbacks | tracing is observe-only; `obsvrGovernLlamaIndexLLM` enforces `chat`/`complete` | enforcing model-start boundary; redaction fails closed |
| OpenAI Agents model callbacks | tracing is observe-only; `governModel` / `governModelProvider` enforce | tracing is observe-only; `govern_model` / `govern_model_provider` enforce |
| Application callable | `governFn`; async wrapper around sync or async callable | `govern_fn` / `@govern`; preserves sync or async shape |

Batch APIs, opaque provider-hosted tools, and methods not named by the SDK's
coverage tables remain outside this ordinary boundary. A later runner turn can
be blocked before its request, but an earlier allowed tool side effect cannot be
rolled back.

The application-callable row reuses the ordinary tool-policy kernel. Policy
block has zero calls to the wrapped function, and redaction reaches its actual
arguments or fails closed. Only the returned wrapper is covered; raw aliases
remain explicit exclusions.

## Cross-language operator contracts

| Contract | TypeScript | Python | Cross-language invariant |
| --- | --- | --- | --- |
| policy lifecycle v1 | `buildPolicyCandidateV1`, `replayPolicyCandidateV1`, `decidePolicyPromotionV1` | `build_policy_candidate_v1`, `replay_policy_candidate_v1`, `decide_policy_promotion_v1` | candidate hash, replay arithmetic, thresholds, rollback, reason codes |
| workload registry v1 | `signWorkloadRegistrationV1`, `WorkloadRegistryV1` | `sign_workload_registration_v1`, `WorkloadRegistryV1` | canonical registration hash and Ed25519 verification |
| policy template v1 | `renderPolicyTemplateV1`, `signRenderedPolicyV1` | `render_policy_template_v1`, `sign_rendered_policy_v1` | typed rendering and template, parameter, artifact, approval, activation hashes |
| control analytics v1 | `buildControlAnalyticsReportV1` | `build_control_analytics_report_v1` | integer basis-point rates, nearest-rank percentiles, report hash |
| signal interface v1 | `resolveSignalV1` and OTEL/OPA/Cedar projections | `resolve_signal_v1` and matching projections | resolution hash, failure constraint, `authoritative_allow: false` |

The fixtures pin representative hashes in both SDK test suites. These contracts
accept JSON-safe bounded values; they do not promise byte parity for values
outside the validated schemas.

## Strict profile 2.1 direct-provider boundary

Strict mode is opt-in and narrower than the ordinary wrapper. It supports unary calls only. Python async-client methods, streams, raw-response helpers, tool runners, factories, chat managers, and all unlisted callables fail closed with `unsupported_surface`; TypeScript's listed unary methods retain their normal Promise-returning API.

| Provider | Python strict methods | TypeScript strict methods | Current evidence |
| --- | --- | --- | --- |
| OpenAI | `chat.completions.create`, `chat.completions.parse`, `responses.create`, `responses.parse` | same | Shared boundary tests in both SDKs; controlled live Python and TypeScript calls on `chat.completions.create` |
| Anthropic | `messages.create`, `messages.parse` | same | Shared boundary tests in both SDKs; controlled live Python and TypeScript calls on `messages.create` |
| Gemini, legacy | `generate_content` | `generateContent` | Boundary and endpoint tests; no strict live-provider claim |
| Gemini, maintained | `models.generate_content` | `models.generateContent` | Real-package shape tests in both SDKs; controlled live Python and TypeScript calls on the maintained unary method |
| Groq, OpenAI-compatible endpoint | OpenAI-shaped methods above | OpenAI-shaped methods above | Endpoint, target-binding, and boundary tests only; no successful live-provider claim |

The controlled live calls are release-validation evidence, not part of CI. They prove that one admitted call crossed each named provider path at the time tested; they do not extend the supported version ranges or prove every method in the row. Groq remains supported by the endpoint and OpenAI-compatible method contract but was not live-validated in this cycle.

Every strict call also requires a trusted profile 2.1 runtime, a durable atomic checkpoint store, positive admission for the exact receipt, a `model:invoke` scope, and an official provider target. The target and exact cleaned JSON invocation are receipt-bound and rechecked before invocation. Only `ALLOW` executes at the direct-provider boundary; `DENY`, `MODIFY`, `STEP_UP`, and `DEFER` fail without contacting the provider.

Signed terminal outcomes can be submitted independently to `/ingest/strict-execution-outcomes/v2-1`. Python and TypeScript use the same exact wrapper, idempotency key, bounded DNS-pinned transport rules, response validation, and retry classification. An `invocation_started` journal recovered after a process interruption can be finalized only as `uncertain/process_interrupted`; recovery never makes it retry-safe or claims what happened remotely.

The provider-neutral `createStrictActionBoundaryV21` / `create_strict_action_boundary_v2_1` surface uses the same runtime for caller-defined side effects and explicit scopes. Its compatibility boundary is the JSON-serializable invocation and the callable supplied by the application, not a third-party package version.

Optional strict trace correlation supports `@opentelemetry/api >=1.4.0,<2.0.0` in TypeScript and `opentelemetry-api >=1.20.0,<2.0.0` in Python. It annotates an existing recording span after the durable checkpoint succeeds; it does not create a span or participate in authorization. The attribute set is fixture-pinned across both SDKs.

The AARM outcome mapping is obsvr compatibility profile 1.0. These profiles and fixtures are not official AARM conformance vectors and make no certification claim.

## Version needed per method

A release can be installable and governed on one method while another does not
exist on the client yet. These are the releases each method first works at.

**This table describes the generic OpenAI-shaped resolver used by
`obsvr.wrap()`, the module interceptor, and the named `wrapAzureOpenAI`,
`wrapTogether`, and `wrapOpenAICompatible` wrappers.** The named wrappers add
endpoint attribution; they do not narrow the method table or its exclusions.

### `openai` (Python)

| Method                         | Needs            |
| ------------------------------ | ---------------- |
| `chat.completions.create`      | `openai>=1.0.0`  |
| `beta.chat.completions.parse`  | `openai>=1.40.0` |
| `responses.create`             | `openai>=1.66.0` |
| `responses.parse`              | `openai>=1.66.0` |
| `beta.chat.completions.create` | `openai>=1.92.0` |
| `chat.completions.parse`       | `openai>=1.92.0` |
| `beta.responses.create`        | `openai>=2.45.0` |

### `anthropic` (Python)

| Method                 | Needs               |
| ---------------------- | ------------------- |
| `beta.messages.create` | `anthropic>=0.8.0`  |
| `messages.create`      | `anthropic>=0.16.0` |
| `messages.parse`       | `anthropic>=0.77.0` |

## Versions that will not work

| Package | Language | Declared         | Why                                                                                                                            |
| ------- | -------- | ---------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `ag2`   | Python   | `>=0.3.2,<1.0`   | 1.0 removed the agent class this integration binds, and renamed the import package.                                            |

## Range requiring a new adapter

The `ag2` current major is a different framework shape from the supported 0.x
line. The reason for excluding it is recorded here.

| Range | Highest inspected | What bounds it |
| --- | --- | --- |
| `ag2>=0.3.2,<1.0` (Python) | `1.0.1` | The cap EXCLUDES the current major, so the declared range tracks only the pre-1.0 line. The cap itself is correct and load-bearing — 1.0 renamed the import package and removed the class the integration binds, both re-confirmed — so what is open is whether to support 1.x at all, not whether to widen the cap. What 1.x IS has been read rather than inferred: a from-scratch framework under the same distribution name, with no `ConversableAgent`, no `register_hook`, no `initiate_chat` and no function map, whose tools are invoked at a single point behind a first-class around-hook — `BaseMiddleware.on_tool_execution`, which takes a `call_next` and whose refusal contract is demonstrated by the project's own human-approval middleware. Nothing of the 0.x integration transfers, and the framework-agnostic `govern_tool` does not reach 1.x tools either. Its similarly-named siblings are not substitutes: `ag2/policies/` is LLM-context assembly with no veto channel, and `ag2/observers/` swallows every exception on its documented path. Separately, the 0.x line was forked and now publishes under the `autogen` distribution, and upstream tells 0.x users to install `ag2-classic`, which this extra does not name — so this range currently follows one half of a fork under a name the other half kept. |

`ag2` is the only range in either manifest that excludes its package's current
major. MCP instead supports the current 2.x protocol line and stops before 3.x;
its descriptor reads accept both protocol spellings.

_Except where the evidence column says otherwise, the Observed columns come from
an integration-test matrix run outside this repository; that harness is not
published, so those cells are updated by hand when the matrix is re-run._
