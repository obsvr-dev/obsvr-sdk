# Compatibility

Which versions of each package the obsvr SDK works with.

## Python

| Package                   | Declared                              | Observed                                            | Range evidence |
| ------------------------- | ------------------------------------- | --------------------------------------------------- | -------------- |
| `ag2`                     | `>=0.3.2,<1.0`                        | `0.3.2`, `0.9.9`                                     | **matrix**     |
| `anthropic`               | `>=0.16.0`                            | `0.8.0` – `0.120.2`                                  | floor located  |
| `boto3`                   | `>=1.34.0`                            | —                                                    | declared       |
| `crewai`                  | `>=1.0.0,<2.0.0; python_version < '3.14'` | `1.0.0`, `1.8.0`, `1.15.2`, `1.15.3`, `1.15.10` | **matrix**     |
| `cryptography`            | `>=41.0.0`                            | —                                                    | declared       |
| `google-cloud-aiplatform` | `>=1.38.0`                            | —                                                    | declared       |
| `google-generativeai`      | any version                           | `0.8.6`                                              | declared       |
| `haystack-ai`             | `>=2.0.0`                             | `2.0.0`, `3.0.0`                                     | **matrix**     |
| `langchain-core`          | `>=1.0.0,<2.0.0`                      | `1.0.0`, `1.5.3`                                     | **matrix**     |
| `llama-index-core`        | `>=0.14.5,<0.15.0`                    | `0.14.5`, `0.14.23`                                  | **matrix**     |
| `mcp`                     | `>=2.0.0,<3.0.0`                      | `1.29.0`, `2.0.0`                                    | **matrix**     |
| `openai`                  | `>=1.66.0`                            | `1.0.0` – `2.50.0`                                   | floor located  |
| `openai-agents`           | `>=0.19.0,<1.0.0`                     | `0.19.0`, `0.19.2`                                   | floor located  |
| `opentelemetry-api`       | `>=1.20.0`                            | —                                                    | declared       |
| `pydantic-ai-slim`        | `>=2.0.0,<3.0.0`                      | `2.0.0`, `2.22.0`                                    | **matrix**     |
| `PyNaCl`                  | `>=1.0.0`                             | —                                                    | declared       |

`google-generativeai` is the legacy line, end-of-life 2025-08.
`cryptography` and `PyNaCl` are the two interchangeable Ed25519 backends behind
the `crypto` / `crypto-nacl` extras — install one, not both.

### What the evidence column means

The **Declared** column is what the package resolver enforces. It is not a
statement that anything in the range was run; the **Range evidence** column is
where that is said, per row.

- **matrix** — the declared range is stood up by a per-version matrix: one
  environment per listed version, the gate driven through each release's own
  dispatch, and a denied tool's side effect measured at zero against a paired
  allow control that reaches exactly one. Seven rows earn it, and what supplies
  the "real" half differs by surface. `crewai` and `pydantic-ai-slim` drive
  their range boundaries against a real provider, because on those surfaces
  nothing is proven until a model has CHOSEN to call the tool: crewai's
  boundaries are `1.0.0` and `1.15.10` with `1.15.2`/`1.15.3` the adjacent pair
  locating the `before_tool_call` hook's arrival, and pydantic-ai's are `2.0.0`
  and `2.22.0`. `mcp` needs no provider and is not weaker for it — a real
  client and a real server exchange real JSON-RPC, so the tool call is made
  directly and every client route into `tools/call` is driven rather than
  waited for. Its listed versions span both protocol majors.

  Four more rows earn it in the same terms. `langchain-core` lists `1.0.0` and
  `1.5.3`, each driven on BOTH runtimes — the graph runtime and the classic
  executor, which deliver different pre-tool callbacks — with a denied tool at
  zero executions, a paired allow control at three, and a step budget of two
  stopping a run the model asked to take further; the latest is additionally
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
- **declared** — the range is asserted and no run has covered it. This is the
  honest label for most of the matrix, and it is deliberately **not** narrowed
  to whatever happens to be installed: a range nobody has driven is untested,
  not wrong, and guessing a tighter one would replace an unmeasured claim with
  a more confident unmeasured claim.

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
  honest reading is per path rather than per range: methods arriving after
  the floor are listed under "Version needed per method" below rather than
  folded into a raised floor, because a range narrowed to cover the newest
  path would misdescribe the many releases on which the older paths work.
  The one upstream-broken release inside the `openai` range — 1.99.0, whose
  responses types ship broken and are repaired in 1.99.1 — is recorded
  rather than excluded, for the same reason.

## TypeScript

No TypeScript range has been stood up by a per-version matrix, so every row is
`declared`. One row carries live evidence inside that label: the
`@openai/agents` Observed versions are paired allow/deny legs against a real
provider, described below the table.

| Package                           | Declared                        | Observed              | Range evidence |
| --------------------------------- | ------------------------------- | --------------------- | -------------- |
| `@anthropic-ai/sdk`               | `>=0.20.0`                      | `0.20.0` – `0.115.0`  | declared       |
| `@aws-sdk/client-bedrock-runtime` | `>=3.587.0`                     | `3.1096.0`            | declared       |
| `@google-cloud/vertexai`          | `>=1.0.0`                       | `1.0.0` – `1.12.0`    | declared       |
| `@google/genai`                   | —                               | **not supported yet** | n/a            |
| `@google/generative-ai`           | `>=0.1.0 <1.0.0`                | `0.1.0` – `0.24.1`    | declared       |
| `@langchain/core`                 | `>=0.2.0`                       | `0.2.0` – `1.2.3`     | declared       |
| `@modelcontextprotocol/sdk`       | `>=1.26.0 <2.0.0`               | `1.26.0`, `1.29.0`, `1.30.0` | measured (floor) |
| `@openai/agents`                  | `>=0.13.0 <1.0.0`               | `0.13.0`, `0.13.4`, `0.14.2` | declared  |
| `@opentelemetry/api`              | `>=1.4.0`                       | `1.4.0` – `1.9.1`     | declared       |
| `ai`                              | `>=3.3.28`                      | `3.4.33` – `7.0.41`   | declared       |
| `llamaindex`                      | `>=0.5.9`                       | `0.5.9` – `0.12.1`    | declared       |
| `openai`                          | `>=6.0.0 <8.0.0`                | `6.0.0` – `7.0.0`     | declared       |
| `together-ai`                     | `>=0.6.0 <1.0.0`                | `0.6.0` – `0.44.0`    | declared       |

`@google/generative-ai` is the legacy line, end-of-life 2025-08. Its replacement `@google/genai` is **not supported yet**.

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
and the latest `0.14.2` each ran the full paired allow/deny suite (denied tool
at zero side-effect writes, payload absent from what the caller received)
against a real provider. The row stays `declared` because no release below the
floor was driven — the label is about locating an edge, and that edge has not
been walked.

**Module format: ESM only.** `@obsvr/sdk` declares `"type": "module"` and every export condition is `import`, so a CommonJS consumer cannot `require()` it at any version. Independently of loading, the zero-code `--import` interception path does not reach `require()` — `module.register()` hooks do not intercept it — so a CJS entrypoint is ungoverned on that path even where the packages above are dual-format. `obsvr.wrap()` and the named compatibility wrappers are unaffected. See the [TypeScript README](sdk-typescript/README.md#this-package-is-esm-only) for why dual-publishing is scoped as future work rather than a quick fix.

## Version needed per method

A release can be installable and governed on one method while another does not
exist on the client yet. These are the releases each method first works at.

**This table describes `obsvr.wrap()` and the module interceptor.** The named
compatibility wrappers — `wrapAzureOpenAI`, `wrapTogether`,
`wrapOpenAICompatible` — govern `chat.completions.create` and nothing else, so
every other row below is ungoverned and unaudited through them however new the
installed client is. Wrap with `obsvr.wrap()` if you need the rest; it accepts
the same clients.

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

## Ranges not yet bounded by measurement

Two declared ranges stand on reasoning rather than on a per-version run, and
what is known about each is recorded here. A third, `mcp`, was resolved by
porting the three reads it named rather than by relaxing a cap.

| Range | Latest upstream | What bounds it |
| --- | --- | --- |
| `ag2>=0.3.2,<1.0` (Python) | `1.0.1` | The cap EXCLUDES the current major, so the declared range tracks only the pre-1.0 line. The cap itself is correct and load-bearing — 1.0 renamed the import package and removed the class the integration binds, both re-confirmed — so what is open is whether to support 1.x at all, not whether to widen the cap. What 1.x IS has been read rather than inferred: a from-scratch framework under the same distribution name, with no `ConversableAgent`, no `register_hook`, no `initiate_chat` and no function map, whose tools are invoked at a single point behind a first-class around-hook — `BaseMiddleware.on_tool_execution`, which takes a `call_next` and whose refusal contract is demonstrated by the project's own human-approval middleware. Nothing of the 0.x integration transfers, and the framework-agnostic `govern_tool` does not reach 1.x tools either. Its similarly-named siblings are not substitutes: `ag2/policies/` is LLM-context assembly with no veto channel, and `ag2/observers/` swallows every exception on its documented path. Separately, the 0.x line was forked and now publishes under the `autogen` distribution, and upstream tells 0.x users to install `ag2-classic`, which this extra does not name — so this range currently follows one half of a fork under a name the other half kept. |
| `ai>=3.3.28` (TypeScript) | `7.0.47` | Four majors of unbounded floor. The declared range promises every release from 3.3.28 onward, across four breaking majors, with no top. No run has covered any of it, so the range is untested rather than known wrong. |

`ag2` is now the only range in either manifest that excludes its package's
current major, and its reason is stated above and under "Versions that will not
work". The `mcp` cap that used to sit beside it is gone: the three
`getattr`-read controls were ported to read both protocol spellings, and the
range moved onto the current major rather than around it.

_Except where the evidence column says otherwise, the Observed columns come from
an integration-test matrix run outside this repository; that harness is not
published, so those cells are updated by hand when the matrix is re-run._
