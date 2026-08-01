# Compatibility

Which versions of each package the obsvr SDK works with.

## Python

| Package                   | Declared                              | Observed                                            | Range evidence |
| ------------------------- | ------------------------------------- | --------------------------------------------------- | -------------- |
| `ag2`                     | `>=0.3.2,<1.0`                        | `0.3.2` – `0.14.0`                                   | declared       |
| `anthropic`               | `>=0.16.0`                            | `0.8.0` – `0.120.2`                                  | floor located  |
| `boto3`                   | `>=1.34.0`                            | —                                                    | declared       |
| `crewai`                  | `>=1.0.0,<2.0.0; python_version < '3.14'` | `1.0.0`, `1.8.0`, `1.15.2`, `1.15.3`, `1.15.10` | **matrix**     |
| `cryptography`            | `>=41.0.0`                            | —                                                    | declared       |
| `google-cloud-aiplatform` | `>=1.38.0`                            | —                                                    | declared       |
| `google-generativeai`      | any version                           | `0.8.6`                                              | declared       |
| `haystack-ai`             | `>=2.0.0`                             | `2.0.0` – `3.0.0`                                    | declared       |
| `langchain-core`          | `>=0.2.0`                             | `0.2.0` – `1.5.2`                                    | declared       |
| `llama-index-core`        | `>=0.11.23`                           | `0.11.23` – `0.14.23`                                | declared       |
| `mcp`                     | `>=2.0.0,<3.0.0`                      | `1.29.0`, `2.0.0`                                    | **matrix**     |
| `openai`                  | `>=1.66.0`                            | `1.0.0` – `2.50.0`                                   | floor located  |
| `openai-agents`           | `>=0.19.0,<1.0.0`                     | `0.19.0`, `0.19.2`                                   | floor located  |
| `opentelemetry-api`       | `>=1.20.0`                            | —                                                    | declared       |
| `pydantic-ai-slim`        | `>=2.0.0,<3.0.0`                      | `2.0.0`, `2.22.0`                                    | **matrix**     |
| `PyNaCl`                  | `>=1.0.0`                             | —                                                    | declared       |
| `starlette`               | `>=0.30.0`                            | `0.30.0` – `1.3.1`                                   | declared       |

`google-generativeai` is the legacy line, end-of-life 2025-08.
`cryptography` and `PyNaCl` are the two interchangeable Ed25519 backends behind
the `crypto` / `crypto-nacl` extras — install one, not both.

### What the evidence column means

The **Declared** column is what the package resolver enforces. It is not a
statement that anything in the range was run, and until this column existed
every row presented the same way whether or not it had been.

- **matrix** — the declared range is stood up by a per-version matrix: one
  environment per listed version, the gate driven through each release's own
  dispatch, and a denied tool's side effect measured at zero against a paired
  allow control that reaches exactly one. Three rows earn it, and what supplies
  the "real" half differs by surface. `crewai` and `pydantic-ai-slim` drive
  their range boundaries against a real provider, because on those surfaces
  nothing is proven until a model has CHOSEN to call the tool: crewai's
  boundaries are `1.0.0` and `1.15.10` with `1.15.2`/`1.15.3` the adjacent pair
  locating the `before_tool_call` hook's arrival, and pydantic-ai's are `2.0.0`
  and `2.22.0`. `mcp` needs no provider and is not weaker for it — a real
  client and a real server exchange real JSON-RPC, so the tool call is made
  directly and every client route into `tools/call` is driven rather than
  waited for. Its listed versions span both protocol majors.
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

The **Observed** column predates this distinction. Except for `crewai`, those
figures come from an integration-test matrix run outside this repository which
is not published, so they cannot be re-derived from this tree — which is why
they do not by themselves promote a row past `declared`.

## TypeScript

Every row is `declared`: no TypeScript range has been stood up by a
per-version matrix, so none of them has the evidence `crewai` has on the
Python side.

| Package                           | Declared                        | Observed              | Range evidence |
| --------------------------------- | ------------------------------- | --------------------- | -------------- |
| `@anthropic-ai/sdk`               | `>=0.20.0`                      | `0.20.0` – `0.115.0`  | declared       |
| `@aws-sdk/client-bedrock-runtime` | `>=3.587.0`                     | `3.1096.0`            | declared       |
| `@google-cloud/vertexai`          | `>=1.0.0`                       | `1.0.0` – `1.12.0`    | declared       |
| `@google/genai`                   | —                               | **not supported yet** | n/a            |
| `@google/generative-ai`           | `>=0.1.0 <1.0.0`                | `0.1.0` – `0.24.1`    | declared       |
| `@langchain/core`                 | `>=0.2.0`                       | `0.2.0` – `1.2.3`     | declared       |
| `@modelcontextprotocol/sdk`       | `>=1.0.0 <1.25.0 \|\| >=1.30.0` | `1.30.0`              | declared       |
| `@openai/agents`                  | `>=0.13.0 <1.0.0`               | `0.13.0`, `0.13.4`, `0.14.2` | declared  |
| `@opentelemetry/api`              | `>=1.4.0`                       | `1.4.0` – `1.9.1`     | declared       |
| `ai`                              | `>=3.3.28`                      | `3.4.33` – `7.0.41`   | declared       |
| `llamaindex`                      | `>=0.5.9`                       | `0.5.9` – `0.12.1`    | declared       |
| `openai`                          | `>=6.0.0 <8.0.0`                | `6.0.0` – `7.0.0`     | declared       |
| `together-ai`                     | `>=0.6.0 <1.0.0`                | `0.6.0` – `0.44.0`    | declared       |

`@google/generative-ai` is the legacy line, end-of-life 2025-08. Its replacement `@google/genai` is **not supported yet**.

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
compatibility wrappers — `wrapAzureOpenAI`, `wrapTogether`, `wrapCloudflare`,
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

## Open support-matrix decisions

Recorded here rather than acted on: each is a decision about what this package
intends to support, which is the owner's call and not a defect to patch. Both
are stated as of the 2026-08-01 version sweep; a third, `mcp`, was answered by
porting the three reads it named rather than by relaxing a cap.

| Range | Latest upstream | The question |
| --- | --- | --- |
| `ag2>=0.3.2,<1.0` (Python) | `1.0.1` | The cap EXCLUDES the current major, so the declared range tracks only the pre-1.0 line. The cap itself is correct and load-bearing — 1.0 renamed the import package and removed the class the integration binds, both re-confirmed — so the question is whether to support 1.x at all, not whether to widen the cap. Separately, the 0.x line was forked and now publishes under the `autogen` distribution, so this range currently follows the abandoned half of a fork. |
| `ai>=3.3.28` (TypeScript) | `7.0.47` | Four majors of unbounded floor. The declared range promises every release from 3.3.28 onward, across four breaking majors, with no top. Nothing here says it is wrong — it says nothing has bounded it. |

`ag2` is now the only range in either manifest that excludes its package's
current major, and its reason is stated above and under "Versions that will not
work". The `mcp` cap that used to sit beside it is gone: the three
`getattr`-read controls were ported to read both protocol spellings, and the
range moved onto the current major rather than around it.

_Except where the evidence column says otherwise, the Observed columns come from
an integration-test matrix run outside this repository; that harness is not
published, so those cells are updated by hand when the matrix is re-run. The
`crewai` row is different: its versions are the ones `crewai-versions` covers on
a rerun, and it is the one row in this file that can be re-derived._
