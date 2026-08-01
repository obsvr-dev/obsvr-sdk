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
| `mcp`                     | `>=1.0.0,<2.0.0`                      | `1.29.0`                                             | declared       |
| `openai`                  | `>=1.66.0`                            | `1.0.0` – `2.50.0`                                   | floor located  |
| `openai-agents`           | `>=0.0.2`                             | `0.0.2` – `0.19.1`                                   | declared       |
| `opentelemetry-api`       | `>=1.20.0`                            | —                                                    | declared       |
| `pydantic-ai-slim`        | `>=0.4.4`                             | `0.4.4` – `2.19.0`                                   | declared       |
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
  environment per listed version, the tool governor driven through each
  release's own dispatch, and the range boundaries additionally driven live
  against a real provider with a denied tool's side effect at zero. **`crewai`
  is the only row that earns this today.** Its listed versions are the ones a
  rerun actually covers; the boundaries `1.0.0` and `1.15.10` are the live
  legs, and `1.15.2`/`1.15.3` are the adjacent pair locating the
  `before_tool_call` hook's arrival.
- **floor located** — the FLOOR is an adjacent tested pair established live
  (at the release below, the audited path is absent; at the floor, it is
  audited on a real call), with the reasoning recorded per extra in
  `sdk-python/pyproject.toml`. The open top is not covered by that work.
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
| `@openai/agents`                  | `>=0.13.0 <1.0.0`               | `0.13.0` – `0.14.0`   | declared       |
| `@opentelemetry/api`              | `>=1.4.0`                       | `1.4.0` – `1.9.1`     | declared       |
| `ai`                              | `>=3.3.28`                      | `3.4.33` – `7.0.41`   | declared       |
| `llamaindex`                      | `>=0.5.9`                       | `0.5.9` – `0.12.1`    | declared       |
| `openai`                          | `>=6.0.0 <8.0.0`                | `6.0.0` – `7.0.0`     | declared       |
| `together-ai`                     | `>=0.6.0 <1.0.0`                | `0.6.0` – `0.44.0`    | declared       |

`@google/generative-ai` is the legacy line, end-of-life 2025-08. Its replacement `@google/genai` is **not supported yet**.

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
| `mcp`   | Python   | `>=1.0.0,<2.0.0` | 2.0 renamed the tool descriptor fields the integration reads, which silently disables the schema scan and the capability gate. |

## Open support-matrix decisions

Recorded here rather than acted on: each is a decision about what this package
intends to support, which is the owner's call and not a defect to patch. All
three are stated as of the 2026-08-01 version sweep.

| Range | Latest upstream | The question |
| --- | --- | --- |
| `ag2>=0.3.2,<1.0` (Python) | `1.0.1` | The cap EXCLUDES the current major, so the declared range tracks only the pre-1.0 line. The cap itself is correct and load-bearing — 1.0 renamed the import package and removed the class the integration binds, both re-confirmed — so the question is whether to support 1.x at all, not whether to widen the cap. Separately, the 0.x line was forked and now publishes under the `autogen` distribution, so this range currently follows the abandoned half of a fork. |
| `mcp>=1.0.0,<2.0.0` (Python) | `2.0.0` | Same shape, same correctness: at 2.0 the hook still binds and the deny gate still fires, but protocol fields move to snake_case and three `getattr`-read controls go dark (schema-poisoning scan, tool pinning, destructive-capability hint gate). Supporting 2.x means porting those three reads, not relaxing the cap. |
| `ai>=3.3.28` (TypeScript) | `7.0.47` | Four majors of unbounded floor. The declared range promises every release from 3.3.28 onward, across four breaking majors, with no top. Nothing here says it is wrong — it says nothing has bounded it. |

The Python caps above are the only two ranges in either manifest that exclude
their package's current major, and each has a stated reason (see "Versions that
will not work"). Every other range is open at the top.

_Except where the evidence column says otherwise, the Observed columns come from
an integration-test matrix run outside this repository; that harness is not
published, so those cells are updated by hand when the matrix is re-run. The
`crewai` row is different: its versions are the ones `crewai-versions` covers on
a rerun, and it is the one row in this file that can be re-derived._
