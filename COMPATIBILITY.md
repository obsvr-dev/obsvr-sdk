# COMPATIBILITY

Version support for every integration the obsvr SDK declares, per package, per
language, with the artifact behind each boundary.

**This file is generated. Do not edit it.** It is produced by
`tools/gen_compatibility.py` in the shape-audit repo, which reads the declared ranges
live out of the SDK manifests and derives every verified boundary, version and
count from the recorded audit artifacts on each run. A hand-maintained matrix
drifts away from its evidence; this one cannot, because no measured value in it
is authored. Re-run it after a probe pass and the new evidence lands for free.

- Declared ranges read from `sdk-python/pyproject.toml` and `sdk-typescript/package.json`
- Evidence: **900 observations** over **25 package/language cells**, from **65 artifact files**
- Generated 2026-07-29
- Evidence captured against SDK `486923f`; SDK is now at `807e519`

> **The evidence is older than the SDK it describes.** Every cell below was
> measured against `486923f`; 40 commits have landed since,
> 33 of them touching the manifests this document reproduces
> or the integration sources its findings describe. Most recent first:
>
> - `807e519 Publish the compatible-endpoint wrapper the docs already sold`
> - `b1187ec Name the one surface the capability gate actually holds on`
> - `a349638 Anchor the two client ranges where auditing actually begins`
> - `486923f Trim redundant product names from three module docstrings`
> - `487bcd8 Call the stream helpers unbuilt, not unreachable`
> - `d232e0f Read the model off a config object, not only off a dict`
> - `3f4eb1c Repoint the autogen extra at the distribution the code binds`
> - `4625405 Hand back an already-governed client instead of wrapping it twice`
> - …and 25 more
>
> Boundaries are unaffected — they are facts about upstream releases, not about
> the SDK. Findings that describe the SDK's own surface can be superseded by
> those commits, and where this document can detect that, it says so in place
> rather than leaving the stale claim standing. Re-run the probes to clear it.

## How to read a row

| Basis | Means |
| --- | --- |
| **LIVE** | A real call through the real integration produced a **captured audit event** that the probe asserted on. The event is the evidence — not that the call returned. |
| **PE** | The integration binds its upstream symbols, or the client shape was read off a real install, and the code path was driven — but **no audit event from a real call was observed**. This can prove a break. It cannot prove the thing works. |
| **DECLARED ONLY** | No artifact. The range is what the manifest says, and nothing more. Says nothing either way. |

The Basis column is the strongest basis anywhere in the row. Where a single
boundary rests on something weaker, it is tagged *(PE)* in place — several rows
have a PE floor and a LIVE ceiling, and collapsing that into one letter would
overstate one end of the range.

Five rules govern what a cell is allowed to say:

1. **No artifact, no claim.** A cell with no observation reads DECLARED ONLY. Boundaries are never inferred from a neighbouring version, and never rounded toward the declared number.
2. **Single cell is not an adjacent pair.** A ceiling measured at the highest tested version says *the top still works*. It does not locate a break, and would not find one mid-range. It is labelled **single cell**. Only a tested cell that fails directly above a passing one earns *adjacent tested pair*.
3. **The two languages are never read across.** They are separate implementations with separate method tables and separate tool-gate code. A Python result says nothing about the TypeScript row of the same name, or the reverse.
4. **Unreachable is not untested.** A surface that cannot be called from this environment is its own state, recorded with the reason — not left to read as one nobody got to.
5. **A verified floor below the declared one is not an argument to lower it.** It means governance begins earlier for *some* path. Which path is the per-method-path table's job.

## Python

Declared ranges read from `sdk-python/pyproject.toml`.

| Package | Declared | Verified floor | Floor artifact | Verified ceiling | Ceiling artifact | Basis | Notes |
| --- | --- | --- | --- | --- | --- | :--: | --- |
| `ag2` | `>=0.3.2,<1.0` | `0.3.2`<br>PASS<br><sub>scenario `deny-weather-batched`</sub><br><sub>no cell below it was tested</sub> | `results/autogen-tool-policy.jsonl:14` | `0.14.0`<br>PASS<br><sub>scenario `deny-weather-batched`</sub><br><sub>**adjacent tested pair**: `1.0.0` NO_CONVERSABLE_AGENT</sub> | `results/autogen-tool-policy.jsonl:29` | **LIVE** | Ceiling is a measured adjacent pair rather than a precaution — see Exclusions. The floor cell `0.3.2` is live. Between the endpoints the walk is binding-only: 57 of the 59 releases walked bind. Cells that do not: `1.0.0` NO_CONVERSABLE_AGENT, `1.0.1` NO_CONVERSABLE_AGENT. Binding is duck-typed, so an existing install of the previously declared distribution `pyautogen` keeps being governed inside its own working range (`0.2.15`–`0.9` bind; `0.2.0` NO_HOOKS, `0.2.1` NO_HOOKS). |
| `anthropic` | `>=0.16.0` | `0.8.0`<br>PASS<br><sub>adjacent tested pair: `0.7.8` NO_AUDIT</sub> | `results/floor-live.jsonl:12` | `0.120.2`<br>PARTIAL<br><sub>**single cell** — nothing above it was tested</sub> | `results/anthropic-py.jsonl:1` | **LIVE** | The verified floor sits **below** the declared one, and that is not an argument for lowering it: at `0.8.0` the only audited path is `beta.messages.create`. The declared floor names the release where the path the range is about arrives. See the per-method-path table — the boundary is per path, not per range. Below that, `0.7.8` NO_AUDIT — a real client, a real init, a real call, and not one auditable path on the client. It stays silent while an operator sends traffic, with nothing raising. |
| `boto3` | `>=1.34.0` | — none | — | — none | — | **DECLARED ONLY** | No credential for this provider, and no introspection cell on this side. See Credential-blocked. |
| `crewai` | `>=0.30.0`<br><sub>`; python_version < '3.14'`</sub> | `1.15.8`<br>PASS<br><sub>scenario `ctl-chain-nolimit`</sub><br><sub>no cell below it was tested</sub> | `results/toolpolicy-crewai.jsonl:5` | `1.15.8`<br>PASS<br><sub>scenario `ctl-chain-nolimit`</sub><br><sub>**single cell** — nothing above it was tested</sub> | `results/toolpolicy-crewai.jsonl:5` | **LIVE** | Only `1.15.8` is evidenced. The declared range also carries the environment marker `; python_version < '3.14'`. |
| `google-cloud-aiplatform` | `>=1.38.0` | — none | — | — none | — | **DECLARED ONLY** | No credential for this provider, and no introspection cell on this side. See Credential-blocked. |
| `google-generativeai` | — *(no extra declares it)* | `0.8.6`<br>PASS<br><sub>no cell below it was tested</sub> | `results/gemini-python.jsonl:1` | `0.8.6`<br>PASS<br><sub>**single cell** — nothing above it was tested</sub> | `results/gemini-python.jsonl:1` | **LIVE** | **Evidenced but undeclared**: no extra in the manifest names this distribution, so the row has a verified floor and no range to compare it against. The auto path emitted **0 events** at this cell — `init()` alone does not pick this client up, and the event above came from an explicit wrap. The asymmetry with the other language is a documentation defect, not a structural one. |
| `haystack-ai` | `>=2.0.0` | `2.0.0`<br>PARTIAL<br><sub>failed: isRealHaystackComponent</sub><br><sub>no cell below it was tested</sub> | `results/haystack-pipeline.jsonl:1` | `3.0.0`<br>PARTIAL<br><sub>failed: isRealHaystackComponent</sub><br><sub>**single cell** — nothing above it was tested</sub> | `results/haystack-pipeline.jsonl:2` | **LIVE** | 2 cells, both emitting from a real pipeline and both blocking a policy-violating run. Both grade PARTIAL on the same check (`isRealHaystackComponent`) — the decorator resolves to a shim — so the governance claim holds and the component-identity caveat is kept rather than dropped. |
| `langchain-core` | `>=0.2.0` | `0.2.0`<br>PASS<br><sub>no cell below it was tested</sub> | `results/langchain-py.jsonl:1` | `1.5.2`<br>PASS<br><sub>scenario `ctl-chain-nolimit`</sub><br><sub>**single cell** — nothing above it was tested</sub> | `results/toolpolicy-langchain.jsonl:5` | **LIVE** | 8 live cells spanning both endpoints of the declared range. The same audit-versus-refusal split applies: the only tool gate implemented on this integration fires on a runtime that has left the current major, and was never successfully driven. |
| `llama-index-core` | `>=0.11.23` | `0.11.23`<br>PASS<br><sub>nearest tested cell below: `0.10.0` BROKEN</sub> | `results/li-floor-postfix.jsonl:1` | `0.14.23`<br>PARTIAL<br><sub>failed: modelCorrect, providerAttributed, inputTokens, outputTokens</sub><br><sub>**single cell** — nothing above it was tested</sub> | `results/llamaindex-py.jsonl:3` | **LIVE** | The declared floor is the lowest release VERIFIED working, not the lowest that works: everything below it is unmeasurable rather than proven broken. `0.10.0` BROKEN — driven, and no event. `0.10.1` PROBE_CRASH, `0.10.68` PROBE_CRASH, `0.11.0` PROBE_CRASH — the early dependency set does not resolve, or the probe does not complete, so those cells decide nothing in either direction. The ceiling cell `0.14.23` emits but fails modelCorrect, providerAttributed, inputTokens, outputTokens. |
| `mcp` | `>=1.0.0,<2.0.0` | `1.29.0`<br>PASS<br><sub>scenario `taint-flag-destructive`</sub><br><sub>no cell below it was tested</sub> | `results/toolpolicy-mcp.jsonl:7` | `1.29.0`<br>PASS<br><sub>scenario `taint-flag-destructive`</sub><br><sub>**single cell** — nothing above it was tested</sub> | `results/toolpolicy-mcp.jsonl:7` | **LIVE** | One cell only (`1.29.0`), sitting inside the range rather than at either end. Neither endpoint of `>=1.0.0,<2.0.0` is evidenced by a cell of its own; the upper bound's basis is in Exclusions. |
| `openai` | `>=1.66.0` | `1.0.0`<br>PASS<br><sub>no cell below it was tested</sub> | `results/floor-live.jsonl:1` | `2.50.0`<br>PASS<br><sub>**single cell** — nothing above it was tested</sub> | `results/floor-live.jsonl:10` | **LIVE** | The verified floor sits **below** the declared one, and that is not an argument for lowering it: at `1.0.0` the only audited path is `chat.completions.create`. The declared floor names the release where the path the range is about arrives. See the per-method-path table — the boundary is per path, not per range. |
| `openai-agents` | `>=0.0.2` | `0.0.2`<br>PASS<br><sub>no cell below it was tested</sub> | `results/openai-agents-py.jsonl:1` | `0.19.1`<br>PASS<br><sub>scenario `taint-block-destructive`</sub><br><sub>**single cell** — nothing above it was tested</sub> | `results/toolpolicy-openai-agents.jsonl:7` | **LIVE** | 4 live cells including the declared floor. Note this is coverage of *auditing*, not of refusal: the tool gate on this surface is post-hoc, and a denied tool runs before the denial is recorded. |
| `opentelemetry-api` | `>=1.20.0` | — none | — | — none | — | **DECLARED ONLY** | The span assertions in this corpus are TypeScript-only and may not be read across. |
| `pydantic-ai-slim` | `>=0.4.4` | `0.4.4`<br>PASS<br><sub>adjacent tested pair: `0.4.3` BROKEN</sub> | `results/pydantic-ai.jsonl:6` | `2.19.0`<br>PASS<br><sub>**single cell** — nothing above it was tested</sub> | `results/pydantic-ai.jsonl:4` | **LIVE** | The tightest floor in this matrix: `0.4.3` BROKEN — the bound symbol does not exist and the integration silently falls back to a shim, so the governed object is returned but is not one the framework accepts — and `0.4.4` emits. An adjacent tested pair straddling the declared number. |
| `starlette` | `>=0.30.0` | `0.30.0` *(PE)*<br>PASS<br><sub>no cell below it was tested</sub> | `results/py-guarded-2b.jsonl:7` | `1.3.1`<br>PASS<br><sub>scenario `direct_wrap`</sub><br><sub>**single cell** — nothing above it was tested</sub> | `results/fastapi-span.jsonl:2` | **LIVE** | Split basis, and the strengths sit at opposite ends: `0.30.0` is a binding check only, while the live cell — a real request producing a chain-signed event — is at `1.3.1`, the top of the tested set. So the floor is PE and the ceiling LIVE, and the row's LIVE badge is not true of its floor. |

## TypeScript

Declared ranges read from `sdk-typescript/package.json`.

| Package | Declared | Verified floor | Floor artifact | Verified ceiling | Ceiling artifact | Basis | Notes |
| --- | --- | --- | --- | --- | --- | :--: | --- |
| `@anthropic-ai/sdk` | `>=0.20.0` | `0.20.0`<br>PASS<br><sub>no cell below it was tested</sub> | `results/anthropic.jsonl:5` | `0.115.0`<br>PASS<br><sub>**single cell** — nothing above it was tested</sub> | `results/anthropic-beta.jsonl:2` | **LIVE** | 5 live cells. No cell failed. Every version named in the declared range has a cell of its own. `beta.messages.create` is evidenced at **one cell only** (`0.115.0`) — see the per-method-path table. The other cells cover the GA path alone. |
| `@aws-sdk/client-bedrock-runtime` | `>=3.586.0` | `3.1096.0` *(PE)*<br>PASS (introspection)<br><sub>nearest tested cell below: `3.422.0` PARTIAL</sub> | `results/introspect.jsonl:2` | `3.1096.0` *(PE)*<br>PASS (introspection)<br><sub>**single cell** — nothing above it was tested</sub> | `results/introspect.jsonl:2` | **PE** | Introspection only — no credential, so no call. `3.422.0`, below the declared floor, is absent: `ConverseCommand`, `ConverseStreamCommand` — the command classes the integration reads are not on the module there. That is consistent with the declared floor but does not establish it: the declared floor release itself was never tested, so where between the two the symbols appear is unmeasured. |
| `@google-cloud/vertexai` | `>=1.0.0` | `1.0.0` *(PE)*<br>PASS (introspection)<br><sub>no cell below it was tested</sub> | `results/introspect.jsonl:3` | `1.12.0` *(PE)*<br>PASS (introspection)<br><sub>**single cell** — nothing above it was tested</sub> | `results/introspect.jsonl:4` | **PE** | Introspection only — no credential, so no call. The symbols the integration reads are present at every tested cell. |
| `@google/generative-ai` | `>=0.1.0 <1.0.0` | `0.1.0`<br>PASS<br><sub>no cell below it was tested</sub> | `results/gemini-matrix-final.jsonl:1` | `0.24.1`<br>PASS<br><sub>**single cell** — nothing above it was tested</sub> | `results/gemini-matrix-final.jsonl:25` | **LIVE** | 25 live cells. No cell failed. The declared range names 2 versions; `0.1.0` has a cell, `1.0.0` does not. |
| `@langchain/core` | `>=0.2.0` | `0.2.0`<br>PASS<br><sub>no cell below it was tested</sub> | `results/langchain-ts.jsonl:1` | `1.2.3`<br>PASS<br><sub>**single cell** — nothing above it was tested</sub> | `results/langchain-ts.jsonl:5` | **LIVE** | 5 live cells. No cell failed. Every version named in the declared range has a cell of its own. |
| `@modelcontextprotocol/sdk` | `>=1.0.0 <1.25.0 || >=1.30.0` | `1.30.0` *(PE)*<br>PASS<br><sub>no cell below it was tested</sub> | `results/mcp-resolution.jsonl:1` | `1.30.0` *(PE)*<br>PASS<br><sub>**single cell** — nothing above it was tested</sub> | `results/mcp-resolution.jsonl:1` | **PE** | PE, not LIVE, and the cell's own `PASS` is about resolution: `deepSpecifierResolves`, `fallbackSpecifierResolves`, `oldRootFallbackStillUnresolvable`, `renamedSpecifierIsGone`, `clientClassReached`, `callToolPatchable`. **No artifact shows a governed tool call against a real server.** Governance on this surface is covered by the offline suites, which are not version evidence. |
| `@openai/agents` | `>=0.13.0 <1.0.0` | `0.13.0`<br>PARTIAL<br><sub>failed: llmModelCorrect</sub><br><sub>no cell below it was tested</sub> | `results/openai-agents.jsonl:1` | `0.14.0`<br>PASS<br><sub>**single cell** — nothing above it was tested</sub> | `results/openai-agents.jsonl:3` | **LIVE** | 2 cells, both live. `0.14.0` was run twice; the earlier run failed its model-attribution check and the re-run appended after the fix is the one reported here. `0.13.0` PARTIAL has no such re-run, so it stands at PARTIAL (llmModelCorrect). |
| `@opentelemetry/api` | `>=1.4.0` | `1.4.0` *(PE)*<br>PASS (introspection)<br><sub>no cell below it was tested</sub> | `results/introspect.jsonl:5` | `1.9.1` *(PE)*<br>PASS (introspection)<br><sub>**single cell** — nothing above it was tested</sub> | `results/introspect.jsonl:6` | **LIVE** | Mixed basis, and the strengths do not line up with the endpoints: the span assertions ran at `1.9.0` only, while `1.4.0`, `1.9.1` are introspection. The floor and ceiling cells are therefore PE and the live cell sits between them. |
| `ai` | `>=3.3.28` | `3.4.33`<br>PARTIAL<br><sub>failed: block.providerAttributed, block.modelAttributed</sub><br><sub>nearest tested cell below: `3.0.0` BROKEN</sub> | `results/ai-matrix.jsonl:12` | `7.0.41`<br>PASS<br><sub>**single cell** — nothing above it was tested</sub> | `results/ai-matrix.jsonl:24` | **LIVE** | **The declared floor `3.3.28` was never tested** — the lowest tested cell that emits is `3.4.33`. Cells below the verified floor were driven and did not govern: `3.0.0` BROKEN. 3 cells (`3.4.33`, `4.0.0`, `4.3.19`) emit but fail block.providerAttributed, block.modelAttributed — those are the versions where the row is LIVE without being clean. |
| `llamaindex` | `>=0.5.9` | `0.5.9`<br>PARTIAL<br><sub>failed: modelCorrect, providerAttributed, inputTokens, outputTokens</sub><br><sub>adjacent tested pair: `0.5.8` BROKEN</sub> | `results/llamaindex-ts.jsonl:8` | `0.12.1`<br>PASS<br><sub>**single cell** — nothing above it was tested</sub> | `results/llamaindex-ts.jsonl:10` | **LIVE** | Floor is a measured boundary rather than the lowest thing tried: `0.5.0` BROKEN, `0.5.8` BROKEN — driven, no event — and `0.5.9` emits. 4 cells emit an event but fail their attribution checks (modelCorrect, providerAttributed, inputTokens, outputTokens), so most of the range is governed without being correctly attributed. Only `0.12.1` is clean, and only in the run appended after the integration fix. `0.5.27` UNINSTALLABLE — no information in either direction. |
| `openai` | `>=6.0.0 <8.0.0` | `6.0.0`<br>PASS<br><sub>no cell below it was tested</sub> | `results/openai.jsonl:1` | `7.0.0`<br>PASS<br><sub>**single cell** — nothing above it was tested</sub> | `results/openai.jsonl:3` | **LIVE** | 4 live cells. No cell failed. The declared range names 2 versions; `6.0.0` has a cell, `8.0.0` does not. |
| `together-ai` | `>=0.6.0 <1.0.0` | `0.6.0`<br>PASS<br><sub>no cell below it was tested</sub> | `results/together.jsonl:1` | `0.44.0`<br>PASS<br><sub>**single cell** — nothing above it was tested</sub> | `results/together.jsonl:3` | **LIVE** | All 3 cells were driven against `https://api.groq.com/openai/v1`, which the probe hardcodes (`harness/probe-together.mjs:18`). **The distribution's own service was never called, in either language** — no credential for it exists. The `provider` label is a wrapper constant, not a function of the endpoint: the same wrapper emits `provider: "together"` for both `http://localhost:11434/v1` and `https://api.groq.com/openai/v1` (`shape-audit-providers/results/prov-ts-compat.jsonl:1`). So the row's provider-label assertion is vacuous with respect to which service answered — it tests that the SDK writes a constant. What *is* verified is the vendor-wrapper → generic-compat → `chat.completions.create` path against a real chat-completions-compatible server. A shared code path is not evidence of a call to the service. |

### The generic `openai-compat` surface

Not a package, so not a row — but three rows above it are vendor wrappers over
this one code path, and they cannot be read correctly without it.

**Reachability (TypeScript).** Of 3 import specifiers tested, 2 fail and 1 resolves:

| Specifier | Result when measured | Still true? |
| --- | --- | --- |
| `public_subpath` | `ERR_PACKAGE_PATH_NOT_EXPORTED` | **no — `./openai-compat` is an export in the current manifest** |
| `deep_subpath` | `ERR_PACKAGE_PATH_NOT_EXPORTED` | n/a |
| `file_url` | `ok` | n/a |

The specifier that resolved bypasses the exports map, which is what placed
the fault in the manifest rather than the implementation — *not exported*,
not *not implemented*, and different fixes.

**1 of these verdicts has since been superseded.** The
finding was real when measured, and a commit that landed after the
evidence was captured addresses it; the check above is the exports map
read live against the recorded verdict, not a re-measurement. Both states
are shown rather than either one alone — re-run the probe to replace the
recorded column.

**Attribution (Python).** The same probe against two different endpoints:

| Endpoint | `provider` | `source` | Names the service? |
| --- | --- | --- | :--: |
| `http://localhost:11434` | `openai` | `python_wrap` | **no** |
| `https://api.groq.com` | `openai` | `python_wrap` | **no** |

Endpoints in different places produce byte-identical provider
attribution. In a Python audit log they are distinguishable only by the
`model` string; nothing records which service received the prompt.

**A field the two languages do not agree on.** Against the same endpoint and payload, TypeScript emits `model_resolved`, `provenance_source` and Python emits neither, so a Python operator cannot answer "which
exact model decided" from the audit log. Since the endpoint and payload
are identical, the difference is the SDK.

## Per-method-path boundaries

The package boundary is not the whole answer for the two direct provider
clients. A release can be installable, constructible and fully governed on one
method path while another path the SDK's own method table names does not exist
on the client yet. An operator who resolves a floor that predates their path
builds a client, wires the SDK, sends traffic, and gets no audit events — with
nothing raising. That is why these tables exist, and why the package-level row
above is not sufficient for these two.

### `openai` — Python

Declared `>=1.66.0`. Exhaustive walk: one throwaway environment per
published release, **326 releases**, `1.0.0` → `2.50.0`, no
bisect anywhere. Every boundary below is therefore an adjacent tested pair with
no untested gap.

| Method path | First release exposing it | Adjacent tested pair | Live grade there | Releases where present |
| --- | --- | --- | :--: | --: |
| `chat.completions.create` | **1.0.0** | — (present at the lowest release walked) | A/A | 326 |
| `beta.chat.completions.parse` | **1.40.0** | `1.39.0` → `1.40.0` | A/A | 221 |
| `responses.create` | **1.66.0** | `1.65.5` → `1.66.0` | A/A | 141 |
| `responses.parse` | **1.66.0** | `1.65.5` → `1.66.0` | A/A | 141 |
| `beta.chat.completions.create` | **1.92.0** | `1.91.0` → `1.92.0` | A/A | 105 |
| `chat.completions.parse` | **1.92.0** | `1.91.0` → `1.92.0` | A/A | 105 |
| `beta.responses.create` | **2.45.0** | `2.44.0` → `2.45.0` | A/A | 6 |

Live grade is `auto/wrap` — the construct-interception path and the explicit-wrap
path, each graded on the captured event. `A` = audited, `—` = the path does not
exist at that release, `CF` = the probe's call recipe failed. `CF` is recorded
distinctly from a missing event on purpose: it is a probe limitation and must not
be read as a governance result.

Non-monotonic paths — present, absent again, present. Each was read at the
boundary release rather than inferred:

- `responses.create` reads absent from `1.99.0` up to the release below `1.99.1`.
- `responses.parse` reads absent from `1.99.0` up to the release below `1.99.1`.

The declared floor is honest per path rather than per range. Raising it to cover the last path to arrive would misdescribe the much larger set of releases on which the middle paths do work; leaving it at the first path's release promises six paths it does not deliver. The count column above is what that trade-off costs, measured.

### `anthropic` — Python

Declared `>=0.16.0`. Exhaustive walk: one throwaway environment per
published release, **197 releases**, `0.3.0` → `0.120.2`, no
bisect anywhere. Every boundary below is therefore an adjacent tested pair with
no untested gap.

| Method path | First release exposing it | Adjacent tested pair | Live grade there | Releases where present |
| --- | --- | --- | :--: | --: |
| `beta.messages.create` | **0.8.0** | `0.7.8` → `0.8.0` | A/A | 127 |
| `messages.create` | **0.16.0** | `0.15.1` → `0.16.0` | A/A | 162 |
| `messages.parse` | **0.77.0** | `0.76.0` → `0.77.0` | CF/CF | 57 |

Live grade is `auto/wrap` — the construct-interception path and the explicit-wrap
path, each graded on the captured event. `A` = audited, `—` = the path does not
exist at that release, `CF` = the probe's call recipe failed. `CF` is recorded
distinctly from a missing event on purpose: it is a probe limitation and must not
be read as a governance result.

Non-monotonic paths — present, absent again, present. Each was read at the
boundary release rather than inferred:

- `beta.messages.create` reads absent from `0.16.0` up to the release below `0.36.0`.

One path is **not established**: it grades `CALL_FAILED` wherever it exists, because the probe's call recipe passes an argument that is not that method's signature. That is a probe limitation, recorded as `CALL_FAILED` rather than as a missing event precisely so it cannot be read as a governance result. Its shape boundary stands; its live grading does not.

The beta-namespace gap above is genuine upstream history rather than a regression: the namespace was removed when that API graduated and returned later without the sub-namespace. Raising the floor to cover the beta path is a real option, and a different number from the one declared.

### `openai` — TypeScript

No exhaustive per-release path walk exists on this side, and the Python one may
not be read across. What the artifacts support is **which audited operations were
observed on a captured event, and at which versions** — coverage, not a boundary.
A path absent from this table was not measured; it is not thereby broken.

| Operation observed on a captured event | Versions | Cells | Artifact |
| --- | --- | :--: | --- |
| `chat.completions.create` | `6.0.0` – `7.0.0` | 4 | `results/openai.jsonl:1 +6` |
| `chat.completions.runTools.finish` | `6.47.0` | 1 | `results/tool-runners.jsonl:1` |
| `chat.completions.runTools.llm` | `6.47.0` | 1 | `results/tool-runners.jsonl:1` |
| `chat.completions.runTools.tool` | `6.47.0` | 1 | `results/tool-runners.jsonl:1` |

The non-streaming Responses path is present on the client shape at every cell but was never driven live on this side — only its streaming helper was. It is therefore PE on TypeScript whatever the Python walk shows, per rule 3.

### `@anthropic-ai/sdk` — TypeScript

No exhaustive per-release path walk exists on this side, and the Python one may
not be read across. What the artifacts support is **which audited operations were
observed on a captured event, and at which versions** — coverage, not a boundary.
A path absent from this table was not measured; it is not thereby broken.

| Operation observed on a captured event | Versions | Cells | Artifact |
| --- | --- | :--: | --- |
| `beta.messages.create` | `0.115.0` | 1 | `results/anthropic-beta.jsonl:2` |
| `messages.create` | `0.20.0` – `0.115.0` | 5 | `results/anthropic-beta.jsonl:1 +6` |

The beta path is evidenced at one cell only, and only in the run appended after the integration fix: the earlier run of that same cell emitted no event for the beta path while its control passed. The cells below it cover the GA path alone.

## Credential-blocked surfaces

These are **unreachable, not untested**. No credential for them exists in the
environment that produced this evidence, so no call can be made. The distinction
matters: an untested row invites someone to go and test it, and these cannot be
tested until that changes. Nothing below was filled in by substituting a different
endpoint for the one named.

| Surface | Languages | Why unreachable | What that leaves standing | Artifact |
| --- | --- | --- | --- | --- |
| `@obsvr/sdk/bedrock` · `bedrock` extra | TS + Python | No credential for this provider exists in this environment. | TypeScript: symbols introspected, no call. Python: no artifact at all — the client library has no cell of any kind. | `results/introspect.jsonl:1`, `results/introspect.jsonl:2` |
| `@obsvr/sdk/vertex` · `vertex` extra | TS + Python | No credential for this provider exists in this environment. | TypeScript: symbols introspected, no call. Python: no artifact at all. | `results/introspect.jsonl:3`, `results/introspect.jsonl:4` |
| `@obsvr/sdk/azure-openai` | TS | No credential, and no `peerDependencies` entry either — the wrapper takes a client whose package it does not name, so there is no declared range to verify. | Shares the generic compat wrapper with the other vendor-labelled wrappers, so the code path has indirect evidence only. A shared code path is not evidence of a call to the service. | — none |
| `@obsvr/sdk/cloudflare` | TS | No credential, and no `peerDependencies` entry either — the wrapper takes a client whose package it does not name, so there is no declared range to verify. | Shares the generic compat wrapper with the other vendor-labelled wrappers, so the code path has indirect evidence only. A shared code path is not evidence of a call to the service. | — none |
| the `together-ai` service endpoint | TS + Python | No credential for it exists. The probe substitutes a different chat-completions-compatible endpoint (`api.groq.com`) at `harness/probe-together.mjs:18`. | The distribution's cells are real calls to that other endpoint. Substituting one endpoint for another was the flaw being corrected, so it was not repeated to fill this row. | `harness/probe-together.mjs:18` |
| other chat-completions-compatible endpoints | TS + Python | No credential. | Never exercised. The endpoints that *were* exercised are `api.groq.com`, `localhost:11434` — anything else would run through the generic compat path, whose state is described below the TypeScript table. | `shape-audit-providers/results/prov-python-compat.jsonl:2`, `shape-audit-providers/results/prov-ts-compat.jsonl:1` |

## Exclusions

Ranges the manifests deliberately close, and what establishes each. The ranges are
read live; whether a bound is *verified* is computed from the cells above it, so a
precautionary bound cannot quietly present as a measured one.

| Package | Language | Declared range | Basis for the bound | Why |
| --- | --- | --- | --- | --- |
| `ag2` | Python | `>=0.3.2,<1.0` | VERIFIED — adjacent tested pair | The major above the bound removes the agent class this integration binds and renames the import package, so both bound symbols are gone. Measured: `0.14.0` PASS inside the range, `1.0.0` NO_CONVERSABLE_AGENT, `1.0.1` NO_CONVERSABLE_AGENT outside it. |
| `mcp` | Python | `>=1.0.0,<2.0.0` | VERIFIED — outside this corpus | The major above the bound moves the protocol types to a snake_case base model, renaming all three descriptor fields this integration reads through `getattr` (`inputSchema`, `nextCursor`, `destructiveHint`). Each would read as absent rather than raise, which silently switches off the schema-surface poisoning scan, drops the schema out of the descriptor pin hash, and empties the destructive-capability gate. The renames were confirmed against the upstream types and the finding is recorded in the manifest; **no cell in this corpus tests a release outside the range**, so this file cannot re-derive it. |
| `@google/generative-ai` | TypeScript | `>=0.1.0 <1.0.0` | VERIFIED — nothing above the bound is published | The bound is exact rather than defensive. The npm release list recorded at `shape-audit-providers/results/floor-candidate-lists.jsonl:9` (40 releases, queried 2026-07-29T09:17:29+00:00) tops out at `0.24.1`, below the bound. |
| `@modelcontextprotocol/sdk` | TypeScript | `>=1.0.0 <1.25.0 || >=1.30.0` | DECLARED ONLY | The carve-out excludes a window in the middle of the range as well as capping it. The reason for that window is not established here. No cell in this corpus falls outside the declared range, so the bound is unverified here in either direction — it may guard a real break or a release line that was never published, and this evidence cannot tell those apart. |
| `@openai/agents` | TypeScript | `>=0.13.0 <1.0.0` | DECLARED ONLY | No cell in this corpus falls outside the declared range, so the bound is unverified here in either direction — it may guard a real break or a release line that was never published, and this evidence cannot tell those apart. |
| `openai` | TypeScript | `>=6.0.0 <8.0.0` | DECLARED ONLY | No cell in this corpus falls outside the declared range, so the bound is unverified here in either direction — it may guard a real break or a release line that was never published, and this evidence cannot tell those apart. |
| `together-ai` | TypeScript | `>=0.6.0 <1.0.0` | DECLARED ONLY | No cell in this corpus falls outside the declared range, so the bound is unverified here in either direction — it may guard a real break or a release line that was never published, and this evidence cannot tell those apart. |

## DECLARED ONLY — what this matrix cannot back

**3 rows** carry a declared range and no artifact at all.
This is the honest statement of the matrix's limits: every row below is a range
the SDK publishes that nothing in this corpus verifies, in either direction.

| Package | Language | Declared | Why there is no artifact |
| --- | --- | --- | --- |
| `opentelemetry-api` | Python | `>=1.20.0` | The span assertions in this corpus are TypeScript-only and may not be read across. |
| `boto3` | Python | `>=1.34.0` | No credential for this provider, and no introspection cell on this side. See Credential-blocked. |
| `google-cloud-aiplatform` | Python | `>=1.38.0` | No credential for this provider, and no introspection cell on this side. See Credential-blocked. |

Separately, **5 rows** do carry artifacts while their
**declared floor specifically** is unevidenced — the lowest cell with an artifact
sits above it, so the bottom of the published range is unverified even though the
row is not:

| Package | Language | Declared floor | Lowest cell with an artifact | Gap |
| --- | --- | --- | --- | --- |
| `mcp` | Python | `1.0.0` | `1.29.0` | no cell at or below the declared floor was ever attempted |
| `crewai` | Python | `0.30.0` | `1.15.8` | no cell at or below the declared floor was ever attempted |
| `@aws-sdk/client-bedrock-runtime` | TypeScript | `3.586.0` | `3.1096.0` | the cells below it (`3.422.0`) show the bound symbols absent, which is consistent with the floor but does not locate it |
| `@modelcontextprotocol/sdk` | TypeScript | `1.0.0` | `1.30.0` | no cell at or below the declared floor was ever attempted |
| `ai` | TypeScript | `3.3.28` | `3.4.33` | the cells below it (`3.0.0`) were driven and emitted nothing |

## Not in this matrix

Extras that gate the SDK's own optional runtime rather than a third-party
surface. There is no upstream package to walk, so they get no row — but their
ranges are shown rather than dropped:

| Extra | Requirement | Why no row |
| --- | --- | --- |
| `crypto` | `cryptography>=41.0.0` | Ed25519 verification backend for signed remote policy. SDK-internal. |
| `crypto-nacl` | `PyNaCl>=1.0.0` | The alternative backend for that same code path. Only one is ever resolved, so the two are mutually exclusive by design. |
| `dev` | `pytest>=7.0`, `cryptography>=41.0.0`, `hypothesis>=6.0` | Test suite only. Not installed by users, not an integration surface. |

**Withdrawn integrations.** Four integrations were withdrawn from the supported
surface. They are absent from this file by construction rather than by omission:
the generator drops their observations at read time, so no future run can
reintroduce them. 16 artifact files in the evidence roots
belong to them and contributed nothing here; they remain in the audit repo as
history.

## Provenance

- Generator: `tools/gen_compatibility.py` (shape-audit repo), which is committed alongside this output.
- Evidence roots: `/Users/sivasaran/Desktop/obsvr-integration-tests/shape-audit/results`, `/Users/sivasaran/Desktop/obsvr-integration-tests/shape-audit-providers/results`
- 65 artifact files read; 900 observations extracted.
- Artifact references are `file:line` into those roots. Every boundary in this
  document is checkable by opening the line it names.
