# What this suite actually drives

Read this before trusting a green run on an integration surface.

## Which upstream packages are real in CI

| Package | In CI | Driven by |
|---|---|---|
| `mcp` | **yes** — declared in the `dev` extra | `test_mcp_real_package.py` stands up a real `FastMCP` server and a future auto-governed `ClientSession` over the package's own in-memory transport; denial leaves the server tool at zero executions |
| `langchain-core` | **yes** — declared in the `dev` extra | `test_langchain_real_package.py` drives the real model-start callback boundary |
| `llama-index-core` | **yes** — declared in the `dev` extra | `test_llamaindex_real_package.py` drives the real callback payload shape |
| `openai` | **yes** — isolated provider CI cell | `test_openai_text_routes_real_package.py` drives the official client with a local transport |
| `anthropic` | **yes** — isolated provider CI cell | `test_provider_tool_runners_real_package.py` drives the official Messages runner and proves a later blocked turn makes no second request |
| `openai-agents` | **yes** — isolated provider CI cell | `test_openai_agents_real_package.py` drives explicit model/model-provider enforcement and automatic future-Agent model assignment plus late tool-list mutation through a real Runner; denied model and tool paths remain at zero executions |
| `google-genai` | **yes** — dev extra and isolated provider CI cell | `test_google_genai_real_package.py` drives the real 2.x request models, streams, and chat resource shape |
| `google-generativeai` | **yes** — isolated provider CI cell | `test_google_generativeai_real_package.py` drives official legacy model and chat objects |
| `google-cloud-aiplatform` | **yes** — isolated provider CI cell | `test_vertex_real_package.py` drives official stable/preview model and chat objects |
| everything else | no | hand-written fakes that duck-type the shape each integration reads |

`crewai`, `autogen`, `haystack`, `pydantic_ai`, and `bedrock` still rely on
fake-driven default-suite coverage or external version harnesses. Their tests
pin the SDK's own logic and its assumptions about a shape; the compatibility
table names the stronger point or range evidence where it exists.

## Why provider packages use isolated cells

Each provider cell installs one exact resolver-admitted package version beside
the SDK and drives the official object shape with local transport. Isolation is
load-bearing: current provider/framework extras can require incompatible MCP or
OpenAI major lines, so one combined environment would either fail resolution or
silently test a different dependency set.

The default `.[dev]` run therefore reports skips for the six isolated provider
files, the provider-alias checks that need OpenAI or Anthropic, and Haystack when
that optional extra is absent. Those skips are expected only in the combined
environment. The CI provider matrix installs each pinned official package and
runs its corresponding file separately; a skipped isolated cell is a failed CI
job rather than accepted coverage.

It does not enter the blocking dependency audit. That job runs
`pip-audit --strict .` over declared **runtime** dependencies, which are still
empty; the audit that would see a test dependency is report-only, by an existing
and deliberate split.

## What a fake-driven test can and cannot tell you

It **can** catch: a gate that stops refusing, a verdict recorded wrongly, a
regression in this SDK's own logic. Those are real and the suite catches them —
measured, not assumed. Replacing the MCP deny check with
`return {"allowed": True}` turns **six** existing tests red: four in
`test_mcp.py`, the `[mcp]` row of the enforcement-reporting invariant, and the
blocked-tool-call row of `test_tool_content_hash_wiring.py`. That is the
opposite of what the fakes-everywhere framing suggests: these fakes drive the
real gate rather than a copy of it.

It **cannot** catch: an upstream release that renames the method being wrapped,
changes when a callback fires, or stops delivering one at all. Every finding of
that kind in this project's history was found by driving the real framework,
never by this suite.

So a green run here is not evidence that an integration still works against a
current install. That evidence comes from live probes against real frameworks
and real providers, and the surfaces which have never had it are named in
`COMPATIBILITY.md`.

## Strict profile 2.1 evidence

The strict receipt tests drive the real Python implementation rather than a restated policy gate:

- `test_strict_provider_boundary_v2_1.py` proves exact cleaned-argument binding, unique action ids, target re-reading, admission/commit/checkpoint ordering, provider-error preservation, and fail-closed unsupported surfaces with provider-shaped fakes. It also drives the installed maintained Gemini package without network access.
- `test_strict_provider_boundary_v2_1_outcomes.py`, `test_strict_execution_outcome_v2_1.py`, and `test_strict_receipt_runtime_v2_1_terminal.py` cover signed success/failure outcomes, post-start finalization failures, and unresolved `invocation_uncertain` state.
- `test_strict_action_boundary_v2_1.py` and the strict coordinator/runtime approval tests cover provider-neutral side effects, exact-action approval, expiry, revalidation, optional separation of duties, and at-most-once execution.
- `test_strict_receipt_runtime_v2_1.py` and `test_strict_receipt_recovery_v2_1.py` cover durable phase ordering, ambiguous admission, checkpoint failure, freeze/reconcile behavior, and the no-automatic-retry boundary after invocation starts.
- `test_strict_runtime_recovery_v2_1.py`, `test_strict_policy_continuity_v2_1.py`, and `test_strict_evidence_bundle_v2_1.py` cover persisted-runtime recovery, policy-history reconstruction, and portable bundle verification.
- `test_strict_otel_correlation_v2_1.py` verifies content-free OpenTelemetry correlation after durable checkpoints without making telemetry authoritative.
- `test_strict_receipt_v2_1.py`, action-context, intent-alignment, identity, and evaluation-evidence tests consume the shared cross-language fixtures and verify the signed receipt itself.

Controlled live OpenAI, Anthropic, and maintained Gemini calls are release-validation probes outside CI. They are recorded as point-in-time evidence in `COMPATIBILITY.md`; they do not turn every method or upstream version into live-tested coverage.
