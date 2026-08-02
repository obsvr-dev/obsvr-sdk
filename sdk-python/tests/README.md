# What this suite actually drives

Read this before trusting a green run on an integration surface.

## One upstream framework package is real in CI. The rest are fakes.

| Package | In CI | Driven by |
|---|---|---|
| `mcp` | **yes** — declared in the `dev` extra | `test_mcp_real_package.py` stands up a real `FastMCP` server and a real `ClientSession` over the package's own in-memory transport |
| everything else | no | hand-written fakes that duck-type the shape each integration reads |

`langchain`, `llamaindex`, `crewai`, `autogen`, `haystack`, `pydantic_ai`,
`fastapi`, `bedrock`, `vertex` and `openai_agents` are each declared as an
optional extra for callers, and **none of them is installed when this suite
runs.** Their tests construct objects that look like the framework's, so they
pin the SDK's own logic and its assumptions about a shape — not that the shape
is still the framework's.

## Why `mcp` is the exception

`SECURITY.md` names the MCP tool gate as the surface to put a destructive
capability behind. It is therefore the one surface where a test that restates
the gate instead of driving it is most expensive, and the one where the cost of
a real dependency is most clearly worth paying.

The version is the same specifier the `mcp` extra declares, so the version this
is tested against is the version a caller installs.

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
