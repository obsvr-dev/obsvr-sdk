# What this suite actually drives

Read this before trusting a green run on an integration surface.

## Which upstream packages are real in CI

`devDependencies` carries four real provider/framework packages, and `npm ci`
installs them, so a test may import any of them:

| Package | Driven by a test |
|---|---|
| `@modelcontextprotocol/sdk` | **yes** — `tests/integration/mcp-real-package.test.ts` connects a real `Client` to a real `McpServer` over the package's own `InMemoryTransport` |
| `openai` | resolution only — `tests/unit/module-hook-resolution.test.ts` |
| `@google/generative-ai`, `@openai/agents` | installed, imported by no test |

Every other integration — `langchain`, `llamaindex`, `vercel-ai`, `bedrock`,
`vertex`, `together`, `azure-openai`, `cloudflare`, `openai-compat` — is tested
against hand-written fakes. `@langchain/core`, `llamaindex`, `ai`, the AWS and
Google client libraries and `@anthropic-ai/sdk` are **not** devDependencies and
are not installed when this suite runs.

## Why the MCP gate got a real-package test and the others did not

`SECURITY.md` names the MCP tool gate as the surface to put a destructive
capability behind, so it is the surface least able to afford a test that cannot
fail for the right reason. **A real-package test covers it, and is what makes
the coverage on this surface hold.** It drives the upstream
`@modelcontextprotocol/sdk` client through the gate, so a release that renames
or moves the method obsvr binds turns it red.

That test exists because of what the mutation numbers showed. With the real deny
check replaced by `return { allowed: true }`, `tests/unit/mcp-integration.test.ts`
still passes **18 of 18** — it carries its own copy of the policy check,
annotated *"mirrors mcp.ts logic"*, and drives that copy rather than the module,
so it does not see the gate it appears to cover. Across the rest of the suite
exactly **three** pre-existing tests go red:

- the enforcement-reporting invariant's `mcp` row (`blocked implies not executed`)
- `emits MCP_TOOL_DENIED when the tool policy refuses a call`
- `stamps blocked tool calls too - what was refused is the record`

So the invariant does cover this surface. What none of the three could show is
that the gate still sits on the method the current package actually calls. The
real-package test adds four more red rows and cost nothing new — the package was
already a devDependency and no test imported it.

## What a fake-driven test can and cannot tell you

It **can** catch: a gate that stops refusing, a verdict recorded wrongly, a
regression in this SDK's own logic.

It **cannot** catch: an upstream release that renames the method being wrapped,
changes when a callback fires, or stops delivering one at all. Every finding of
that kind in this project's history was found by driving the real framework,
never by this suite.

So a green run here is not evidence that an integration still works against a
current install. That evidence comes from live probes against real frameworks
and real providers, and the surfaces which have never had it are named in
`COMPATIBILITY.md`.

## One test that must not be weakened

`tests/unit/optional-dependency-resolution.test.ts` walks every non-relative
import specifier in `src/` and asserts each one resolves. It has caught real
defects — including an MCP specifier that was wrong in both branches, so the
integration was not degraded to a fallback, it was off. Keep it in the suite and
keep it strict.
