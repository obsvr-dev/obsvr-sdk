# @obsvr/sdk

Runtime governance for LLM applications: intercept every model and tool call, enforce deterministic policies (PII, allowlists, budgets, custom rules), and produce a tamper-evident audit trail. One line to integrate.

## Installation

> Private beta — not yet published to npm. Request access at [obsvr.dev](https://obsvr.dev).

```bash
npm install @obsvr/sdk    # private beta — not yet on npm; request access at obsvr.dev
```

Requires **Node.js >= 22**.

## Quick Start

Wrap your existing LLM client. No other code changes.

```typescript
import { obsvr } from '@obsvr/sdk';
import OpenAI from 'openai';

obsvr.init({
  apiKey: process.env.OBSVR_API_KEY,
  ingestUrl: 'https://your-ingest-service', // HTTPS enforced for non-localhost
  environment: 'production',
});

// Wrap your existing client
const openai = obsvr.wrap(new OpenAI({ apiKey: process.env.OPENAI_API_KEY }));

// Every call is now intercepted, policy-checked, and audited
const response = await openai.chat.completions.create({
  model: 'gpt-4o',
  messages: [{ role: 'user', content: 'What is 2+2?' }],
});
```

Anthropic and Google Gemini work the same way:

```typescript
const anthropic = obsvr.wrap(new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY }));
// Gemini via @google/generative-ai — see the note below on which SDK this is
const gemini = obsvr.wrap(genAI.getGenerativeModel({ model: 'gemini-2.5-flash' }));
```

**Which Gemini SDK.** Google ships two, and obsvr integrates one of them:

| Package | State |
| --- | --- |
| `@google/generative-ai` | **supported, compatibility only** — legacy line, last release 0.24.1, end-of-life August 2025 |
| `@google/genai` | **not yet supported** — the current SDK; obsvr does not intercept it and has no adapter for it |

Compatibility only means fixes, not features: the legacy adapter is kept working because a large installed base still runs it, and instrumenting what people actually run is the point. Note that npm carries **no deprecation flag on any version** of either package, so neither `npm outdated` nor `npm audit` will tell you which one you have — check your `package.json`. `@google/genai` has a different response shape, so support for it is new work rather than a rename.

### Zero-code global coverage (no monkey patching)

If you would rather not call `wrap()` on every client, start Node with the obsvr module interceptor:

```bash
node --import @obsvr/sdk/register app.js
# or: NODE_OPTIONS="--import @obsvr/sdk/register" npm start
```

Every `new OpenAI()`, `new Anthropic()`, and `getGenerativeModel()` in the process (including ones created inside third-party libraries) then returns a governed instance automatically. obsvr never mutates provider prototypes, classes, or module objects: the interceptor swaps the module's exported class for a construct-trap `Proxy`, and the instance underneath stays a genuine SDK client. APM, tracing, and other instrumentation layered on the same SDKs keep working. Clients constructed before `obsvr.init()` pass through untouched and pick up governance on their first call after init.

Use `providers: ['openai']` in `obsvr.init()` to narrow which providers the interceptor governs; omit it to govern all supported ones.

## Policy Enforcement

Policies run **before** the call leaves your process. Deterministic code only; no LLM in the decision path.

```typescript
obsvr.init({
  apiKey: process.env.OBSVR_API_KEY,
  ingestUrl: 'https://your-ingest-service',

  // Built-in PII scanning: block | redact | detect_only per type
  piiPolicy: {
    default: 'detect_only',
    rules: { ssn: 'block', credit_card: 'block', email: 'redact' },
  },

  // Structured policy rules (keyword, regex, topics, action gates, quotas...)
  policyRules: [
    {
      id: 'no-wire-transfers',
      name: 'Block wire transfer instructions',
      enabled: true,
      action: 'block',
      type: 'keyword',
      conditions: { keywords: ['wire transfer'] },
    },
  ],

  // Custom pre-call hook: allow | block | redact (supports human-in-the-loop)
  onPreCall: async (event) => {
    if (event.provider === 'openai' && isHighRisk(event.prompt)) {
      return await waitForHumanApproval(event); // pause until a human decides
    }
    return 'allow';
  },
  hookTimeoutMs: 2000,

  // Enforcement fail mode when a hook times out or throws:
  // 'open' (default) allows the call; 'closed' blocks it.
  failMode: 'closed',
});
```

Built-in regex detection covers 13 PII types including SSN, credit cards, API keys, AWS keys, private keys, GitHub tokens, Slack webhooks, JWTs, and prompt-injection patterns. Optional [Presidio](https://microsoft.github.io/presidio/) integration adds the 6 NLP types (`name`, `address`, `person`, `location`, `medical`, `national_id`) for the full 19-type taxonomy.

**Opt-in security controls** (all off by default): **`policyFloor`** — a non-overridable operator baseline (same shape as `policyRules`) that customer rules and the `onPreCall` hook can't weaken, with a floor `redact` failing closed to a block; **`deobfuscation: { enabled: true }`** — also scan base64/hex/percent-decoded and invisible/confusable-folded views so encoded payloads can't dodge detection; **`mcpToolPolicy: { pinning: { enabled: true, mode: 'block' } }`** — content-hash MCP tool descriptors to catch a rug-pull swap; **`sessionTaint: { enabled: true }`** — latch a session as compromised on an injection/canary leak and escalate later egress, with `destructiveTools` naming exact tools a tainted session may never invoke even in flag mode — **which holds only on the surfaces where obsvr is genuinely on the tool boundary; see [Does a tool-policy block actually stop the tool?](#does-a-tool-policy-block-actually-stop-the-tool)**; and **canary honeytokens** via `mintCanary()` — plant a unique token and get a CRITICAL signal if it resurfaces. See [`SECURITY.md`](../SECURITY.md) for each control's exact guarantee and boundary.

### Verdict reason codes

Every policy verdict carries a stable, machine-groupable `reason_code` drawn from a **closed registry** (the `ReasonCode` enum, exported from the package) **plus** the existing free-form `reason` string as human detail — the code is additive, so nothing is lost. The same code rides every audit **event** (`reason_code`), always identical to the one on the thrown `ObsvrPolicyError`, so the record and the exception never classify a decision differently. Codes such as `KEYWORD_BLOCKED`, `QUOTA_EXCEEDED`, `MODEL_GATE_BLOCKED`, `APPROVAL_REQUIRED`, and `SHADOW_WOULD_BLOCK` are pinned in [`conformance/fixtures/reason_codes.json`](../conformance/fixtures/reason_codes.json) so the TypeScript and Python SDKs share one identical vocabulary. One is worth knowing by name: `QUOTA_UNMETERED` is the only code that reports enforcement **did not happen** rather than a verdict the engine reached, and it is emitted when a quota scope the bounded counter store could not admit is refused under `failMode: 'closed'`. A CI staleness check fails if the two registries diverge, if the engine can emit a code outside the registry, or — the inverse — if a registry code has no emission path at all (a code without one must be explicitly reserved, with its owning control named).

```typescript
import { ReasonCode, REASON_CODES } from '@obsvr/sdk';
```

## External Policy Backend (OPA / Cedar)

Already standardized on policy-as-code? Point obsvr at your existing **OPA** HTTP endpoint or **Cedar** authorization service and its verdict participates in every pre-call decision — no need to re-author your policies here.

```typescript
obsvr.init({
  apiKey: process.env.OBSVR_API_KEY,
  ingestUrl: 'https://your-ingest-service',
  externalPolicyBackend: {
    type: 'opa',                                           // 'opa' | 'cedar'
    url: 'https://opa.internal.example.com/v1/data/obsvr/allow',
    // shadow: true,          // observe-only rollout: record the verdict, never block
    // timeoutMs: 2000,       // error/timeout => DENY (fail-closed) in enforce mode
    // headers: { authorization: 'Bearer ...' },
    // name: 'corp-opa',      // identity recorded on events (provenance)
    // policy: '<rego text or bundle revision>',  // hashed into backend_policy_hash
    // allowPrivateNetwork: true, // permit a sidecar/private-network backend (see below)
  },
});
```

Semantics:

- **Deny-wins merge.** A `deny` from *either* the local rules or the backend blocks the call. A backend `allow` never downgrades a local block — the backend can only add restriction.
- **Fail-closed.** A backend error or timeout counts as `deny` (a policy engine that cannot render a verdict is not approval). Use `shadow: true` for a safe, observe-only rollout that records what the backend *would* have done without ever blocking.
- **SSRF-guarded.** The backend URL must be `http(s)`; requests to private / loopback / link-local / cloud-metadata addresses (`169.254.169.254`, `10/8`, `127/8`, `::1`, …) are refused, resolving the hostname before connecting. A legitimate sidecar on `localhost`/a private network needs `allowPrivateNetwork: true`; the cloud-metadata and link-local ranges are blocked even then.
- **Provenance.** Each event records which backend decided via `external_backend` (identity, backend type, raw outcome, shadow flag, and a hash of the effective backend policy).

The **OPA** endpoint is POSTed `{ "input": <decision document> }` and its `result` is read as `allow` (boolean, or `{ allow, reasons }`). The **Cedar** endpoint receives the decision document and its `decision` (`Allow`/`Deny`) is read. The decision document carries non-content fields only — operation, provider, model, principal (user/service/tenant), the local decision so far, the rules hash, and a SHA-256 **digest** of the prompt (never the raw prompt). Zero-config default is no backend (unchanged behavior).

## What Gets Governed

`obsvr.wrap()` (and the module interceptor) govern exactly these provider method paths:

| Provider | Governed methods |
| --- | --- |
| OpenAI / Azure OpenAI (through `obsvr.wrap()`) | `chat.completions.create`, `chat.completions.parse`, `beta.chat.completions.create`, `beta.chat.completions.parse` |
| OpenAI Responses API | `responses.create`, `responses.parse`, `beta.responses.create` |
| Anthropic | `messages.create`, `messages.parse`, `beta.messages.create` |
| Google Gemini (`@google/generative-ai` only) | `generateContent` |

Beta namespaces are listed one by one rather than matched by stripping a leading `beta.`, so a provider shipping a new beta namespace never widens governance without review.

Three different things sit outside that table, and only the first is a policy decision:

- **Excluded — no chat text to govern.** `embeddings.create`, `images.generate`, `audio.*`, `files.*`, `fine_tuning.*` and the moderation/model-listing surfaces pass through **ungoverned and unaudited**. They carry no chat-shaped prompt/response text for the policy engine to evaluate.
- **Text-bearing but not covered yet.** The batch surfaces (`messages.batches.create`) carry many prompts per call against a one-prompt event schema; `countTokens` returns no response text; and Gemini's `startChat()` session calls an internal function rather than a method on the model, so no method-path table can reach it.
- **Governed, but not through that table.** The `.stream()` helpers (`messages.stream`, `chat.completions.stream`, `responses.stream`) and the tool runners (`chat.completions.runTools`, `beta.messages.toolRunner`) return their runner object synchronously, so they cannot go through the async method wrapper. They are governed by a deferred runner that returns the runner immediately and reaches the provider only once governance has resolved — so a blocked call never leaves the process. A stream helper emits one event when the stream ends. A tool runner emits the run as a sequence instead: one event per model call, one per tool call, and a run-level start/finish pair sharing an `agent_run_id`, with the tool events carrying `content_provenance: "tool_result"`. **The model calls a tool runner makes after the first are audited but not individually gated** — the runner holds the provider client internally, so per-turn enforcement would need its own mechanism.

**The named compatibility wrappers are NOT that table.** `wrapAzureOpenAI`, `wrapTogether`, `wrapCloudflare` and `wrapOpenAICompatible` consult a one-entry path table (`integrations/openai-compat.ts`) and govern **`chat.completions.create` only**. Counted against real `AzureOpenAI` and `Together` clients: 17 governed paths through `obsvr.wrap()`, 1 through these. The other 26 text-bearing paths on a current client — `responses.create`, `responses.parse`, `responses.stream`, `chat.completions.parse`, `chat.completions.stream`, `chat.completions.runTools`, `completions.create`, and the whole `beta.threads.*` assistants surface — bind straight through with **no gate and no event**. That is not a limitation of the client: `obsvr.wrap()` duck-types the same objects and covers the full table above. These wrappers exist to set a provider label and a source; use `obsvr.wrap()` when you need the coverage.

**The framework integrations are not that table either.** LangChain and LlamaIndex call `applyObservePolicy`, which is the PII scan and the stored redacted copy — not `applyPreCallPolicy`. Measured layer by layer: `policyRules`, `policyFloor`, the `onPreCall` hook, outbound redaction, the kill-switch integrity gate, the response-side scan and PII **blocking** do not run there, and metering is opt-in. A `pii_policy` of `{ssn: "block"}` blocks through `obsvr.wrap()`, Bedrock, Vertex, Vercel AI and MCP, and does not block through LangChain or LlamaIndex — the call goes out and the event records the stored copy as redacted. Treat them as observability integrations with a PII scan.

MCP tool calls are governed separately (below); any framework's tools can be governed with `obsvrGovernTool` / `obsvrGovernTools`.

## MCP Governance

Govern the MCP client once; every tool call on every connected server is policy-checked and audited, and `listTools()` results are scanned for tool poisoning:

```typescript
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { obsvr, obsvrGovernMCP, getConfig } from '@obsvr/sdk';

obsvr.init({
  apiKey: process.env.OBSVR_API_KEY,
  ingestUrl: 'https://your-ingest-service',
  mcpToolPolicy: { deniedTools: ['delete_file'], allowedTools: ['read_file', 'list_directory'] },
});

// Non-mutating: returns a governed class; the real Client prototype is never touched.
const GovernedClient = obsvrGovernMCP(Client, getConfig());
const client = new GovernedClient({ name: 'my-agent', version: '1.0.0' }, { capabilities: {} });
```

`obsvrGovernMCP` also accepts an existing Client **instance** and returns a governed instance. The legacy `patchMCP()` (prototype-mutating) is **deprecated**: it logs a one-time warning and will be removed in the next major release — migrate to `obsvrGovernMCP`.

Governance covers all three MCP phases: **discovery** (`listTools()` is scanned for tool poisoning), **request** (tool arguments are policy- and PII-checked before the call runs), and **response** (the tool RESULT is scanned before it reaches the caller). Tool results are the exfiltration/poisoning channel, so a result carrying PII, secrets, or an injection payload is **blocked**, **sanitized** (offending spans redacted), or **logged** per policy — a blocked result is withheld from the caller entirely. Pass caller identity via the options argument (`obsvrGovernMCP(Client, getConfig(), { user_id })`) so user/service/tenant-scoped quota rules meter the right bucket and the decision is attributed to the principal in the audit trail.

## Tamper-Evident Audit Trail

Every event is stamped with a session ID, a monotonic sequence number, and an HMAC-SHA256 signature chained to the previous event's signature. The client signature covers the prompt/response **content** and event **order**, so tampering with captured content — or dropping/reordering events once they are in the chain — breaks it. Events the bounded sender queue drops under load never enter the chain and so hole nothing; those are declared instead by a signed **gap marker** stating how many were lost at that point, which both verifiers report alongside the verdict. Since **chain format 3** the preimage also covers the **decision fields** — `action_taken`, `action_reason`, `reason_code`, `rule_id`, `policy_version`, `model`, `provider`, `user_id` — so a rewritten verdict breaks the chain offline. `tenant_id`, token counts and cost are still outside it; their integrity is sealed at ingest, which verifies the client signature on acceptance and **countersigns the full canonical event** with a server-held key. Chains signed under formats 1 and 2 keep verifying as those formats, without the decision coverage, and the verifier reports which format it checked.

Verify an exported bundle offline with the shipped `obsvr-verify` CLI — no network, no trust in obsvr's servers:

```bash
npx -p @obsvr/sdk obsvr-verify evidence-bundle.json            # structural (keyless)
npx -p @obsvr/sdk obsvr-verify evidence-bundle.json --api-key $OBSVR_API_KEY  # full HMAC re-verification
```

To gate merges on this in CI, use the [obsvr Evidence Verification GitHub Action](../action/README.md).

## Framework Integrations

LangChain, LlamaIndex, OpenAI Agents SDK, Vercel AI SDK, plus provider modules for Azure OpenAI, AWS Bedrock, Google Vertex AI, Together, Cloudflare Workers AI, and any OpenAI-compatible API (Groq, Mistral, Ollama):

```typescript
import { ObsvrCallbackHandler } from '@obsvr/sdk/langchain';
```

Any endpoint that speaks `chat.completions.create` and has no named module of its own goes through `wrapOpenAICompatible`, which takes the labels rather than guessing them — so the audit event names the endpoint you actually reached:

```typescript
import { wrapOpenAICompatible } from '@obsvr/sdk/openai-compat'; // also on the root export

const client = wrapOpenAICompatible(new OpenAI({ baseURL: 'http://localhost:11434/v1' }), {
  provider: 'openai',   // the wire protocol the event is classified under
  source: 'ollama',     // the endpoint, which is what tells two of these apart
});
```

Set `source` per endpoint. **The recorded `provider` follows the endpoint, not the wrapper.** The named wrappers built on this one (`wrapTogether`, and the Azure/Cloudflare modules) pass their label as a FALLBACK, used only when the client exposes no readable base URL; when it does, the label is derived from the host, `metadata.endpoint_host` records that host, and `metadata.provider_attribution` says whether the value was checked against the endpoint (`endpoint`) or merely declared (`client_declared`). A destination the canonical provider enum cannot name records `provider: "unknown"` and keeps its identity in `metadata.provider_detail` — so a Groq or Ollama endpoint reads as what it is rather than as whichever module wrapped it. These labels used to be unconditional, which meant one wrapper pointed at two different servers reported the same destination for both. **`obsvr.wrap()` resolves the same way** — through the same endpoint table — so the front door does not have to be traded for honest attribution; its duck-typed detection is the fallback there, exactly as a named wrapper's label is here. The client's shape still selects the extractors; only the recorded destination follows the endpoint.

### Does a tool-policy block actually stop the tool?

**Read this before putting a destructive capability behind `agentPolicy` or
`sessionTaint.destructiveTools`.** Whether a block stops the tool depends on
whether the framework hands obsvr a hook that runs *before* the tool does, and
they do not all. Every grade below was driven against a real run and graded on a
captured audit event.

| Surface | Tool policy |
| --- | --- |
| MCP (`callTool`) | **enforces** — the gate patches the invocation itself |
| `obsvrGovernTool` | **enforces** — wraps the tool's own execute and gates before delegating |
| LangChain (`ObsvrCallbackHandler`) | **enforces** — `handleToolStart` plus `awaitHandlers`/`raiseError` |
| LlamaIndex, Vercel AI SDK | no gate of their own; govern individual tools with `obsvrGovernTool` |
| OpenAI Agents SDK | **records only** — see below |
| `chat.completions.runTools`, `beta.messages.toolRunner` | **enforces on the tools, not on the turns** — see below |

**OpenAI Agents SDK: records only.** A `TracingProcessor` cannot refuse anything
— the framework dispatches processor callbacks fire-and-forget, so nothing raised
there reaches the run — and a function span does not end until its tool has
returned. So a denied tool executes and its result reaches the caller. The event
records `action_taken: "not_evaluated"` with the reason in
`metadata.obsvr_telemetry.policy_not_evaluated`; it must not be read as a
refusal. To actually refuse tools under that framework, wrap them with
`obsvrGovernTool`.

**Provider tool runners: the tools are gated, the intermediate turns are not.**
A runner invokes its tools itself and holds the raw provider client, so obsvr
used to be off that boundary entirely — measured, a session obsvr had already
marked tainted executed a tool named in `destructiveTools`. obsvr now gates each
tool's callback through `obsvrGovernTool` before the runner is constructed, which
is the only point either runner will accept a substitution: both snapshot their
tool set when the method is applied.

What that reaches, and what it does not:

- **Tool execution is gated.** Denied tools, allowlists and the tainted-session
  destructive-capability set all apply, and a refused tool's callback does not
  run. Verified live on both runners, each against a policy-off control.
- **The refusal shape differs by provider, because the runners differ.**
  `beta.messages.toolRunner` invokes its tools inside a `try`/`catch`, so a
  refusal comes back to the model as an error tool result and the loop continues
  — in a live run the model went on to explain that the capability was blocked.
  `chat.completions.runTools` does not guard its tool call, so a refusal
  propagates and the run ends with the refusal error. Both fail closed; only one
  lets the run survive.
- **The model calls on turns 2..N are still audited and not gated.** Reaching
  those means substituting the runner's own client, and a refusal arriving on
  turn 3 would land after earlier tools had already had real side effects. That
  needs a stated position before it ships.
- **A hosted tool the provider executes on its own infrastructure carries no
  local callback**, so there is nothing to gate. Those are named individually in
  `tool_gate_ungated_tools` on the run's start event rather than counted.

The runner's own per-tool event records `not_evaluated` either way, and its
`policy_not_evaluated.gate` says which absence it is: `runner_observation` when
the gate ran and the verdict is on that tool's own `tool.call` event, or
`tool_gate` when no gate reached the call. `metadata.tool_gate` carries the same
answer as `callback` or `absent`.

**Do not read Python's grades across, or vice versa.** The two SDKs have separate
tool-gate implementations and they disagree: this SDK's LangChain integration
enforces, and the Python one does not wire its gate to a callback current
runtimes deliver. The per-integration table for Python is in
[`../sdk-python/README.md`](../sdk-python/README.md), and the combined view is in
the [root README](../README.md).

### Agent runs

`obsvr.agentRun(name, fn)` records one agentic execution as a **run** — every governed action inside it (LLM calls, `obsvrGovernTool` tool calls, spans) is grouped under one `agent_run_id`, so it appears as a single row in the dashboard's Runs tab with its full trace. It emits a signed `<source>.agent.run.start` on entry and a terminal `<source>.agent.run.finish` on completion (success or failure).

```typescript
await obsvr.agentRun('support-agent', () => agent.run(userMessage), {
  source: 'llamaindex_ts', // or 'vercel_ai', etc. — labels the run's source
});
```

Use it for frameworks governed at the tool level (LlamaIndex, Vercel AI) so their executions form runs. LangChain and the OpenAI Agents SDK integrations form runs on their own and do not need it. The run boundary is this explicit scope — deterministic and developer-declared, never inferred. (Python: `with obsvr.agent_run("support-agent", source="llamaindex_py"): ...`.)

## Known Limitations & Architecture Notes

We document enforcement limits honestly — what the signature chain does and does not prove, streaming semantics, fail-open/closed behavior, and the inherent bypass surface of any in-process library. The key ones:

### Streaming calls

With `stream: true`, PII scanning and policy hooks run **before** the LLM is contacted; a blocked call never opens the stream. However, **post-call** policies on streamed responses are audit-time, not enforcement-time: tokens reach the caller as they arrive, and response scanning happens after completion.

### Signing model

Event signatures are derived from your API key inside the SDK. They prove capture order and detect after-the-fact modification, but a party holding the API key could construct validly-signed events. Server-side countersigning at ingest binds each accepted event to a key that never leaves the server. Treat the client chain as integrity, not as non-repudiation against a key-holder.

### Fail mode

Default is fail-open: if a hook times out or throws, or a detector layer fails while deciding, the call is allowed, that layer's enforcement is lost for it, and the failure is counted and recorded on the call's own event. Set `failMode: 'closed'` for policies that must never fail open. `failMode` deliberately cannot move three things: `policy_floor` and `canary` always fail **closed** (a floor that cannot run must not wave a call through), a `redact` decision whose redactor then throws **blocks** rather than forwarding the content it was told to strip, and after the provider has answered nothing is withheld from your application — a response-side failure falls closed only on the stored audit copy. If the obsvr backend is unreachable, cached policy rules keep enforcing; only rule updates degrade.

### PII scanning scope

Policy decisions scan the **last user message**. System prompts, earlier turns, assistant turns and tool results do not drive block/redact decisions, so a payload sitting in one of them reaches the provider unmodified. They are still stored — and the stored copy is scrubbed for any type resolving to `block` or `redact`, with `stored_redaction_outbound_unmodified` on the event so the record is not mistaken for enforcement. Types `name`, `address`, `person`, `location`, `medical`, `national_id` require the Presidio integration; built-in regex will never fire for them.

### Unicode normalization (matching-time only)

Before rule, PII, and injection matching, text is normalized (Unicode **NFKC** + zero-width/invisible-character stripping + a small curated confusable fold) so an attacker cannot slip a keyword or pattern past the scanners with a lookalike or zero-width-joined variant (`оverride`, `ｏｖｅｒｒｉｄｅ`, `over<ZWJ>ride` all match `override`). This is a **matching-time transform only**: it changes what the engine *detects*, never what it *stores or forwards*. The audited prompt/response and the redaction output reflect exactly what the user sent (redaction is the sole content mutation). The transform is pinned across both SDKs by `conformance/fixtures/normalization.json`.

### Serverless / Lambda

Each cold start begins a fresh integrity session (`sdk_session_id`, `seq_no` reset). Multiple sessions starting at `seq_no=1` are expected and verify correctly. Call `await obsvr.flush()` before the runtime freezes.

### SDK bypass

Not calling `obsvr.init()` means no governance coverage; there is no post-hoc runtime check. Assert `obsvr.isInitialized()` at startup in production. Setting `disabled: true` in a production environment logs a prominent warning and emits a `governance_disabled` audit event so the bypass is on the record.

## License

Apache-2.0
