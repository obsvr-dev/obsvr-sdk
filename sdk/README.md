# @obsvr/sdk

Runtime governance for LLM applications: intercept every model and tool call, enforce deterministic policies (PII, allowlists, budgets, custom rules), and produce a tamper-evident audit trail. One line to integrate.

## Installation

> Private beta — not yet published to npm. Request access at [obsvr.dev](https://obsvr.dev).

```bash
npm install @obsvr/sdk    # private beta — not yet on npm; request access at obsvr.dev
```

Requires **Node.js >= 18**.

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
const gemini = obsvr.wrap(genAI.getGenerativeModel({ model: 'gemini-2.5-flash' }));
```

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

**Opt-in security controls** (all off by default): **`policyFloor`** — a non-overridable operator baseline (same shape as `policyRules`) that customer rules and the `onPreCall` hook can't weaken, with a floor `redact` failing closed to a block; **`deobfuscation: { enabled: true }`** — also scan base64/hex/percent-decoded and invisible/confusable-folded views so encoded payloads can't dodge detection; **`mcpToolPolicy: { pinning: { enabled: true, mode: 'block' } }`** — content-hash MCP tool descriptors to catch a rug-pull swap; **`sessionTaint: { enabled: true }`** — latch a session as compromised on an injection/canary leak and escalate later egress; and **canary honeytokens** via `mintCanary()` — plant a unique token and get a CRITICAL signal if it resurfaces. See [`SECURITY.md`](../SECURITY.md) for each control's exact guarantee and boundary.

### Verdict reason codes

Every policy verdict carries a stable, machine-groupable `reason_code` drawn from a **closed registry** (the `ReasonCode` enum, exported from the package) **plus** the existing free-form `reason` string as human detail — the code is additive, so nothing is lost. Codes such as `KEYWORD_BLOCKED`, `QUOTA_EXCEEDED`, `MODEL_GATE_BLOCKED`, `APPROVAL_REQUIRED`, and `SHADOW_WOULD_BLOCK` are pinned in [`conformance/fixtures/reason_codes.json`](../conformance/fixtures/reason_codes.json) so the TypeScript and Python SDKs share one identical vocabulary. A CI staleness check fails if the two registries diverge or the engine can emit a code outside the registry.

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

| Provider | Governed method |
| --- | --- |
| OpenAI / Azure OpenAI | `chat.completions.create` |
| OpenAI Responses API | `responses.create` |
| Anthropic | `messages.create` |
| Google Gemini | `generateContent` |

All other client methods (`embeddings.create`, `images.generate`, `audio.*`, `files.*`, `fine_tuning.*`, ...) pass through **ungoverned and unaudited** — they carry no chat-shaped prompt/response text for the policy engine to evaluate. MCP tool calls are governed separately (below); any framework's tools can be governed with `obsvrGovernTool` / `obsvrGovernTools`.

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

Every event is stamped with a session ID, a monotonic sequence number, and an HMAC-SHA256 signature chained to the previous event's signature. The client signature covers the prompt/response **content** and event **order**, so tampering with captured content — or dropping/reordering events — breaks the chain. The decision/attribution fields (verdict, rule, tenant) are not in the client preimage; their integrity is sealed at ingest, which verifies the client signature on acceptance and **countersigns the full canonical event** with a server-held key.

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

### Agent runs

`obsvr.agentRun(name, fn)` records one agentic execution as a **run** — every governed action inside it (LLM calls, `obsvrGovernTool` tool calls, spans) is grouped under one `agent_run_id`, so it appears as a single row in the dashboard's Runs tab with its full trace. It emits a signed `<source>.agent.run.start` on entry and a terminal `<source>.agent.run.finish` on completion (success or failure).

```typescript
await obsvr.agentRun('support-agent', () => agent.run(userMessage), {
  source: 'llamaindex_ts', // or 'vercel_ai', etc. — labels the run's source
});
```

Use it for frameworks governed at the tool level (LlamaIndex, Vercel AI) so their executions form runs. LangChain and the OpenAI Agents SDK integrations form runs on their own and do not need it. The run boundary is this explicit scope — deterministic and developer-declared, never inferred. (Python: `with obsvr.agent_run("support-agent", source="llamaindex_py"): ...`.)

## Manual Tracking (no compliance controls)

For explicit tracking without interception, `ObsvrClient` posts events directly (`LLMAuditClient` remains as a deprecated alias). Note: this path bypasses PII scanning, policy rules, and chain signing; events are flagged `compliance_bypass` server-side.

```typescript
import { ObsvrClient } from '@obsvr/sdk';

const client = new ObsvrClient({ apiKey: '...', baseUrl: 'https://your-ingest-service' });
await client.trackCompletion({ prompt: 'Hello!', response: 'Hi!', model: 'gpt-4o', region: 'us-east-1' });
```

## Known Limitations & Architecture Notes

We document enforcement limits honestly — what the signature chain does and does not prove, streaming semantics, fail-open/closed behavior, and the inherent bypass surface of any in-process library. The key ones:

### Streaming calls

With `stream: true`, PII scanning and policy hooks run **before** the LLM is contacted; a blocked call never opens the stream. However, **post-call** policies on streamed responses are audit-time, not enforcement-time: tokens reach the caller as they arrive, and response scanning happens after completion.

### Signing model

Event signatures are derived from your API key inside the SDK. They prove capture order and detect after-the-fact modification, but a party holding the API key could construct validly-signed events. Server-side countersigning at ingest binds each accepted event to a key that never leaves the server. Treat the client chain as integrity, not as non-repudiation against a key-holder.

### Fail mode

Default is fail-open: if a pre-call hook times out or throws, the call is allowed (and the failure recorded). Set `failMode: 'closed'` for policies that must never fail open. If the obsvr backend is unreachable, cached policy rules keep enforcing; only rule updates degrade.

### PII scanning scope

Policy decisions scan the **last user message**. System prompts and earlier turns are stored (and redacted if applicable) but do not drive block/redact decisions. Types `name`, `address`, `person`, `location`, `medical`, `national_id` require the Presidio integration; built-in regex will never fire for them.

### Unicode normalization (matching-time only)

Before rule, PII, and injection matching, text is normalized (Unicode **NFKC** + zero-width/invisible-character stripping + a small curated confusable fold) so an attacker cannot slip a keyword or pattern past the scanners with a lookalike or zero-width-joined variant (`оverride`, `ｏｖｅｒｒｉｄｅ`, `over<ZWJ>ride` all match `override`). This is a **matching-time transform only**: it changes what the engine *detects*, never what it *stores or forwards*. The audited prompt/response and the redaction output reflect exactly what the user sent (redaction is the sole content mutation). The transform is pinned across both SDKs by `conformance/fixtures/normalization.json`.

### Serverless / Lambda

Each cold start begins a fresh integrity session (`sdk_session_id`, `seq_no` reset). Multiple sessions starting at `seq_no=1` are expected and verify correctly. Call `await obsvr.flush()` before the runtime freezes.

### SDK bypass

Not calling `obsvr.init()` means no governance coverage; there is no post-hoc runtime check. Assert `obsvr.isInitialized()` at startup in production. Setting `disabled: true` in a production environment logs a prominent warning and emits a `governance_disabled` audit event so the bypass is on the record.

## License

Apache-2.0
