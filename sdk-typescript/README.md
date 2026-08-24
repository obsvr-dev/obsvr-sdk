# @obsvr/sdk

Runtime governance for documented LLM and tool boundaries: enforce deterministic policies (PII, allowlists, budgets, custom rules) on supported wrapped methods and produce a tamper-evident audit stream. Coverage is per integration, not process-wide.

## Installation

```bash
npm install @obsvr/sdk
```

> **Enforcement needs no account.** Policy, PII, and agent checks run entirely
> in your process, but you must configure the controls you want to enforce; an
> API key enables signing and delivery, not a default block policy.
> Delivering the signed audit record needs an obsvr ingest service, which is in
> private beta; you receive its URL together with your key. Until `ingestUrl` is
> set the SDK still enforces — it warns once and delivers nothing.
> [Request access →](https://obsvr.dev)

Requires **Node.js >= 22**.

### This package is ESM-only

`"type": "module"`, and every export condition is `import`. **A CommonJS service
cannot consume it**: `require("@obsvr/sdk")` fails, and there is no `require`
condition to fall back to. Your project needs `"type": "module"`, `.mjs`
entrypoints, or a bundler that emits ESM.

This is worth checking before you install rather than after, because the failure
is not only at load time. **Zero-code interception is silently nil under
`require()`**, and that half would not be fixed by shipping a CommonJS build:
`module.register()` hooks — what `--import @obsvr/sdk/register` installs — do not
intercept `require()` at all. Measured, with a control: under `--import` with an
ESM entrypoint a policy-violating call is refused and one audit event is written;
with a `require()` entrypoint the same call reaches the provider, no event is
written, and `interception_active` reads `false`. `obsvr.wrap()` and the named
compatibility wrappers are unaffected — they govern the client you hand them,
whatever loaded it.

**Dual-publishing is deliberate future work, not an oversight**, and the reason
is specific to what this package is. A dual build invites the dual-package
hazard — one process resolving both copies — and this SDK keeps the audit chain
in module-level state: the session id, the sequence number, and the previous
signature all live as bindings in one module. Two copies means **two session ids
and two independent sequence counters writing one claimed session**, which the
ingest service already classifies as a `sequence_fork`. That is the same defect
shape as a chain forking across `os.fork()`, and shipping a convenience that
manufactures it would trade a documented limitation for a corrupted record.
Closing this properly means moving chain state out of module scope first.

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

// Supported text-generation methods are policy-checked; clean allows may be sampled.
const response = await openai.chat.completions.create({
  model: 'gpt-4o',
  messages: [{ role: 'user', content: 'What is 2+2?' }],
});
```

Anthropic and current Google Gemini work the same way:

```typescript
const anthropic = obsvr.wrap(new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY }));
const gemini = obsvr.wrap(new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY }));
const result = await gemini.models.generateContent({
  model: 'gemini-2.5-flash',
  contents: 'What is 2+2?',
});
```

**Which Gemini SDK.** Google ships two, and obsvr integrates both:

| Package | State |
| --- | --- |
| `@google/generative-ai` | **supported, compatibility only** — legacy line, last release 0.24.1, end-of-life August 2025 |
| `@google/genai` | **supported** — current 2.x client; `models.generateContent` and `models.generateContentStream` |

Compatibility only means fixes, not features: the legacy adapter is kept working for existing deployments. The two packages have different method and response shapes and use separate adapters. npm carries no deprecation flag on either package, so check `package.json` to identify the installed line.

### Zero-code global coverage (no monkey patching)

If you would rather not call `wrap()` on every client, start Node with the obsvr module interceptor:

```bash
node --import @obsvr/sdk/register app.js
# or: NODE_OPTIONS="--import @obsvr/sdk/register" npm start
```

`new OpenAI()`, `new Anthropic()`, `new GoogleGenAI()` and legacy `getGenerativeModel()` then return governed instances automatically, including ones created inside third-party libraries. obsvr never mutates provider prototypes, classes, or module objects: the interceptor swaps the module's exported class for a construct-trap `Proxy`, and the instance underneath stays a genuine SDK client. APM, tracing, and other instrumentation layered on the same SDKs keep working. Clients constructed before `obsvr.init()` pass through untouched and pick up governance on their first call after init.

Use `providers: ['openai']` in `obsvr.init()` to narrow which providers the interceptor governs; omit it to govern all supported ones.

#### What this does not reach

The hook's reach is narrower than *every* client anywhere in the process, and the gaps below were measured against a real provider with a governed control in the same run rather than reasoned about. What the hook governs is each supported root client export of a supported package, imported by its **exact specifier**, from an **ESM** entry point. Two import shapes escape:

| Escapes | Why |
| --- | --- |
| `require("openai")` | `module.register()` hooks do not intercept CommonJS. Interception never activates; the call reaches the provider and nothing is recorded. |
| `openai/index.mjs`, `openai/index`, `openai/client`, `openai/client.mjs`, `openai/client.js`, `openai/azure` | The specifier table is exact-match, so a subpath resolves to the untouched module. |

**Neither puts a false record in the audit trail** — an escaped import emits no event rather than a wrong one, so it is reported as a coverage gap. Where the application can import `@obsvr/sdk`, explicit `obsvr.wrap(client)` governs the resulting client instance.

The CommonJS row is structural and cannot be closed by the ESM loader hook; subpath coverage remains an open gap. Widening the specifier table is a change to the interception path across the whole declared version range of each provider package, not a documentation-only change.

## Strict profile 2.1 provider boundary

Ordinary `wrap()` runs the policy pipeline before documented methods. For a supported direct-provider call that must also have a device-signed decision receipt admitted and committed **before execution**, construct a `StrictReceiptRuntimeV21` and pass an explicit capability:

```typescript
import { createStrictProviderBoundaryV21, obsvr } from '@obsvr/sdk';

// Configure this runtime with a StrictReceiptCoordinatorV21, admission options,
// a device signer, trusted identity/evaluation providers, and an atomic durable store.
const strict = createStrictProviderBoundaryV21({
  runtime,
  context: () => ({
    active_intents: ['serve'],
    requested_scopes: ['model:invoke'],
    run_id: 'run-123',
  }),
});

const client = obsvr.wrap(new OpenAI({ apiKey: process.env.OPENAI_API_KEY }), {
  strict_receipt_v2_1: strict,
});
```

The strict sequence is `prepared -> remote_accepted -> committed -> invocation_started -> terminal`. No provider call occurs without positive admission and the preceding durable checkpoints. After `invocation_started`, an ambiguous result is `invocation_uncertain` and must not be retried automatically.

This mode supports only unary `chat.completions.create` / `.parse`, `responses.create` / `.parse`, `messages.create` / `.parse`, legacy `generateContent`, and maintained `models.generateContent`; these retain their normal Promise-returning API. Streams, helper managers, runners, and other callables fail closed with `unsupported_surface`. Only an `ALLOW` outcome executes; `DENY`, `MODIFY`, `STEP_UP`, and `DEFER` do not contact the provider.

The full construction used by the executable tests is in [`strict-provider-boundary-v2-1.test.ts`](https://github.com/obsvr-dev/obsvr-sdk/blob/main/sdk-typescript/tests/unit/strict-provider-boundary-v2-1.test.ts). Read the repository [security boundary](https://github.com/obsvr-dev/obsvr-sdk/blob/main/SECURITY.md#strict-profile-21-execution-boundary) and [compatibility matrix](https://github.com/obsvr-dev/obsvr-sdk/blob/main/COMPATIBILITY.md#strict-profile-21-direct-provider-boundary) before enabling it.

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

  // Custom pre-call hook: allow | block | redact. Enforcement is monotonic:
  // "allow" keeps a clean call allowed but never erases a PII/rule block.
  // Budgeted by hookTimeoutMs and resolved by failMode on expiry — for human
  // approval, use approvalWaitMs below, not a hook that waits.
  onPreCall: async (event) => {
    if (event.provider === 'openai' && isHighRisk(event.prompt)) {
      return 'block';
    }
    return 'allow';
  },
  hookTimeoutMs: 2000,

  // Human-in-the-loop: hold a require_approval block while the grant
  // channel is polled. 0 (default) = refuse now, pass on a retry once granted.
  approvalWaitMs: 300_000,
  approvalPollMs: 5_000,

  // Enforcement fail mode when a hook times out or throws:
  // 'open' (default) allows the call; 'closed' blocks it.
  failMode: 'closed',
});
```

Built-in regex detection covers 13 PII types including SSN, credit cards, API keys, AWS keys, private keys, GitHub tokens, Slack webhooks, JWTs, and prompt-injection patterns. Optional [Presidio](https://microsoft.github.io/presidio/) integration adds the 6 NLP types (`name`, `address`, `person`, `location`, `medical`, `national_id`) for the full 19-type taxonomy.

**Opt-in security controls** (all off by default): **`policyFloor`** — a non-overridable operator baseline (same shape as `policyRules`) that customer rules and the `onPreCall` hook can't weaken, with a floor `redact` failing closed to a block; **`deobfuscation: { enabled: true }`** — also scan base64/hex/percent-decoded and invisible/confusable-folded views so encoded payloads can't dodge detection; **`mcpToolPolicy: { pinning: { enabled: true, mode: 'block' } }`** — content-hash MCP tool descriptors to catch a rug-pull swap; **`sessionTaint: { enabled: true }`** — latch a session as compromised on an injection/canary leak and escalate later egress, with `destructiveTools` naming exact tools a tainted session may never invoke even in flag mode — **which holds only on the surfaces where obsvr is genuinely on the tool boundary; see [Does a tool-policy block actually stop the tool?](#does-a-tool-policy-block-actually-stop-the-tool)**; **`requirePrincipal: true`** — refuse a call that arrives with no non-blank `user_id` on the enforcing channel (`PRINCIPAL_REQUIRED`; empty and whitespace-only strings are unattributed — see [Per-request identity](#per-request-identity)); and **canary honeytokens** via `mintCanary()` — plant a unique token and get a CRITICAL signal if it resurfaces. See [`SECURITY.md`](https://github.com/obsvr-dev/obsvr-sdk/blob/main/SECURITY.md) for each control's exact guarantee and boundary.

**Global monitor mode.** `enforcementMode: 'monitor'` is one flip meaning
"keep deciding and recording, stop enforcing": every applicable layer still evaluates,
every governed decision and execution-span event emits, and a final block is converted to an allow whose
`shadow_outcome` carries the would-be verdict with the same `rule_id` and
`reason_code` an enforcing run records. Two classes enforce in **both**
modes: the enforcement-integrity gate (kill switch / fail-closed staleness),
re-derived at the moment of conversion so a stale snapshot cannot extend
monitor mode to a revoked key, and canary-leak blocks. A converted event is
enforcement evidence, exempt from allowed-call sampling even at
`sampleRate: 0`, and `explain()` keeps predicting **enforce**-mode behaviour
so the pre-flight check still describes what turning enforcement on would do.

**Rule ordering, and opting out of it.** Rules evaluate **first-match in
document order** by default, and a matched `topic_allow` short-circuits — an
allow rule's list position can decide the verdict. `ruleResolution:
'deny_wins'` opts a deployment out: every enforcing rule is evaluated and the
strongest action prevails regardless of position (refusal over redaction over
flag over permit, smallest rule id breaking ties), decisions carry engine
version `obsvr-rules/2`, and the stamped `policy_version` commits to the
declared semantics — under a declared `first_match` it commits to evaluation
order, while undeclared rulesets keep their existing hash bytes. An unknown
declaration throws at `init()`. Two deliberate, pinned edges: shadow rules
evaluate first-match regardless of the declared mode, and under `deny_wins`
every quota rule meters every evaluated call — a call that ends blocked can
still consume quota, where first-match stopped metering at its first match.

**Blocking human approval.** A rule with `require_approval: true` refuses
when no grant covers the call and files a request for the approvals queue; a
retry passes once a human grants it. That is the default, and
`approvalWaitMs: 0` means exactly that — no waiting. Set it above zero and
the SDK **holds the call in-process** instead, polling the grant channel
(`approvalPollMs`, default 5000) until a covering grant lands or the budget
expires. Only an explicit, still-live grant lifts the hold — it is
re-validated after the wait, so a grant that expires mid-hold authorizes
nothing — and an expired hold blocks with its own registry code,
`APPROVAL_TIMEOUT`, distinct from `APPROVAL_REQUIRED` so a run-out hold is
never conflated with a plain refusal. Degradation mid-wait aborts the hold
and the block stands. One stated limit: **a denial is currently
indistinguishable from indecision client-side** — the grant channel carries
grants, not verdicts, so an explicitly denied request surfaces as the same
`APPROVAL_TIMEOUT` as one nobody looked at. Do not build this out of
`onPreCall`: the hook is budgeted by `hookTimeoutMs` and resolves by
`failMode` on expiry, which at shipped defaults means a hook that waits for a
human times out and allows.

### Verdict reason codes

Every policy verdict carries a stable, machine-groupable `reason_code` drawn from a **closed registry** (the `ReasonCode` enum, exported from the package) **plus** the existing free-form `reason` string as human detail — the code is additive, so nothing is lost. The same code rides every audit **event** (`reason_code`), always identical to the one on the thrown `ObsvrPolicyError`, so the record and the exception never classify a decision differently. Codes such as `KEYWORD_BLOCKED`, `QUOTA_EXCEEDED`, `MODEL_GATE_BLOCKED`, `APPROVAL_REQUIRED`, `APPROVAL_TIMEOUT`, `PRINCIPAL_REQUIRED`, and `SHADOW_WOULD_BLOCK` are pinned in [`conformance/fixtures/reason_codes.json`](https://github.com/obsvr-dev/obsvr-sdk/blob/main/conformance/fixtures/reason_codes.json) so the TypeScript and Python SDKs share one identical vocabulary. One is worth knowing by name: `QUOTA_UNMETERED` is the only code that reports enforcement **did not happen** rather than a verdict the engine reached, and it is emitted when a quota scope the bounded counter store could not admit is refused under `failMode: 'closed'`. A CI staleness check fails if the two registries diverge, if the engine can emit a code outside the registry, or — the inverse — if a registry code has no emission path at all (a code without one must be explicitly reserved, with its owning control named).

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
- **SSRF-guarded.** The production transport resolves the backend hostname once, rejects the complete address snapshot if any answer is private / loopback / link-local / cloud metadata, and pins the connection to an approved address while retaining the original Host header and TLS server name. Redirects are not followed. A legitimate sidecar on `localhost`/a private network needs `allowPrivateNetwork: true`; cloud-metadata and link-local ranges remain blocked. An explicitly injected `fetchImpl` is a trusted embedding seam and must provide equivalent address pinning.
- **Provenance.** Each event records which backend decided via `external_backend` (identity, backend type, raw outcome, shadow flag, and a hash of the effective backend policy).

The **OPA** endpoint is POSTed `{ "input": <decision document> }` and its `result` is read as `allow` (boolean, or `{ allow, reasons }`). The **Cedar** endpoint receives the decision document and its `decision` (`Allow`/`Deny`) is read. The decision document carries non-content fields only — operation, provider, model, principal (user/service/tenant), the local decision so far, the rules hash, and a SHA-256 **digest** of the prompt (never the raw prompt). Zero-config default is no backend (unchanged behavior).

## What Gets Governed

`obsvr.wrap()` (and the module interceptor) govern exactly these provider method paths:

| Provider | Governed methods |
| --- | --- |
| OpenAI / Azure OpenAI (through `obsvr.wrap()`) | `chat.completions.create`, `chat.completions.parse`, `beta.chat.completions.create`, `beta.chat.completions.parse` |
| OpenAI Responses API | `responses.create`, `responses.parse`, `beta.responses.create` |
| Anthropic | `messages.create`, `messages.parse`, `beta.messages.create` |
| Google Gemini (`@google/genai`) | `models.generateContent`, `models.generateContentStream` |
| Google Gemini legacy (`@google/generative-ai`) | `generateContent` |

Beta namespaces are listed one by one rather than matched by stripping a leading `beta.`, so a provider shipping a new beta namespace never widens governance without review.

Three different things sit outside that table, and only the first is a policy decision:

- **Excluded — no chat text to govern.** `embeddings.create`, `images.generate`, `audio.*`, `files.*`, `fine_tuning.*` and the moderation/model-listing surfaces pass through **ungoverned and unaudited**. They carry no chat-shaped prompt/response text for the policy engine to evaluate.
- **Text-bearing but not covered yet.** The batch surfaces (`messages.batches.create`) carry many prompts per call against a one-prompt event schema; token-counting methods return no response text; legacy Gemini's `startChat()` calls an internal function rather than a method on the model; and current Gemini chat sessions, Live API, Interactions, and batches are outside the table.
- **Governed, but not through that table.** The `.stream()` helpers (`messages.stream`, `chat.completions.stream`, `responses.stream`) and the tool runners (`chat.completions.runTools`, `beta.messages.toolRunner`) return their runner object synchronously, so they cannot go through the async method wrapper. They are governed by a deferred runner that returns the runner immediately and reaches the provider only once governance has resolved — so a blocked call never leaves the process. A stream helper emits one event when the stream ends. A tool runner emits the run as a sequence instead: one event per model call, one per tool call, and a run-level start/finish pair sharing an `agent_run_id`, with the tool events carrying `content_provenance: "tool_result"`. **The model calls a tool runner makes after the first are audited but not individually gated** — the runner holds the provider client internally, so per-turn enforcement would need its own mechanism.

**The named compatibility wrappers share that table.** `wrapAzureOpenAI`, `wrapTogether` and `wrapOpenAICompatible` delegate to the same generic governed-path resolver and enforcement pipeline as `obsvr.wrap()`. Their difference is attribution: they supply a destination fallback and per-endpoint source label when the client exposes no readable base URL. `wrapWorkersAI` is separate: it proxies `run` on a Workers AI binding and applies the pre-call policy and outbound redaction directly. The generic table still has documented exclusions below; a named wrapper does not make an unsupported OpenAI surface governed.

**The framework integrations are not that table either.** LangChain, LlamaIndex and the OpenAI Agents tracing processor call `applyObservePolicy` on their model-call paths, which is the PII scan and the stored redacted copy — not `applyPreCallPolicy`. Measured layer by layer: `policyRules`, `policyFloor`, the `onPreCall` hook, outbound redaction, the kill-switch integrity gate, the response-side scan and PII **blocking** do not run there, and metering is opt-in. A `pii_policy` of `{ssn: "block"}` blocks through `obsvr.wrap()`, Bedrock, Vertex, Vercel AI and MCP, and does not block through any of those three — the call goes out and the event records `action_taken: "not_evaluated"` plus stored-copy provenance under `metadata.obsvr_telemetry`. Treat those paths as observability with a PII scan; their tool gates are graded separately below.

**"Metering is opt-in" means the default is OFF, and that is a decision.** ``meterIntegrationEvents`` defaults to **false**, so framework-integration events carry no cost fragment and never increment a token-unit quota; the ``obsvr.wrap()`` client-proxy path is metered either way and the flag does not affect it. The default is off because turning it on is not a neutral correction — a token-unit budget that has never bound on framework traffic **begins binding**, and calls that previously succeeded start being refused once it is reached. For an operator already running a token quota that is an outage rather than a fix, so it has to be a deliberate choice. One flag covers cost and quota together, because metering what a call cost without counting it against the budget it belongs to produces a record that disagrees with itself.

**A `wrap()` that governs nothing says so.** If none of the paths above resolve on the client you pass, the returned object still works and still forwards every call — but no policy runs and no event is emitted for it, so `wrap()` prints one `console.warn` naming the gap and the paths it looks for. Once per client, not per call. Set `requireGovernedSurface: true` at `init()` to make it throw instead, for a deployment that wants an ungoverned client to fail at startup rather than at audit time.

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

Every event is stamped with a session ID, a monotonic sequence number, and an HMAC-SHA256 signature chained to the previous event's signature. The client signature covers the prompt/response **content** and event **order**, so tampering with captured content — or dropping/reordering events once they are in the chain — breaks it. Sender-visible loss is declared by a signed **gap marker**: queue overflow links a marker into the current session, while ingest rejection, permanent failure, and retry exhaustion start a fresh session whose sequence-1 marker names the reason and count. Both verifiers report those markers. A marker is still in-memory work, so abrupt process death or failure to deliver the marker leaves only local counters and warnings. Since **chain format 3** the preimage also covers the **decision fields** — `action_taken`, `action_reason`, `reason_code`, `rule_id`, `policy_version`, `model`, `provider`, `user_id` — so a rewritten verdict breaks the chain offline. `tenant_id`, token counts and cost are still outside it; their integrity is sealed at ingest, which verifies the client signature on acceptance and **countersigns the full canonical event** with a server-held key. Chains signed under formats 1 and 2 keep verifying as those formats, without the decision coverage, and the verifier reports which format it checked.

Verify an exported bundle offline with the shipped `obsvr-verify` CLI — no network, no trust in obsvr's servers:

```bash
npx -p @obsvr/sdk obsvr-verify evidence-bundle.json            # structural (keyless)
npx -p @obsvr/sdk obsvr-verify evidence-bundle.json --api-key $OBSVR_API_KEY  # full HMAC re-verification
```

To gate merges on this in CI, use the [obsvr Evidence Verification GitHub Action](https://github.com/obsvr-dev/obsvr-sdk/blob/main/action/README.md).

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

Set `source` per endpoint. **The recorded `provider` follows the endpoint, not the wrapper.** The named wrappers built on this one (`wrapTogether`, and the Azure/Cloudflare modules) pass their label as a FALLBACK, used only when the client exposes no readable base URL; when it does, the label is derived from the host, `metadata.endpoint_host` records that host, and `metadata.provider_attribution` says whether the value was checked against the endpoint (`endpoint`) or merely declared (`client_declared`). A destination the canonical provider enum cannot name records `provider: "unknown"` and keeps its identity in `metadata.provider_detail` — so a Groq or Ollama endpoint reads as what it is rather than as whichever module wrapped it. These labels used to be unconditional, which meant one wrapper pointed at two different servers reported the same destination for both. **`obsvr.wrap()` resolves the same way** — through the same endpoint table — so the front door does not have to be traded for accurate attribution; its duck-typed detection is the fallback there, exactly as a named wrapper's label is here. The client's shape still selects the extractors; only the recorded destination follows the endpoint.

### Does a tool-policy block actually stop the tool?

**Read this before putting a destructive capability behind `agentPolicy` or
`sessionTaint.destructiveTools`.** Whether a block stops the tool depends on
whether the framework hands obsvr a hook that runs *before* the tool does, and
they do not all. Every grade below was driven against a real run and graded on a
captured audit event.

| Surface | Tool policy |
| --- | --- |
| MCP | **enforces** — the gate binds `request`, above the `callTool` convenience. Driven against a real server on `callTool`, a hand-built `tools/call` frame, the task API's `callToolStream`, and a task facade retained before governance: denied tool at ZERO executions with its result absent, allow control at one. An already-issued task facade is rebound in place. A raw `request` / `requestStream` function explicitly bound and retained before governance cannot be revoked by a later Proxy. `listTools` is bound separately for discovery-time poisoning defense |
| `obsvrGovernTool` | **enforces** — wraps the tool's own execute and gates before delegating |
| LangChain (`ObsvrCallbackHandler`) | **enforces** — `handleToolStart` plus `awaitHandlers`/`raiseError`. Both pre-tool callbacks reach one gate and the discount for a duplicate delivery is credited per call, not per handler: as a per-handler flag, one dispatch of the legacy `handleAgentAction` left every later `handleToolStart` returning before the gate, and `copy()` hands the same instance to every child manager. Driven against a real LangGraph agent |
| LlamaIndex, Vercel AI SDK | no gate of their own; govern individual tools with `obsvrGovernTool` |
| OpenAI Agents SDK | **enforces** via `attachToolGate` and/or `obsvrGovernTool` — see below |
| `chat.completions.runTools`, `beta.messages.toolRunner` | **enforces on the tools, not on the turns** — see below |

**OpenAI Agents SDK: enforces, through two independent pre-execution
mechanisms.** Driven live at `@openai/agents` 0.13.0, 0.13.4 and 0.14.2 with a
side-effect-counting tool: a denied tool writes ZERO marker lines under either
mechanism, exactly one on every paired allow control, with the tool's payload
asserted absent from what the caller received; the two redden independently
under mutation.

- `attachToolGate(agent)` pushes obsvr's tool input guardrail into each
  function tool's own `inputGuardrails` — the framework's per-tool extension
  point, awaited by the runtime BEFORE every invocation — walking handoff
  targets reachable from the agent, by tool OBJECT. Refusal is the guardrail
  contract's `rejectContent` sentinel: the model receives the block message as
  the tool's result and the run continues. The record is `blocked` /
  `TOOL_DENIED`, true on this path. A function tool carrying no
  `inputGuardrails` array (a build whose executor never consults guardrails)
  makes the attach THROW and roll back rather than arm a property nothing
  reads. Hosted provider-side tools have no client-side invocation to guard,
  and MCP-server tools are converted per turn after the attach — govern those
  at the MCP boundary.
- `obsvrGovernTool(tool)` gates the tool's own `invoke`; its refusal throws,
  which the framework wraps into `ToolCallError` — the RUN ABORTS with obsvr's
  denial in the error chain. Choose by what a denial should do to the run.

The `TracingProcessor` beneath them is the audit rail and still cannot refuse
anything — the framework dispatches processor callbacks fire-and-forget, and a
function span does not end until its tool has returned. With no mechanism
installed a denied tool records `action_taken: "not_evaluated"` with the reason
in `metadata.obsvr_telemetry.policy_not_evaluated`; beside a real gate it
defers, so no `not_evaluated` appears next to the gate's own verdict.

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
tool-gate implementations and they do not cover the same surfaces: Python ships
AutoGen, CrewAI, Haystack and PydanticAI gates this SDK has no equivalent of,
and it gates MCP on a different method. Both SDKs' LangChain integrations
enforce — each in the framework's pre-execution tool callback, with the handler
flag that lets a refusal escape rather than be logged. The per-integration table for Python is in
[`sdk-python/README.md`](https://github.com/obsvr-dev/obsvr-sdk/blob/main/sdk-python/README.md), and the combined view is in
the [root README](https://github.com/obsvr-dev/obsvr-sdk/blob/main/README.md).

### Agent runs

`obsvr.agentRun(name, fn)` records one agentic execution as a **run** — every governed action inside it (LLM calls, `obsvrGovernTool` tool calls, spans) is grouped under one `agent_run_id`, so it appears as a single row in the dashboard's Runs tab with its full trace. It emits a signed `<source>.agent.run.start` on entry and a terminal `<source>.agent.run.finish` on completion (success or failure).

```typescript
await obsvr.agentRun('support-agent', () => agent.run(userMessage), {
  source: 'llamaindex_ts', // or 'vercel_ai', etc. — labels the run's source
});
```

Use it for frameworks governed at the tool level (LlamaIndex, Vercel AI) so their executions form runs. LangChain and the OpenAI Agents SDK integrations form runs on their own and do not need it. The run boundary is this explicit scope — deterministic and developer-declared, never inferred. (Python: `with obsvr.agent_run("support-agent", source="llamaindex_py"): ...`.)

## Per-request identity

When supplied, a governed call resolves one principal — the `user_id` that user-scoped
quota rules meter, the session-taint latch keys on, approval grants bind to,
and the signed event carries inside the decision preimage. Attribution is optional
unless `requirePrincipal: true`. Resolution is one
fixed precedence — per-call audit fields / `metadata`, then the wrap-time or
integration `user_id` option, then the ambient subject — and one resolution
feeds both enforcement and the record.

`useSubject()` binds that identity to the current execution context
(`AsyncLocalStorage`), so one wrapped client or governed tool attributes per
request rather than per process:

```typescript
import { useSubject } from '@obsvr/sdk';

const wrapped = obsvr.wrap(new OpenAI());     // wrap once...

await useSubject('user:alice;tenant:acme', async () => {
  await wrapped.chat.completions.create({ ... }); // ...signed and metered as alice
});
```

An explicit `user_id` always beats the ambient subject, and with no scope
active behavior is unchanged. The scope now reaches every identity the wrap
path resolves: its **signed audit events** previously read only per-call audit
fields and wrap-time options — no ambient fallback — so a `useSubject()`
caller was attributed on the integration surfaces and the session-taint key
but not on the proxy's own events. All five wrap-path resolutions (completed,
streamed and blocked events, the external-backend input, and the
decision-input document) now fall back to the ambient subject.

**`requirePrincipal: true`** (off by default) refuses a governed call whose
enforcing channel carries no non-blank `user_id` — `PRINCIPAL_REQUIRED`, after
the enforcement-integrity gate, before any scanning layer. Empty and whitespace-
only strings are unattributed. It is enforced on the proxy
wrapper, the integration pipeline, the generic tool governor, and the
governance `evaluate()` endpoint, and it arms the MCP pre-call net by itself,
so a config whose only policy is this flag still refuses there.

## Known Limitations & Architecture Notes

This section documents signature, streaming, fail-mode, and in-process bypass boundaries.

### Before you install: the seven limits of the TypeScript SDK

**Scope: this list is the TypeScript SDK only.** The two SDKs do not have the
same limitations and neither list may be read across to the other — the Python
SDK has one of its own that does not apply here, and three below do not apply to it.
The combined list for both, with the scope marked on each entry, is in the
[repository README](https://github.com/obsvr-dev/obsvr-sdk#before-you-install-the-eight-limits-worth-knowing).

1. **Most integration tests drive hand-written fakes, not the real frameworks.**
   Five surfaces run against real upstream packages in CI — MCP, OpenAI,
   legacy Google Generative AI, maintained Google Gen AI and OpenAI Agents; every other integration is
   fake-driven. A green integration suite says the shape is right, not that the
   framework behaves the way the test models it.
   [`tests/README.md`](https://github.com/obsvr-dev/obsvr-sdk/blob/main/sdk-typescript/tests/README.md) says which surfaces are which.

2. **This package is ESM-only, and the zero-code path cannot reach `require()`.**
   A CommonJS service cannot consume it at all, and even where it loads,
   `--import` interception never sees `require()` — so that coverage is nil
   rather than partial. See [below](#this-package-is-esm-only).

3. **Coverage is method-table based, even on named compatibility wrappers.**
   `wrapAzureOpenAI`, `wrapTogether` and `wrapOpenAICompatible` now share
   `obsvr.wrap()`'s governed OpenAI-shaped paths and exclusions. Their extra
   behavior is endpoint attribution, not a narrower policy engine.
   [Detail](#what-gets-governed).

4. **LangChain, LlamaIndex and the OpenAI Agents tracing processor observe rather
   than govern.** On those model-call paths the PII scan runs over what the event
   will store, and nothing else runs — so the provider receives the raw prompt
   while the stored copy reads redacted. A `piiPolicy` of `{ssn: "block"}` blocks
   through `obsvr.wrap()` and does not block there. The event reports
   `action_taken: "not_evaluated"` and records the stored-copy action separately
   under `metadata.obsvr_telemetry`.

5. **The OpenAI Agents tracing surface cannot refuse a tool, structurally —
   the gates on that framework live elsewhere.** The framework dispatches
   processor callbacks fire-and-forget, and the gate there runs after the tool
   has already returned; those events record `not_evaluated`, never `blocked`
   — a silence, not a false refusal. The surface itself enforces through the
   framework's own pre-invocation tool guardrails (`attachToolGate`) or
   `obsvrGovernTool`, and the processor defers to either. Put a destructive
   capability behind MCP, a tool guardrail, or a governed tool.
   [Grading](#framework-integrations).

6. **The zero-code auto-register misses two import shapes, each measured rather
   than reasoned about.** A `require()` entry point (the hook does not
   intercept CommonJS at all) and a subpath import such as `openai/index.mjs`
   or `openai/client` (the specifier table is exact-match) bypass interception.
   Supported root exports, including `OpenAI`, `AzureOpenAI`, and
   `BedrockOpenAI`, are rebound to governed clients. An escaped import records
   nothing rather than recording something false, and explicit `obsvr.wrap()`
   remains available for client instances.
   [Detail](#zero-code-global-coverage-no-monkey-patching).

7. **Current Gemini coverage is method-bounded.** `@google/genai` 2.x is
   governed on `models.generateContent` and `models.generateContentStream`,
   through explicit wrapping or the module interceptor. Chat sessions, Live
   API, Interactions, batches, token counting, and binary/multimodal payload
   contents remain outside this wrapper.

### Streaming calls

With `stream: true`, PII scanning and policy hooks run **before** the LLM is contacted; a blocked call never opens the stream. However, **post-call** policies on streamed responses are audit-time, not enforcement-time: tokens reach the caller as they arrive, and response scanning happens after completion.

`streamingMode: "skip"` is an enforce-mode evidence opt-out, not a policy
opt-out: pre-call block/redaction still runs, but an allowed stream is returned
without wrapping or emitting its stream event. Monitor mode ignores this opt-out
and emits the governed stream evidence even when `skip` is configured.

### Signing model

Event signatures are derived from your API key inside the SDK. They prove capture order and detect after-the-fact modification, but a party holding the API key could construct validly-signed events. Server-side countersigning at ingest binds each accepted event to a key that never leaves the server. Treat the client chain as integrity, not as non-repudiation against a key-holder.

For local non-repudiation without trusting ingest, set `deviceSigningKeyFile` to an operator-generated Ed25519 key: every event then also carries a `device_sig` over the same preimage the HMAC covers, and `obsvr-verify --device-pubkey <pinned key>` verifies it — with or without the API key. Pinned keys are trusted, an unpinned key id is reported foreign (never trusted on first use), and a missing seal on a pinned chain is a break. It catches an API-key holder re-forging the chain, which the HMAC cannot. The SDK never generates the key (uses `node:crypto` to sign; a key it cannot read refuses at init). Full boundary in [`SECURITY.md`](https://github.com/obsvr-dev/obsvr-sdk/blob/main/SECURITY.md).

### Fail mode

Default is fail-open: if a hook times out or throws, or a detector layer fails while deciding, the call is allowed, that layer's enforcement is lost for it, and the failure is counted and recorded on the call's own event. Set `failMode: 'closed'` for policies that must never fail open. `failMode` deliberately cannot move three things: `policy_floor` and `canary` always fail **closed** (a floor that cannot run must not wave a call through), a `redact` decision whose redactor then throws **blocks** rather than forwarding the content it was told to strip, and after the provider has answered nothing is withheld from your application — a response-side failure falls closed only on the stored audit copy. If the obsvr backend is unreachable, cached policy rules keep enforcing; only rule updates degrade.

### PII scanning scope

On direct wrapper paths, policy decisions scan all provider-bound text carried by
system, user, assistant, and tool-result roles. A block stops the request and a
redaction rewrites the affected role while preserving the message structure.
The centralized stored-content pass separately scans the final prompt and
response for every emitted event. Observe-only LangChain, LlamaIndex, and OpenAI
Agents tracing callbacks do not control provider-bound content; their stored
redaction is labeled `not_evaluated`. Types `name`, `address`, `person`,
`location`, `medical`, and `national_id` require Presidio.

### Unicode normalization (matching-time only)

Before rule, PII, and injection matching, text is normalized (Unicode **NFKC** + zero-width/invisible-character stripping + a small curated confusable fold) so an attacker cannot slip a keyword or pattern past the scanners with a lookalike or zero-width-joined variant (`оverride`, `ｏｖｅｒｒｉｄｅ`, `over<ZWJ>ride` all match `override`). This is a **matching-time transform only**: it changes what the engine *detects*, never what it *stores or forwards*. The audited prompt/response and the redaction output reflect exactly what the user sent (redaction is the sole content mutation). The transform is pinned across both SDKs by `conformance/fixtures/normalization.json`.

### Serverless / Lambda

Each cold start begins a fresh integrity session (`sdk_session_id`, `seq_no` reset). Multiple sessions starting at `seq_no=1` are expected and verify correctly. Call `await obsvr.flush()` before the runtime freezes.

### Process shutdown

Wrapping a client installs `SIGTERM`/`SIGINT` handlers that flush the audit queue within a two-second budget. They call `process.exit()` **only when nothing else is listening for that signal**: attaching a listener replaces the runtime's default disposition, so a library that attaches one and never exits leaves a process that ignores `SIGTERM` forever.

If your application has its own graceful shutdown, it owns termination. obsvr flushes beside it and will not end the process while your drain, transaction commit or pool close is still in flight — the trade being that a host exiting before the flush completes drops whatever is still queued, which is the cheaper of the two losses. Ownership is decided **when the signal arrives**, not when the client was wrapped, so installing your handler after `wrap()` behaves the same way.

The Python SDK now does the same, with the same ownership rules and its own five-second budget. One difference is structural rather than chosen: a POSIX disposition is a single slot where Node keeps a listener list, so Python decides ownership at install time — a host installing its handler after `obsvr.init()` replaces obsvr's there, where installing yours after `wrap()` works here.

### SDK bypass

Not calling `obsvr.init()` means no governance coverage; there is no post-hoc runtime check. Assert `obsvr.isInitialized()` at startup in production. Setting `disabled: true` in a production environment logs a prominent warning and emits a `governance_disabled` audit event so the bypass is on the record.

## License

Apache-2.0
