# obsvr-sdk

Runtime governance for LLM applications in Python: deterministic policy enforcement (PII, custom rules, human-in-the-loop hooks), and a tamper-evident, HMAC-chained audit trail. Fire-and-forget delivery that never blocks your LLM path.

## Installation

> Private beta — not yet published to PyPI. Request access at [obsvr.dev](https://obsvr.dev).

```bash
pip install obsvr-sdk
```

Requires **Python >= 3.9**. No runtime dependencies.

Optional extras for framework integrations:

```bash
pip install "obsvr-sdk[langchain]"        # LangChain callback handler
pip install "obsvr-sdk[crewai]"           # CrewAI integration
pip install "obsvr-sdk[autogen]"          # AutoGen integration
pip install "obsvr-sdk[llamaindex]"       # LlamaIndex integration
pip install "obsvr-sdk[fastapi]"          # FastAPI / Starlette middleware
pip install "obsvr-sdk[bedrock]"          # AWS Bedrock (boto3) governance
pip install "obsvr-sdk[vertex]"           # Google Vertex AI governance
pip install "obsvr-sdk[adk]"              # Google ADK callbacks
pip install "obsvr-sdk[pydantic-ai]"      # PydanticAI toolset governance
pip install "obsvr-sdk[haystack]"         # Haystack 2.x governance component
pip install "obsvr-sdk[smolagents]"       # smolagents tool governance
pip install "obsvr-sdk[agent-framework]"  # Microsoft Agent Framework middleware
pip install "obsvr-sdk[semantic-kernel]"  # Semantic Kernel filter
```

## Quick Start

Wrap your existing LLM client. No other code changes.

```python
import obsvr
from openai import OpenAI

obsvr.init(
    api_key="your-api-key",
    ingest_url="https://your-ingest-service",  # HTTPS enforced for non-localhost
    environment="production",
)

client = obsvr.wrap(OpenAI())

# Every call is now intercepted, policy-checked, and audited
client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "What is 2+2?"}],
)
```

Anthropic and Google Gemini work the same way (sync and async clients both supported):

```python
client = obsvr.wrap(Anthropic())          # messages.create
model = obsvr.wrap(genai.GenerativeModel("gemini-2.5-flash"))  # generate_content
```

## MCP Governance

Wrap the MCP client session; governance then covers all three phases —
**discovery** (tool descriptions scanned for poisoning), **request** (tool
arguments policy- and PII-checked before the call runs), and **response** (the
tool RESULT scanned before it reaches the caller). Tool results are the
exfiltration/poisoning channel, so a result carrying PII, secrets, or an
injection payload is **blocked**, **sanitized** (offending spans redacted), or
**logged** per policy — a blocked result is withheld from the caller entirely.

`govern_mcp(session)` is **non-mutating** — the Python analog of the TypeScript
`obsvrGovernMCP`. It returns a wrapper that delegates every attribute to the real
session via `__getattr__` and intercepts only `call_tool` / `list_tools`; the
`ClientSession` class is never patched, so other MCP tooling on the same session
keeps working.

```python
from mcp import ClientSession
from obsvr.integrations.mcp import govern_mcp

obsvr.init(
    api_key="your-api-key",
    ingest_url="https://your-ingest-service",
    mcp_tool_policy={
        "denied_tools": ["delete_file"],
        "block_poisoned_tools": True,
    },
)

async with ClientSession(read, write) as session:
    # Bind the caller identity (options mirror the TS obsvrGovernMCP opts) so
    # user/service/tenant-scoped quota rules meter the right bucket and the audit
    # attributes each decision to the principal.
    session = govern_mcp(session, options={"user_id": "alice"})
    await session.call_tool("read_file", {"path": "/tmp/x"})
```

> The legacy `patch_mcp(ClientSession)` — which monkey-patches the session class
> in place — is **deprecated** (it warns once and will be removed in the next
> major release). Migrate to `govern_mcp`.

### Unicode normalization (matching-time only)

Before rule, PII, and injection matching, text is normalized (Unicode **NFKC** +
zero-width/invisible-character stripping + a small curated confusable fold) so an
attacker cannot slip a keyword or pattern past the scanners with a lookalike or
zero-width-joined variant. This is a **matching-time transform only**: it changes
what the engine *detects*, never what it *stores or forwards* — the audited
content and the redaction output reflect exactly what the user sent. The
transform is pinned across both SDKs by
`conformance/fixtures/normalization.json`.

## Framework Integrations

Each integration hooks its framework's real call/tool path and runs the same
enforcement pipeline (pre-call PII/rules/HITL, and where the framework exposes
it, post-call governance) — a policy **block** stops or changes execution, it
does not merely log.

| Integration | Module | Interception point | Enforcement |
| --- | --- | --- | --- |
| LangChain | `integrations.langchain` | `BaseCallbackHandler` | observe + stored-copy PII |
| CrewAI | `integrations.crewai` | `step_callback` / kickoff callbacks | tool allow-deny, step limit, output policy |
| AutoGen | `integrations.autogen` | `process_message_before_send` hook | pre-send block/redact, tool + step limits |
| LlamaIndex | `integrations.llamaindex` | `BaseCallbackHandler` | observe + stored-copy PII |
| OpenAI Agents | `integrations.openai_agents` | `TracingProcessor` | tool allow-deny, step limit |
| MCP | `integrations.mcp` | `ClientSession.call_tool` / `list_tools` | request + response + discovery governance |
| **AWS Bedrock** | `integrations.bedrock` | boto3 `converse` / `invoke_model` (+ streams) | pre-call block/redact, post-call output governance |
| **Vertex AI** | `integrations.vertex` | `GenerativeModel.generate_content` | pre-call block/redact, post-call output governance |
| **Google ADK** | `integrations.adk` | `before_tool_callback` / `before_model_callback` | tool + request block (skips execution) |
| **PydanticAI** | `integrations.pydantic_ai` | `WrapperToolset.call_tool` | tool block before delegation |
| **Haystack 2.x** | `integrations.haystack` | `@component` pipeline node | block aborts the pipeline before the generator |
| **smolagents** | `integrations.smolagents` | tool `__call__` / `forward` | tool block before execution |
| **Microsoft Agent Framework** | `integrations.agent_framework` | agent middleware | block terminates the run (no `next`) |
| **Semantic Kernel** | `integrations.semantic_kernel` | function-invocation filter | block prevents function execution |

Callback-style (LangChain / LlamaIndex / OpenAI Agents / CrewAI):

```python
from obsvr.integrations.langchain import ObsvrCallbackHandler

handler = ObsvrCallbackHandler()
llm = ChatOpenAI(callbacks=[handler])
# Every chain/LLM call is now policy-checked and audited
```

Infrastructure providers — wrap the client/model; every governed call is
policy-checked on the way in and governed on the way out:

```python
import boto3, obsvr
from obsvr.integrations.bedrock import wrap_bedrock

obsvr.init(api_key="...", ingest_url="https://...",
           pii_policy={"rules": {"ssn": "block"}})
client = wrap_bedrock(boto3.client("bedrock-runtime"))
client.converse(modelId="anthropic.claude-3-5-sonnet-...", messages=[...])
```

```python
from vertexai.generative_models import GenerativeModel
from obsvr.integrations.vertex import wrap_vertex

model = wrap_vertex(GenerativeModel("gemini-1.5-pro"))
model.generate_content("...")
```

Agent frameworks — register the governance hook; a blocked tool/agent/function
never executes:

```python
# Google ADK
from google.adk.agents import Agent
from obsvr.integrations.adk import make_before_tool_callback, make_before_model_callback
agent = Agent(..., before_tool_callback=make_before_tool_callback(),
              before_model_callback=make_before_model_callback())

# PydanticAI
from obsvr.integrations.pydantic_ai import ObsvrToolset
agent = Agent("openai:gpt-4o", toolsets=[ObsvrToolset(my_toolset)])

# smolagents
from obsvr.integrations.smolagents import govern_agent
govern_agent(agent)   # wraps every tool in place

# Microsoft Agent Framework
from obsvr.integrations.agent_framework import obsvr_agent_middleware
agent = ChatAgent(chat_client=..., middleware=[obsvr_agent_middleware])

# Semantic Kernel
from obsvr.integrations.semantic_kernel import obsvr_function_invocation_filter
kernel.add_filter("function_invocation", obsvr_function_invocation_filter)

# Haystack 2.x
from obsvr.integrations.haystack import ObsvrGuard
pipe.add_component("guard", ObsvrGuard()); pipe.connect("guard.prompt", "llm.prompt")
```

### Agent runs

`obsvr.agent_run(name)` records one agentic execution as a **run** — every
governed action inside it (LLM calls, tool calls, spans) is grouped under one
`agent_run_id`, so it appears as a single row in the dashboard's Runs tab with
its full trace. It emits a signed `<source>.agent.run.start` on entry and a
terminal `<source>.agent.run.finish` on exit (success or failure).

```python
with obsvr.agent_run("support-agent", source="llamaindex_py"):
    agent.chat(user_message)   # LLM calls, tool calls inside join this run
```

The run boundary is this explicit scope — deterministic and developer-declared,
never inferred. (TypeScript: `await obsvr.agentRun("support-agent", () => agent.run(msg), { source: "llamaindex_ts" })`.)

## Policy Enforcement

Policies run before the call proceeds. Deterministic code only; no LLM in the decision path.

```python
obsvr.init(
    api_key="your-api-key",
    ingest_url="https://your-ingest-service",

    # Built-in PII scanning: block | redact | detect_only per type
    pii_policy={
        "default": "detect_only",
        "rules": {"ssn": "block", "credit_card": "block", "email": "redact"},
    },

    # Custom pre-call hook: return "allow" | "block" | "redact"
    on_pre_call=lambda event: "block" if is_high_risk(event["prompt"]) else "allow",
    hook_timeout_ms=2000,

    # Enforcement fail mode when a hook times out or raises:
    # "open" (default) allows the call; "closed" blocks it.
    fail_mode="closed",
)
```

Built-in regex detection covers 13 PII types including SSN, credit cards, API keys, AWS access keys, private keys, GitHub tokens, Slack webhooks, JWTs, and prompt-injection patterns. Optional [Presidio](https://microsoft.github.io/presidio/) integration (set `presidio_analyzer_url`) adds the 6 NLP types (`name`, `address`, `person`, `location`, `medical`, `national_id`) for the full 19-type taxonomy. Detection parity with the TypeScript SDK is enforced by shared test vectors.

**Opt-in security controls** (all off by default): **`policy_floor`** — a non-overridable operator baseline (same shape as a policy rule) that customer rules and the `on_pre_call` hook can't weaken, with a floor `redact` failing closed to a block; **`deobfuscation={"enabled": True}`** — also scan base64/hex/percent-decoded and invisible/confusable-folded views so encoded payloads can't dodge detection; **`mcp_tool_policy={"pinning": {"enabled": True, "mode": "block"}}`** — content-hash MCP tool descriptors to catch a rug-pull swap; **`session_taint={"enabled": True}`** — latch a session as compromised on an injection/canary leak and escalate later egress; and **canary honeytokens** via `mint_canary()` — plant a unique token and get a CRITICAL signal if it resurfaces. See [`SECURITY.md`](../SECURITY.md) for each control's exact guarantee and boundary.

### Verdict reason codes

Every policy verdict carries a stable, machine-groupable `reason_code` drawn from a **closed registry** (`obsvr.ReasonCode`) **plus** the existing free-form `reason` string as human detail — the code is additive, so nothing is lost. Codes such as `KEYWORD_BLOCKED`, `QUOTA_EXCEEDED`, `MODEL_GATE_BLOCKED`, `APPROVAL_REQUIRED`, and `SHADOW_WOULD_BLOCK` are pinned in [`conformance/fixtures/reason_codes.json`](../conformance/fixtures/reason_codes.json) so the Python and TypeScript SDKs share one identical vocabulary. A CI staleness check fails if the two registries diverge or the engine can emit a code outside the registry.

```python
from obsvr import ReasonCode, REASON_CODES
```

## External Policy Backend (OPA / Cedar)

Already standardized on policy-as-code? Point obsvr at your existing **OPA** HTTP endpoint or **Cedar** authorization service and its verdict participates in every pre-call decision.

```python
obsvr.init(
    api_key="your-api-key",
    ingest_url="https://your-ingest-service",
    external_policy_backend={
        "type": "opa",  # "opa" | "cedar"
        "url": "https://opa.internal.example.com/v1/data/obsvr/allow",
        # "shadow": True,        # observe-only rollout: record the verdict, never block
        # "timeout_ms": 2000,    # error/timeout => DENY (fail-closed) in enforce mode
        # "headers": {"authorization": "Bearer ..."},
        # "name": "corp-opa",    # identity recorded on events (provenance)
        # "policy": "<rego text or bundle revision>",  # hashed into the provenance record
        # "allow_private_network": True,  # permit a sidecar/private-network backend
    },
)
```

Semantics (byte-identical to the TypeScript SDK, pinned by shared conformance fixtures):

- **Deny-wins merge.** A `deny` from *either* the local rules or the backend blocks the call. A backend `allow` never downgrades a local block.
- **Fail-closed.** A backend error or timeout counts as `deny`. Use `"shadow": True` for a safe, observe-only rollout that records what the backend *would* have done without ever blocking.
- **SSRF-guarded.** The backend URL must be `http(s)`; private / loopback / link-local / cloud-metadata addresses (`169.254.169.254`, `10/8`, `127/8`, `::1`, …) are refused, resolving the hostname before connecting. A legitimate sidecar on `localhost`/a private network needs `"allow_private_network": True`; the cloud-metadata and link-local ranges are blocked even then.
- **Provenance.** Each event records which backend decided via `external_backend` (identity, backend type, raw outcome, shadow flag, and a hash of the effective backend policy).

The **OPA** endpoint is POSTed `{"input": <decision document>}` and its `result` is read as allow (boolean, or `{allow, reasons}`); the **Cedar** endpoint receives the decision document and its `decision` (`Allow`/`Deny`) is read. The decision document carries non-content fields only — operation, provider, model, principal, the local decision so far, the rules hash, and a SHA-256 **digest** of the prompt (never the raw prompt). Zero-config default is no backend.

## Tamper-Evident Audit Trail

Every event is stamped with a session ID, a monotonic sequence number, and an HMAC-SHA256 signature chained to the previous event's signature (`prev_sig`). The signing algorithm is byte-for-byte identical to the TypeScript SDK, verified by shared cross-language test vectors, so the ingest service verifies events from both SDKs with the same code and countersigns each accepted event.

Exported bundles verify offline with the `obsvr-verify` CLI (shipped in `@obsvr/sdk`), and merges can be gated on it in CI via the [obsvr Evidence Verification GitHub Action](../action/README.md).

## Known Limitations & Architecture Notes

We document enforcement limits honestly.

- **Transport**: `init()` raises when a non-localhost `ingest_url` uses plaintext `http` (localhost, `127.0.0.1`, and `[::1]` are exempt for local development). Set the environment variable `OBSVR_ALLOW_HTTP=1` to explicitly allow http, e.g. behind a TLS-terminating proxy on a private network.
- **Signing model**: signatures are derived from your API key inside the SDK. They prove capture order and detect after-the-fact modification, but a party holding the API key could construct validly-signed events. Server-side countersigning at ingest binds accepted events to a key that never leaves the server.
- **Fail mode**: default is fail-open. Set `fail_mode="closed"` for policies that must never fail open.
- **NLP PII types** (`name`, `address`, `person`, `location`, `medical`, `national_id`) are not detected by the built-in regex scanner; they require the Presidio integration.
- **Serverless**: each cold start begins a fresh integrity session; multiple sessions starting at `seq_no=1` are expected and verify correctly. Call `obsvr.flush()` before shutdown.

## License

Apache-2.0
