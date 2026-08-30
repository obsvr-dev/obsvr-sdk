# obsvr-sdk

Runtime governance for LLM applications in Python: deterministic policy enforcement (PII, custom rules, human-in-the-loop hooks), and a tamper-evident, HMAC-chained audit trail. Delivery that does not wait on the ingest transport, so a slow or dead backend does not slow your calls.

## Installation

```bash
pip install obsvr-sdk
```

> **Enforcement needs no account.** Policy, PII, and agent checks run entirely
> in your process, but you must configure the controls you want to enforce; an
> API key enables signing and delivery, not a default block policy.
> Delivering the signed audit record needs an obsvr ingest service, which is in
> private beta; you receive its URL together with your key. Until `ingest_url`
> is set the SDK still enforces — it warns once and delivers nothing.
> [Request access →](https://obsvr.dev)

Requires **Python >= 3.10**. No runtime dependencies.

Optional extras for the provider clients `obsvr.register` / `obsvr.auto` patch:

```bash
pip install "obsvr-sdk[openai]"           # OpenAI client governance
pip install "obsvr-sdk[anthropic]"        # Anthropic client governance
pip install "obsvr-sdk[openai-agents]"    # OpenAI Agents tool gate + tracing processor
pip install "obsvr-sdk[gemini]"           # Google Gemini (current google-genai + legacy client)
pip install "obsvr-sdk[mcp]"              # MCP tool governance (mcp 2.x)
```

Optional extras for framework integrations:

```bash
pip install "obsvr-sdk[langchain]"        # LangChain callback handler
pip install "obsvr-sdk[crewai]"           # CrewAI integration (Python < 3.14)
pip install "obsvr-sdk[autogen]"          # AutoGen integration
pip install "obsvr-sdk[llamaindex]"       # LlamaIndex integration
pip install "obsvr-sdk[bedrock]"          # AWS Bedrock (boto3) governance
pip install "obsvr-sdk[vertex]"           # Google Vertex AI governance
pip install "obsvr-sdk[pydantic-ai]"      # PydanticAI toolset governance
pip install "obsvr-sdk[haystack]"         # Haystack 2.x / 3.x prompt guard + Agent tool gate
pip install "obsvr-sdk[otel]"             # OpenTelemetry span mirroring
```

Ed25519 verification of signed remote policy needs one of two backends —
install either, not both:

```bash
pip install "obsvr-sdk[crypto]"           # cryptography (preferred)
pip install "obsvr-sdk[crypto-nacl]"      # PyNaCl (alternative)
```

## Quick Start

To initialize before application imports, run the application through obsvr:

```bash
OBSVR_API_KEY=... \
OBSVR_PII_POLICY='{"rules":{"ssn":"block"}}' \
OBSVR_AGENT_POLICY='{"denied_tools":["send_contract"]}' \
OBSVR_MCP_TOOL_POLICY='{"denied_tools":["delete_record"]}' \
OBSVR_REQUIRED_BINDINGS='openai.client,mcp.client,openai_agents.model,openai_agents.tools' \
obsvr-run app.py
# or: obsvr-run -m package.module
```

`obsvr-run` also reads `OBSVR_INGEST_URL`, `OBSVR_ENVIRONMENT`,
`OBSVR_ENFORCEMENT_MODE`, `OBSVR_FAIL_MODE`, `OBSVR_AGENT_POLICY`,
`OBSVR_MCP_TOOL_POLICY`, and `OBSVR_POLICY_REFRESH_INTERVAL_S`.

Set `OBSVR_REQUIRED_BINDINGS` to the exact boundaries the process requires:

| Key | Successful binding means |
| --- | --- |
| `openai.client` | documented future OpenAI construction is intercepted |
| `anthropic.client` | documented future Anthropic construction is intercepted |
| `mcp.client` | documented future MCP `ClientSession` construction receives the `tools/call` gate |
| `openai_agents.model` | intercepted Agents receive concrete-model governance |
| `openai_agents.tools` | intercepted Agents receive local function-tool and handoff gates, including supported later mutations |
| `llamaindex.models` | the process-global LlamaIndex model-start gate is installed |
| `crewai.tools` | the supported CrewAI pre-tool hook is installed |
| `autogen.tools` | the supported AutoGen/ag2 tool-execution gate is installed |

Startup fails before the target runs unless every listed boundary binds.
`openai_agents.tools` does not include tracing or hosted tools.
`auto_governance_status()` reports each boundary as `armed`, `bound`, or
`not-applicable`.

For deployment admission, `sign_coverage_attestation()` signs that binding
snapshot with an operator-held Ed25519 key. Requirements can demand `observe`
or `enforce` depth for exact integration symbols; ungraded legacy records are
`unknown` and cannot satisfy enforcement. The signed body also carries
policy-pack hashes, versions, initialization times, and known exclusions.
`verify_coverage_attestation()` rejects altered or noncanonical statements
under the pinned public key. This proves the process-reported bindings, not
calls made through a raw alias or outside a documented boundary.

After an application factory runs, use `assert_coverage_requirements()` to
require exact symbols and enforcement depth. Pair it with
`assert_enforcement_boundary()` or `assert_enforcement_boundary_async()` to run
one known-deny request and require zero additional calls in the supplied
transport counter. These checks prove the named factory path, not every client
in the process.

For local crash recovery of ordinary audit events, enable the optional outbox:

```python
obsvr.init(
    api_key=os.environ["OBSVR_API_KEY"],
    durable_delivery={
        "directory": "/var/lib/my-service/obsvr-outbox",
        "failure_mode": "error",
    },
)
```

Each signed event is atomically persisted before enqueue, replayed after
restart, and removed only after ingest acceptance. Permanent failures move to
`dead/`. Inspect counters with `obsvr.get_delivery_status()`. Use an absolute,
private directory per process; outbox files may contain governed data.

Govern an application-owned action without adapting it to a framework tool:

```python
@obsvr.govern(name="contract.send", consequence="external_write")
def send_contract(contract_id):
    return raw_send_contract(contract_id)
```

`govern_fn(function, ...)` is the equivalent direct wrapper. Python preserves
the original sync or async shape. Block occurs before the function is entered;
redaction changes the arguments it receives or fails closed. The returned
wrapper is the boundary. A retained raw function alias is not governed and is
reported as a coverage exclusion.

`build_action_context_v2()` provides the bounded context for strict
application actions. Optional principal, execution, and governance layers
carry stable facts and hashes only; unknown fields and raw target storage are
rejected.
Structured remediation uses `build_remediation_plan_v1()` and
`build_remediation_retry_v1()`: a retry is a new attempt linked to the original
receipt and requires hashed evidence for every declared requirement.

The same manifest is enforced by direct `obsvr.init(auto=True)`. Production
direct-init also warns if a supported package was imported first, because a
constructor or object reference copied before rebinding can remain raw.

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

# Supported text-generation methods are policy-checked; clean allows may be sampled.
client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "What is 2+2?"}],
)
```

Anthropic and current Google Gemini work the same way (sync and async clients supported):

```python
client = obsvr.wrap(Anthropic())          # messages.create
client = obsvr.wrap(GoogleGenAI())        # models.generate_content / aio.models.generate_content
```

**Which Gemini SDK.** Google ships two, and obsvr integrates both:

| Distribution | Extra | State |
| --- | --- | --- |
| `google-generativeai` | `obsvr-sdk[gemini]` | **supported, compatibility only** — the legacy line |
| `google-genai` | `obsvr-sdk[gemini]` | **supported** — current 2.x client; unary and streaming generation |

Compatibility only means fixes, not features: the legacy adapter is kept working for existing deployments. The two distributions have different method and response shapes and use separate adapters.

Both Gemini clients need an explicit `obsvr.wrap()` — unlike OpenAI and Anthropic, Python auto-registration does not intercept either package. The current adapter wraps `GoogleGenAI` and governs `models.generate_content`, `models.generate_content_stream`, and the corresponding `aio.models` methods. The legacy adapter wraps `GenerativeModel` and remains compatibility-only.

`obsvr-run` is the safest automatic path because it installs constructor and
supported process-global interception before the target imports. If the
application controls import order, `obsvr.init(..., auto=True)` provides the
same registration. Automatic startup currently covers OpenAI and Anthropic
client construction, future MCP `ClientSession` construction, CrewAI's
supported process-global pre-tool hook, AutoGen/ag2 0.x `ConversableAgent`
execution, Python LlamaIndex model-start callbacks, and future OpenAI Agents
`Agent` construction. Agents concrete model assignments and ordinary
tool/handoff list mutations stay on their pre-call gates. This is not a heap
scan. Existing instances, constructor references copied before init, unlisted
import aliases, custom transports, hosted tools, LlamaIndex agent tools,
Gemini, and LangChain callback configuration remain outside that automatic
boundary.

Explicit wrapping accepts `seal_raw=True` to revoke documented governed methods
on the exact raw client after the proxy is ready. This does not freeze provider
internals, revoke another instance, or invalidate a callable copied earlier.

`wrap()` governs `chat.completions.create` / `.parse`, `responses.create` / `.parse`,
`messages.create` / `.parse`, their `with_raw_response` and
`with_streaming_response` variants where the provider exposes them,
legacy `generate_content` / `generate_content_async`, current
`models.generate_content` / `models.generate_content_stream` and their
`aio.models` counterparts,
`start_chat().send_message` / `.send_message_async`, and the `beta.chat.completions.create` / `.parse`,
`beta.messages.create`, and `beta.responses.create` namespaces. Anthropic's
`beta.messages.tool_runner` is also governed from Anthropic 0.68.0, including
the initial Messages prompt and every local runnable tool; the async
`beta.sessions.events.tool_runner` local tools are governed from 0.103.0.
Hosted tool definitions have no local callback to gate. Everything else on the client passes through
ungoverned and unaudited — see the coverage boundary in `obsvr/wrap.py` for which of
those carry no chat text at all and which are text-bearing but not yet reachable from
a method-path table.

**A `wrap()` that governs nothing says so.** If none of those paths resolve on the
client you pass, the returned object still works and still forwards every call — but
no policy runs and no event is emitted for it, so `wrap()` logs one WARNING naming
the gap and the paths it looks for. Once per client, not per call. Pass
`require_governed_surface=True` to `init()` to make it raise instead, for a
deployment that wants an ungoverned client to fail at startup rather than at audit
time.

## Strict profile 2.1 provider boundary

Ordinary `wrap()` runs the policy pipeline before documented methods. For a supported direct-provider call that must also have a device-signed decision receipt admitted and committed **before execution**, construct a `StrictReceiptRuntimeV21` and pass an explicit capability:

```python
from obsvr import create_strict_provider_boundary_v2_1

# Configure this runtime with a StrictReceiptCoordinatorV21, admission options,
# a device signer, trusted identity/evaluation providers, and an atomic durable store.
strict = create_strict_provider_boundary_v2_1(
    runtime=runtime,
    context=lambda call: {
        "active_intents": ["serve"],
        "requested_scopes": ["model:invoke"],
        "run_id": "run-123",
    },
)

client = obsvr.wrap(OpenAI(), strict_receipt_v2_1=strict)
```

The strict sequence is `prepared -> remote_accepted -> committed -> invocation_started -> terminal`. No provider call occurs without positive admission and the preceding durable checkpoints. After `invocation_started`, an ambiguous result is `invocation_uncertain` and must not be retried automatically.

A successfully finalized invocation records a device-signed terminal outcome bound to the admitted decision, operation fingerprint, attempt, start time, and a result digest or bounded failure code. If terminal signing or persistence fails after execution starts, the durable journal remains unresolved; no terminal outcome is claimed. `reconcile_strict_runtime_execution_v2_1()` verifies a saved journal and an optional terminal outcome without ever declaring the action retry-safe. After restart, `finalize_interrupted_strict_runtime_execution_v2_1()` can sign and durably save only `uncertain/process_interrupted`; it does not infer what happened remotely.

Outcome delivery is explicit, not automatic. The terminal outcome remains in the durable checkpoint until the application submits the outcome or terminal journal, and delivery can resume after restart:

```python
delivery = submit_strict_runtime_terminal_journal_v2_1(
    terminal_journal,
    ingest_url=os.environ["OBSVR_INGEST_URL"],
    api_key=os.environ["OBSVR_API_KEY"],
    **receipt_trust,
)
```

`submit_strict_execution_outcome_v2_1()` and `submit_strict_runtime_terminal_journal_v2_1()` verify and send the exact outcome through a bounded DNS-pinned transport. Only an exact matching `400`, `401`, `403`, or `413` response with `stored: false` proves non-storage; conflicts and ambiguous transport results remain uncertain. Upload status is separate from the execution result. `create_strict_evidence_bundle_v2_1()` and `verify_strict_evidence_bundle_v2_1()` create and verify a portable signed chain with outcome coverage and reconstructed policy continuity; this SDK bundle does not include hosted acceptance attestations or daily anchoring.

This mode supports only synchronous unary `chat.completions.create` / `.parse`, `responses.create` / `.parse`, `messages.create` / `.parse`, legacy `generate_content`, and maintained `models.generate_content`. Async calls, streams, helper managers, runners, and other callables fail closed with `unsupported_surface`. Only an `ALLOW` outcome executes; `DENY`, `MODIFY`, `STEP_UP`, and `DEFER` do not contact the provider.

For a side effect that is not a model call, use `create_strict_action_boundary_v2_1()` with an explicit action, target, data classifications, requested scopes, and invocation function. Suspended `STEP_UP` decisions can be resumed through the runtime's signed approval-resolution path; a valid `ALLOW`, or `MODIFY` with bound effective arguments, executes the original action at most once.

To prevent self-approval, configure the coordinator with
`approval_separation_of_duties="requester_and_initiator"`. Its trusted
`approval_verifier` must return `principal_ref_hash` in the same pseudonymous
identity namespace as the requester's and agent's receipt hashes. Use
`"requester"` to check only the requester. The compatibility default is
`"none"`.

To correlate durable strict evidence with an existing OpenTelemetry trace, wrap the checkpoint store with `with_strict_otel_correlation_v2_1()`. It adds content-free `obsvr.strict.*` references only to the active recording span and only after `save()` succeeds. Telemetry errors are ignored and telemetry never authorizes an action. The cross-language keys are pinned by [`strict_otel_attributes_v2_1.json`](https://github.com/obsvr-dev/obsvr-sdk/blob/main/conformance/fixtures/strict_otel_attributes_v2_1.json).

The full construction used by the executable tests is in [`test_strict_provider_boundary_v2_1.py`](https://github.com/obsvr-dev/obsvr-sdk/blob/main/sdk-python/tests/test_strict_provider_boundary_v2_1.py). Read the repository [security boundary](https://github.com/obsvr-dev/obsvr-sdk/blob/main/SECURITY.md#strict-profile-21-execution-boundary) and [compatibility matrix](https://github.com/obsvr-dev/obsvr-sdk/blob/main/COMPATIBILITY.md#strict-profile-21-direct-provider-boundary) before enabling it.

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
session via `__getattr__` and intercepts `send_request`, `call_tool` and
`list_tools`; the `ClientSession` class is never patched, so other MCP tooling on
the same session keeps working. `send_request` is the load-bearing one:
`call_tool` is a convenience over it, and the task API and a hand-built
`tools/call` frame reach a tool without touching `call_tool` at all — measured,
each executed a denied tool before the gate bound there.

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
> major release). Migrate to `govern_mcp` unless you need the one route only a
> class-level patch reaches: a `ClientSessionGroup` handed the RAW session from
> underneath an instance wrapper dispatches through that object, so `govern_mcp`
> never sees the call. That route is measured and is listed in the table below.

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

Each enforcing integration hooks its framework's real call/tool path and runs
the applicable pre-call PII/rules/HITL pipeline, plus post-call governance where
the framework exposes it. LangChain and LlamaIndex model-start callbacks enforce
before dispatch; a requested redaction fails closed because callbacks cannot
reliably rewrite provider-bound content. OpenAI Agents tracing remains
observe-only, while `govern_model` and `govern_model_provider` enforce at the
model interface. Tool gates are documented separately below.

**Automatic startup attachment uses those same gates; it does not create a
second enforcement mechanism.** `obsvr-run` / early `init(auto=True)` installs
the supported CrewAI and AutoGen execution gates and attaches the OpenAI Agents
input guardrail to function tools present on every later `Agent` construction.
Use the explicit functions below for already-created objects, tools added later,
LangChain callbacks, LlamaIndex agent tool assembly, and MCP sessions.
**Whether a tool-policy block actually stops the tool
is a per-integration property, not a property of the SDK** — it depends on
whether the framework hands obsvr a hook that runs *before* the tool does, and
several do not. Each tool-policy state below was driven live against a real run
rather than read off the code, and the one row that has not been says so; where
a gate is present but unreachable the row reports that instead of listing the
feature.

| Integration | Module | Interception point | Enforcement |
| --- | --- | --- | --- |
| **Any framework's tools** | `obsvr.govern_tool` (`integrations.tools`) | the tool's own callable | **Tool policy: enforces** — the allow/deny gate raises the SDK's typed policy error before the tool body runs, and the call gets the FULL pre-call net (policy rules, the floor, PII block/redact, canary and session-taint destructive gates — the `obsvr.wrap()` pipeline, not the observe-only subset) plus a signed `tool.call` event carrying the sealed tool-content digest. The exec-attr table covers `on_invoke_tool`, `_run`/`_arun` with `func` co-gated (entry points fan out; the stored callable is where they converge), `execute`, `call`/`acall`, `invoke`/`ainvoke` **plus the `invoke_async` alias**, `run`/`arun`, and bare callables — sync and async wrapped as a pair, one verdict and one audit event per invocation. **What each supported framework resolves to is measured, not assumed:** every one of their real tool objects was run through the table and the result pinned per framework, so an addition that moved an existing shape onto a different entry point fails a test rather than reaching a customer. Two surfaces resolve to nothing by shape rather than omission — pydantic-ai's `Tool` carries no execute attribute and is governed at its toolset boundary, and MCP has no client-side tool object. Wraps a copy where the object permits one; an unrecognized shape is returned unchanged, never broken. **An attribute exposed as a property is not an entry point** — the gate installs by shadowing and a data descriptor cannot be shadowed — so a tool whose only match is one (ag2's `Tool.func`) comes back exactly as passed rather than raising at the caller, and its name is deliberately left out of the governed-name registry so no other surface's audit rail stands down for a gate that was never installed. A governed tool additionally DECLINES the framework's result cache (`cache_function`) — a cache hit answers from the framework's memory without entering the gated callable, escaping the gate and leaving no execution to count, measured on CrewAI. Note the governor governs an OBJECT: a second, unwrapped reference to the same tool held elsewhere (another agent's `tools` list) is not governed by it. CrewAI dispatch driven live on both executor paths, across six routes around them, and measured per version across the supported range. Four more surfaces drive the governor live as their second mechanism: openai-agents at 0.19.0 and 0.19.2, LlamaIndex at llama-index-core 0.14.5 and 0.14.23, Haystack at 3.0.0, and AutoGen's `install_tool_gate`, which governs the function-map entry through it. The remaining frameworks' shapes are pinned offline and not yet driven live per framework |
| LangChain | `integrations.langchain` | `BaseCallbackHandler` | **Model policy: enforces at model start.** The full pre-call policy runs before provider dispatch; a requested redaction fails closed because the callback cannot replace provider-bound input. **Tool policy: enforces** — the allow-deny check runs in `on_tool_start`, which the framework dispatches before the `try` that guards tool execution and outside the error handling that would turn a refusal into a tool result; the handler sets `raise_error`, so the refusal propagates instead of being logged and ignored, and it is defined synchronously because the framework's sync dispatcher discards a coroutine handler's exception without consulting that flag. **Step budget: enforces, and did not before** — it counts TOOL CALLS per run, and the run it belonged to was never found: `serialized` is a literal `None` at the graph root, at every graph node and from the classic executor's own `Chain.invoke`, so the chain the old code recognised runs from never matched and `max_steps` allowed every call on both runtimes. A run is now recognised from the `name` keyword and the graph metadata the framework does populate, and a tool call walks the recorded chain ancestry to reach it, since its immediate parent is the node that dispatched it rather than the run. Both driven live at `langchain-core` 1.0.0 and 1.5.3, on the graph runtime and the classic executor, at a budget of two against a model asking for three. The two runtimes deliver different pre-tool callbacks and a run delivering both is charged once, credited per call rather than latched — a latch disarmed the gate for every later run on the same handler |
| CrewAI | `integrations.crewai` | `before_tool_call` hook / `step_callback` / kickoff callbacks | observe (agent run, step, task) + post-run output policy. **Tool policy: enforces, through two independent pre-execution mechanisms — driven live on both executor paths with a side-effect-counting tool: a denied tool writes ZERO marker lines under either mechanism, exactly one on every paired allow control, and the two redden independently under mutation. Six further routes were driven live the same way and all gate: delegation to a coworker (including denying the injected delegation tool itself by name), the crew's result cache, the hierarchical manager, `kickoff_async` / `kickoff_for_each` / a Task's `async_execution`, tools attached to a Task rather than an Agent, and streaming — each asserting the tool's payload never reached the caller, not only that nothing ran.** Tool names in `denied_tools` / `allowed_tools` may be written the way CrewAI's docs and prompts spell them ("Delegate work to coworker") or the way CrewAI dispatches them (`delegate_work_to_coworker`): both sides of the comparison are normalized through CrewAI's own function. Before that normalization the two spellings did not match, so a policy written in the documented form governed nothing on this surface — a silent gap, not a false record. (1) `install_tool_gate_hook()` registers on CrewAI's own `before_tool_call` hook system, consulted before every tool execution on both the native function-calling and ReAct paths; it refuses by the hook system's returned sentinel — never by raising, which the dispatcher swallows fail-open — and the agent receives a blocked-tool observation while the run continues. Its record is `blocked` / `TOOL_DENIED`, which on this path is the truth. Process-global (the only scope CrewAI offers for tool hooks), allow/deny list only, and a 1.15.3+ capability: the installer feature-detects the DISPATCH half by attribute presence, never the version string, and on builds where hooks would be registered but never consulted — 1.8.0 through 1.15.2 ship exactly that trap — it refuses loudly and points at `govern_tool`. (2) `obsvr.govern_tool(tool)` gates inside the tool's own callable with the full pre-call policy net; it needs no CrewAI hook API and gates on every version in the supported range, measured through each release's own dispatch chains. With NEITHER mechanism installed the step callback is an audit rail and says so: it fires only after the step it reports, a denied tool that already ran on the ReAct path records `not_evaluated` with the reason in `metadata.obsvr_telemetry.policy_not_evaluated` — never a false `blocked`, and never a raise, because the executor retries raises and re-runs the side effect — and the native path delivers no per-tool callback at all. The **step limit does fire** on the step callback, post-hoc. Run-level audit wires through `before_kickoff_callbacks=[...]` / `after_kickoff_callbacks=[...]` — plural and list-valued. The singular `before_kickoff=` / `after_kickoff=` spellings are not Crew fields on current releases and are silently discarded by Crew's `extra="ignore"` pydantic config, so a crew wired that way emits no run-level audit and raises nothing to say so |
| AutoGen (ag2) | `integrations.autogen` | `process_message_before_send` hook (message) / `execute_function` (execution) | pre-send block/redact. **Tool policy: enforces, through two independent mechanisms at opposite ends of the same call — driven live at ag2 0.3.2 and 0.9.9 with a side-effect-counting tool: a denied tool writes ZERO marker lines, exactly one on every paired allow control, and the two redden independently under mutation.** (1) The **send hook** inspects the outgoing message: every call in a `tool_calls` array is checked and the step budget is charged per call. It refuses by raising out of `send`, which the framework wraps in no `try`, so the message is never delivered and the chat stops. It used to read `tool_calls[0]` only, so a denied tool anywhere after the first was delivered and executed. Two conditions: register on every agent that can EMIT a tool call (the hook fires on the sender, and registering on the initiating proxy alone leaves tool policy inert), and install `patch_initiate_chat` whenever `max_steps` is set — it is what scopes the budget to a conversation, and **without it `max_steps` is not applied at all**: each affected tool call records `not_evaluated` with the reason rather than being charged against a counter that is per thread for the process lifetime. (2) `install_tool_gate()` gates `ConversableAgent.execute_function` / `a_execute_function`, governing the `_function_map` entry with the full pre-call net before the executor invokes it. **It exists because the send hook governs the MESSAGE, so it governs only routes that send one** — `_process_message_before_send` has exactly two call sites in the framework, `send` and `a_send`, and measured live with the hook installed, a tool-call dict handed straight to `generate_reply`, to `receive`, or to `execute_function` executed the denied tool and returned its payload to the caller. So does an agent the caller never constructs: `run()` builds a hidden executor holding every callable and no hooks, and group and swarm chats build their own the same way, which is why the gate patches the class rather than an instance. Its refusal raises inside the callable, which `execute_function` catches and reports as a failed tool — the body was never entered, the model is told, the conversation continues. Choose by what a denial should do to the run, and note the `run()` family catches the send hook's raise and demotes it to an `ErrorEvent` on the response stream. Not covered, stated rather than implied: `RealtimeAgent` keeps its tools in a separate registry no executor reads (gate those functions with `obsvr.govern_tool` before registering), and code-execution replies run code from message CONTENT rather than a `tool_calls` array, so no tool allow/deny list bounds them |
| LlamaIndex | `integrations.llamaindex` | `BaseCallbackHandler` (audit) / `get_tools` (gate) | **Model policy: enforces at model start.** The full pre-call policy runs before provider dispatch; a requested redaction fails closed because the callback cannot replace every provider-bound request. **Tool policy: enforces, through `govern_agent(agent)` — driven live at llama-index-core 0.14.5 and 0.14.23 with a side-effect-counting tool: a denied tool writes ZERO marker lines, exactly one on every paired allow control, with the payload asserted absent from the `ToolCallResult` the caller received, on the plain, ReAct, tool-retriever and multi-agent-handoff routes.** The gate is on the tools and never on the callback, because on this framework a callback gate cannot work: `CBEventType.FUNCTION_CALL` has zero dispatch sites at any current version, and the newer instrumentation dispatcher swallows every handler exception, so nothing raised from one reaches the run. `govern_agent` binds to `get_tools`, where a workflow agent assembles the tools for a turn, and governs each with the full pre-call net. **Which mechanism you install decides the coverage:** `obsvr.govern_tool(tool)` applied by hand covers a `tools=[...]` list and does enforce (measured), but it governs an OBJECT — measured live, a tool supplied per turn by a `tool_retriever`, and a tool whose governed copy was discarded while the agent kept the original, both RAN under a policy that denied them. `govern_agent` reaches them because it governs whatever the agent hands back, whoever built it. Refusal is a raise from inside the tool, which the framework catches and reports as `ToolOutput(is_error=True)`, so the run continues and the model is told — the record, not an exception, is the evidence a refusal happened, and the exception TYPE is what separates a refusal from a tool that merely crashed. Not covered, stated rather than implied: `CodeActAgent`'s generated-code path runs model-written Python through the caller's own `code_execute_fn` instead of calling tools, so no tool allow/deny list bounds it — the gate does reach `real_fn`, so a denied tool called BY NAME from generated code is still refused, but arbitrary generated code is not a tool call; and tools invoked outside an agent (`llm.predict_and_call`, `tools.calling.call_tool`) never consult `get_tools`, so wrap those with `obsvr.govern_tool` at the call site, where the gate holds (measured live) |
| OpenAI Agents | `integrations.openai_agents` | tool input guardrails / `TracingProcessor` | **Tool policy: enforces, through two independent pre-execution mechanisms — driven live at openai-agents 0.19.0 and 0.19.2 with a side-effect-counting tool: a denied tool writes ZERO marker lines under either mechanism, exactly one on every paired allow control, with the tool's payload asserted absent from the run result, on the plain, streamed and handoff routes; the two redden independently under mutation.** (1) `attach_tool_gate(agent)` appends obsvr's `ToolInputGuardrail` to every function tool reachable from the agent — handoff targets included, by tool OBJECT, so a tool shared between agents is gated for both. The executor consults tool input guardrails BEFORE invoking the tool; refusal is the guardrail contract's `reject_content` sentinel, so the model receives the block message as the tool's result and the run continues. Its record is `blocked` / `TOOL_DENIED`, which on this path is the truth. Allow/deny list only; a 0.4.0+ capability, feature-detected by attribute presence on BOTH framework halves (guardrail types AND the executor's consult site) — a build that would accept the registration and never consult it gets a loud `ImportError` pointing at `govern_tool`, never a silent no-op. Not covered, stated rather than implied: hosted provider-side tools (no client-side invocation to guard) and MCP-server tools, which the framework converts per turn — govern those at the MCP boundary. (2) `obsvr.govern_tool(tool)` gates inside the tool's own `on_invoke_tool` with the full pre-call policy net; its refusal RAISES, which this framework's per-tool error boundary converts to `UserError` — the run aborts with obsvr's typed error in the chain. Choose by what a denial should do to the run. The `TracingProcessor` beneath them is the audit rail: it cannot refuse (processor callbacks are wrapped in the framework's own `try/except`, and a function span ends after its tool returned), and with no mechanism installed a denied tool records `action_taken: "not_evaluated"` with the reason in `metadata.obsvr_telemetry.policy_not_evaluated`. Beside a real gate it defers — no `not_evaluated` next to the gate's own verdict. The step limit and loop detection are observed on the processor's terms. **Its tracing MODEL-call path remains observe-only** and records stored-copy PII provenance without claiming a wire decision. Use `govern_model` or `govern_model_provider` to own `get_response` / `stream_response`, run the full pre-call policy, and rewrite provider-bound content before dispatch; a rewrite that cannot be guaranteed fails closed.
| MCP | `integrations.mcp` | `ClientSession.send_request` / `call_tool` / `list_tools` | request + response + discovery governance. **Tool policy: enforces** — a denied tool's callback does not run, including under the default `flag` taint action, because the gate sits on the request path itself rather than on a callback near it. **Driven end to end over real JSON-RPC against a real server, on protocol majors 1 and 2**: a denied tool at ZERO executions with its payload absent from what the caller received, and a paired allow control at exactly one, on every client route into `tools/call` — the documented `call_tool`, a hand-built frame handed to `send_request`, `experimental.call_tool_as_task`, discovery-then-call, and a `ClientSessionGroup` holding the governed session. `call_tool` is a convenience over `send_request` and was not the only way in: before the gate also bound to `send_request`, the task API and a hand-built frame each executed a denied tool, the raw route additionally returning its payload to the caller. One route is uncovered and measured rather than described: a `ClientSessionGroup` handed the RAW session from underneath an instance wrapper dispatches through that object, so `govern_mcp` never sees the call and only the class-level `patch_mcp` reaches it — the same object-not-name property `govern_tool` carries. Descriptor fields are read under both protocol spellings (`inputSchema` / `input_schema`), so the 2.0 rename does not silently empty the schema-surface poisoning scan, the descriptor pin hash or the destructive-capability gate. No step limit is implemented in this integration |
| **AWS Bedrock** | `integrations.bedrock` | boto3 `converse` / `invoke_model` (+ streams) | pre-call block/redact, post-call output governance |
| **Vertex AI** | `integrations.vertex` | `GenerativeModel.generate_content` / `start_chat` | pre-call block/redact across model calls and retained chat history, post-call output governance |
| **PydanticAI** | `integrations.pydantic_ai` | `Agent._get_toolset` (`govern_agent`) / `WrapperToolset.call_tool` (`ObsvrToolset`) | tool block before delegation — the same pre-execution boundary MCP holds on. **Driven live at both ends of the declared range**, and at the highest tested version against a real provider whose model chose to call the tool: a denied tool at ZERO side-effect writes with its payload absent from the caller's result, paired allow controls at exactly one. **Which mechanism you install decides what is covered.** `govern_agent(agent)` binds to the toolset the agent assembles for its tool manager — the one object every dispatch crosses — so `@agent.tool`, `@agent.tool_plain`, `Agent(tools=[...])` and every toolset passed to `Agent(toolsets=[...])` are all governed, including tools registered after the call. `ObsvrToolset` governs the toolset it wraps and nothing beside it: an agent's own function toolset is a SIBLING of the wrapped one, and a combined toolset dispatches each call to whichever sibling owns the tool, so a tool registered with `@agent.tool` executed under a policy naming it — measured, not inferred. A refusal raises and is not a `ModelRetry`, so the run ends rather than the model being handed a retry prompt; callers should expect to catch it. Caller options (`user_id` / `service_name` / `metadata`) are declared fields so they survive the `dataclasses.replace` rebuild the agent performs on its toolset tree; held outside them they were dropped, and the events named no principal while still refusing correctly. No step limit is implemented |
| **Haystack 2.x / 3.x** | `integrations.haystack` | `@component` pipeline node | a block emits a terminal `blocked` branch and omits the connected `prompt` output, so the downstream generator never becomes runnable. **Driven through real Pipeline schedulers** against Haystack 2.0.0 sync and 3.0.0 sync/async with paired allow controls: blocked runs reach the generator zero times, return only the safe block branch, and create no `PipelineRuntimeError` snapshot carrying the prompt; allowed runs reach it once. A redacted run sends the scrubbed prompt downstream. Callers inspect `result["guard"]["blocked"]`. The caller still owns the input object it supplied, and host-level content tracing can observe inputs before any in-graph guard runs. |
| **Haystack Agent tools** | `integrations.haystack` | `before_tool` hook | **Tool policy: enforces** — `install_tool_gate_hook()` registers obsvr's gate as `Agent(hooks={"before_tool": [...]})`. The Agent runs it before it resolves the pending tool calls and before it builds the executor that dispatches them, so a refusal takes the denied call out and leaves its siblings pending rather than racing one already in flight — driven with a denied call and a benign one in the same reply, and only the benign one runs. The gate rules on the CALL rather than on a tool object, which is what makes it total here: tools handed to `run(tools=...)`, tools inside a `Toolset` that respawns per run, and tools rebuilt by a serialization round-trip all still arrive as a named call in the Agent's own state. Refusal answers the model and the run continues; `on_denial="abort"` raises instead. Allow/deny only — `obsvr.govern_tool` carries the rest of the pre-call net and aborts. Requires the `before_tool` hook point, which 2.0.0 does not have: the installer probes for it and refuses loudly rather than arming a gate nothing would consult. **Survives serialization**, measured: an Agent saved with `to_dict` and rebuilt with `from_dict` comes back with the hook and still refuses at zero executions, where the same reload with no mechanism runs the denied tool. A `govern_tool`-wrapped tool does NOT survive that cycle — serialization records the tool's own `function` while the governor sits on `invoke`, so the reload succeeds and hands back an ungoverned tool. Register `obsvr.integrations.haystack` on Haystack's deserialization allowlist for the hook to load back |
| **Haystack `ComponentTool` / `PipelineTool`** | `integrations.haystack` | — | **Not covered, and measured rather than warned about.** These wrap a component (or a pipeline) and keep it as a live attribute, so the gate covers the TOOL CALL while the wrapped object stays reachable to anyone holding the tool. Driven: a denied `ComponentTool` runs zero times through the Agent, and the same component invoked directly off the tool — or added to a Pipeline of its own — runs once and returns its payload, with nothing claiming to have blocked either. This is the object-scope limit every tool gate in this SDK has; put the capability behind MCP, or govern the component's own entry point, if a second reference must not reach it |

**The callback timing decides whether model policy can enforce.** LangChain and
LlamaIndex dispatch their model-start callbacks before provider execution and
propagate obsvr's refusal, so the full pre-call policy runs there. Those
callbacks cannot reliably replace provider-bound content, so a redaction
verdict becomes a fail-closed block. OpenAI Agents tracing is different: its
processor exceptions are swallowed and the trace does not own dispatch, so it
records stored-copy provenance with `action_taken: "not_evaluated"`. Use
`govern_model` or `govern_model_provider` when OpenAI Agents model calls must
block or redact before transport.

**"Metering is opt-in" means the default is OFF, and that is a decision.** ``meter_integration_events`` defaults to **false**, so framework-integration events carry no cost fragment and never increment a token-unit quota; the ``obsvr.wrap()`` client-proxy path is metered either way and the flag does not affect it. The default is off because turning it on is not a neutral correction — a token-unit budget that has never bound on framework traffic **begins binding**, and calls that previously succeeded start being refused once it is reached. For an operator already running a token quota that is an outage rather than a fix, so it has to be a deliberate choice. One flag covers cost and quota together, because metering what a call cost without counting it against the budget it belongs to produces a record that disagrees with itself.

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
# PydanticAI
from obsvr.integrations.pydantic_ai import ObsvrToolset
agent = Agent("openai:gpt-4o", toolsets=[ObsvrToolset(my_toolset)])

# OpenAI Agents — obsvr-run attaches this guardrail to function tools present
# on future Agent construction. Call it explicitly for an existing Agent or
# after adding tools. Handoff targets are included; a denied tool never runs
# and the model receives the block message as the tool result. govern_tool is
# the alternative when a denial should ABORT the run instead.
from obsvr.integrations.openai_agents import attach_tool_gate
detach = attach_tool_gate(agent)

# Haystack — the guard is the same on 2.x and 3.x; only the socket differs,
# because 3.0 removed the text OpenAIGenerator and its `prompt` input.
from obsvr.integrations.haystack import ObsvrGuard
pipe.add_component("guard", ObsvrGuard())
pipe.connect("guard.prompt", "llm.prompt")    # haystack-ai 2.x, OpenAIGenerator
pipe.connect("guard.prompt", "llm.messages")  # haystack-ai 3.x, OpenAIChatGenerator

# Haystack tools are governed separately, by the Agent's own before_tool hook.
from obsvr.integrations.haystack import install_tool_gate_hook
agent = Agent(chat_generator=..., tools=[...],
              hooks={"before_tool": [install_tool_gate_hook()]})

# The prompt guard uses a terminal result rather than an exception, which keeps
# the raw prompt out of Haystack's PipelineRuntimeError snapshots.
result = pipe.run({"guard": {"prompt": "..."}})
if result.get("guard", {}).get("blocked"):
    handle_policy_block(result["guard"]["block_reason"])
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

## Per-request identity

When supplied, a governed call resolves one principal — the `user_id` that user-scoped quota
buckets meter, the session-taint latch keys on, approval grants bind to, and the
signed event carries inside the decision preimage. Attribution is optional unless
`require_principal=True`. One resolution feeds both
enforcement and the record: per-call `metadata` first, then the wrap-time
`user_id=` option, then the ambient subject below. This used to be two channels
on the generic tool governor — the wrap-time kwarg reached the **signed record
only** while quota, taint, approvals and the decision-input hash read metadata
it never touched, so `govern_tool(tool, user_id="mallory")` produced a signed
principal with none of the user-scoped enforcement bound to it. The fold is now
shared, and a tree-scan test fails any pre-call surface that ships without it.

A wrap-time option binds one identity for the object's lifetime. A process
serving many end users binds per request instead:

```python
from obsvr import use_subject

governed = obsvr.govern_tool(tool)          # govern once...

with use_subject("user:alice;tenant:acme"): # ...attribute per request
    governed.run("...")                     # metered, latched, signed as alice
with use_subject({"user_id": "bob"}):
    governed.run("...")                     # a different bucket, a different record
```

An explicit `user_id=` or `metadata` identity always beats the ambient one, and
with no scope active behavior is exactly as before. **The propagation boundary
is pinned in tests, not inferred:** the subject survives `await`,
`asyncio.create_task` and `asyncio.to_thread`, and is **silently lost** across
`loop.run_in_executor`, `ThreadPoolExecutor.submit` and `threading.Thread` — a
worker-thread tool call inside a scope runs as if no scope were active, with
nothing on the record to say so. If a tool body hops to a worker thread, pass
`user_id` explicitly on that path.

**`require_principal=True`** (off by default) refuses a governed call whose
enforcing channel carries no non-blank `user_id` — `PRINCIPAL_REQUIRED`, after the
enforcement-integrity gate, before any scanning layer. Empty and whitespace-
only strings are unattributed. It is enforced in the shared
pre-call pipeline (`wrap()`, the integrations, `govern_tool`, MCP) and arms the
tool and MCP pre-call nets by itself, so a config whose only policy is this
flag still refuses there.

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

    # Custom pre-call hook: return "allow" | "block" | "redact".
    # Enforcement is monotonic: "allow" keeps a clean call allowed but never
    # erases a PII/rule block rendered by an earlier layer.
    on_pre_call=lambda event: "block" if is_high_risk(event["prompt"]) else "allow",
    hook_timeout_ms=2000,

    # Enforcement fail mode when a hook times out or raises:
    # "open" (default) allows the call; "closed" blocks it.
    fail_mode="closed",
)
```

Built-in regex detection covers 13 PII types including SSN, credit cards, API keys, AWS access keys, private keys, GitHub tokens, Slack webhooks, JWTs, and prompt-injection patterns. Optional [Presidio](https://microsoft.github.io/presidio/) integration (set `presidio_analyzer_url`) adds the 6 NLP types (`name`, `address`, `person`, `location`, `medical`, `national_id`) for the full 19-type taxonomy. Detection parity with the TypeScript SDK is enforced by shared test vectors.

**Opt-in security controls** (all off by default): **`policy_floor`** — a non-overridable operator baseline (same shape as a policy rule) that customer rules and the `on_pre_call` hook can't weaken, with a floor `redact` failing closed to a block; **`deobfuscation={"enabled": True}`** — also scan base64/hex/percent-decoded and invisible/confusable-folded views so encoded payloads can't dodge detection; **`mcp_tool_policy={"pinning": {"enabled": True, "mode": "block"}}`** — content-hash MCP tool descriptors to catch a rug-pull swap; **`session_taint={"enabled": True}`** — latch a session as compromised on an injection/canary leak and escalate later egress, with `destructive_tools` naming exact tools a tainted session may never invoke even in flag mode; **`require_principal=True`** — refuse a call that arrives with no non-blank `user_id` on the enforcing channel (`PRINCIPAL_REQUIRED`; empty and whitespace-only strings are unattributed — see [Per-request identity](#per-request-identity)); and **canary honeytokens** via `mint_canary()` — plant a unique token and get a CRITICAL signal if it resurfaces. See [`SECURITY.md`](https://github.com/obsvr-dev/obsvr-sdk/blob/main/SECURITY.md) for each control's exact guarantee and boundary.

**Global monitor mode.** `enforcement_mode="monitor"` is one flip meaning
"keep deciding and recording, stop enforcing": every applicable layer still evaluates,
every governed decision and execution-span event emits, and a final block is converted to an allow whose
`shadow_outcome` carries the would-be verdict with the same `rule_id` and
`reason_code` an enforcing run records. Two classes enforce in **both**
modes: the enforcement-integrity gate (kill switch / fail-closed staleness),
re-derived at the moment of conversion so a stale snapshot cannot extend
monitor mode to a revoked key, and canary-leak blocks. A converted event is
enforcement evidence, exempt from allowed-call sampling even at
`sample_rate=0`, and `explain()` keeps predicting **enforce**-mode behaviour
so the pre-flight check still describes what turning enforcement on would do.

**Rule ordering, and opting out of it.** Rules evaluate **first-match in
document order** by default, and a matched `topic_allow` short-circuits — an
allow rule's list position can decide the verdict. `rule_resolution=
"deny_wins"` opts a deployment out: every enforcing rule is evaluated and the
strongest action prevails regardless of position (refusal over redaction over
flag over permit, smallest rule id breaking ties), decisions carry engine
version `obsvr-rules/2`, and the stamped `policy_version` commits to the
declared semantics — under a declared `first_match` it commits to evaluation
order, while undeclared rulesets keep their existing hash bytes. An unknown
declaration raises at `init()`. Two deliberate, pinned edges: shadow rules
evaluate first-match regardless of the declared mode, and under `deny_wins`
every quota rule meters every evaluated call — a call that ends blocked can
still consume quota, where first-match stopped metering at its first match.

**Blocking human approval.** A rule with `"require_approval": True` refuses
when no grant covers the call and files a request for the approvals queue; a
retry passes once a human grants it. That is the default, and
`approval_wait_ms=0` means exactly that — no waiting. Set it above zero and
the SDK **holds the call in the calling thread** instead, polling the grant
channel (`approval_poll_ms`, default 5000) until a covering grant lands or
the budget expires. Only an explicit, still-live grant lifts the hold — it is
re-validated after the wait, so a grant that expires mid-hold authorizes
nothing — and an expired hold blocks with its own registry code,
`APPROVAL_TIMEOUT`, distinct from `APPROVAL_REQUIRED` so a run-out hold is
never conflated with a plain refusal. Degradation mid-wait aborts the hold and
the block stands. One stated limit: **a denial is currently indistinguishable
from indecision client-side** — the grant channel carries grants, not
verdicts, so an explicitly denied request surfaces as the same
`APPROVAL_TIMEOUT` as one nobody looked at. Do not build this out of
`on_pre_call`: the hook is budgeted by `hook_timeout_ms` and resolves by
`fail_mode` on expiry, which at shipped defaults means a hook that waits for a
human times out and allows.

### Verdict reason codes

Every policy verdict carries a stable, machine-groupable `reason_code` drawn from a **closed registry** (`obsvr.ReasonCode`) **plus** the existing free-form `reason` string as human detail — the code is additive, so nothing is lost. The same code rides every audit **event** (`reason_code`), always identical to the one on the raised `ObsvrPolicyError`, so the record and the exception never classify a decision differently. Codes such as `KEYWORD_BLOCKED`, `QUOTA_EXCEEDED`, `MODEL_GATE_BLOCKED`, `APPROVAL_REQUIRED`, `APPROVAL_TIMEOUT`, `PRINCIPAL_REQUIRED`, and `SHADOW_WOULD_BLOCK` are pinned in [`conformance/fixtures/reason_codes.json`](https://github.com/obsvr-dev/obsvr-sdk/blob/main/conformance/fixtures/reason_codes.json) so the Python and TypeScript SDKs share one identical vocabulary. One is worth knowing by name: `QUOTA_UNMETERED` is the only code that reports enforcement **did not happen** rather than a verdict the engine reached, and it is emitted when a quota scope the bounded counter store could not admit is refused under `fail_mode="closed"`. A CI staleness check fails if the two registries diverge, if the engine can emit a code outside the registry, or — the inverse — if a registry code has no emission path at all (a code without one must be explicitly reserved, with its owning control named).

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
- **SSRF-guarded.** The production transport resolves the backend hostname once, rejects the complete address snapshot if any answer is private / loopback / link-local / cloud metadata, and pins a fresh connection to an approved numeric address while retaining the original Host header and TLS server name. Redirects are not followed. A legitimate sidecar on `localhost`/a private network needs `"allow_private_network": True`; cloud-metadata and link-local ranges remain blocked. An explicitly injected transport is a trusted embedding seam and must provide equivalent address pinning.
- **Provenance.** Each event records which backend decided via `external_backend` (identity, backend type, raw outcome, shadow flag, and a hash of the effective backend policy).

The **OPA** endpoint is POSTed `{"input": <decision document>}` and its `result` is read as allow (boolean, or `{allow, reasons}`); the **Cedar** endpoint receives the decision document and its `decision` (`Allow`/`Deny`) is read. The decision document carries non-content fields only — operation, provider, model, principal, the local decision so far, the rules hash, and a SHA-256 **digest** of the prompt (never the raw prompt). Zero-config default is no backend.

## Tamper-Evident Audit Trail

Every event is stamped with a session ID, a monotonic sequence number, and an HMAC-SHA256 signature chained to the previous event's signature (`prev_sig`). Chain format 4 seals prompt/response content, ordering, decision fields, and the classification fields `operation`, `source`, and `event_type`; an ordinary event cannot be relabeled as an audit-gap marker without breaking verification. Formats 1–3 remain verifiable at their original strength. The signing algorithm is byte-for-byte identical to the TypeScript SDK and pinned by shared cross-language vectors.

The default queue is memory-backed. `durable_delivery` adds atomic local
persistence, restart replay, accepted-delivery acknowledgement and dead-letter
retention. It does not discover calls that bypass every obsvr boundary, and loss
of the outbox volume remains loss of the recovery copy.

Exported bundles verify offline with the `obsvr-verify` CLI shipped by both SDK packages, and merges can be gated on it in CI via the [obsvr Evidence Verification GitHub Action](https://github.com/obsvr-dev/obsvr-sdk/blob/main/action/README.md).

## Known Limitations & Architecture Notes

The boundaries below are enforcement limits.

### Before you install: the five limits of the Python SDK

**Scope: this list is the Python SDK only.** The two SDKs do not have the same
limitations — the TypeScript SDK has an ESM-only public API while its startup
preload additionally chains documented CommonJS provider construction. Both
runtimes still have import-order and saved-reference limits, and one limit below
does not apply to TypeScript. The combined list for both, with the scope marked on each entry, is in the
[repository README](https://github.com/obsvr-dev/obsvr-sdk#before-you-install-the-eight-limits-worth-knowing).

**A limit measured on one SDK is a hypothesis about the other, not a fact about
it.** This paragraph used to say neither list "may be read across", which reads
as an assurance that a TypeScript limit is absent here. One of them was not:
zero-code interception enumerated client class NAMES in both languages, and a
provider binds one class to several of them (`anthropic.Client is
anthropic.Anthropic` is True), so construction through an unlisted name escaped
governance on BOTH sides while `init(auto=True)` reported success. It is fixed
in both — Python resolves the class objects and rebinds every public name bound
to one — and the wording is corrected here because the sentence was doing work
it could not support. Read each list as scoped, not as a guarantee about what is
absent elsewhere.

1. **Most integration tests drive hand-written fakes, not the real frameworks.**
   MCP and maintained Google Gen AI run against real upstream packages in CI. A green
   integration suite says the shape is right, not that the framework behaves the
   way the test models it. [`tests/README.md`](https://github.com/obsvr-dev/obsvr-sdk/blob/main/sdk-python/tests/README.md) says which
   surfaces are which.

2. **A shutdown handler you install AFTER `obsvr.init()` replaces obsvr's.**
   This SDK flushes on `SIGTERM`/`SIGINT` as well as `atexit`, chains to
   whatever disposition was already there, and restores the default and
   re-delivers only when nothing else owned the signal — so a container stop no
   longer drops the queue tail, and the process still dies **by** the signal
   rather than with an exit code standing in for one. The residual is ordering,
   and it is structural: a POSIX disposition is a single slot where Node keeps a
   listener list, so TypeScript decides ownership when the signal arrives and
   this SDK can only decide it at install time. Call `obsvr.init()` before your
   shutdown wiring, or call `obsvr.flush()` from your own handler. Two smaller
   consequences of the same rule: `SIG_IGN` is left alone entirely, and a
   handler installed from outside Python cannot be chained to, so obsvr keeps
   the exit there rather than swallowing the signal.

3. **Tracing is not always an enforcement point.** LangChain and LlamaIndex
   model-start callbacks enforce before dispatch; requested redaction fails
   closed because the callback cannot reliably rewrite provider-bound content.
   OpenAI Agents tracing remains observe-only. Use `govern_model` or
   `govern_model_provider` to enforce at that framework's model interface.

4. **Three frameworks needed pre-execution mechanisms of their own, and WHICH
   one you install decides the coverage.** A callback that fires after the
   step it reports can refuse nothing, so on the three surfaces where obsvr's
   only callback was one of those it now refuses ahead of it instead: on
   LlamaIndex, `govern_agent(agent)`, which binds to `get_tools` where the
   agent assembles a turn's tools and governs each through the full pre-call
   net; on CrewAI, its own `before_tool_call` hook (1.15.3+, sentinel
   contract) and the governed tool; on OpenAI Agents, `attach_tool_gate` —
   obsvr's `ToolInputGuardrail` on each function tool, consulted by the
   executor before invocation, refusing by `reject_content` so the run
   continues — and the governed tool, whose refusal aborts the run as
   `UserError`. All driven live to zero side-effect writes on denied tools.
   The mechanism matters because each framework can reach a tool by more than
   one route: `obsvr.govern_tool` governs an OBJECT, so on LlamaIndex a tool
   arriving per turn from a `tool_retriever` ran under a policy that denied
   it, and `govern_agent` is what reaches it. Where a
   surface records a denial it cannot enforce, it records `not_evaluated`,
   never `blocked` — silences, not false refusals. `mcp`, `langchain`,
   `autogen`, `pydantic_ai`, `llamaindex` (via `govern_agent`), `crewai` (via
   its hook), `openai_agents` (via its guardrail), `haystack` (via its
   `before_tool` hook) and any `govern_tool`-wrapped tool are where a
   tool-policy decision means what it says.
   [Grading](#framework-integrations).

5. **Current Gemini coverage is method-bounded.** `google-genai` 2.x is
   governed through explicit wrapping on unary and streaming generation plus
   retained chat sessions for sync and async clients. Live API, Interactions,
   batches, token counting, and opaque binary payload contents remain outside
   this wrapper.

- **Transport**: `init()` raises when a non-localhost `ingest_url` uses plaintext `http` (localhost, `127.0.0.1`, and `[::1]` are exempt for local development — compared as the parsed hostname, never as a substring). Set the environment variable `OBSVR_ALLOW_HTTP=1` to explicitly allow http, e.g. behind a TLS-terminating proxy on a private network. `ingest_url` also runs the SSRF guard at `init()`: the scheme must be `http(s)`, so `file:`, `gopher:` and `ftp:` are refused, and the cloud-metadata address is refused in every spelling — including over `https`, and regardless of `OBSVR_ALLOW_HTTP`, which relaxes the TLS posture only. The guard is static, so a hostname that *resolves* to a private address is not refused; see `SECURITY.md`.
- **Signing model**: signatures are derived from your API key inside the SDK. They prove capture order and detect after-the-fact modification, but a party holding the API key could construct validly-signed events. Server-side countersigning at ingest binds accepted events to a key that never leaves the server. For local non-repudiation without trusting ingest, set `device_signing_key_file` to an operator-generated Ed25519 key: every event also carries a `device_sig` over the same preimage the HMAC covers, verified offline with `obsvr-verify --device-pubkey <pinned key>` (with or without the API key). Pinned keys are trusted; an unpinned key id is foreign, never trusted on first use; a missing seal on a pinned chain is a break. The SDK never generates the key (a key it cannot read refuses at init; signing needs an Ed25519 backend — `pip install "obsvr-sdk[crypto]"` or PyNaCl). See [`SECURITY.md`](https://github.com/obsvr-dev/obsvr-sdk/blob/main/SECURITY.md).
- **Fail mode**: default is fail-open — a hook or a detector layer that fails while deciding loses that layer's enforcement for the call, which is counted and recorded on the event. Set `fail_mode="closed"` for policies that must never fail open. `fail_mode` deliberately cannot move three things: `policy_floor` and `canary` always fail **closed** (a floor that cannot run must not wave a call through), a `redact` decision whose redactor then throws **blocks** rather than forwarding the content it was told to strip, and after the provider has answered nothing is withheld from your application — a response-side failure falls closed only on the stored audit copy.
- **NLP PII types** (`name`, `address`, `person`, `location`, `medical`, `national_id`) are not detected by the built-in regex scanner; they require the Presidio integration.
- **Serverless**: each cold start begins a fresh integrity session; multiple sessions starting at `seq_no=1` are expected and verify correctly. Call `obsvr.flush()` before shutdown.

## License

Apache-2.0
