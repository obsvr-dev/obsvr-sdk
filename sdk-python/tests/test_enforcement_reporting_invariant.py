"""The enforcement-reporting invariant, as a per-integration table.

    For every event where ``action_taken == "blocked"``, the governed
    operation did not execute.

Nothing in this tree asserted that before. Two separate false-record defects
reached ``main`` because of it: a tool gate that ran after the tool returned and
still stamped ``blocked``, and a batched tool-call message where only the first
call was ever checked. Both were found by hand, against live providers. Hand
measurement does not run in CI, so it found each defect exactly once.

WHY THIS FILE IS OFFLINE AND MUST STAY OFFLINE
----------------------------------------------
Live probing and this invariant are different instruments. Live probing finds
what a class does not cover; the invariant catches the class on every commit.
Coupling this to real providers would hand a cheap, deterministic check a
credential-bound, rate-limited, slow dependency it does not need. There is no
network here, no provider, and no API key.

WHAT MAKES IT MORE THAN A MOCK TEST
-----------------------------------
The load-bearing part of each driver below is its ORDERING, and each ordering
models what the real framework was observed to do:

- MCP and PydanticAI both intercept the invocation boundary itself
  (``call_tool``), so the gate is reached before the tool. The drivers call the
  governed wrapper and let it decide whether the spy is ever entered.
- The tracing-processor driver runs the spy BEFORE the span-end callback,
  because that is the real order: ``on_span_start`` is a documented no-op and
  the gate lives in ``on_span_end``, after the tool returned. It also models the
  framework SWALLOWING the exception the gate raises, which is why raising there
  does not undo the call.
- The message-hook driver executes every tool call the delivered message
  carries, not just the first, because that is what the receiving agent does
  with a batched ``tool_calls`` array.
- The callback-handler and step-callback drivers deliver only the callbacks
  current runtimes were measured to deliver, and pass a step payload shaped like
  the modern one.

A driver whose ordering flattered the code would make this file worthless. Each
one is therefore written to be unkind, and each records its reasoning inline.

THE TABLE IS A DECLARATION, AND THAT IS THE POINT
-------------------------------------------------
Asserting only "blocked implies not executed" would pass an integration that
enforces nothing at all, because it never says ``blocked``. So each integration
declares a GRADE, and the assertion checks the measured outcome against it. An
integration that silently stops enforcing fails its ENFORCES row; an integration
that starts enforcing fails its INERT row and has to be regraded deliberately.
Both directions are pinned.
"""

import asyncio

import pytest

import obsvr


SPY_TOOL = "send_money"
BENIGN_TOOL = "get_weather"


@pytest.fixture(autouse=True)
def _fresh_governed_names(monkeypatch):
    """govern_tool registers wrapped names process-wide (the crewai step
    callback defers to them); tests must not inherit each other's registry."""
    from obsvr.integrations import tools as tools_mod

    monkeypatch.setattr(tools_mod, "_GOVERNED_TOOL_NAMES", set())


@pytest.fixture
def captured(sent, monkeypatch):
    """Event capture that does not depend on test ORDER.

    THIS PROBE WAS WRONG ONCE, AND THE WRONG ANSWER LOOKED LIKE A FINDING.
    ``integrations/mcp.py`` binds ``send_audit_async`` by name at import time,
    so patching the attribute on the sender module only reaches it when that
    module had not yet been imported. Run alone, this file imported mcp AFTER
    the patch and captured everything; run after the MCP suite, it captured
    nothing — and the invariant duly reported that MCP refused a denied tool
    while recording no event at all.

    A silent refusal IS a real defect class, which is what made the result
    convincing: the enforcement half was correct, the tool genuinely did not
    run, and only the record was missing. It was the harness. Patching the
    binding the code actually calls removes the order dependency, and this
    fixture is where the mistake is written down.
    """
    import obsvr.integrations.mcp as mcp_mod

    monkeypatch.setattr(mcp_mod, "send_audit_async", lambda cfg, ev: sent.append(ev))
    return sent


# ── Grades ───────────────────────────────────────────────────────────────────
#
# ENFORCES      the gate sits at the invocation boundary. The spy must NOT run
#               and the record must claim `blocked`.
# RECORDS_ONLY  a gate runs, but too late to stop the tool. The spy runs, and
#               the record must NOT claim `blocked` — claiming it is the lie
#               this whole file exists to prevent.
# INERT         the gate never fires on current runtimes. The spy runs and
#               nothing claims `blocked`.
# NO_GATE       no tool policy is implemented for this surface at all.

ENFORCES = "enforces"
RECORDS_ONLY = "records_only"
INERT = "inert"
NO_GATE = "no_gate"


class Spy:
    """Records that the governed operation was actually entered.

    ``entered`` is the side-effect half of the invariant. Nothing else in this
    file is allowed to infer it.
    """

    def __init__(self) -> None:
        self.entries = []

    def enter(self, tool_name: str) -> str:
        self.entries.append(tool_name)
        return f"result of {tool_name}"

    @property
    def entered(self) -> bool:
        return bool(self.entries)


class Outcome:
    """What one drive produced: did it run, and what did the record claim."""

    def __init__(self, spy: Spy, events: list, raised: BaseException = None) -> None:
        self.spy = spy
        self.events = events
        self.raised = raised

    @property
    def blocked_events(self) -> list:
        return [e for e in self.events if e.get("action_taken") == "blocked"]

    @property
    def claims_blocked(self) -> bool:
        return bool(self.blocked_events)

    def describe(self) -> str:
        return (
            f"spy_entries={self.spy.entries!r} "
            f"raised={type(self.raised).__name__ if self.raised else None} "
            f"claims={[e.get('action_taken') for e in self.events]!r} "
            f"operations={[e.get('operation') for e in self.events]!r}"
        )


# ── Drivers ──────────────────────────────────────────────────────────────────
#
# Every driver returns an Outcome. Every driver runs the spy exactly where the
# real framework would run the tool, and nowhere else.


def _drive_mcp(spy, sent):
    """MCP patches ``call_tool`` — the actual invocation boundary."""
    from obsvr.integrations.mcp import govern_mcp

    class _FakeContent:
        def __init__(self, text):
            self.text = text

    class _FakeResult:
        def __init__(self, text):
            self.content = [_FakeContent(text)]

    class _FakeListTools:
        tools = []

    class FakeClientSession:
        async def call_tool(self, name, arguments=None, **kw):
            return _FakeResult(spy.enter(name))

        async def list_tools(self):
            return _FakeListTools()

    governed = govern_mcp(FakeClientSession())

    async def go():
        await governed.call_tool(SPY_TOOL, {"amount": 500})

    raised = None
    try:
        asyncio.run(go())
    except BaseException as exc:  # noqa: BLE001 - the block is the signal
        raised = exc
    return Outcome(spy, sent, raised)


def _drive_pydantic_ai(spy, sent):
    """PydanticAI wraps the toolset's ``call_tool`` and delegates after gating."""
    from obsvr.integrations.pydantic_ai import ObsvrToolset

    class SpyToolset:
        async def call_tool(self, name, tool_args, *args, **kwargs):
            return spy.enter(name)

    governed = ObsvrToolset(SpyToolset())

    async def go():
        await governed.call_tool(SPY_TOOL, {"amount": 500})

    raised = None
    try:
        asyncio.run(go())
    except BaseException as exc:  # noqa: BLE001
        raised = exc
    return Outcome(spy, sent, raised)


class _FakeConversableAgent:
    """Minimal ConversableAgent: the hook registry and nothing else."""

    def __init__(self):
        self._hooks = {}
        self.llm_config = {"model": "gpt-4o"}

    def register_hook(self, hookpoint, fn):
        self._hooks.setdefault(hookpoint, []).append(fn)

    def run_hook(self, hookpoint, **kwargs):
        result = kwargs.get("message")
        for fn in self._hooks.get(hookpoint, []):
            result = fn(**kwargs)
        return result


def _tool_call(name, index):
    return {
        "id": f"call_{index}",
        "type": "function",
        "function": {"name": name, "arguments": '{"amount": 500}'},
    }


def _drive_autogen(spy, sent, tool_names=(SPY_TOOL,)):
    """The send hook gates a message; the RECIPIENT then runs what it carries.

    The hook fires before the message is sent, which is why it can enforce at
    all. But enforcement only holds for the calls it actually inspects: once the
    message is delivered, the receiving agent executes EVERY tool call in the
    ``tool_calls`` array. So the driver executes every one of them, in order,
    and does so only if the hook let the message through.
    """
    from obsvr.integrations.autogen import register_obsvr

    agent = _FakeConversableAgent()
    register_obsvr(agent)

    message = {
        "role": "assistant",
        "content": None,
        "tool_calls": [_tool_call(n, i) for i, n in enumerate(tool_names)],
    }

    raised = None
    try:
        agent.run_hook("process_message_before_send", message=message)
    except BaseException as exc:  # noqa: BLE001
        # Refused before send: the message never reaches the recipient, so no
        # tool in it runs.
        raised = exc
        return Outcome(spy, sent, raised)

    for call in message["tool_calls"]:
        spy.enter(call["function"]["name"])
    return Outcome(spy, sent, raised)


class _FakeTrace:
    def __init__(self, trace_id):
        self.trace_id = trace_id


class _FakeFunctionSpanData:
    type = "function"

    def __init__(self, name):
        self.name = name
        self.input = '{"amount": 500}'


class _FakeSpan:
    def __init__(self, trace_id, span_id, name):
        self.trace_id = trace_id
        self.span_id = span_id
        self.span_data = _FakeFunctionSpanData(name)


def _drive_tracing_processor(spy, sent):
    """The gate is in ``on_span_end`` — after the tool returned.

    Ordering is the whole point of this driver. ``on_span_start`` is an explicit
    no-op ("wait for span end to have complete data"), so the tool runs, and
    only then does the gate see it. The exception the gate raises is swallowed
    by the framework's trace-processor layer, so it cannot unwind the call that
    already happened; the driver catches it here to model exactly that.
    """
    from obsvr.integrations.openai_agents import ObsvrTracingProcessor

    proc = ObsvrTracingProcessor()
    trace = _FakeTrace("trace-inv-1")
    proc.on_trace_start(trace)

    span = _FakeSpan("trace-inv-1", "span-inv-1", SPY_TOOL)
    proc.on_span_start(span)      # documented no-op
    spy.enter(SPY_TOOL)           # the framework invokes the tool here

    raised = None
    try:
        proc.on_span_end(span)
    except BaseException as exc:  # noqa: BLE001
        # Swallowed in production by the tracing layer. Recorded, not honoured:
        # the tool above has already run and nothing rolls it back.
        raised = exc
    return Outcome(spy, sent, raised)


def _drive_langchain_callbacks(spy, sent):
    """Deliver the callbacks current runtimes actually deliver.

    ``on_agent_action`` is delivered by the CLASSIC executor only; the graph
    runtimes never fire it. So the driver does not call it, and instead delivers
    ``on_tool_start`` — the pre-execution hook the framework dispatches before
    the ``try`` that guards tool execution, and outside the error handling that
    would otherwise turn a refusal into a tool result.

    The handler must DEFINE that method itself. Probing with ``getattr`` is not
    enough and used to be what this did: the base class supplies a no-op
    ``on_tool_start``, so the probe was non-None whether or not the integration
    implemented anything, and the driver called the inherited no-op while the
    docstring claimed it was calling a gate. It happened not to change the grade,
    because a no-op cannot refuse — but it measured something other than what it
    said.
    """
    from obsvr.integrations.langchain import ObsvrCallbackHandler

    handler = ObsvrCallbackHandler()
    handler.on_chain_start(
        {"id": ["langchain", "agents", "agent", "AgentExecutor"]},
        {"input": "move the money"},
        run_id="run-inv-1",
    )

    raised = None
    if "on_tool_start" in type(handler).__dict__:
        try:
            handler.on_tool_start(
                {"name": SPY_TOOL, "description": "moves money"},
                '{"amount": 500}',
                run_id="tool-inv-1",
                parent_run_id="run-inv-1",
            )
        except BaseException as exc:  # noqa: BLE001
            # Refused before the tool: the framework never reaches the body.
            return Outcome(spy, sent, exc)

    spy.enter(SPY_TOOL)
    handler.on_tool_end("ok", run_id="tool-inv-1", parent_run_id="run-inv-1")
    return Outcome(spy, sent, raised)


class _ModernCrewStep:
    """A step payload shaped like the current one: no ``tool`` attribute.

    The gate reads ``step.tool``. Current releases hand the step callback an
    output object that does not carry it, which is why the gate never fires.
    Giving this stub a ``tool`` attribute would make the test pass for a reason
    production does not enjoy.
    """

    def __init__(self):
        self.output = f"called {SPY_TOOL}"


def _drive_crewai_step_callback(spy, sent):
    from obsvr.integrations.crewai import make_step_callback

    callback = make_step_callback()
    spy.enter(SPY_TOOL)  # the crew runs the tool, then reports the step

    raised = None
    try:
        callback(_ModernCrewStep())
    except BaseException as exc:  # noqa: BLE001
        raised = exc
    return Outcome(spy, sent, raised)


class _ReActCrewStep:
    """A step payload shaped like the ReAct path's ``AgentAction``: ``tool`` set.

    Any model whose ``supports_function_calling()`` is False takes this path —
    measured live. Unlike the native shape above, the tool name IS delivered,
    but the executor runs the tool first and hands the callback the action
    afterwards, so the only honest record is one that does not claim a block.
    """

    def __init__(self):
        self.tool = SPY_TOOL
        self.tool_input = '{"amount": 500}'
        self.text = f"Action: {SPY_TOOL}"


def _drive_crewai_step_callback_react(spy, sent):
    from obsvr.integrations.crewai import make_step_callback

    callback = make_step_callback()
    spy.enter(SPY_TOOL)  # ReAct runs the tool, THEN delivers the AgentAction

    raised = None
    try:
        callback(_ReActCrewStep())
    except BaseException as exc:  # noqa: BLE001
        raised = exc
    return Outcome(spy, sent, raised)


def _drive_crewai_gate_hook(spy, sent):
    """CrewAI's before_tool_call hook, driven on the framework's own contract.

    The hook system consults the hook BEFORE executing the tool, and a
    returned ``False`` means the tool is not run (CrewAI hands the agent a
    blocked-tool observation instead). The driver models exactly that: the
    spy runs only when the hook did not return the blocking sentinel. No
    crewai import — the hook factory is framework-free; only registration
    needs the framework.
    """
    from obsvr.integrations.crewai import make_tool_gate_hook

    class _HookContext:
        tool_name = SPY_TOOL
        tool_input = {"amount": 500}
        agent = None

    hook = make_tool_gate_hook()
    verdict = hook(_HookContext())
    if verdict is not False:
        spy.enter(SPY_TOOL)
    return Outcome(spy, sent, None)


def _drive_govern_tool(spy, sent):
    """The framework-agnostic governor: the gate lives inside the tool's own
    callable, so calling the governed tool IS the invocation boundary."""
    from obsvr.integrations.tools import govern_tool

    class _Tool:
        name = SPY_TOOL
        description = "moves money"

        def _run(self, amount: int = 0):
            return spy.enter(SPY_TOOL)

    governed = govern_tool(_Tool())
    raised = None
    try:
        governed._run(amount=500)
    except BaseException as exc:  # noqa: BLE001
        raised = exc
    return Outcome(spy, sent, raised)


def _drive_govern_tool_on_invoke(spy, sent):
    """The governor on the openai-agents ``FunctionTool`` shape.

    The framework awaits ``tool.on_invoke_tool(tool_context, arguments)`` —
    the input rides at POSITION 1, not 0, and the callable is async. Both
    halves of that contract have to hold or the gate reads the run context
    as the tool input; this driver dispatches exactly as the framework does
    (``tool.py``'s ``_invoke_function_tool_with_metadata``, re-read at
    0.19.2).
    """
    from obsvr.integrations.tools import govern_tool

    class _FunctionTool:
        name = SPY_TOOL
        description = "moves money"
        tool_input_guardrails = None

        async def on_invoke_tool(self, ctx, args_json):
            return spy.enter(SPY_TOOL)

    governed = govern_tool(_FunctionTool())

    async def go():
        await governed.on_invoke_tool(object(), '{"amount": 500}')

    raised = None
    try:
        asyncio.run(go())
    except BaseException as exc:  # noqa: BLE001
        raised = exc
    return Outcome(spy, sent, raised)


def _openai_agents_guardrail_stub():
    """A stub of the two framework halves obsvr's guardrail factory probes.

    sdk-python's venv carries no frameworks by design, so the factory's
    feature-detect is satisfied here the way the invariant file satisfies
    every other framework contract: with the smallest faithful model of the
    upstream surface (``agents.tool_guardrails`` types at 0.4.0 == 0.19.2,
    and the dispatch half's consult site by attribute presence).
    """
    import types

    class ToolGuardrailFunctionOutput:
        def __init__(self, output_info=None, behavior=None):
            self.output_info = output_info
            self.behavior = behavior or {"type": "allow"}

        @classmethod
        def allow(cls, output_info=None):
            return cls(output_info, {"type": "allow"})

        @classmethod
        def reject_content(cls, message, output_info=None):
            return cls(output_info, {"type": "reject_content", "message": message})

    class ToolInputGuardrail:
        def __init__(self, guardrail_function, name=None):
            self.guardrail_function = guardrail_function
            self.name = name

    tg = types.ModuleType("agents.tool_guardrails")
    tg.ToolGuardrailFunctionOutput = ToolGuardrailFunctionOutput
    tg.ToolInputGuardrail = ToolInputGuardrail

    te = types.ModuleType("agents.run_internal.tool_execution")

    async def _execute_tool_input_guardrails(**kwargs):  # pragma: no cover
        return None

    te._execute_tool_input_guardrails = _execute_tool_input_guardrails

    run_internal = types.ModuleType("agents.run_internal")
    run_internal.tool_execution = te

    agents_mod = types.ModuleType("agents")
    agents_mod.tool_guardrails = tg
    agents_mod.run_internal = run_internal

    return {
        "agents": agents_mod,
        "agents.tool_guardrails": tg,
        "agents.run_internal": run_internal,
        "agents.run_internal.tool_execution": te,
    }


def _drive_openai_agents_guardrail(spy, sent):
    """openai-agents consults tool input guardrails BEFORE invoking the tool.

    The executor's contract (``run_internal/tool_execution.py``, read at
    0.19.2 and identical at 0.4.0): ``reject_content`` means the tool is
    NOT invoked and the message becomes the tool's output to the model;
    ``allow`` proceeds to invocation. The driver dispatches exactly that,
    against obsvr's guardrail built by its own factory.
    """
    import sys

    stub = _openai_agents_guardrail_stub()
    saved = {name: sys.modules.get(name) for name in stub}
    sys.modules.update(stub)
    try:
        from obsvr.integrations.openai_agents import make_tool_gate_guardrail

        guardrail = make_tool_gate_guardrail()
        data = type(
            "Data",
            (),
            {
                "context": type(
                    "Ctx", (), {"tool_name": SPY_TOOL, "tool_call_id": "call-1"}
                )(),
                "agent": None,
            },
        )()
        out = guardrail.guardrail_function(data)
        if out.behavior["type"] != "reject_content":
            spy.enter(SPY_TOOL)
    finally:
        for name, prior in saved.items():
            if prior is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = prior
    return Outcome(spy, sent, None)


# ── The table ────────────────────────────────────────────────────────────────
#
# `policy_key` is the config field each surface reads. MCP deliberately reads a
# different one from the agent integrations, and pinning that here means a
# rename cannot quietly disarm the gate.

TABLE = [
    ("mcp", _drive_mcp, "mcp_tool_policy", ENFORCES),
    ("pydantic_ai", _drive_pydantic_ai, "agent_policy", ENFORCES),
    ("autogen", _drive_autogen, "agent_policy", ENFORCES),
    ("openai_agents", _drive_tracing_processor, "agent_policy", RECORDS_ONLY),
    ("langchain", _drive_langchain_callbacks, "agent_policy", ENFORCES),
    ("crewai", _drive_crewai_step_callback, "agent_policy", INERT),
    # Same module, second delivery shape: `surface:variant` names a driver for
    # a payload the same gate receives on a different runtime path.
    ("crewai:react", _drive_crewai_step_callback_react, "agent_policy", RECORDS_ONLY),
    # The pre-execution mechanisms. The step-callback rows above stay graded
    # as the AUDIT rail they are; these two are where refusal actually lives.
    ("crewai:gate-hook", _drive_crewai_gate_hook, "agent_policy", ENFORCES),
    ("tools", _drive_govern_tool, "agent_policy", ENFORCES),
    # openai-agents' pre-execution mechanisms. The tracing-processor row above
    # stays RECORDS_ONLY — it is the audit rail; these two are the gates.
    ("openai_agents:guardrail-gate", _drive_openai_agents_guardrail, "agent_policy", ENFORCES),
    ("tools:on-invoke-tool", _drive_govern_tool_on_invoke, "agent_policy", ENFORCES),
]

# Rows this invariant currently CATCHES. Each marker names a live defect and
# comes off in the commit that fixes it — `strict` guarantees that, because a
# row that starts passing while still marked fails the suite. So the exemption
# cannot outlive the defect it documents.
_KNOWN_FAILING = {}


def _row(name, driver, policy_key, grade):
    reason = _KNOWN_FAILING.get(name)
    marks = [pytest.mark.xfail(strict=True, reason=reason)] if reason else []
    return pytest.param(name, driver, policy_key, grade, marks=marks, id=name)


def _init_with_deny(policy_key):
    obsvr.init(
        api_key="test",
        sample_rate=1,
        **{policy_key: {"denied_tools": [SPY_TOOL]}},
    )


def assert_invariant(grade, outcome):
    """Both halves, every time. Either half alone is a defect that shipped."""
    if grade == ENFORCES:
        assert not outcome.spy.entered, (
            f"ENFORCES surface let the denied tool run: {outcome.describe()}"
        )
        assert outcome.claims_blocked, (
            f"ENFORCES surface refused the tool but no record claims blocked: "
            f"{outcome.describe()}"
        )
    elif grade == RECORDS_ONLY:
        assert outcome.spy.entered, (
            f"graded RECORDS_ONLY but the tool did not run — if this surface "
            f"now enforces, regrade it: {outcome.describe()}"
        )
        assert not outcome.claims_blocked, (
            f"THE LIE: the tool executed and the record claims blocked. "
            f"{outcome.describe()}"
        )
    elif grade == INERT:
        assert outcome.spy.entered, (
            f"graded INERT but the tool did not run — if this surface now "
            f"enforces, regrade it: {outcome.describe()}"
        )
        assert not outcome.claims_blocked, (
            f"THE LIE: no gate fired and the record claims blocked. "
            f"{outcome.describe()}"
        )
    else:  # pragma: no cover - NO_GATE surfaces are pinned structurally
        raise AssertionError(f"unhandled grade {grade!r}")


@pytest.mark.parametrize(
    "name,driver,policy_key,grade",
    [_row(*row) for row in TABLE],
)
def test_blocked_implies_not_executed(name, driver, policy_key, grade, captured):
    """A `blocked` record must mean the operation did not happen."""
    _init_with_deny(policy_key)
    assert_invariant(grade, driver(Spy(), captured))


def test_crewai_react_denial_records_not_evaluated_and_does_not_raise(captured):
    """The two halves of the CrewAI repair, pinned separately from the grade.

    Record half: a denied tool on the ReAct path must be recorded as
    ``not_evaluated`` naming the reason — the tool has already run when the
    step callback fires, so ``blocked`` would be a false record.

    Raise half: the callback must not raise. CrewAI's executor passes through
    only its own ``ToolExecutionFailedError`` and retries the whole task on
    anything else, so a raise here re-runs the already-executed tool's side
    effect — measured live at three writes for one denied call under the
    default ``max_retry_limit`` of 2.
    """
    _init_with_deny("agent_policy")
    outcome = _drive_crewai_step_callback_react(Spy(), captured)

    assert outcome.raised is None, (
        f"the step callback raised; CrewAI retries the task on this and "
        f"re-runs the denied tool: {outcome.describe()}"
    )

    not_evaluated = [
        e for e in outcome.events if e.get("action_taken") == "not_evaluated"
    ]
    assert not_evaluated, f"no not_evaluated record: {outcome.describe()}"
    event = not_evaluated[0]
    assert event.get("operation") == "crewai.agent.policy.tool_not_evaluated"

    telemetry = (event.get("metadata") or {}).get("obsvr_telemetry") or {}
    pne = telemetry.get("policy_not_evaluated") or {}
    assert pne.get("surface") == "crewai.step_callback"
    assert pne.get("gate") == "tool_gate"
    assert "after the tool has already run" in (pne.get("reason") or "")


def test_crewai_step_callback_defers_to_an_installed_gate_hook(captured, monkeypatch):
    """With the gate hook active, the hook is the tool-policy authority.

    The hook ruled on this call BEFORE it resolved — blocked or allowed — so
    the post-hoc callback adding ``not_evaluated`` about the same call would
    be a second, contradictory verdict. The step is still observed as a step;
    it is just not re-judged.
    """
    import obsvr.integrations.crewai as crewai_mod

    _init_with_deny("agent_policy")
    monkeypatch.setattr(crewai_mod, "_active_tool_gate_hooks", 1)
    outcome = _drive_crewai_step_callback_react(Spy(), captured)

    assert outcome.raised is None
    assert not any(
        e.get("action_taken") == "not_evaluated" for e in outcome.events
    ), outcome.describe()
    assert any(e.get("operation") == "crewai.step" for e in outcome.events)


def test_crewai_step_callback_defers_to_a_governed_tool(captured):
    """Same authority rule as the hook, for the wrapper: a name govern_tool
    owns gets its verdicts from the wrapper (blocked pre-execution, or an
    audited allowed call) — the post-hoc callback must not add
    ``not_evaluated`` about it."""
    from obsvr.integrations import tools as tools_mod

    _init_with_deny("agent_policy")
    tools_mod._GOVERNED_TOOL_NAMES.add(SPY_TOOL)
    outcome = _drive_crewai_step_callback_react(Spy(), captured)

    assert outcome.raised is None
    assert not any(
        e.get("action_taken") == "not_evaluated" for e in outcome.events
    ), outcome.describe()


def test_crewai_gate_hook_never_raises_and_fails_open(captured, monkeypatch):
    """The hook dispatcher swallows exceptions and RUNS the tool, so the only
    honest failure posture for the hook is an explicit allow. A context whose
    ``tool_name`` access explodes must yield None (allow), not a raise the
    dispatcher would silently convert into fail-open anyway."""
    from obsvr.integrations.crewai import make_tool_gate_hook

    _init_with_deny("agent_policy")

    class _ExplodingContext:
        @property
        def tool_name(self):
            raise RuntimeError("attacker-shaped context")

    hook = make_tool_gate_hook()
    assert hook(_ExplodingContext()) is None


def test_gate_hook_install_fails_loudly_without_the_hook_system(captured):
    """On a CrewAI build with no before_tool_call hook system the installer
    must refuse with a pointer at the wrapper — feature-detected by attribute
    presence, never version-compared, and never a silent no-op the caller
    would mistake for a gate. (crewai is not installed in this test env, so
    this IS the no-hook-system case.)"""
    from obsvr.integrations.crewai import install_tool_gate_hook

    with pytest.raises(ImportError, match="govern_tool"):
        install_tool_gate_hook()


def test_crewai_kickoff_callbacks_honour_the_replace_contract(sent):
    """Crew ASSIGNS each kickoff callback's return over what it passed in
    (``normalized = before_callback(normalized)``; ``result = after_callback(result)``).

    An observe-only callback returning None therefore discards the caller's
    inputs dict, or hands the caller None instead of their CrewOutput. Both
    directions are pinned, with and without a chained callback.
    """
    from obsvr.integrations.crewai import make_crew_callbacks

    obsvr.init(api_key="test", sample_rate=1)

    before_cb, after_cb = make_crew_callbacks()
    inputs = {"topic": "quarterly report"}
    result = object()  # stands in for CrewOutput
    assert before_cb(inputs) is inputs
    assert after_cb(result) is result

    # A chained observe-only callback (returns None) must not break the chain.
    seen = []
    before_cb, after_cb = make_crew_callbacks(
        existing_before=lambda i: seen.append(("before", i)),
        existing_after=lambda r: seen.append(("after", r)),
    )
    assert before_cb(inputs) is inputs
    assert after_cb(result) is result
    assert seen == [("before", inputs), ("after", result)]

    # A chained TRANSFORMING callback keeps its transformation.
    before_cb, after_cb = make_crew_callbacks(
        existing_before=lambda i: {**i, "extra": True},
    )
    assert before_cb(inputs) == {"topic": "quarterly report", "extra": True}


def test_autogen_gates_every_position_in_a_batched_message(captured):
    """A denied tool must be refused wherever it sits in ``tool_calls``.

    Position dependence is not a batching quirk — it is the gate reading one
    element of an array and the recipient running all of them. The control is
    the first-position case in the table above: that one already passes, so a
    failure here is about position and nothing else.
    """
    _init_with_deny("agent_policy")
    outcome = _drive_autogen(Spy(), captured, tool_names=(BENIGN_TOOL, SPY_TOOL))
    assert_invariant(ENFORCES, outcome)


def test_langchain_lets_a_tool_the_policy_does_not_name_through(captured):
    """The control for the row above, and the reason it means anything.

    A gate that refused everything would satisfy the ENFORCES row completely.
    This drives the same pre-execution hook with the deny list naming a different
    tool: the spy must run, and no event may claim a refusal.
    """
    obsvr.init(
        api_key="test", sample_rate=1,
        agent_policy={"denied_tools": ["something_else"]},
    )
    outcome = _drive_langchain_callbacks(Spy(), captured)

    assert outcome.spy.entries == [SPY_TOOL]
    assert not any(e.get("action_taken") == "blocked" for e in outcome.events)


def test_langchain_does_not_gate_the_same_tool_twice(captured):
    """One gate per tool, whichever callback the runtime delivers.

    Both pre-tool callbacks reach the same gate. A runtime that delivered both
    would otherwise charge the tool two steps and audit it twice, and the step
    budget is the control that would silently drift.
    """
    obsvr.init(api_key="test", sample_rate=1, agent_policy={"max_steps": 5})
    from obsvr.integrations.langchain import ObsvrCallbackHandler

    handler = ObsvrCallbackHandler()
    handler.on_chain_start(
        {"id": ["langchain", "agents", "agent", "AgentExecutor"]},
        {"input": "go"},
        run_id="run-dup-1",
    )

    class _Action:
        tool = SPY_TOOL
        tool_input = {"amount": 1}

    handler.on_agent_action(_Action(), run_id="tool-dup-1", parent_run_id="run-dup-1")
    handler.on_tool_start(
        {"name": SPY_TOOL}, '{"amount": 1}',
        run_id="tool-dup-1", parent_run_id="run-dup-1",
    )

    calls = [e for e in captured if e["operation"] == "langchain.tool.call"]
    assert len(calls) == 1, (
        f"the tool was gated {len(calls)} times; both pre-tool callbacks reached "
        f"the gate for one tool invocation"
    )


def test_the_table_covers_every_surface_that_has_a_tool_gate():
    """Completeness is a property here, not a convention.

    A new integration that ships a tool gate and is never added to the table
    would leave this invariant reporting green about a surface it has never
    driven — the same "we have a check for that" gap that let the two false
    records through. So the table is checked against the tree: every module
    carrying a tool-policy helper must appear above, graded.
    """
    import pathlib

    integrations = pathlib.Path(__file__).resolve().parents[1] / "obsvr" / "integrations"
    gated = set()
    for path in sorted(integrations.glob("*.py")):
        if path.stem.startswith("_"):
            continue
        text = path.read_text(encoding="utf-8")
        if "def _check_tool(" in text or "def _check_tool_policy(" in text:
            gated.add(path.stem)

    # A `surface:variant` row is a second driver for the same module — one
    # gate, another delivery shape — so it grades its base surface.
    graded = {row[0].split(":")[0] for row in TABLE}
    missing = gated - graded
    assert not missing, (
        f"these surfaces carry a tool gate but are not graded in the "
        f"invariant table: {sorted(missing)} — add a driver that models the "
        f"framework's real invocation ordering, then grade it"
    )

    stale = graded - gated
    assert not stale, (
        f"these surfaces are graded but no longer carry a tool gate: "
        f"{sorted(stale)} — if the gate was removed, the grade and the "
        f"documentation both have to move"
    )


def test_llamaindex_has_no_tool_gate_and_says_so():
    """NO_GATE, pinned structurally so it cannot become a silent regression.

    There is no tool-invocation boundary in this handler to gate on, so there is
    nothing to drive. What is pinned instead is the absence itself: if a tool
    policy helper appears in this module, this surface has been regraded and the
    documentation that calls it observability-only has to move with it.
    """
    import obsvr.integrations.llamaindex as llamaindex

    assert not hasattr(llamaindex, "_check_tool"), (
        "a tool gate appeared in the observability-only handler — regrade it "
        "in the table above, in COMPATIBILITY.md, and in both READMEs"
    )


# ── Non-vacuity ──────────────────────────────────────────────────────────────
#
# A green invariant that cannot go red is the exact failure this plan keeps
# finding. These two tests point a gate at a no-op and require the assertion to
# break, so the check is proven able to fail on every run rather than once, by
# hand, on the day it was written.


def test_invariant_catches_a_disarmed_gate(captured, monkeypatch):
    """Neuter an ENFORCES gate; the assertion must notice the tool ran."""
    import obsvr.integrations.pydantic_ai as pydantic_ai

    monkeypatch.setattr(pydantic_ai, "_check_tool", lambda name, policy: (True, ""))
    _init_with_deny("agent_policy")
    outcome = _drive_pydantic_ai(Spy(), captured)

    assert outcome.spy.entered, "the disarmed gate should have let the tool run"
    with pytest.raises(AssertionError, match="let the denied tool run"):
        assert_invariant(ENFORCES, outcome)


def test_invariant_catches_a_fabricated_denial():
    """A record claiming `blocked` about a tool that ran must fail RECORDS_ONLY.

    Built by hand rather than by driving an integration, so the assertion is
    tested against the exact shape it exists to reject even if no integration
    currently produces it.
    """
    spy = Spy()
    spy.enter(SPY_TOOL)
    fabricated = Outcome(spy, [{"action_taken": "blocked", "operation": "x.tool"}])

    with pytest.raises(AssertionError, match="THE LIE"):
        assert_invariant(RECORDS_ONLY, fabricated)
    with pytest.raises(AssertionError, match="THE LIE"):
        assert_invariant(INERT, fabricated)


def test_invariant_catches_a_silent_refusal():
    """Refusing without recording is also a failure, not a pass.

    The inverse of the fabricated denial: the operation was stopped and the
    trail says nothing. Every `blocked_call` filter misses it, so an operator
    reviewing refusals never learns it happened.
    """
    silent = Outcome(Spy(), [])
    with pytest.raises(AssertionError, match="no record claims blocked"):
        assert_invariant(ENFORCES, silent)
