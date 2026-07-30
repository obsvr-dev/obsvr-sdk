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

    graded = {row[0] for row in TABLE}
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
