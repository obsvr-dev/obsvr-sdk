"""The openai-agents pre-execution tool gate: the guardrail mechanism.

The tracing processor on this surface records and cannot refuse
(``test_openai_agents_tool_policy.py`` pins that half). Refusal lives in
``attach_tool_gate``: obsvr's ``ToolInputGuardrail`` appended to each function
tool's own ``tool_input_guardrails``, which the executor consults BEFORE
invoking the tool. A denied tool is refused by the guardrail contract's
``reject_content`` sentinel — the model receives the block message as the
tool's result and the run continues — and the record is ``blocked``,
true at the point it is written.

The framework surface is stubbed at the exact contract read off the installed
package (0.19.2, byte-identical guardrail semantics at 0.4.0): sdk-python's
venv carries no frameworks by design. The live proof lives in the integration
harness, not here.
"""

import sys
import types
import weakref

import pytest

import obsvr


TOOL = "gate_probe_tool"


@pytest.fixture(autouse=True)
def _fresh_governed_names(monkeypatch):
    """attach_tool_gate registers governed names process-wide (the tracing
    processor defers to them); tests must not inherit each other's registry."""
    from obsvr.integrations import tools as tools_mod

    monkeypatch.setattr(tools_mod, "_GOVERNED_TOOL_NAMES", set())


class _ToolGuardrailFunctionOutput:
    def __init__(self, output_info=None, behavior=None):
        self.output_info = output_info
        self.behavior = behavior or {"type": "allow"}

    @classmethod
    def allow(cls, output_info=None):
        return cls(output_info, {"type": "allow"})

    @classmethod
    def reject_content(cls, message, output_info=None):
        return cls(output_info, {"type": "reject_content", "message": message})


class _ToolInputGuardrail:
    def __init__(self, guardrail_function, name=None):
        self.guardrail_function = guardrail_function
        self.name = name


def _stub_agents(monkeypatch, with_dispatch=True):
    """The two framework halves the factory feature-detects, stubbed at the
    contract read off the installed package. ``with_dispatch=False`` models
    the trap CrewAI actually shipped: guardrail TYPES present, executor
    consult site absent — a gate accepted there is never asked."""
    tg = types.ModuleType("agents.tool_guardrails")
    tg.ToolGuardrailFunctionOutput = _ToolGuardrailFunctionOutput
    tg.ToolInputGuardrail = _ToolInputGuardrail

    te = types.ModuleType("agents.run_internal.tool_execution")
    if with_dispatch:
        async def _execute_tool_input_guardrails(**kwargs):  # pragma: no cover
            return None

        te._execute_tool_input_guardrails = _execute_tool_input_guardrails

    run_internal = types.ModuleType("agents.run_internal")
    run_internal.tool_execution = te

    agents_mod = types.ModuleType("agents")
    agents_mod.tool_guardrails = tg
    agents_mod.run_internal = run_internal

    monkeypatch.setitem(sys.modules, "agents", agents_mod)
    monkeypatch.setitem(sys.modules, "agents.tool_guardrails", tg)
    monkeypatch.setitem(sys.modules, "agents.run_internal", run_internal)
    monkeypatch.setitem(sys.modules, "agents.run_internal.tool_execution", te)


def _guardrail_data(tool_name=TOOL):
    return types.SimpleNamespace(
        context=types.SimpleNamespace(tool_name=tool_name, tool_call_id="call-1"),
        agent=None,
    )


def _make_guardrail(monkeypatch, **stub_kwargs):
    _stub_agents(monkeypatch, **stub_kwargs)
    from obsvr.integrations.openai_agents import make_tool_gate_guardrail

    return make_tool_gate_guardrail()


# ── The guardrail function ──────────────────────────────────────────────────


def test_a_denied_tool_is_rejected_with_a_blocked_record(sent, monkeypatch):
    obsvr.init(api_key="test", sample_rate=1,
               agent_policy={"denied_tools": [TOOL]})
    guardrail = _make_guardrail(monkeypatch)

    out = guardrail.guardrail_function(_guardrail_data())

    assert out.behavior["type"] == "reject_content"
    assert TOOL in out.behavior["message"]
    assert "tool_denied" in out.behavior["message"]

    blocked = [e for e in sent if e.get("action_taken") == "blocked"]
    assert len(blocked) == 1
    event = blocked[0]
    assert event["operation"] == "openai_agents.agent.policy.tool_blocked"
    assert event["reason_code"] == "TOOL_DENIED"
    assert event["metadata"]["tool_name"] == TOOL
    assert event["metadata"]["reason"] == "tool_denied"
    assert event["metadata"]["tool_call_id"] == "call-1"


def test_an_allowlist_miss_is_rejected_too(sent, monkeypatch):
    obsvr.init(api_key="test", sample_rate=1,
               agent_policy={"allowed_tools": ["some_other_tool"]})
    guardrail = _make_guardrail(monkeypatch)

    out = guardrail.guardrail_function(_guardrail_data())

    assert out.behavior["type"] == "reject_content"
    assert "tool_not_in_allowlist" in out.behavior["message"]


def test_a_permitted_tool_is_allowed_with_no_verdict(sent, monkeypatch):
    """The control: a gate that rejects everything passes the deny tests."""
    obsvr.init(api_key="test", sample_rate=1,
               agent_policy={"denied_tools": ["something_else"]})
    guardrail = _make_guardrail(monkeypatch)

    out = guardrail.guardrail_function(_guardrail_data())

    assert out.behavior["type"] == "allow"
    assert not [e for e in sent if e.get("action_taken") == "blocked"]


def test_an_internal_failure_never_raises_and_follows_fail_mode(monkeypatch, sent):
    """A raise from a guardrail is converted to ``UserError`` by the executor
    and ABORTS THE CALLER'S WHOLE RUN — an obsvr defect must not become the
    host's outage. Default fail_mode allows with this layer lost; "closed"
    refuses through the same sentinel the policy path uses."""

    class _Poisoned:
        @property
        def context(self):
            raise RuntimeError("detector imploded")

        agent = None

    obsvr.init(api_key="test", sample_rate=1,
               agent_policy={"denied_tools": [TOOL]})
    guardrail = _make_guardrail(monkeypatch)
    out = guardrail.guardrail_function(_Poisoned())
    assert out.behavior["type"] == "allow"

    obsvr.init(api_key="test", sample_rate=1, fail_mode="closed",
               agent_policy={"denied_tools": [TOOL]})
    out = guardrail.guardrail_function(_Poisoned())
    assert out.behavior["type"] == "reject_content"
    assert "fail_mode=closed" in out.behavior["message"]


# ── Feature detection ───────────────────────────────────────────────────────


def test_the_factory_refuses_loudly_without_the_framework(monkeypatch):
    """No silent no-op installs: a gate the caller believes in and does not
    have is the failure mode, not the missing framework."""
    monkeypatch.setitem(sys.modules, "agents", None)
    monkeypatch.setitem(sys.modules, "agents.tool_guardrails", None)
    from obsvr.integrations.openai_agents import make_tool_gate_guardrail

    with pytest.raises(ImportError, match="govern_tool"):
        make_tool_gate_guardrail()


def test_the_factory_requires_the_dispatch_half(monkeypatch):
    """Guardrail TYPES present, executor consult site absent — the shape
    CrewAI shipped for seven releases. A gate accepted there is never asked,
    so the install must refuse rather than arm a no-op."""
    with pytest.raises(ImportError, match="never consults"):
        _make_guardrail(monkeypatch, with_dispatch=False)


# ── attach_tool_gate ────────────────────────────────────────────────────────


class _FunctionTool:
    def __init__(self, name):
        self.name = name
        self.description = "d"
        self.tool_input_guardrails = None

    async def on_invoke_tool(self, ctx, args):  # pragma: no cover - never run
        return "x"


class _HostedTool:
    """No guardrail field, no client-side callable — nothing to bind."""

    def __init__(self, name):
        self.name = name


class _Agent:
    def __init__(self, tools, handoffs=()):
        self.tools = list(tools)
        self.handoffs = list(handoffs)


class _Handoff:
    """The ``handoff()`` object shape: target reachable only via weakref."""

    def __init__(self, agent):
        self._agent_ref = weakref.ref(agent)


def test_init_auto_gates_future_agent_construction(monkeypatch, sent):
    from obsvr import auto

    _stub_agents(monkeypatch)
    agents_mod = sys.modules["agents"]
    agent_mod = types.ModuleType("agents.agent")
    agents_mod.Agent = _Agent
    agents_mod.agent = agent_mod
    agent_mod.Agent = _Agent
    monkeypatch.setitem(sys.modules, "agents.agent", agent_mod)
    monkeypatch.setattr(auto, "_module_available", lambda name: name == "agents")
    monkeypatch.setattr(auto, "_wire_providers", lambda: [])

    obsvr.init(
        api_key="test",
        sample_rate=1,
        agent_policy={"denied_tools": [TOOL]},
        auto=True,
    )
    tool = _FunctionTool(TOOL)
    agent = agents_mod.Agent(tools=[tool])
    guardrail = tool.tool_input_guardrails[0]

    executions = []
    verdict = guardrail.guardrail_function(_guardrail_data())
    if verdict.behavior["type"] == "allow":
        executions.append(TOOL)

    assert agents_mod.Agent is agent_mod.Agent
    assert agents_mod.Agent is not _Agent
    assert executions == [], "a denied auto-gated Agents tool entered its body"
    assert any(
        event["operation"] == "openai_agents.agent.policy.tool_blocked"
        for event in sent
    )


def test_init_auto_does_not_replace_agent_when_dispatch_is_missing(monkeypatch):
    from obsvr import auto

    _stub_agents(monkeypatch, with_dispatch=False)
    agents_mod = sys.modules["agents"]
    agent_mod = types.ModuleType("agents.agent")
    agents_mod.Agent = _Agent
    agents_mod.agent = agent_mod
    agent_mod.Agent = _Agent
    monkeypatch.setitem(sys.modules, "agents.agent", agent_mod)
    monkeypatch.setattr(auto, "_module_available", lambda name: name == "agents")
    monkeypatch.setattr(auto, "_wire_providers", lambda: [])

    report = auto.enable_auto_instrumentation()

    assert agents_mod.Agent is _Agent
    assert agent_mod.Agent is _Agent
    assert "openai-agents:tool-gate" not in report["wired"]


def test_attach_gates_tools_and_handoff_targets_and_detaches(monkeypatch, sent):
    from obsvr.integrations.openai_agents import attach_tool_gate
    from obsvr.integrations.tools import is_tool_governed

    _stub_agents(monkeypatch)
    obsvr.init(api_key="test", sample_rate=1)
    worker_tool = _FunctionTool("worker_probe_tool")
    worker = _Agent(tools=[worker_tool])
    hosted = _HostedTool("hosted_probe_tool")
    triage_tool = _FunctionTool(TOOL)
    triage = _Agent(tools=[triage_tool, hosted], handoffs=[_Handoff(worker)])
    # A cycle must terminate, not recurse forever.
    worker.handoffs = [triage]

    detach = attach_tool_gate(triage)

    assert len(triage_tool.tool_input_guardrails) == 1
    assert len(worker_tool.tool_input_guardrails) == 1
    assert not hasattr(hosted, "tool_input_guardrails")
    assert is_tool_governed(TOOL)
    assert is_tool_governed("worker_probe_tool")
    assert not is_tool_governed("hosted_probe_tool")

    # Idempotent: a second attach adds nothing.
    detach_again = attach_tool_gate(triage)
    assert len(triage_tool.tool_input_guardrails) == 1

    detach()
    detach()  # idempotent handle
    detach_again()
    assert triage_tool.tool_input_guardrails is None
    assert worker_tool.tool_input_guardrails is None


def test_attach_leaves_a_callers_own_guardrails_in_place(monkeypatch):
    from obsvr.integrations.openai_agents import attach_tool_gate

    _stub_agents(monkeypatch)
    obsvr.init(api_key="test", sample_rate=1)
    tool = _FunctionTool(TOOL)
    theirs = _ToolInputGuardrail(lambda data: None, name="their_gate")
    tool.tool_input_guardrails = [theirs]

    detach = attach_tool_gate(_Agent(tools=[tool]))
    assert [g.name for g in tool.tool_input_guardrails] == [
        "their_gate", "obsvr_tool_gate",
    ]

    detach()
    assert tool.tool_input_guardrails == [theirs]
