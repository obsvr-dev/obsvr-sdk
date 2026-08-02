"""AutoGen's pre-execution tool gate — the half the send hook cannot reach.

ag2 is not installed in this venv by design, so ``ConversableAgent`` is modelled
rather than imported. The model is taken from ag2 0.9.9 and holds at the 0.3.2
floor too; the two facts it depends on were re-read at both versions:

  * ``execute_function`` looks the name up in ``_function_map`` FRESH on every
    call rather than capturing the callable, which is what lets a gate govern a
    map entry at all;
  * it wraps the invocation in ``try/except Exception`` and reports
    ``is_exec_success=False`` with ``content=f"Error: {e}"``, which is how a
    refusal becomes the framework's own failed-tool result instead of an abort.

The live suite in the harness is what proves the model matches the framework.
"""

import asyncio
import json
import sys
import types

import pytest

import obsvr


TOOL = "send_money"
OTHER = "get_weather"


class _ConversableAgent:
    """The executor pair, and nothing else the gate touches."""

    def __init__(self, function_map=None):
        self._function_map = dict(function_map or {})

    def execute_function(self, func_call, call_id=None, verbose=False):
        name = func_call.get("name", "")
        func = self._function_map.get(name)
        if func is None:
            return False, {"name": name, "role": "function", "content": "not found"}
        try:
            content = func(**json.loads(func_call.get("arguments", "{}")))
            return True, {"name": name, "role": "function", "content": content}
        except Exception as exc:  # noqa: BLE001 - upstream swallows here
            return False, {"name": name, "role": "function", "content": f"Error: {exc}"}

    async def a_execute_function(self, func_call, call_id=None, verbose=False):
        return self.execute_function(func_call, call_id, verbose)


def _call(name=TOOL, **kwargs):
    return {"name": name, "arguments": json.dumps(kwargs or {"amount": 7})}


@pytest.fixture
def ag2(monkeypatch):
    """A stub ``autogen`` module exposing the class the gate patches."""
    stub = types.ModuleType("autogen")
    stub.ConversableAgent = _ConversableAgent
    monkeypatch.setitem(sys.modules, "autogen", stub)
    yield stub
    # The gate patches the CLASS, so a leaked install would contaminate the
    # next test in this file rather than fail visibly in it.
    detach = getattr(_ConversableAgent, "_obsvr_tool_gate_detach", None)
    if callable(detach):
        detach()


@pytest.fixture(autouse=True)
def _fresh_governed_names(monkeypatch):
    """``govern_tool`` records every wrapped NAME process-wide, and the audit
    rails on other surfaces consult that registry to avoid stamping a verdict
    beside a real gate's own. Leaking a name out of this file therefore silences
    another surface's ``not_evaluated`` record and fails a test that has nothing
    to do with AutoGen — which is exactly what it did before this fixture."""
    from obsvr.integrations import tools as tools_mod

    monkeypatch.setattr(tools_mod, "_GOVERNED_TOOL_NAMES", set())


@pytest.fixture
def calls():
    return []


def _tool(calls, name=TOOL):
    def body(amount=0):
        calls.append((name, amount))
        return f"SECRET sent {amount}"

    return body


def _deny(*names):
    obsvr.init(api_key="k", agent_policy={"denied_tools": list(names)})


def _allow():
    obsvr.init(api_key="k", agent_policy={})


def test_a_denied_tool_never_enters_its_body(ag2, sent, calls):
    from obsvr.integrations.autogen import install_tool_gate

    install_tool_gate()
    agent = _ConversableAgent({TOOL: _tool(calls)})
    _deny(TOOL)

    ok, result = agent.execute_function(_call())
    assert calls == [], "the denied tool's body ran"
    assert ok is False
    assert "[obsvr]" in result["content"], result
    assert any(e["operation"] == "tool.policy.tool_blocked" for e in sent)


def test_the_refusal_is_the_frameworks_failed_tool_contract_not_an_abort(ag2, sent, calls):
    """Nothing propagates to the caller: the conversation continues and the
    model is told the tool failed. That is the deliberate difference from the
    send hook, which raises out of ``send`` and stops the chat."""
    from obsvr.integrations.autogen import install_tool_gate

    install_tool_gate()
    agent = _ConversableAgent({TOOL: _tool(calls)})
    _deny(TOOL)

    ok, result = agent.execute_function(_call())  # must not raise
    assert (ok, result["role"]) == (False, "function")


def test_an_allowed_tool_runs_once_and_is_audited_once(ag2, sent, calls):
    from obsvr.integrations.autogen import install_tool_gate

    install_tool_gate()
    agent = _ConversableAgent({TOOL: _tool(calls)})
    _allow()

    ok, result = agent.execute_function(_call(amount=7))
    assert (ok, calls) == (True, [(TOOL, 7)])
    assert "SECRET sent 7" in result["content"]
    assert len([e for e in sent if e["operation"] == "tool.call"]) == 1


def test_repeated_dispatch_does_not_stack_a_gate_per_call(ag2, sent, calls):
    """The map entry is replaced in place, so without a marker the gate would
    add a layer on every dispatch and the audit would grow a record per layer."""
    from obsvr.integrations.autogen import install_tool_gate

    install_tool_gate()
    agent = _ConversableAgent({TOOL: _tool(calls)})
    _allow()

    for _ in range(3):
        agent.execute_function(_call(amount=1))

    assert len(calls) == 3
    assert len([e for e in sent if e["operation"] == "tool.call"]) == 3, (
        "three dispatches must yield three audit events, not six or twelve"
    )


def test_the_async_executor_is_gated_too(ag2, sent, calls):
    from obsvr.integrations.autogen import install_tool_gate

    install_tool_gate()
    agent = _ConversableAgent({TOOL: _tool(calls)})
    _deny(TOOL)

    ok, _ = asyncio.run(agent.a_execute_function(_call()))
    assert (ok, calls) == (False, [])


def test_a_tool_registered_after_the_install_is_still_governed(ag2, sent, calls):
    """``run()`` builds its executor and registers every callable on it AFTER
    the caller has installed anything. The map is read at call time, so the
    gate governs what it finds then rather than what existed at install."""
    from obsvr.integrations.autogen import install_tool_gate

    install_tool_gate()
    agent = _ConversableAgent()
    agent._function_map[TOOL] = _tool(calls)  # registered late
    _deny(TOOL)

    ok, _ = agent.execute_function(_call())
    assert (ok, calls) == (False, [])


def test_an_untouched_tool_is_left_alone(ag2, sent, calls):
    """Only the name being dispatched is governed, so a map full of tools does
    not get rewritten wholesale on the first call."""
    from obsvr.integrations.autogen import install_tool_gate

    install_tool_gate()
    original = _tool(calls, name=OTHER)
    agent = _ConversableAgent({TOOL: _tool(calls), OTHER: original})
    _allow()

    agent.execute_function(_call(TOOL, amount=1))
    assert agent._function_map[OTHER] is original


def test_install_is_idempotent(ag2, calls):
    from obsvr.integrations.autogen import install_tool_gate

    first = install_tool_gate()
    second = install_tool_gate()
    assert first is second, "a second install must not stack a second wrapper"


def test_uninstall_restores_the_class_and_every_map_entry(ag2, sent, calls):
    from obsvr.integrations.autogen import install_tool_gate

    original_sync = _ConversableAgent.execute_function
    original_fn = _tool(calls)
    agent = _ConversableAgent({TOOL: original_fn})

    detach = install_tool_gate()
    _deny(TOOL)
    agent.execute_function(_call())
    assert calls == []

    detach()
    detach()  # idempotent

    assert _ConversableAgent.execute_function is original_sync
    assert agent._function_map[TOOL] is original_fn
    ok, _ = agent.execute_function(_call(amount=7))
    assert (ok, calls) == (True, [(TOOL, 7)]), (
        "uninstalled: the gate must be gone, not merely quiet"
    )


def test_it_refuses_loudly_where_the_executors_are_absent(monkeypatch, calls):
    """The F-1b-2 lesson. ag2 1.0 deleted ConversableAgent outright; a build
    without the executors must produce a refusal, not a silent no-op install."""
    from obsvr.integrations.autogen import install_tool_gate

    class _NoExecutors:
        pass

    stub = types.ModuleType("autogen")
    stub.ConversableAgent = _NoExecutors
    monkeypatch.setitem(sys.modules, "autogen", stub)

    with pytest.raises(ImportError, match="govern_tool"):
        install_tool_gate()


def test_it_says_what_to_install_when_ag2_is_absent(monkeypatch):
    from obsvr.integrations.autogen import install_tool_gate

    monkeypatch.setitem(sys.modules, "autogen", None)
    with pytest.raises(ImportError, match="ag2"):
        install_tool_gate()
