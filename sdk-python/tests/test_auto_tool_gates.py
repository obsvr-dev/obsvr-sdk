"""Startup auto-governance reaches genuine framework tool boundaries.

These tests model the public hook/executor contracts without importing the
large optional frameworks into the base unit-test environment. The versioned
integration harness drives the same installers against the real packages.
The side-effect counter is the oracle: a denial only passes when the tool body
is never entered.
"""

from __future__ import annotations

import json
import sys
import types

import obsvr
from obsvr import auto


def _only(*available: str):
    names = set(available)
    return lambda name: name in names


def _disable_provider_wiring(monkeypatch) -> None:
    monkeypatch.setattr(auto, "_wire_providers", lambda: [])


def test_init_installs_crewai_pre_tool_gate(monkeypatch, sent):
    hooks = []

    crewai = types.ModuleType("crewai")
    crewai_hooks = types.ModuleType("crewai.hooks")
    tool_hooks = types.ModuleType("crewai.hooks.tool_hooks")
    crewai_utilities = types.ModuleType("crewai.utilities")
    tool_utils = types.ModuleType("crewai.utilities.tool_utils")

    def register(hook):
        hooks.append(hook)

    def unregister(hook):
        if hook in hooks:
            hooks.remove(hook)

    def run_before_tool_call_hooks(context):
        return all(hook(context) is not False for hook in list(hooks))

    tool_hooks.register_before_tool_call_hook = register
    tool_hooks.unregister_before_tool_call_hook = unregister
    tool_utils.run_before_tool_call_hooks = run_before_tool_call_hooks
    crewai_hooks.tool_hooks = tool_hooks
    crewai_utilities.tool_utils = tool_utils
    crewai.hooks = crewai_hooks
    crewai.utilities = crewai_utilities

    for name, module in {
        "crewai": crewai,
        "crewai.hooks": crewai_hooks,
        "crewai.hooks.tool_hooks": tool_hooks,
        "crewai.utilities": crewai_utilities,
        "crewai.utilities.tool_utils": tool_utils,
    }.items():
        monkeypatch.setitem(sys.modules, name, module)

    _disable_provider_wiring(monkeypatch)
    monkeypatch.setattr(auto, "_module_available", _only("crewai"))
    obsvr.init(
        api_key="test",
        sample_rate=1,
        agent_policy={"denied_tools": ["send_contract"]},
        auto=True,
    )

    class Context:
        tool_name = "send_contract"
        tool_input = {"recipient": "external@example.com"}
        agent = None

    executions = []
    if run_before_tool_call_hooks(Context()):
        executions.append("sent")

    assert len(hooks) == 1
    assert executions == [], "CrewAI entered a tool body denied during init"
    assert any(
        event["operation"] == "crewai.agent.policy.tool_blocked" for event in sent
    )


def test_init_installs_autogen_pre_tool_gate(monkeypatch, sent):
    class ConversableAgent:
        def __init__(self, function_map=None):
            self._function_map = dict(function_map or {})

        def execute_function(self, func_call, call_id=None, verbose=False):
            name = func_call.get("name", "")
            function = self._function_map.get(name)
            if function is None:
                return False, {"name": name, "content": "not found"}
            try:
                value = function(**json.loads(func_call.get("arguments", "{}")))
                return True, {"name": name, "content": value}
            except Exception as exc:  # upstream returns a failed-tool result
                return False, {"name": name, "content": f"Error: {exc}"}

        async def a_execute_function(self, func_call, call_id=None, verbose=False):
            return self.execute_function(func_call, call_id, verbose)

    autogen = types.ModuleType("autogen")
    autogen.ConversableAgent = ConversableAgent
    monkeypatch.setitem(sys.modules, "autogen", autogen)

    _disable_provider_wiring(monkeypatch)
    monkeypatch.setattr(auto, "_module_available", _only("autogen"))
    obsvr.init(
        api_key="test",
        sample_rate=1,
        agent_policy={"denied_tools": ["send_contract"]},
        auto=True,
    )

    executions = []

    def send_contract(recipient=""):
        executions.append(recipient)
        return "sent"

    agent = ConversableAgent({"send_contract": send_contract})
    ok, result = agent.execute_function(
        {
            "name": "send_contract",
            "arguments": json.dumps({"recipient": "external@example.com"}),
        }
    )

    assert ok is False
    assert "[obsvr]" in result["content"]
    assert executions == [], "AutoGen entered a tool body denied during init"
    assert any(event["operation"] == "tool.policy.tool_blocked" for event in sent)
