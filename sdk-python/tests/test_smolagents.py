"""Tests for the smolagents integration.

smolagents is not installed; a fake Tool duck-types the smolagents Tool call
path (``tool(**kwargs)`` -> ``forward``). The behavior tests prove a block
raises before the wrapped tool executes.
"""
import pytest

import obsvr
from obsvr.integrations.smolagents import (
    ObsvrGovernedTool,
    SmolagentsToolBlockedError,
    govern_agent,
    govern_tool,
)


class FakeTool:
    def __init__(self, name):
        self.name = name
        self.description = f"tool {name}"
        self.inputs = {"q": {"type": "string"}}
        self.output_type = "string"
        self.ran = False

    def forward(self, **kwargs):
        self.ran = True
        return f"result of {self.name}"

    def __call__(self, *args, **kwargs):
        return self.forward(*args, **kwargs)


class FakeAgent:
    def __init__(self, tools):
        self.tools = {t.name: t for t in tools}


def _init(**extra):
    extra.setdefault("policy_refresh_interval_s", 0)
    obsvr.init(api_key="k", ingest_url="http://localhost:9", **extra)


def test_allowed_tool_runs_and_audits(sent):
    _init()
    tool = FakeTool("web_search")
    governed = govern_tool(tool)
    out = governed(q="cats")
    assert out == "result of web_search"
    assert tool.ran is True
    assert sent[0]["operation"] == "smolagents.tool.call"


def test_denied_tool_blocked_before_execution(sent):
    _init(agent_policy={"denied_tools": ["python_interpreter"]})
    tool = FakeTool("python_interpreter")
    governed = govern_tool(tool)
    with pytest.raises(SmolagentsToolBlockedError):
        governed(q="import os; os.system('rm -rf /')")
    assert tool.ran is False  # never executed
    assert sent[0]["operation"] == "smolagents.tool.policy.tool_blocked"


def test_pii_in_args_blocked(sent):
    _init(pii_policy={"rules": {"ssn": "block"}})
    tool = FakeTool("lookup")
    governed = govern_tool(tool)
    with pytest.raises(SmolagentsToolBlockedError):
        governed(q="ssn 123-45-6789")
    assert tool.ran is False


def test_metadata_mirrored(sent):
    _init()
    tool = FakeTool("calc")
    governed = govern_tool(tool)
    assert governed.name == "calc"
    assert governed.output_type == "string"
    assert isinstance(governed, ObsvrGovernedTool)


def test_govern_agent_wraps_all_tools(sent):
    _init(agent_policy={"denied_tools": ["danger"]})
    safe, danger = FakeTool("safe"), FakeTool("danger")
    agent = FakeAgent([safe, danger])
    govern_agent(agent)
    assert isinstance(agent.tools["safe"], ObsvrGovernedTool)
    with pytest.raises(SmolagentsToolBlockedError):
        agent.tools["danger"](q="x")
    assert danger.ran is False


def test_govern_tool_idempotent(sent):
    _init()
    tool = FakeTool("x")
    once = govern_tool(tool)
    assert govern_tool(once) is once
