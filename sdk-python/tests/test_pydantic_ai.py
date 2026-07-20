"""Tests for the PydanticAI integration.

PydanticAI is not installed; ObsvrToolset falls back to a shim WrapperToolset
base. A fake wrapped toolset duck-types the ``call_tool`` seam. The behavior
tests prove a block raises before the wrapped toolset's ``call_tool`` runs.
"""
import asyncio

import pytest

import obsvr
from obsvr.integrations.pydantic_ai import ObsvrToolset, PydanticAIToolBlockedError


class FakeToolset:
    def __init__(self):
        self.calls = []

    async def call_tool(self, name, tool_args, *args, **kwargs):
        self.calls.append((name, tool_args))
        return f"ran {name}"

    async def get_tools(self, ctx=None):
        return {}


def _init(**extra):
    extra.setdefault("policy_refresh_interval_s", 0)
    obsvr.init(api_key="k", ingest_url="http://localhost:9", **extra)


def _run(coro):
    return asyncio.run(coro)


def test_allowed_tool_delegates(sent):
    _init()
    fake = FakeToolset()
    ts = ObsvrToolset(fake)
    out = _run(ts.call_tool("search", {"q": "cats"}, None, None))
    assert out == "ran search"
    assert fake.calls == [("search", {"q": "cats"})]


def test_denied_tool_blocked_before_delegation(sent):
    _init(agent_policy={"denied_tools": ["shell_exec"]})
    fake = FakeToolset()
    ts = ObsvrToolset(fake)
    with pytest.raises(PydanticAIToolBlockedError):
        _run(ts.call_tool("shell_exec", {"cmd": "rm -rf /"}, None, None))
    assert fake.calls == []  # wrapped toolset never reached
    assert sent[0]["operation"] == "pydantic_ai.tool.policy.tool_blocked"


def test_allowlist_blocks_unlisted_tool(sent):
    _init(agent_policy={"allowed_tools": ["search"]})
    fake = FakeToolset()
    ts = ObsvrToolset(fake)
    with pytest.raises(PydanticAIToolBlockedError):
        _run(ts.call_tool("delete", {}, None, None))
    assert fake.calls == []


def test_pii_in_args_blocked(sent):
    _init(pii_policy={"rules": {"ssn": "block"}})
    fake = FakeToolset()
    ts = ObsvrToolset(fake)
    with pytest.raises(PydanticAIToolBlockedError):
        _run(ts.call_tool("lookup", {"ssn": "123-45-6789"}, None, None))
    assert fake.calls == []


def test_inherited_methods_delegate(sent):
    _init()
    fake = FakeToolset()
    ts = ObsvrToolset(fake)
    # Non-overridden toolset methods forward to the wrapped toolset.
    assert _run(ts.get_tools()) == {}
