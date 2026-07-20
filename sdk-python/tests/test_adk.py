"""Tests for the Google ADK integration.

ADK is not installed; a fake tool/context duck-types the ADK callback contract.
The behavior tests prove that a block short-circuits execution the way ADK
actually treats callback return values (dict result for tools => tool skipped).
"""
import pytest

import obsvr
from obsvr.integrations.adk import (
    make_before_agent_callback,
    make_before_model_callback,
    make_before_tool_callback,
)


class FakeTool:
    def __init__(self, name):
        self.name = name
        self.ran = False

    def forward(self, **kwargs):
        self.ran = True
        return {"ok": True}


class FakePart:
    def __init__(self, text):
        self.text = text


class FakeContentReq:
    def __init__(self, text, role="user"):
        self.role = role
        self.parts = [FakePart(text)]


class FakeLlmRequest:
    def __init__(self, text, role="user"):
        self.contents = [FakeContentReq(text, role)]


def _init(**extra):
    extra.setdefault("policy_refresh_interval_s", 0)
    obsvr.init(api_key="k", ingest_url="http://localhost:9", **extra)


def _adk_run_tool(cb, tool, args, ctx=None):
    """Simulate ADK's contract: a non-None callback return SKIPS the tool."""
    result = cb(tool, args, ctx)
    if result is not None:
        return result
    return tool.forward(**args)


# ── before_tool_callback ─────────────────────────────────────────────────────

def test_allowed_tool_runs(sent):
    _init()
    cb = make_before_tool_callback()
    tool = FakeTool("read_file")
    out = _adk_run_tool(cb, tool, {"path": "/x"})
    assert tool.ran is True
    assert out == {"ok": True}


def test_denied_tool_blocked_and_skipped(sent):
    _init(agent_policy={"denied_tools": ["delete_database"]})
    cb = make_before_tool_callback()
    tool = FakeTool("delete_database")
    out = _adk_run_tool(cb, tool, {})
    assert tool.ran is False  # tool body never executed
    assert out["obsvr_blocked"] is True
    assert sent[0]["operation"] == "adk.tool.policy.tool_blocked"


def test_pii_in_tool_args_blocked_and_skipped(sent):
    _init(pii_policy={"rules": {"ssn": "block"}})
    cb = make_before_tool_callback()
    tool = FakeTool("send_email")
    out = _adk_run_tool(cb, tool, {"body": "ssn 123-45-6789"})
    assert tool.ran is False
    assert out["obsvr_blocked"] is True


# ── before_model_callback ────────────────────────────────────────────────────

def test_model_request_allowed(sent):
    _init()
    cb = make_before_model_callback()
    assert cb(None, FakeLlmRequest("hello")) is None


def test_model_request_blocked_short_circuits(sent):
    _init(on_pre_call=lambda e: "block")
    cb = make_before_model_callback()
    out = cb(None, FakeLlmRequest("secret plan"))
    assert out is not None  # non-None short-circuits the model call in ADK
    assert sent[0]["event_type"] == "blocked_call"


# ── before_agent_callback ────────────────────────────────────────────────────

def test_agent_callback_emits_start_and_never_skips(sent):
    _init()
    cb = make_before_agent_callback()
    assert cb(None) is None
    assert sent[0]["operation"] == "adk.agent.run.start"
