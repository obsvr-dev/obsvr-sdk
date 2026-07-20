"""Tests for the Microsoft Agent Framework (MAF) integration.

MAF is not installed; a fake AgentRunContext + next duck-type the middleware
contract. The behavior tests prove a block terminates the run (context.terminate
set, next() never awaited) — the real MiddlewareTermination mechanism.
"""
import asyncio

import pytest

import obsvr
from obsvr.integrations.agent_framework import (
    ObsvrAgentMiddleware,
    make_agent_middleware,
    obsvr_agent_middleware,
)


class FakeMessage:
    def __init__(self, text, role="user"):
        self.text = text
        self.role = role


class FakeContext:
    def __init__(self, messages):
        self.messages = messages
        self.terminate = False
        self.result = None


class Recorder:
    def __init__(self):
        self.called = False

    async def __call__(self, context):
        self.called = True


def _init(**extra):
    extra.setdefault("policy_refresh_interval_s", 0)
    obsvr.init(api_key="k", ingest_url="http://localhost:9", **extra)


def _run(coro):
    return asyncio.run(coro)


def test_allowed_run_calls_next(sent):
    _init()
    ctx = FakeContext([FakeMessage("hello there")])
    nxt = Recorder()
    _run(obsvr_agent_middleware(ctx, nxt))
    assert nxt.called is True
    assert ctx.terminate is False


def test_pii_block_terminates_run(sent):
    _init(pii_policy={"rules": {"ssn": "block"}})
    ctx = FakeContext([FakeMessage("my ssn is 123-45-6789")])
    nxt = Recorder()
    _run(obsvr_agent_middleware(ctx, nxt))
    assert nxt.called is False  # agent never runs
    assert ctx.terminate is True
    assert ctx.result is not None
    assert sent[0]["event_type"] == "blocked_call"


def test_hook_block_terminates_run(sent):
    _init(on_pre_call=lambda e: "block")
    ctx = FakeContext([FakeMessage("do the thing")])
    nxt = Recorder()
    _run(make_agent_middleware(user_id="alice")(ctx, nxt))
    assert nxt.called is False
    assert ctx.terminate is True


def test_class_middleware_blocks(sent):
    _init(pii_policy={"rules": {"ssn": "block"}})
    ctx = FakeContext([FakeMessage("ssn 123-45-6789")])
    nxt = Recorder()
    mw = ObsvrAgentMiddleware()
    _run(mw.process(ctx, nxt))
    assert nxt.called is False
    assert ctx.terminate is True
