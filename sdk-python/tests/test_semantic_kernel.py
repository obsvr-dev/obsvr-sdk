"""Tests for the Semantic Kernel (SK) integration.

SK is not installed; a fake FunctionInvocationContext + next duck-type the
filter contract. The behavior tests prove a block prevents ``next`` from being
called — so the kernel function never executes.
"""
import asyncio

import pytest

import obsvr
from obsvr.integrations.semantic_kernel import (
    make_function_invocation_filter,
    obsvr_function_invocation_filter,
)


class FakeFunction:
    def __init__(self, name):
        self.name = name
        self.plugin_name = "plugin"


class FakeContext:
    def __init__(self, name, arguments):
        self.function = FakeFunction(name)
        self.arguments = dict(arguments)
        self.result = None


class Recorder:
    def __init__(self):
        self.called = False

    async def __call__(self, context):
        self.called = True
        context.result = "executed"


def _init(**extra):
    extra.setdefault("policy_refresh_interval_s", 0)
    obsvr.init(api_key="k", ingest_url="http://localhost:9", **extra)


def _run(coro):
    return asyncio.run(coro)


def test_allowed_function_calls_next(sent):
    _init()
    ctx = FakeContext("search", {"q": "cats"})
    nxt = Recorder()
    _run(obsvr_function_invocation_filter(ctx, nxt))
    assert nxt.called is True
    assert ctx.result == "executed"


def test_denied_function_blocked(sent):
    _init(agent_policy={"denied_tools": ["delete_records"]})
    ctx = FakeContext("delete_records", {})
    nxt = Recorder()
    _run(obsvr_function_invocation_filter(ctx, nxt))
    assert nxt.called is False  # kernel function never runs
    assert ctx.result is not None
    assert sent[0]["operation"] == "semantic_kernel.function.policy.tool_blocked"


def test_pii_in_arguments_blocked(sent):
    _init(pii_policy={"rules": {"ssn": "block"}})
    ctx = FakeContext("lookup", {"ssn": "123-45-6789"})
    nxt = Recorder()
    _run(obsvr_function_invocation_filter(ctx, nxt))
    assert nxt.called is False


def test_hook_block_prevents_next(sent):
    _init(on_pre_call=lambda e: "block")
    ctx = FakeContext("anything", {"x": 1})
    nxt = Recorder()
    _run(make_function_invocation_filter(user_id="alice")(ctx, nxt))
    assert nxt.called is False
