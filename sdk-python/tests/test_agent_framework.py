"""Tests for the Microsoft Agent Framework (MAF) integration.

MAF is not installed here, so the fakes below duck-type its middleware contract.
That makes WHICH contract they encode the whole point of this file.

The previous version of these tests passed against fakes built to match obsvr's
assumptions rather than MAF's API: a one-argument ``next``, and a context with a
``terminate`` attribute. Neither exists. The real handler is zero-argument, and
``AgentContext`` has no ``terminate`` — writing one created an attribute nothing
reads. So the suite certified a integration that could not register with MAF at
any published version and would have raised TypeError on every allowed run.
Fakes are only as good as the contract they copy, and these now copy the
published one: ``call_next()`` takes no arguments, and a block is "return
without awaiting it".

The registration half — which is what actually raised, at agent construction —
cannot be checked with fakes at all, because it depends on MAF's own
``categorize_middleware`` reading the parameter annotation. It is asserted
structurally here (the annotation name is what MAF matches on) and verified
live against the installed package by the shape-audit probe.
"""
import asyncio
import inspect

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
    """AgentContext as MAF actually defines it: messages and a result slot.

    Deliberately NO ``terminate`` attribute — the real one has none, and giving
    the fake one is what let the old assertion pass.
    """

    def __init__(self, messages):
        self.messages = messages
        self.result = None


class Recorder:
    """MAF's next-handler: ZERO arguments."""

    def __init__(self):
        self.called = False

    async def __call__(self):
        self.called = True


def _init(**extra):
    extra.setdefault("policy_refresh_interval_s", 0)
    obsvr.init(api_key="k", ingest_url="http://localhost:9", **extra)


def _run(coro):
    return asyncio.run(coro)


# ── the registration contract ───────────────────────────────────────────────

def test_first_parameter_is_annotated_AgentContext():
    """MAF's categorize_middleware accepts a bare callable only when the first
    parameter's annotation is named AgentContext. Annotated Any — as it was —
    it raises at AGENT CONSTRUCTION, so no call is ever made and no test that
    invokes the middleware directly can see it."""
    for fn in (obsvr_agent_middleware, make_agent_middleware(user_id="a")):
        params = list(inspect.signature(fn).parameters.values())
        assert params[0].annotation.__name__ == "AgentContext", fn


def test_next_handler_takes_no_arguments():
    """Awaiting call_next(context) raises TypeError against the real handler,
    which is what made every ALLOWED run fail even after registration."""
    for fn in (obsvr_agent_middleware, make_agent_middleware()):
        params = list(inspect.signature(fn).parameters.values())
        assert len(params) == 2
        assert params[1].name == "call_next"


def test_class_middleware_is_not_callable_as_an_instance():
    """A __call__ passthrough makes the INSTANCE callable, which sent it down
    MAF's bare-callable classification path and produced an AttributeError
    about a missing __name__ instead of registering."""
    assert "__call__" not in vars(ObsvrAgentMiddleware)
    assert not callable(ObsvrAgentMiddleware())


# ── the governance behaviour ────────────────────────────────────────────────

def test_allowed_run_calls_next(sent):
    _init()
    ctx = FakeContext([FakeMessage("hello there")])
    nxt = Recorder()
    _run(obsvr_agent_middleware(ctx, nxt))
    assert nxt.called is True
    assert ctx.result is None


def test_pii_block_stops_the_run(sent):
    _init(pii_policy={"rules": {"ssn": "block"}})
    ctx = FakeContext([FakeMessage("my ssn is 123-45-6789")])
    nxt = Recorder()
    _run(obsvr_agent_middleware(ctx, nxt))
    # Not calling call_next IS the block: the agent never runs.
    assert nxt.called is False
    assert ctx.result is not None
    assert sent[0]["event_type"] == "blocked_call"


def test_hook_block_stops_the_run(sent):
    _init(on_pre_call=lambda e: "block")
    ctx = FakeContext([FakeMessage("do the thing")])
    nxt = Recorder()
    _run(make_agent_middleware(user_id="alice")(ctx, nxt))
    assert nxt.called is False
    assert ctx.result is not None


def test_class_middleware_blocks(sent):
    _init(pii_policy={"rules": {"ssn": "block"}})
    ctx = FakeContext([FakeMessage("ssn 123-45-6789")])
    nxt = Recorder()
    _run(ObsvrAgentMiddleware().process(ctx, nxt))
    assert nxt.called is False
    assert ctx.result is not None


def test_blocked_result_is_not_a_bare_dict_when_MAF_types_are_present(sent):
    """With MAF absent the fallback dict is correct. The point of the assertion
    is the shape of the FALLBACK, so a future MAF-present run is told apart."""
    _init(pii_policy={"rules": {"ssn": "block"}})
    ctx = FakeContext([FakeMessage("ssn 123-45-6789")])
    _run(obsvr_agent_middleware(ctx, Recorder()))
    from obsvr.integrations.agent_framework import _HAS_MAF

    if _HAS_MAF:
        assert not isinstance(ctx.result, dict)
    else:
        assert ctx.result == {
            "obsvr_blocked": True,
            "text": "[obsvr] Agent run blocked by policy",
        }


# ── the record describes the outcome, not the intention ─────────────────────
#
# The allowed-path event used to be emitted BEFORE call_next() with
# response="" hardcoded and no latency, so it asserted success before the
# outcome existed. A live agent run confirmed it: the agent returned "ok" and
# the event recorded an empty response with success true. These pin the repair.

class ResultRecorder:
    """A next-handler that behaves like a real agent: it leaves a result."""

    def __init__(self, text="the answer", boom=None):
        self.called = False
        self._text = text
        self._boom = boom
        self.ctx = None

    def bind(self, ctx):
        self.ctx = ctx
        return self

    async def __call__(self):
        self.called = True
        if self._boom:
            raise self._boom
        self.ctx.result = type(
            "FakeAgentResponse", (), {"messages": [FakeMessage(self._text, "assistant")]}
        )()


def test_allowed_run_records_the_agents_response(sent):
    _init()
    ctx = FakeContext([FakeMessage("hello there")])
    nxt = ResultRecorder("the answer").bind(ctx)
    _run(obsvr_agent_middleware(ctx, nxt))

    assert nxt.called is True
    ev = sent[-1]
    assert ev["operation"] == "agent_framework.agent.run"
    # The whole point: what came back is on the record.
    assert ev["response"] == "the answer"
    assert ev["success"] is True
    # Emitted after the run, so a duration exists to report.
    assert isinstance(ev.get("latency_ms"), int)


def test_a_run_that_raises_is_not_recorded_as_a_success(sent):
    _init()
    ctx = FakeContext([FakeMessage("hello there")])
    boom = RuntimeError("provider exploded")
    nxt = ResultRecorder(boom=boom).bind(ctx)

    # The exception still reaches the caller — obsvr reports the outcome, it
    # does not swallow it.
    try:
        _run(obsvr_agent_middleware(ctx, nxt))
        raise AssertionError("the middleware swallowed the agent's exception")
    except RuntimeError as exc:
        assert exc is boom

    ev = sent[-1]
    assert ev["operation"] == "agent_framework.agent.run"
    assert ev["success"] is False
    # Exactly one event for the run, not a start/finish pair.
    runs = [e for e in sent if e["operation"] == "agent_framework.agent.run"]
    assert len(runs) == 1


def test_class_middleware_records_the_outcome_too(sent):
    _init()
    ctx = FakeContext([FakeMessage("hello there")])
    nxt = ResultRecorder("from the class").bind(ctx)
    _run(ObsvrAgentMiddleware().process(ctx, nxt))
    assert sent[-1]["response"] == "from the class"


def test_bound_middleware_records_the_outcome_too(sent):
    _init()
    ctx = FakeContext([FakeMessage("hello there")])
    nxt = ResultRecorder("from the factory").bind(ctx)
    _run(make_agent_middleware(user_id="u1")(ctx, nxt))
    assert sent[-1]["response"] == "from the factory"
