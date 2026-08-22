"""Structured pre-call planning for the direct provider boundary."""

import sys

import pytest

import obsvr
from obsvr import sender
from obsvr.config import _reset

WRAP_MODULE = sys.modules["obsvr.wrap"]


class _Response:
    choices = []


class _Completions:
    def __init__(self):
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return _Response()


class _Chat:
    def __init__(self):
        self.completions = _Completions()


class FakeOpenAI:
    def __init__(self):
        self.chat = _Chat()


def _init(**extra):
    _reset()
    sender._reset_sender()
    extra.setdefault("disabled", False)
    obsvr.init(api_key="test-key", ingest_url="http://localhost:9", **extra)


def _plan(kwargs, args=()):
    raw = FakeOpenAI()
    plan = WRAP_MODULE._build_direct_call_pre_call_plan(
        raw.chat.completions,
        "openai",
        "chat.completions.create",
        {},
        args,
        kwargs,
    )
    return raw, plan


def test_ready_plan_contains_exact_cleaned_invocation_without_provider_call():
    _init(sample_rate=0)
    extra_argument = object()
    raw, plan = _plan(
        {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "hello"}],
            "temperature": 0.25,
            "obsvr_metadata": {"session_id": "session-1"},
        },
        args=(extra_argument,),
    )

    assert plan.disposition == "ready"
    assert plan.args == (extra_argument,)
    assert plan.kwargs == {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}],
        "temperature": 0.25,
    }
    assert plan.pre.args == plan.args
    assert plan.pre.kwargs == plan.kwargs
    assert plan.pre.metadata["session_id"] == "session-1"
    assert plan.classifications == ()
    assert raw.chat.completions.calls == []


def test_ready_plan_contains_exact_redaction_and_classifications():
    _init(sample_rate=0, pii_policy={"rules": {"email": "redact"}})
    raw, plan = _plan(
        {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "mail a@b.com"}],
        }
    )

    assert plan.disposition == "ready"
    assert plan.kwargs["messages"][0]["content"] == "mail [REDACTED_EMAIL]"
    assert "email" in plan.classifications
    assert raw.chat.completions.calls == []


def test_block_plan_does_not_emit_and_legacy_wrapper_raises_same_error(monkeypatch):
    _init(pii_policy={"rules": {"ssn": "block"}})
    captured = []
    monkeypatch.setattr(
        WRAP_MODULE, "send_audit_async", lambda config, event: captured.append(event)
    )
    request = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "ssn 123-45-6789"}],
        "obsvr_metadata": {"session_id": "session-1"},
    }

    raw, plan = _plan(request)
    assert plan.disposition == "blocked"
    assert plan.args == ()
    assert plan.kwargs == {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "ssn 123-45-6789"}],
    }
    assert "ssn" in plan.classifications
    assert captured == []
    assert raw.chat.completions.calls == []

    wrapped_raw = FakeOpenAI()
    with pytest.raises(type(plan.error)) as raised:
        obsvr.wrap(wrapped_raw).chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "ssn 123-45-6789"}],
            obsvr_metadata={"session_id": "session-1"},
        )
    assert str(raised.value) == str(plan.error)
    assert raised.value.reason_code == plan.error.reason_code
    assert wrapped_raw.chat.completions.calls == []
