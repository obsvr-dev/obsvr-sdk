"""Provider-bound and stored-content coverage across every text role.

Twin: sdk-typescript/tests/unit/stored-content-net.test.ts.

    H1  block/redact decisions apply before provider execution across roles;
    H2  a detect_only resolution leaves the record ALONE — that mode exists so
        an operator can baseline what actually flows, and scrubbing the record
        destroys the only thing it produces;
    H3  the event verdict and the actual provider payload agree.
"""
import sys

import pytest

import obsvr
import obsvr.wrap  # ensure module is loaded; package attr shadows it
from obsvr import sender
from obsvr.config import _reset
from obsvr.config import get_config
from obsvr.events import build_audit_event

WRAP_MODULE = sys.modules["obsvr.wrap"]

SSN = "123-45-6789"


class _Completions:
    def __init__(self):
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)

        class _Msg:
            content = "ok"

        class _Choice:
            message = _Msg()

        class _Resp:
            choices = [_Choice()]

        return _Resp()


class FakeOpenAI:
    def __init__(self):
        class _Chat:
            pass

        self.chat = _Chat()
        self.chat.completions = _Completions()


def _init(**extra):
    _reset()
    sender._reset_sender()
    extra.setdefault("disabled", False)
    obsvr.init(api_key="test-key", ingest_url="http://localhost:9", **extra)


def _captured(monkeypatch):
    captured = []
    monkeypatch.setattr(WRAP_MODULE, "send_audit_async", lambda cfg, ev: captured.append(ev))
    return captured


# Four provider-bound roles that must all be governed.
UNSCANNED_ROLES = {
    "system": lambda p: [
        {"role": "system", "content": f"operator note: {p}"},
        {"role": "user", "content": "hello"},
    ],
    "earlier_user_turn": lambda p: [
        {"role": "user", "content": f"earlier: {p}"},
        {"role": "assistant", "content": "noted"},
        {"role": "user", "content": "hello"},
    ],
    "assistant": lambda p: [
        {"role": "user", "content": "summarise"},
        {"role": "assistant", "content": f"doc says: {p}"},
        {"role": "user", "content": "hello"},
    ],
    "tool_result": lambda p: [
        {"role": "user", "content": "look it up"},
        {"role": "tool", "content": f"lookup returned: {p}", "tool_call_id": "c1"},
        {"role": "user", "content": "hello"},
    ],
}


def _drive(monkeypatch, pii_policy, messages):
    _init(pii_policy=pii_policy)
    captured = _captured(monkeypatch)
    fake = FakeOpenAI()
    client = obsvr.wrap(fake)
    client.chat.completions.create(model="gpt-4", messages=messages)
    assert len(fake.chat.completions.calls) == 1
    assert captured, "no audit event was emitted"
    return captured[0], fake.chat.completions.calls[0]


def test_provider_bound_system_pii_is_blocked_before_execution(monkeypatch):
    _init(pii_policy={"rules": {"ssn": "block"}})
    _captured(monkeypatch)
    fake = FakeOpenAI()
    client = obsvr.wrap(fake)
    with pytest.raises(Exception):
        client.chat.completions.create(
            model="gpt-4", messages=UNSCANNED_ROLES["system"](SSN)
        )
    assert fake.chat.completions.calls == []


@pytest.mark.parametrize("role", sorted(UNSCANNED_ROLES))
def test_h1_provider_bound_role_is_blocked_before_execution(monkeypatch, role):
    _init(pii_policy={"rules": {"ssn": "block"}})
    _captured(monkeypatch)
    fake = FakeOpenAI()
    with pytest.raises(Exception):
        obsvr.wrap(fake).chat.completions.create(
            model="gpt-4", messages=UNSCANNED_ROLES[role](SSN)
        )
    assert fake.chat.completions.calls == []


@pytest.mark.parametrize("role", sorted(UNSCANNED_ROLES))
def test_h1_provider_bound_role_is_redacted_before_execution(monkeypatch, role):
    event, sent = _drive(
        monkeypatch, {"rules": {"ssn": "redact"}}, UNSCANNED_ROLES[role](SSN)
    )
    assert event["action_taken"] == "redacted"
    assert SSN not in event["prompt"]
    assert "[REDACTED_SSN]" in event["prompt"]
    assert SSN not in str(sent["messages"])


@pytest.mark.parametrize("role", sorted(UNSCANNED_ROLES))
def test_h2_detect_only_leaves_the_record_readable(monkeypatch, role):
    event, _sent = _drive(
        monkeypatch, {"rules": {"ssn": "detect_only"}}, UNSCANNED_ROLES[role](SSN)
    )
    assert SSN in event["prompt"]


def test_h3_event_and_outbound_redaction_agree(monkeypatch):
    event, sent = _drive(
        monkeypatch, {"rules": {"ssn": "redact"}}, UNSCANNED_ROLES["system"](SSN)
    )
    assert event["action_taken"] == "redacted"
    assert SSN not in event["prompt"]
    assert SSN not in str(sent["messages"])


def test_single_turn_call_is_decided_by_the_ordinary_gate(monkeypatch):
    """Control: the provider is never reached and the block is recorded."""
    _init(pii_policy={"rules": {"ssn": "block"}})
    captured = _captured(monkeypatch)
    fake = FakeOpenAI()
    client = obsvr.wrap(fake)
    with pytest.raises(Exception):
        client.chat.completions.create(
            model="gpt-4", messages=[{"role": "user", "content": f"my ssn is {SSN}"}]
        )
    assert fake.chat.completions.calls == []
    assert captured[0]["event_type"] == "blocked_call"
    tel = (captured[0].get("metadata") or {}).get("obsvr_telemetry") or {}
    assert "stored_redaction_scope" not in tel


def test_no_pii_policy_the_net_never_fires(monkeypatch):
    _init()
    captured = _captured(monkeypatch)
    fake = FakeOpenAI()
    client = obsvr.wrap(fake)
    client.chat.completions.create(
        model="gpt-4", messages=UNSCANNED_ROLES["system"](SSN)
    )
    assert SSN in captured[0]["prompt"]
    tel = (captured[0].get("metadata") or {}).get("obsvr_telemetry") or {}
    assert "stored_redaction_scope" not in tel


def test_response_only_pii_is_redacted_from_the_stored_event(monkeypatch):
    _init(pii_policy={"rules": {"ssn": "redact"}})
    captured = _captured(monkeypatch)
    fake = FakeOpenAI()

    def create_with_pii(**kwargs):
        fake.chat.completions.calls.append(kwargs)

        class _Msg:
            content = f"generated ssn {SSN}"

        class _Choice:
            message = _Msg()

        class _Resp:
            choices = [_Choice()]

        return _Resp()

    fake.chat.completions.create = create_with_pii
    response = obsvr.wrap(fake).chat.completions.create(
        model="gpt-4", messages=[{"role": "user", "content": "hello"}]
    )
    assert SSN in response.choices[0].message.content
    assert SSN not in captured[0]["response"]
    assert "[REDACTED_SSN]" in captured[0]["response"]
    tel = (captured[0].get("metadata") or {}).get("obsvr_telemetry") or {}
    assert tel["response_pii_detected"] is True
    assert tel["response_pii_types"] == ["ssn"]
    assert tel["response_pii_action"] == "redacted"
    assert tel["stored_redaction_scope"] == "all_event_content"
    assert tel["stored_redaction_surfaces"] == ["response"]


def test_integration_event_builder_redacts_response_only_pii():
    _init(pii_policy={"rules": {"ssn": "redact"}})
    event = build_audit_event(
        get_config(),
        provider="unknown",
        model="gpt-4",
        operation="framework.callback",
        source="test",
        prompt="hello",
        response=f"generated ssn {SSN}",
    )
    assert SSN not in event["response"]
    assert "[REDACTED_SSN]" in event["response"]
    tel = (event.get("metadata") or {}).get("obsvr_telemetry") or {}
    assert tel["stored_redaction_scope"] == "all_event_content"
    assert tel["stored_redaction_types"] == ["ssn"]
    assert tel["stored_redaction_surfaces"] == ["response"]
    assert tel["stored_redaction_outbound_unmodified"] is True
