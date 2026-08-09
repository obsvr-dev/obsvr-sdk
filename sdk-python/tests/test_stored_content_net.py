"""The stored-content net for content the decision scan never reached.

Twin: sdk-typescript/tests/unit/stored-content-net.test.ts.

The README promise this pins, in its own words:

    "Policy decisions scan the last user message; earlier turns and system
     prompts are still stored (and redacted if configured)..."

The first clause was true and the second was not. Measured across
block x redact x flag x four roles, no configuration redacted content the
decision scan never reached — the full multi-role prompt went into the signed
event verbatim. "Still stored" was the half that was true, and that was the
harm.

Both halves are asserted, because a fix satisfying only the first would trade a
storage leak for a worse defect:

    H1  content outside the decision scan is redacted in the stored copy when a
        PII type resolves to block/redact;
    H2  a detect_only resolution leaves the record ALONE — that mode exists so
        an operator can baseline what actually flows, and scrubbing the record
        destroys the only thing it produces;
    H3  the event states the OUTBOUND request was not modified, so a redacted
        stored prompt beside ``action_taken: "allowed"`` cannot be read as
        prevention.

H2 is also what makes H1 falsifiable: without it, a redacted stored prompt
could mean "this net fired" or "this SDK redacts everything always", and the
test could not tell them apart.
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


# The four roles the decision scan does not reach.
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
    # The call was allowed — enforcement scope is unchanged by this net.
    assert len(fake.chat.completions.calls) == 1
    assert captured, "no audit event was emitted"
    return captured[0], fake.chat.completions.calls[0]


@pytest.mark.parametrize("role", sorted(UNSCANNED_ROLES))
@pytest.mark.parametrize("action", ["block", "redact"])
def test_h1_unscanned_role_is_redacted_in_the_stored_copy(monkeypatch, role, action):
    event, _sent = _drive(
        monkeypatch, {"rules": {"ssn": action}}, UNSCANNED_ROLES[role](SSN)
    )
    assert event["action_taken"] == "allowed"
    assert SSN not in event["prompt"]
    assert "[REDACTED_SSN]" in event["prompt"]


@pytest.mark.parametrize("role", sorted(UNSCANNED_ROLES))
def test_h2_detect_only_leaves_the_record_readable(monkeypatch, role):
    event, _sent = _drive(
        monkeypatch, {"rules": {"ssn": "detect_only"}}, UNSCANNED_ROLES[role](SSN)
    )
    assert SSN in event["prompt"]


def test_h3_event_states_the_outbound_request_was_not_modified(monkeypatch):
    event, sent = _drive(
        monkeypatch, {"rules": {"ssn": "block"}}, UNSCANNED_ROLES["system"](SSN)
    )
    tel = (event.get("metadata") or {}).get("obsvr_telemetry") or {}
    assert tel.get("stored_redaction_scope") == "unscanned_roles"
    assert tel.get("stored_redaction_types") == ["ssn"]
    assert tel.get("stored_redaction_outbound_unmodified") is True
    # ...and that claim is TRUE: the provider did receive the raw value.
    # Recording a redacted prompt without saying this would assert an
    # enforcement that did not happen.
    assert SSN in str(sent["messages"])


def test_single_turn_call_is_decided_by_the_ordinary_gate(monkeypatch):
    """Control: the provider is never reached. That is the enforcement this net
    does NOT provide and must not be credited with — a storage net that also
    blocked would look identical from the record alone."""
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
