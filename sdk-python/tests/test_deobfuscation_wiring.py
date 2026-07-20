"""Pipeline wiring for the de-obfuscation view layer (server-side normalizer mirror).

Twin: sdk/tests/unit/deobfuscation-wiring.test.ts. The pure decision
semantics are fixture-pinned (deobfuscation.json decision/storage/policy
cases); these tests pin that the REAL pipelines actually route through
them: opt-in gate, redact->block escalation, whole-text stored copies,
and the sealed security_normalized provenance.
"""
import sys

import pytest

import obsvr
import obsvr.wrap  # ensure module is loaded; package attr shadows it
from obsvr import sender
from obsvr.config import _reset, get_config
from obsvr.deobfuscate import OBFUSCATED_REDACTION_PLACEHOLDER
from obsvr.policy import apply_observe_policy, apply_post_call_policy
from obsvr.response_scan import scan_mcp_tool_result

WRAP_MODULE = sys.modules["obsvr.wrap"]

# base64("my ssn is 123-45-6789") — raw-clean, view-detectable.
B64_SSN = "bXkgc3NuIGlzIDEyMy00NS02Nzg5"


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


def _captured_events(monkeypatch):
    captured = []

    def fake_send(config, event):
        captured.append(event)

    monkeypatch.setattr(WRAP_MODULE, "send_audit_async", fake_send)
    return captured


class TestWrapPreCall:
    def test_flag_off_default_encoded_payload_passes(self, monkeypatch):
        _init(pii_policy={})
        _captured_events(monkeypatch)
        raw = FakeOpenAI()
        client = obsvr.wrap(raw)
        client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": f"please summarize: {B64_SSN}"}],
        )
        assert len(raw.chat.completions.calls) == 1

    def test_flag_on_block_policy_seals_provenance_and_placeholder(self, monkeypatch):
        _init(pii_policy={"default": "block"}, deobfuscation={"enabled": True})
        captured = _captured_events(monkeypatch)
        raw = FakeOpenAI()
        client = obsvr.wrap(raw)
        with pytest.raises(RuntimeError):
            client.chat.completions.create(
                model="gpt-4o", messages=[{"role": "user", "content": B64_SSN}]
            )
        assert raw.chat.completions.calls == []  # provider never contacted
        assert len(captured) == 1
        ev = captured[0]
        assert ev["event_type"] == "blocked_call"
        assert ev["action_reason"] == "pii_detected"
        # Server-side normalizer mirror: the view that defeated the obfuscation is sealed.
        assert (ev.get("metadata") or {}).get("security_normalized") == "base64"
        # The stored prompt/user_input never carry the (trivially decodable)
        # encoded payload: whole-text placeholder, since spans are unlocatable.
        assert ev["prompt"] == OBFUSCATED_REDACTION_PLACEHOLDER
        assert ev["user_input"] == OBFUSCATED_REDACTION_PLACEHOLDER

    def test_flag_on_redact_policy_view_hit_escalates_to_block(self, monkeypatch):
        _init(pii_policy={"default": "redact"}, deobfuscation={"enabled": True})
        _captured_events(monkeypatch)
        raw = FakeOpenAI()
        client = obsvr.wrap(raw)
        with pytest.raises(RuntimeError):
            client.chat.completions.create(
                model="gpt-4o", messages=[{"role": "user", "content": B64_SSN}]
            )
        assert raw.chat.completions.calls == []

    def test_flag_on_redact_policy_raw_hit_still_redacts(self, monkeypatch):
        _init(pii_policy={"default": "redact"}, deobfuscation={"enabled": True})
        _captured_events(monkeypatch)
        raw = FakeOpenAI()
        client = obsvr.wrap(raw)
        client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "my ssn is 123-45-6789"}],
        )
        assert len(raw.chat.completions.calls) == 1
        # Span redaction on the outgoing request, exactly as without the layer.
        sent = raw.chat.completions.calls[0]["messages"][0]["content"]
        assert sent == "my ssn is [REDACTED_SSN]"


class TestPostCallMcpObserve:
    def test_post_call_view_hit_stores_placeholder(self):
        _init(pii_policy={"default": "redact"}, deobfuscation={"enabled": True})
        post = apply_post_call_policy(f"result: {B64_SSN}", {}, get_config())
        assert post["decision"] == "redact_response"
        assert post["response_pii"]["via"] == "base64"
        assert post["redacted_response"] == OBFUSCATED_REDACTION_PLACEHOLDER

    def test_post_call_raw_hit_keeps_span_redaction(self):
        _init(pii_policy={"default": "redact"}, deobfuscation={"enabled": True})
        post = apply_post_call_policy("ssn 123-45-6789", {}, get_config())
        assert post["decision"] == "redact_response"
        assert "via" not in post["response_pii"]
        assert post["redacted_response"] == "ssn [REDACTED_SSN]"

    def test_post_call_merge_stamps_via_telemetry(self):
        _init(pii_policy={"default": "redact"}, deobfuscation={"enabled": True})
        post = apply_post_call_policy(f"x {B64_SSN}", {}, get_config())
        event = {"metadata": {}}
        WRAP_MODULE._merge_post_call(event, post)
        assert event["metadata"]["obsvr_telemetry"]["response_pii_via"] == "base64"
        assert event["response"] == OBFUSCATED_REDACTION_PLACEHOLDER

    def test_mcp_result_view_hit_escalates_sanitize_to_block(self):
        _init(pii_policy={"default": "redact"}, deobfuscation={"enabled": True})
        verdict = scan_mcp_tool_result(B64_SSN, get_config())
        assert verdict["action"] == "block"
        assert verdict["via"] == "base64"
        assert "no locatable span" in verdict["policy_reason"]

    def test_mcp_result_flag_off_prior_behavior(self):
        _init(pii_policy={"default": "redact"})
        verdict = scan_mcp_tool_result(B64_SSN, get_config())
        assert verdict["action"] == "allow"
        assert "via" not in verdict

    def test_observe_view_hit_sets_stored_redaction_via(self):
        _init(pii_policy={"default": "redact"}, deobfuscation={"enabled": True})
        res = apply_observe_policy(B64_SSN, get_config())
        assert res["should_redact_stored"] is True
        assert res["stored_redaction_via"] == "base64"
