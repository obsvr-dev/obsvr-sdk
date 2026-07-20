"""Tests for post-call policy."""
import pytest
from obsvr.config import ResolvedConfig
from obsvr.policy import apply_post_call_policy


def test_pass_for_clean_response():
    config = ResolvedConfig(api_key="test")
    result = apply_post_call_policy("nice response", {}, config)
    assert result["decision"] == "pass"


def test_flag_from_hook():
    def flag_hook(resp, event):
        return {"decision": "flag", "reason": "flagged"}
    config = ResolvedConfig(api_key="test", on_post_call=flag_hook)
    result = apply_post_call_policy("response text", {}, config)
    assert result["decision"] == "flag"
    assert result["compliance"].get("event_type") == "policy_flag"


def test_redact_response_from_hook():
    def redact_hook(resp, event):
        return {"decision": "redact_response"}
    config = ResolvedConfig(api_key="test", on_post_call=redact_hook)
    result = apply_post_call_policy("call me at 555-123-4567", {}, config)
    assert result["decision"] == "redact_response"
    assert result["redacted_response"] is not None
    assert "555-123-4567" not in result["redacted_response"]


def test_hook_error_falls_back_to_pass():
    def bad_hook(resp, event):
        raise RuntimeError("fail")
    config = ResolvedConfig(api_key="test", on_post_call=bad_hook)
    result = apply_post_call_policy("response", {}, config)
    assert result["decision"] == "pass"


# ── Built-in response-side PII scan (post_call phase; TS twin suite) ─────────

def test_response_scan_redacts_stored_copy_for_redact_severity():
    config = ResolvedConfig(api_key="test", pii_policy={"default": "redact"})
    result = apply_post_call_policy("the SSN is 123-45-6789", {}, config)
    assert result["decision"] == "redact_response"
    assert result["response_pii"]["detected"] is True
    assert "ssn" in result["response_pii"]["types"]
    assert result["response_pii"]["action"] == "redacted"
    assert "123-45-6789" not in (result["redacted_response"] or "")
    assert result["compliance"]["policy_reason"] == "pii_detected_in_response"


def test_response_scan_detect_only_records_without_redacting():
    config = ResolvedConfig(api_key="test", pii_policy={"default": "detect_only"})
    result = apply_post_call_policy("the SSN is 123-45-6789", {}, config)
    assert result["decision"] == "pass"
    assert result["response_pii"]["action"] == "detected_only"
    assert result["redacted_response"] is None


def test_response_scan_block_severity_redacts_stored_copy():
    config = ResolvedConfig(api_key="test", pii_policy={"default": "block"})
    result = apply_post_call_policy("card 4111 1111 1111 1111", {}, config)
    assert result["decision"] == "redact_response"
    assert result["response_pii"]["action"] == "redacted"


def test_no_pii_policy_means_no_response_scan():
    config = ResolvedConfig(api_key="test")
    result = apply_post_call_policy("the SSN is 123-45-6789", {}, config)
    assert "response_pii" not in result


def test_merge_post_call_stamps_response_pii_telemetry():
    from obsvr.wrap import _merge_post_call
    event = {"response": "raw 123-45-6789", "metadata": {"obsvr_telemetry": {"finish_reason": "stop"}}}
    _merge_post_call(event, {
        "decision": "redact_response",
        "redacted_response": "raw [SSN]",
        "compliance": {"policy_reason": "pii_detected_in_response"},
        "response_pii": {"detected": True, "types": ["ssn"], "action": "redacted"},
    })
    assert event["response"] == "raw [SSN]"
    assert event["policy_reason"] == "pii_detected_in_response"
    t = event["metadata"]["obsvr_telemetry"]
    assert t["finish_reason"] == "stop"
    assert t["response_pii_detected"] is True
    assert t["response_pii_types"] == ["ssn"]
    assert t["response_pii_action"] == "redacted"
