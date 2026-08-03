"""Audit event building tests."""

import pytest

from obsvr.config import ResolvedConfig
from obsvr.events import (
    build_audit_event,
    classify_error,
    infer_provider_from_string,
    truncate,
)
from obsvr.policy import DEFAULT_COMPLIANCE


def _cfg(**kw):
    defaults = dict(api_key="test", sample_rate=1)
    defaults.update(kw)
    return ResolvedConfig(**defaults)


# ---------------------------------------------------------------------------
# truncate
# ---------------------------------------------------------------------------


def test_truncate_short():
    assert truncate("hello", 100) == "hello"


def test_truncate_long():
    result = truncate("a" * 10, 5)
    assert result == "aaaaa [TRUNCATED]"


def test_truncate_none():
    assert truncate(None, 100) == ""


# ---------------------------------------------------------------------------
# classify_error
# ---------------------------------------------------------------------------


def test_classify_rate_limit():
    assert classify_error(Exception("rate limit exceeded")) == "rate_limit"


def test_classify_timeout():
    assert classify_error(TimeoutError("timed out")) == "timeout"


def test_classify_auth():
    assert classify_error(Exception("unauthorized 401")) == "auth_error"


def test_classify_api_error():
    assert classify_error(Exception("server error")) == "api_error"


# ---------------------------------------------------------------------------
# infer_provider_from_string
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "identifier,expected",
    [
        ("azure_openai", "azure_openai"),
        ("openai.chat", "openai"),
        ("anthropic.claude3", "anthropic"),
        ("google.gemini", "google"),
        ("bedrock.converse", "bedrock"),
        ("vertex_ai.gemini", "vertex_ai"),
        ("together.llama", "together"),
        ("cloudflare.workersai", "cloudflare"),
        ("unknown_provider", "unknown"),
    ],
)
def test_infer_provider(identifier, expected):
    assert infer_provider_from_string(identifier) == expected


# ---------------------------------------------------------------------------
# build_audit_event
# ---------------------------------------------------------------------------


def test_build_event_basic_fields():
    cfg = _cfg()
    event = build_audit_event(
        cfg,
        provider="openai",
        model="gpt-4o",
        operation="chat.completions",
        source="test",
        prompt="Hello",
        response="Hi back",
        input_tokens=5,
        output_tokens=3,
        total_tokens=8,
    )
    assert event["provider"] == "openai"
    assert event["model"] == "gpt-4o"
    assert event["prompt"] == "Hello"
    assert event["response"] == "Hi back"
    assert event["input_tokens"] == 5
    assert event["output_tokens"] == 3
    assert event["total_tokens"] == 8
    assert event["success"] is True
    assert event["status_code"] == 200
    assert "request_id" in event


def test_build_event_failure():
    cfg = _cfg()
    err = Exception("boom")
    event = build_audit_event(
        cfg,
        provider="openai",
        model="gpt-4o",
        operation="chat",
        source="test",
        prompt="p",
        success=False,
        status_code=500,
        error=err,
    )
    assert event["success"] is False
    assert event["status_code"] == 500
    assert event["error_message"] == "boom"
    assert event["error_type"] == "api_error"


def test_build_event_compliance_fields():
    cfg = _cfg()
    compliance = {
        "event_type": "blocked_call",
        "policy_version": "v1",
        "action_taken": "blocked",
        "action_reason": "pii_detected",
        "action_source": "builtin",
        "redacted_types": ["ssn"],
        "blocked_types": ["ssn"],
    }
    event = build_audit_event(
        cfg,
        provider="openai",
        model="gpt-4o",
        operation="chat",
        source="test",
        prompt="[REDACTED_SSN]",
        success=False,
        status_code=403,
        compliance=compliance,
    )
    assert event["event_type"] == "blocked_call"
    assert event["action_taken"] == "blocked"
    assert event["action_reason"] == "pii_detected"
    assert event["redacted_types"] == ["ssn"]
    assert event["blocked_types"] == ["ssn"]


def test_build_event_truncation():
    cfg = _cfg(max_payload_chars=5)
    event = build_audit_event(
        cfg,
        provider="openai",
        model="m",
        operation="op",
        source="s",
        prompt="hello world",
    )
    assert event["prompt"] == "hello [TRUNCATED]"


def test_build_event_options_source_wins():
    cfg = _cfg(default_source="config_source")
    event = build_audit_event(
        cfg,
        provider="openai",
        model="m",
        operation="op",
        source="default_source",
        prompt="p",
        options={"source": "options_source"},
    )
    assert event["source"] == "options_source"


def test_build_event_region_default():
    cfg = _cfg()
    event = build_audit_event(
        cfg, provider="openai", model="m", operation="op", source="s", prompt="p"
    )
    assert event["region"] == "unknown"


def test_metadata_trimmed_to_budget_preserves_grouping_keys():
    # oversized metadata must be trimmed by the SDK (not replaced
    # wholesale by ingest), keeping trace_id / agent_run_id so the event stays
    # linked to its run and trace.
    big_attrs = {f"k{i}": "v" * 20 for i in range(2000)}  # well over 9 KB
    ev = build_audit_event(
        _cfg(),
        provider="unknown",
        model="m",
        source="test",
        operation="op",
        prompt="",
        response="",
        metadata={
            "trace_id": "T1",
            "agent_run_id": "R1",
            "obsvr_span": {"span_id": "s", "attributes": big_attrs},
        },
    )
    import json as _json

    md = ev["metadata"]
    assert len(_json.dumps(md)) <= 9000
    assert md["trace_id"] == "T1"
    assert md["agent_run_id"] == "R1"
    assert md["_obsvr_metadata_trimmed"] is True


def test_mcp_provider_detail_marker():
    # MCP events carry metadata.provider_detail so the identity survives
    # ingest coercing provider "mcp" -> "unknown"; other providers do not.
    mcp = build_audit_event(_cfg(), provider="mcp", model="mcp-tool", operation="mcp.tools.call", source="mcp", prompt="", response="")
    assert mcp["metadata"]["provider_detail"] == "mcp"
    other = build_audit_event(_cfg(), provider="openai", model="m", operation="chat", source="x", prompt="", response="")
    assert "provider_detail" not in (other.get("metadata") or {})


# ---------------------------------------------------------------------------
# user_id boundary coercion
# ---------------------------------------------------------------------------
#
# user_id is inside the format-3 decision digest, and str()/String() disagree
# on scalars (str(1.0) vs String(1.0), str(True) vs "true") while a JSON
# export destroys what the other runtime would need to reproduce the
# emitter's rendering. So the event stores ONE canonical string, minted at
# this boundary; everything downstream handles only that string. The exact
# cross-language strings and digests are pinned by the user_id_coercion
# section of conformance/fixtures/signing_vectors.json (consumed by
# test_signing.py and the TS twin suite).


def _built_user_id(raw):
    ev = build_audit_event(
        _cfg(), provider="openai", model="m", operation="chat", source="x",
        prompt="", response="", options={"user_id": raw},
    )
    # The builder strips None-valued fields, so an absent principal is a
    # missing key — .get() maps both spellings of absent to None here.
    return ev.get("user_id")


def test_a_non_string_user_id_is_stored_as_its_canonical_string():
    assert _built_user_id(123) == "123"
    assert _built_user_id(1.0) == "1"
    assert _built_user_id(1.5) == "1.5"
    assert _built_user_id(True) == "true"
    assert _built_user_id("alice") == "alice"


def test_an_absent_user_id_stays_absent_never_the_string_none():
    # The decision digest's presence byte keeps absent distinct from empty;
    # "None" leaking in as a string would collapse that distinction.
    assert _built_user_id(None) is None
    ev = build_audit_event(
        _cfg(), provider="openai", model="m", operation="chat", source="x",
        prompt="", response="",
    )
    assert ev.get("user_id") is None


def test_an_uncoercible_user_id_is_absent_not_a_repr():
    # Containers and non-finite floats have no rendering both languages can
    # recompute, so they are treated as absent rather than sealed as a repr.
    assert _built_user_id({"id": 1}) is None
    assert _built_user_id(["a"]) is None
    assert _built_user_id(float("nan")) is None
    assert _built_user_id(float("inf")) is None
