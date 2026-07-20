"""Unit tests for the inbound OPA/Cedar external policy backend (ADR-4):
  - SSRF guard (scheme, literal + resolved private/metadata addresses)
  - backend evaluation (OPA/Cedar response parsing, timeout, error, ssrf)
  - init-time validation
  - pre-call pipeline integration (deny-wins, fail-closed, shadow, provenance)

The cross-language merge + provenance semantics are pinned separately by
test_external_backend_conformance.py against
conformance/fixtures/external_backend.json.
"""
import json

import pytest

import obsvr
import obsvr.external_backend as eb
from obsvr.config import get_config
from obsvr.external_backend import (
    build_backend_input,
    evaluate_external_backend,
)
from obsvr.policy import apply_pre_call_policy
from obsvr.ssrf import (
    SsrfError,
    assert_backend_url_allowed,
    assert_backend_url_static,
    is_always_blocked_ip,
    is_private_or_reserved_ip,
)


def _reset():
    from obsvr.config import _reset as cfg_reset

    cfg_reset()


INPUT = build_backend_input(
    operation="chat.completions.create",
    provider="openai",
    model="gpt-4o",
    environment="production",
    user_id="u1",
    local_decision="allow",
    rules_hash="abcd",
    prompt_sha256="deadbeef",
)

OPA = {"type": "opa", "url": "https://8.8.8.8/v1/data/obsvr/allow"}
CEDAR = {"type": "cedar", "url": "https://1.1.1.1/v1/is_authorized"}


def _ok(body):
    """Transport that returns HTTP 200 with the given parsed body."""

    def transport(url, headers, body_str, timeout_s):
        return 200, body

    return transport


# ── SSRF classification ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "ip",
    [
        "10.0.0.1", "127.0.0.1", "169.254.169.254", "172.16.5.5", "192.168.1.1",
        "100.64.0.1", "0.0.0.0", "::1", "fe80::1", "fc00::1", "fd00:ec2::254",
        "::ffff:10.0.0.1", "203.0.113.10", "198.51.100.1", "198.18.0.1",
    ],
)
def test_flags_private_reserved(ip):
    assert is_private_or_reserved_ip(ip) is True


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "9.9.9.9", "2606:4700:4700::1111"])
def test_treats_public(ip):
    assert is_private_or_reserved_ip(ip) is False


def test_always_blocks_metadata_and_link_local():
    assert is_always_blocked_ip("169.254.169.254") is True
    assert is_always_blocked_ip("fe80::1") is True
    assert is_always_blocked_ip("fd00:ec2::254") is True
    assert is_always_blocked_ip("10.0.0.1") is False  # private but not always-blocked


# ── static url guard ─────────────────────────────────────────────────────────


def test_static_rejects_non_http_scheme():
    with pytest.raises(SsrfError):
        assert_backend_url_static("ftp://opa.example.com/x")
    with pytest.raises(SsrfError):
        assert_backend_url_static("file:///etc/passwd")


def test_static_rejects_metadata_even_with_flag():
    with pytest.raises(SsrfError):
        assert_backend_url_static("http://169.254.169.254/latest/meta-data", True)


def test_static_rejects_private_by_default():
    with pytest.raises(SsrfError):
        assert_backend_url_static("http://10.0.0.5:8181/v1/data/x")


def test_static_permits_private_with_flag():
    assert_backend_url_static("http://127.0.0.1:8181/v1/data/x", True)  # no raise


def test_static_permits_public_literal():
    assert_backend_url_static("https://8.8.8.8/v1/data/x")  # no raise


# ── resolve-before-connect ───────────────────────────────────────────────────


def test_resolve_rejects_private_resolution():
    with pytest.raises(SsrfError):
        assert_backend_url_allowed("https://opa.example.com/x", False, lambda h: ["10.1.2.3"])


def test_resolve_always_blocks_metadata_resolution():
    with pytest.raises(SsrfError):
        assert_backend_url_allowed("https://sneaky.example.com/x", True, lambda h: ["169.254.169.254"])


def test_resolve_allows_public_resolution():
    assert assert_backend_url_allowed("https://opa.example.com/x", False, lambda h: ["93.184.216.34"]) is None


# ── backend evaluation ───────────────────────────────────────────────────────


def test_opa_true_allow():
    assert evaluate_external_backend(OPA, INPUT, transport=_ok({"result": True}))["outcome"] == "allow"


def test_opa_false_deny():
    assert evaluate_external_backend(OPA, INPUT, transport=_ok({"result": False}))["outcome"] == "deny"


def test_opa_object_result_with_reasons():
    r = evaluate_external_backend(
        OPA, INPUT, transport=_ok({"result": {"allow": False, "reasons": ["tenant not permitted"]}})
    )
    assert r["outcome"] == "deny"
    assert r["reasons"] == ["tenant not permitted"]


def test_opa_missing_result_is_error():
    assert evaluate_external_backend(OPA, INPUT, transport=_ok({}))["outcome"] == "error"


def test_opa_wraps_input_under_input_key():
    captured = {}

    def cap(url, headers, body_str, timeout_s):
        captured["body"] = json.loads(body_str)
        return 200, {"result": True}

    evaluate_external_backend(OPA, INPUT, transport=cap)
    assert captured["body"] == {"input": INPUT}


def test_cedar_allow():
    assert evaluate_external_backend(CEDAR, INPUT, transport=_ok({"decision": "Allow"}))["outcome"] == "allow"


def test_cedar_deny_case_insensitive():
    assert evaluate_external_backend(CEDAR, INPUT, transport=_ok({"decision": "DENY"}))["outcome"] == "deny"


def test_cedar_sends_input_directly():
    captured = {}

    def cap(url, headers, body_str, timeout_s):
        captured["body"] = json.loads(body_str)
        return 200, {"decision": "Allow"}

    evaluate_external_backend(CEDAR, INPUT, transport=cap)
    assert captured["body"] == INPUT


def test_timeout_maps_to_timeout():
    def boom(url, headers, body_str, timeout_s):
        raise TimeoutError("timed out")

    assert evaluate_external_backend(OPA, INPUT, transport=boom)["outcome"] == "timeout"


def test_network_error_maps_to_error():
    def boom(url, headers, body_str, timeout_s):
        raise RuntimeError("ECONNREFUSED")

    assert evaluate_external_backend(OPA, INPUT, transport=boom)["outcome"] == "error"


def test_non_2xx_maps_to_error():
    assert evaluate_external_backend(OPA, INPUT, transport=lambda *a: (503, None))["outcome"] == "error"


def test_ssrf_blocked_url_is_error_without_transport_call():
    called = {"v": False}

    def transport(url, headers, body_str, timeout_s):
        called["v"] = True
        return 200, {"result": True}

    blocked = {"type": "opa", "url": "http://169.254.169.254/x"}
    r = evaluate_external_backend(blocked, INPUT, transport=transport)
    assert r["outcome"] == "error"
    assert "ssrf_guard_blocked_backend_url" in r["reasons"]
    assert called["v"] is False


# ── init-time validation ─────────────────────────────────────────────────────


def test_init_rejects_unknown_type():
    _reset()
    with pytest.raises(ValueError, match='must be "opa" or "cedar"'):
        obsvr.init(api_key="t", external_policy_backend={"type": "xacml", "url": "https://x.example.com"})


def test_init_rejects_non_http_scheme():
    _reset()
    with pytest.raises(SsrfError):
        obsvr.init(api_key="t", external_policy_backend={"type": "opa", "url": "ftp://opa.example.com"})


def test_init_rejects_metadata_literal():
    _reset()
    with pytest.raises(SsrfError):
        obsvr.init(api_key="t", external_policy_backend={"type": "opa", "url": "http://169.254.169.254/x"})


def test_init_accepts_localhost_sidecar_with_flag():
    _reset()
    obsvr.init(
        api_key="t",
        external_policy_backend={
            "type": "opa",
            "url": "http://127.0.0.1:8181/v1/data/x",
            "allow_private_network": True,
        },
    )
    assert get_config().external_policy_backend["type"] == "opa"


# ── pre-call pipeline integration ────────────────────────────────────────────


def _pre_call():
    return apply_pre_call_policy(
        "hello world", get_config(), provider="openai", operation="chat.completions.create"
    )


def test_pipeline_backend_deny_blocks(monkeypatch):
    _reset()
    monkeypatch.setattr(
        eb, "_urllib_transport",
        lambda url, headers, body, timeout: (200, {"result": {"allow": False, "reasons": ["blocked by corp policy"]}}),
    )
    obsvr.init(api_key="t", external_policy_backend={"type": "opa", "url": "https://8.8.8.8/v1/data/obsvr/allow"})
    result = _pre_call()
    assert result["decision"] == "block"
    assert result["compliance"]["action_source"] == "external_backend"
    assert result["compliance"]["policy_reason"] == "blocked by corp policy"
    rec = result["compliance"]["external_backend"]
    assert rec["type"] == "opa"
    assert rec["outcome"] == "deny"
    assert rec["shadow"] is False
    assert rec["identity"] == "opa:8.8.8.8"


def test_pipeline_backend_allow_records_provenance(monkeypatch):
    _reset()
    monkeypatch.setattr(eb, "_urllib_transport", lambda *a: (200, {"decision": "Allow"}))
    obsvr.init(api_key="t", external_policy_backend={"type": "cedar", "url": "https://1.1.1.1/authz"})
    result = _pre_call()
    assert result["decision"] == "allow"
    rec = result["compliance"]["external_backend"]
    assert rec["type"] == "cedar"
    assert rec["outcome"] == "allow"


def test_pipeline_fail_closed_on_error(monkeypatch):
    _reset()

    def boom(*a):
        raise RuntimeError("ECONNREFUSED")

    monkeypatch.setattr(eb, "_urllib_transport", boom)
    obsvr.init(api_key="t", external_policy_backend={"type": "opa", "url": "https://8.8.8.8/v1/data/obsvr/allow"})
    result = _pre_call()
    assert result["decision"] == "block"
    assert result["compliance"]["action_source"] == "external_backend"
    assert result["compliance"]["external_backend"]["outcome"] == "error"


def test_pipeline_shadow_never_blocks_but_records(monkeypatch):
    _reset()
    monkeypatch.setattr(eb, "_urllib_transport", lambda *a: (200, {"result": False}))
    obsvr.init(
        api_key="t",
        external_policy_backend={"type": "opa", "url": "https://8.8.8.8/v1/data/obsvr/allow", "shadow": True},
    )
    result = _pre_call()
    assert result["decision"] == "allow"
    assert result["compliance"]["action_source"] != "external_backend"
    rec = result["compliance"]["external_backend"]
    assert rec["outcome"] == "deny"
    assert rec["shadow"] is True


def test_pipeline_no_backend_is_inert():
    _reset()
    obsvr.init(api_key="t")
    result = _pre_call()
    assert result["decision"] == "allow"
    assert result["compliance"]["external_backend"] is None
