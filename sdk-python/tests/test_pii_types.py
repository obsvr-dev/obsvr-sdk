"""Tests for shared PII type constants."""
from obsvr.pii_types import PII_TYPES, BUILTIN_SEVERITY
from obsvr.policy import run_builtin_pii_scan, redact_builtin_pii


def test_pii_types_contains_all():
    assert "ip_address" in PII_TYPES
    assert "jwt" in PII_TYPES
    assert "uuid" in PII_TYPES
    assert "email" in PII_TYPES


def test_builtin_severity_ip_block():
    assert BUILTIN_SEVERITY.get("ip_address") == "redact" # was block (over-fires)


def test_builtin_severity_jwt_block():
    assert BUILTIN_SEVERITY.get("jwt") == "block"


def test_scan_ip_address():
    r = run_builtin_pii_scan("server at 203.0.113.1")
    assert r["pii_detected"] is True
    assert "ip_address" in r["detected_types"]


def test_scan_jwt():
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123xyz"
    r = run_builtin_pii_scan(f"token: {token}")
    assert r["pii_detected"] is True
    assert "jwt" in r["detected_types"]


def test_scan_uuid():
    r = run_builtin_pii_scan("id 550e8400-e29b-41d4-a716-446655440000")
    assert r["pii_detected"] is True
    assert "uuid" in r["detected_types"]
