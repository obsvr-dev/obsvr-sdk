"""ADR-6 MCP response-side interception + Phase-1A quota residual (Python).

Parity target: sdk/tests/unit/mcp-response-scan.test.ts and
sdk/tests/unit/quota-residual.test.ts. A governed MCP tool RESULT is scanned for
PII / secrets / injection and BLOCK / SANITIZE / LOG'd before it reaches the
caller; user-scoped quota rules meter the caller principal's bucket, not
'default'.
"""
import asyncio

import pytest

import obsvr
import obsvr.integrations.mcp as mcp_mod
from obsvr import sender
from obsvr.config import _reset
from obsvr.integrations.mcp import McpToolBlockedError, patch_mcp
from obsvr.response_scan import sanitize_mcp_result, scan_mcp_tool_result
from obsvr.rules import PolicyRule, _reset_quota


# ── Fakes ────────────────────────────────────────────────────────────────────

class FakeTextContent:
    def __init__(self, text):
        self.text = text


class FakeCallToolResult:
    def __init__(self, text):
        self.content = [FakeTextContent(text)]


def make_session_returning(text):
    class FakeClientSession:
        def __init__(self):
            self.calls = []

        async def call_tool(self, name, arguments=None):
            self.calls.append((name, arguments))
            return FakeCallToolResult(text)

    return FakeClientSession


def _init(**extra):
    _reset()
    sender._reset_sender()
    _reset_quota()
    extra.setdefault("disabled", False)
    obsvr.init(api_key="test-key", ingest_url="http://localhost:9", **extra)


def _captured(monkeypatch):
    captured = []
    monkeypatch.setattr(mcp_mod, "send_audit_async", lambda cfg, ev: captured.append(ev))
    return captured


def _run(coro):
    return asyncio.run(coro)


def _cfg():
    from obsvr.config import get_config

    return get_config()


# ── Unit: scan_mcp_tool_result ───────────────────────────────────────────────

class TestScanMcpToolResult:
    def test_clean_passes(self):
        _init(pii_policy={})
        scan = scan_mcp_tool_result("all quiet on the western front", _cfg())
        assert scan["action"] == "allow"
        assert scan["action_taken"] == "allowed"

    def test_sanitizes_redact_pii(self):
        _init(pii_policy={"rules": {"ssn": "redact"}})
        scan = scan_mcp_tool_result("the ssn is 123-45-6789", _cfg())
        assert scan["action"] == "sanitize"
        assert scan["action_taken"] == "redacted"
        assert "ssn" in scan["detected_types"]

    def test_blocks_block_pii(self):
        _init(pii_policy={"rules": {"ssn": "block"}})
        scan = scan_mcp_tool_result("the ssn is 123-45-6789", _cfg())
        assert scan["action"] == "block"
        assert scan["event_type"] == "blocked_call"

    def test_blocks_response_rule(self):
        rules = [PolicyRule(id="r1", name="no exfil", enabled=True, action="block",
                            type="keyword", conditions={"keywords": ["EXFIL_TOKEN"]},
                            applies_to="response")]
        _init(policy_rules=rules)
        scan = scan_mcp_tool_result("here is your EXFIL_TOKEN payload", _cfg())
        assert scan["action"] == "block"
        assert scan["rule_id"] == "r1"

    def test_zero_width_split_secret(self):
        _init(pii_policy={"rules": {"ssn": "block"}})
        # U+200B inside the SSN dodges a naive scan but not the normalized one.
        scan = scan_mcp_tool_result("leaked: 1​23-45-6789", _cfg())
        assert scan["action"] == "block"

    def test_principal_scoped_response_quota(self):
        rules = [PolicyRule(id="q", name="resp quota", enabled=True, action="block",
                            type="quota", applies_to="response",
                            conditions={"quota_limit": 1, "quota_window_ms": 60000,
                                        "quota_scope": "user_id"})]
        _init(policy_rules=rules)
        cfg = _cfg()
        assert scan_mcp_tool_result("ok", cfg, {"user_id": "alice"})["action"] == "allow"
        assert scan_mcp_tool_result("ok", cfg, {"user_id": "alice"})["action"] == "block"
        assert scan_mcp_tool_result("ok", cfg, {"user_id": "bob"})["action"] == "allow"


# ── Unit: sanitize_mcp_result ────────────────────────────────────────────────

class TestSanitizeMcpResult:
    def test_redacts_content_text(self):
        result = FakeCallToolResult("ssn 123-45-6789")
        out = sanitize_mcp_result(result)
        assert "[REDACTED_SSN]" in out.content[0].text
        assert "123-45-6789" not in out.content[0].text

    def test_redacts_bare_string(self):
        assert "[REDACTED_PHONE]" in sanitize_mcp_result("call me at 555-123-4567")


# ── Integration: governed call_tool response governance ──────────────────────

class TestGovernedResponse:
    def test_clean_passes_and_audits(self, monkeypatch):
        _init(pii_policy={})
        captured = _captured(monkeypatch)
        Session = make_session_returning("clean output")
        patch_mcp(Session)
        s = Session()
        result = _run(s.call_tool("read", {"path": "/tmp"}))
        assert result.content[0].text == "clean output"
        ev = [e for e in captured if e.get("success")][0]
        assert ev["event_type"] == "tool_call"
        assert ev["action_taken"] == "allowed"

    def test_sanitizes_pii_before_caller(self, monkeypatch):
        _init(pii_policy={"rules": {"ssn": "redact"}})
        captured = _captured(monkeypatch)
        Session = make_session_returning("user ssn 123-45-6789 leaked")
        patch_mcp(Session)
        s = Session()
        result = _run(s.call_tool("lookup", {"id": 1}))
        assert "[REDACTED_SSN]" in result.content[0].text
        assert "123-45-6789" not in result.content[0].text
        ev = [e for e in captured if e.get("success")][0]
        assert ev["action_taken"] == "redacted"

    def test_blocks_result_with_blocked_pattern(self, monkeypatch):
        _init(pii_policy={"rules": {"ssn": "block"}})
        captured = _captured(monkeypatch)
        Session = make_session_returning("exfiltrated ssn 123-45-6789")
        patch_mcp(Session)
        s = Session()
        with pytest.raises(McpToolBlockedError, match="tool result blocked by policy"):
            _run(s.call_tool("lookup", {"id": 1}))
        blocked = [e for e in captured if e.get("event_type") == "blocked_call"]
        assert blocked and blocked[0]["action_taken"] == "blocked"

    def test_audits_with_principal(self, monkeypatch):
        _init(pii_policy={})
        captured = _captured(monkeypatch)
        Session = make_session_returning("ok")
        patch_mcp(Session, options={"user_id": "alice"})
        s = Session()
        _run(s.call_tool("read", {}))
        ev = [e for e in captured if e.get("operation") == "mcp.tool.call"][0]
        assert ev["user_id"] == "alice"


# ── Phase-1A quota residual via the MCP framework integration ────────────────

class TestQuotaResidual:
    def test_user_scoped_quota_meters_principal_bucket(self, monkeypatch):
        from obsvr.rules import _quota_store

        rules = [PolicyRule(id="uq", name="per-user", enabled=True, action="block",
                            type="quota",
                            conditions={"quota_limit": 1, "quota_window_ms": 60000,
                                        "quota_scope": "user_id"})]
        # pii_policy={} opens the pre-call gate so the quota rule is evaluated.
        _init(pii_policy={}, policy_rules=rules)
        _captured(monkeypatch)

        SessionAlice = make_session_returning("ok")
        SessionBob = make_session_returning("ok")
        patch_mcp(SessionAlice, options={"user_id": "alice"})
        patch_mcp(SessionBob, options={"user_id": "bob"})
        alice, bob = SessionAlice(), SessionBob()

        _run(alice.call_tool("read", {}))  # alice unit 1/1
        with pytest.raises(McpToolBlockedError):
            _run(alice.call_tool("read", {}))  # alice exhausted
        # bob's bucket is independent — still allowed.
        _run(bob.call_tool("read", {}))

        # The 'default' bucket was never metered.
        assert "user_id:default" not in _quota_store


def test_apply_pre_call_policy_threads_identity_to_bucket():
    """Direct seam test (parity with the TS applyPreCallPolicy test)."""
    from obsvr.config import get_config
    from obsvr.policy import apply_pre_call_policy
    from obsvr.rules import _quota_store

    rules = [PolicyRule(id="uq", name="per-user", enabled=True, action="block",
                        type="quota",
                        conditions={"quota_limit": 5, "quota_window_ms": 60000,
                                    "quota_scope": "user_id"})]
    _init(policy_rules=rules)
    cfg = get_config()
    apply_pre_call_policy("hi", cfg, provider="openai", operation="op",
                          metadata={"user_id": "alice"})
    assert _quota_store.get("user_id:alice", {}).get("count") == 1
    assert "user_id:default" not in _quota_store
