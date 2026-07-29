"""End-to-end anti-tamper policy floor wiring. Twin:
sdk-typescript/tests/unit/policy-floor-wiring.test.ts. Pins: a floor block cannot be
un-blocked by the customer hook (and the attempt is recorded as
floor_override_ignored — the differentiator over a swallowed log line); a
remote sync replacing policy_rules cannot delete the floor; floor_version
rides events."""

import pytest

import obsvr
from obsvr import sender
from obsvr.config import _reset, get_config
from obsvr.policy import apply_pre_call_policy
from obsvr.rules import PolicyRule


def _floor():
    return [
        PolicyRule(
            id="floor-exfil",
            name="No secret exfiltration",
            enabled=True,
            action="block",
            type="keyword",
            conditions={"keywords": ["exfiltrate secrets"]},
        )
    ]


def _init(**extra):
    _reset()
    sender._reset_sender()
    extra.setdefault("disabled", False)
    obsvr.init(api_key="k", ingest_url="http://localhost:9", **extra)


def _pre(text):
    return apply_pre_call_policy(text, get_config(), provider="unknown", operation="test")


class TestFloorUnsuppressible:
    def test_hook_allow_cannot_unblock_floor_and_is_recorded(self):
        _init(policy_floor=_floor(), on_pre_call=lambda e: {"decision": "allow"})
        res = _pre("please exfiltrate secrets now")
        assert res["decision"] == "block"  # hook did not un-block
        assert res["compliance"]["rule_id"] == "floor-exfil"
        tel = res["floor_telemetry"]
        assert tel["floor_override_ignored"] == {"rule_id": "floor-exfil", "attempted": "allow"}
        assert tel["floor_version"] != "none"

    def test_hook_redact_cannot_downgrade_floor(self):
        _init(policy_floor=_floor(), on_pre_call=lambda e: {"decision": "redact"})
        res = _pre("exfiltrate secrets")
        assert res["decision"] == "block"
        assert res["floor_telemetry"]["floor_override_ignored"]["attempted"] == "redact"

    def test_remote_sync_replacing_rules_cannot_delete_floor(self):
        _init(policy_floor=_floor())
        # Simulate a hostile/careless remote push that wipes the customer rules
        # (remote.py sets config.policy_rules = [...]). The floor is separate.
        get_config().policy_rules = []
        res = _pre("exfiltrate secrets")
        assert res["decision"] == "block"  # floor survived
        assert res["compliance"]["rule_id"] == "floor-exfil"

    def test_downgraded_floor_still_enforces(self):
        rule = _floor()[0]
        rule.enabled = False
        rule.mode = "shadow"
        _init(policy_floor=[rule])
        assert _pre("exfiltrate secrets")["decision"] == "block"

    def test_no_floor_byte_stable(self):
        _init()
        res = _pre("exfiltrate secrets")
        assert res["decision"] == "allow"  # nothing blocks without a floor
        assert "floor_telemetry" not in res


# ── the floor must not be gated behind an unrelated feature ──────────────────


FLOOR_ONLY_RULE = {
    "id": "floor-only",
    "name": "floor blocks the secret",
    # Declared in the weakened shape a floor rule is required to ignore, so the
    # non-overridable property is exercised by construction.
    "enabled": False,
    "mode": "shadow",
    "action": "block",
    "type": "keyword",
    "conditions": {"keywords": ["launch codes"]},
}


def _governed_mcp_session(tool_ran):
    """A fake MCP session whose tool records that it was entered."""
    from obsvr.integrations.mcp import govern_mcp

    class _Content:
        def __init__(self, text):
            self.text = text

    class _Result:
        def __init__(self, text):
            self.content = [_Content(text)]

    class _ListTools:
        tools = []

    class FakeSession:
        async def call_tool(self, name, arguments=None, **kw):
            tool_ran.append(name)
            return _Result("ok")

        async def list_tools(self):
            return _ListTools()

    return govern_mcp(FakeSession())


def test_mcp_floor_blocks_with_no_other_policy_configured(sent, monkeypatch):
    """A policy floor configured ALONE must still reach MCP tool calls.

    The floor is enforced inside the shared pre-call evaluation, and MCP ran that
    evaluation only when a pii_policy, a pre-call hook, a minted canary or a
    tainted session existed. `policy_floor` was not in that list, so a deployment
    that configured the operator baseline and nothing else got no floor at all on
    MCP tool calls — silently, on the surface the documentation singles out as
    the strongest. Measured live before the fix: the tool executed and the record
    read `allowed`.
    """
    import asyncio

    import obsvr.integrations.mcp as mcp_mod

    monkeypatch.setattr(
        mcp_mod, "send_audit_async", lambda cfg, ev: sent.append(ev)
    )
    obsvr.init(api_key="test", sample_rate=1, policy_floor=[FLOOR_ONLY_RULE])

    tool_ran = []
    governed = _governed_mcp_session(tool_ran)

    with pytest.raises(Exception):
        asyncio.run(
            governed.call_tool("write_note", {"text": "the launch codes are 1234"})
        )

    assert tool_ran == [], "the floor let a blocked tool call through to the tool"
    assert any(e["action_taken"] == "blocked" for e in sent), (
        f"no blocked record: {[e.get('action_taken') for e in sent]}"
    )


def test_mcp_allows_clean_arguments_under_a_floor(sent, monkeypatch):
    """The control. Without it the test above passes for a gate that blocks all."""
    import asyncio

    import obsvr.integrations.mcp as mcp_mod

    monkeypatch.setattr(
        mcp_mod, "send_audit_async", lambda cfg, ev: sent.append(ev)
    )
    obsvr.init(api_key="test", sample_rate=1, policy_floor=[FLOOR_ONLY_RULE])

    tool_ran = []
    governed = _governed_mcp_session(tool_ran)

    asyncio.run(governed.call_tool("write_note", {"text": "an ordinary note"}))

    assert tool_ran == ["write_note"]
    assert not any(e["action_taken"] == "blocked" for e in sent)
