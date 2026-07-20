"""End-to-end anti-tamper policy floor wiring. Twin:
sdk/tests/unit/policy-floor-wiring.test.ts. Pins: a floor block cannot be
un-blocked by the customer hook (and the attempt is recorded as
floor_override_ignored — the differentiator over a swallowed log line); a
remote sync replacing policy_rules cannot delete the floor; floor_version
rides events."""

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
