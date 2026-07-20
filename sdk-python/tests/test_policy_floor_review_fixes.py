"""Slice-6 anti-tamper policy-floor ADVERSARIAL-REVIEW follow-up (Python side).
Twin: sdk/tests/unit/policy-floor-review-fixes.test.ts. Pins the review-confirmed
defects so the floor guarantee holds on every pre/post surface:
  - a floor action:'redact' FAILS CLOSED to a block (no unredacted prompt);
  - response-target floor rules (applies_to 'response'/'both') enforce, and the
    onPostCall hook cannot downgrade a floor-forced response redaction;
  - context-dependent floor rules (model_gate / environment_gate) enforce on
    the shared pre-call path (current_environment threaded into the floor ctx);
  - a floor rule may be a plain dict (TS parity) without a fail-open TypeError;
  - floor_version rides EVERY event under an active floor (build_audit_event).
"""

import obsvr
from obsvr import sender
from obsvr.config import _reset, get_config
from obsvr.events import build_audit_event
from obsvr.policy import apply_post_call_policy, apply_pre_call_policy
from obsvr.rules import PolicyRule


def _init(**extra):
    _reset()
    sender._reset_sender()
    extra.setdefault("disabled", False)
    obsvr.init(api_key="k", ingest_url="http://localhost:9", **extra)


def _pre(text, model=None):
    return apply_pre_call_policy(
        text, get_config(), provider="openai", operation="op", model=model
    )


class TestFloorRedactFailsClosed:
    def test_floor_redact_escalates_to_block(self):
        _init(
            policy_floor=[
                PolicyRule(id="floor-ssn", name="no ssn", enabled=True,
                           action="redact", type="keyword",
                           conditions={"keywords": ["ssn"]})
            ]
        )
        res = _pre("my ssn is private")
        assert res["decision"] == "block"  # never 'redact' — never forward it
        assert res["compliance"]["rule_id"] == "floor-ssn"


class TestResponseFloor:
    def _resp_floor(self):
        return [
            PolicyRule(id="floor-resp", name="no marker", enabled=True,
                       action="block", type="keyword",
                       conditions={"keywords": ["classified-marker"]},
                       applies_to="response")
        ]

    def test_response_floor_catches_output(self):
        _init(policy_floor=self._resp_floor())
        res = apply_post_call_policy(
            "here is the classified-marker", {}, get_config()
        )
        assert res["decision"] == "redact_response"
        assert res["compliance"]["rule_id"] == "floor-resp"
        assert "classified-marker" not in (res["redacted_response"] or "")

    def test_post_hook_cannot_downgrade_floor(self):
        _init(
            policy_floor=self._resp_floor(),
            on_post_call=lambda text, event: {"decision": "flag"},
        )
        res = apply_post_call_policy("leak classified-marker", {}, get_config())
        assert res["decision"] == "redact_response"  # floor re-asserted
        assert res["compliance"]["rule_id"] == "floor-resp"

    def test_clean_response_under_floor_passes(self):
        _init(policy_floor=self._resp_floor())
        assert apply_post_call_policy("ordinary answer", {}, get_config())["decision"] == "pass"


class TestContextFloorRules:
    def test_model_gate_floor_enforces(self):
        _init(
            environment="production",
            policy_floor=[
                PolicyRule(id="floor-model", name="no gpt-4", enabled=True,
                           action="block", type="model_gate",
                           conditions={"denied_models": ["gpt-4"]})
            ],
        )
        assert _pre("hi", "gpt-4")["decision"] == "block"
        assert _pre("hi", "gpt-3.5-turbo")["decision"] == "allow"

    def test_environment_gate_floor_enforces(self):
        # Regression for the current_environment omission from the floor ctx.
        _init(
            environment="production",
            policy_floor=[
                PolicyRule(id="floor-env", name="no prod", enabled=True,
                           action="block", type="environment_gate",
                           conditions={"target_environments": ["production"]})
            ],
        )
        res = _pre("hi")
        assert res["decision"] == "block"
        assert res["compliance"]["rule_id"] == "floor-env"


class TestDictFloorRule:
    def test_plain_dict_floor_rule_does_not_raise_and_enforces(self):
        # TS accepts plain objects for policyFloor; a Python caller mirroring the
        # docs may pass dicts. Must coerce (fail closed), not TypeError.
        _init(
            policy_floor=[
                {"id": "floor-kw", "name": "kw", "enabled": True, "action": "block",
                 "type": "keyword", "conditions": {"keywords": ["exfiltrate"]}}
            ]
        )
        assert _pre("please exfiltrate now")["decision"] == "block"


class TestFloorVersionOnEveryEvent:
    def test_build_audit_event_stamps_floor_version_on_clean_event(self):
        _init(
            policy_floor=[
                PolicyRule(id="floor-kw", name="kw", enabled=True, action="block",
                           type="keyword", conditions={"keywords": ["nope"]})
            ]
        )
        ev = build_audit_event(
            get_config(), provider="openai", model="gpt-4",
            operation="chat", source="test",
            prompt="totally benign", response="benign",
        )
        tel = (ev.get("metadata") or {}).get("obsvr_telemetry") or {}
        assert tel.get("floor_version")
        assert tel["floor_version"] != "none"

    def test_no_floor_no_floor_version(self):
        _init()
        ev = build_audit_event(
            get_config(), provider="openai", model="gpt-4",
            operation="chat", source="test", prompt="x", response="y",
        )
        tel = (ev.get("metadata") or {}).get("obsvr_telemetry") or {}
        assert "floor_version" not in tel
