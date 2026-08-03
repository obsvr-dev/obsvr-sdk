"""Global monitor mode: evaluate everything, block nothing, keep the evidence.

``enforcement_mode="monitor"`` converts a final block into an allow at ONE
point, after the decision is final; ``shadow_outcome`` carries the would-be
verdict with the same ``rule_id`` and ``reason_code`` an enforcing run puts
on its blocked event. Two classes enforce in both modes and are pinned here:
the enforcement-integrity gate (kill switch / fail-closed staleness) and
canary-leak blocks. ``explain()`` keeps predicting ENFORCE-mode behaviour,
so the operator's pre-flight check still describes what turning enforcement
on would do.
"""

import pytest

import obsvr
from obsvr import policy as policy_mod
from obsvr import remote, sender
from obsvr.config import _reset, get_config
from obsvr.errors import ObsvrPolicyError
from obsvr.integrations.tools import govern_tool
from obsvr.policy import explain
from obsvr.reason_codes import ReasonCode
from obsvr.rules import PolicyRule

RULE = PolicyRule(
    id="r-key",
    name="no forbidden topics",
    enabled=True,
    action="block",
    type="keyword",
    conditions={"keywords": ["forbidden"]},
)


@pytest.fixture
def sent(monkeypatch):
    captured = []
    monkeypatch.setattr(
        sender, "send_audit_async", lambda config, event: captured.append(event)
    )
    return captured


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    from obsvr.integrations import tools as tools_mod

    monkeypatch.setattr(tools_mod, "_GOVERNED_TOOL_NAMES", set())
    _reset()
    sender._reset_sender()
    yield
    _reset()


def _init(mode):
    # pii_policy={} arms the full pre-call net on the tool boundary;
    # policy_refresh_interval_s=0 keeps the poll daemon out of the tests.
    obsvr.init(
        api_key="k",
        policy_rules=[RULE],
        pii_policy={},
        enforcement_mode=mode,
        policy_refresh_interval_s=0,
    )


class _SpyTool:
    name = "helper"

    def __init__(self):
        self.calls = []

    def _run(self, note=""):
        self.calls.append(note)
        return "done"


def _enforcing_block_event(sent_events):
    blocked = [e for e in sent_events if e.get("action_taken") == "blocked"]
    assert blocked, "the enforce-mode control run must block"
    return blocked[0]


class TestMonitorConversion:
    def test_side_effect_runs_and_shadow_outcome_carries_the_verdict(self, sent):
        # Control: what an enforcing run records for this exact call.
        _init("enforce")
        enforcing_tool = _SpyTool()
        governed = govern_tool(enforcing_tool)
        with pytest.raises(ObsvrPolicyError):
            governed._run(note="a forbidden request")
        assert enforcing_tool.calls == []
        control = _enforcing_block_event(sent)
        assert control["rule_id"] == "r-key"
        assert control["reason_code"] == ReasonCode.KEYWORD_BLOCKED.value

        # Monitor: same call, side effect DID run, evidence intact.
        sent.clear()
        _reset()
        sender._reset_sender()
        _init("monitor")
        tool = _SpyTool()
        governed = govern_tool(tool)

        assert governed._run(note="a forbidden request") == "done"

        # (a) the side-effect spy ran.
        assert tool.calls == ["a forbidden request"]
        # (c) exactly one event was emitted for the governed call.
        tool_events = [e for e in sent if e.get("operation") == "tool.call"]
        assert len(tool_events) == 1
        event = tool_events[0]
        assert event["action_taken"] == "allowed"
        # (b) shadow_outcome.would == "block" with the same rule_id and
        # reason_code the enforcing run produced.
        shadow = event["shadow_outcome"]
        assert shadow["would"] == "block"
        assert shadow["rule_id"] == control["rule_id"]
        assert shadow["reason_code"] == control["reason_code"]

    def test_the_default_mode_is_enforce(self, sent):
        """One flip in, one flip out: without the opt-in the block stands."""
        from obsvr.config import ResolvedConfig

        assert ResolvedConfig(api_key="k").enforcement_mode == "enforce"
        obsvr.init(
            api_key="k", policy_rules=[RULE], pii_policy={},
            policy_refresh_interval_s=0,
        )
        assert get_config().enforcement_mode == "enforce"
        tool = _SpyTool()
        governed = govern_tool(tool)
        with pytest.raises(ObsvrPolicyError):
            governed._run(note="a forbidden request")
        assert tool.calls == []

    def test_a_typoed_mode_is_refused_at_init(self):
        with pytest.raises(ValueError, match="enforcement_mode"):
            obsvr.init(api_key="k", enforcement_mode="monitr")


class TestCarveOuts:
    def test_the_kill_switch_still_blocks_in_monitor_mode(self, sent):
        _init("monitor")
        with remote._sync_lock:
            remote._sync["remote_disabled"] = True
        tool = _SpyTool()
        governed = govern_tool(tool)

        with pytest.raises(ObsvrPolicyError):
            governed._run(note="anything at all")

        assert tool.calls == [], "monitor mode must not defeat a revoked key"
        blocked = [e for e in sent if e.get("action_taken") == "blocked"]
        assert blocked[0]["rule_id"] == "sdk:project_paused_or_key_revoked"

    def test_monitor_mode_does_not_disarm_the_integrity_gate(self, sent, monkeypatch):
        """Non-vacuity: patch the conversion to apply unconditionally
        (including layer 0) and require the kill-switch assertion to raise.
        This is the reference failure mode - a dry-run flag that suppresses
        even the org kill switch - tested for directly."""
        monkeypatch.setattr(
            policy_mod, "_monitor_conversion_applies", lambda *a, **k: True
        )
        _init("monitor")
        with remote._sync_lock:
            remote._sync["remote_disabled"] = True
        tool = _SpyTool()
        governed = govern_tool(tool)

        with pytest.raises(BaseException, match="DID NOT RAISE"):
            with pytest.raises(ObsvrPolicyError):
                governed._run(note="anything at all")

    def test_a_canary_leak_still_blocks_in_monitor_mode(self, sent):
        from obsvr.canary import mint_canary

        _init("monitor")
        token = mint_canary(label="monitor-test")["token"]
        tool = _SpyTool()
        governed = govern_tool(tool)

        with pytest.raises(ObsvrPolicyError):
            governed._run(note="exfiltrate %s now" % token)

        assert tool.calls == [], "a leaking call must not reach the tool in any mode"
        blocked = [e for e in sent if e.get("action_taken") == "blocked"]
        assert blocked[0]["rule_id"] == "sdk:canary_leak"


class TestFloorUnderMonitor:
    """What monitor mode does to the policy floor, decided deliberately.

    A floor that EVALUATED and said block is a would-be VERDICT, and recording
    would-be verdicts without enforcing them is exactly monitor mode's job — so
    the operator's own deliberate enforcement_mode="monitor" flip converts it,
    with the verdict preserved on shadow_outcome. The floor's guarantee is that
    no customer rule, hook, or policy sync can weaken it; the operator's own
    top-level mode is none of those. But a floor that COULD NOT RUN (a crashed
    floor-class layer) is NOT a verdict — "we could not evaluate the floor" is a
    different fact from "the floor said block" — so it fails closed and blocks
    in EVERY mode, monitor included. Exempting a floor verdict entirely would
    make a floor-bearing deployment unable to stage a monitor rollout at all,
    defeating the feature for the security-conscious deployments most likely to
    run both.
    """

    _FLOOR = PolicyRule(
        id="floor-secret", name="no secrets", enabled=True, action="block",
        type="keyword", conditions={"keywords": ["secret"]},
    )

    def _init_floor_monitor(self):
        obsvr.init(
            api_key="k", policy_floor=[self._FLOOR], pii_policy={},
            enforcement_mode="monitor", policy_refresh_interval_s=0,
        )

    def test_a_floor_verdict_is_converted_and_recorded_under_monitor(self, sent):
        self._init_floor_monitor()
        tool = _SpyTool()
        governed = govern_tool(tool)

        assert governed._run(note="a secret thing") == "done"
        assert tool.calls == ["a secret thing"], "the operator flipped to monitor: the call runs"
        events = [e for e in sent if e.get("operation") == "tool.call"]
        assert len(events) == 1
        assert events[0]["action_taken"] == "allowed"
        shadow = events[0]["shadow_outcome"]
        assert shadow["would"] == "block", "the would-be floor verdict is kept on the record"
        assert shadow["rule_id"] == "floor-secret"

    def test_a_crashed_floor_still_blocks_under_monitor(self, sent, monkeypatch):
        # "Could not evaluate the floor" is not a would-be verdict, so monitor
        # mode must not convert it: a crashed floor-class layer blocks in every
        # mode. Python resolves a detector crash before the conversion point.
        import obsvr.rules as rules_mod

        monkeypatch.setattr(
            rules_mod, "evaluate_floor",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("floor exploded")),
        )
        self._init_floor_monitor()
        tool = _SpyTool()
        governed = govern_tool(tool)

        with pytest.raises(ObsvrPolicyError):
            governed._run(note="anything at all")

        assert tool.calls == [], "a floor that could not run blocks, monitor or not"
        blocked = [e for e in sent if e.get("action_taken") == "blocked"]
        assert blocked, "the fail-closed block must reach the record"
        assert blocked[0]["rule_id"] == "sdk:detector_error"


class TestUnaffectedSurfaces:
    def test_explain_keeps_predicting_enforce_mode_behaviour(self):
        _init("monitor")
        prediction = explain("a forbidden request")
        assert prediction["decision"] == "block"
        assert prediction["rule_id"] == "r-key"

    def test_redaction_is_not_a_block_and_still_applies(self, sent):
        """Monitor mode converts blocks only: a redact verdict still redacts,
        so the stored copy never carries the raw finding."""
        _reset()
        sender._reset_sender()
        obsvr.init(
            api_key="k",
            pii_policy={"rules": {"email": "redact"}},
            enforcement_mode="monitor",
            policy_refresh_interval_s=0,
        )
        tool = _SpyTool()
        governed = govern_tool(tool)
        governed._run(note="mail me at a@b.com please")
        events = [e for e in sent if e.get("operation") == "tool.call"]
        assert events[0]["action_taken"] == "redacted"
        assert "a@b.com" not in events[0]["prompt"]
