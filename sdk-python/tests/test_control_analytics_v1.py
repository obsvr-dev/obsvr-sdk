import pytest

from obsvr.control_analytics_v1 import build_control_analytics_report_v1

EVENTS = [
    {"event_id": "1", "workload_id": "contract-ai", "policy_hash": "a" * 64, "outcome": "ALLOW", "shadow_outcome": "DENY", "approval": "none", "latency_ms": 2, "coverage_complete": True, "evidence_complete": True, "occurred_at_ms": 100},
    {"event_id": "2", "workload_id": "contract-ai", "policy_hash": "a" * 64, "outcome": "STEP_UP", "shadow_outcome": "STEP_UP", "approval": "requested", "latency_ms": 7, "coverage_complete": False, "evidence_complete": True, "occurred_at_ms": 200},
    {"event_id": "3", "workload_id": "contract-ai", "policy_hash": "a" * 64, "outcome": "ALLOW", "approval": "overridden", "latency_ms": 20, "coverage_complete": True, "evidence_complete": False, "occurred_at_ms": 300},
]


def test_reports_bounded_effectiveness_indicators_without_hiding_gaps():
    report = build_control_analytics_report_v1(EVENTS)
    assert report["input_event_count"] == 3
    assert report["control_action_bps"] == 3333
    assert report["coverage_gap_count"] == report["evidence_gap_count"] == 1
    assert report["shadow"] == {"evaluated_count": 2, "changed_count": 1, "changed_bps": 5000}
    assert report["latency_ms"] == {"p50": 7, "p95": 20, "max": 20}


def test_is_deterministic_across_input_order():
    assert build_control_analytics_report_v1(list(reversed(EVENTS)))["report_hash"] == build_control_analytics_report_v1(EVENTS)["report_hash"]
    assert build_control_analytics_report_v1(EVENTS)["report_hash"] == "7bdad8cb33d6e675c38584f4ee120db8a1324fd48b93c082cc1f067ba5db5a93"


def test_rejects_duplicate_ids_and_unbounded_raw_fields():
    with pytest.raises(ValueError, match="unique"):
        build_control_analytics_report_v1([*EVENTS, EVENTS[0]])
    with pytest.raises(ValueError, match="unsupported field"):
        build_control_analytics_report_v1([{**EVENTS[0], "prompt": "secret"}])
