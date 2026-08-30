import pytest

from obsvr.policy_lifecycle_v1 import (
    PolicyLifecycleV1ValidationError,
    build_policy_candidate_v1,
    decide_policy_promotion_v1,
    policy_candidate_v1_hash,
    replay_policy_candidate_v1,
)

CANDIDATE = {"policy_id": "contracts", "version": "7", "artifact_hash": "a" * 64, "previous_active_hash": "b" * 64, "stage": "shadow", "rollout_bps": 0, "explanation_codes": ["contract.external_send", "contract.pii"]}
CASES = [
    {"case_id": "a", "baseline_outcome": "ALLOW", "candidate_outcome": "DENY", "evidence_complete": True},
    {"case_id": "b", "baseline_outcome": "ALLOW", "candidate_outcome": "ALLOW", "evidence_complete": True},
]


def test_builds_deterministic_candidate_and_replay_report():
    assert policy_candidate_v1_hash(CANDIDATE) == "b761b5bdbf23d80ad49f9499ad5b58f772051c7389f279a57033f2128ee0226f"
    assert replay_policy_candidate_v1(CANDIDATE, CASES) | {"outcome_counts": None} == {
        "schema": "obsvr-policy-replay-report-v1", "candidate_hash": policy_candidate_v1_hash(CANDIDATE),
        "total_cases": 2, "changed_cases": 1, "changed_bps": 5000, "error_count": 0,
        "evidence_gap_count": 0, "outcome_counts": None,
    }


def test_promotes_inside_thresholds_and_carries_rollback():
    report = replay_policy_candidate_v1(CANDIDATE, CASES)
    result = decide_policy_promotion_v1(CANDIDATE, report, "canary", 500, {"max_error_count": 0, "max_evidence_gap_count": 0, "max_changed_bps": 5000})
    assert result["approved"] is True
    assert result["rollback_artifact_hash"] == "b" * 64
    denied = decide_policy_promotion_v1(CANDIDATE, report, "active", 10_000, {"max_error_count": 0, "max_evidence_gap_count": 0, "max_changed_bps": 100})
    assert denied["reason_codes"] == ["policy.replay.change_budget_exceeded"]


def test_lints_invalid_lifecycle_metadata():
    with pytest.raises(PolicyLifecycleV1ValidationError, match="inconsistent"):
        build_policy_candidate_v1({**CANDIDATE, "stage": "active", "rollout_bps": 50})
    with pytest.raises(PolicyLifecycleV1ValidationError, match="unique"):
        replay_policy_candidate_v1(CANDIDATE, [*CASES, CASES[0]])
