"""Deterministic policy candidate, replay, promotion, and rollback contracts."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from .strict_canonical import code_point_key
from .tool_pinning import _canonical_json_for_hash

POLICY_CANDIDATE_V1_SCHEMA = "obsvr-policy-candidate-v1"
POLICY_REPLAY_REPORT_V1_SCHEMA = "obsvr-policy-replay-report-v1"
POLICY_PROMOTION_V1_SCHEMA = "obsvr-policy-promotion-v1"
_HEX = frozenset("0123456789abcdef")
_OUTCOMES = ("ALLOW", "DENY", "MODIFY", "STEP_UP", "DEFER", "ERROR")
_MAX_SAFE = 9_007_199_254_740_991


class PolicyLifecycleV1ValidationError(ValueError):
    pass


def _fail(message: str) -> None:
    raise PolicyLifecycleV1ValidationError(message)


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip().encode()) > 256:
        _fail(f"{field} must be nonblank and at most 256 UTF-8 bytes")
    return value.strip()


def _hash(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in _HEX for c in value):
        _fail(f"{field} must be a lowercase SHA-256 hash")
    return value


def _integer(value: Any, field: str, maximum: int = _MAX_SAFE) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > maximum:
        _fail(f"{field} must be a nonnegative safe integer no greater than {maximum}")
    return value


def _exact(value: Dict[str, Any], allowed: set[str], field: str) -> None:
    unknown = sorted(set(value) - allowed, key=code_point_key)
    if unknown:
        _fail(f"{field} contains unsupported field: {unknown[0]}")


def build_policy_candidate_v1(input_value: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(input_value, dict):
        _fail("candidate must be an object")
    _exact(input_value, {"schema", "policy_id", "version", "artifact_hash", "previous_active_hash", "stage", "rollout_bps", "explanation_codes"}, "candidate")
    if "schema" in input_value and input_value["schema"] != POLICY_CANDIDATE_V1_SCHEMA:
        _fail("candidate schema is invalid")
    stage = input_value.get("stage")
    if stage not in {"shadow", "canary", "active"}:
        _fail("stage is invalid")
    rollout = _integer(input_value.get("rollout_bps"), "rollout_bps", 10_000)
    if (stage == "shadow" and rollout != 0) or (stage == "canary" and not 1 <= rollout <= 9_999) or (stage == "active" and rollout != 10_000):
        _fail("rollout_bps is inconsistent with stage")
    raw_codes = input_value.get("explanation_codes")
    if not isinstance(raw_codes, list) or not 1 <= len(raw_codes) <= 256:
        _fail("explanation_codes must contain between 1 and 256 items")
    codes = sorted({_text(item, f"explanation_codes[{i}]") for i, item in enumerate(raw_codes)}, key=code_point_key)
    result = {"schema": POLICY_CANDIDATE_V1_SCHEMA, "policy_id": _text(input_value.get("policy_id"), "policy_id"), "version": _text(input_value.get("version"), "version"), "artifact_hash": _hash(input_value.get("artifact_hash"), "artifact_hash"), "stage": stage, "rollout_bps": rollout, "explanation_codes": codes}
    if "previous_active_hash" in input_value:
        result["previous_active_hash"] = _hash(input_value["previous_active_hash"], "previous_active_hash")
    if stage != "shadow" and "previous_active_hash" not in result:
        _fail("canary and active candidates require previous_active_hash for rollback")
    return result


def policy_candidate_v1_hash(input_value: Dict[str, Any]) -> str:
    body = _canonical_json_for_hash(build_policy_candidate_v1(input_value))
    return hashlib.sha256(f"obsvr-policy-candidate/1\0{body}".encode()).hexdigest()


def replay_policy_candidate_v1(candidate_input: Dict[str, Any], cases_input: List[Dict[str, Any]]) -> Dict[str, Any]:
    candidate = build_policy_candidate_v1(candidate_input)
    if not isinstance(cases_input, list) or not 1 <= len(cases_input) <= 10_000:
        _fail("cases must contain between 1 and 10000 items")
    cases = []
    for index, item in enumerate(cases_input):
        if not isinstance(item, dict):
            _fail(f"cases[{index}] must be an object")
        _exact(item, {"case_id", "baseline_outcome", "candidate_outcome", "evidence_complete"}, f"cases[{index}]")
        if item.get("baseline_outcome") not in _OUTCOMES or item.get("candidate_outcome") not in _OUTCOMES:
            _fail(f"cases[{index}] outcome is invalid")
        if not isinstance(item.get("evidence_complete"), bool):
            _fail(f"cases[{index}].evidence_complete must be boolean")
        cases.append({**item, "case_id": _text(item.get("case_id"), f"cases[{index}].case_id")})
    cases.sort(key=lambda item: code_point_key(item["case_id"]))
    if len({item["case_id"] for item in cases}) != len(cases):
        _fail("case_id values must be unique")
    counts = {outcome: 0 for outcome in _OUTCOMES}
    for item in cases:
        counts[item["candidate_outcome"]] += 1
    changed = sum(item["baseline_outcome"] != item["candidate_outcome"] for item in cases)
    return {"schema": POLICY_REPLAY_REPORT_V1_SCHEMA, "candidate_hash": policy_candidate_v1_hash(candidate), "total_cases": len(cases), "changed_cases": changed, "changed_bps": changed * 10_000 // len(cases), "error_count": counts["ERROR"], "evidence_gap_count": sum(not item["evidence_complete"] for item in cases), "outcome_counts": counts}


def decide_policy_promotion_v1(candidate_input: Dict[str, Any], report: Dict[str, Any], requested_stage: str, requested_rollout_bps: int, thresholds: Dict[str, int]) -> Dict[str, Any]:
    candidate = build_policy_candidate_v1(candidate_input)
    if report.get("schema") != POLICY_REPLAY_REPORT_V1_SCHEMA or report.get("candidate_hash") != policy_candidate_v1_hash(candidate):
        _fail("replay report does not match candidate")
    reasons = []
    if report["error_count"] > _integer(thresholds.get("max_error_count"), "max_error_count"):
        reasons.append("policy.replay.errors_exceeded")
    if report["evidence_gap_count"] > _integer(thresholds.get("max_evidence_gap_count"), "max_evidence_gap_count"):
        reasons.append("policy.replay.evidence_gaps_exceeded")
    if report["changed_bps"] > _integer(thresholds.get("max_changed_bps"), "max_changed_bps", 10_000):
        reasons.append("policy.replay.change_budget_exceeded")
    if requested_stage not in {"shadow", "canary", "active"}:
        _fail("requested_stage is invalid")
    rollout = _integer(requested_rollout_bps, "requested_rollout_bps", 10_000)
    if (requested_stage == "shadow" and rollout != 0) or (requested_stage == "canary" and not 1 <= rollout <= 9_999) or (requested_stage == "active" and rollout != 10_000):
        _fail("requested rollout is inconsistent with stage")
    if requested_stage != "shadow" and "previous_active_hash" not in candidate:
        reasons.append("policy.rollback.target_missing")
    approved = not reasons
    return {"schema": POLICY_PROMOTION_V1_SCHEMA, "candidate_hash": policy_candidate_v1_hash(candidate), "approved": approved, "requested_stage": requested_stage, "requested_rollout_bps": rollout, "effective_stage": requested_stage if approved else "shadow", "effective_rollout_bps": rollout if approved else 0, "rollback_artifact_hash": candidate.get("previous_active_hash", candidate["artifact_hash"]), "reason_codes": ["policy.promotion.ready"] if approved else sorted(reasons, key=code_point_key)}
