"""Deterministic control-effectiveness summaries over explicit event inputs."""

from __future__ import annotations

import hashlib
import math
from typing import Any, Dict, List

from .tool_pinning import _canonical_json_for_hash

CONTROL_ANALYTICS_REPORT_V1_SCHEMA = "obsvr-control-analytics-report-v1"
_OUTCOMES = ("ALLOW", "DENY", "MODIFY", "STEP_UP", "DEFER", "ERROR")
_APPROVALS = {"none", "requested", "approved", "denied", "expired", "overridden"}
_HEX = frozenset("0123456789abcdef")


class ControlAnalyticsV1ValidationError(ValueError):
    pass


def _fail(message: str) -> None:
    raise ControlAnalyticsV1ValidationError(message)


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip().encode()) > 256:
        _fail(f"{field} must be nonblank and at most 256 UTF-8 bytes")
    return value.strip()


def _integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 9_007_199_254_740_991:
        _fail(f"{field} must be a nonnegative safe integer")
    return value


def _bps(count: int, total: int) -> int:
    return count * 10_000 // total if total else 0


def _percentile(values: List[int], fraction: float) -> int:
    ordered = sorted(values)
    return ordered[math.ceil(fraction * len(ordered)) - 1] if ordered else 0


def build_control_analytics_report_v1(events_input: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(events_input, list) or not 1 <= len(events_input) <= 100_000:
        _fail("events must contain between 1 and 100000 items")
    allowed = {"event_id", "workload_id", "policy_hash", "outcome", "shadow_outcome", "approval", "latency_ms", "coverage_complete", "evidence_complete", "occurred_at_ms"}
    events = []
    for index, item in enumerate(events_input):
        if not isinstance(item, dict):
            _fail(f"events[{index}] must be an object")
        unknown = set(item) - allowed
        if unknown:
            _fail(f"events[{index}] contains unsupported field: {sorted(unknown)[0]}")
        if item.get("outcome") not in _OUTCOMES or ("shadow_outcome" in item and item["shadow_outcome"] not in _OUTCOMES):
            _fail(f"events[{index}] outcome is invalid")
        if item.get("approval") not in _APPROVALS:
            _fail(f"events[{index}].approval is invalid")
        if not isinstance(item.get("coverage_complete"), bool) or not isinstance(item.get("evidence_complete"), bool):
            _fail(f"events[{index}] completeness fields must be boolean")
        policy_hash = item.get("policy_hash")
        if not isinstance(policy_hash, str) or len(policy_hash) != 64 or any(c not in _HEX for c in policy_hash):
            _fail(f"events[{index}].policy_hash is invalid")
        events.append({**item, "event_id": _text(item.get("event_id"), f"events[{index}].event_id"), "workload_id": _text(item.get("workload_id"), f"events[{index}].workload_id"), "latency_ms": _integer(item.get("latency_ms"), "latency_ms"), "occurred_at_ms": _integer(item.get("occurred_at_ms"), "occurred_at_ms")})
    if len({item["event_id"] for item in events}) != len(events):
        _fail("event_id values must be unique")
    outcomes = {outcome: sum(event["outcome"] == outcome for event in events) for outcome in _OUTCOMES}
    shadow = [event for event in events if "shadow_outcome" in event]
    shadow_changed = sum(event["shadow_outcome"] != event["outcome"] for event in shadow)
    approvals = {state: sum(event["approval"] == state for event in events) for state in ("requested", "approved", "denied", "expired", "overridden")}
    total = len(events)
    resolved = approvals["approved"] + approvals["denied"] + approvals["expired"] + approvals["overridden"]
    report = {"schema": CONTROL_ANALYTICS_REPORT_V1_SCHEMA, "window_start_ms": min(event["occurred_at_ms"] for event in events), "window_end_ms": max(event["occurred_at_ms"] for event in events), "input_event_count": total, "workload_ids": sorted({event["workload_id"] for event in events}), "policy_hashes": sorted({event["policy_hash"] for event in events}), "outcome_counts": outcomes, "control_action_bps": _bps(outcomes["DENY"] + outcomes["MODIFY"] + outcomes["STEP_UP"] + outcomes["DEFER"], total), "coverage_gap_count": sum(not event["coverage_complete"] for event in events), "evidence_gap_count": sum(not event["evidence_complete"] for event in events), "shadow": {"evaluated_count": len(shadow), "changed_count": shadow_changed, "changed_bps": _bps(shadow_changed, len(shadow))}, "approvals": {**approvals, "request_bps": _bps(sum(approvals.values()), total), "override_bps": _bps(approvals["overridden"], resolved)}, "latency_ms": {"p50": _percentile([event["latency_ms"] for event in events], 0.5), "p95": _percentile([event["latency_ms"] for event in events], 0.95), "max": max(event["latency_ms"] for event in events)}}
    return {**report, "report_hash": hashlib.sha256(f"obsvr-control-analytics/1\0{_canonical_json_for_hash(report)}".encode()).hexdigest()}
