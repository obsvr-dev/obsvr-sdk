"""Terminal-outcome construction helpers for the strict 2.1 runtime."""

from __future__ import annotations

import hashlib
from typing import Any, Callable, Dict, Optional

from .strict_execution_outcome_v2_1 import (
    STRICT_EXECUTION_OUTCOME_V2_1_SCHEMA,
    strict_execution_result_v2_1_hash,
    strict_execution_start_v2_1_hash,
)
from .tool_pinning import _canonical_json_for_hash


def create_strict_runtime_execution_start_v2_1(
    receipt: Dict[str, Any], operation_fingerprint: str, started_at_ms: int
) -> Dict[str, Any]:
    start = {
        "tenant_id": receipt["body"]["tenant_id"],
        "session_id": receipt["body"]["session_id"],
        "action_id": receipt["body"]["action"]["action_id"],
        "decision_receipt_hash": receipt["receipt_hash"],
        "operation_fingerprint": operation_fingerprint,
        "attempt": 1,
        "started_at_ms": started_at_ms,
    }
    return {
        **start,
        "execution_start_hash": strict_execution_start_v2_1_hash(start),
    }


def _outcome_id(receipt_hash: str, operation_fingerprint: str) -> str:
    canonical = _canonical_json_for_hash(
        {
            "schema": "obsvr-strict-runtime-outcome-id-v2-1",
            "receipt_hash": receipt_hash,
            "operation_fingerprint": operation_fingerprint,
            "attempt": 1,
        }
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _base(
    receipt: Dict[str, Any], start: Dict[str, Any], completed_at_ms: int
) -> Dict[str, Any]:
    return {
        "schema": STRICT_EXECUTION_OUTCOME_V2_1_SCHEMA,
        "profile_version": "2.1",
        "record_type": "execution_outcome",
        "outcome_id": _outcome_id(
            receipt["receipt_hash"], start["operation_fingerprint"]
        ),
        "tenant_id": start["tenant_id"],
        "session_id": start["session_id"],
        "action_id": start["action_id"],
        "decision_receipt_hash": start["decision_receipt_hash"],
        "decision_sequence": receipt["body"]["sequence"],
        "operation_fingerprint": start["operation_fingerprint"],
        "attempt": 1,
        "started_at_ms": start["started_at_ms"],
        "execution_start_hash": start["execution_start_hash"],
        "completed_at_ms": completed_at_ms,
    }


def create_strict_runtime_success_outcome_v2_1(
    receipt: Dict[str, Any],
    start: Dict[str, Any],
    completed_at_ms: int,
    result_projection: Any,
) -> Dict[str, Any]:
    return {
        **_base(receipt, start, completed_at_ms),
        "status": "succeeded",
        "result_hash": strict_execution_result_v2_1_hash(result_projection),
    }


def create_strict_runtime_error_outcome_v2_1(
    receipt: Dict[str, Any],
    start: Dict[str, Any],
    completed_at_ms: int,
    classification: Dict[str, str],
) -> Dict[str, Any]:
    return {
        **_base(receipt, start, completed_at_ms),
        "status": classification["status"],
        "error_code": classification["error_code"],
    }


def default_strict_runtime_result_projection_v2_1() -> Dict[str, str]:
    return {"schema": "obsvr-strict-runtime-result-v2-1", "status": "succeeded"}


def classify_strict_runtime_error_v2_1(
    error: Any,
    classifier: Optional[Callable[[Any], Dict[str, str]]],
) -> Dict[str, str]:
    if classifier is None:
        return {"status": "uncertain", "error_code": "action_error_unclassified"}
    try:
        result = classifier(error)
        if (
            isinstance(result, dict)
            and result.get("status") in ("failed", "uncertain")
            and isinstance(result.get("error_code"), str)
        ):
            return result
    except Exception:
        pass
    return {"status": "uncertain", "error_code": "error_classification_failed"}
