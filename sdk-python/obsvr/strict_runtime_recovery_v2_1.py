"""Validate and reconcile self-contained strict 2.1 execution journals."""

from __future__ import annotations

import copy
from typing import Any, Dict, Optional, Sequence

from .strict_execution_outcome_v2_1 import (
    strict_execution_start_v2_1_hash,
    verify_strict_execution_outcome_v2_1,
)
from .strict_receipt_v2_1_verify import verify_strict_receipt_v2_1
from .tool_pinning import _canonical_json_for_hash

_BASE_KEYS = {
    "schema",
    "profile_version",
    "phase",
    "tenant_id",
    "session_id",
    "runtime_action_id",
    "operation_fingerprint",
    "prepared_token",
    "receipt_hash",
    "committed_sequence",
    "committed_head_receipt_hash",
    "receipt",
}
_OPTIONAL_KEYS = {
    "terminal_status",
    "execution_start",
    "execution_start_hash",
    "execution_outcome",
}
_PHASES = {
    "prepared",
    "remote_accepted",
    "committed",
    "invocation_started",
    "terminal",
}
_TERMINAL = {
    "executed",
    "invocation_failed",
    "invocation_uncertain",
    "nonexecuted",
}
_HEX = frozenset("0123456789abcdef")
_MAX_SAFE = 9_007_199_254_740_991


class StrictRuntimeRecoveryV21Error(ValueError):
    """A runtime journal or supplied terminal outcome is not trustworthy."""


def _fail(message: str) -> None:
    raise StrictRuntimeRecoveryV21Error(message)


def _record(value: Any, field: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{field} must be an object")
    return value


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _fail(f"{field} must be nonblank")
    return value


def _integer(value: Any, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= _MAX_SAFE
    ):
        _fail(f"{field} must be a nonnegative safe integer")
    return value


def _hash(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in _HEX for char in value)
    ):
        _fail(f"{field} must be a SHA-256 hash")
    return value


def _same(left: Any, right: Any) -> bool:
    try:
        return _canonical_json_for_hash(left) == _canonical_json_for_hash(right)
    except Exception:
        return False


def _expected_terminal(status: str) -> str:
    if status == "succeeded":
        return "executed"
    if status == "failed":
        return "invocation_failed"
    if status == "uncertain":
        return "invocation_uncertain"
    _fail("execution outcome has an unsupported status")


def _validate_start(journal: Dict[str, Any], receipt: Dict[str, Any]) -> None:
    start = _record(journal.get("execution_start"), "execution_start")
    required = {
        "tenant_id",
        "session_id",
        "action_id",
        "decision_receipt_hash",
        "operation_fingerprint",
        "attempt",
        "started_at_ms",
    }
    if set(start) != required:
        _fail("execution_start contains missing or unsupported fields")
    start_hash = _hash(journal.get("execution_start_hash"), "execution_start_hash")
    if (
        start["tenant_id"] != journal["tenant_id"]
        or start["session_id"] != journal["session_id"]
        or start["action_id"] != journal["runtime_action_id"]
        or start["decision_receipt_hash"] != journal["receipt_hash"]
        or start["operation_fingerprint"] != journal["operation_fingerprint"]
        or start["attempt"] != 1
        or start["started_at_ms"] < receipt["body"]["timestamp_ms"]
        or strict_execution_start_v2_1_hash(start) != start_hash
    ):
        _fail("execution_start does not bind the journal and decision receipt")


def _validate_journal(
    value: Any,
    trusted_agent_keys: Sequence[Dict[str, Any]],
    allowed_evaluator_manifest_hashes: Sequence[str],
) -> tuple[Dict[str, Any], bool]:
    root = _record(value, "runtime journal")
    if set(root) - _BASE_KEYS - _OPTIONAL_KEYS or _BASE_KEYS - set(root):
        _fail("runtime journal contains missing or unsupported fields")
    if (
        root.get("schema") != "obsvr-strict-runtime-execution-journal-v2-1"
        or root.get("profile_version") != "2.1"
        or root.get("phase") not in _PHASES
    ):
        _fail("runtime journal schema, profile, or phase is invalid")
    for field in ("tenant_id", "session_id", "runtime_action_id", "prepared_token"):
        _text(root.get(field), field)
    _hash(root.get("operation_fingerprint"), "operation_fingerprint")
    _hash(root.get("receipt_hash"), "receipt_hash")
    _integer(root.get("committed_sequence"), "committed_sequence")
    if root.get("committed_head_receipt_hash") is not None:
        _hash(root["committed_head_receipt_hash"], "committed_head_receipt_hash")
    journal = copy.deepcopy(root)
    receipt = _record(journal["receipt"], "receipt")
    verification = verify_strict_receipt_v2_1(
        receipt,
        trusted_agent_keys=trusted_agent_keys,
        allowed_evaluator_manifest_hashes=allowed_evaluator_manifest_hashes,
    )
    if (
        not verification["integrity_valid"]
        or receipt["body"].get("record_type") != "decision"
        or receipt["body"].get("profile_version") != "2.1"
        or receipt.get("receipt_hash") != journal["receipt_hash"]
        or receipt["body"].get("tenant_id") != journal["tenant_id"]
        or receipt["body"].get("session_id") != journal["session_id"]
        or receipt["body"]["action"].get("action_id")
        != journal["runtime_action_id"]
    ):
        _fail("runtime journal does not contain its intact bound decision receipt")
    current = (
        journal["committed_sequence"] == receipt["body"]["sequence"]
        and journal["committed_head_receipt_hash"] == receipt["receipt_hash"]
    )
    previous = (
        journal["committed_sequence"] == receipt["body"]["sequence"] - 1
        and journal["committed_head_receipt_hash"]
        == receipt["body"]["previous_receipt_hash"]
    )
    if journal["phase"] in ("prepared", "remote_accepted") and not previous:
        _fail("pre-commit journal does not continue the prior receipt head")
    if journal["phase"] in ("committed", "invocation_started") and not current:
        _fail("committed journal does not match the decision receipt head")
    if journal["phase"] != "terminal" and "terminal_status" in journal:
        _fail("only terminal journals can contain terminal_status")
    if journal["phase"] == "invocation_started":
        if "execution_outcome" in journal:
            _fail("started journal cannot contain an outcome")
        _validate_start(journal, receipt)
    elif journal["phase"] != "terminal" and any(
        field in journal
        for field in ("execution_start", "execution_start_hash", "execution_outcome")
    ):
        _fail("pre-invocation journal cannot contain execution evidence")
    if journal["phase"] == "terminal":
        terminal = journal.get("terminal_status")
        if terminal not in _TERMINAL:
            _fail("terminal journal requires a supported terminal_status")
        if terminal == "nonexecuted":
            if not current and not previous:
                _fail("nonexecuted journal does not match a receipt head")
            if any(
                field in journal
                for field in (
                    "execution_start",
                    "execution_start_hash",
                    "execution_outcome",
                )
            ):
                _fail("nonexecuted journal cannot contain execution evidence")
        else:
            if not current or "execution_outcome" not in journal:
                _fail("executed terminal journal requires committed execution evidence")
            _validate_start(journal, receipt)
    return journal, verification["trusted"]


def reconcile_strict_runtime_execution_v2_1(
    value: Any,
    outcome: Optional[Dict[str, Any]] = None,
    *,
    trusted_agent_keys: Sequence[Dict[str, Any]] = (),
    allowed_evaluator_manifest_hashes: Sequence[str] = (),
) -> Dict[str, Any]:
    journal, decision_trusted = _validate_journal(
        value, trusted_agent_keys, allowed_evaluator_manifest_hashes
    )
    phase = journal["phase"]
    if phase in ("prepared", "remote_accepted", "committed"):
        if outcome is not None:
            _fail("pre-invocation journal cannot accept an outcome")
        return {
            "status": "pre_invocation",
            "retry_safe": False,
            "decision_trusted": decision_trusted,
            "journal": journal,
        }
    if phase == "terminal" and journal["terminal_status"] == "nonexecuted":
        if outcome is not None:
            _fail("nonexecuted journal cannot accept an outcome")
        return {
            "status": "resolved",
            "retry_safe": False,
            "terminal_status": "nonexecuted",
            "decision_trusted": decision_trusted,
            "journal": journal,
        }
    candidate = outcome if outcome is not None else journal.get("execution_outcome")
    if candidate is None:
        return {
            "status": "outcome_unresolved",
            "retry_safe": False,
            "decision_trusted": decision_trusted,
            "journal": journal,
        }
    if "execution_outcome" in journal and not _same(
        journal["execution_outcome"], candidate
    ):
        _fail("supplied outcome conflicts with the terminal journal")
    verification = verify_strict_execution_outcome_v2_1(
        candidate,
        journal["receipt"],
        trusted_agent_keys=trusted_agent_keys,
        allowed_evaluator_manifest_hashes=allowed_evaluator_manifest_hashes,
    )
    if not verification["integrity_valid"]:
        _fail("execution outcome is not intact or bound to the journal")
    terminal_status = _expected_terminal(candidate["body"]["status"])
    if (
        "terminal_status" in journal
        and journal["terminal_status"] != terminal_status
    ):
        _fail("execution outcome conflicts with terminal_status")
    terminal = {
        **journal,
        "phase": "terminal",
        "terminal_status": terminal_status,
        "execution_outcome": copy.deepcopy(candidate),
    }
    return {
        "status": "resolved",
        "retry_safe": False,
        "terminal_status": terminal_status,
        "decision_trusted": decision_trusted,
        "outcome_integrity_valid": True,
        "outcome_trusted": verification["trusted"],
        "journal": terminal,
    }


__all__ = [
    "StrictRuntimeRecoveryV21Error",
    "reconcile_strict_runtime_execution_v2_1",
]
