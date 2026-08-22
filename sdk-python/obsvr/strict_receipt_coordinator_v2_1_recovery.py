"""Recoverable profile-2.1 coordinator with authenticated checkpoints."""

from __future__ import annotations

import copy
from typing import Any, Dict, Optional

from .strict_receipt_coordinator_v2_1 import StrictReceiptCoordinatorV21
from .strict_receipt_coordinator_v2_1_support import normalize_decision_action_v2_1
from .strict_receipt_reconcile_v2_1 import assert_accepted_strict_reconciliation_v2_1
from .strict_receipt_recovery_v2_1 import (
    sign_strict_recovery_v2_1,
    verify_strict_recovery_v2_1,
)


class RecoverableStrictReceiptCoordinatorV21(StrictReceiptCoordinatorV21):
    """Restore a prepared decision, reconcile it, and never invoke an action."""

    def __init__(
        self,
        *,
        sdk_version: str,
        recovery_checkpoint: Optional[Dict[str, Any]] = None,
        expected_origin_pid: Optional[int] = None,
        **options: Any,
    ) -> None:
        super().__init__(**options)
        if not isinstance(sdk_version, str) or not sdk_version.strip():
            raise ValueError("sdk_version must be nonblank")
        self._sdk_version = sdk_version
        self._recovery_prepared: Optional[Dict[str, Any]] = None
        if recovery_checkpoint is not None:
            document = verify_strict_recovery_v2_1(
                recovery_checkpoint, options["signer"]
            )
            self._restore(document, expected_origin_pid)

    def prepare_decision(self, input_value: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            self._assert_recovery_ready()
            normalized = normalize_decision_action_v2_1(input_value)
            prepared = super().prepare_decision(normalized)
            self._recovery_prepared = {
                "kind": "decision",
                "input": copy.deepcopy(normalized),
                "result": copy.deepcopy(prepared["value"]),
            }
            return prepared

    def commit_prepared(self, token: str, receipt_hash: str) -> Dict[str, Any]:
        result = super().commit_prepared(token, receipt_hash)
        self._recovery_prepared = None
        return result

    def abort_prepared(self, token: str, receipt_hash: str, capability: Any) -> None:
        super().abort_prepared(token, receipt_hash, capability)
        self._recovery_prepared = None

    def inspect_state(self) -> Dict[str, Any]:
        state = super().inspect_state()
        if self._recovery_prepared is not None and "prepared" not in state:
            state.update(frozen=True, freeze_reason="restart_reconciliation_required")
        return state

    def export_recovery_checkpoint(self) -> Dict[str, Any]:
        with self._lock:
            self._ensure_process()
            document = {
                "schema": "obsvr-strict-receipt-recovery-v2-1",
                "profile_version": "2.1",
                "tenant_id": self._tenant_id,
                "session_id": self._session_id,
                "sdk_language": "python",
                "sdk_version": self._sdk_version,
                "origin_pid": self._owner_pid,
                "committed": {
                    "sequence": self._sequence,
                    "head_receipt_hash": self._head_receipt_hash,
                    "last_timestamp_ms": self._last_timestamp,
                    "prior_actions": copy.deepcopy(self._prior_actions),
                    "action_ids": sorted(self._committed_action_ids),
                    "pending_approval_ids": sorted(self._pending_approval_ids),
                },
            }
            if self._recovery_prepared is not None:
                document["prepared"] = copy.deepcopy(self._recovery_prepared)
            return sign_strict_recovery_v2_1(document, self._signer)

    def reconcile_recovered_accepted(self, proof: Any) -> Dict[str, Any]:
        with self._lock:
            self._ensure_process()
            pending = self._recovery_prepared
            if pending is None:
                raise ValueError("no recovered decision is pending")
            receipt = pending["result"]["receipt"]
            assert_accepted_strict_reconciliation_v2_1(proof, receipt)
            self._commit_decision(pending["result"], pending["input"])
            self._recovery_prepared = None
            return copy.deepcopy(receipt)

    def _restore(self, document: Dict[str, Any], expected_origin_pid: Any) -> None:
        if (
            isinstance(expected_origin_pid, bool)
            or not isinstance(expected_origin_pid, int)
            or expected_origin_pid < 0
            or document["origin_pid"] != expected_origin_pid
        ):
            raise ValueError("recovery origin PID mismatch")
        if (
            document["tenant_id"] != self._tenant_id
            or document["session_id"] != self._session_id
            or document["sdk_language"] != "python"
            or document["sdk_version"] != self._sdk_version
            or document["profile_version"] != "2.1"
        ):
            raise ValueError("recovery tenant/session/sdk/profile mismatch")
        state = document["committed"]
        self._sequence = state["sequence"]
        self._head_receipt_hash = state["head_receipt_hash"]
        self._last_timestamp = state["last_timestamp_ms"]
        self._prior_actions = copy.deepcopy(state["prior_actions"])
        self._committed_action_ids = set(state["action_ids"])
        self._pending_approval_ids = set(state["pending_approval_ids"])
        self._recovery_prepared = copy.deepcopy(document.get("prepared"))

    def _assert_recovery_ready(self) -> None:
        if self._recovery_prepared is not None:
            raise ValueError(
                "recovered decision requires accepted reconciliation before new work"
            )


__all__ = ["RecoverableStrictReceiptCoordinatorV21"]
