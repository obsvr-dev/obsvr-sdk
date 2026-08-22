"""Recoverable strict v2 coordinator with authenticated durable checkpoints."""

from __future__ import annotations

import copy
from typing import Any, Dict, Optional

from .strict_receipt_coordinator_v2 import StrictReceiptCoordinatorV2
from .strict_receipt_coordinator_v2_support import build_coordinator_context_v2
from .strict_receipt_reconcile_v2 import (
    assert_accepted_strict_reconciliation_v2,
)
from .strict_receipt_recovery_v2 import (
    sign_strict_recovery_v2,
    verify_strict_recovery_v2,
)


class RecoverableStrictReceiptCoordinatorV2(StrictReceiptCoordinatorV2):
    """Persist exact prepared state and reconcile it without action invocation."""

    def __init__(
        self,
        *,
        recovery_checkpoint: Optional[Dict[str, Any]] = None,
        expected_origin_pid: Optional[int] = None,
        **options: Any,
    ) -> None:
        super().__init__(**options)
        self._recovery_prepared: Optional[Dict[str, Any]] = None
        if recovery_checkpoint is not None:
            document = verify_strict_recovery_v2(recovery_checkpoint, options["signer"])
            self._restore(document, expected_origin_pid)

    def prepare_decision(self, **value: Any) -> Dict[str, Any]:
        with self._lock:
            self._assert_recovery_ready()
            context = build_coordinator_context_v2(
                value["context"], self._session_id, self._prior_actions
            )
            prepared = super().prepare_decision(**value)
            result = prepared["value"]
            self._recovery_prepared = {
                "kind": "decision",
                "receipt": copy.deepcopy(result["receipt"]),
                "context": context,
                "base_result": copy.deepcopy(value["base_result"]),
                "evaluation": copy.deepcopy(result["evaluation"]),
            }
            return prepared

    def prepare_resolution(self, **value: Any) -> Dict[str, Any]:
        with self._lock:
            self._assert_recovery_ready()
            prepared = super().prepare_resolution(**value)
            self._recovery_prepared = {
                "kind": "resolution",
                "receipt": copy.deepcopy(prepared["value"]),
                "suspended_receipt_hash": value["suspended_receipt_hash"],
            }
            return prepared

    def prepare_timeout(self, **value: Any) -> Dict[str, Any]:
        with self._lock:
            self._assert_recovery_ready()
            prepared = super().prepare_timeout(**value)
            self._recovery_prepared = {
                "kind": "timeout",
                "receipt": copy.deepcopy(prepared["value"]),
                "suspended_receipt_hash": value["suspended_receipt_hash"],
            }
            return prepared

    def commit_prepared(self, token: str, receipt_hash: str) -> Any:
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
            return self._export_recovery_checkpoint()

    def _export_recovery_checkpoint(self) -> Dict[str, Any]:
        suspended = [
            {
                "receipt_hash": receipt_hash,
                "receipt": copy.deepcopy(value["receipt"]),
                "context": copy.deepcopy(value["context"]),
                "base_result": copy.deepcopy(value["base_result"]),
            }
            for receipt_hash, value in self._suspended.items()
        ]
        document = {
            "schema": "obsvr-strict-receipt-recovery-v2",
            "profile_version": "2.0",
            "tenant_id": self._tenant_id,
            "session_id": self._session_id,
            "sdk_language": "python",
            "sdk_version": self._sdk_version,
            "origin_pid": self._owner_pid,
            "committed": {
                "sequence": self._sequence,
                "head_receipt_hash": self._last_receipt_hash,
                "last_timestamp_ms": self._last_timestamp,
                "prior_actions": copy.deepcopy(self._prior_actions),
                "suspended": suspended,
                "resolved_receipt_hashes": sorted(self._resolved),
                "action_ids": sorted(self._action_ids),
                "approval_requests": [
                    {"request_id": request_id, "receipt_hash": receipt_hash}
                    for request_id, receipt_hash in sorted(
                        self._approval_requests.items()
                    )
                ],
            },
        }
        if self._recovery_prepared is not None:
            document["prepared"] = copy.deepcopy(self._recovery_prepared)
        return sign_strict_recovery_v2(document, self._signer)

    def reconcile_recovered_accepted(self, proof: Any) -> Dict[str, Any]:
        with self._lock:
            self._ensure_process()
            pending = self._recovery_prepared
            if pending is None:
                raise ValueError("no recovered receipt is pending")
            assert_accepted_strict_reconciliation_v2(proof, pending["receipt"])
            if pending["kind"] == "decision":
                self._commit_decision(
                    {
                        "evaluation": pending["evaluation"],
                        "receipt": pending["receipt"],
                    },
                    pending["context"],
                    pending["base_result"],
                )
            else:
                receipt_hash = pending.get("suspended_receipt_hash")
                index = next(
                    (
                        index
                        for index, item in enumerate(self._prior_actions)
                        if item["receipt_hash"] == receipt_hash
                    ),
                    None,
                )
                if index is None:
                    raise ValueError("recovered suspension summary is missing")
                self._commit_resolution(pending["receipt"], receipt_hash, index)
            self._recovery_prepared = None
            return copy.deepcopy(pending["receipt"])

    def _restore(self, document: Dict[str, Any], expected_origin_pid: Any) -> None:
        if (
            isinstance(expected_origin_pid, bool)
            or not isinstance(expected_origin_pid, int)
            or document["origin_pid"] != expected_origin_pid
        ):
            raise ValueError("recovery origin PID mismatch")
        if (
            document["tenant_id"] != self._tenant_id
            or document["session_id"] != self._session_id
            or document["sdk_version"] != self._sdk_version
        ):
            raise ValueError("recovery tenant/session/sdk mismatch")
        state = document["committed"]
        self._sequence = state["sequence"]
        self._last_receipt_hash = state["head_receipt_hash"]
        self._last_timestamp = state["last_timestamp_ms"]
        self._prior_actions = copy.deepcopy(state["prior_actions"])
        self._suspended = {
            item["receipt_hash"]: {
                "receipt": copy.deepcopy(item["receipt"]),
                "context": copy.deepcopy(item["context"]),
                "base_result": copy.deepcopy(item["base_result"]),
            }
            for item in state["suspended"]
        }
        self._resolved = set(state["resolved_receipt_hashes"])
        self._action_ids = set(state["action_ids"])
        self._approval_requests = {
            item["request_id"]: item["receipt_hash"]
            for item in state["approval_requests"]
        }
        self._recovery_prepared = copy.deepcopy(document.get("prepared"))

    def _assert_recovery_ready(self) -> None:
        if self._recovery_prepared is not None:
            raise ValueError(
                "recovered receipt requires reconciliation before new work"
            )
