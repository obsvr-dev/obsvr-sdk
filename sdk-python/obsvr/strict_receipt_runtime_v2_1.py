"""Decision-only strict profile-2.1 admission and action orchestration."""

from __future__ import annotations

import copy
import hashlib
import threading
from typing import Any, Dict

from .strict_admission_v2_1 import _transport_prepared_strict_receipt_v2_1
from .strict_receipt_prepared_state import DEFINITIVE_NO_STORE
from .tool_pinning import _canonical_json_for_hash

STRICT_RUNTIME_EXECUTION_JOURNAL_V2_1_SCHEMA = (
    "obsvr-strict-runtime-execution-journal-v2-1"
)


class StrictReceiptRuntimeV21Error(RuntimeError):
    """The profile-2.1 runtime cannot safely continue an operation."""


class _BoundArguments:
    __slots__ = ("arguments_hash", "_value")

    def __init__(self, value: Any) -> None:
        snapshot = copy.deepcopy(value)
        self.arguments_hash = hashlib.sha256(
            _canonical_json_for_hash(snapshot).encode("utf-8")
        ).hexdigest()
        self._value = snapshot

    def snapshot(self) -> Any:
        return copy.deepcopy(self._value)


def bind_strict_v2_1_json_arguments(value: Any) -> Any:
    """Snapshot bounded JSON and bind it to its canonical SHA-256."""
    return _BoundArguments(value)


class StrictReceiptRuntimeV21:
    """Persist, admit, commit, and only then invoke one governed decision."""

    def __init__(
        self,
        *,
        coordinator: Any,
        admission_config: Dict[str, Any],
        checkpoint_store: Any,
    ) -> None:
        if not callable(getattr(checkpoint_store, "save", None)):
            raise StrictReceiptRuntimeV21Error("durable checkpoint store is required")
        state = coordinator.inspect_state()
        self._tenant_id = self._text(state.get("tenant_id"), "tenant_id")
        self._session_id = self._text(state.get("session_id"), "session_id")
        self._coordinator = coordinator
        self._admission_config = copy.deepcopy(admission_config)
        self._checkpoint_store = checkpoint_store
        self._lock = threading.Lock()
        self._frozen_reason = None
        self._results: Dict[str, Dict[str, Any]] = {}

    def run_decision(
        self, *, decision: Dict[str, Any], action: Dict[str, Any]
    ) -> Dict[str, Any]:
        if self._frozen_reason is not None:
            raise StrictReceiptRuntimeV21Error(
                f"strict 2.1 runtime is frozen: {self._frozen_reason}"
            )
        action_id = self._text(action.get("runtime_action_id"), "runtime_action_id")
        fingerprint = self._fingerprint(decision, action)
        prior = self._results.get(action_id)
        if prior is not None:
            if prior["fingerprint"] != fingerprint:
                raise StrictReceiptRuntimeV21Error(
                    "runtime_action_id was reused with different input"
                )
            return prior["result"]
        if not self._lock.acquire(blocking=False):
            raise StrictReceiptRuntimeV21Error("strict 2.1 runtime is busy")
        try:
            prior = self._results.get(action_id)
            if prior is not None:
                if prior["fingerprint"] != fingerprint:
                    raise StrictReceiptRuntimeV21Error(
                        "runtime_action_id was reused with different input"
                    )
                return prior["result"]
            return self._run_locked(decision, action, action_id, fingerprint)
        finally:
            self._lock.release()

    def _run_locked(
        self,
        decision: Dict[str, Any],
        action: Dict[str, Any],
        action_id: str,
        fingerprint: str,
    ) -> Dict[str, Any]:
        prepared = self._coordinator.prepare_decision(decision)
        receipt = copy.deepcopy(prepared["value"]["receipt"])
        base = {"receipt": receipt, "receipt_hash": prepared["receipt_hash"]}
        if receipt["body"]["action"]["action_id"] != action_id:
            self._coordinator.abort_prepared(
                prepared["token"], prepared["receipt_hash"], DEFINITIVE_NO_STORE
            )
            return self._finish(
                action_id,
                fingerprint,
                {**base, "status": "nonexecuted", "reason": "binding_unavailable"},
            )
        arguments = (
            self._execution_arguments(action, receipt)
            if receipt["body"]["execution_authorized"]
            else (True, None)
        )
        if not arguments[0]:
            self._coordinator.abort_prepared(
                prepared["token"], prepared["receipt_hash"], DEFINITIVE_NO_STORE
            )
            return self._finish(
                action_id,
                fingerprint,
                {**base, "status": "nonexecuted", "reason": "binding_unavailable"},
            )
        try:
            self._persist(
                "prepared",
                prepared,
                receipt,
                action_id,
                fingerprint,
                include_receipt=True,
            )
        except Exception as error:
            self._coordinator.abort_prepared(
                prepared["token"], prepared["receipt_hash"], DEFINITIVE_NO_STORE
            )
            return self._finish(
                action_id,
                fingerprint,
                {
                    **base,
                    "status": "nonexecuted",
                    "reason": "checkpoint_persist_failed",
                    "error": error,
                },
            )
        try:
            admission = _transport_prepared_strict_receipt_v2_1(
                self._coordinator, prepared, **self._admission_config
            )
        except Exception as error:
            self._freeze_prepared(prepared, "admission_threw")
            return self._finish(
                action_id,
                fingerprint,
                {
                    **base,
                    "status": "nonexecuted",
                    "reason": "admission_uncertain",
                    "error": error,
                },
            )
        if admission["disposition"] == "definitive_no_store":
            self._coordinator.abort_prepared(
                prepared["token"], prepared["receipt_hash"], DEFINITIVE_NO_STORE
            )
            try:
                self._persist(
                    "terminal",
                    prepared,
                    receipt,
                    action_id,
                    fingerprint,
                    include_receipt=False,
                    terminal_status="nonexecuted",
                )
            except Exception as error:
                self._frozen_reason = "journal_terminal_failed"
                return self._finish(
                    action_id,
                    fingerprint,
                    {
                        **base,
                        "status": "nonexecuted",
                        "reason": "checkpoint_persist_failed",
                        "admission": admission,
                        "error": error,
                    },
                )
            return self._finish(
                action_id,
                fingerprint,
                {
                    **base,
                    "status": "nonexecuted",
                    "reason": "definitive_no_store",
                    "admission": admission,
                },
            )
        if admission["disposition"] != "accepted":
            self._coordinator.freeze_prepared(
                prepared["token"],
                prepared["receipt_hash"],
                f"admission_{admission['reason']}",
            )
            self._frozen_reason = f"admission_{admission['reason']}"
            return self._finish(
                action_id,
                fingerprint,
                {
                    **base,
                    "status": "nonexecuted",
                    "reason": "admission_uncertain",
                    "admission": admission,
                },
            )
        try:
            self._persist(
                "remote_accepted",
                prepared,
                receipt,
                action_id,
                fingerprint,
                include_receipt=True,
            )
        except Exception as error:
            self._freeze_prepared(prepared, "remote_accepted_journal_failed")
            return self._finish(
                action_id,
                fingerprint,
                {
                    **base,
                    "status": "nonexecuted",
                    "reason": "checkpoint_persist_failed",
                    "admission": admission,
                    "error": error,
                },
            )
        try:
            self._coordinator.commit_prepared(
                prepared["token"], prepared["receipt_hash"]
            )
        except Exception as error:
            self._freeze_prepared(prepared, "accepted_but_local_commit_failed")
            return self._finish(
                action_id,
                fingerprint,
                {
                    **base,
                    "status": "nonexecuted",
                    "reason": "admission_uncertain",
                    "admission": admission,
                    "error": error,
                },
            )
        try:
            self._persist(
                "committed",
                prepared,
                receipt,
                action_id,
                fingerprint,
                include_receipt=False,
            )
        except Exception as error:
            self._frozen_reason = "committed_journal_failed"
            return self._finish(
                action_id,
                fingerprint,
                {
                    **base,
                    "status": "nonexecuted",
                    "reason": "checkpoint_persist_failed",
                    "admission": admission,
                    "error": error,
                },
            )
        if not receipt["body"]["execution_authorized"]:
            try:
                self._persist(
                    "terminal",
                    prepared,
                    receipt,
                    action_id,
                    fingerprint,
                    include_receipt=False,
                    terminal_status="nonexecuted",
                )
            except Exception as error:
                self._frozen_reason = "terminal_journal_failed"
                return self._finish(
                    action_id,
                    fingerprint,
                    {
                        **base,
                        "status": "nonexecuted",
                        "reason": "checkpoint_persist_failed",
                        "admission": admission,
                        "error": error,
                    },
                )
            return self._finish(
                action_id,
                fingerprint,
                {
                    **base,
                    "status": "nonexecuted",
                    "reason": "not_authorized",
                    "admission": admission,
                },
            )
        try:
            self._persist(
                "invocation_started",
                prepared,
                receipt,
                action_id,
                fingerprint,
                include_receipt=False,
            )
        except Exception as error:
            self._frozen_reason = "invocation_started_journal_failed"
            return self._finish(
                action_id,
                fingerprint,
                {
                    **base,
                    "status": "nonexecuted",
                    "reason": "checkpoint_persist_failed",
                    "admission": admission,
                    "error": error,
                },
            )
        in_progress = {
            **base,
            "status": "invocation_uncertain",
            "admission": admission,
            "error": StrictReceiptRuntimeV21Error(
                "action invocation is already in progress"
            ),
        }
        self._results[action_id] = {
            "fingerprint": fingerprint,
            "result": in_progress,
        }
        try:
            value = action["invoke"](arguments[1])
            try:
                self._persist(
                    "terminal",
                    prepared,
                    receipt,
                    action_id,
                    fingerprint,
                    include_receipt=False,
                    terminal_status="executed",
                )
            except Exception as error:
                self._frozen_reason = "terminal_journal_failed"
                return self._finish(
                    action_id,
                    fingerprint,
                    {
                        **base,
                        "status": "invocation_uncertain",
                        "admission": admission,
                        "error": error,
                    },
                )
            return self._finish(
                action_id,
                fingerprint,
                {**base, "status": "executed", "admission": admission, "value": value},
            )
        except Exception as error:
            try:
                self._persist(
                    "terminal",
                    prepared,
                    receipt,
                    action_id,
                    fingerprint,
                    include_receipt=False,
                    terminal_status="invocation_failed",
                )
            except Exception as journal_error:
                self._frozen_reason = "terminal_journal_failed"
                return self._finish(
                    action_id,
                    fingerprint,
                    {
                        **base,
                        "status": "invocation_uncertain",
                        "admission": admission,
                        "error": journal_error,
                    },
                )
            return self._finish(
                action_id,
                fingerprint,
                {
                    **base,
                    "status": "invocation_failed",
                    "admission": admission,
                    "error": error,
                },
            )

    @staticmethod
    def _execution_arguments(action: Dict[str, Any], receipt: Dict[str, Any]):
        modified = receipt["body"]["outcome"] == "MODIFY"
        bound = action.get("effective_arguments" if modified else "original_arguments")
        expected = receipt["body"]["action"].get(
            "effective_arguments_hash" if modified else "arguments_hash"
        )
        if not isinstance(bound, _BoundArguments) or bound.arguments_hash != expected:
            return False, None
        return True, bound.snapshot()

    def _persist(
        self,
        phase: str,
        prepared: Dict[str, Any],
        receipt: Dict[str, Any],
        action_id: str,
        fingerprint: str,
        *,
        include_receipt: bool,
        terminal_status: str | None = None,
    ) -> None:
        coordinator_state = self._coordinator.inspect_state()
        checkpoint = {
            "schema": STRICT_RUNTIME_EXECUTION_JOURNAL_V2_1_SCHEMA,
            "profile_version": "2.1",
            "phase": phase,
            "tenant_id": self._tenant_id,
            "session_id": self._session_id,
            "runtime_action_id": action_id,
            "operation_fingerprint": fingerprint,
            "prepared_token": prepared["token"],
            "receipt_hash": receipt["receipt_hash"],
            "committed_sequence": coordinator_state["sequence"],
            "committed_head_receipt_hash": coordinator_state["head_receipt_hash"],
        }
        if terminal_status is not None:
            checkpoint["terminal_status"] = terminal_status
        if include_receipt:
            checkpoint["receipt"] = copy.deepcopy(receipt)
        self._checkpoint_store.save(copy.deepcopy(checkpoint))

    def _freeze_prepared(self, prepared: Dict[str, Any], reason: str) -> None:
        self._frozen_reason = reason
        try:
            self._coordinator.freeze_prepared(
                prepared["token"], prepared["receipt_hash"], reason
            )
        except Exception:
            pass

    def _finish(
        self, action_id: str, fingerprint: str, result: Dict[str, Any]
    ) -> Dict[str, Any]:
        self._results[action_id] = {"fingerprint": fingerprint, "result": result}
        return result

    def _fingerprint(self, decision: Dict[str, Any], action: Dict[str, Any]) -> str:
        original = action.get("original_arguments")
        effective = action.get("effective_arguments")
        return hashlib.sha256(
            _canonical_json_for_hash(
                {
                    "schema": "obsvr-strict-runtime-operation-v2-1",
                    "tenant_id": self._tenant_id,
                    "session_id": self._session_id,
                    "decision": decision,
                    "runtime_action_id": action.get("runtime_action_id"),
                    "original_arguments_hash": getattr(
                        original, "arguments_hash", None
                    ),
                    "effective_arguments_hash": getattr(
                        effective, "arguments_hash", None
                    ),
                }
            ).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _text(value: Any, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise StrictReceiptRuntimeV21Error(f"{field} must be nonblank")
        return value
