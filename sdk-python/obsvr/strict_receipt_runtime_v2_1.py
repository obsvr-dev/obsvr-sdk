"""Strict profile-2.1 admission and action orchestration."""

from __future__ import annotations

import copy
from typing import Any, Dict

from .strict_admission_v2_1 import _transport_prepared_strict_receipt_v2_1
from .strict_receipt_prepared_state import DEFINITIVE_NO_STORE
from .strict_receipt_runtime_v2_1_execution import (
    execute_committed_strict_action_v2_1,
)
from .strict_receipt_runtime_v2_1_support import (
    TRUSTED_RUNTIMES as _TRUSTED_RUNTIMES,
    TRUSTED_APPROVAL_RUNTIME_RUNNERS as _TRUSTED_APPROVAL_RUNTIME_RUNNERS,
    TRUSTED_RUNTIME_RUNNERS as _TRUSTED_RUNTIME_RUNNERS,
    TRUSTED_RUNTIME_STATES as _TRUSTED_RUNTIME_STATES,
    BoundCheckpointStore as _BoundCheckpointStore,
    BoundCoordinator as _BoundCoordinator,
    RuntimeState as _RuntimeState,
    StrictReceiptRuntimeV21Error,
    approval_runtime_fingerprint as _approval_runtime_fingerprint,
    bind_strict_v2_1_json_arguments,  # noqa: F401
    finish_runtime_result as _finish_runtime_result,
    freeze_prepared_runtime as _freeze_prepared_runtime,
    persist_runtime_checkpoint as _persist_runtime_checkpoint,
    read_execution_arguments as _read_execution_arguments,
    runtime_fingerprint as _runtime_fingerprint,
    runtime_state as _runtime_state,
    runtime_text as _runtime_text,
)

STRICT_RUNTIME_EXECUTION_JOURNAL_V2_1_SCHEMA = (
    "obsvr-strict-runtime-execution-journal-v2-1"
)


class StrictReceiptRuntimeV21:
    """Persist, admit, commit, and only then invoke a governed action."""

    __slots__ = ("__weakref__",)

    def __init__(
        self,
        *,
        coordinator: Any,
        admission_config: Dict[str, Any],
        checkpoint_store: Any,
    ) -> None:
        if not callable(getattr(checkpoint_store, "save", None)):
            raise StrictReceiptRuntimeV21Error("durable checkpoint store is required")
        bound_coordinator = _BoundCoordinator(coordinator)
        coordinator_state = bound_coordinator.inspect_state()
        _TRUSTED_RUNTIME_STATES[self] = _RuntimeState(
            tenant_id=_runtime_text(coordinator_state.get("tenant_id"), "tenant_id"),
            session_id=_runtime_text(coordinator_state.get("session_id"), "session_id"),
            coordinator=bound_coordinator,
            admission_config=admission_config,
            checkpoint_store=_BoundCheckpointStore(checkpoint_store),
        )
        _TRUSTED_RUNTIMES.add(self)
        _TRUSTED_RUNTIME_RUNNERS[self] = _STRICT_RUNTIME_RUN_DECISION_IMPL.__get__(
            self, StrictReceiptRuntimeV21
        )
        _TRUSTED_APPROVAL_RUNTIME_RUNNERS[self] = (
            _STRICT_RUNTIME_RUN_APPROVAL_IMPL.__get__(self, StrictReceiptRuntimeV21)
        )

    def run_decision(
        self, *, decision: Dict[str, Any], action: Dict[str, Any]
    ) -> Dict[str, Any]:
        state = _runtime_state(self)
        if state.frozen_reason is not None:
            raise StrictReceiptRuntimeV21Error(
                f"strict 2.1 runtime is frozen: {state.frozen_reason}"
            )
        action_id = _runtime_text(action.get("runtime_action_id"), "runtime_action_id")
        fingerprint = _runtime_fingerprint(self, decision, action)
        prior = state.results.get(action_id)
        if prior is not None:
            if prior["fingerprint"] != fingerprint:
                raise StrictReceiptRuntimeV21Error(
                    "runtime_action_id was reused with different input"
                )
            return prior["result"]
        if not state.lock.acquire(blocking=False):
            raise StrictReceiptRuntimeV21Error("strict 2.1 runtime is busy")
        try:
            prior = state.results.get(action_id)
            if prior is not None:
                if prior["fingerprint"] != fingerprint:
                    raise StrictReceiptRuntimeV21Error(
                        "runtime_action_id was reused with different input"
                    )
                return prior["result"]
            return _STRICT_RUNTIME_RUN_LOCKED_IMPL(
                self, decision, action, action_id, fingerprint
            )
        finally:
            state.lock.release()

    def run_approval(
        self, *, resolution: Dict[str, Any], action: Dict[str, Any]
    ) -> Dict[str, Any]:
        state = _runtime_state(self)
        if state.frozen_reason is not None:
            raise StrictReceiptRuntimeV21Error(
                f"strict 2.1 runtime is frozen: {state.frozen_reason}"
            )
        if not isinstance(resolution, dict):
            raise StrictReceiptRuntimeV21Error("approval resolution must be an object")
        suspended_hash = _runtime_text(
            resolution.get("suspended_receipt_hash"), "suspended_receipt_hash"
        )
        result_key = f"approval:{suspended_hash}"
        fingerprint = _approval_runtime_fingerprint(self, resolution, action)
        prior = state.results.get(result_key)
        if prior is not None:
            if prior["fingerprint"] != fingerprint:
                raise StrictReceiptRuntimeV21Error(
                    "suspended_receipt_hash was reused with different approval input"
                )
            return prior["result"]
        if not state.lock.acquire(blocking=False):
            raise StrictReceiptRuntimeV21Error("strict 2.1 runtime is busy")
        try:
            prior = state.results.get(result_key)
            if prior is not None:
                if prior["fingerprint"] != fingerprint:
                    raise StrictReceiptRuntimeV21Error(
                        "suspended_receipt_hash was reused with different approval input"
                    )
                return prior["result"]
            return _STRICT_RUNTIME_RUN_APPROVAL_LOCKED_IMPL(
                self, resolution, action, result_key, fingerprint
            )
        finally:
            state.lock.release()

    def _run_locked(
        self,
        decision: Dict[str, Any],
        action: Dict[str, Any],
        action_id: str,
        fingerprint: str,
    ) -> Dict[str, Any]:
        state = _runtime_state(self)
        prepared = state.coordinator.prepare_decision(decision)
        receipt = copy.deepcopy(prepared["value"]["receipt"])
        return _STRICT_RUNTIME_RUN_PREPARED_LOCKED_IMPL(
            self,
            prepared,
            receipt,
            action,
            action_id,
            action_id,
            fingerprint,
        )

    def _run_approval_locked(
        self,
        resolution: Dict[str, Any],
        action: Dict[str, Any],
        result_key: str,
        fingerprint: str,
    ) -> Dict[str, Any]:
        state = _runtime_state(self)
        prepared = state.coordinator.prepare_approval_resolution(resolution)
        receipt = copy.deepcopy(prepared["value"])
        action_id = _runtime_text(
            receipt["body"]["action"].get("action_id"), "action_id"
        )
        return _STRICT_RUNTIME_RUN_PREPARED_LOCKED_IMPL(
            self,
            prepared,
            receipt,
            action,
            action_id,
            result_key,
            fingerprint,
        )

    def _run_prepared_locked(
        self,
        prepared: Dict[str, Any],
        receipt: Dict[str, Any],
        action: Dict[str, Any],
        action_id: str,
        result_key: str,
        fingerprint: str,
    ) -> Dict[str, Any]:
        state = _runtime_state(self)
        base = {"receipt": receipt, "receipt_hash": prepared["receipt_hash"]}
        if receipt["body"]["action"]["action_id"] != action_id:
            state.coordinator.abort_prepared(
                prepared["token"], prepared["receipt_hash"], DEFINITIVE_NO_STORE
            )
            return _STRICT_RUNTIME_FINISH_IMPL(
                self,
                result_key,
                fingerprint,
                {**base, "status": "nonexecuted", "reason": "binding_unavailable"},
            )
        arguments = (
            _read_execution_arguments(action, receipt)
            if receipt["body"]["execution_authorized"]
            else (True, None)
        )
        if not arguments[0]:
            state.coordinator.abort_prepared(
                prepared["token"], prepared["receipt_hash"], DEFINITIVE_NO_STORE
            )
            return _STRICT_RUNTIME_FINISH_IMPL(
                self,
                result_key,
                fingerprint,
                {**base, "status": "nonexecuted", "reason": "binding_unavailable"},
            )
        try:
            _STRICT_RUNTIME_PERSIST_IMPL(
                self,
                "prepared",
                prepared,
                receipt,
                action_id,
                fingerprint,
            )
        except Exception as error:
            state.coordinator.abort_prepared(
                prepared["token"], prepared["receipt_hash"], DEFINITIVE_NO_STORE
            )
            return _STRICT_RUNTIME_FINISH_IMPL(
                self,
                result_key,
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
                state.coordinator, prepared, **state.admission_config
            )
        except Exception as error:
            _STRICT_RUNTIME_FREEZE_PREPARED_IMPL(self, prepared, "admission_threw")
            return _STRICT_RUNTIME_FINISH_IMPL(
                self,
                result_key,
                fingerprint,
                {
                    **base,
                    "status": "nonexecuted",
                    "reason": "admission_uncertain",
                    "error": error,
                },
            )
        if admission["disposition"] == "definitive_no_store":
            state.coordinator.abort_prepared(
                prepared["token"], prepared["receipt_hash"], DEFINITIVE_NO_STORE
            )
            try:
                _STRICT_RUNTIME_PERSIST_IMPL(
                    self,
                    "terminal",
                    prepared,
                    receipt,
                    action_id,
                    fingerprint,
                    terminal_status="nonexecuted",
                )
            except Exception as error:
                state.frozen_reason = "journal_terminal_failed"
                return _STRICT_RUNTIME_FINISH_IMPL(
                    self,
                    result_key,
                    fingerprint,
                    {
                        **base,
                        "status": "nonexecuted",
                        "reason": "checkpoint_persist_failed",
                        "admission": admission,
                        "error": error,
                    },
                )
            return _STRICT_RUNTIME_FINISH_IMPL(
                self,
                result_key,
                fingerprint,
                {
                    **base,
                    "status": "nonexecuted",
                    "reason": "definitive_no_store",
                    "admission": admission,
                },
            )
        if admission["disposition"] != "accepted":
            state.coordinator.freeze_prepared(
                prepared["token"],
                prepared["receipt_hash"],
                f"admission_{admission['reason']}",
            )
            state.frozen_reason = f"admission_{admission['reason']}"
            return _STRICT_RUNTIME_FINISH_IMPL(
                self,
                result_key,
                fingerprint,
                {
                    **base,
                    "status": "nonexecuted",
                    "reason": "admission_uncertain",
                    "admission": admission,
                },
            )
        try:
            _STRICT_RUNTIME_PERSIST_IMPL(
                self,
                "remote_accepted",
                prepared,
                receipt,
                action_id,
                fingerprint,
            )
        except Exception as error:
            _STRICT_RUNTIME_FREEZE_PREPARED_IMPL(
                self, prepared, "remote_accepted_journal_failed"
            )
            return _STRICT_RUNTIME_FINISH_IMPL(
                self,
                result_key,
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
            state.coordinator.commit_prepared(
                prepared["token"], prepared["receipt_hash"]
            )
        except Exception as error:
            _STRICT_RUNTIME_FREEZE_PREPARED_IMPL(
                self, prepared, "accepted_but_local_commit_failed"
            )
            return _STRICT_RUNTIME_FINISH_IMPL(
                self,
                result_key,
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
            _STRICT_RUNTIME_PERSIST_IMPL(
                self,
                "committed",
                prepared,
                receipt,
                action_id,
                fingerprint,
            )
        except Exception as error:
            state.frozen_reason = "committed_journal_failed"
            return _STRICT_RUNTIME_FINISH_IMPL(
                self,
                result_key,
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
                _STRICT_RUNTIME_PERSIST_IMPL(
                    self,
                    "terminal",
                    prepared,
                    receipt,
                    action_id,
                    fingerprint,
                    terminal_status="nonexecuted",
                )
            except Exception as error:
                state.frozen_reason = "terminal_journal_failed"
                return _STRICT_RUNTIME_FINISH_IMPL(
                    self,
                    result_key,
                    fingerprint,
                    {
                        **base,
                        "status": "nonexecuted",
                        "reason": "checkpoint_persist_failed",
                        "admission": admission,
                        "error": error,
                    },
                )
            return _STRICT_RUNTIME_FINISH_IMPL(
                self,
                result_key,
                fingerprint,
                {
                    **base,
                    "status": "nonexecuted",
                    "reason": "not_authorized",
                    "admission": admission,
                },
            )
        return execute_committed_strict_action_v2_1(
            self,
            prepared=prepared,
            receipt=receipt,
            action=action,
            arguments=arguments[1],
            action_id=action_id,
            result_key=result_key,
            fingerprint=fingerprint,
            admission=admission,
            base=base,
        )


_STRICT_RUNTIME_RUN_DECISION_IMPL = StrictReceiptRuntimeV21.run_decision
_STRICT_RUNTIME_RUN_APPROVAL_IMPL = StrictReceiptRuntimeV21.run_approval
_STRICT_RUNTIME_RUN_LOCKED_IMPL = StrictReceiptRuntimeV21._run_locked
_STRICT_RUNTIME_RUN_APPROVAL_LOCKED_IMPL = StrictReceiptRuntimeV21._run_approval_locked
_STRICT_RUNTIME_RUN_PREPARED_LOCKED_IMPL = StrictReceiptRuntimeV21._run_prepared_locked
_STRICT_RUNTIME_PERSIST_IMPL = _persist_runtime_checkpoint
_STRICT_RUNTIME_FREEZE_PREPARED_IMPL = _freeze_prepared_runtime
_STRICT_RUNTIME_FINISH_IMPL = _finish_runtime_result


def assert_strict_receipt_runtime_v2_1(value: Any) -> None:
    if value not in _TRUSTED_RUNTIMES:
        raise StrictReceiptRuntimeV21Error("trusted strict 2.1 runtime is required")


def run_trusted_strict_receipt_runtime_v2_1(
    runtime: Any, *, decision: Dict[str, Any], action: Dict[str, Any]
) -> Dict[str, Any]:
    assert_strict_receipt_runtime_v2_1(runtime)
    return _TRUSTED_RUNTIME_RUNNERS[runtime](decision=decision, action=action)


def run_trusted_strict_approval_runtime_v2_1(
    runtime: Any, *, resolution: Dict[str, Any], action: Dict[str, Any]
) -> Dict[str, Any]:
    assert_strict_receipt_runtime_v2_1(runtime)
    return _TRUSTED_APPROVAL_RUNTIME_RUNNERS[runtime](
        resolution=resolution, action=action
    )
