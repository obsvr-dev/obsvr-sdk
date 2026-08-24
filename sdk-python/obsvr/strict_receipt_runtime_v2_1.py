"""Decision-only strict profile-2.1 admission and action orchestration."""

from __future__ import annotations

import copy
import hashlib
import threading
import weakref
from types import MappingProxyType
from typing import Any, Dict

from .strict_admission_v2_1 import _transport_prepared_strict_receipt_v2_1
from .strict_receipt_prepared_state import DEFINITIVE_NO_STORE
from .tool_pinning import _canonical_json_for_hash

STRICT_RUNTIME_EXECUTION_JOURNAL_V2_1_SCHEMA = (
    "obsvr-strict-runtime-execution-journal-v2-1"
)
_TRUSTED_RUNTIMES: "weakref.WeakSet[Any]" = weakref.WeakSet()
_TRUSTED_RUNTIME_RUNNERS: "weakref.WeakKeyDictionary[Any, Any]" = (
    weakref.WeakKeyDictionary()
)


class _BoundCoordinator:
    __slots__ = (
        "inspect_state",
        "prepare_decision",
        "commit_prepared",
        "abort_prepared",
        "freeze_prepared",
    )

    def __init__(self, coordinator: Any) -> None:
        self.inspect_state = coordinator.inspect_state
        self.prepare_decision = coordinator.prepare_decision
        self.commit_prepared = coordinator.commit_prepared
        self.abort_prepared = coordinator.abort_prepared
        self.freeze_prepared = coordinator.freeze_prepared


class _BoundCheckpointStore:
    __slots__ = ("save",)

    def __init__(self, checkpoint_store: Any) -> None:
        self.save = checkpoint_store.save


class _RuntimeState:
    __slots__ = (
        "tenant_id",
        "session_id",
        "coordinator",
        "admission_config",
        "checkpoint_store",
        "lock",
        "frozen_reason",
        "results",
    )

    def __init__(
        self,
        *,
        tenant_id: str,
        session_id: str,
        coordinator: _BoundCoordinator,
        admission_config: Dict[str, Any],
        checkpoint_store: _BoundCheckpointStore,
    ) -> None:
        self.tenant_id = tenant_id
        self.session_id = session_id
        self.coordinator = coordinator
        self.admission_config = MappingProxyType(copy.deepcopy(admission_config))
        self.checkpoint_store = checkpoint_store
        self.lock = threading.Lock()
        self.frozen_reason = None
        self.results: Dict[str, Dict[str, Any]] = {}


_TRUSTED_RUNTIME_STATES: "weakref.WeakKeyDictionary[Any, _RuntimeState]" = (
    weakref.WeakKeyDictionary()
)


def _runtime_state(runtime: Any) -> _RuntimeState:
    try:
        return _TRUSTED_RUNTIME_STATES[runtime]
    except (KeyError, TypeError) as error:
        raise StrictReceiptRuntimeV21Error(
            "trusted strict 2.1 runtime state is unavailable"
        ) from error


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
            tenant_id=_STRICT_RUNTIME_TEXT_IMPL(
                coordinator_state.get("tenant_id"), "tenant_id"
            ),
            session_id=_STRICT_RUNTIME_TEXT_IMPL(
                coordinator_state.get("session_id"), "session_id"
            ),
            coordinator=bound_coordinator,
            admission_config=admission_config,
            checkpoint_store=_BoundCheckpointStore(checkpoint_store),
        )
        _TRUSTED_RUNTIMES.add(self)
        _TRUSTED_RUNTIME_RUNNERS[self] = _STRICT_RUNTIME_RUN_DECISION_IMPL.__get__(
            self, StrictReceiptRuntimeV21
        )

    def run_decision(
        self, *, decision: Dict[str, Any], action: Dict[str, Any]
    ) -> Dict[str, Any]:
        state = _runtime_state(self)
        if state.frozen_reason is not None:
            raise StrictReceiptRuntimeV21Error(
                f"strict 2.1 runtime is frozen: {state.frozen_reason}"
            )
        action_id = _STRICT_RUNTIME_TEXT_IMPL(
            action.get("runtime_action_id"), "runtime_action_id"
        )
        fingerprint = _STRICT_RUNTIME_FINGERPRINT_IMPL(self, decision, action)
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
        base = {"receipt": receipt, "receipt_hash": prepared["receipt_hash"]}
        if receipt["body"]["action"]["action_id"] != action_id:
            state.coordinator.abort_prepared(
                prepared["token"], prepared["receipt_hash"], DEFINITIVE_NO_STORE
            )
            return _STRICT_RUNTIME_FINISH_IMPL(
                self,
                action_id,
                fingerprint,
                {**base, "status": "nonexecuted", "reason": "binding_unavailable"},
            )
        arguments = (
            _STRICT_RUNTIME_EXECUTION_ARGUMENTS_IMPL(action, receipt)
            if receipt["body"]["execution_authorized"]
            else (True, None)
        )
        if not arguments[0]:
            state.coordinator.abort_prepared(
                prepared["token"], prepared["receipt_hash"], DEFINITIVE_NO_STORE
            )
            return _STRICT_RUNTIME_FINISH_IMPL(
                self,
                action_id,
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
                include_receipt=True,
            )
        except Exception as error:
            state.coordinator.abort_prepared(
                prepared["token"], prepared["receipt_hash"], DEFINITIVE_NO_STORE
            )
            return _STRICT_RUNTIME_FINISH_IMPL(
                self,
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
                state.coordinator, prepared, **state.admission_config
            )
        except Exception as error:
            _STRICT_RUNTIME_FREEZE_PREPARED_IMPL(self, prepared, "admission_threw")
            return _STRICT_RUNTIME_FINISH_IMPL(
                self,
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
                    include_receipt=False,
                    terminal_status="nonexecuted",
                )
            except Exception as error:
                state.frozen_reason = "journal_terminal_failed"
                return _STRICT_RUNTIME_FINISH_IMPL(
                    self,
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
            return _STRICT_RUNTIME_FINISH_IMPL(
                self,
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
            state.coordinator.freeze_prepared(
                prepared["token"],
                prepared["receipt_hash"],
                f"admission_{admission['reason']}",
            )
            state.frozen_reason = f"admission_{admission['reason']}"
            return _STRICT_RUNTIME_FINISH_IMPL(
                self,
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
            _STRICT_RUNTIME_PERSIST_IMPL(
                self,
                "remote_accepted",
                prepared,
                receipt,
                action_id,
                fingerprint,
                include_receipt=True,
            )
        except Exception as error:
            _STRICT_RUNTIME_FREEZE_PREPARED_IMPL(
                self, prepared, "remote_accepted_journal_failed"
            )
            return _STRICT_RUNTIME_FINISH_IMPL(
                self,
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
            state.coordinator.commit_prepared(
                prepared["token"], prepared["receipt_hash"]
            )
        except Exception as error:
            _STRICT_RUNTIME_FREEZE_PREPARED_IMPL(
                self, prepared, "accepted_but_local_commit_failed"
            )
            return _STRICT_RUNTIME_FINISH_IMPL(
                self,
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
            _STRICT_RUNTIME_PERSIST_IMPL(
                self,
                "committed",
                prepared,
                receipt,
                action_id,
                fingerprint,
                include_receipt=False,
            )
        except Exception as error:
            state.frozen_reason = "committed_journal_failed"
            return _STRICT_RUNTIME_FINISH_IMPL(
                self,
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
                _STRICT_RUNTIME_PERSIST_IMPL(
                    self,
                    "terminal",
                    prepared,
                    receipt,
                    action_id,
                    fingerprint,
                    include_receipt=False,
                    terminal_status="nonexecuted",
                )
            except Exception as error:
                state.frozen_reason = "terminal_journal_failed"
                return _STRICT_RUNTIME_FINISH_IMPL(
                    self,
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
            return _STRICT_RUNTIME_FINISH_IMPL(
                self,
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
            _STRICT_RUNTIME_PERSIST_IMPL(
                self,
                "invocation_started",
                prepared,
                receipt,
                action_id,
                fingerprint,
                include_receipt=False,
            )
        except Exception as error:
            state.frozen_reason = "invocation_started_journal_failed"
            return _STRICT_RUNTIME_FINISH_IMPL(
                self,
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
        state.results[action_id] = {
            "fingerprint": fingerprint,
            "result": in_progress,
        }
        try:
            value = action["invoke"](arguments[1])
            try:
                _STRICT_RUNTIME_PERSIST_IMPL(
                    self,
                    "terminal",
                    prepared,
                    receipt,
                    action_id,
                    fingerprint,
                    include_receipt=False,
                    terminal_status="executed",
                )
            except Exception as error:
                state.frozen_reason = "terminal_journal_failed"
                return _STRICT_RUNTIME_FINISH_IMPL(
                    self,
                    action_id,
                    fingerprint,
                    {
                        **base,
                        "status": "invocation_uncertain",
                        "admission": admission,
                        "error": error,
                    },
                )
            return _STRICT_RUNTIME_FINISH_IMPL(
                self,
                action_id,
                fingerprint,
                {**base, "status": "executed", "admission": admission, "value": value},
            )
        except Exception as error:
            try:
                _STRICT_RUNTIME_PERSIST_IMPL(
                    self,
                    "terminal",
                    prepared,
                    receipt,
                    action_id,
                    fingerprint,
                    include_receipt=False,
                    terminal_status="invocation_failed",
                )
            except Exception as journal_error:
                state.frozen_reason = "terminal_journal_failed"
                return _STRICT_RUNTIME_FINISH_IMPL(
                    self,
                    action_id,
                    fingerprint,
                    {
                        **base,
                        "status": "invocation_uncertain",
                        "admission": admission,
                        "error": journal_error,
                    },
                )
            return _STRICT_RUNTIME_FINISH_IMPL(
                self,
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
        state = _runtime_state(self)
        coordinator_state = state.coordinator.inspect_state()
        checkpoint = {
            "schema": STRICT_RUNTIME_EXECUTION_JOURNAL_V2_1_SCHEMA,
            "profile_version": "2.1",
            "phase": phase,
            "tenant_id": state.tenant_id,
            "session_id": state.session_id,
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
        state.checkpoint_store.save(copy.deepcopy(checkpoint))

    def _freeze_prepared(self, prepared: Dict[str, Any], reason: str) -> None:
        state = _runtime_state(self)
        state.frozen_reason = reason
        try:
            state.coordinator.freeze_prepared(
                prepared["token"], prepared["receipt_hash"], reason
            )
        except Exception:
            pass

    def _finish(
        self, action_id: str, fingerprint: str, result: Dict[str, Any]
    ) -> Dict[str, Any]:
        _runtime_state(self).results[action_id] = {
            "fingerprint": fingerprint,
            "result": result,
        }
        return result

    def _fingerprint(self, decision: Dict[str, Any], action: Dict[str, Any]) -> str:
        state = _runtime_state(self)
        original = action.get("original_arguments")
        effective = action.get("effective_arguments")
        return hashlib.sha256(
            _canonical_json_for_hash(
                {
                    "schema": "obsvr-strict-runtime-operation-v2-1",
                    "tenant_id": state.tenant_id,
                    "session_id": state.session_id,
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


_STRICT_RUNTIME_RUN_DECISION_IMPL = StrictReceiptRuntimeV21.run_decision
_STRICT_RUNTIME_RUN_LOCKED_IMPL = StrictReceiptRuntimeV21._run_locked
_STRICT_RUNTIME_EXECUTION_ARGUMENTS_IMPL = StrictReceiptRuntimeV21._execution_arguments
_STRICT_RUNTIME_PERSIST_IMPL = StrictReceiptRuntimeV21._persist
_STRICT_RUNTIME_FREEZE_PREPARED_IMPL = StrictReceiptRuntimeV21._freeze_prepared
_STRICT_RUNTIME_FINISH_IMPL = StrictReceiptRuntimeV21._finish
_STRICT_RUNTIME_FINGERPRINT_IMPL = StrictReceiptRuntimeV21._fingerprint
_STRICT_RUNTIME_TEXT_IMPL = StrictReceiptRuntimeV21._text


def assert_strict_receipt_runtime_v2_1(value: Any) -> None:
    if value not in _TRUSTED_RUNTIMES:
        raise StrictReceiptRuntimeV21Error("trusted strict 2.1 runtime is required")


def run_trusted_strict_receipt_runtime_v2_1(
    runtime: Any, *, decision: Dict[str, Any], action: Dict[str, Any]
) -> Dict[str, Any]:
    assert_strict_receipt_runtime_v2_1(runtime)
    return _TRUSTED_RUNTIME_RUNNERS[runtime](decision=decision, action=action)
