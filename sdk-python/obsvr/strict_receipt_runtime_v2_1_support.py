"""Trusted state and argument binding for the strict 2.1 runtime."""

from __future__ import annotations

import copy
import hashlib
import threading
import weakref
from types import MappingProxyType
from typing import Any, Dict

from .tool_pinning import _canonical_json_for_hash


class StrictReceiptRuntimeV21Error(RuntimeError):
    """The profile-2.1 runtime cannot safely continue an operation."""


class BoundCoordinator:
    __slots__ = (
        "inspect_state",
        "prepare_decision",
        "commit_prepared",
        "abort_prepared",
        "freeze_prepared",
        "observe_execution_time",
        "sign_execution_outcome",
    )

    def __init__(self, coordinator: Any) -> None:
        self.inspect_state = coordinator.inspect_state
        self.prepare_decision = coordinator.prepare_decision
        self.commit_prepared = coordinator.commit_prepared
        self.abort_prepared = coordinator.abort_prepared
        self.freeze_prepared = coordinator.freeze_prepared
        self.observe_execution_time = coordinator.observe_execution_time
        self.sign_execution_outcome = coordinator.sign_execution_outcome


class BoundCheckpointStore:
    __slots__ = ("save",)

    def __init__(self, checkpoint_store: Any) -> None:
        self.save = checkpoint_store.save


class RuntimeState:
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
        coordinator: BoundCoordinator,
        admission_config: Dict[str, Any],
        checkpoint_store: BoundCheckpointStore,
    ) -> None:
        self.tenant_id = tenant_id
        self.session_id = session_id
        self.coordinator = coordinator
        self.admission_config = MappingProxyType(copy.deepcopy(admission_config))
        self.checkpoint_store = checkpoint_store
        self.lock = threading.Lock()
        self.frozen_reason = None
        self.results: Dict[str, Dict[str, Any]] = {}


TRUSTED_RUNTIMES: "weakref.WeakSet[Any]" = weakref.WeakSet()
TRUSTED_RUNTIME_RUNNERS: "weakref.WeakKeyDictionary[Any, Any]" = (
    weakref.WeakKeyDictionary()
)
TRUSTED_RUNTIME_STATES: "weakref.WeakKeyDictionary[Any, RuntimeState]" = (
    weakref.WeakKeyDictionary()
)


def runtime_state(runtime: Any) -> RuntimeState:
    try:
        return TRUSTED_RUNTIME_STATES[runtime]
    except (KeyError, TypeError) as error:
        raise StrictReceiptRuntimeV21Error(
            "trusted strict 2.1 runtime state is unavailable"
        ) from error


class BoundArguments:
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
    return BoundArguments(value)


def read_execution_arguments(action: Dict[str, Any], receipt: Dict[str, Any]):
    modified = receipt["body"]["outcome"] == "MODIFY"
    bound = action.get("effective_arguments" if modified else "original_arguments")
    expected = receipt["body"]["action"].get(
        "effective_arguments_hash" if modified else "arguments_hash"
    )
    if not isinstance(bound, BoundArguments) or bound.arguments_hash != expected:
        return False, None
    return True, bound.snapshot()


def runtime_fingerprint(
    runtime: Any, decision: Dict[str, Any], action: Dict[str, Any]
) -> str:
    state = runtime_state(runtime)
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
                "original_arguments_hash": getattr(original, "arguments_hash", None),
                "effective_arguments_hash": getattr(effective, "arguments_hash", None),
            }
        ).encode("utf-8")
    ).hexdigest()


def runtime_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise StrictReceiptRuntimeV21Error(f"{field} must be nonblank")
    return value


def persist_runtime_checkpoint(
    runtime: Any,
    phase: str,
    prepared: Dict[str, Any],
    receipt: Dict[str, Any],
    action_id: str,
    fingerprint: str,
    *,
    terminal_status: str | None = None,
    execution_start: Dict[str, Any] | None = None,
    execution_outcome: Dict[str, Any] | None = None,
) -> None:
    state = runtime_state(runtime)
    coordinator_state = state.coordinator.inspect_state()
    checkpoint = {
        "schema": "obsvr-strict-runtime-execution-journal-v2-1",
        "profile_version": "2.1",
        "phase": phase,
        "tenant_id": state.tenant_id,
        "session_id": state.session_id,
        "runtime_action_id": action_id,
        "operation_fingerprint": fingerprint,
        "prepared_token": prepared["token"],
        "receipt_hash": receipt["receipt_hash"],
        "receipt": copy.deepcopy(receipt),
        "committed_sequence": coordinator_state["sequence"],
        "committed_head_receipt_hash": coordinator_state["head_receipt_hash"],
    }
    if terminal_status is not None:
        checkpoint["terminal_status"] = terminal_status
    if execution_start is not None:
        checkpoint["execution_start"] = {
            key: execution_start[key]
            for key in (
                "tenant_id",
                "session_id",
                "action_id",
                "decision_receipt_hash",
                "operation_fingerprint",
                "attempt",
                "started_at_ms",
            )
        }
        checkpoint["execution_start_hash"] = execution_start["execution_start_hash"]
    if execution_outcome is not None:
        checkpoint["execution_outcome"] = copy.deepcopy(execution_outcome)
    state.checkpoint_store.save(copy.deepcopy(checkpoint))


def freeze_prepared_runtime(
    runtime: Any, prepared: Dict[str, Any], reason: str
) -> None:
    state = runtime_state(runtime)
    state.frozen_reason = reason
    try:
        state.coordinator.freeze_prepared(
            prepared["token"], prepared["receipt_hash"], reason
        )
    except Exception:
        pass


def finish_runtime_result(
    runtime: Any,
    action_id: str,
    fingerprint: str,
    result: Dict[str, Any],
) -> Dict[str, Any]:
    runtime_state(runtime).results[action_id] = {
        "fingerprint": fingerprint,
        "result": result,
    }
    return result
