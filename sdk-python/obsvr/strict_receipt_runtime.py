"""Fail-closed orchestration from strict receipt preparation through invocation."""

from __future__ import annotations

import copy
import hashlib
import threading
from typing import Any, Callable, Dict, Optional

from .strict_receipt_coordinator import StrictReceiptCoordinator
from .strict_receipt_prepared_state import DEFINITIVE_NO_STORE
from .tool_pinning import _canonical_json_for_hash


class _StrictBoundArguments:
    status = "trusted_bound_arguments"


STRICT_BOUND_ARGUMENTS = _StrictBoundArguments()


class StrictReceiptRuntimeError(RuntimeError):
    """The process-local runtime cannot safely start another operation."""


class StrictReceiptRuntime:
    """Admit and commit a signed receipt before invoking one governed action."""

    def __init__(
        self,
        *,
        coordinator: StrictReceiptCoordinator,
        admission: Callable[[Dict[str, Any], Any], Dict[str, Any]],
        admission_config: Any,
    ) -> None:
        if not callable(admission):
            raise StrictReceiptRuntimeError("admission function must be callable")
        self._coordinator = coordinator
        self._admission = admission
        self._admission_config = admission_config
        self._lock = threading.Lock()
        self._invocation_results: Dict[str, Dict[str, Any]] = {}

    def run_decision(
        self, *, decision: Dict[str, Any], action: Dict[str, Any]
    ) -> Dict[str, Any]:
        fingerprint = self._operation_fingerprint("decision", decision, action)
        return self._run_exclusive(
            action,
            fingerprint,
            lambda: self._coordinator.prepare_decision(**decision),
        )

    def run_resolution(
        self, *, resolution: Dict[str, Any], action: Dict[str, Any]
    ) -> Dict[str, Any]:
        fingerprint = self._operation_fingerprint("resolution", resolution, action)
        return self._run_exclusive(
            action,
            fingerprint,
            lambda: self._coordinator.prepare_resolution(**resolution),
        )

    def run_timeout(self, *, timeout: Dict[str, Any]) -> Dict[str, Any]:
        return self._run_exclusive(
            None, None, lambda: self._coordinator.prepare_timeout(**timeout)
        )

    def _run_exclusive(
        self,
        action: Optional[Dict[str, Any]],
        fingerprint: Optional[str],
        prepare: Callable[[], Dict[str, Any]],
    ) -> Dict[str, Any]:
        if not self._lock.acquire(blocking=False):
            raise StrictReceiptRuntimeError("strict runtime is busy")
        try:
            if action is not None:
                action_id = self._action_id(action)
                prior = self._invocation_results.get(action_id)
                if prior is not None:
                    if prior["fingerprint"] != fingerprint:
                        raise StrictReceiptRuntimeError(
                            "runtime_action_id was reused with different input"
                        )
                    return self._copy_result(prior["result"])
            prepared = prepare()
            receipt = self._prepared_receipt(prepared)
            base = {"receipt": receipt, "receipt_hash": prepared["receipt_hash"]}
            if (
                action is not None
                and action_id != receipt["body"]["action"]["action_id"]
            ):
                self._coordinator.abort_prepared(
                    prepared["token"],
                    prepared["receipt_hash"],
                    DEFINITIVE_NO_STORE,
                )
                return {**base, "status": "nonexecuted", "reason": "action_id_mismatch"}
            argument_snapshot = None
            if receipt["body"]["execution_authorized"]:
                if action is None:
                    self._coordinator.abort_prepared(
                        prepared["token"],
                        prepared["receipt_hash"],
                        DEFINITIVE_NO_STORE,
                    )
                    return {**base, "status": "nonexecuted", "reason": "not_authorized"}
                # Snapshot the selected reference; adapters own nested value immutability.
                argument_snapshot = self._execution_arguments(action, receipt)
                if argument_snapshot["value"] is _MISSING:
                    self._coordinator.abort_prepared(
                        prepared["token"],
                        prepared["receipt_hash"],
                        DEFINITIVE_NO_STORE,
                    )
                    return {
                        **base,
                        "status": "nonexecuted",
                        "reason": argument_snapshot["reason"],
                    }
            try:
                admission = self._admission(receipt, self._admission_config)
            except Exception as error:
                self._coordinator.freeze_prepared(
                    prepared["token"], prepared["receipt_hash"], "admission_threw"
                )
                return {
                    **base,
                    "status": "nonexecuted",
                    "reason": "admission_uncertain",
                    "error": error,
                }
            if admission.get("receipt_hash") != prepared["receipt_hash"]:
                self._coordinator.freeze_prepared(
                    prepared["token"],
                    prepared["receipt_hash"],
                    "admission_receipt_hash_mismatch",
                )
                return {
                    **base,
                    "status": "nonexecuted",
                    "reason": "receipt_hash_mismatch",
                    "admission": admission,
                }
            disposition = admission.get("disposition")
            if disposition == "definitive_no_store":
                self._coordinator.abort_prepared(
                    prepared["token"],
                    prepared["receipt_hash"],
                    DEFINITIVE_NO_STORE,
                )
                return {
                    **base,
                    "status": "nonexecuted",
                    "reason": "definitive_no_store",
                    "admission": admission,
                }
            if disposition != "accepted":
                reason = admission.get("reason", "invalid_response")
                self._coordinator.freeze_prepared(
                    prepared["token"],
                    prepared["receipt_hash"],
                    f"admission_{reason}",
                )
                return {
                    **base,
                    "status": "nonexecuted",
                    "reason": "admission_uncertain",
                    "admission": admission,
                }
            try:
                committed = self._coordinator.commit_prepared(
                    prepared["token"], admission["receipt_hash"]
                )
            except Exception as error:
                return {
                    **base,
                    "status": "admitted",
                    "reason": "local_commit_failed",
                    "admission": admission,
                    "error": error,
                }
            committed_receipt = self._committed_receipt(committed)
            committed_base = {
                "receipt": committed_receipt,
                "receipt_hash": committed_receipt["receipt_hash"],
            }
            if not committed_receipt["body"]["execution_authorized"]:
                return {
                    **committed_base,
                    "status": "nonexecuted",
                    "reason": "not_authorized",
                }
            if action is None:
                return {
                    **committed_base,
                    "status": "nonexecuted",
                    "reason": "not_authorized",
                }
            if argument_snapshot is None:
                raise StrictReceiptRuntimeError("argument preflight was lost")
            previous = self._invocation_results.get(action_id)
            if previous is not None:
                if previous["fingerprint"] != fingerprint:
                    raise StrictReceiptRuntimeError(
                        "runtime_action_id was reused with different input"
                    )
                return self._copy_result(previous["result"])
            in_progress = {
                **committed_base,
                "status": "invocation_failed",
                "error": StrictReceiptRuntimeError(
                    "action invocation is already in progress"
                ),
            }
            self._invocation_results[action_id] = {
                "fingerprint": fingerprint,
                "result": self._stored_result(in_progress),
            }
            try:
                value = action["invoke"](argument_snapshot["value"])
                result = {**committed_base, "status": "executed", "value": value}
            except Exception as error:
                result = {
                    **committed_base,
                    "status": "invocation_failed",
                    "error": error,
                }
            self._invocation_results[action_id] = {
                "fingerprint": fingerprint,
                "result": self._stored_result(result),
            }
            return self._copy_result(result)
        finally:
            self._lock.release()

    @staticmethod
    def _action_id(action: Dict[str, Any]) -> str:
        value = action.get("runtime_action_id")
        if not isinstance(value, str) or not value.strip():
            raise StrictReceiptRuntimeError("runtime_action_id must be nonblank")
        if not callable(action.get("invoke")):
            raise StrictReceiptRuntimeError("action invoke must be callable")
        return value

    @staticmethod
    def _execution_arguments(
        action: Dict[str, Any], receipt: Dict[str, Any]
    ) -> Dict[str, Any]:
        if receipt["body"]["evaluation"]["outcome"] != "MODIFY":
            original = action.get("original_arguments")
            if (
                not isinstance(original, dict)
                or original.get("capability") is not STRICT_BOUND_ARGUMENTS
                or original.get("arguments_hash")
                != receipt["body"]["action"]["arguments_hash"]
                or "value" not in original
            ):
                return {"value": _MISSING, "reason": "original_arguments_unavailable"}
            return {
                "value": original["value"],
                "reason": "original_arguments_unavailable",
            }
        effective = action.get("effective_arguments")
        if (
            not isinstance(effective, dict)
            or effective.get("capability") is not STRICT_BOUND_ARGUMENTS
            or effective.get("arguments_hash")
            != receipt["body"]["action"].get("effective_arguments_hash")
            or "value" not in effective
        ):
            return {"value": _MISSING, "reason": "effective_arguments_unavailable"}
        return {
            "value": effective["value"],
            "reason": "effective_arguments_unavailable",
        }

    @staticmethod
    def _prepared_receipt(prepared: Dict[str, Any]) -> Dict[str, Any]:
        value = prepared["value"]
        return value["receipt"] if prepared["kind"] == "decision" else value

    @staticmethod
    def _committed_receipt(value: Dict[str, Any]) -> Dict[str, Any]:
        return value["receipt"] if "receipt" in value else value

    @staticmethod
    def _operation_fingerprint(
        kind: str, coordinator_input: Dict[str, Any], action: Dict[str, Any]
    ) -> str:
        action_id = StrictReceiptRuntime._action_id(action)
        effective = action.get("effective_arguments")
        original = action.get("original_arguments")
        effective_hash = (
            effective.get("arguments_hash") if isinstance(effective, dict) else None
        )
        bindings = {
            "original_arguments_hash": coordinator_input["context"]["current_action"][
                "arguments_hash"
            ],
        }
        if isinstance(original, dict) and "arguments_hash" in original:
            bindings["supplied_original_arguments_hash"] = original["arguments_hash"]
        if effective_hash is not None:
            bindings["effective_arguments_hash"] = effective_hash
        document = {
            "schema": "obsvr-strict-runtime-operation-v1",
            "kind": kind,
            "runtime_action_id": action_id,
            "coordinator_input": coordinator_input,
            "argument_bindings": bindings,
        }
        return hashlib.sha256(
            _canonical_json_for_hash(document).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _stored_result(result: Dict[str, Any]) -> Dict[str, Any]:
        return StrictReceiptRuntime._copy_result(result)

    @staticmethod
    def _copy_result(result: Dict[str, Any]) -> Dict[str, Any]:
        copied = dict(result)
        copied["receipt"] = copy.deepcopy(result["receipt"])
        if "admission" in result:
            copied["admission"] = copy.deepcopy(result["admission"])
        return copied


_MISSING = object()
