"""Fail-closed v2 receipt admission and governed action orchestration."""

from __future__ import annotations

import copy
import hashlib
import threading
from typing import Any, Callable, Dict, Optional

from .strict_admission_v2 import (
    STRICT_RECEIPT_V2_ADMISSION_SCHEMA,
    admit_strict_receipt_v2,
)
from .strict_receipt_prepared_state import DEFINITIVE_NO_STORE
from .tool_pinning import _canonical_json_for_hash

_ENVELOPE_SCHEMA = "obsvr-strict-receipt-envelope-v2"
_RECEIPT_SCHEMA = "obsvr-strict-receipt-v2"


class _BoundArguments:
    def __init__(self, value: Any) -> None:
        self._value = copy.deepcopy(value)
        canonical = _canonical_json_for_hash(self._value).encode("utf-8")
        self.arguments_hash = hashlib.sha256(canonical).hexdigest()

    def snapshot(self) -> Any:
        return copy.deepcopy(self._value)


class _TrustedAdmission:
    def __init__(self, admit: Callable[[Dict[str, Any], Any], Dict[str, Any]]) -> None:
        self.admit = admit


def bind_strict_v2_json_arguments(value: Any) -> Any:
    return _BoundArguments(value)


class StrictReceiptRuntimeV2Error(RuntimeError):
    """The v2 runtime cannot safely continue the operation."""


def create_trusted_strict_v2_admission(
    admit: Callable[[Dict[str, Any], Any], Dict[str, Any]],
) -> Any:
    if not callable(admit):
        raise StrictReceiptRuntimeV2Error("trusted admission must be callable")
    return _TrustedAdmission(admit)


class StrictReceiptRuntimeV2:
    """Prepare, durably admit, commit, and only then invoke one action."""

    def __init__(
        self,
        *,
        coordinator: Any,
        admission_config: Dict[str, Any],
        trusted_admission: Optional[Any] = None,
    ) -> None:
        if trusted_admission is not None and not isinstance(
            trusted_admission, _TrustedAdmission
        ):
            raise StrictReceiptRuntimeV2Error(
                "trusted admission must be created explicitly"
            )
        self._coordinator = coordinator
        self._trusted_admission = trusted_admission
        self._admission_config = admission_config
        state = coordinator.inspect_state()
        self._tenant_id = self._text(state.get("tenant_id"), "tenant_id")
        self._session_id = self._text(state.get("session_id"), "session_id")
        self._lock = threading.Lock()
        self._results: Dict[str, Dict[str, Any]] = {}

    def run_decision(
        self, *, decision: Dict[str, Any], action: Dict[str, Any]
    ) -> Dict[str, Any]:
        return self._run_action(
            "decision",
            decision,
            action,
            lambda: self._coordinator.prepare_decision(**decision),
        )

    def run_resolution(
        self, *, resolution: Dict[str, Any], action: Dict[str, Any]
    ) -> Dict[str, Any]:
        return self._run_action(
            "resolution",
            resolution,
            action,
            lambda: self._coordinator.prepare_resolution(**resolution),
        )

    def run_timeout(self, *, timeout: Dict[str, Any]) -> Dict[str, Any]:
        return self._run_exclusive(
            None, None, lambda: self._coordinator.prepare_timeout(**timeout)
        )

    def _run_action(
        self,
        kind: str,
        input_value: Dict[str, Any],
        action: Dict[str, Any],
        prepare: Callable[[], Dict[str, Any]],
    ) -> Dict[str, Any]:
        action_id = self._action_id(action)
        fingerprint = self._fingerprint(kind, input_value, action)
        prior = self._results.get(action_id)
        if prior is not None:
            if prior["fingerprint"] != fingerprint:
                raise StrictReceiptRuntimeV2Error(
                    "runtime_action_id was reused with different input"
                )
            return self._copy_result(prior["result"])
        return self._run_exclusive(action, fingerprint, prepare)

    def _run_exclusive(
        self,
        action: Optional[Dict[str, Any]],
        fingerprint: Optional[str],
        prepare: Callable[[], Dict[str, Any]],
    ) -> Dict[str, Any]:
        if not self._lock.acquire(blocking=False):
            raise StrictReceiptRuntimeV2Error("strict v2 runtime is busy")
        action_id: Optional[str] = None
        try:
            if action is not None:
                action_id = self._action_id(action)
                prior = self._results.get(action_id)
                if prior is not None:
                    if prior["fingerprint"] != fingerprint:
                        raise StrictReceiptRuntimeV2Error(
                            "runtime_action_id was reused with different input"
                        )
                    return self._copy_result(prior["result"])
            prepared = prepare()
            receipt = self._prepared_receipt(prepared)
            base = {
                "receipt": copy.deepcopy(receipt),
                "receipt_hash": prepared["receipt_hash"],
            }
            reason = self._local_contract_reason(prepared, receipt, action_id)
            if reason is not None:
                return self._abort_local(prepared, base, reason, action_id, fingerprint)
            snapshot = (
                self._execution_arguments(action, receipt)
                if receipt["body"]["execution_authorized"]
                else {"ok": True, "value": None}
            )
            if not snapshot["ok"]:
                return self._abort_local(
                    prepared, base, snapshot["reason"], action_id, fingerprint
                )
            try:
                admission = (
                    self._trusted_admission.admit(
                        copy.deepcopy(receipt), self._admission_config
                    )
                    if self._trusted_admission is not None
                    else admit_strict_receipt_v2(
                        copy.deepcopy(receipt), **self._admission_config
                    )
                )
            except Exception as error:
                self._coordinator.freeze_prepared(
                    prepared["token"],
                    prepared["receipt_hash"],
                    "admission_threw",
                )
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
            response_reason = self._admission_reason(
                admission, prepared["receipt_hash"]
            )
            if response_reason is not None:
                self._coordinator.freeze_prepared(
                    prepared["token"],
                    prepared["receipt_hash"],
                    f"admission_{response_reason}",
                )
                return self._finish(
                    action_id,
                    fingerprint,
                    {
                        **base,
                        "status": "nonexecuted",
                        "reason": response_reason,
                        "admission": admission,
                    },
                )
            if admission["disposition"] == "definitive_no_store":
                self._coordinator.abort_prepared(
                    prepared["token"],
                    prepared["receipt_hash"],
                    DEFINITIVE_NO_STORE,
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
            if admission["disposition"] == "uncertain":
                self._coordinator.freeze_prepared(
                    prepared["token"],
                    prepared["receipt_hash"],
                    f"admission_{admission['reason']}",
                )
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
                committed = self._coordinator.commit_prepared(
                    prepared["token"], admission["receipt_hash"]
                )
            except Exception as error:
                return self._finish(
                    action_id,
                    fingerprint,
                    {
                        **base,
                        "status": "admitted",
                        "reason": "local_commit_failed",
                        "admission": admission,
                        "error": error,
                    },
                )
            committed_receipt = self._committed_receipt(committed)
            committed_base = {
                "receipt": copy.deepcopy(committed_receipt),
                "receipt_hash": committed_receipt["receipt_hash"],
            }
            if not committed_receipt["body"]["execution_authorized"] or action is None:
                return self._finish(
                    action_id,
                    fingerprint,
                    {
                        **committed_base,
                        "status": "nonexecuted",
                        "reason": "not_authorized",
                    },
                )
            in_progress = {
                **committed_base,
                "status": "invocation_failed",
                "error": StrictReceiptRuntimeV2Error(
                    "action invocation is already in progress"
                ),
            }
            self._store(action_id, fingerprint, in_progress)
            try:
                value = action["invoke"](snapshot["value"])
                return self._finish(
                    action_id,
                    fingerprint,
                    {**committed_base, "status": "executed", "value": value},
                )
            except Exception as error:
                return self._finish(
                    action_id,
                    fingerprint,
                    {**committed_base, "status": "invocation_failed", "error": error},
                )
        finally:
            self._lock.release()

    def _local_contract_reason(
        self,
        prepared: Dict[str, Any],
        receipt: Dict[str, Any],
        action_id: Optional[str],
    ) -> Optional[str]:
        if (
            receipt.get("schema") != _ENVELOPE_SCHEMA
            or receipt.get("body", {}).get("schema") != _RECEIPT_SCHEMA
        ):
            return "receipt_schema_mismatch"
        if receipt["body"].get("tenant_id") != self._tenant_id:
            return "tenant_mismatch"
        if receipt["body"].get("session_id") != self._session_id:
            return "session_mismatch"
        if receipt.get("receipt_hash") != prepared.get("receipt_hash"):
            return "receipt_hash_mismatch"
        if (
            action_id is not None
            and receipt["body"].get("action", {}).get("action_id") != action_id
        ):
            return "action_id_mismatch"
        return None

    def _admission_reason(self, value: Any, receipt_hash: str) -> Optional[str]:
        if (
            not isinstance(value, dict)
            or value.get("schema") != STRICT_RECEIPT_V2_ADMISSION_SCHEMA
        ):
            return "admission_schema_mismatch"
        if value.get("tenant_id") != self._tenant_id:
            return "tenant_mismatch"
        if value.get("session_id") != self._session_id:
            return "session_mismatch"
        if value.get("receipt_hash") != receipt_hash:
            return "receipt_hash_mismatch"
        disposition = value.get("disposition")
        if disposition == "accepted" and value.get("status") not in (
            "accepted",
            "already_accepted",
        ):
            return "admission_schema_mismatch"
        if disposition == "definitive_no_store" and value.get("http_status") not in (
            400,
            401,
            403,
            413,
        ):
            return "admission_schema_mismatch"
        if disposition == "uncertain" and not isinstance(value.get("reason"), str):
            return "admission_schema_mismatch"
        if disposition not in ("accepted", "definitive_no_store", "uncertain"):
            return "admission_schema_mismatch"
        attempts = value.get("attempts")
        if not isinstance(attempts, int) or isinstance(attempts, bool) or attempts < 1:
            return "admission_schema_mismatch"
        return None

    def _execution_arguments(
        self, action: Optional[Dict[str, Any]], receipt: Dict[str, Any]
    ) -> Dict[str, Any]:
        if action is None:
            return {"ok": False, "reason": "original_arguments_unavailable"}
        modified = receipt["body"]["evaluation"]["outcome"] == "MODIFY"
        key = "effective_arguments" if modified else "original_arguments"
        reason = (
            "effective_arguments_unavailable"
            if modified
            else "original_arguments_unavailable"
        )
        bound = action.get(key)
        expected = (
            receipt["body"]["action"].get("effective_arguments_hash")
            if modified
            else receipt["body"]["action"]["arguments_hash"]
        )
        if not isinstance(bound, _BoundArguments) or bound.arguments_hash != expected:
            return {"ok": False, "reason": reason}
        return {"ok": True, "value": bound.snapshot()}

    @staticmethod
    def _prepared_receipt(prepared: Dict[str, Any]) -> Dict[str, Any]:
        value = prepared["value"]
        return value["receipt"] if prepared["kind"] == "decision" else value

    @staticmethod
    def _committed_receipt(value: Dict[str, Any]) -> Dict[str, Any]:
        return value["receipt"] if "receipt" in value else value

    def _abort_local(
        self,
        prepared: Dict[str, Any],
        base: Dict[str, Any],
        reason: str,
        action_id: Optional[str],
        fingerprint: Optional[str],
    ) -> Dict[str, Any]:
        self._coordinator.abort_prepared(
            prepared["token"], prepared["receipt_hash"], DEFINITIVE_NO_STORE
        )
        return self._finish(
            action_id,
            fingerprint,
            {**base, "status": "nonexecuted", "reason": reason},
        )

    def _finish(
        self,
        action_id: Optional[str],
        fingerprint: Optional[str],
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        if action_id is not None and fingerprint is not None:
            self._store(action_id, fingerprint, result)
        return self._copy_result(result)

    def _store(self, action_id: str, fingerprint: str, result: Dict[str, Any]) -> None:
        self._results[action_id] = {
            "fingerprint": fingerprint,
            "result": self._copy_result(result),
        }

    def _fingerprint(
        self, kind: str, input_value: Dict[str, Any], action: Dict[str, Any]
    ) -> str:
        original = action.get("original_arguments")
        effective = action.get("effective_arguments")
        document = {
            "schema": "obsvr-strict-runtime-operation-v2",
            "kind": kind,
            "tenant_id": self._tenant_id,
            "session_id": self._session_id,
            "runtime_action_id": action.get("runtime_action_id"),
            "input": input_value,
            "original_arguments_hash": (
                original.arguments_hash
                if isinstance(original, _BoundArguments)
                else None
            ),
            "effective_arguments_hash": (
                effective.arguments_hash
                if isinstance(effective, _BoundArguments)
                else None
            ),
        }
        return hashlib.sha256(
            _canonical_json_for_hash(document).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _action_id(action: Dict[str, Any]) -> str:
        if not isinstance(action, dict):
            raise StrictReceiptRuntimeV2Error("action must be an object")
        return StrictReceiptRuntimeV2._text(
            action.get("runtime_action_id"), "runtime_action_id"
        )

    @staticmethod
    def _text(value: Any, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise StrictReceiptRuntimeV2Error(f"{field} must be nonblank")
        return value

    @staticmethod
    def _copy_result(result: Dict[str, Any]) -> Dict[str, Any]:
        output = dict(result)
        if "receipt" in output:
            output["receipt"] = copy.deepcopy(output["receipt"])
        if "admission" in output:
            output["admission"] = copy.deepcopy(output["admission"])
        return output
