"""Two-phase strict v2 receipt coordinator with tenant-bound state."""

from __future__ import annotations

import copy
import os
import threading
import uuid
from typing import Any, Callable, Dict, List, Optional

from .strict_receipt_coordinator_v2_support import (
    build_coordinator_context_v2,
    build_intent_policy_v2,
    context_input_from_v2_document,
    decision_v2_fingerprint,
    evaluate_intent_alignment_v2,
    resolution_v2_fingerprint,
    sign_decision_v2,
    sign_resolution_v2,
    timeout_v2_fingerprint,
    v2_canonical_hash,
    v2_hash,
    v2_integer,
    v2_text,
    validate_resolution_v2,
)
from .strict_receipt_prepared_state import PreparedReceiptState
from .strict_receipt_v2 import strict_receipt_v2_key_id


class StrictReceiptCoordinatorV2Error(ValueError):
    """Strict v2 coordination cannot proceed safely."""


class StrictReceiptCoordinatorV2:
    """Prepare signed v2 receipts, then advance only after durable admission."""

    def __init__(
        self,
        *,
        signer: Any,
        policy: Dict[str, Any],
        sdk_language: str,
        sdk_version: str,
        tenant_id: str,
        session_id: str,
        clock: Callable[[], int],
        defer_ttl_ms: int,
        approval_verifier: Callable[[Any, Dict[str, Any]], Dict[str, Any]],
        include_public_key: bool = True,
        pid: Callable[[], int] = os.getpid,
        prepared_token_factory: Callable[[], str] = lambda: str(uuid.uuid4()),
    ) -> None:
        if sdk_language != "python":
            raise StrictReceiptCoordinatorV2Error("sdk_language must be python")
        self._signer = signer
        self._policy = build_intent_policy_v2(policy)
        self._sdk_version = v2_text(sdk_version, "sdk_version")
        self._tenant_id = v2_text(tenant_id, "tenant_id")
        self._session_id = v2_text(session_id, "session_id")
        self._clock = clock
        self._defer_ttl_ms = v2_integer(defer_ttl_ms, "defer_ttl_ms")
        if self._defer_ttl_ms == 0:
            raise StrictReceiptCoordinatorV2Error("defer_ttl_ms must be positive")
        if not callable(approval_verifier):
            raise StrictReceiptCoordinatorV2Error(
                "approval_verifier must be a function"
            )
        self._approval_verifier = approval_verifier
        self._include_public_key = include_public_key
        self._pid_source = pid
        self._owner_pid = v2_integer(pid(), "pid")
        strict_receipt_v2_key_id(signer.raw_public_key)
        self._prepared_state = PreparedReceiptState(prepared_token_factory)
        self._sequence = 0
        self._last_receipt_hash: Optional[str] = None
        self._last_timestamp: Optional[int] = None
        self._prior_actions: List[Dict[str, Any]] = []
        self._suspended: Dict[str, Dict[str, Any]] = {}
        self._resolved: set[str] = set()
        self._action_ids: set[str] = set()
        self._approval_requests: Dict[str, str] = {}
        self._lock = threading.RLock()

    def prepare_decision(
        self,
        *,
        context: Dict[str, Any],
        base_result: Dict[str, Any],
        policy_version: str,
        rule_ids: List[str],
        action_id: str,
    ) -> Dict[str, Any]:
        with self._lock:
            self._ensure_process()
            input_value = {
                "context": context,
                "base_result": base_result,
                "policy_version": policy_version,
                "rule_ids": rule_ids,
                "action_id": action_id,
            }
            action_id = v2_text(action_id, "action_id")
            fingerprint = decision_v2_fingerprint(
                input_value=input_value,
                tenant_id=self._tenant_id,
                session_id=self._session_id,
            )
            if action_id in self._action_ids:
                raise StrictReceiptCoordinatorV2Error("action_id is already committed")
            retry = self._prepared_state.retry(fingerprint, "decision")
            if retry is not None:
                return copy.deepcopy(retry)
            normalized = build_coordinator_context_v2(
                context, self._session_id, self._prior_actions
            )
            base = copy.deepcopy(base_result)
            evaluation = evaluate_intent_alignment_v2(
                context=normalized, base_result=base, policy=self._policy
            )
            timestamp, clamped = self._allocate_timestamp()
            receipt = sign_decision_v2(
                action_id=action_id,
                tenant_id=self._tenant_id,
                session_id=self._session_id,
                sequence=self._sequence + 1,
                timestamp=timestamp,
                clamped=clamped,
                previous_hash=self._last_receipt_hash,
                sdk_version=self._sdk_version,
                signer=self._signer,
                include_public_key=self._include_public_key,
                context=normalized,
                base_result=base,
                evaluation=evaluation,
                policy_version=policy_version,
                rule_ids=rule_ids,
                defer_ttl_ms=self._defer_ttl_ms,
            )
            request_id = (
                receipt["body"].get("suspension", {}).get("approval_request_id")
            )
            if request_id in self._approval_requests:
                raise StrictReceiptCoordinatorV2Error(
                    "approval_request_id is already pending"
                )
            result = {"evaluation": evaluation, "receipt": receipt}
            prepared = self._prepared_state.prepare(
                fingerprint=fingerprint,
                receipt_hash=receipt["receipt_hash"],
                kind="decision",
                value=result,
                commit=lambda: self._commit_decision(result, normalized, base),
            )
            return copy.deepcopy(prepared)

    def prepare_resolution(
        self,
        *,
        suspended_receipt_hash: str,
        method: str,
        context: Dict[str, Any],
        base_result: Dict[str, Any],
        policy_version: str,
        rule_ids: List[str],
        resolver_principal_id: Optional[str] = None,
        resolution_source_hash: Optional[str] = None,
        approval_evidence_value: Any = None,
    ) -> Dict[str, Any]:
        with self._lock:
            self._ensure_process()
            if method == "expired":
                raise StrictReceiptCoordinatorV2Error(
                    "expired suspensions must use prepare_timeout"
                )
            input_value = {
                "suspended_receipt_hash": suspended_receipt_hash,
                "method": method,
                "context": context,
                "base_result": base_result,
                "policy_version": policy_version,
                "rule_ids": rule_ids,
                "resolver_principal_id": resolver_principal_id,
                "resolution_source_hash": resolution_source_hash,
                "approval_evidence": approval_evidence_value,
            }
            fingerprint = resolution_v2_fingerprint(
                input_value=input_value,
                tenant_id=self._tenant_id,
                session_id=self._session_id,
            )
            retry = self._prepared_state.retry(fingerprint, "resolution")
            if retry is not None:
                return copy.deepcopy(retry)
            receipt_hash = v2_hash(suspended_receipt_hash, "suspended_receipt_hash")
            pending = self._pending(receipt_hash)
            normalized = build_coordinator_context_v2(
                context, self._session_id, self._prior_actions
            )
            base = copy.deepcopy(base_result)
            evaluation = evaluate_intent_alignment_v2(
                context=normalized, base_result=base, policy=self._policy
            )
            timestamp, clamped = self._allocate_timestamp()
            evidence = validate_resolution_v2(
                input_value=input_value,
                pending=pending,
                context=normalized,
                base=base,
                evaluation=evaluation,
                timestamp=timestamp,
                approval_verifier=self._approval_verifier,
                approval_requests=self._approval_requests,
            )
            index = next(
                (
                    index
                    for index, item in enumerate(self._prior_actions)
                    if item["receipt_hash"] == receipt_hash
                ),
                None,
            )
            if index is None:
                raise StrictReceiptCoordinatorV2Error(
                    "suspended action summary is missing"
                )
            receipt = sign_resolution_v2(
                prior=pending["receipt"],
                method=method,
                principal_id=evidence["principal_id"],
                source_hash=evidence["source_hash"],
                tenant_id=self._tenant_id,
                session_id=self._session_id,
                sequence=self._sequence + 1,
                timestamp=timestamp,
                clamped=clamped,
                previous_hash=self._last_receipt_hash,
                sdk_version=self._sdk_version,
                signer=self._signer,
                include_public_key=self._include_public_key,
                context=normalized,
                base_result=base,
                evaluation=evaluation,
                policy_version=policy_version,
                rule_ids=rule_ids,
            )
            prepared = self._prepared_state.prepare(
                fingerprint=fingerprint,
                receipt_hash=receipt["receipt_hash"],
                kind="resolution",
                value=receipt,
                commit=lambda: self._commit_resolution(receipt, receipt_hash, index),
            )
            return copy.deepcopy(prepared)

    def prepare_timeout(
        self,
        *,
        suspended_receipt_hash: str,
        policy_version: str,
        rule_ids: List[str],
    ) -> Dict[str, Any]:
        with self._lock:
            self._ensure_process()
            input_value = {
                "suspended_receipt_hash": suspended_receipt_hash,
                "policy_version": policy_version,
                "rule_ids": rule_ids,
            }
            fingerprint = timeout_v2_fingerprint(
                input_value=input_value,
                tenant_id=self._tenant_id,
                session_id=self._session_id,
            )
            retry = self._prepared_state.retry(fingerprint, "timeout")
            if retry is not None:
                return copy.deepcopy(retry)
            receipt_hash = v2_hash(suspended_receipt_hash, "suspended_receipt_hash")
            pending = self._pending(receipt_hash)
            suspension = pending["receipt"]["body"]["suspension"]
            normalized = build_coordinator_context_v2(
                context_input_from_v2_document(pending["context"]),
                self._session_id,
                self._prior_actions,
            )
            base = {"action_taken": "blocked"}
            evaluation = evaluate_intent_alignment_v2(
                context=normalized, base_result=base, policy=self._policy
            )
            timestamp, clamped = self._allocate_timestamp()
            if timestamp < suspension["expires_at_ms"]:
                raise StrictReceiptCoordinatorV2Error("suspension has not expired")
            index = next(
                (
                    index
                    for index, item in enumerate(self._prior_actions)
                    if item["receipt_hash"] == receipt_hash
                ),
                None,
            )
            if index is None:
                raise StrictReceiptCoordinatorV2Error(
                    "suspended action summary is missing"
                )
            source_hash = v2_canonical_hash(
                {
                    "schema": "obsvr-strict-timeout-evidence-v2",
                    "tenant_id": self._tenant_id,
                    "session_id": self._session_id,
                    "suspended_receipt_hash": receipt_hash,
                    "expires_at_ms": suspension["expires_at_ms"],
                }
            )
            receipt = sign_resolution_v2(
                prior=pending["receipt"],
                method="expired",
                principal_id="obsvr:strict-receipt-coordinator",
                source_hash=source_hash,
                tenant_id=self._tenant_id,
                session_id=self._session_id,
                sequence=self._sequence + 1,
                timestamp=timestamp,
                clamped=clamped,
                previous_hash=self._last_receipt_hash,
                sdk_version=self._sdk_version,
                signer=self._signer,
                include_public_key=self._include_public_key,
                context=normalized,
                base_result=base,
                evaluation=evaluation,
                policy_version=policy_version,
                rule_ids=rule_ids,
            )
            prepared = self._prepared_state.prepare(
                fingerprint=fingerprint,
                receipt_hash=receipt["receipt_hash"],
                kind="timeout",
                value=receipt,
                commit=lambda: self._commit_resolution(receipt, receipt_hash, index),
            )
            return copy.deepcopy(prepared)

    def commit_prepared(self, token: str, receipt_hash: str) -> Any:
        with self._lock:
            self._ensure_process()
            return copy.deepcopy(self._prepared_state.commit(token, receipt_hash))

    def abort_prepared(self, token: str, receipt_hash: str, capability: Any) -> None:
        with self._lock:
            self._ensure_process()
            self._prepared_state.abort(token, receipt_hash, capability)

    def freeze_prepared(
        self,
        token: str,
        receipt_hash: str,
        reason: str = "transport_ambiguous",
    ) -> None:
        with self._lock:
            self._ensure_process()
            self._prepared_state.freeze(token, receipt_hash, reason)

    def inspect_state(self) -> Dict[str, Any]:
        with self._lock:
            self._ensure_process()
            return {
                "tenant_id": self._tenant_id,
                "session_id": self._session_id,
                "sequence": self._sequence,
                "head_receipt_hash": self._last_receipt_hash,
                **self._prepared_state.inspect(),
            }

    def _pending(self, receipt_hash: str) -> Dict[str, Any]:
        pending = self._suspended.get(receipt_hash)
        if pending is None:
            raise StrictReceiptCoordinatorV2Error("suspended receipt is not known")
        if receipt_hash in self._resolved:
            raise StrictReceiptCoordinatorV2Error("suspension is already resolved")
        return pending

    def _allocate_timestamp(self) -> tuple[int, bool]:
        observed = v2_integer(self._clock(), "clock")
        timestamp = max(observed, self._last_timestamp or 0)
        return timestamp, observed < timestamp

    def _commit_decision(
        self,
        result: Dict[str, Any],
        context: Dict[str, Any],
        base: Dict[str, Any],
    ) -> None:
        receipt = result["receipt"]
        self._advance(receipt)
        self._action_ids.add(receipt["body"]["action"]["action_id"])
        self._prior_actions.append(
            {
                "sequence": receipt["body"]["sequence"],
                "kind": receipt["body"]["action"]["kind"],
                "name": receipt["body"]["action"]["name"],
                "outcome": receipt["body"]["evaluation"]["outcome"],
                "receipt_hash": receipt["receipt_hash"],
                "data_classifications": list(context["action"]["data_classifications"]),
            }
        )
        if "suspension" in receipt["body"]:
            self._suspended[receipt["receipt_hash"]] = {
                "receipt": copy.deepcopy(receipt),
                "context": copy.deepcopy(context),
                "base_result": copy.deepcopy(base),
            }
        request_id = receipt["body"].get("suspension", {}).get("approval_request_id")
        if request_id is not None:
            self._approval_requests[request_id] = receipt["receipt_hash"]

    def _commit_resolution(
        self,
        receipt: Dict[str, Any],
        suspended_hash: str,
        index: int,
    ) -> None:
        classifications = self._prior_actions[index]["data_classifications"]
        self._advance(receipt)
        self._prior_actions[index] = {
            "sequence": receipt["body"]["sequence"],
            "kind": receipt["body"]["action"]["kind"],
            "name": receipt["body"]["action"]["name"],
            "outcome": receipt["body"]["evaluation"]["outcome"],
            "receipt_hash": receipt["receipt_hash"],
            "data_classifications": list(classifications),
        }
        self._prior_actions.sort(key=lambda item: item["sequence"])
        self._resolved.add(suspended_hash)

    def _advance(self, receipt: Dict[str, Any]) -> None:
        self._sequence = receipt["body"]["sequence"]
        self._last_receipt_hash = receipt["receipt_hash"]
        self._last_timestamp = receipt["body"]["timestamp_ms"]

    def _ensure_process(self) -> None:
        if v2_integer(self._pid_source(), "pid") != self._owner_pid:
            raise StrictReceiptCoordinatorV2Error(
                "strict v2 coordinator cannot cross a process boundary"
            )


__all__ = ["StrictReceiptCoordinatorV2", "StrictReceiptCoordinatorV2Error"]
