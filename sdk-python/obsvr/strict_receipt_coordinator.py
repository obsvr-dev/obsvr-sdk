"""Stateful strict-receipt coordination over pure policy and receipt cores."""

from __future__ import annotations

import copy
import hashlib
import os
import threading
import uuid
from typing import Any, Callable, Dict, List, Optional

from .device_identity import DeviceSigner
from .intent_alignment import build_intent_policy, evaluate_intent_alignment
from .strict_receipt import (
    strict_receipt_key_id,
)
from .strict_receipt_coordinator_support import (
    build_coordinator_context,
    context_input_from_document,
    coordinator_hash,
    coordinator_text,
    request_fingerprint,
    safe_integer,
    sign_coordinator_decision,
    sign_coordinator_resolution,
    validate_coordinator_resolution,
)
from .strict_receipt_prepared_state import PreparedReceiptState
from .tool_pinning import _canonical_json_for_hash


class StrictReceiptCoordinatorError(ValueError):
    """Coordinator input or lifecycle state is invalid."""


class StrictReceiptCoordinator:
    """Own one process-local strict receipt session and its suspension state."""

    def __init__(
        self, *, signer: DeviceSigner, policy: Any, sdk_language: str,
        sdk_version: str, session_id: str, clock: Callable[[], int],
        defer_ttl_ms: int,
        approval_verifier: Callable[[Any, Dict[str, Any]], Dict[str, Any]],
        include_public_key: bool = True,
        pid: Optional[Callable[[], int]] = None,
        session_factory: Optional[Callable[[], str]] = None,
        prepared_token_factory: Optional[Callable[[], str]] = None,
    ) -> None:
        if sdk_language != "python":
            raise StrictReceiptCoordinatorError("sdk_language must be python")
        if not isinstance(include_public_key, bool):
            raise StrictReceiptCoordinatorError("include_public_key must be a boolean")
        self._signer = signer
        self._policy = build_intent_policy(policy)
        self._sdk_version = coordinator_text(sdk_version, "sdk_version")
        self._session_id = coordinator_text(session_id, "session_id")
        self._clock = clock
        self._defer_ttl_ms = safe_integer(defer_ttl_ms, "defer_ttl_ms")
        if self._defer_ttl_ms == 0:
            raise StrictReceiptCoordinatorError("defer_ttl_ms must be positive")
        if not callable(approval_verifier):
            raise StrictReceiptCoordinatorError("approval_verifier must be callable")
        self._approval_verifier = approval_verifier
        self._include_public_key = include_public_key
        self._pid_source = pid or os.getpid
        self._session_factory = session_factory or (lambda: str(uuid.uuid4()))
        self._owner_pid = safe_integer(self._pid_source(), "pid")
        strict_receipt_key_id(signer.raw_public_key)
        self._lock = threading.RLock()
        self._prepared_state = PreparedReceiptState(
            prepared_token_factory or (lambda: str(uuid.uuid4()))
        )
        self._reset_state()
        if hasattr(os, "register_at_fork"):
            os.register_at_fork(after_in_child=self._after_fork_child)

    def decide(
        self, *, context: Dict[str, Any], base_result: Dict[str, Any],
        policy_version: str, rule_ids: List[str], action_id: str,
    ) -> Dict[str, Any]:
        with self._lock:
            self._ensure_process()
            fingerprint = request_fingerprint(
                context=context, base_result=base_result,
                policy_version=policy_version, rule_ids=rule_ids,
                session_id=self._session_id, action_id=action_id,
            )
            cached = self._decisions.get(action_id)
            if cached is not None:
                if cached["fingerprint"] != fingerprint:
                    raise StrictReceiptCoordinatorError(
                        "action_id was reused with different input"
                    )
                return copy.deepcopy(cached["result"])
            prepared = self._prepare_decision(
                context=context, base_result=base_result,
                policy_version=policy_version, rule_ids=rule_ids,
                action_id=action_id, fingerprint=fingerprint,
            )
            return copy.deepcopy(self._prepared_state.commit(
                prepared["token"], prepared["receipt_hash"]
            ))

    def prepare_decision(
        self, *, context: Dict[str, Any], base_result: Dict[str, Any],
        policy_version: str, rule_ids: List[str], action_id: str,
    ) -> Dict[str, Any]:
        with self._lock:
            self._ensure_process()
            fingerprint = request_fingerprint(
                context=context, base_result=base_result,
                policy_version=policy_version, rule_ids=rule_ids,
                session_id=self._session_id, action_id=action_id,
            )
            return self._prepare_decision(
                context=context, base_result=base_result,
                policy_version=policy_version, rule_ids=rule_ids,
                action_id=action_id, fingerprint=fingerprint,
            )

    def _prepare_decision(
        self, *, context: Dict[str, Any], base_result: Dict[str, Any],
        policy_version: str, rule_ids: List[str], action_id: str,
        fingerprint: str,
    ) -> Dict[str, Any]:
        action = coordinator_text(action_id, "action_id")
        if action in self._decisions:
            raise StrictReceiptCoordinatorError("action_id is already committed")
        retry = self._prepared_state.retry(fingerprint, "decision")
        if retry is not None:
            return copy.deepcopy(retry)
        base_snapshot = copy.deepcopy(base_result)
        normalized = build_coordinator_context(
            context, self._session_id, self._prior_actions
        )
        evaluation = evaluate_intent_alignment(
            context=normalized, base_result=base_snapshot, policy=self._policy
        )
        timestamp, clamped = self._allocate_timestamp()
        receipt = sign_coordinator_decision(
            action_id=action, context=normalized, base_result=base_snapshot,
            evaluation=evaluation, policy_version=policy_version,
            rule_ids=rule_ids, timestamp=timestamp, clamped=clamped,
            sequence=self._sequence + 1, session_id=self._session_id,
            previous_hash=self._last_receipt_hash,
            sdk_version=self._sdk_version, signer=self._signer,
            include_public_key=self._include_public_key,
            defer_ttl_ms=self._defer_ttl_ms,
            approval_request_pending=lambda value: value in self._approval_requests,
        )
        result = {"evaluation": evaluation, "receipt": receipt}
        prepared = self._prepared_state.prepare(
            fingerprint=fingerprint, receipt_hash=receipt["receipt_hash"],
            kind="decision", value=result,
            commit=lambda: self._commit_decision(
                result, normalized, base_snapshot, fingerprint
            ),
        )
        return copy.deepcopy(prepared)

    def resolve(
        self, *, suspended_receipt_hash: str, method: str,
        context: Dict[str, Any], base_result: Dict[str, Any],
        policy_version: str, rule_ids: List[str],
        resolver_principal_id: Optional[str] = None,
        resolution_source_hash: Optional[str] = None,
        approval_evidence_value: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        with self._lock:
            self._ensure_process()
            prepared = self._prepare_resolution(
                suspended_receipt_hash=suspended_receipt_hash, method=method,
                context=context, base_result=base_result,
                policy_version=policy_version, rule_ids=rule_ids,
                resolver_principal_id=resolver_principal_id,
                resolution_source_hash=resolution_source_hash,
                approval_evidence_value=approval_evidence_value,
            )
            return copy.deepcopy(self._prepared_state.commit(
                prepared["token"], prepared["receipt_hash"]
            ))

    def prepare_resolution(self, **input_value: Any) -> Dict[str, Any]:
        with self._lock:
            self._ensure_process()
            return self._prepare_resolution(**input_value)

    def _prepare_resolution(
        self, *, suspended_receipt_hash: str, method: str,
        context: Dict[str, Any], base_result: Dict[str, Any],
        policy_version: str, rule_ids: List[str],
        resolver_principal_id: Optional[str] = None,
        resolution_source_hash: Optional[str] = None,
        approval_evidence_value: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if method == "expired":
            raise StrictReceiptCoordinatorError("expired suspensions must use timeout")
        fingerprint = hashlib.sha256(
            _canonical_json_for_hash({
                "schema": "obsvr-strict-prepare-resolution-v1",
                "session_id": self._session_id,
                "input": {
                    "suspended_receipt_hash": suspended_receipt_hash,
                    "method": method, "context": context,
                    "base_result": base_result, "policy_version": policy_version,
                    "rule_ids": rule_ids,
                    "resolver_principal_id": resolver_principal_id,
                    "resolution_source_hash": resolution_source_hash,
                    "approval_evidence_value": approval_evidence_value,
                },
            }).encode("utf-8")
        ).hexdigest()
        retry = self._prepared_state.retry(fingerprint, "resolution")
        if retry is not None:
            return copy.deepcopy(retry)
        receipt_hash = coordinator_hash(
            suspended_receipt_hash, "suspended_receipt_hash"
        )
        pending = self._pending(receipt_hash)
        normalized = build_coordinator_context(
            context, self._session_id, self._prior_actions
        )
        base_snapshot = copy.deepcopy(base_result)
        evaluation = evaluate_intent_alignment(
            context=normalized, base_result=base_snapshot, policy=self._policy
        )
        timestamp, clamped = self._allocate_timestamp()
        principal, source = validate_coordinator_resolution(
            pending=pending, method=method, context=normalized,
            base_result=base_snapshot, evaluation=evaluation,
            resolved_at=timestamp, resolver_principal_id=resolver_principal_id,
            resolution_source_hash=resolution_source_hash,
            approval_evidence_value=approval_evidence_value,
            approval_verifier=self._approval_verifier,
            approval_request_receipt=self._approval_requests.get,
        )
        receipt = sign_coordinator_resolution(
            prior=pending["receipt"], evaluation=evaluation,
            context=normalized, base_result=base_snapshot,
            policy_version=policy_version, rule_ids=rule_ids, method=method,
            principal_id=principal, source_hash=source,
            timestamp=timestamp, clamped=clamped,
            sequence=self._sequence + 1, session_id=self._session_id,
            previous_hash=self._last_receipt_hash,
            sdk_version=self._sdk_version, signer=self._signer,
            include_public_key=self._include_public_key,
        )
        summary_index = next(
            (index for index, item in enumerate(self._prior_actions)
             if item["receipt_hash"] == receipt_hash), None
        )
        if summary_index is None:
            raise StrictReceiptCoordinatorError("suspended action summary is missing")
        prepared = self._prepared_state.prepare(
            fingerprint=fingerprint, receipt_hash=receipt["receipt_hash"],
            kind="resolution", value=receipt,
            commit=lambda: self._commit_resolution(
                receipt, receipt_hash, summary_index
            ),
        )
        return copy.deepcopy(prepared)

    def timeout(
        self, *, suspended_receipt_hash: str,
        policy_version: str, rule_ids: List[str],
    ) -> Dict[str, Any]:
        with self._lock:
            self._ensure_process()
            prepared = self._prepare_timeout(
                suspended_receipt_hash=suspended_receipt_hash,
                policy_version=policy_version, rule_ids=rule_ids,
            )
            return copy.deepcopy(self._prepared_state.commit(
                prepared["token"], prepared["receipt_hash"]
            ))

    def prepare_timeout(
        self, *, suspended_receipt_hash: str,
        policy_version: str, rule_ids: List[str],
    ) -> Dict[str, Any]:
        with self._lock:
            self._ensure_process()
            return self._prepare_timeout(
                suspended_receipt_hash=suspended_receipt_hash,
                policy_version=policy_version, rule_ids=rule_ids,
            )

    def _prepare_timeout(
        self, *, suspended_receipt_hash: str,
        policy_version: str, rule_ids: List[str],
    ) -> Dict[str, Any]:
        fingerprint = hashlib.sha256(
            _canonical_json_for_hash({
                "schema": "obsvr-strict-prepare-timeout-v1",
                "session_id": self._session_id,
                "input": {
                    "suspended_receipt_hash": suspended_receipt_hash,
                    "policy_version": policy_version, "rule_ids": rule_ids,
                },
            }).encode("utf-8")
        ).hexdigest()
        retry = self._prepared_state.retry(fingerprint, "timeout")
        if retry is not None:
            return copy.deepcopy(retry)
        receipt_hash = coordinator_hash(
            suspended_receipt_hash, "suspended_receipt_hash"
        )
        pending = self._pending(receipt_hash)
        suspension = pending["receipt"]["body"]["suspension"]
        normalized = build_coordinator_context(
            context_input_from_document(pending["context"]),
            self._session_id, self._prior_actions,
        )
        base_result = {"action_taken": "blocked"}
        evaluation = evaluate_intent_alignment(
            context=normalized, base_result=base_result, policy=self._policy
        )
        timestamp, clamped = self._allocate_timestamp()
        if timestamp < suspension["expires_at_ms"]:
            raise StrictReceiptCoordinatorError("suspension has not expired")
        source = hashlib.sha256(
            _canonical_json_for_hash({
                "schema": "obsvr-strict-timeout-evidence-v1",
                "suspended_receipt_hash": receipt_hash,
                "expires_at_ms": suspension["expires_at_ms"],
            }).encode("utf-8")
        ).hexdigest()
        receipt = sign_coordinator_resolution(
            prior=pending["receipt"], evaluation=evaluation,
            context=normalized, base_result=base_result,
            policy_version=policy_version, rule_ids=rule_ids,
            method="expired", principal_id="obsvr:strict-receipt-coordinator",
            source_hash=source, timestamp=timestamp, clamped=clamped,
            sequence=self._sequence + 1, session_id=self._session_id,
            previous_hash=self._last_receipt_hash,
            sdk_version=self._sdk_version, signer=self._signer,
            include_public_key=self._include_public_key,
        )
        summary_index = next(
            (index for index, item in enumerate(self._prior_actions)
             if item["receipt_hash"] == receipt_hash), None
        )
        if summary_index is None:
            raise StrictReceiptCoordinatorError("suspended action summary is missing")
        prepared = self._prepared_state.prepare(
            fingerprint=fingerprint, receipt_hash=receipt["receipt_hash"],
            kind="timeout", value=receipt,
            commit=lambda: self._commit_resolution(
                receipt, receipt_hash, summary_index
            ),
        )
        return copy.deepcopy(prepared)

    def commit_prepared(self, token: str, receipt_hash: str) -> Any:
        with self._lock:
            self._ensure_process()
            return copy.deepcopy(self._prepared_state.commit(token, receipt_hash))

    def abort_prepared(self, token: str, receipt_hash: str, status: Any) -> None:
        with self._lock:
            self._ensure_process()
            self._prepared_state.abort(token, receipt_hash, status)

    def freeze_prepared(
        self, token: str, receipt_hash: str,
        reason: str = "transport_ambiguous",
    ) -> None:
        with self._lock:
            self._ensure_process()
            self._prepared_state.freeze(token, receipt_hash, reason)

    def reconcile_prepared(self, input_value: Dict[str, Any]) -> Any:
        with self._lock:
            self._ensure_process()
            return copy.deepcopy(self._prepared_state.reconcile(input_value))

    def inspect_state(self) -> Dict[str, Any]:
        with self._lock:
            self._ensure_process()
            return {
                "session_id": self._session_id, "sequence": self._sequence,
                "head_receipt_hash": self._last_receipt_hash,
                **self._prepared_state.inspect(),
            }

    def _pending(self, receipt_hash: str) -> Dict[str, Any]:
        pending = self._suspended.get(receipt_hash)
        if pending is None:
            raise StrictReceiptCoordinatorError("suspended receipt is not known")
        if receipt_hash in self._resolved:
            raise StrictReceiptCoordinatorError("suspension is already resolved")
        return pending

    def _allocate_timestamp(self) -> tuple[int, bool]:
        observed = safe_integer(self._clock(), "clock")
        timestamp = max(observed, self._last_timestamp or 0)
        return timestamp, observed < timestamp

    def _commit_decision(
        self, result: Dict[str, Any], context: Dict[str, Any],
        base_result: Dict[str, Any], fingerprint: str,
    ) -> None:
        receipt = result["receipt"]
        body = receipt["body"]
        self._advance(receipt)
        self._prior_actions.append(
            {
                "sequence": body["sequence"], "kind": body["action"]["kind"],
                "name": body["action"]["name"],
                "outcome": body["evaluation"]["outcome"],
                "receipt_hash": receipt["receipt_hash"],
                "data_classifications": list(context["action"]["data_classifications"]),
            }
        )
        if "suspension" in body:
            self._suspended[receipt["receipt_hash"]] = {
                "receipt": receipt, "context": copy.deepcopy(context),
                "base_result": copy.deepcopy(base_result),
            }
        self._decisions[body["action"]["action_id"]] = {
            "fingerprint": fingerprint, "result": copy.deepcopy(result),
        }
        request_id = body.get("suspension", {}).get("approval_request_id")
        if request_id is not None:
            self._approval_requests[request_id] = receipt["receipt_hash"]

    def _commit_resolution(
        self, receipt: Dict[str, Any], suspended_hash: str, index: int,
    ) -> None:
        classifications = self._prior_actions[index]["data_classifications"]
        body = receipt["body"]
        self._advance(receipt)
        self._prior_actions[index] = {
            "sequence": body["sequence"], "kind": body["action"]["kind"],
            "name": body["action"]["name"],
            "outcome": body["evaluation"]["outcome"],
            "receipt_hash": receipt["receipt_hash"],
            "data_classifications": list(classifications),
        }
        self._prior_actions.sort(key=lambda item: item["sequence"])
        self._resolved.add(suspended_hash)

    def _advance(self, receipt: Dict[str, Any]) -> None:
        self._sequence = receipt["body"]["sequence"]
        self._last_receipt_hash = receipt["receipt_hash"]
        self._last_timestamp = receipt["body"]["timestamp_ms"]

    def _reset_state(self) -> None:
        self._sequence = 0
        self._last_receipt_hash: Optional[str] = None
        self._last_timestamp: Optional[int] = None
        self._prior_actions: List[Dict[str, Any]] = []
        self._suspended: Dict[str, Dict[str, Any]] = {}
        self._resolved: set[str] = set()
        self._decisions: Dict[str, Dict[str, Any]] = {}
        self._approval_requests: Dict[str, str] = {}
        self._prepared_state.reset()

    def _new_session(self, allow_fallback: bool = False) -> str:
        try:
            value = coordinator_text(self._session_factory(), "session_factory result")
            if value == self._session_id:
                raise ValueError("fork session_factory must return a new session_id")
            return value
        except (TypeError, ValueError):
            if not allow_fallback:
                raise
            return str(uuid.uuid4())

    def _after_fork_child(self) -> None:
        self._lock = threading.RLock()
        self._owner_pid = safe_integer(self._pid_source(), "pid")
        self._session_id = self._new_session(allow_fallback=True)
        self._reset_state()

    def _ensure_process(self) -> None:
        current = safe_integer(self._pid_source(), "pid")
        if current == self._owner_pid:
            return
        self._session_id = self._new_session()
        self._owner_pid = current
        self._reset_state()
