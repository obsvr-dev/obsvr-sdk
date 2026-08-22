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
    STRICT_RECEIPT_PROFILE_VERSION,
    STRICT_RECEIPT_SCHEMA,
    sign_strict_receipt,
    strict_receipt_key_id,
)
from .strict_receipt_coordinator_support import (
    build_coordinator_context,
    context_input_from_document,
    coordinator_hash,
    coordinator_text,
    normalized_strings,
    request_fingerprint,
    safe_add,
    safe_integer,
    sign_coordinator_resolution,
    trusted_approval_result,
    validate_deferred_changes,
)
from .tool_pinning import _canonical_json_for_hash

_FINAL_OUTCOMES = frozenset({"ALLOW", "DENY", "MODIFY"})
_DENIAL_METHODS = frozenset({"approval_denied", "expired", "cancelled"})
_APPROVAL_METHODS = frozenset({"approval_granted", "approval_denied"})


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
        self._reset_state()
        if hasattr(os, "register_at_fork"):
            os.register_at_fork(after_in_child=self._after_fork_child)

    def decide(
        self, *, context: Dict[str, Any], base_result: Dict[str, Any],
        policy_version: str, rule_ids: List[str], action_id: str,
    ) -> Dict[str, Any]:
        with self._lock:
            self._ensure_process()
            action = coordinator_text(action_id, "action_id")
            fingerprint = request_fingerprint(
                context=context, base_result=base_result,
                policy_version=policy_version, rule_ids=rule_ids,
                session_id=self._session_id,
            )
            cached = self._decisions.get(action)
            if cached is not None:
                if cached["fingerprint"] != fingerprint:
                    raise StrictReceiptCoordinatorError(
                        "action_id was reused with different input"
                    )
                return copy.deepcopy(cached["result"])
            base_snapshot = copy.deepcopy(base_result)
            normalized = build_coordinator_context(
                context, self._session_id, self._prior_actions
            )
            evaluation = evaluate_intent_alignment(
                context=normalized, base_result=base_snapshot, policy=self._policy
            )
            timestamp, clamped = self._allocate_timestamp()
            sequence = self._sequence + 1
            body = self._decision_body(
                action, normalized, base_snapshot, evaluation, policy_version,
                rule_ids, timestamp, clamped, sequence,
            )
            receipt = sign_strict_receipt(
                body, self._signer, self._include_public_key
            )
            result = {"evaluation": evaluation, "receipt": receipt}
            self._commit_decision(result, normalized, base_snapshot, fingerprint)
            return copy.deepcopy(result)

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
            if method == "expired":
                raise StrictReceiptCoordinatorError(
                    "expired suspensions must use timeout"
                )
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
            principal, source = self._validate_resolution(
                pending=pending, method=method, context=normalized,
                base_result=base_snapshot, evaluation=evaluation,
                resolved_at=timestamp, resolver_principal_id=resolver_principal_id,
                resolution_source_hash=resolution_source_hash,
                approval_evidence_value=approval_evidence_value,
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
            self._commit_resolution(receipt, receipt_hash)
            return copy.deepcopy(receipt)

    def timeout(
        self, *, suspended_receipt_hash: str,
        policy_version: str, rule_ids: List[str],
    ) -> Dict[str, Any]:
        with self._lock:
            self._ensure_process()
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
                _canonical_json_for_hash(
                    {
                        "schema": "obsvr-strict-timeout-evidence-v1",
                        "suspended_receipt_hash": receipt_hash,
                        "expires_at_ms": suspension["expires_at_ms"],
                    }
                ).encode("utf-8")
            ).hexdigest()
            receipt = sign_coordinator_resolution(
                prior=pending["receipt"], evaluation=evaluation,
                context=normalized, base_result=base_result,
                policy_version=policy_version, rule_ids=rule_ids,
                method="expired",
                principal_id="obsvr:strict-receipt-coordinator",
                source_hash=source, timestamp=timestamp, clamped=clamped,
                sequence=self._sequence + 1, session_id=self._session_id,
                previous_hash=self._last_receipt_hash,
                sdk_version=self._sdk_version, signer=self._signer,
                include_public_key=self._include_public_key,
            )
            self._commit_resolution(receipt, receipt_hash)
            return copy.deepcopy(receipt)

    def _decision_body(
        self, action_id: str, context: Dict[str, Any], base: Dict[str, Any],
        evaluation: Dict[str, Any], policy_version: str, rule_ids: List[str],
        timestamp: int, clamped: bool, sequence: int,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "schema": STRICT_RECEIPT_SCHEMA,
            "profile_version": STRICT_RECEIPT_PROFILE_VERSION,
            "record_type": "decision",
            "receipt_id": f"{self._session_id}:{sequence}",
            "session_id": self._session_id, "sequence": sequence,
            "timestamp_ms": timestamp, "clock_regression_clamped": clamped,
            "previous_receipt_hash": self._last_receipt_hash,
            "sdk": {"language": "python", "version": self._sdk_version},
            "initiator": {
                "agent_id": context["agent"]["agent_id"],
                "key_id": strict_receipt_key_id(self._signer.raw_public_key),
            },
            "action": {
                "action_id": action_id, "kind": context["action"]["kind"],
                "name": context["action"]["name"],
                "arguments_hash": context["action"]["arguments_hash"],
            },
            "context": {
                "schema": "obsvr-action-context-v1",
                "context_hash": evaluation["context_hash"],
                "run_id": context["run_id"],
            },
            "evaluation": {
                "input_hash": evaluation["input_hash"],
                "policy_hash": evaluation["policy_hash"],
                "evaluator_hash": evaluation["evaluator_hash"],
                "engine_version": evaluation["engine_version"],
                "policy_version": coordinator_text(policy_version, "policy_version"),
                "outcome": evaluation["outcome"],
                "reason_code": evaluation["reason_code"],
                "rule_ids": normalized_strings(rule_ids, "rule_ids"),
            },
            "execution_authorized": evaluation["outcome"] in ("ALLOW", "MODIFY"),
        }
        if "target" in context["action"]:
            body["action"]["target"] = context["action"]["target"]
        if "thread_id" in context:
            body["context"]["thread_id"] = context["thread_id"]
        if evaluation["outcome"] == "MODIFY":
            body["action"]["effective_arguments_hash"] = base["modified_arguments_hash"]
        if evaluation["outcome"] == "STEP_UP":
            request_id = base["approval_request_id"]
            if request_id in self._approval_requests:
                raise StrictReceiptCoordinatorError(
                    "approval_request_id is already pending"
                )
            body["suspension"] = {
                "suspension_id": request_id, "type": "approval",
                "status": "pending", "required_fields": [],
                "expires_at_ms": base["approval_expires_at_ms"],
                "approval_request_id": request_id,
                "approval_action_hash": base["approval_action_hash"],
            }
            if body["suspension"]["expires_at_ms"] <= timestamp:
                raise StrictReceiptCoordinatorError(
                    "approval expiry must follow decision timestamp"
                )
        elif evaluation["outcome"] == "DEFER":
            body["suspension"] = {
                "suspension_id": f"defer:{self._session_id}:{sequence}",
                "type": "context", "status": "pending",
                "required_fields": evaluation["required_fields"],
                "expires_at_ms": safe_add(timestamp, self._defer_ttl_ms),
            }
        return body

    def _validate_resolution(
        self, *, pending: Dict[str, Any], method: str,
        context: Dict[str, Any], base_result: Dict[str, Any],
        evaluation: Dict[str, Any], resolved_at: int,
        resolver_principal_id: Optional[str],
        resolution_source_hash: Optional[str],
        approval_evidence_value: Optional[Dict[str, Any]],
    ) -> tuple[str, str]:
        prior = pending["receipt"]
        suspension = prior["body"]["suspension"]
        if evaluation["outcome"] not in _FINAL_OUTCOMES:
            raise StrictReceiptCoordinatorError("resolution evaluation must be final")
        action = context["action"]
        prior_action = prior["body"]["action"]
        if (
            context["agent"]["agent_id"] != prior["body"]["initiator"]["agent_id"]
            or any(action.get(key) != prior_action.get(key)
                   for key in ("kind", "name", "arguments_hash", "target"))
        ):
            raise StrictReceiptCoordinatorError(
                "resolution action or initiator does not match suspension"
            )
        approval_method = method in _APPROVAL_METHODS
        if (
            (suspension["type"] == "approval") != approval_method
            and method not in ("expired", "cancelled")
        ):
            raise StrictReceiptCoordinatorError(
                "resolution method does not match suspension"
            )
        if approval_method:
            expected = {
                "request_id": suspension["approval_request_id"],
                "action_hash": suspension["approval_action_hash"],
                "decision": "granted" if method == "approval_granted" else "denied",
                "current_time_ms": resolved_at,
            }
            evidence = trusted_approval_result(
                self._approval_verifier(approval_evidence_value, expected),
                expected,
                suspension["expires_at_ms"],
            )
            if evidence["request_id"] != suspension["approval_request_id"]:
                raise StrictReceiptCoordinatorError(
                    "approval_request_id does not match suspension"
                )
            if evidence["action_hash"] != suspension["approval_action_hash"]:
                raise StrictReceiptCoordinatorError(
                    "approval_action_hash does not match suspension"
                )
            if self._approval_requests.get(evidence["request_id"]) != prior["receipt_hash"]:
                raise StrictReceiptCoordinatorError(
                    "approval request belongs to another suspension"
                )
            if resolver_principal_id is not None or resolution_source_hash is not None:
                raise StrictReceiptCoordinatorError(
                    "approval source must come from approval evidence"
                )
            principal, source = evidence["principal_id"], evidence["source_hash"]
        else:
            if approval_evidence_value is not None:
                raise StrictReceiptCoordinatorError(
                    "approval evidence requires an approval method"
                )
            if suspension["type"] == "context":
                validate_deferred_changes(
                    original_context=pending["context"], current_context=context,
                    original_base=pending["base_result"], current_base=base_result,
                    required_fields=suspension["required_fields"],
                )
            principal = coordinator_text(
                resolver_principal_id, "resolver_principal_id"
            )
            source = coordinator_hash(
                resolution_source_hash, "resolution_source_hash"
            )
        if method in ("approval_granted", "context_supplied") and (
            resolved_at >= suspension["expires_at_ms"]
        ):
            raise StrictReceiptCoordinatorError(
                "authorization cannot occur after suspension expiry"
            )
        if method in _DENIAL_METHODS and evaluation["outcome"] != "DENY":
            raise StrictReceiptCoordinatorError("resolution method requires DENY")
        if method == "approval_granted" and evaluation["outcome"] == "DENY":
            raise StrictReceiptCoordinatorError(
                "approval_granted requires ALLOW or MODIFY"
            )
        if evaluation["outcome"] == "MODIFY" and (
            coordinator_hash(base_result.get("modified_arguments_hash"),
                             "modified_arguments_hash")
            == prior_action["arguments_hash"]
        ):
            raise StrictReceiptCoordinatorError(
                "effective_arguments_hash must change arguments"
            )
        return principal, source

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

    def _commit_resolution(self, receipt: Dict[str, Any], suspended_hash: str) -> None:
        index = next(
            (index for index, item in enumerate(self._prior_actions)
             if item["receipt_hash"] == suspended_hash), None
        )
        if index is None:
            raise StrictReceiptCoordinatorError("suspended action summary is missing")
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
