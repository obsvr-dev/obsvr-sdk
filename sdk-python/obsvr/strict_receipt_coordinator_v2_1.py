"""Two-phase strict profile-2.1 decision receipt coordinator."""

from __future__ import annotations

import copy
import os
import threading
import uuid
from typing import Any, Callable, Dict, List, Optional

from .strict_receipt_coordinator_v2_1_support import (
    StrictReceiptCoordinatorV21Error,
    assert_trusted_intent_decision_provider_v2_1,
    build_coordinator_context_v2_1,
    build_intent_policy_v2,
    capture_identity_v2_1,
    create_trusted_intent_decision_provider_v2_1,
    decision_v2_1_fingerprint,
    evaluate_decision_v2_1,
    normalize_decision_action_v2_1,
    sign_decision_v2_1,
    v21_integer,
    v21_text,
)
from .strict_receipt_coordinator_v2_1_approval import (
    approval_resolution_fingerprint_v2_1,
    normalize_approval_resolution_v2_1,
    sign_approval_resolution_v2_1,
)
from .strict_receipt_prepared_state import PreparedReceiptState
from .strict_execution_outcome_v2_1 import sign_strict_execution_outcome_v2_1
from .strict_receipt_v2_1 import strict_receipt_v2_1_key_id


class StrictReceiptCoordinatorV21:
    """Prepare signed decisions, then advance only after durable admission."""

    def __init__(
        self,
        *,
        signer: Any,
        policy: Dict[str, Any],
        tenant_id: str,
        session_id: str,
        sdk_language: str,
        clock: Callable[[], int],
        defer_ttl_ms: int,
        identity_authority: Any,
        identity_snapshot: Callable[[int], Dict[str, Any]],
        intent_decision_provider: Any,
        evaluation_evidence_provider: Any,
        approval_verifier: Optional[Callable[[Any, Dict[str, Any]], Dict[str, Any]]] = None,
        pid: Callable[[], int] = os.getpid,
        prepared_token_factory: Callable[[], str] = lambda: str(uuid.uuid4()),
    ) -> None:
        if sdk_language != "python":
            raise StrictReceiptCoordinatorV21Error("sdk_language must be python")
        if not callable(clock):
            raise StrictReceiptCoordinatorV21Error("clock must be callable")
        if not callable(identity_snapshot) or not callable(
            getattr(identity_authority, "issue", None)
        ):
            raise StrictReceiptCoordinatorV21Error(
                "trusted identity authority and snapshot are required"
            )
        assert_trusted_intent_decision_provider_v2_1(intent_decision_provider)
        self._signer = signer
        self._policy = build_intent_policy_v2(policy)
        self._tenant_id = v21_text(tenant_id, "tenant_id")
        self._session_id = v21_text(session_id, "session_id")
        self._clock = clock
        self._defer_ttl_ms = v21_integer(defer_ttl_ms, "defer_ttl_ms")
        if self._defer_ttl_ms == 0:
            raise StrictReceiptCoordinatorV21Error("defer_ttl_ms must be positive")
        self._identity_authority = identity_authority
        self._identity_snapshot = identity_snapshot
        self._intent_decision_provider = intent_decision_provider
        self._evaluation_evidence_provider = evaluation_evidence_provider
        self._approval_verifier = approval_verifier
        self._pid_source = pid
        self._owner_pid = v21_integer(pid(), "pid")
        strict_receipt_v2_1_key_id(signer.raw_public_key)
        self._prepared_state = PreparedReceiptState(prepared_token_factory)
        self._sequence = 0
        self._head_receipt_hash: Optional[str] = None
        self._last_timestamp: Optional[int] = None
        self._prior_actions: List[Dict[str, Any]] = []
        self._committed_action_ids: set[str] = set()
        self._pending_approval_ids: set[str] = set()
        self._suspended_approvals: Dict[str, Dict[str, Any]] = {}
        self._resolved_approvals: set[str] = set()
        self._lock = threading.RLock()

    def prepare_decision(self, input_value: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            self._ensure_process()
            normalized_input = normalize_decision_action_v2_1(input_value)
            action_id = normalized_input["action_id"]
            if action_id in self._committed_action_ids:
                raise StrictReceiptCoordinatorV21Error("action_id is already committed")
            fingerprint = decision_v2_1_fingerprint(
                normalized_input,
                self._tenant_id,
                self._session_id,
                self._policy,
            )
            retry = self._prepared_state.retry(fingerprint, "decision")
            if retry is not None:
                return copy.deepcopy(retry)

            timestamp = self._allocate_timestamp()
            identity = capture_identity_v2_1(
                {
                    "identity_authority": self._identity_authority,
                    "identity_snapshot": self._identity_snapshot,
                },
                timestamp,
            )
            context = build_coordinator_context_v2_1(
                normalized_input,
                identity,
                self._session_id,
                copy.deepcopy(self._prior_actions),
            )
            evaluated = evaluate_decision_v2_1(
                context,
                self._policy,
                self._intent_decision_provider,
                self._evaluation_evidence_provider,
            )
            receipt = sign_decision_v2_1(
                input_value=normalized_input,
                identity=identity,
                context=context,
                evaluation=evaluated["evidence"],
                base_result=evaluated["base_result"],
                tenant_id=self._tenant_id,
                session_id=self._session_id,
                sequence=self._sequence + 1,
                timestamp=timestamp,
                previous_hash=self._head_receipt_hash,
                defer_ttl_ms=self._defer_ttl_ms,
                signer=self._signer,
            )
            if receipt["body"]["context_hash"] != evaluated["intent"]["context_hash"]:
                raise StrictReceiptCoordinatorV21Error(
                    "signed context_hash does not match intent evaluation"
                )
            suspension = receipt["body"].get("suspension")
            approval_id = (
                suspension["suspension_id"]
                if suspension is not None and suspension["type"] == "approval"
                else None
            )
            if approval_id is not None and approval_id in self._pending_approval_ids:
                raise StrictReceiptCoordinatorV21Error(
                    "approval request is already pending"
                )
            result = {
                "action_context": context,
                "intent_evaluation": {
                    key: evaluated["intent"][key]
                    for key in (
                        "outcome",
                        "reason_code",
                        "context_hash",
                        "policy_hash",
                    )
                },
                "evaluation_evidence": evaluated["evidence"],
                "receipt": receipt,
            }
            prepared = self._prepared_state.prepare(
                fingerprint=fingerprint,
                receipt_hash=receipt["receipt_hash"],
                kind="decision",
                value=result,
                commit=lambda: self._commit_decision(result, normalized_input),
            )
            return copy.deepcopy(prepared)

    def prepare_approval_resolution(self, input_value: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            self._ensure_process()
            normalized = normalize_approval_resolution_v2_1(input_value)
            fingerprint = approval_resolution_fingerprint_v2_1(
                normalized, self._tenant_id, self._session_id
            )
            retry = self._prepared_state.retry(fingerprint, "resolution")
            if retry is not None:
                return copy.deepcopy(retry)
            pending = self._pending_approval(normalized["suspended_receipt_hash"])
            timestamp = self._allocate_timestamp()
            receipt = sign_approval_resolution_v2_1(
                input_value=normalized,
                pending=pending,
                options={
                    "signer": self._signer,
                    "approval_verifier": self._approval_verifier,
                    "evaluation_evidence_provider": self._evaluation_evidence_provider,
                },
                policy=self._policy,
                tenant_id=self._tenant_id,
                session_id=self._session_id,
                sequence=self._sequence + 1,
                timestamp=timestamp,
                previous_hash=self._head_receipt_hash,
            )
            index = next(
                (
                    index
                    for index, item in enumerate(self._prior_actions)
                    if item["receipt_hash"] == normalized["suspended_receipt_hash"]
                ),
                -1,
            )
            if index < 0:
                raise StrictReceiptCoordinatorV21Error(
                    "suspended action summary is missing"
                )
            prepared = self._prepared_state.prepare(
                fingerprint=fingerprint,
                receipt_hash=receipt["receipt_hash"],
                kind="resolution",
                value=receipt,
                commit=lambda: self._commit_approval_resolution(
                    receipt, normalized["suspended_receipt_hash"], index
                ),
            )
            return copy.deepcopy(prepared)

    def commit_prepared(self, token: str, receipt_hash: str) -> Dict[str, Any]:
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
                "head_receipt_hash": self._head_receipt_hash,
                **self._prepared_state.inspect(),
            }

    def observe_execution_time(self) -> int:
        with self._lock:
            self._ensure_process()
            observed = v21_integer(self._clock(), "clock")
            if self._last_timestamp is not None and observed < self._last_timestamp:
                raise StrictReceiptCoordinatorV21Error("clock regressed")
            return observed

    def sign_execution_outcome(
        self, body: Dict[str, Any], decision: Dict[str, Any]
    ) -> Dict[str, Any]:
        with self._lock:
            self._ensure_process()
            return sign_strict_execution_outcome_v2_1(body, self._signer, decision)

    def _allocate_timestamp(self) -> int:
        observed = v21_integer(self._clock(), "clock")
        if self._last_timestamp is not None and observed < self._last_timestamp:
            raise StrictReceiptCoordinatorV21Error("clock regressed")
        return observed

    def _commit_decision(
        self, result: Dict[str, Any], input_value: Dict[str, Any]
    ) -> None:
        receipt = result["receipt"]
        body = receipt["body"]
        self._sequence = body["sequence"]
        self._head_receipt_hash = receipt["receipt_hash"]
        self._last_timestamp = body["timestamp_ms"]
        self._committed_action_ids.add(body["action"]["action_id"])
        self._prior_actions.append(
            {
                "sequence": body["sequence"],
                "kind": body["action"]["kind"],
                "name": body["action"]["name"],
                "outcome": body["outcome"],
                "receipt_hash": receipt["receipt_hash"],
                "data_classifications": list(
                    input_value["current_action"]["data_classifications"]
                ),
            }
        )
        suspension = body.get("suspension")
        if suspension is not None and suspension["type"] == "approval":
            self._pending_approval_ids.add(suspension["suspension_id"])
            self._suspended_approvals[receipt["receipt_hash"]] = {
                "receipt": copy.deepcopy(receipt),
                "context": copy.deepcopy(result["action_context"]),
            }

    def _commit_approval_resolution(
        self, receipt: Dict[str, Any], suspended_receipt_hash: str, index: int
    ) -> None:
        classifications = self._prior_actions[index]["data_classifications"]
        body = receipt["body"]
        self._sequence = body["sequence"]
        self._head_receipt_hash = receipt["receipt_hash"]
        self._last_timestamp = body["timestamp_ms"]
        self._prior_actions[index] = {
            "sequence": body["sequence"],
            "kind": body["action"]["kind"],
            "name": body["action"]["name"],
            "outcome": body["outcome"],
            "receipt_hash": receipt["receipt_hash"],
            "data_classifications": list(classifications),
        }
        self._prior_actions.sort(key=lambda item: item["sequence"])
        self._resolved_approvals.add(suspended_receipt_hash)

    def _pending_approval(self, receipt_hash: str) -> Dict[str, Any]:
        pending = self._suspended_approvals.get(receipt_hash)
        if pending is None:
            raise StrictReceiptCoordinatorV21Error("suspended approval is not known")
        if receipt_hash in self._resolved_approvals:
            raise StrictReceiptCoordinatorV21Error("approval is already resolved")
        return pending

    def _ensure_process(self) -> None:
        if v21_integer(self._pid_source(), "pid") != self._owner_pid:
            raise StrictReceiptCoordinatorV21Error(
                "strict profile 2.1 coordinator cannot cross a process boundary"
            )


__all__ = [
    "StrictReceiptCoordinatorV21",
    "StrictReceiptCoordinatorV21Error",
    "create_trusted_intent_decision_provider_v2_1",
]
