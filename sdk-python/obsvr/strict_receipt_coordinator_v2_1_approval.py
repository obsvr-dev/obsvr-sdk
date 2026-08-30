"""Trusted one-use approval resolution for strict receipt profile 2.1."""

from __future__ import annotations

import copy
import hashlib
from typing import Any, Dict

from .strict_receipt_coordinator_support import trusted_approval_result
from .strict_receipt_coordinator_v2_1_support import (
    create_trusted_intent_decision_provider_v2_1,
    evaluate_decision_v2_1,
    v21_hash,
    v21_text,
)
from .strict_receipt_v2_1 import (
    STRICT_RECEIPT_V2_1_PROFILE_VERSION,
    STRICT_RECEIPT_V2_1_SCHEMA,
    sign_strict_receipt_v2_1,
)
from .tool_pinning import _canonical_json_for_hash


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(_canonical_json_for_hash(value).encode("utf-8")).hexdigest()


def normalize_approval_resolution_v2_1(input_value: Any) -> Dict[str, Any]:
    if not isinstance(input_value, dict) or set(input_value) != {
        "suspended_receipt_hash",
        "method",
        "approval_evidence",
    }:
        raise ValueError("approval resolution has missing or unsupported fields")
    if input_value["method"] not in ("approval_granted", "approval_denied"):
        raise ValueError("approval resolution method is unsupported")
    return {
        "suspended_receipt_hash": v21_hash(
            input_value["suspended_receipt_hash"], "suspended_receipt_hash"
        ),
        "method": input_value["method"],
        "approval_evidence": copy.deepcopy(input_value["approval_evidence"]),
    }


def approval_resolution_fingerprint_v2_1(
    input_value: Dict[str, Any], tenant_id: str, session_id: str
) -> str:
    return _canonical_hash(
        {
            "schema": "obsvr-strict-approval-resolution-request-v2-1",
            "tenant_id": tenant_id,
            "session_id": session_id,
            "input": input_value,
        }
    )


def _assert_authority_active(pending: Dict[str, Any], timestamp: int) -> None:
    chain = pending["receipt"]["body"]["identity"]["delegation_chain"]
    if any(
        hop["issued_at_ms"] > timestamp or timestamp >= hop["expires_at_ms"]
        for hop in chain
    ):
        raise ValueError("delegated authority is not active at approval time")


def _assert_approval_separation_of_duties(
    pending: Dict[str, Any], approver_ref_hash: str | None, mode: str
) -> None:
    if mode == "none":
        return
    if approver_ref_hash is None:
        raise ValueError(
            "approval separation of duties requires principal_ref_hash"
        )
    identity = pending["receipt"]["body"]["identity"]
    if approver_ref_hash == identity["requester"]["requester_ref_hash"]:
        raise ValueError("approver must differ from the requester")
    if (
        mode == "requester_and_initiator"
        and approver_ref_hash == identity["initiator"]["agent_ref_hash"]
    ):
        raise ValueError("approver must differ from the initiating agent")


def sign_approval_resolution_v2_1(
    *,
    input_value: Dict[str, Any],
    pending: Dict[str, Any],
    options: Dict[str, Any],
    policy: Dict[str, Any],
    tenant_id: str,
    session_id: str,
    sequence: int,
    timestamp: int,
    previous_hash: str | None,
) -> Dict[str, Any]:
    prior = pending["receipt"]
    suspension = prior["body"].get("suspension")
    if suspension is None or suspension["type"] != "approval":
        raise ValueError("suspended receipt is not awaiting approval")
    action_hash = suspension.get("approval_action_hash")
    if action_hash is None:
        raise ValueError("suspended approval is missing its action binding")
    if (
        timestamp >= suspension["expires_at_ms"]
        and input_value["method"] == "approval_granted"
    ):
        raise ValueError("approval cannot authorize after suspension expiry")
    verifier = options.get("approval_verifier")
    if not callable(verifier):
        raise ValueError("approval_verifier is required to resolve an approval")
    _assert_authority_active(pending, timestamp)
    decision = (
        "granted" if input_value["method"] == "approval_granted" else "denied"
    )
    expected = {
        "request_id": suspension["suspension_id"],
        "action_hash": action_hash,
        "decision": decision,
        "current_time_ms": timestamp,
    }
    trusted = trusted_approval_result(
        verifier(input_value["approval_evidence"], expected),
        expected,
        suspension["expires_at_ms"],
    )
    if decision == "granted":
        _assert_approval_separation_of_duties(
            pending,
            trusted.get("principal_ref_hash"),
            options.get("approval_separation_of_duties", "none"),
        )
    evaluated = evaluate_decision_v2_1(
        pending["context"],
        policy,
        create_trusted_intent_decision_provider_v2_1(
            lambda _context: {
                "action_taken": "allowed" if decision == "granted" else "blocked"
            }
        ),
        options["evaluation_evidence_provider"],
    )
    outcome = evaluated["evidence"]["outcome"]
    if decision == "granted" and outcome not in ("ALLOW", "MODIFY"):
        raise ValueError("granted approval did not produce an authorized policy outcome")
    if decision == "denied" and outcome != "DENY":
        raise ValueError("denied approval did not produce a deny policy outcome")
    body = {
        "schema": STRICT_RECEIPT_V2_1_SCHEMA,
        "profile_version": STRICT_RECEIPT_V2_1_PROFILE_VERSION,
        "record_type": "resolution",
        "receipt_id": f"{session_id}:{sequence}",
        "tenant_id": tenant_id,
        "session_id": session_id,
        "sequence": sequence,
        "timestamp_ms": timestamp,
        "previous_receipt_hash": previous_hash,
        "action": copy.deepcopy(prior["body"]["action"]),
        "context_hash": evaluated["intent"]["context_hash"],
        "identity": copy.deepcopy(prior["body"]["identity"]),
        "evaluation": evaluated["evidence"],
        "outcome": outcome,
        "reason_code": evaluated["evidence"]["reason_code"],
        "execution_authorized": decision == "granted",
        "resolution": {
            "resolves_receipt_hash": prior["receipt_hash"],
            "suspension_id": suspension["suspension_id"],
            "method": input_value["method"],
            "resolver_ref_hash": trusted.get("principal_ref_hash")
            or _canonical_hash(
                {
                    "schema": "obsvr-strict-resolver-ref-v2-1",
                    "principal_id": v21_text(
                        trusted["principal_id"], "trusted principal_id"
                    ),
                }
            ),
            "resolved_at_ms": timestamp,
            "approval_evidence_hash": trusted["source_hash"],
        },
    }
    return sign_strict_receipt_v2_1(body, options["signer"])


__all__ = [
    "approval_resolution_fingerprint_v2_1",
    "normalize_approval_resolution_v2_1",
    "sign_approval_resolution_v2_1",
]
