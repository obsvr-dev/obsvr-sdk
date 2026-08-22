"""Validation and canonical helpers for strict receipt coordination."""

from __future__ import annotations

import copy
import hashlib
from typing import Any, Dict, List

from .action_context import build_action_context
from .strict_receipt import (
    STRICT_RECEIPT_PROFILE_VERSION,
    STRICT_RECEIPT_SCHEMA,
    sign_strict_receipt,
)
from .tool_pinning import _canonical_json_for_hash

_HEX = frozenset("0123456789abcdef")
_MAX_SAFE_INTEGER = 9_007_199_254_740_991


def coordinator_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a nonblank string")
    return value


def coordinator_hash(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in _HEX for char in value)
    ):
        raise ValueError(f"{field} must be 64 lowercase hex characters")
    return value


def normalized_strings(value: Any, field: str) -> List[str]:
    if not isinstance(value, list):
        raise ValueError(f"{field} must be an array")
    values = [
        coordinator_text(item, f"{field}[{index}]")
        for index, item in enumerate(value)
    ]
    return sorted(set(values), key=lambda item: tuple(ord(char) for char in item))


def safe_integer(value: Any, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > _MAX_SAFE_INTEGER
    ):
        raise ValueError(f"{field} must be a nonnegative safe integer")
    return value


def safe_add(left: int, right: int) -> int:
    result = left + right
    if result > _MAX_SAFE_INTEGER:
        raise ValueError("value exceeds safe integer range")
    return result


def build_coordinator_context(
    context: Dict[str, Any], session_id: str, prior_actions: List[Dict[str, Any]]
) -> Dict[str, Any]:
    if not isinstance(context, dict):
        raise ValueError("context must be an object")
    if "prior_actions" in context:
        raise ValueError("caller prior_actions are not accepted")
    if "session_id" in context:
        raise ValueError("caller session_id is not accepted")
    return build_action_context(
        {
            **copy.deepcopy(context),
            "session_id": session_id,
            "prior_actions": copy.deepcopy(prior_actions),
        }
    )


def context_input_from_document(context: Dict[str, Any]) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "agent_id": context["agent"]["agent_id"],
        "active_intents": list(context["agent"]["active_intents"]),
        "current_action": copy.deepcopy(context["action"]),
        "run_id": context["run_id"],
    }
    if "role" in context["agent"]:
        result["agent_role"] = context["agent"]["role"]
    if "privilege_scope" in context["agent"]:
        result["privilege_scope"] = list(context["agent"]["privilege_scope"])
    if "thread_id" in context:
        result["thread_id"] = context["thread_id"]
    return result


def request_fingerprint(
    *, context: Dict[str, Any], base_result: Dict[str, Any],
    policy_version: str, rule_ids: List[str], session_id: str
) -> str:
    normalized_context = build_action_context(
        {**context, "session_id": session_id, "prior_actions": []}
    )
    document = {
        "schema": "obsvr-strict-decision-request-v1",
        "context": normalized_context,
        "base_result": dict(base_result),
        "policy_version": coordinator_text(policy_version, "policy_version"),
        "rule_ids": normalized_strings(rule_ids, "rule_ids"),
    }
    return hashlib.sha256(
        _canonical_json_for_hash(document).encode("utf-8")
    ).hexdigest()


def trusted_approval_result(
    value: Any, expected: Dict[str, Any], suspension_expiry: int
) -> Dict[str, str]:
    if not isinstance(value, dict):
        raise ValueError("approval verifier returned an invalid result")
    allowed = {
        "request_id", "action_hash", "principal_id", "decision",
        "source_hash", "expires_at_ms",
    }
    if set(value) != allowed:
        raise ValueError("approval verifier returned an invalid result")
    request_id = coordinator_text(value.get("request_id"), "trusted request_id")
    action_hash = coordinator_hash(value.get("action_hash"), "trusted action_hash")
    principal_id = coordinator_text(value.get("principal_id"), "trusted principal_id")
    source_hash = coordinator_hash(value.get("source_hash"), "trusted source_hash")
    expires_at = safe_integer(value.get("expires_at_ms"), "trusted expires_at_ms")
    if (
        request_id != expected["request_id"]
        or action_hash != expected["action_hash"]
        or value.get("decision") != expected["decision"]
    ):
        raise ValueError("approval verifier result does not match expected binding")
    if expires_at > suspension_expiry:
        raise ValueError("approval verifier expiry exceeds suspension expiry")
    if expected["decision"] == "granted" and (
        expected["current_time_ms"] >= expires_at
        or expected["current_time_ms"] >= suspension_expiry
    ):
        raise ValueError("trusted approval is expired")
    return {
        "request_id": request_id,
        "action_hash": action_hash,
        "principal_id": principal_id,
        "source_hash": source_hash,
    }


def _projection(context: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "agent_id": context["agent"]["agent_id"],
        "role": context["agent"].get("role"),
        "privilege_scope": context["agent"].get("privilege_scope"),
        "active_intents": context["agent"]["active_intents"],
        "action": dict(context["action"]),
        "run_id": context["run_id"],
        "session_id": context.get("session_id"),
        "thread_id": context.get("thread_id"),
    }


def validate_deferred_changes(
    *, original_context: Dict[str, Any], current_context: Dict[str, Any],
    original_base: Dict[str, Any], current_base: Dict[str, Any],
    required_fields: List[str]
) -> None:
    required = set(required_fields)
    before = _projection(original_context)
    after = _projection(current_context)
    if "action.target" in required:
        before["action"].pop("target", None)
        after["action"].pop("target", None)
    if "active_intents" in required:
        before.pop("active_intents")
        after.pop("active_intents")
    if _canonical_json_for_hash(before) != _canonical_json_for_hash(after):
        raise ValueError("DEFER resolution changed fields outside required_fields")
    if "policy_evaluation" in required:
        return
    allowed_base = {
        field for field in required_fields
        if field == "modified_arguments_hash" or field.startswith("approval_")
    }
    old_base = dict(original_base)
    new_base = dict(current_base)
    for field in allowed_base:
        old_base.pop(field, None)
        new_base.pop(field, None)
    if _canonical_json_for_hash(old_base) != _canonical_json_for_hash(new_base):
        raise ValueError(
            "DEFER resolution changed base result outside required_fields"
        )


def sign_coordinator_resolution(
    *, prior: Dict[str, Any], evaluation: Dict[str, Any],
    context: Dict[str, Any], base_result: Dict[str, Any], policy_version: str,
    rule_ids: List[str], method: str, principal_id: str, source_hash: str,
    timestamp: int, clamped: bool, sequence: int, session_id: str,
    previous_hash: str | None, sdk_version: str, signer: Any,
    include_public_key: bool,
) -> Dict[str, Any]:
    action = {
        "action_id": prior["body"]["action"]["action_id"],
        "kind": context["action"]["kind"],
        "name": context["action"]["name"],
        "arguments_hash": context["action"]["arguments_hash"],
    }
    if "target" in context["action"]:
        action["target"] = context["action"]["target"]
    if evaluation["outcome"] == "MODIFY":
        action["effective_arguments_hash"] = base_result["modified_arguments_hash"]
    body = {
        "schema": STRICT_RECEIPT_SCHEMA,
        "profile_version": STRICT_RECEIPT_PROFILE_VERSION,
        "record_type": "resolution",
        "receipt_id": f"{session_id}:{sequence}",
        "session_id": session_id,
        "sequence": sequence,
        "timestamp_ms": timestamp,
        "clock_regression_clamped": clamped,
        "previous_receipt_hash": previous_hash,
        "sdk": {"language": "python", "version": sdk_version},
        "initiator": copy.deepcopy(prior["body"]["initiator"]),
        "action": action,
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
            "reason_code": f"resolution_{method}",
            "rule_ids": normalized_strings(rule_ids, "rule_ids"),
        },
        "execution_authorized": evaluation["outcome"] in ("ALLOW", "MODIFY"),
        "resolution": {
            "resolves_receipt_hash": prior["receipt_hash"],
            "suspension_id": prior["body"]["suspension"]["suspension_id"],
            "method": method,
            "resolver_principal_id": principal_id,
            "resolution_source_hash": source_hash,
            "resolved_at_ms": timestamp,
        },
    }
    if "thread_id" in context:
        body["context"]["thread_id"] = context["thread_id"]
    return sign_strict_receipt(body, signer, include_public_key)
