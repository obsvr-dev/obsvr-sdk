"""Canonical helpers and v2 receipt builders for strict coordination."""

from __future__ import annotations

import copy
import hashlib
from typing import Any, Dict, List

from .action_context_v2 import build_action_context_v2
from .intent_alignment_v2 import (
    build_intent_policy_v2,
    evaluate_intent_alignment_v2,
)
from .strict_canonical import (
    STRICT_IDENTIFIER_MAX_BYTES,
    STRICT_SET_MAX_ITEMS,
    bounded_canonical_text,
    normalized_bounded_set,
)
from .strict_receipt_v2 import (
    STRICT_RECEIPT_V2_PROFILE_VERSION,
    STRICT_RECEIPT_V2_SCHEMA,
    sign_strict_receipt_v2,
    strict_receipt_v2_key_id,
)
from .strict_receipt_v2_verify import verify_strict_receipt_v2
from .strict_receipt_coordinator_support import trusted_approval_result
from .tool_pinning import _canonical_json_for_hash

_HEX = frozenset("0123456789abcdef")
_MAX_SAFE = 9_007_199_254_740_991


def _fail(message: str) -> None:
    raise ValueError(message)


def v2_text(value: Any, field: str) -> str:
    return bounded_canonical_text(value, field, STRICT_IDENTIFIER_MAX_BYTES, _fail)


def v2_hash(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _HEX for character in value)
    ):
        raise ValueError(f"{field} must be 64 lowercase hex characters")
    return value


def v2_integer(value: Any, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > _MAX_SAFE
    ):
        raise ValueError(f"{field} must be a nonnegative safe integer")
    return value


def v2_strings(value: Any, field: str) -> List[str]:
    return normalized_bounded_set(
        value, field, STRICT_SET_MAX_ITEMS, STRICT_IDENTIFIER_MAX_BYTES, _fail
    )


def v2_canonical_hash(value: Any) -> str:
    return hashlib.sha256(_canonical_json_for_hash(value).encode("utf-8")).hexdigest()


def v2_safe_add(left: int, right: int) -> int:
    result = left + right
    if result > _MAX_SAFE:
        raise ValueError("value exceeds safe integer range")
    return result


def build_coordinator_context_v2(
    context: Dict[str, Any], session_id: str, prior_actions: List[Dict[str, Any]]
) -> Dict[str, Any]:
    if not isinstance(context, dict):
        raise ValueError("context must be an object")
    if "prior_actions" in context:
        raise ValueError("caller prior_actions are not accepted")
    if "session_id" in context:
        raise ValueError("caller session_id is not accepted")
    return build_action_context_v2(
        {
            **copy.deepcopy(context),
            "session_id": session_id,
            "prior_actions": copy.deepcopy(prior_actions),
        }
    )


def context_input_from_v2_document(context: Dict[str, Any]) -> Dict[str, Any]:
    output = {
        "agent_id": context["agent"]["agent_id"],
        "active_intents": list(context["agent"]["active_intents"]),
        "current_action": copy.deepcopy(context["action"]),
        "run_id": context["run_id"],
    }
    if "role" in context["agent"]:
        output["agent_role"] = context["agent"]["role"]
    if "privilege_scope" in context["agent"]:
        output["privilege_scope"] = list(context["agent"]["privilege_scope"])
    if "thread_id" in context:
        output["thread_id"] = context["thread_id"]
    return output


def _request_context(context: Dict[str, Any], session_id: str) -> Dict[str, Any]:
    return build_action_context_v2(
        {
            **copy.deepcopy(context),
            "session_id": session_id,
            "prior_actions": [],
        }
    )


def decision_v2_fingerprint(
    *, input_value: Dict[str, Any], tenant_id: str, session_id: str
) -> str:
    return v2_canonical_hash(
        {
            "schema": "obsvr-strict-decision-request-v2",
            "tenant_id": tenant_id,
            "session_id": session_id,
            "action_id": v2_text(input_value["action_id"], "action_id"),
            "context": _request_context(input_value["context"], session_id),
            "base_result": copy.deepcopy(input_value["base_result"]),
            "policy_version": v2_text(input_value["policy_version"], "policy_version"),
            "rule_ids": v2_strings(input_value["rule_ids"], "rule_ids"),
        }
    )


def resolution_v2_fingerprint(
    *, input_value: Dict[str, Any], tenant_id: str, session_id: str
) -> str:
    evidence = input_value.get("approval_evidence")
    return v2_canonical_hash(
        {
            "schema": "obsvr-strict-resolution-request-v2",
            "tenant_id": tenant_id,
            "session_id": session_id,
            "suspended_receipt_hash": input_value["suspended_receipt_hash"],
            "method": input_value["method"],
            "context": _request_context(input_value["context"], session_id),
            "base_result": copy.deepcopy(input_value["base_result"]),
            "policy_version": input_value["policy_version"],
            "rule_ids": v2_strings(input_value["rule_ids"], "rule_ids"),
            "resolver_principal_id": input_value.get("resolver_principal_id"),
            "resolution_source_hash": input_value.get("resolution_source_hash"),
            "approval_evidence_hash": (
                None if evidence is None else v2_canonical_hash(evidence)
            ),
        }
    )


def timeout_v2_fingerprint(
    *, input_value: Dict[str, Any], tenant_id: str, session_id: str
) -> str:
    return v2_canonical_hash(
        {
            "schema": "obsvr-strict-timeout-request-v2",
            "tenant_id": tenant_id,
            "session_id": session_id,
            "suspended_receipt_hash": input_value["suspended_receipt_hash"],
            "policy_version": input_value["policy_version"],
            "rule_ids": v2_strings(input_value["rule_ids"], "rule_ids"),
        }
    )


def _common_body(**params: Any) -> Dict[str, Any]:
    context = params["context"]
    evaluation = params["evaluation"]
    action = {
        "action_id": params["action_id"],
        "kind": context["action"]["kind"],
        "name": context["action"]["name"],
        "arguments_hash": context["action"]["arguments_hash"],
    }
    if "target_hash" in context["action"]:
        action["target_hash"] = context["action"]["target_hash"]
    if evaluation["outcome"] == "MODIFY":
        action["effective_arguments_hash"] = v2_hash(
            params["base_result"].get("modified_arguments_hash"),
            "modified_arguments_hash",
        )
    body = {
        "schema": STRICT_RECEIPT_V2_SCHEMA,
        "profile_version": STRICT_RECEIPT_V2_PROFILE_VERSION,
        "receipt_id": f"{params['session_id']}:{params['sequence']}",
        "tenant_id": params["tenant_id"],
        "session_id": params["session_id"],
        "sequence": params["sequence"],
        "timestamp_ms": params["timestamp"],
        "clock_regression_clamped": params["clamped"],
        "previous_receipt_hash": params["previous_hash"],
        "sdk": {"language": "python", "version": params["sdk_version"]},
        "initiator": {
            "agent_id": context["agent"]["agent_id"],
            "key_id": strict_receipt_v2_key_id(params["signer"].raw_public_key),
        },
        "action": action,
        "context": {
            "schema": "obsvr-action-context-v2",
            "context_hash": evaluation["context_hash"],
            "run_id": context["run_id"],
        },
        "evaluation": {
            "input_hash": evaluation["input_hash"],
            "policy_hash": evaluation["policy_hash"],
            "evaluator_hash": evaluation["evaluator_hash"],
            "engine_version": evaluation["engine_version"],
            "policy_version": v2_text(params["policy_version"], "policy_version"),
            "outcome": evaluation["outcome"],
            "reason_code": evaluation["reason_code"],
            "rule_ids": v2_strings(params["rule_ids"], "rule_ids"),
        },
        "execution_authorized": evaluation["outcome"] in ("ALLOW", "MODIFY"),
    }
    if "thread_id" in context:
        body["context"]["thread_id"] = context["thread_id"]
    return body


def _checked_sign(
    body: Dict[str, Any], signer: Any, include_key: bool
) -> Dict[str, Any]:
    receipt = sign_strict_receipt_v2(body, signer, include_key)
    axes = verify_strict_receipt_v2(
        receipt, pinned_public_key_b64=signer.public_key_b64
    )
    if (
        not all(
            axes[key]
            for key in (
                "schema_valid",
                "hash_valid",
                "signature_valid",
                "semantic_valid",
                "identity_binding_valid",
            )
        )
        or axes["key_trust"] != "pinned"
    ):
        raise ValueError("signed v2 receipt failed self-verification")
    return receipt


def sign_decision_v2(**params: Any) -> Dict[str, Any]:
    body = _common_body(**params)
    body["record_type"] = "decision"
    evaluation = params["evaluation"]
    base = params["base_result"]
    if evaluation["outcome"] == "STEP_UP":
        request_id = v2_text(base.get("approval_request_id"), "approval_request_id")
        body["suspension"] = {
            "suspension_id": request_id,
            "type": "approval",
            "status": "pending",
            "required_fields": [],
            "expires_at_ms": v2_integer(
                base.get("approval_expires_at_ms"), "approval_expires_at_ms"
            ),
            "approval_request_id": request_id,
            "approval_action_hash": v2_hash(
                base.get("approval_action_hash"), "approval_action_hash"
            ),
        }
    elif evaluation["outcome"] == "DEFER":
        body["suspension"] = {
            "suspension_id": f"defer:{params['session_id']}:{params['sequence']}",
            "type": "context",
            "status": "pending",
            "required_fields": list(evaluation.get("required_fields", [])),
            "expires_at_ms": v2_safe_add(params["timestamp"], params["defer_ttl_ms"]),
        }
    if (
        body.get("suspension", {}).get("expires_at_ms", params["timestamp"] + 1)
        <= params["timestamp"]
    ):
        raise ValueError("suspension expiry must follow decision timestamp")
    return _checked_sign(body, params["signer"], params["include_public_key"])


def sign_resolution_v2(**params: Any) -> Dict[str, Any]:
    body = _common_body(
        **params, action_id=params["prior"]["body"]["action"]["action_id"]
    )
    body["record_type"] = "resolution"
    body["initiator"] = copy.deepcopy(params["prior"]["body"]["initiator"])
    body["evaluation"]["reason_code"] = f"resolution_{params['method']}"
    body["resolution"] = {
        "resolves_receipt_hash": params["prior"]["receipt_hash"],
        "suspension_id": params["prior"]["body"]["suspension"]["suspension_id"],
        "method": params["method"],
        "resolver_principal_id": v2_text(
            params["principal_id"], "resolver_principal_id"
        ),
        "resolution_source_hash": v2_hash(
            params["source_hash"], "resolution_source_hash"
        ),
        "resolved_at_ms": params["timestamp"],
    }
    return _checked_sign(body, params["signer"], params["include_public_key"])


def validate_deferred_changes_v2(
    *,
    original_context: Dict[str, Any],
    current_context: Dict[str, Any],
    original_base: Dict[str, Any],
    current_base: Dict[str, Any],
    required_fields: List[str],
) -> None:
    def project(context: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "agent_id": context["agent"]["agent_id"],
            "role": context["agent"].get("role"),
            "privilege_scope": context["agent"].get("privilege_scope"),
            "active_intents": context["agent"]["active_intents"],
            "action": copy.deepcopy(context["action"]),
            "run_id": context["run_id"],
            "session_id": context.get("session_id"),
            "thread_id": context.get("thread_id"),
        }

    before, after = project(original_context), project(current_context)
    required = set(required_fields)
    if "action.target" in required:
        before["action"].pop("target_hash", None)
        after["action"].pop("target_hash", None)
    if "active_intents" in required:
        before.pop("active_intents")
        after.pop("active_intents")
    if _canonical_json_for_hash(before) != _canonical_json_for_hash(after):
        raise ValueError("DEFER resolution changed fields outside required_fields")
    if "policy_evaluation" in required:
        return
    old_base, new_base = copy.deepcopy(original_base), copy.deepcopy(current_base)
    for field in required_fields:
        if field == "modified_arguments_hash" or field.startswith("approval_"):
            old_base.pop(field, None)
            new_base.pop(field, None)
    if _canonical_json_for_hash(old_base) != _canonical_json_for_hash(new_base):
        raise ValueError("DEFER resolution changed base result outside required_fields")


def validate_resolution_v2(
    *,
    input_value: Dict[str, Any],
    pending: Dict[str, Any],
    context: Dict[str, Any],
    base: Dict[str, Any],
    evaluation: Dict[str, Any],
    timestamp: int,
    approval_verifier: Any,
    approval_requests: Dict[str, str],
) -> Dict[str, str]:
    if evaluation["outcome"] not in ("ALLOW", "DENY", "MODIFY"):
        raise ValueError("resolution evaluation must be final")
    prior = pending["receipt"]
    suspension = prior["body"]["suspension"]
    action, prior_action = context["action"], prior["body"]["action"]
    if context["agent"]["agent_id"] != prior["body"]["initiator"]["agent_id"] or any(
        action.get(key) != prior_action.get(key)
        for key in ("kind", "name", "arguments_hash", "target_hash")
    ):
        raise ValueError("resolution action or initiator does not match suspension")
    method = input_value["method"]
    approval_method = method in ("approval_granted", "approval_denied")
    if (suspension["type"] == "approval") != approval_method and method != "cancelled":
        raise ValueError("resolution method does not match suspension")
    if approval_method:
        if (
            input_value.get("resolver_principal_id") is not None
            or input_value.get("resolution_source_hash") is not None
        ):
            raise ValueError("approval source must come from approval_evidence")
        if (
            approval_requests.get(suspension["approval_request_id"])
            != prior["receipt_hash"]
        ):
            raise ValueError("approval request belongs to another suspension")
        expected = {
            "request_id": suspension["approval_request_id"],
            "action_hash": suspension["approval_action_hash"],
            "decision": "granted" if method == "approval_granted" else "denied",
            "current_time_ms": timestamp,
        }
        trusted = trusted_approval_result(
            approval_verifier(input_value["approval_evidence"], expected),
            expected,
            suspension["expires_at_ms"],
        )
        _validate_final_resolution_v2(method, prior, base, evaluation, timestamp)
        return {
            "principal_id": trusted["principal_id"],
            "source_hash": trusted["source_hash"],
        }
    if input_value.get("approval_evidence") is not None:
        raise ValueError("approval_evidence requires an approval method")
    if suspension["type"] == "context":
        validate_deferred_changes_v2(
            original_context=pending["context"],
            current_context=context,
            original_base=pending["base_result"],
            current_base=base,
            required_fields=suspension["required_fields"],
        )
    result = {
        "principal_id": v2_text(
            input_value.get("resolver_principal_id"), "resolver_principal_id"
        ),
        "source_hash": v2_hash(
            input_value.get("resolution_source_hash"), "resolution_source_hash"
        ),
    }
    _validate_final_resolution_v2(method, prior, base, evaluation, timestamp)
    return result


def _validate_final_resolution_v2(
    method: str,
    prior: Dict[str, Any],
    base: Dict[str, Any],
    evaluation: Dict[str, Any],
    timestamp: int,
) -> None:
    suspension = prior["body"]["suspension"]
    if (
        method in ("approval_granted", "context_supplied")
        and timestamp >= suspension["expires_at_ms"]
    ):
        raise ValueError("authorization cannot occur after suspension expiry")
    if method in ("approval_denied", "cancelled") and evaluation["outcome"] != "DENY":
        raise ValueError("resolution method requires DENY")
    if method == "approval_granted" and evaluation["outcome"] not in (
        "ALLOW",
        "MODIFY",
    ):
        raise ValueError("approval_granted requires ALLOW or MODIFY")
    if evaluation["outcome"] == "MODIFY":
        effective = v2_hash(
            base.get("modified_arguments_hash"), "modified_arguments_hash"
        )
        if effective == prior["body"]["action"]["arguments_hash"]:
            raise ValueError("effective_arguments_hash must change arguments")


__all__ = ["build_intent_policy_v2", "evaluate_intent_alignment_v2"]
