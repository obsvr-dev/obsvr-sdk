"""Canonical helpers and trusted decision boundary for the 2.1 coordinator."""

from __future__ import annotations

import copy
import hashlib
import weakref
from typing import Any, Callable, Dict, List

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
from .strict_evaluation_evidence_v2_1 import (
    build_strict_evaluation_evidence_v2_1,
    create_trusted_decision_reason_codes_v2_1,
)
from .strict_identity_evidence_v2_1 import (
    trusted_strict_identity_evidence_v2_1_document,
)
from .strict_receipt_v2_1 import (
    STRICT_RECEIPT_V2_1_PROFILE_VERSION,
    STRICT_RECEIPT_V2_1_SCHEMA,
    sign_strict_receipt_v2_1,
)
from .tool_pinning import _canonical_json_for_hash

_HEX = frozenset("0123456789abcdef")
_TRUSTED_DECISIONS: weakref.WeakSet[Any] = weakref.WeakSet()


class StrictReceiptCoordinatorV21Error(ValueError):
    """Profile-2.1 coordination cannot proceed without trusted evidence."""


def _fail(message: str):
    raise StrictReceiptCoordinatorV21Error(message)


def _record(value: Any, field: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{field} must be an object")
    return value


def _exact(value: Dict[str, Any], allowed: set[str], field: str) -> None:
    unknown = sorted(
        set(value) - allowed, key=lambda item: tuple(ord(char) for char in item)
    )
    if unknown:
        _fail(f"{field} contains unsupported field: {unknown[0]}")
    missing = sorted(
        allowed - set(value), key=lambda item: tuple(ord(char) for char in item)
    )
    if missing:
        _fail(f"{field} is missing required field: {missing[0]}")


def v21_text(value: Any, field: str) -> str:
    return bounded_canonical_text(value, field, STRICT_IDENTIFIER_MAX_BYTES, _fail)


def v21_hash(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in _HEX for char in value)
    ):
        _fail(f"{field} must be 64 lowercase hex characters")
    return value


def v21_integer(value: Any, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > 9_007_199_254_740_991
    ):
        _fail(f"{field} must be a nonnegative safe integer")
    return value


def _v21_set(value: Any, field: str) -> List[str]:
    return normalized_bounded_set(
        value, field, STRICT_SET_MAX_ITEMS, STRICT_IDENTIFIER_MAX_BYTES, _fail
    )


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(_canonical_json_for_hash(value).encode("utf-8")).hexdigest()


def _safe_add(left: int, right: int) -> int:
    result = left + right
    if result > 9_007_199_254_740_991:
        _fail("value exceeds safe integer range")
    return result


class _TrustedIntentDecisionProviderV21:
    def __init__(self, evaluate: Callable[[Dict[str, Any]], Dict[str, Any]]) -> None:
        self.evaluate = evaluate


def create_trusted_intent_decision_provider_v2_1(evaluate):
    if not callable(evaluate):
        _fail("trusted intent decision provider must be callable")
    provider = _TrustedIntentDecisionProviderV21(evaluate)
    _TRUSTED_DECISIONS.add(provider)
    return provider


def assert_trusted_intent_decision_provider_v2_1(provider) -> None:
    if not isinstance(provider, _TrustedIntentDecisionProviderV21) or (
        provider not in _TRUSTED_DECISIONS
    ):
        _fail("trusted intent decision provider is required")


def normalize_decision_action_v2_1(input_value: Any) -> Dict[str, Any]:
    root = _record(input_value, "decision request")
    allowed = {"action_id", "active_intents", "current_action", "run_id"}
    if "thread_id" in root:
        allowed.add("thread_id")
    _exact(root, allowed, "decision request")
    action = _record(root["current_action"], "current_action")
    action_fields = {
        "kind",
        "name",
        "arguments_hash",
        "target_hash",
        "data_classifications",
        "requested_scopes",
    }
    for optional_field in (
        "attempt_id",
        "parent_attempt_id",
        "remediation_retry_hash",
    ):
        if optional_field in action:
            action_fields.add(optional_field)
    _exact(action, action_fields, "current_action")
    has_parent = "parent_attempt_id" in action
    has_retry_hash = "remediation_retry_hash" in action
    if has_parent != has_retry_hash:
        _fail(
            "current_action parent_attempt_id and remediation_retry_hash must appear together"
        )
    if has_parent and "attempt_id" not in action:
        _fail("current_action retry linkage requires attempt_id")
    if has_parent and action["parent_attempt_id"] == action["attempt_id"]:
        _fail("current_action retry must use a new attempt_id")
    normalized = {
        "action_id": v21_text(root["action_id"], "action_id"),
        "active_intents": _v21_set(root["active_intents"], "active_intents"),
        "current_action": {
            "kind": v21_text(action["kind"], "current_action.kind"),
            "name": v21_text(action["name"], "current_action.name"),
            "arguments_hash": v21_hash(
                action["arguments_hash"], "current_action.arguments_hash"
            ),
            "target_hash": v21_hash(
                action["target_hash"], "current_action.target_hash"
            ),
            "data_classifications": _v21_set(
                action["data_classifications"],
                "current_action.data_classifications",
            ),
            "requested_scopes": _v21_set(
                action["requested_scopes"], "current_action.requested_scopes"
            ),
            **(
                {"attempt_id": v21_text(action["attempt_id"], "current_action.attempt_id")}
                if "attempt_id" in action
                else {}
            ),
            **(
                {
                    "parent_attempt_id": v21_text(
                        action["parent_attempt_id"],
                        "current_action.parent_attempt_id",
                    ),
                    "remediation_retry_hash": v21_hash(
                        action["remediation_retry_hash"],
                        "current_action.remediation_retry_hash",
                    ),
                }
                if "parent_attempt_id" in action and "remediation_retry_hash" in action
                else {}
            ),
        },
        "run_id": v21_text(root["run_id"], "run_id"),
    }
    if "thread_id" in root:
        normalized["thread_id"] = v21_text(root["thread_id"], "thread_id")
    return normalized


def decision_v2_1_fingerprint(
    input_value: Dict[str, Any], tenant_id: str, session_id: str, policy: Dict[str, Any]
) -> str:
    return _canonical_hash(
        {
            "schema": "obsvr-strict-decision-request-v2-1",
            "tenant_id": tenant_id,
            "session_id": session_id,
            "policy_hash": _canonical_hash(policy),
            "input": input_value,
        }
    )


def capture_identity_v2_1(options: Dict[str, Any], timestamp: int) -> Dict[str, Any]:
    try:
        input_value = options["identity_snapshot"](timestamp)
    except Exception:
        _fail("trusted identity snapshot failed")
    try:
        trusted = options["identity_authority"].issue(input_value)
    except Exception:
        _fail("trusted identity issuance failed")
    try:
        return trusted_strict_identity_evidence_v2_1_document(trusted)
    except Exception:
        _fail("trusted identity evidence is invalid")


def build_coordinator_context_v2_1(
    input_value: Dict[str, Any],
    identity: Dict[str, Any],
    session_id: str,
    prior_actions: List[Dict[str, Any]],
) -> Dict[str, Any]:
    agent = identity["initiator"]
    return build_action_context_v2(
        {
            "agent_id": agent["agent_ref_hash"],
            "active_intents": input_value["active_intents"],
            **({"agent_role": agent["role_ids"][0]} if agent["role_ids"] else {}),
            "privilege_scope": agent["privilege_scopes"],
            "current_action": input_value["current_action"],
            "run_id": input_value["run_id"],
            "session_id": session_id,
            **(
                {"thread_id": input_value["thread_id"]}
                if "thread_id" in input_value
                else {}
            ),
            "prior_actions": copy.deepcopy(prior_actions),
        }
    )


def evaluate_decision_v2_1(
    context: Dict[str, Any],
    policy: Dict[str, Any],
    intent_provider: Any,
    evidence_provider: Any,
) -> Dict[str, Any]:
    assert_trusted_intent_decision_provider_v2_1(intent_provider)
    try:
        base_result = intent_provider.evaluate(copy.deepcopy(context))
    except Exception:
        _fail("trusted intent decision failed")
    intent = evaluate_intent_alignment_v2(
        context=context, base_result=base_result, policy=policy
    )
    reasons = create_trusted_decision_reason_codes_v2_1([intent["reason_code"]])
    evidence = build_strict_evaluation_evidence_v2_1(
        evidence_provider, intent["outcome"], reasons
    )["evidence"]
    if evidence["effective_policy"]["artifact_hash"] != intent["policy_hash"]:
        _fail("effective policy artifact_hash does not match evaluated policy")
    active = set(context["agent"]["active_intents"])
    expected_rules = sorted(
        scope["intent_id"]
        for scope in policy["intent_scopes"]
        if scope["intent_id"] in active
    )
    if evidence["effective_policy"]["matched_rule_ids"] != expected_rules:
        _fail("matched_rule_ids do not match active policy intents")
    if evidence["decision_reason_codes"] != [intent["reason_code"]]:
        _fail("decision_reason_codes do not match intent evaluation")
    return {
        "base_result": copy.deepcopy(base_result),
        "intent": intent,
        "evidence": evidence,
    }


def sign_decision_v2_1(
    *,
    input_value: Dict[str, Any],
    identity: Dict[str, Any],
    context: Dict[str, Any],
    evaluation: Dict[str, Any],
    base_result: Dict[str, Any],
    tenant_id: str,
    session_id: str,
    sequence: int,
    timestamp: int,
    previous_hash: str | None,
    defer_ttl_ms: int,
    signer: Any,
) -> Dict[str, Any]:
    action = {
        "action_id": input_value["action_id"],
        "kind": input_value["current_action"]["kind"],
        "name": input_value["current_action"]["name"],
        "arguments_hash": input_value["current_action"]["arguments_hash"],
        "target_hash": input_value["current_action"]["target_hash"],
    }
    if evaluation["outcome"] == "MODIFY":
        action["effective_arguments_hash"] = v21_hash(
            base_result.get("modified_arguments_hash"), "modified_arguments_hash"
        )
    context_hash = hashlib.sha256(
        _canonical_json_for_hash(context).encode("utf-8")
    ).hexdigest()
    body = {
        "schema": STRICT_RECEIPT_V2_1_SCHEMA,
        "profile_version": STRICT_RECEIPT_V2_1_PROFILE_VERSION,
        "record_type": "decision",
        "receipt_id": f"{session_id}:{sequence}",
        "tenant_id": tenant_id,
        "session_id": session_id,
        "sequence": sequence,
        "timestamp_ms": timestamp,
        "previous_receipt_hash": previous_hash,
        "action": action,
        "context_hash": context_hash,
        "identity": identity,
        "evaluation": evaluation,
        "outcome": evaluation["outcome"],
        "reason_code": evaluation["reason_code"],
        "execution_authorized": evaluation["outcome"] in ("ALLOW", "MODIFY"),
    }
    if evaluation["outcome"] == "STEP_UP":
        body["suspension"] = {
            "suspension_id": v21_text(
                base_result.get("approval_request_id"), "approval_request_id"
            ),
            "type": "approval",
            "expires_at_ms": v21_integer(
                base_result.get("approval_expires_at_ms"), "approval_expires_at_ms"
            ),
            "approval_action_hash": v21_hash(
                base_result.get("approval_action_hash"), "approval_action_hash"
            ),
        }
    elif evaluation["outcome"] == "DEFER":
        suspension_hash = _canonical_hash(
            {
                "session_id": session_id,
                "sequence": sequence,
                "context_hash": context_hash,
            }
        )
        body["suspension"] = {
            "suspension_id": f"defer:{suspension_hash}",
            "type": "context",
            "expires_at_ms": _safe_add(timestamp, defer_ttl_ms),
        }
    return sign_strict_receipt_v2_1(body, signer)


__all__ = [
    "StrictReceiptCoordinatorV21Error",
    "assert_trusted_intent_decision_provider_v2_1",
    "build_coordinator_context_v2_1",
    "build_intent_policy_v2",
    "capture_identity_v2_1",
    "create_trusted_intent_decision_provider_v2_1",
    "decision_v2_1_fingerprint",
    "evaluate_decision_v2_1",
    "normalize_decision_action_v2_1",
    "sign_decision_v2_1",
    "v21_hash",
    "v21_integer",
    "v21_text",
]
