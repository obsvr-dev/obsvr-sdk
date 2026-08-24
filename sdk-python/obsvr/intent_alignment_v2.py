"""Pure v2 intent alignment over bounded, target-tokenized context."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from .aarm_outcome import AARM_OUTCOMES
from .action_context_v2 import (
    ACTION_CONTEXT_V2_SCHEMA,
    action_target_hash,
    build_action_context_v2,
)
from .strict_canonical import (
    STRICT_IDENTIFIER_MAX_BYTES,
    STRICT_SET_MAX_ITEMS,
    STRICT_TARGET_MAX_BYTES,
    bounded_canonical_text,
    code_point_key,
    normalized_bounded_set,
)
from .tool_pinning import _canonical_json_for_hash

INTENT_POLICY_V2_SCHEMA = "obsvr-intent-policy-v2"
INTENT_POLICY_V2_PROFILE_VERSION = "2.0"
INTENT_V2_ENGINE_VERSION = "obsvr-intent/2"
INTENT_V2_EVALUATION_INPUT_SCHEMA = "obsvr-intent-evaluation-input-v2"

_OUTCOMES = frozenset(AARM_OUTCOMES)
_ACTION_TAKEN = frozenset(
    {"allowed", "blocked", "redacted", "not_evaluated", "hook_error", "hook_timeout"}
)
_HEX = frozenset("0123456789abcdef")
_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_APPROVAL_FIELDS = frozenset(
    {"approval_request_id", "approval_action_hash", "approval_expires_at_ms"}
)


class IntentAlignmentV2ValidationError(ValueError):
    """The v2 policy or base result cannot be evaluated unambiguously."""


def _fail(message: str) -> None:
    raise IntentAlignmentV2ValidationError(message)


def _record(value: Any, field: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{field} must be an object")
    return value


def _exact_keys(value: Dict[str, Any], allowed: set[str], field: str) -> None:
    unknown = sorted(set(value) - allowed, key=code_point_key)
    if unknown:
        _fail(f"{field} contains unsupported field: {unknown[0]}")


def _text(value: Any, field: str) -> str:
    return bounded_canonical_text(value, field, STRICT_IDENTIFIER_MAX_BYTES, _fail)


def _hash(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _HEX for character in value)
    ):
        _fail(f"{field} must be 64 lowercase hex characters")
    return value


def _string_set(value: Any, field: str) -> List[str]:
    return normalized_bounded_set(
        value, field, STRICT_SET_MAX_ITEMS, STRICT_IDENTIFIER_MAX_BYTES, _fail
    )


def _hash_set(value: Any, field: str) -> List[str]:
    if not isinstance(value, list):
        _fail(f"{field} must be an array")
    if len(value) > STRICT_SET_MAX_ITEMS:
        _fail(f"{field} exceeds {STRICT_SET_MAX_ITEMS} items")
    return sorted(
        {_hash(item, f"{field}[{index}]") for index, item in enumerate(value)}
    )


def _outcome_set(value: Any, field: str) -> List[str]:
    values = _string_set(value, field)
    if any(item not in _OUTCOMES for item in values):
        _fail(f"{field} contains unsupported outcome")
    return values


def _action_pair(value: Any, field: str) -> Dict[str, str]:
    pair = _record(value, field)
    _exact_keys(pair, {"kind", "name"}, field)
    return {
        "kind": _text(pair.get("kind"), f"{field}.kind"),
        "name": _text(pair.get("name"), f"{field}.name"),
    }


def _action_set(value: Any, field: str) -> List[Dict[str, str]]:
    if not isinstance(value, list):
        _fail(f"{field} must be an array")
    if len(value) > STRICT_SET_MAX_ITEMS:
        _fail(f"{field} exceeds {STRICT_SET_MAX_ITEMS} items")
    pairs = [
        _action_pair(item, f"{field}[{index}]") for index, item in enumerate(value)
    ]
    unique = {(pair["kind"], pair["name"]): pair for pair in pairs}
    return [
        unique[key]
        for key in sorted(
            unique, key=lambda pair: (code_point_key(pair[0]), code_point_key(pair[1]))
        )
    ]


def _intent_scope(value: Any, index: int) -> Dict[str, Any]:
    field = f"intent_scopes[{index}]"
    item = _record(value, field)
    _exact_keys(
        item,
        {
            "intent_id",
            "allowed_actions",
            "allowed_targets",
            "allowed_target_hashes",
            "allowed_requested_scopes",
            "allowed_data_classifications",
            "deny_after_outcomes",
            "max_prior_actions",
        },
        field,
    )
    raw_targets = "allowed_targets" in item
    hashed_targets = "allowed_target_hashes" in item
    if raw_targets == hashed_targets:
        _fail(f"{field} must contain exactly one target representation")
    if raw_targets:
        targets = item["allowed_targets"]
        if not isinstance(targets, list):
            _fail(f"{field}.allowed_targets must be an array")
        if len(targets) > STRICT_SET_MAX_ITEMS:
            _fail(f"{field}.allowed_targets exceeds {STRICT_SET_MAX_ITEMS} items")
        target_hashes = sorted(
            {
                action_target_hash(
                    bounded_canonical_text(
                        target,
                        f"{field}.allowed_targets[{target_index}]",
                        STRICT_TARGET_MAX_BYTES,
                        _fail,
                    )
                )
                for target_index, target in enumerate(targets)
            }
        )
    else:
        target_hashes = _hash_set(
            item["allowed_target_hashes"], f"{field}.allowed_target_hashes"
        )
    scope: Dict[str, Any] = {
        "intent_id": _text(item.get("intent_id"), f"{field}.intent_id"),
        "allowed_actions": _action_set(
            item.get("allowed_actions"), f"{field}.allowed_actions"
        ),
        "allowed_target_hashes": target_hashes,
        "allowed_requested_scopes": _string_set(
            item.get("allowed_requested_scopes"),
            f"{field}.allowed_requested_scopes",
        ),
        "allowed_data_classifications": _string_set(
            item.get("allowed_data_classifications"),
            f"{field}.allowed_data_classifications",
        ),
    }
    if "deny_after_outcomes" in item:
        scope["deny_after_outcomes"] = _outcome_set(
            item["deny_after_outcomes"], f"{field}.deny_after_outcomes"
        )
    if "max_prior_actions" in item:
        maximum = item["max_prior_actions"]
        if (
            isinstance(maximum, bool)
            or not isinstance(maximum, int)
            or maximum < 0
            or maximum > _MAX_SAFE_INTEGER
        ):
            _fail(f"{field}.max_prior_actions must be a nonnegative safe integer")
        scope["max_prior_actions"] = maximum
    return scope


def build_intent_policy_v2(input_value: Any) -> Dict[str, Any]:
    root = _record(input_value, "intent policy")
    _exact_keys(root, {"schema", "profile_version", "intent_scopes"}, "intent policy")
    if root.get("schema") != INTENT_POLICY_V2_SCHEMA:
        _fail(f"schema must be {INTENT_POLICY_V2_SCHEMA}")
    if root.get("profile_version") != INTENT_POLICY_V2_PROFILE_VERSION:
        _fail(f"profile_version must be {INTENT_POLICY_V2_PROFILE_VERSION}")
    scopes_value = root.get("intent_scopes")
    if not isinstance(scopes_value, list):
        _fail("intent_scopes must be an array")
    if len(scopes_value) > STRICT_SET_MAX_ITEMS:
        _fail(f"intent_scopes exceeds {STRICT_SET_MAX_ITEMS} items")
    scopes = [_intent_scope(value, index) for index, value in enumerate(scopes_value)]
    ids = [scope["intent_id"] for scope in scopes]
    if len(ids) != len(set(ids)):
        _fail("duplicate intent_id")
    scopes.sort(key=lambda scope: code_point_key(scope["intent_id"]))
    return {
        "schema": INTENT_POLICY_V2_SCHEMA,
        "profile_version": INTENT_POLICY_V2_PROFILE_VERSION,
        "intent_scopes": scopes,
    }


def canonicalize_intent_policy_v2(input_value: Any) -> str:
    return _canonical_json_for_hash(build_intent_policy_v2(input_value))


def intent_policy_v2_hash(input_value: Any) -> str:
    return hashlib.sha256(
        canonicalize_intent_policy_v2(input_value).encode("utf-8")
    ).hexdigest()


def _context_input(value: Dict[str, Any]) -> Dict[str, Any]:
    agent = value["agent"]
    result = {
        "agent_id": agent["agent_id"],
        "active_intents": agent["active_intents"],
        "current_action": value["action"],
        "run_id": value["run_id"],
        "prior_actions": value["prior_actions"],
    }
    if "role" in agent:
        result["agent_role"] = agent["role"]
    if "privilege_scope" in agent:
        result["privilege_scope"] = agent["privilege_scope"]
    if "session_id" in value:
        result["session_id"] = value["session_id"]
    if "thread_id" in value:
        result["thread_id"] = value["thread_id"]
    return result


def _normalized_context(value: Any) -> Dict[str, Any]:
    raw = _record(value, "action context")
    if "schema" in raw:
        if raw.get("schema") != ACTION_CONTEXT_V2_SCHEMA:
            _fail(f"context schema must be {ACTION_CONTEXT_V2_SCHEMA}")
        return build_action_context_v2(_context_input(raw))
    return build_action_context_v2(value)


def _normalized_base(value: Any) -> Dict[str, Any]:
    base = _record(value, "base result")
    _exact_keys(
        base,
        {
            "action_taken",
            "approval_required",
            "approval_request_id",
            "approval_action_hash",
            "approval_expires_at_ms",
            "modified_arguments_hash",
        },
        "base result",
    )
    action_taken = base.get("action_taken")
    if not isinstance(action_taken, str) or action_taken not in _ACTION_TAKEN:
        _fail("base result action_taken is unsupported")
    if "approval_required" in base and not isinstance(base["approval_required"], bool):
        _fail("approval_required must be a boolean")
    if base.get("approval_required") is True and action_taken != "blocked":
        _fail("approval_required is valid only when blocked")
    if _APPROVAL_FIELDS.intersection(base) and (
        action_taken != "blocked" or base.get("approval_required") is not True
    ):
        _fail(
            "approval binding fields are valid only when blocked with approval_required"
        )
    if "approval_request_id" in base:
        _text(base["approval_request_id"], "approval_request_id")
    if "approval_action_hash" in base:
        _hash(base["approval_action_hash"], "approval_action_hash")
    expiry = base.get("approval_expires_at_ms")
    if "approval_expires_at_ms" in base and (
        isinstance(expiry, bool)
        or not isinstance(expiry, int)
        or expiry < 0
        or expiry > _MAX_SAFE_INTEGER
    ):
        _fail("approval_expires_at_ms must be a nonnegative safe integer")
    if "modified_arguments_hash" in base and not isinstance(
        base["modified_arguments_hash"], str
    ):
        _fail("modified_arguments_hash must be a string")
    if "modified_arguments_hash" in base and action_taken != "redacted":
        _fail("modified_arguments_hash is valid only when redacted")
    return {key: value_ for key, value_ in base.items() if value_ is not False}


def _result(
    outcome: str, reason: str, hashes: Dict[str, str], required: List[str] | None = None
) -> Dict[str, Any]:
    output = {
        "outcome": outcome,
        "reason_code": reason,
        "prevents_original_action": outcome != "ALLOW",
        **hashes,
    }
    if outcome == "DEFER":
        if not required:
            _fail("DEFER requires required_fields")
        output["required_fields"] = sorted(set(required), key=code_point_key)
    return output


def evaluate_intent_alignment_v2(
    *, context: Any, base_result: Any, policy: Any
) -> Dict[str, Any]:
    context = _normalized_context(context)
    policy = build_intent_policy_v2(policy)
    base = _normalized_base(base_result)
    context_hash = hashlib.sha256(
        _canonical_json_for_hash(context).encode("utf-8")
    ).hexdigest()
    policy_hash = hashlib.sha256(
        _canonical_json_for_hash(policy).encode("utf-8")
    ).hexdigest()
    input_hash = hashlib.sha256(
        _canonical_json_for_hash(
            {
                "schema": INTENT_V2_EVALUATION_INPUT_SCHEMA,
                "base_result": base,
                "context_hash": context_hash,
                "policy_hash": policy_hash,
            }
        ).encode("utf-8")
    ).hexdigest()
    evaluator_hash = hashlib.sha256(
        _canonical_json_for_hash(
            {"engine_version": INTENT_V2_ENGINE_VERSION, "policy_hash": policy_hash}
        ).encode("utf-8")
    ).hexdigest()
    hashes = {
        "engine_version": INTENT_V2_ENGINE_VERSION,
        "context_hash": context_hash,
        "policy_hash": policy_hash,
        "input_hash": input_hash,
        "evaluator_hash": evaluator_hash,
    }
    action_taken = base["action_taken"]
    if action_taken == "blocked" and base.get("approval_required") is not True:
        return _result("DENY", "base_blocked", hashes)
    if action_taken in {"hook_error", "hook_timeout", "not_evaluated"}:
        return _result("DEFER", f"base_{action_taken}", hashes, ["policy_evaluation"])
    intents = context["agent"]["active_intents"]
    if len(intents) > 1:
        return _result("DEFER", "multiple_active_intents", hashes, ["active_intents"])
    scope = next(
        (item for item in policy["intent_scopes"] if item["intent_id"] == intents[0]),
        None,
    )
    if scope is None:
        return _result("DEFER", "intent_not_declared", hashes, ["intent_policy"])
    action = context["action"]
    if not any(
        allowed["kind"] == action["kind"] and allowed["name"] == action["name"]
        for allowed in scope["allowed_actions"]
    ):
        return _result("DENY", "action_not_allowed", hashes)
    if "target_hash" not in action and scope["allowed_target_hashes"]:
        return _result("DEFER", "target_missing", hashes, ["action.target"])
    if (
        "target_hash" in action
        and action["target_hash"] not in scope["allowed_target_hashes"]
    ):
        return _result("DENY", "target_not_allowed", hashes)
    allowed_scopes = set(scope["allowed_requested_scopes"])
    if any(item not in allowed_scopes for item in action["requested_scopes"]):
        return _result("DENY", "requested_scope_not_allowed", hashes)
    allowed_classes = set(scope["allowed_data_classifications"])
    if any(item not in allowed_classes for item in action["data_classifications"]):
        return _result("DENY", "data_classification_not_allowed", hashes)
    privileges = set(context["agent"].get("privilege_scope", []))
    if any(item not in privileges for item in action["requested_scopes"]):
        return _result("DENY", "requested_scope_not_privileged", hashes)
    denied = set(scope.get("deny_after_outcomes", []))
    if any(item["outcome"] in denied for item in context["prior_actions"]):
        return _result("DENY", "prior_outcome_denied", hashes)
    if (
        "max_prior_actions" in scope
        and len(context["prior_actions"]) > scope["max_prior_actions"]
    ):
        return _result("DENY", "prior_action_limit_exceeded", hashes)
    if action_taken == "blocked" and base.get("approval_required") is True:
        missing = sorted(_APPROVAL_FIELDS.difference(base), key=code_point_key)
        return (
            _result("DEFER", "approval_binding_missing", hashes, missing)
            if missing
            else _result("STEP_UP", "approval_required", hashes)
        )
    if action_taken == "redacted":
        modified = base.get("modified_arguments_hash")
        if (
            not isinstance(modified, str)
            or len(modified) != 64
            or any(character not in _HEX for character in modified)
            or modified == action["arguments_hash"]
        ):
            return _result(
                "DEFER",
                "modified_arguments_hash_unproven",
                hashes,
                ["modified_arguments_hash"],
            )
        return _result("MODIFY", "arguments_modified", hashes)
    return _result("ALLOW", "intent_aligned", hashes)
