"""Pure intent-scope evaluation over canonical action context."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from .aarm_outcome import AARM_OUTCOMES
from .action_context import ACTION_CONTEXT_SCHEMA, build_action_context
from .tool_pinning import _canonical_json_for_hash

INTENT_POLICY_SCHEMA = "obsvr-intent-policy-v1"
INTENT_POLICY_PROFILE_VERSION = "1.0"
INTENT_ENGINE_VERSION = "obsvr-intent/1"
INTENT_EVALUATION_INPUT_SCHEMA = "obsvr-intent-evaluation-input-v1"

_OUTCOMES = frozenset(AARM_OUTCOMES)
_ACTION_TAKEN = frozenset(
    {"allowed", "blocked", "redacted", "not_evaluated", "hook_error", "hook_timeout"}
)
_HASH_LENGTH = 64
_HEX = frozenset("0123456789abcdef")
_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_APPROVAL_FIELDS = frozenset(
    {"approval_request_id", "approval_action_hash", "approval_expires_at_ms"}
)


class IntentAlignmentValidationError(ValueError):
    """The policy or base result cannot be evaluated unambiguously."""


def _record(value: Any, field: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise IntentAlignmentValidationError(f"{field} must be an object")
    return value


def _exact_keys(value: Dict[str, Any], allowed: set[str], field: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise IntentAlignmentValidationError(
            f"{field} contains unsupported field: {unknown[0]}"
        )


def _nonblank(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise IntentAlignmentValidationError(f"{field} must be a nonblank string")
    return value


def _scalar_key(value: str) -> tuple[int, ...]:
    return tuple(ord(char) for char in value)


def _normalized_set(value: Any, field: str) -> List[str]:
    if not isinstance(value, list):
        raise IntentAlignmentValidationError(f"{field} must be an array")
    values = [_nonblank(item, f"{field}[{index}]") for index, item in enumerate(value)]
    return sorted(set(values), key=_scalar_key)


def _normalized_outcomes(value: Any, field: str) -> List[str]:
    values = _normalized_set(value, field)
    if any(value_ not in _OUTCOMES for value_ in values):
        raise IntentAlignmentValidationError(f"{field} contains unsupported outcome")
    return values


def _action_pair(value: Any, field: str) -> Dict[str, str]:
    item = _record(value, field)
    _exact_keys(item, {"kind", "name"}, field)
    return {
        "kind": _nonblank(item.get("kind"), f"{field}.kind"),
        "name": _nonblank(item.get("name"), f"{field}.name"),
    }


def _normalized_actions(value: Any, field: str) -> List[Dict[str, str]]:
    if not isinstance(value, list):
        raise IntentAlignmentValidationError(f"{field} must be an array")
    pairs = [_action_pair(item, f"{field}[{index}]") for index, item in enumerate(value)]
    unique = {(pair["kind"], pair["name"]): pair for pair in pairs}
    return [
        unique[key]
        for key in sorted(unique, key=lambda pair: (_scalar_key(pair[0]), _scalar_key(pair[1])))
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
            "allowed_requested_scopes",
            "allowed_data_classifications",
            "deny_after_outcomes",
            "max_prior_actions",
        },
        field,
    )
    scope: Dict[str, Any] = {
        "intent_id": _nonblank(item.get("intent_id"), f"{field}.intent_id"),
        "allowed_actions": _normalized_actions(
            item.get("allowed_actions"), f"{field}.allowed_actions"
        ),
        "allowed_targets": _normalized_set(
            item.get("allowed_targets"), f"{field}.allowed_targets"
        ),
        "allowed_requested_scopes": _normalized_set(
            item.get("allowed_requested_scopes"),
            f"{field}.allowed_requested_scopes",
        ),
        "allowed_data_classifications": _normalized_set(
            item.get("allowed_data_classifications"),
            f"{field}.allowed_data_classifications",
        ),
    }
    if "deny_after_outcomes" in item:
        scope["deny_after_outcomes"] = _normalized_outcomes(
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
            raise IntentAlignmentValidationError(
                f"{field}.max_prior_actions must be a nonnegative safe integer"
            )
        scope["max_prior_actions"] = maximum
    return scope


def build_intent_policy(input_value: Any) -> Dict[str, Any]:
    root = _record(input_value, "intent policy")
    _exact_keys(root, {"schema", "profile_version", "intent_scopes"}, "intent policy")
    if root.get("schema") != INTENT_POLICY_SCHEMA:
        raise IntentAlignmentValidationError(f"schema must be {INTENT_POLICY_SCHEMA}")
    if root.get("profile_version") != INTENT_POLICY_PROFILE_VERSION:
        raise IntentAlignmentValidationError(
            f"profile_version must be {INTENT_POLICY_PROFILE_VERSION}"
        )
    raw_scopes = root.get("intent_scopes")
    if not isinstance(raw_scopes, list):
        raise IntentAlignmentValidationError("intent_scopes must be an array")
    scopes = [_intent_scope(value, index) for index, value in enumerate(raw_scopes)]
    intent_ids = [scope["intent_id"] for scope in scopes]
    if len(intent_ids) != len(set(intent_ids)):
        raise IntentAlignmentValidationError("duplicate intent_id")
    scopes.sort(key=lambda scope: _scalar_key(scope["intent_id"]))
    return {
        "schema": INTENT_POLICY_SCHEMA,
        "profile_version": INTENT_POLICY_PROFILE_VERSION,
        "intent_scopes": scopes,
    }


def canonicalize_intent_policy(input_value: Any) -> str:
    return _canonical_json_for_hash(build_intent_policy(input_value))


def intent_policy_hash(input_value: Any) -> str:
    return hashlib.sha256(canonicalize_intent_policy(input_value).encode("utf-8")).hexdigest()


def _input_from_document(value: Any) -> Dict[str, Any]:
    root = _record(value, "action context document")
    _exact_keys(
        root,
        {"schema", "agent", "action", "run_id", "session_id", "thread_id", "prior_actions"},
        "action context document",
    )
    if root.get("schema") != ACTION_CONTEXT_SCHEMA:
        raise IntentAlignmentValidationError(
            f"context schema must be {ACTION_CONTEXT_SCHEMA}"
        )
    agent = _record(root.get("agent"), "action context document.agent")
    _exact_keys(
        agent,
        {"agent_id", "active_intents", "role", "privilege_scope"},
        "action context document.agent",
    )
    action = _record(root.get("action"), "action context document.action")
    _exact_keys(
        action,
        {
            "kind",
            "name",
            "arguments_hash",
            "target",
            "data_classifications",
            "requested_scopes",
        },
        "action context document.action",
    )
    input_value: Dict[str, Any] = {
        "agent_id": agent.get("agent_id"),
        "active_intents": agent.get("active_intents"),
        "current_action": action,
        "run_id": root.get("run_id"),
        "prior_actions": root.get("prior_actions"),
    }
    if "role" in agent:
        input_value["agent_role"] = agent["role"]
    if "privilege_scope" in agent:
        input_value["privilege_scope"] = agent["privilege_scope"]
    if "session_id" in root:
        input_value["session_id"] = root["session_id"]
    if "thread_id" in root:
        input_value["thread_id"] = root["thread_id"]
    return input_value


def _normalized_context(value: Any) -> Dict[str, Any]:
    raw = _record(value, "action context")
    return build_action_context(
        _input_from_document(raw) if "schema" in raw else value
    )


def _normalized_base_result(value: Any) -> Dict[str, Any]:
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
        raise IntentAlignmentValidationError("base result action_taken is unsupported")
    if "approval_required" in base and not isinstance(base["approval_required"], bool):
        raise IntentAlignmentValidationError("approval_required must be a boolean")
    if base.get("approval_required") is True and action_taken != "blocked":
        raise IntentAlignmentValidationError(
            "approval_required is valid only when blocked"
        )
    if _APPROVAL_FIELDS.intersection(base) and (
        action_taken != "blocked" or base.get("approval_required") is not True
    ):
        raise IntentAlignmentValidationError(
            "approval binding fields are valid only when blocked with approval_required"
        )
    if "approval_request_id" in base:
        _nonblank(base["approval_request_id"], "approval_request_id")
    if "approval_action_hash" in base and (
        not isinstance(base["approval_action_hash"], str)
        or len(base["approval_action_hash"]) != _HASH_LENGTH
        or any(char not in _HEX for char in base["approval_action_hash"])
    ):
        raise IntentAlignmentValidationError(
            "approval_action_hash must be 64 lowercase hex characters"
        )
    if "approval_expires_at_ms" in base and (
        isinstance(base["approval_expires_at_ms"], bool)
        or not isinstance(base["approval_expires_at_ms"], int)
        or base["approval_expires_at_ms"] < 0
        or base["approval_expires_at_ms"] > _MAX_SAFE_INTEGER
    ):
        raise IntentAlignmentValidationError(
            "approval_expires_at_ms must be a nonnegative safe integer"
        )
    if "modified_arguments_hash" in base and not isinstance(
        base["modified_arguments_hash"], str
    ):
        raise IntentAlignmentValidationError(
            "modified_arguments_hash must be a string"
        )
    if "modified_arguments_hash" in base and action_taken != "redacted":
        raise IntentAlignmentValidationError(
            "modified_arguments_hash is valid only when redacted"
        )
    result = {"action_taken": action_taken}
    if base.get("approval_required") is True:
        result["approval_required"] = True
    for field in _APPROVAL_FIELDS:
        if field in base:
            result[field] = base[field]
    if isinstance(base.get("modified_arguments_hash"), str):
        result["modified_arguments_hash"] = base["modified_arguments_hash"]
    return result


def _subset(values: List[str], allowed: List[str]) -> bool:
    allowed_set = set(allowed)
    return all(value in allowed_set for value in values)


def _result(
    outcome: str,
    reason_code: str,
    hashes: Dict[str, str],
    required_fields: List[str] | None = None,
) -> Dict[str, Any]:
    output = {
        "outcome": outcome,
        "reason_code": reason_code,
        "prevents_original_action": outcome != "ALLOW",
        **hashes,
    }
    if outcome == "DEFER":
        if not required_fields:
            raise IntentAlignmentValidationError("DEFER requires required_fields")
        output["required_fields"] = sorted(set(required_fields), key=_scalar_key)
    return output


def evaluate_intent_alignment(
    *, context: Any, base_result: Any, policy: Any
) -> Dict[str, Any]:
    normalized_context = _normalized_context(context)
    normalized_policy = build_intent_policy(policy)
    base = _normalized_base_result(base_result)
    context_hash = hashlib.sha256(
        _canonical_json_for_hash(normalized_context).encode("utf-8")
    ).hexdigest()
    policy_hash = hashlib.sha256(
        _canonical_json_for_hash(normalized_policy).encode("utf-8")
    ).hexdigest()
    evaluation_input = {
        "schema": INTENT_EVALUATION_INPUT_SCHEMA,
        "base_result": base,
        "context_hash": context_hash,
        "policy_hash": policy_hash,
    }
    input_hash = hashlib.sha256(
        _canonical_json_for_hash(evaluation_input).encode("utf-8")
    ).hexdigest()
    evaluator_hash = hashlib.sha256(
        _canonical_json_for_hash(
            {"engine_version": INTENT_ENGINE_VERSION, "policy_hash": policy_hash}
        ).encode("utf-8")
    ).hexdigest()
    hashes = {
        "engine_version": INTENT_ENGINE_VERSION,
        "context_hash": context_hash,
        "policy_hash": policy_hash,
        "input_hash": input_hash,
        "evaluator_hash": evaluator_hash,
    }

    action_taken = base["action_taken"]
    if action_taken == "blocked" and base.get("approval_required") is not True:
        return _result("DENY", "base_blocked", hashes)
    if action_taken == "hook_error":
        return _result("DEFER", "base_hook_error", hashes, ["policy_evaluation"])
    if action_taken == "hook_timeout":
        return _result("DEFER", "base_hook_timeout", hashes, ["policy_evaluation"])
    if action_taken == "not_evaluated":
        return _result("DEFER", "base_not_evaluated", hashes, ["policy_evaluation"])

    active_intents = normalized_context["agent"]["active_intents"]
    if len(active_intents) > 1:
        return _result("DEFER", "multiple_active_intents", hashes, ["active_intents"])
    scope = next(
        (
            candidate
            for candidate in normalized_policy["intent_scopes"]
            if candidate["intent_id"] == active_intents[0]
        ),
        None,
    )
    if scope is None:
        return _result("DEFER", "intent_not_declared", hashes, ["intent_policy"])
    action = normalized_context["action"]
    if not any(
        allowed["kind"] == action["kind"] and allowed["name"] == action["name"]
        for allowed in scope["allowed_actions"]
    ):
        return _result("DENY", "action_not_allowed", hashes)
    if "target" not in action and scope["allowed_targets"]:
        return _result("DEFER", "target_missing", hashes, ["action.target"])
    if "target" in action and action["target"] not in scope["allowed_targets"]:
        return _result("DENY", "target_not_allowed", hashes)
    if not _subset(action["requested_scopes"], scope["allowed_requested_scopes"]):
        return _result("DENY", "requested_scope_not_allowed", hashes)
    if not _subset(
        action["data_classifications"], scope["allowed_data_classifications"]
    ):
        return _result("DENY", "data_classification_not_allowed", hashes)
    if not _subset(
        action["requested_scopes"],
        normalized_context["agent"].get("privilege_scope", []),
    ):
        return _result("DENY", "requested_scope_not_privileged", hashes)
    denied_prior = set(scope.get("deny_after_outcomes", []))
    if any(
        prior["outcome"] in denied_prior
        for prior in normalized_context["prior_actions"]
    ):
        return _result("DENY", "prior_outcome_denied", hashes)
    if (
        "max_prior_actions" in scope
        and len(normalized_context["prior_actions"]) > scope["max_prior_actions"]
    ):
        return _result("DENY", "prior_action_limit_exceeded", hashes)
    if action_taken == "blocked" and base.get("approval_required") is True:
        missing = sorted(
            _APPROVAL_FIELDS.difference(base),
            key=_scalar_key,
        )
        if missing:
            return _result("DEFER", "approval_binding_missing", hashes, missing)
        return _result("STEP_UP", "approval_required", hashes)
    if action_taken == "redacted":
        modified = base.get("modified_arguments_hash")
        if (
            not isinstance(modified, str)
            or len(modified) != _HASH_LENGTH
            or any(char not in _HEX for char in modified)
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
