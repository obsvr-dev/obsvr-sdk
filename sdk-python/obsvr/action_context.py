"""Strict canonical action context without raw arguments or sensitive content."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from .aarm_outcome import AARM_OUTCOMES
from .tool_pinning import _canonical_json_for_hash

ACTION_CONTEXT_SCHEMA = "obsvr-action-context-v1"
_HASH_LENGTH = 64
_HEX = frozenset("0123456789abcdef")
_OUTCOMES = frozenset(AARM_OUTCOMES)
_MAX_SAFE_INTEGER = 9_007_199_254_740_991


class ActionContextValidationError(ValueError):
    """The input cannot produce one unambiguous canonical context."""


def _record(value: Any, field: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ActionContextValidationError(f"{field} must be an object")
    return value


def _exact_keys(value: Dict[str, Any], allowed: set[str], field: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ActionContextValidationError(
            f"{field} contains unsupported field: {unknown[0]}"
        )


def _nonblank(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ActionContextValidationError(f"{field} must be a nonblank string")
    return value


def _optional_nonblank(value: Dict[str, Any], key: str, field: str) -> str | None:
    if key not in value:
        return None
    return _nonblank(value[key], field)


def _hash(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != _HASH_LENGTH
        or any(char not in _HEX for char in value)
    ):
        raise ActionContextValidationError(
            f"{field} must be exactly 64 lowercase hexadecimal characters"
        )
    return value


def _normalized_set(value: Any, field: str) -> List[str]:
    if not isinstance(value, list):
        raise ActionContextValidationError(f"{field} must be an array")
    strings = [_nonblank(entry, f"{field}[{index}]") for index, entry in enumerate(value)]
    return sorted(set(strings), key=lambda item: tuple(ord(char) for char in item))


def _prior_action(value: Any, index: int) -> Dict[str, Any]:
    field = f"prior_actions[{index}]"
    item = _record(value, field)
    _exact_keys(
        item,
        {
            "sequence",
            "kind",
            "name",
            "outcome",
            "receipt_hash",
            "data_classifications",
        },
        field,
    )
    sequence = item.get("sequence")
    if (
        isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or sequence < 0
        or sequence > _MAX_SAFE_INTEGER
    ):
        raise ActionContextValidationError(
            f"{field}.sequence must be a nonnegative safe integer"
        )
    outcome = item.get("outcome")
    if not isinstance(outcome, str) or outcome not in _OUTCOMES:
        raise ActionContextValidationError(f"{field}.outcome is unsupported")
    return {
        "sequence": sequence,
        "kind": _nonblank(item.get("kind"), f"{field}.kind"),
        "name": _nonblank(item.get("name"), f"{field}.name"),
        "outcome": outcome,
        "receipt_hash": _hash(item.get("receipt_hash"), f"{field}.receipt_hash"),
        "data_classifications": _normalized_set(
            item.get("data_classifications"), f"{field}.data_classifications"
        ),
    }


def build_action_context(input_value: Any) -> Dict[str, Any]:
    """Build a strict canonical document from structured, non-content facts."""
    root = _record(input_value, "action context")
    _exact_keys(
        root,
        {
            "agent_id",
            "intent",
            "agent_role",
            "privilege_scope",
            "current_action",
            "run_id",
            "session_id",
            "thread_id",
            "prior_actions",
        },
        "action context",
    )
    current = _record(root.get("current_action"), "current_action")
    _exact_keys(
        current,
        {"kind", "name", "arguments_hash", "target", "data_classifications"},
        "current_action",
    )

    agent: Dict[str, Any] = {
        "agent_id": _nonblank(root.get("agent_id"), "agent_id"),
        "intent": _nonblank(root.get("intent"), "intent"),
    }
    role = _optional_nonblank(root, "agent_role", "agent_role")
    if role is not None:
        agent["role"] = role
    if "privilege_scope" in root:
        agent["privilege_scope"] = _normalized_set(
            root["privilege_scope"], "privilege_scope"
        )

    action: Dict[str, Any] = {
        "kind": _nonblank(current.get("kind"), "current_action.kind"),
        "name": _nonblank(current.get("name"), "current_action.name"),
        "arguments_hash": _hash(
            current.get("arguments_hash"), "current_action.arguments_hash"
        ),
        "data_classifications": _normalized_set(
            current.get("data_classifications"),
            "current_action.data_classifications",
        ),
    }
    target = _optional_nonblank(current, "target", "current_action.target")
    if target is not None:
        action["target"] = target

    prior_input = root.get("prior_actions")
    if not isinstance(prior_input, list):
        raise ActionContextValidationError("prior_actions must be an array")
    prior_actions = [_prior_action(item, index) for index, item in enumerate(prior_input)]
    for previous, current_action in zip(prior_actions, prior_actions[1:]):
        if current_action["sequence"] <= previous["sequence"]:
            raise ActionContextValidationError(
                "prior_actions sequences must be strictly increasing in input order"
            )

    doc: Dict[str, Any] = {
        "schema": ACTION_CONTEXT_SCHEMA,
        "agent": agent,
        "action": action,
        "run_id": _nonblank(root.get("run_id"), "run_id"),
        "prior_actions": prior_actions,
    }
    session_id = _optional_nonblank(root, "session_id", "session_id")
    if session_id is not None:
        doc["session_id"] = session_id
    thread_id = _optional_nonblank(root, "thread_id", "thread_id")
    if thread_id is not None:
        doc["thread_id"] = thread_id
    return doc


def canonicalize_action_context(input_value: Any) -> str:
    return _canonical_json_for_hash(build_action_context(input_value))


def action_context_hash(input_value: Any) -> str:
    return hashlib.sha256(
        canonicalize_action_context(input_value).encode("utf-8")
    ).hexdigest()
