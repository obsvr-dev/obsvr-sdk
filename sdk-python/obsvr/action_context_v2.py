"""Bounded v2 action context with tokenized targets."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from .aarm_outcome import AARM_OUTCOMES
from .strict_canonical import (
    STRICT_CONTEXT_MAX_BYTES,
    STRICT_IDENTIFIER_MAX_BYTES,
    STRICT_PRIOR_ACTIONS_MAX_ITEMS,
    STRICT_SET_MAX_ITEMS,
    STRICT_TARGET_MAX_BYTES,
    bounded_canonical_text,
    code_point_key,
    normalized_bounded_set,
)
from .tool_pinning import _canonical_json_for_hash

ACTION_CONTEXT_V2_SCHEMA = "obsvr-action-context-v2"
ACTION_TARGET_HASH_DOMAIN = b"obsvr-action-target/1"
_HEX = frozenset("0123456789abcdef")
_OUTCOMES = frozenset(AARM_OUTCOMES)
_MAX_SAFE_INTEGER = 9_007_199_254_740_991


class ActionContextV2ValidationError(ValueError):
    """The input cannot produce one bounded canonical v2 context."""


def _fail(message: str) -> None:
    raise ActionContextV2ValidationError(message)


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


def _optional_text(value: Dict[str, Any], key: str, field: str) -> str | None:
    return _text(value[key], field) if key in value else None


def _hash(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _HEX for character in value)
    ):
        _fail(f"{field} must be exactly 64 lowercase hexadecimal characters")
    return value


def _string_set(value: Any, field: str) -> List[str]:
    return normalized_bounded_set(
        value, field, STRICT_SET_MAX_ITEMS, STRICT_IDENTIFIER_MAX_BYTES, _fail
    )


def action_target_hash(value: Any) -> str:
    target = bounded_canonical_text(
        value, "current_action.target", STRICT_TARGET_MAX_BYTES, _fail
    )
    return hashlib.sha256(
        ACTION_TARGET_HASH_DOMAIN + b"\x00" + target.encode("utf-8")
    ).hexdigest()


def _prior_action(value: Any, index: int) -> Dict[str, Any]:
    field = f"prior_actions[{index}]"
    item = _record(value, field)
    _exact_keys(
        item,
        {"sequence", "kind", "name", "outcome", "receipt_hash", "data_classifications"},
        field,
    )
    sequence = item.get("sequence")
    if (
        isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or sequence < 0
        or sequence > _MAX_SAFE_INTEGER
    ):
        _fail(f"{field}.sequence must be a nonnegative safe integer")
    outcome = item.get("outcome")
    if not isinstance(outcome, str) or outcome not in _OUTCOMES:
        _fail(f"{field}.outcome is unsupported")
    return {
        "sequence": sequence,
        "kind": _text(item.get("kind"), f"{field}.kind"),
        "name": _text(item.get("name"), f"{field}.name"),
        "outcome": outcome,
        "receipt_hash": _hash(item.get("receipt_hash"), f"{field}.receipt_hash"),
        "data_classifications": _string_set(
            item.get("data_classifications"), f"{field}.data_classifications"
        ),
    }


def build_action_context_v2(input_value: Any) -> Dict[str, Any]:
    """Build a bounded context whose canonical form excludes the raw target."""
    root = _record(input_value, "action context")
    _exact_keys(
        root,
        {
            "agent_id",
            "active_intents",
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
        {
            "kind",
            "name",
            "arguments_hash",
            "target",
            "target_hash",
            "data_classifications",
            "requested_scopes",
        },
        "current_action",
    )

    active_intents = _string_set(root.get("active_intents"), "active_intents")
    if not active_intents:
        _fail("active_intents must not be empty")
    agent: Dict[str, Any] = {
        "agent_id": _text(root.get("agent_id"), "agent_id"),
        "active_intents": active_intents,
    }
    role = _optional_text(root, "agent_role", "agent_role")
    if role is not None:
        agent["role"] = role
    if "privilege_scope" in root:
        agent["privilege_scope"] = _string_set(
            root["privilege_scope"], "privilege_scope"
        )

    action: Dict[str, Any] = {
        "kind": _text(current.get("kind"), "current_action.kind"),
        "name": _text(current.get("name"), "current_action.name"),
        "arguments_hash": _hash(
            current.get("arguments_hash"), "current_action.arguments_hash"
        ),
        "data_classifications": _string_set(
            current.get("data_classifications"),
            "current_action.data_classifications",
        ),
        "requested_scopes": _string_set(
            current.get("requested_scopes"), "current_action.requested_scopes"
        ),
    }
    if "target" in current and "target_hash" in current:
        _fail("current_action cannot contain target and target_hash")
    if "target" in current:
        action["target_hash"] = action_target_hash(current["target"])
    elif "target_hash" in current:
        action["target_hash"] = _hash(
            current["target_hash"], "current_action.target_hash"
        )

    prior_input = root.get("prior_actions")
    if not isinstance(prior_input, list):
        _fail("prior_actions must be an array")
    if len(prior_input) > STRICT_PRIOR_ACTIONS_MAX_ITEMS:
        _fail(f"prior_actions exceeds {STRICT_PRIOR_ACTIONS_MAX_ITEMS} items")
    prior_actions = [
        _prior_action(item, index) for index, item in enumerate(prior_input)
    ]
    for previous, current_action in zip(prior_actions, prior_actions[1:]):
        if current_action["sequence"] <= previous["sequence"]:
            _fail("prior_actions sequences must be strictly increasing in input order")

    doc: Dict[str, Any] = {
        "schema": ACTION_CONTEXT_V2_SCHEMA,
        "agent": agent,
        "action": action,
        "run_id": _text(root.get("run_id"), "run_id"),
        "prior_actions": prior_actions,
    }
    session_id = _optional_text(root, "session_id", "session_id")
    if session_id is not None:
        doc["session_id"] = session_id
    thread_id = _optional_text(root, "thread_id", "thread_id")
    if thread_id is not None:
        doc["thread_id"] = thread_id
    if len(_canonical_json_for_hash(doc).encode("utf-8")) > STRICT_CONTEXT_MAX_BYTES:
        _fail(
            f"canonical action context exceeds {STRICT_CONTEXT_MAX_BYTES} UTF-8 bytes"
        )
    return doc


def canonicalize_action_context_v2(input_value: Any) -> str:
    return _canonical_json_for_hash(build_action_context_v2(input_value))


def action_context_v2_hash(input_value: Any) -> str:
    return hashlib.sha256(
        canonicalize_action_context_v2(input_value).encode("utf-8")
    ).hexdigest()
