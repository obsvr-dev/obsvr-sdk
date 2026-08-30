"""Deterministic remediation requirements and linked retry attempts."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from .strict_canonical import (
    STRICT_IDENTIFIER_MAX_BYTES,
    STRICT_SET_MAX_ITEMS,
    bounded_canonical_text,
    code_point_key,
)
from .tool_pinning import _canonical_json_for_hash

REMEDIATION_PLAN_V1_SCHEMA = "obsvr-remediation-plan-v1"
REMEDIATION_RETRY_V1_SCHEMA = "obsvr-remediation-retry-v1"
REMEDIATION_PLAN_HASH_DOMAIN = b"obsvr-remediation-plan/1"
_HEX = frozenset("0123456789abcdef")
_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_OUTCOMES = frozenset({"MODIFY", "STEP_UP", "DEFER"})
_REQUIREMENT_KINDS = frozenset(
    {"approval", "context", "modification", "scope", "tool", "verification", "wait_until"}
)


class RemediationV1ValidationError(ValueError):
    """The remediation statement is not bounded or internally consistent."""


def _fail(message: str) -> None:
    raise RemediationV1ValidationError(message)


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
        _fail(f"{field} must be exactly 64 lowercase hexadecimal characters")
    return value


def _integer(value: Any, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > _MAX_SAFE_INTEGER
    ):
        _fail(f"{field} must be a nonnegative safe integer")
    return value


def _requirement(value: Any, index: int) -> Dict[str, Any]:
    field = f"requirements[{index}]"
    item = _record(value, field)
    _exact_keys(
        item,
        {"kind", "code", "evidence_key", "expected_value_hash", "guidance"},
        field,
    )
    if item.get("kind") not in _REQUIREMENT_KINDS:
        _fail(f"{field}.kind is unsupported")
    result = {
        "kind": item["kind"],
        "code": _text(item.get("code"), f"{field}.code"),
        "evidence_key": _text(item.get("evidence_key"), f"{field}.evidence_key"),
    }
    if "expected_value_hash" in item:
        result["expected_value_hash"] = _hash(
            item["expected_value_hash"], f"{field}.expected_value_hash"
        )
    if "guidance" in item:
        result["guidance"] = _text(item["guidance"], f"{field}.guidance")
    return result


def build_remediation_plan_v1(input_value: Dict[str, Any]) -> Dict[str, Any]:
    root = _record(input_value, "remediation plan")
    _exact_keys(
        root,
        {
            "schema",
            "plan_id",
            "attempt_id",
            "receipt_hash",
            "outcome",
            "reason_code",
            "requirements",
            "created_at_ms",
            "expires_at_ms",
        },
        "remediation plan",
    )
    if "schema" in root and root["schema"] != REMEDIATION_PLAN_V1_SCHEMA:
        _fail("remediation plan schema is invalid")
    if root.get("outcome") not in _OUTCOMES:
        _fail("outcome must be MODIFY, STEP_UP, or DEFER")
    raw_requirements = root.get("requirements")
    if (
        not isinstance(raw_requirements, list)
        or not raw_requirements
        or len(raw_requirements) > STRICT_SET_MAX_ITEMS
    ):
        _fail(f"requirements must contain between 1 and {STRICT_SET_MAX_ITEMS} items")
    requirements = sorted(
        (_requirement(item, index) for index, item in enumerate(raw_requirements)),
        key=lambda item: code_point_key(
            f"{item['kind']}\x00{item['code']}\x00{item['evidence_key']}"
        ),
    )
    if len({item["code"] for item in requirements}) != len(requirements):
        _fail("requirement codes must be unique")
    created = _integer(root.get("created_at_ms"), "created_at_ms")
    document = {
        "schema": REMEDIATION_PLAN_V1_SCHEMA,
        "plan_id": _text(root.get("plan_id"), "plan_id"),
        "attempt_id": _text(root.get("attempt_id"), "attempt_id"),
        "receipt_hash": _hash(root.get("receipt_hash"), "receipt_hash"),
        "outcome": root["outcome"],
        "reason_code": _text(root.get("reason_code"), "reason_code"),
        "requirements": requirements,
        "created_at_ms": created,
    }
    if "expires_at_ms" in root:
        expires = _integer(root["expires_at_ms"], "expires_at_ms")
        if expires <= created:
            _fail("expires_at_ms must be after created_at_ms")
        document["expires_at_ms"] = expires
    return document


def canonicalize_remediation_plan_v1(input_value: Dict[str, Any]) -> str:
    return _canonical_json_for_hash(build_remediation_plan_v1(input_value))


def remediation_plan_v1_hash(input_value: Dict[str, Any]) -> str:
    payload = (
        REMEDIATION_PLAN_HASH_DOMAIN
        + b"\x00"
        + canonicalize_remediation_plan_v1(input_value).encode("utf-8")
    )
    return hashlib.sha256(payload).hexdigest()


def build_remediation_retry_v1(input_value: Dict[str, Any]) -> Dict[str, Any]:
    root = _record(input_value, "remediation retry")
    _exact_keys(
        root,
        {"retry_attempt_id", "plan", "satisfied_requirements"},
        "remediation retry",
    )
    plan = build_remediation_plan_v1(root.get("plan"))
    retry_attempt_id = _text(root.get("retry_attempt_id"), "retry_attempt_id")
    if retry_attempt_id == plan["attempt_id"]:
        _fail("retry_attempt_id must identify a new attempt")
    raw_satisfied = root.get("satisfied_requirements")
    if not isinstance(raw_satisfied, list) or len(raw_satisfied) > STRICT_SET_MAX_ITEMS:
        _fail(
            f"satisfied_requirements must contain at most {STRICT_SET_MAX_ITEMS} items"
        )
    satisfied: List[Dict[str, str]] = []
    for index, candidate in enumerate(raw_satisfied):
        field = f"satisfied_requirements[{index}]"
        item = _record(candidate, field)
        _exact_keys(item, {"code", "evidence_hash"}, field)
        satisfied.append(
            {
                "code": _text(item.get("code"), f"{field}.code"),
                "evidence_hash": _hash(
                    item.get("evidence_hash"), f"{field}.evidence_hash"
                ),
            }
        )
    satisfied.sort(key=lambda item: code_point_key(item["code"]))
    if len({item["code"] for item in satisfied}) != len(satisfied):
        _fail("satisfied requirement codes must be unique")
    required_codes = sorted(
        (item["code"] for item in plan["requirements"]), key=code_point_key
    )
    if [item["code"] for item in satisfied] != required_codes:
        _fail("satisfied_requirements must provide evidence for every plan requirement")
    return {
        "schema": REMEDIATION_RETRY_V1_SCHEMA,
        "retry_attempt_id": retry_attempt_id,
        "parent_attempt_id": plan["attempt_id"],
        "parent_receipt_hash": plan["receipt_hash"],
        "remediation_plan_hash": remediation_plan_v1_hash(plan),
        "satisfied_requirements": satisfied,
    }


def remediation_retry_v1_hash(input_value: Dict[str, Any]) -> str:
    return hashlib.sha256(
        _canonical_json_for_hash(build_remediation_retry_v1(input_value)).encode("utf-8")
    ).hexdigest()


__all__ = [
    "REMEDIATION_PLAN_V1_SCHEMA",
    "REMEDIATION_RETRY_V1_SCHEMA",
    "RemediationV1ValidationError",
    "build_remediation_plan_v1",
    "build_remediation_retry_v1",
    "canonicalize_remediation_plan_v1",
    "remediation_plan_v1_hash",
    "remediation_retry_v1_hash",
]
