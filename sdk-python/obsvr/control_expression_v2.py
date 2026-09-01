"""Bounded deterministic control expressions shared by every governed surface."""

from __future__ import annotations

import re
from typing import Any, Dict

from .safe_regex import safe_regex_search, validate_regex_pattern

CONTROL_EXPRESSION_V2_SCHEMA = "obsvr-control-expression-v2"
CONTROL_EXPRESSION_MAX_DEPTH = 12
CONTROL_EXPRESSION_MAX_NODES = 128
CONTROL_EXPRESSION_MAX_SET_ITEMS = 64

_OPERATORS = {
    "exists", "equals", "not_equals", "contains", "in", "greater_than",
    "greater_than_or_equal", "less_than", "less_than_or_equal", "matches",
}


class ControlExpressionValidationError(TypeError):
    """Raised when an authored expression is ambiguous, unsafe, or unbounded."""


def _fail(message: str) -> None:
    raise ControlExpressionValidationError(message)


def _scalar(value: Any, field: str) -> None:
    if value is None or isinstance(value, (str, bool)):
        if isinstance(value, str) and len(value) > 4096:
            _fail(f"{field} exceeds 4096 characters")
        return
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if value != value or value in (float("inf"), float("-inf")):
            _fail(f"{field} must be finite")
        return
    _fail(f"{field} must be a string, finite number, boolean, or null")


def validate_control_expression_v2(expression: Any) -> Dict[str, Any]:
    """Validate and return a normalized expression without mutating the input."""
    nodes = 0

    def visit(candidate: Any, depth: int, field: str) -> Dict[str, Any]:
        nonlocal nodes
        nodes += 1
        if nodes > CONTROL_EXPRESSION_MAX_NODES:
            _fail(f"expression exceeds {CONTROL_EXPRESSION_MAX_NODES} nodes")
        if depth > CONTROL_EXPRESSION_MAX_DEPTH:
            _fail(f"expression exceeds depth {CONTROL_EXPRESSION_MAX_DEPTH}")
        if not isinstance(candidate, dict):
            _fail(f"{field} must be an object")
        branches = [key for key in ("predicate", "all", "any", "not") if key in candidate]
        if len(branches) != 1 or len(candidate) != 1:
            _fail(f"{field} must contain exactly one of predicate, all, any, or not")
        branch = branches[0]
        if branch == "predicate":
            raw = candidate[branch]
            if not isinstance(raw, dict):
                _fail(f"{field}.predicate must be an object")
            unknown = sorted(set(raw) - {"path", "operator", "value"})
            if unknown:
                _fail(f"{field}.predicate contains unsupported field {unknown[0]}")
            path = raw.get("path")
            if not isinstance(path, str) or not path or len(path) > 256:
                _fail("predicate.path must be a non-empty string of at most 256 characters")
            parts = path.split(".")
            if parts[0] not in {"input", "context"} or len(parts) < 2 or len(parts) > 10:
                _fail(f"predicate.path is not a bounded input/context path: {path!r}")
            if any(re.fullmatch(r"[A-Za-z0-9_-]+", part) is None for part in parts[1:]):
                _fail(f"predicate.path is not a bounded input/context path: {path!r}")
            operator = raw.get("operator")
            if operator not in _OPERATORS:
                _fail(f"{field}.predicate.operator is unsupported")
            if operator == "exists":
                if "value" in raw:
                    _fail(f"{field}.predicate.value is not allowed for exists")
            elif "value" not in raw:
                _fail(f"{field}.predicate.value is required for {operator}")
            elif operator == "in":
                value = raw["value"]
                if not isinstance(value, list) or not 1 <= len(value) <= CONTROL_EXPRESSION_MAX_SET_ITEMS:
                    _fail(f"{field}.predicate.value must contain 1-{CONTROL_EXPRESSION_MAX_SET_ITEMS} scalar items for in")
                for index, item in enumerate(value):
                    _scalar(item, f"{field}.predicate.value[{index}]")
            else:
                _scalar(raw["value"], f"{field}.predicate.value")
            if operator == "contains" and not isinstance(raw.get("value"), str):
                _fail(f"{field}.predicate.value must be a string for contains")
            if operator in {
                "greater_than", "greater_than_or_equal", "less_than",
                "less_than_or_equal",
            } and (isinstance(raw.get("value"), bool) or not isinstance(raw.get("value"), (int, float))):
                _fail(f"{field}.predicate.value must be a number for {operator}")
            if operator == "matches":
                if not isinstance(raw.get("value"), str):
                    _fail(f"{field}.predicate.value must be a string for matches")
                ok, why = validate_regex_pattern(raw["value"])
                if not ok:
                    _fail(f"{field}.predicate.value was refused by the ReDoS guard ({why})")
            return {"predicate": dict(raw)}
        if branch == "not":
            return {"not": visit(candidate[branch], depth + 1, f"{field}.not")}
        items = candidate[branch]
        if not isinstance(items, list) or not 1 <= len(items) <= CONTROL_EXPRESSION_MAX_SET_ITEMS:
            _fail(f"{field}.{branch} must contain 1-{CONTROL_EXPRESSION_MAX_SET_ITEMS} expressions")
        return {branch: [visit(item, depth + 1, f"{field}.{branch}[{index}]") for index, item in enumerate(items)]}

    return visit(expression, 1, "expression")


def _resolve(root: Dict[str, Any], path: str) -> tuple[bool, Any]:
    value: Any = root
    for segment in path.split("."):
        if not isinstance(value, dict) or segment not in value:
            return False, None
        value = value[segment]
    return True, value


def _scalar_equal(left: Any, right: Any) -> bool:
    """Match ECMAScript JSON scalar equality across both SDKs."""
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left == right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return left == right
    return type(left) is type(right) and left == right


def evaluate_control_expression_v2(expression: Any, input_document: Dict[str, Any]) -> bool:
    """Evaluate a validated expression with no I/O and no evaluator plugins."""
    valid = validate_control_expression_v2(expression)

    def evaluate(node: Dict[str, Any]) -> bool:
        if "all" in node:
            return all(evaluate(item) for item in node["all"])
        if "any" in node:
            return any(evaluate(item) for item in node["any"])
        if "not" in node:
            return not evaluate(node["not"])
        predicate = node["predicate"]
        found, actual = _resolve(input_document, predicate["path"])
        operator = predicate["operator"]
        if operator == "exists":
            return found
        if not found:
            return False
        expected = predicate.get("value")
        if operator == "equals":
            return _scalar_equal(actual, expected)
        if operator == "not_equals":
            return not _scalar_equal(actual, expected)
        if operator == "contains":
            return isinstance(actual, str) and isinstance(expected, str) and expected in actual
        if operator == "in":
            return any(_scalar_equal(actual, item) for item in expected)
        if operator in {"greater_than", "greater_than_or_equal", "less_than", "less_than_or_equal"}:
            if isinstance(actual, bool) or isinstance(expected, bool):
                return False
            if not isinstance(actual, (int, float)) or not isinstance(expected, (int, float)):
                return False
            return {
                "greater_than": actual > expected,
                "greater_than_or_equal": actual >= expected,
                "less_than": actual < expected,
                "less_than_or_equal": actual <= expected,
            }[operator]
        if operator == "matches":
            return isinstance(actual, str) and safe_regex_search(expected, actual)
        return False

    return evaluate(valid)


__all__ = [
    "CONTROL_EXPRESSION_V2_SCHEMA", "CONTROL_EXPRESSION_MAX_DEPTH",
    "CONTROL_EXPRESSION_MAX_NODES", "CONTROL_EXPRESSION_MAX_SET_ITEMS",
    "ControlExpressionValidationError", "validate_control_expression_v2",
    "evaluate_control_expression_v2",
]
