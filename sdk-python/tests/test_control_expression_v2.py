import json
from pathlib import Path

import pytest

from obsvr.control_expression_v2 import (
    ControlExpressionValidationError,
    evaluate_control_expression_v2,
    validate_control_expression_v2,
)
from obsvr.rules import PolicyRule, evaluate_policy_rules


EXPRESSION = {
    "all": [
        {"predicate": {"path": "context.environment", "operator": "equals", "value": "production"}},
        {"any": [
            {"predicate": {"path": "context.metadata.role", "operator": "not_equals", "value": "admin"}},
            {"predicate": {"path": "context.amount", "operator": "greater_than", "value": 1000}},
        ]},
    ]
}


def test_shared_cross_language_fixture():
    fixture = json.loads(
        (Path(__file__).parent / "../../conformance/fixtures/control_expression_v2.json")
        .resolve()
        .read_text("utf-8")
    )
    for case in fixture["cases"]:
        assert evaluate_control_expression_v2(case["expression"], case["input"]) is case["matches"]


def test_nested_expression_is_deterministic():
    assert evaluate_control_expression_v2(EXPRESSION, {
        "input": {"text": "wire funds", "target": "prompt"},
        "context": {"environment": "production", "amount": 10, "metadata": {"role": "member"}},
    }) is True
    assert evaluate_control_expression_v2(EXPRESSION, {
        "input": {"text": "wire funds", "target": "prompt"},
        "context": {"environment": "staging", "amount": 5000, "metadata": {"role": "member"}},
    }) is False


def test_ambiguous_and_unsafe_documents_are_refused():
    with pytest.raises(ControlExpressionValidationError):
        validate_control_expression_v2({"all": [], "any": []})
    with pytest.raises(ControlExpressionValidationError, match="ReDoS"):
        validate_control_expression_v2({"predicate": {
            "path": "context.metadata.value", "operator": "matches", "value": "(a+)+$",
        }})
    with pytest.raises(ControlExpressionValidationError, match="bounded input/context path"):
        validate_control_expression_v2({"predicate": {
            "path": "context.métadata", "operator": "equals", "value": "x",
        }})
    with pytest.raises(ControlExpressionValidationError, match="must be a number"):
        validate_control_expression_v2({"predicate": {
            "path": "context.amount", "operator": "greater_than", "value": "100",
        }})
    with pytest.raises(ControlExpressionValidationError, match="must be a string"):
        validate_control_expression_v2({"predicate": {
            "path": "context.label", "operator": "contains", "value": 100,
        }})


def test_steer_is_a_real_refusal_with_corrective_context():
    rule = PolicyRule(
        id="control:external-write",
        name="External writes need an owner",
        enabled=True,
        type="control",
        action="steer",
        conditions={
            "expression": {"predicate": {
                "path": "context.metadata.owner", "operator": "not_equals", "value": "legal",
            }},
            "steering_context": 'Route the draft to Legal and retry with metadata.owner="legal".',
        },
    )
    result = evaluate_policy_rules([rule], "send contract", "prompt", {"metadata": {"owner": "sales"}})
    assert result["decision"] == "block"
    assert result["steering"] == {
        "outcome": "MODIFY",
        "guidance": 'Route the draft to Legal and retry with metadata.owner="legal".',
    }
