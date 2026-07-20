"""Cross-SDK conformance harness (Python side). Twin:
sdk/tests/unit/conformance.test.ts. Runs every case in
conformance/fixtures/eval_semantics.json through validator + evaluator +
shadow evaluator. A divergence from the fixture (or from the TS harness)
is a release blocker unless recorded in conformance/known-divergences.md."""

import json
from pathlib import Path

import pytest

from obsvr.remote import _valid_rule
from obsvr.rules import PolicyRule, evaluate_policy_rules, evaluate_shadow_rules

FIXTURE = json.loads(
    (Path(__file__).parent / "../../conformance/fixtures/eval_semantics.json")
    .resolve()
    .read_text()
)


def _to_rule(r):
    return PolicyRule(
        id=r["id"], name=r["name"], enabled=r["enabled"],
        action=r["action"], type=r["type"],
        conditions=r.get("conditions", {}),
        applies_to=r.get("applies_to"),
        mode=r.get("mode"),
    )


@pytest.mark.parametrize("case", FIXTURE["cases"], ids=[c["id"] for c in FIXTURE["cases"]])
def test_conformance_case(case):
    # 1. Validator pass (EV-12): malformed rules are dropped.
    valid_raw = [r for r in case["rules"] if _valid_rule(r)]
    if "expect_valid_rule_ids" in case:
        assert [r["id"] for r in valid_raw] == case["expect_valid_rule_ids"]
    rules = [_to_rule(r) for r in valid_raw]

    # 2. Active evaluation.
    target = case["input"].get("target", "prompt")
    result = evaluate_policy_rules(
        rules, case["input"]["text"], target, case["input"].get("context")
    )
    assert result["decision"] == case["expect"]["decision"]
    expected_rule = case["expect"].get("rule_id", "__unchecked__")
    if expected_rule is None:
        assert result.get("rule_id") is None
    elif expected_rule != "__unchecked__":
        assert result.get("rule_id") == expected_rule
    if "approval_required" in case["expect"]:
        assert result.get("approval_required") is case["expect"]["approval_required"]

    # 3. Shadow evaluation (EV-20/21).
    shadow = evaluate_shadow_rules(
        rules, case["input"]["text"], target, case["input"].get("context")
    )
    if "expect_shadow" not in case or case["expect_shadow"] is None:
        assert shadow is None
    else:
        assert shadow is not None
        assert shadow["rule_id"] == case["expect_shadow"]["rule_id"]
        assert shadow["would"] == case["expect_shadow"]["would"]
