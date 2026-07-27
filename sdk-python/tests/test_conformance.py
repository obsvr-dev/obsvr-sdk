"""Cross-SDK conformance harness (Python side). Twin:
sdk/tests/unit/conformance.test.ts. Runs every case in
conformance/fixtures/eval_semantics.json through validator + evaluator +
shadow evaluator. A divergence from the fixture (or from the TS harness)
is a release blocker unless recorded in conformance/known-divergences.md.

Three case modes:
    rules     (default) drive the rules engine directly
    pipeline  drive the full pre-call pipeline - the only way to pin
              statements about step composition and the integrity gate
    explain   drive check-only evaluation and prove it consumes nothing
"""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

import obsvr
from obsvr.config import _reset, get_config
from obsvr.policy import apply_pre_call_policy, explain
from obsvr.remote import _valid_rule
from obsvr.rules import (
    PolicyRule,
    _reset_quota,
    evaluate_policy_rules,
    evaluate_shadow_rules,
)

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


def _valid_rules(case):
    return [_to_rule(r) for r in case["rules"] if _valid_rule(r)]


def _run_rules_case(case):
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


def _run_pipeline_case(case):
    pipeline = case.get("pipeline", {})
    hook_ran = {"value": False}

    init_kwargs = {"api_key": "test", "policy_rules": _valid_rules(case)}
    if pipeline.get("pii_policy"):
        init_kwargs["pii_policy"] = pipeline["pii_policy"]
    if pipeline.get("hook"):
        def hook(_event, _decision=pipeline["hook"]):
            hook_ran["value"] = True
            return _decision

        init_kwargs["on_pre_call"] = hook

    _reset()
    obsvr.init(**init_kwargs)

    # The integrity gate is driven by sync state, not by policy input: a paused
    # project or revoked key is what the server told this client.
    degraded = (
        {"degraded": True, "reason": pipeline["degraded_reason"]}
        if pipeline.get("degraded_reason")
        else {"degraded": False, "reason": None}
    )

    with patch("obsvr.remote.is_enforcement_degraded", return_value=degraded):
        result = apply_pre_call_policy(
            case["input"]["text"],
            get_config(),
            provider="openai",
            operation="chat.completions.create",
        )

    expected = case["expect_pipeline"]
    compliance = result["compliance"]
    assert result["decision"] == expected["decision"]
    if "action_reason" in expected:
        assert compliance["action_reason"] == expected["action_reason"]
    if "action_source" in expected:
        assert compliance["action_source"] == expected["action_source"]
    if "rule_id" in expected:
        assert compliance.get("rule_id") == expected["rule_id"]
    if "hook_ran" in expected:
        assert hook_ran["value"] is expected["hook_ran"]


def _run_explain_case(case):
    rules = _valid_rules(case)
    _reset()
    _reset_quota()
    obsvr.init(api_key="test", policy_rules=rules)

    # Check-only evaluation, repeated: if it consumed anything, the budget
    # below would already be gone.
    for _ in range(case.get("explain_runs", 1)):
        explained = explain(case["input"]["text"], config=get_config())
        assert explained["decision"] == case["expect"]["decision"]
        if case["expect"].get("rule_id") is None:
            assert explained.get("rule_id") is None
        else:
            assert explained.get("rule_id") == case["expect"]["rule_id"]

    # A real evaluation consumes; the first one still fits the budget...
    first = evaluate_policy_rules(rules, case["input"]["text"], "prompt")
    assert first["decision"] == case["expect_first_real_call"]["decision"]
    if case["expect_first_real_call"].get("rule_id") is None:
        assert first.get("rule_id") is None
    else:
        assert first.get("rule_id") == case["expect_first_real_call"]["rule_id"]

    # ...and the next one does not, proving the counter moves for real calls
    # and did not move for the explains.
    second = evaluate_policy_rules(rules, case["input"]["text"], "prompt")
    assert second["decision"] == case["expect_second_real_call"]["decision"]
    if case["expect_second_real_call"].get("rule_id"):
        assert second.get("rule_id") == case["expect_second_real_call"]["rule_id"]


@pytest.mark.parametrize("case", FIXTURE["cases"], ids=[c["id"] for c in FIXTURE["cases"]])
def test_conformance_case(case):
    mode = case.get("mode", "rules")
    try:
        if mode == "rules":
            _run_rules_case(case)
        elif mode == "pipeline":
            _run_pipeline_case(case)
        elif mode == "explain":
            _run_explain_case(case)
        else:
            raise AssertionError(f"unknown case mode in fixture: {mode}")
    finally:
        if mode != "rules":
            _reset()
            _reset_quota()


# ---------------------------------------------------------------------------
# ev_coverage: the EV coverage map cannot drift from the cases
# ---------------------------------------------------------------------------
# The uncovered list is the RECORDED gap: statements exercised only
# indirectly, whose divergence would not fail CI. Recording it as data (with
# these checks, mirrored in TypeScript) means closing or opening a gap is a
# reviewable fixture edit, never a silent drift.


def test_ev_coverage_partitions_the_full_ev_list():
    cov = FIXTURE["ev_coverage"]
    partition = sorted(list(cov["covered"].keys()) + cov["uncovered"])
    assert partition == sorted(cov["all"])
    for ev in cov["uncovered"]:
        assert ev not in cov["covered"]


def test_case_ev_tokens_match_the_statements_covered_by_this_fixture():
    import re

    cov = FIXTURE["ev_coverage"]
    pinned_here = set()
    for case in FIXTURE["cases"]:
        pinned_here.update(re.findall(r"EV-\d+", case.get("ev", "")))
    covered_here = {
        ev for ev, files in cov["covered"].items() if "eval_semantics.json" in files
    }
    assert pinned_here == covered_here


def test_every_fixture_named_in_the_coverage_map_exists():
    from pathlib import Path

    fixtures_dir = (Path(__file__).parent / "../../conformance/fixtures").resolve()
    cov = FIXTURE["ev_coverage"]
    for files in cov["covered"].values():
        for f in files:
            assert (fixtures_dir / f).exists(), f
