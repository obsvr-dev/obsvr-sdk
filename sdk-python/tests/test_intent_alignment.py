"""Twin consumer of the Obsvr-authored intent-alignment fixture."""

import copy
import hashlib
import json
from pathlib import Path

import pytest

from obsvr.action_context import build_action_context
from obsvr.intent_alignment import (
    IntentAlignmentValidationError,
    build_intent_policy,
    canonicalize_intent_policy,
    evaluate_intent_alignment,
    intent_policy_hash,
)

FIXTURE = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "conformance"
        / "fixtures"
        / "intent_alignment.json"
    ).read_text(encoding="utf-8")
)


def _mutate(root, mutation):
    cursor = root
    for segment in mutation["path"][:-1]:
        cursor = cursor[segment]
    last = mutation["path"][-1]
    if mutation.get("delete") is True:
        del cursor[last]
    else:
        cursor[last] = mutation["value"]


def _materialize(case):
    roots = {
        "context": copy.deepcopy(FIXTURE["base_context"]),
        "policy": copy.deepcopy(FIXTURE["base_policy"]),
        "base_result": copy.deepcopy(FIXTURE["base_result"]),
    }
    for mutation in case["mutations"]:
        _mutate(roots[mutation["target"]], mutation)
    context = roots["context"]
    if case.get("context_form") == "document":
        context = build_action_context(context)
    return {
        "context": context,
        "policy": roots["policy"],
        "base_result": roots["base_result"],
    }


def test_local_normalized_policy_is_not_presented_as_official_vectors():
    assert FIXTURE["claimable"] is False
    assert "not an official AARM conformance vector" in FIXTURE["description"]
    canonical = canonicalize_intent_policy(FIXTURE["base_policy"])
    assert canonical.encode("utf-8") == FIXTURE["policy_expect"]["canonical"].encode(
        "utf-8"
    )
    assert build_intent_policy(FIXTURE["base_policy"]) == json.loads(
        FIXTURE["policy_expect"]["canonical"]
    )
    assert intent_policy_hash(FIXTURE["base_policy"]) == FIXTURE["policy_expect"]["hash"]
    assert hashlib.sha256(canonical.encode("utf-8")).hexdigest() == FIXTURE[
        "policy_expect"
    ]["hash"]


@pytest.mark.parametrize(
    "case", FIXTURE["valid_cases"], ids=lambda case: case["id"]
)
def test_evaluation(case):
    expected = {**FIXTURE["expected_defaults"], **case["expect"]}
    assert evaluate_intent_alignment(**_materialize(case)) == expected


def test_all_five_outcomes_are_covered():
    assert {case["expect"]["outcome"] for case in FIXTURE["valid_cases"]} == {
        "ALLOW",
        "DENY",
        "MODIFY",
        "STEP_UP",
        "DEFER",
    }


def test_approval_details_are_bound_into_evaluation_input_hash():
    cases = {case["id"]: case for case in FIXTURE["valid_cases"]}
    first = cases["approval_required"]["expect"]["input_hash"]
    second = cases["approval_binding_changes_input_hash"]["expect"]["input_hash"]
    assert first != second


@pytest.mark.parametrize(
    "case", FIXTURE["invalid_policy_cases"], ids=lambda case: case["id"]
)
def test_invalid_policy(case):
    policy = copy.deepcopy(FIXTURE["base_policy"])
    _mutate(policy, case["mutation"])
    with pytest.raises(IntentAlignmentValidationError):
        build_intent_policy(policy)


@pytest.mark.parametrize(
    "case", FIXTURE["invalid_base_cases"], ids=lambda case: case["id"]
)
def test_invalid_base_result(case):
    base = copy.deepcopy(FIXTURE["base_result"])
    if case.get("mutation"):
        _mutate(base, case["mutation"])
    if case.get("second_mutation"):
        _mutate(base, case["second_mutation"])
    for mutation in case.get("mutations", []):
        _mutate(base, mutation)
    with pytest.raises(IntentAlignmentValidationError):
        evaluate_intent_alignment(
            context=FIXTURE["base_context"],
            policy=FIXTURE["base_policy"],
            base_result=base,
        )
