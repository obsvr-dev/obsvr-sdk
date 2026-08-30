"""Twin tests for v2 target-tokenized intent alignment."""

import copy
import json
from pathlib import Path

import pytest

from obsvr.action_context_v2 import build_action_context_v2
from obsvr.intent_alignment_v2 import (
    IntentAlignmentV2ValidationError,
    build_intent_policy_v2,
    canonicalize_intent_policy_v2,
    evaluate_intent_alignment_v2,
    intent_policy_v2_hash,
)

FIXTURE = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "conformance"
        / "fixtures"
        / "intent_alignment_v2.json"
    ).read_text(encoding="utf-8")
)
LAYERED = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "conformance"
        / "fixtures"
        / "action_context_layers_v2.json"
    ).read_text(encoding="utf-8")
)


def test_raw_policy_targets_normalize_to_hashes_only():
    assert FIXTURE["claimable"] is False
    document = build_intent_policy_v2(FIXTURE["base_policy"])
    assert document == FIXTURE["policy_expect"]["document"]
    assert (
        canonicalize_intent_policy_v2(FIXTURE["base_policy"])
        == FIXTURE["policy_expect"]["canonical"]
    )
    assert (
        intent_policy_v2_hash(FIXTURE["base_policy"])
        == FIXTURE["policy_expect"]["hash"]
    )
    assert "workspace/租户🚀" not in json.dumps(document, ensure_ascii=False)
    assert "allowed_targets" not in json.dumps(document)


@pytest.mark.parametrize("case", FIXTURE["cases"], ids=lambda case: case["id"])
def test_evaluation(case):
    context = copy.deepcopy(FIXTURE["base_context"])
    context["current_action"]["target"] = case["target"]
    assert (
        evaluate_intent_alignment_v2(
            context=context,
            policy=FIXTURE["base_policy"],
            base_result={"action_taken": "allowed"},
        )
        == case["expect"]
    )


def test_canonical_context_and_policy_evaluate_identically():
    raw = evaluate_intent_alignment_v2(
        context=FIXTURE["base_context"],
        policy=FIXTURE["base_policy"],
        base_result={"action_taken": "allowed"},
    )
    canonical = evaluate_intent_alignment_v2(
        context=build_action_context_v2(FIXTURE["base_context"]),
        policy=build_intent_policy_v2(FIXTURE["base_policy"]),
        base_result={"action_taken": "allowed"},
    )
    assert canonical == raw


def test_optional_layers_survive_canonical_context_revalidation():
    raw = evaluate_intent_alignment_v2(
        context=LAYERED["input"],
        policy=FIXTURE["base_policy"],
        base_result={"action_taken": "allowed"},
    )
    canonical = evaluate_intent_alignment_v2(
        context=build_action_context_v2(LAYERED["input"]),
        policy=FIXTURE["base_policy"],
        base_result={"action_taken": "allowed"},
    )
    assert canonical == raw


def test_policy_caps_and_surrogates():
    set_overflow = copy.deepcopy(FIXTURE["base_policy"])
    set_overflow["intent_scopes"][0]["allowed_targets"] = [
        f"target-{index}" for index in range(65)
    ]
    with pytest.raises(IntentAlignmentV2ValidationError):
        build_intent_policy_v2(set_overflow)
    identifier = copy.deepcopy(FIXTURE["base_policy"])
    identifier["intent_scopes"][0]["intent_id"] = "x" * 257
    with pytest.raises(IntentAlignmentV2ValidationError):
        build_intent_policy_v2(identifier)
    surrogate = copy.deepcopy(FIXTURE["base_policy"])
    surrogate["intent_scopes"][0]["allowed_targets"] = ["\ud800"]
    with pytest.raises(IntentAlignmentV2ValidationError):
        build_intent_policy_v2(surrogate)
