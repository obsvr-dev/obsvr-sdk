"""Twin consumer of the Obsvr-authored canonical action-context fixture."""

import copy
import hashlib
import json
from pathlib import Path

import pytest

from obsvr.action_context import (
    ACTION_CONTEXT_SCHEMA,
    ActionContextValidationError,
    action_context_hash,
    build_action_context,
    canonicalize_action_context,
)

FIXTURE = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "conformance"
        / "fixtures"
        / "action_context.json"
    ).read_text(encoding="utf-8")
)


def _mutated(case):
    input_value = copy.deepcopy(FIXTURE["invalid_base"])
    cursor = input_value
    for segment in case["mutation"]["path"][:-1]:
        cursor = cursor[segment]
    last = case["mutation"]["path"][-1]
    if case["mutation"].get("delete") is True:
        del cursor[last]
    else:
        cursor[last] = case["mutation"]["value"]
    return input_value


def test_local_schema_is_not_presented_as_official_vectors():
    assert ACTION_CONTEXT_SCHEMA == "obsvr-action-context-v1"
    assert FIXTURE["claimable"] is False
    assert "not an official AARM conformance vector" in FIXTURE["description"]


@pytest.mark.parametrize(
    "case", FIXTURE["valid_cases"], ids=lambda case: case["id"]
)
def test_valid_context(case):
    document = build_action_context(case["input"])
    canonical = canonicalize_action_context(case["input"])
    assert document == case["expect"]["document"]
    assert canonical.encode("utf-8") == case["expect"]["canonical"].encode("utf-8")
    assert action_context_hash(case["input"]) == case["expect"]["hash"]
    assert (
        hashlib.sha256(case["expect"]["canonical"].encode("utf-8")).hexdigest()
        == case["expect"]["hash"]
    )
    assert '"arguments"' not in canonical
    assert "sensitive_content" not in canonical


@pytest.mark.parametrize(
    "case", FIXTURE["invalid_cases"], ids=lambda case: case["id"]
)
def test_invalid_context(case):
    with pytest.raises(ActionContextValidationError):
        build_action_context(_mutated(case))
