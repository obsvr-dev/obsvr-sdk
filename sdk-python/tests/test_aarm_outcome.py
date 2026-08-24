"""Twin consumer of the Obsvr-authored AARM outcome compatibility fixture."""

import json
from pathlib import Path

import pytest

from obsvr.aarm_outcome import (
    AARM_COMPATIBILITY_PROFILE_VERSION,
    AARM_OUTCOMES,
    AarmOutcomeMappingError,
    map_aarm_outcome,
)

FIXTURE = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "conformance"
        / "fixtures"
        / "aarm_outcomes.json"
    ).read_text(encoding="utf-8")
)


def _map_case(case):
    inputs = case["input"]
    return map_aarm_outcome(
        inputs["action_taken"],
        approval_required=inputs.get("approval_required", False),
        deferred=inputs.get("deferred", False),
    )


def test_profile_version_and_outcome_vocabulary_are_pinned():
    assert AARM_COMPATIBILITY_PROFILE_VERSION == FIXTURE["profile_version"]
    assert list(AARM_OUTCOMES) == FIXTURE["outcomes"]
    assert FIXTURE["claimable"] is False


@pytest.mark.parametrize(
    "case", FIXTURE["mapping_cases"], ids=lambda case: case["id"]
)
def test_mapping_case(case):
    assert _map_case(case) == case["expect"]


@pytest.mark.parametrize(
    "case", FIXTURE["rejection_cases"], ids=lambda case: case["id"]
)
def test_rejection_case(case):
    with pytest.raises(AarmOutcomeMappingError):
        _map_case(case)
