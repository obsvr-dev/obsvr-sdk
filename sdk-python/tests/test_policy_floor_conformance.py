"""Cross-SDK anti-tamper policy-floor conformance harness (Python side). Twin:
sdk/tests/unit/policy-floor-conformance.test.ts. Pins the floor evaluation
(downgraded floor rule still enforces; empty floor allows) and the floor
version hash (downgrade hashes identically to enforced)."""

import json
from pathlib import Path

import pytest

from obsvr.rules import PolicyRule, derive_floor_version, evaluate_floor

FIXTURE = json.loads(
    (Path(__file__).parent / "../../conformance/fixtures/policy_floor.json")
    .resolve()
    .read_text()
)


def _floor(rules):
    return [PolicyRule(**r) for r in rules] if rules else None


@pytest.mark.parametrize(
    "case", FIXTURE["decision_cases"], ids=[c["id"] for c in FIXTURE["decision_cases"]]
)
def test_floor_evaluation(case):
    assert (
        evaluate_floor(_floor(case["floor"]), case["input"], "prompt")["decision"]
        == case["expect"]["decision"]
    )


@pytest.mark.parametrize(
    "case", FIXTURE["version_cases"], ids=[c["id"] for c in FIXTURE["version_cases"]]
)
def test_floor_version(case):
    assert derive_floor_version(_floor(case["floor"])) == case["expect"]["floor_version"]
