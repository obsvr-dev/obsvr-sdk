"""Cross-SDK agent-run control conformance harness (Python side). Twin:
sdk/tests/unit/agent-controls-conformance.test.ts. Runs every case in
conformance/fixtures/agent_controls.json; a divergence from the fixture (or
from the TS harness) is a release blocker unless recorded in
conformance/known-divergences.json."""

import json
from pathlib import Path

import pytest

from obsvr.agent_policy import (
    create_delegation_tracker,
    create_loop_detector,
    has_circular_delegation,
)

FIXTURE = json.loads(
    (Path(__file__).parent / "../../conformance/fixtures/agent_controls.json")
    .resolve()
    .read_text()
)


@pytest.mark.parametrize(
    "case", FIXTURE["loop_cases"], ids=[c["id"] for c in FIXTURE["loop_cases"]]
)
def test_loop_detector(case):
    detector = create_loop_detector(case["detector"])
    results = [detector.record_iteration() for _ in range(case["iterations"])]
    assert results == case["expect"]
    # The window is far wider than this test takes, so nothing was pruned.
    assert detector.get_iteration_count() == case["iterations"]


@pytest.mark.parametrize(
    "case", FIXTURE["delegation_cases"], ids=[c["id"] for c in FIXTURE["delegation_cases"]]
)
def test_delegation_tracker(case):
    tracker = create_delegation_tracker(case["tracker"])
    results = [tracker.record_delegation(f, t) for f, t in case["delegations"]]
    assert results == case["expect"]
    # A refused delegation never joins the chain, so the surviving depth is
    # exactly the number of delegations the tracker accepted.
    assert tracker.get_depth() == sum(1 for r in case["expect"] if r is None)


@pytest.mark.parametrize(
    "case",
    FIXTURE["circular_chain_cases"],
    ids=[c["id"] for c in FIXTURE["circular_chain_cases"]],
)
def test_has_circular_delegation(case):
    assert has_circular_delegation(case["chain"]) is case["expect"]
