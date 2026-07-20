"""Cross-SDK conformance harness (Python side) for the inbound OPA/Cedar
external policy backend (ADR-4). Twin:
sdk/tests/unit/external-backend-conformance.test.ts. Both drive every case in
conformance/fixtures/external_backend.json through the DENY-WINS merge
(merge_external_backend_decision) and the provenance computation
(backend_provenance) and must reach identical results. A divergence is a
release blocker."""

import json
from pathlib import Path

import pytest

from obsvr.external_backend import (
    backend_provenance,
    merge_external_backend_decision,
)

FIXTURE = json.loads(
    (Path(__file__).parent / "../../conformance/fixtures/external_backend.json")
    .resolve()
    .read_text()
)


@pytest.mark.parametrize(
    "case", FIXTURE["merge_cases"], ids=[c["id"] for c in FIXTURE["merge_cases"]]
)
def test_merge_case(case):
    result = merge_external_backend_decision(case["local"], case["outcome"], case["shadow"])
    assert result == case["expect"], case["id"]


@pytest.mark.parametrize(
    "case", FIXTURE["provenance_cases"], ids=[c["id"] for c in FIXTURE["provenance_cases"]]
)
def test_provenance_case(case):
    prov = backend_provenance(case["backend"])
    assert prov == case["expect"], case["id"]
