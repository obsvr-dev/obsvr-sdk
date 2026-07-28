"""Built-in PII/secret/injection scanner — Python side of the cross-SDK
conformance harness. Twin: sdk-typescript/tests/unit/pii-scan-conformance.test.ts. Every
case in conformance/fixtures/pii_scan.json must produce the pinned
detected_types (unique labels in span order after overlap suppression, Luhn
validation applied) and redacted output byte-for-byte. A divergence is a
release blocker."""

import json
from pathlib import Path

import pytest

from obsvr.policy import redact_builtin_pii, run_builtin_pii_scan

FIXTURE = json.loads(
    (Path(__file__).parent / "../../conformance/fixtures/pii_scan.json")
    .resolve()
    .read_text()
)


@pytest.mark.parametrize("case", FIXTURE["cases"], ids=[c["id"] for c in FIXTURE["cases"]])
def test_detected_types_pinned(case):
    scan = run_builtin_pii_scan(case["input"])
    assert scan["detected_types"] == case["detected_types"]
    assert scan["pii_detected"] is (len(case["detected_types"]) > 0)


_QUOTED_CASES = [c for c in FIXTURE["cases"] if "quoted" in c]


@pytest.mark.parametrize("case", _QUOTED_CASES, ids=[c["id"] for c in _QUOTED_CASES])
def test_quoted_flags_pinned(case):
    scan = run_builtin_pii_scan(case["input"])
    assert [m["quoted"] for m in scan["matches"]] == case["quoted"]
    # A quoted match is a DOWNGRADE, never a suppression: the detection still
    # has to be reported.
    if any(case["quoted"]):
        assert scan["pii_detected"] is True
        assert scan["detected_types"] == case["detected_types"]


@pytest.mark.parametrize("case", FIXTURE["cases"], ids=[c["id"] for c in FIXTURE["cases"]])
def test_redaction_pinned(case):
    assert redact_builtin_pii(case["input"]) == case["redacted"]


def test_scan_never_mutates_input():
    for case in FIXTURE["cases"]:
        source = str(case["input"])
        run_builtin_pii_scan(source)
        assert source == case["input"]
