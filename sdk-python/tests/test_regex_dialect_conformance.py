"""A-3 -- cross-SDK regex dialect. Twin:
sdk-typescript/tests/unit/regex-dialect-conformance.test.ts.

A ``regex`` rule is authored once and run by two engines. Before this fixture
the corpus held exactly ONE regex case -- ``(a+)+$``, a pattern both validators
reject -- so it asserted only that a rejected pattern never matches. Thirty
diverging verdicts across seventeen construct families survived it.

Both validators must agree on ok/not-ok for every pattern here. The REASON is
deliberately not pinned: each engine's own parser legitimately catches some of
these first and reports its own wording.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from obsvr.safe_regex import validate_regex_pattern  # noqa: E402

FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "conformance/fixtures/regex_dialect.json"
)
with open(FIXTURE_PATH, encoding="utf-8") as fh:
    FIXTURE = json.load(fh)

CASES = FIXTURE["cases"]


def test_the_fixture_carries_both_verdicts():
    """The single pre-existing regex case in the whole corpus was a REJECT.
    Without portable controls here, "every pattern is rejected" would pass."""
    assert any(c["portable"] for c in CASES)
    assert any(not c["portable"] for c in CASES)


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_validator_verdict_matches_the_fixture(case):
    ok, _reason = validate_regex_pattern(case["pattern"])
    assert ok is case["portable"], f"{case['id']} ({case['family']}): {case['note']}"
