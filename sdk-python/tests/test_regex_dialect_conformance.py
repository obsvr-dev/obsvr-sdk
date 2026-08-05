r"""A-3 -- cross-SDK regex dialect. Twin:
sdk-typescript/tests/unit/regex-dialect-conformance.test.ts.

A ``regex`` rule is authored once and run by two engines. Before this fixture
the corpus held exactly ONE regex case -- ``(a+)+$``, a pattern both validators
reject -- so it asserted only that a rejected pattern never matches. Thirty
diverging verdicts across seventeen construct families survived it.

TWO HALVES, because the split has two. ``cases`` is the SYNTAX half: both
validators must agree on ok/not-ok for every pattern. The REASON is deliberately
not pinned -- each engine's own parser legitimately catches some of these first
and reports its own wording.

``semantic_cases`` is the half that used to be open. ``\d`` ``\w`` ``\s``
``\b`` ``$`` and ``.`` read differently in ``re`` and ``RegExp`` and carry no
syntactic marker, so they could not be rejected without banning the most common
constructs in the language. They are closed by normalizing THIS side to
ECMAScript's meaning at the one compile call in ``safe_regex.py``, so these rows
are where that repair is measured: every one of them was a diverging verdict
before it landed.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from obsvr.safe_regex import (  # noqa: E402
    safe_regex_search,
    validate_regex_pattern,
)

FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "conformance/fixtures/regex_dialect.json"
)
with open(FIXTURE_PATH, encoding="utf-8") as fh:
    FIXTURE = json.load(fh)

CASES = FIXTURE["cases"]
SEMANTIC_CASES = FIXTURE["semantic_cases"]


def test_the_fixture_carries_both_verdicts():
    """The single pre-existing regex case in the whole corpus was a REJECT.
    Without portable controls here, "every pattern is rejected" would pass."""
    assert any(c["portable"] for c in CASES)
    assert any(not c["portable"] for c in CASES)


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_validator_verdict_matches_the_fixture(case):
    ok, _reason = validate_regex_pattern(case["pattern"])
    assert ok is case["portable"], f"{case['id']} ({case['family']}): {case['note']}"


def test_the_semantic_fixture_carries_both_verdicts():
    """A corpus of nothing but non-matches would agree with any broken engine."""
    assert any(c["matches"] for c in SEMANTIC_CASES)
    assert any(not c["matches"] for c in SEMANTIC_CASES)


def test_every_semantic_case_uses_a_pattern_the_validator_accepts():
    """A rejected pattern never matches, so a typo'd row would read as a passing
    "does not match" case rather than as the mistake it is."""
    rejected = [
        c["id"] for c in SEMANTIC_CASES if not validate_regex_pattern(c["pattern"])[0]
    ]

    assert rejected == []


@pytest.mark.parametrize(
    "case", SEMANTIC_CASES, ids=[c["id"] for c in SEMANTIC_CASES]
)
def test_match_verdict_matches_the_fixture(case):
    verdict = safe_regex_search(case["pattern"], case["input"])
    assert verdict is case["matches"], f"{case['id']} ({case['family']}): {case['note']}"
