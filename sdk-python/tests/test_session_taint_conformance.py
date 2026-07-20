"""Cross-SDK session-taint conformance harness (Python side). Twin:
sdk/tests/unit/session-taint-conformance.test.ts. Pins the deterministic key
derivation + enforcement decision, plus the store invariants (monotonic
reason, bounded eviction)."""

import json
from pathlib import Path

import pytest

from obsvr.session_taint import (
    MAX_TAINTED_SESSIONS,
    _reset_session_taint,
    derive_session_key,
    evaluate_session_taint,
    mark_tainted,
    session_taint_size,
    taint_reason,
    touch_taint,
)

FIXTURE = json.loads(
    (Path(__file__).parent / "../../conformance/fixtures/session_taint.json")
    .resolve()
    .read_text()
)


@pytest.mark.parametrize(
    "case", FIXTURE["key_cases"], ids=[c["id"] for c in FIXTURE["key_cases"]]
)
def test_session_key_derivation(case):
    assert derive_session_key(case["metadata"]) == case["expect"]


@pytest.mark.parametrize(
    "case", FIXTURE["decision_cases"], ids=[c["id"] for c in FIXTURE["decision_cases"]]
)
def test_taint_enforcement_decision(case):
    _reset_session_taint()
    if case["tainted"]:
        mark_tainted("k", "prompt_injection", 1.0)
    assert (
        evaluate_session_taint("k", case["config"])["enforcement"]
        == case["expect"]["enforcement"]
    )
    _reset_session_taint()


class TestStoreInvariants:
    def setup_method(self):
        _reset_session_taint()

    def teardown_method(self):
        _reset_session_taint()

    def test_latch_is_monotonic(self):
        mark_tainted("s", "prompt_injection", 1)
        mark_tainted("s", "canary_leak", 2)  # later signal must not overwrite
        assert taint_reason("s") == "prompt_injection"

    def test_untainted_session_has_no_reason(self):
        assert taint_reason("never") is None
        assert session_taint_size() == 0

    def test_bounded_eviction(self):
        for i in range(MAX_TAINTED_SESSIONS):
            mark_tainted("s%d" % i, "prompt_injection", i)
        assert session_taint_size() == MAX_TAINTED_SESSIONS
        mark_tainted("newest", "canary_leak", MAX_TAINTED_SESSIONS + 1)
        assert session_taint_size() == MAX_TAINTED_SESSIONS
        assert taint_reason("newest") == "canary_leak"
        assert taint_reason("s0") is None

    def test_touch_keeps_enforced_victim_from_eviction(self):
        # A victim tainted early (oldest) survives an attacker flooding the
        # store IF it is still being enforced (touch refreshes recency).
        mark_tainted("victim", "prompt_injection", 0.0)
        touch_taint("victim", 1_000_000.0)  # enforce keeps it fresh
        for i in range(MAX_TAINTED_SESSIONS - 1):
            mark_tainted("flood%d" % i, "prompt_injection", 100.0 + i)
        # One more insert past the cap evicts the OLDEST — now a flood entry,
        # not the recently-touched victim.
        mark_tainted("attacker", "prompt_injection", 200_000.0)
        assert taint_reason("victim") == "prompt_injection"  # survived
