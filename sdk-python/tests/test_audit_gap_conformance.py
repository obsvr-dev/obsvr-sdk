"""Cross-language audit-gap conformance (Python side).

Twin: sdk/tests/unit/audit-gap-conformance.test.ts. The marker's canonical
statement goes through SHA-256 into the HMAC, so a single character of drift
between the two SDKs makes them sign different markers for the same loss - and
a chain would then verify in one language and not the other. The format lives
in conformance/fixtures/audit_gap.json rather than in either test file so
neither language can drift its own expectations.
"""

import json
from pathlib import Path

import pytest

from obsvr.audit_gap import (
    AUDIT_GAP_FORMAT,
    AUDIT_GAP_GOVERNANCE_EVENT,
    AUDIT_GAP_METADATA_KEY,
    AUDIT_GAP_OPERATION,
    AUDIT_GAP_REASON_QUEUE_OVERFLOW,
    format_audit_gap_prompt,
    parse_audit_gap_prompt,
)
from obsvr.verify_chain import verify_chain

FIXTURE_PATH = (
    Path(__file__).parent / "../../conformance/fixtures/audit_gap.json"
).resolve()


def _fixture():
    with open(FIXTURE_PATH) as f:
        return json.load(f)


FIXTURE = _fixture()


def _chain():
    """The fixture's chain as an exported event list."""
    signing = FIXTURE["signing"]
    return [
        {
            "sdk_session_id": signing["session_id"],
            "seq_no": ev["seq_no"],
            "timestamp_sdk": ev["timestamp_sdk"],
            "prompt": ev["prompt"],
            "response": ev["response"],
            "prev_sig": ev["prev_sig"],
            "sdk_sig": ev["sdk_sig"],
        }
        for ev in signing["events"]
    ]


def test_constants_match_the_pinned_wire_values():
    constants = FIXTURE["constants"]
    assert AUDIT_GAP_FORMAT == constants["format"]
    assert AUDIT_GAP_REASON_QUEUE_OVERFLOW == constants["reason_queue_overflow"]
    assert AUDIT_GAP_METADATA_KEY == constants["metadata_key"]
    assert AUDIT_GAP_GOVERNANCE_EVENT == constants["governance_event"]
    assert AUDIT_GAP_OPERATION == constants["operation"]


@pytest.mark.parametrize("case", FIXTURE["preimage_cases"], ids=lambda c: c["id"])
def test_produces_the_pinned_statement(case):
    assert format_audit_gap_prompt(case["dropped"], case["reason"]) == case["prompt"]


@pytest.mark.parametrize("case", FIXTURE["preimage_cases"], ids=lambda c: c["id"])
def test_round_trips_the_pinned_statement(case):
    assert parse_audit_gap_prompt(case["prompt"]) == {
        "dropped": case["dropped"],
        "reason": case["reason"],
    }


@pytest.mark.parametrize("case", FIXTURE["parse_rejects"], ids=lambda c: c["id"])
def test_refuses_to_read_a_loss_claim_from(case):
    assert parse_audit_gap_prompt(case["prompt"]) is None


def test_verifies_the_pinned_chain_and_reports_the_loss_it_declares():
    expected = FIXTURE["verification"]["cases"][0]["expect"]
    result = verify_chain(_chain(), FIXTURE["signing"]["api_key"])
    assert result.valid is expected["valid"]
    assert result.events_verified == expected["events_verified"]
    assert result.gap_markers == expected["gap_markers"]
    assert result.events_declared_lost == expected["events_declared_lost"]


@pytest.mark.parametrize(
    "case", FIXTURE["verification"]["cases"], ids=lambda c: c["id"]
)
def test_reaches_the_pinned_verdict(case):
    events = _chain()
    for mutation in case["mutations"]:
        assert mutation["op"] == "set"
        events[mutation["index"]][mutation["field"]] = mutation["value"]

    result = verify_chain(events, FIXTURE["signing"]["api_key"])
    expected = case["expect"]
    assert result.valid is expected["valid"]
    assert result.events_verified == expected["events_verified"]
    assert result.gap_markers == expected["gap_markers"]
    assert result.events_declared_lost == expected["events_declared_lost"]
    if "broken_at" in expected:
        assert result.broken_at == expected["broken_at"]
    if "reason" in expected:
        assert result.reason == expected["reason"]
