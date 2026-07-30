"""Cross-language audit-gap conformance (Python side).

Twin: sdk-typescript/tests/unit/audit-gap-conformance.test.ts. The marker's canonical
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
    """The fixture's chain as an exported event list.

    EVERY key on the fixture event is copied. This used to enumerate a fixed
    list, which dropped the marker's ``operation`` and so hid the very field the
    verifier discriminates on - a copier that decides what a chain contains is
    exactly what a verifier test must not have.
    """
    signing = FIXTURE["signing"]
    return [
        {"sdk_session_id": signing["session_id"], **ev} for ev in signing["events"]
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


# ── A gap marker is an event the SDK emitted as one, not any event that
#    contains the string ────────────────────────────────────────────────────


def test_a_user_prompt_cannot_forge_a_loss_declaration():
    """The defect: the verifier parsed the prompt of EVERY event.

    A user who types the marker string produces a legitimately-signed event, so
    the signature check passes and the loss claim was counted - a fabricated
    declaration of 999,999 lost events on a chain that reports valid.

    REACHABILITY is not hypothetical: ``wrap()`` is immune by accident (its
    extractor stores ``"user: <content>"`` and the pattern is anchored), but the
    LangChain integration stores the bare prompt string.
    """
    from obsvr import sender
    from obsvr.audit_gap import format_audit_gap_prompt, read_audit_gap_claim

    sender._reset_sender()
    api_key = "test-api-key"
    forged = {
        # Exactly what a user would have to type, and nothing else.
        "prompt": format_audit_gap_prompt(999999),
        "response": "",
        "operation": "chat.completions.create",
    }
    sender.sign_event(forged, api_key)

    result = verify_chain([forged], api_key)
    # The chain is genuinely valid - the user did sign this content.
    assert result.valid is True
    # But it declares nothing.
    assert result.gap_markers == 0
    assert result.events_declared_lost == 0
    assert read_audit_gap_claim(forged) is None

    # CONTROL: the same content, on an event the SDK marks as a marker, IS
    # counted. Without this the fix could be "never count anything".
    sender._reset_sender()
    genuine = dict(forged, operation="audit.gap")
    sender.sign_event(genuine, api_key)
    genuine_result = verify_chain([genuine], api_key)
    assert genuine_result.valid is True
    assert genuine_result.gap_markers == 1
    assert genuine_result.events_declared_lost == 999999


def test_the_forged_prompt_still_parses_as_content():
    """The parser is not what changed, and that distinction matters.

    ``parse_audit_gap_prompt`` still reads the claim out of any matching string -
    it is a content function and the preimage fixtures depend on it. What moved
    is that the verification path no longer treats a matching string as proof
    the event is a marker.
    """
    from obsvr.audit_gap import format_audit_gap_prompt, parse_audit_gap_prompt

    assert parse_audit_gap_prompt(format_audit_gap_prompt(999999)) == {
        "dropped": 999999,
        "reason": "queue_overflow",
    }
