"""Chain-verification tests, driven by the shared signing vectors.

conformance/fixtures/signing_vectors.json is the contract of record for the
signing chain; the TypeScript verifier is asserted against it in
sdk-typescript/tests/unit/signing-vectors.test.ts. This suite asserts the Python
verifier accepts exactly the chain those vectors describe and rejects every
way it can be tampered with, so a Python-only compliance team gets the same
verdict a Node toolchain would give it.
"""
import json
from pathlib import Path

from obsvr.verify_chain import ChainVerificationResult, verify_chain

VECTORS_PATH = (
    Path(__file__).parent / "../../conformance/fixtures/signing_vectors.json"
).resolve()


def _load_vectors():
    with open(VECTORS_PATH) as f:
        return json.load(f)


def _chain(source=None):
    """The shared vectors as an exported event chain.

    ``source="legacy_v1"`` selects the frozen pre-format-2 vectors and
    ``"legacy_v2"`` the frozen format-2 ones. Legacy-v1 events carry no
    ``chain_format`` field, and that absence is part of what those cases
    exercise, so nothing is added that the vector does not already have.

    EVERY key on the vector event is copied. This used to enumerate a fixed
    list, which silently dropped the format-3 decision fields and made every
    signature irreproducible - a copier that decides what a chain contains is
    exactly the thing a verifier test must not have.
    """
    v = _load_vectors()
    if source == "legacy_v1":
        base = v["legacy_v1_events"]["events"]
    elif source == "legacy_v2":
        base = v["legacy_v2_events"]["events"]
    else:
        base = v["events"]
    events = []
    for ev in base:
        event = {"sdk_session_id": v["session_id"]}
        event.update(ev)
        events.append(event)
    return v["api_key"], events


def _signed_chain(n):
    """A chain of n events produced by the real signer, for cases the two
    shared vectors are too short to express (a deletion needs a middle)."""
    from obsvr import sender

    sender._reset_sender()
    api_key = "test-api-key"
    events = []
    for i in range(n):
        event = {"prompt": f"prompt-{i}", "response": f"response-{i}"}
        sender.sign_event(event, api_key)
        events.append(event)
    return api_key, events


class TestValidChains:
    def test_shared_vectors_verify(self):
        api_key, events = _chain()
        result = verify_chain(events, api_key)
        assert result.valid is True
        assert result.events_verified == len(events)
        assert result.broken_at is None
        assert result.reason is None

    def test_empty_chain_is_vacuously_valid(self):
        assert verify_chain([], "test-api-key") == ChainVerificationResult(
            valid=True, events_verified=0
        )

    def test_single_event_chain_verifies(self):
        api_key, events = _chain()
        result = verify_chain(events[:1], api_key)
        assert result.valid is True
        assert result.events_verified == 1

    def test_result_serializes_with_cross_language_field_names(self):
        api_key, events = _chain()
        assert verify_chain(events, api_key).to_dict() == {
            "valid": True,
            "eventsVerified": len(events),
            # Always present, even at zero: a consumer that never sees these
            # keys cannot tell "this chain declares no loss" from "this
            # verifier is too old to report loss".
            "gapMarkers": 0,
            "eventsDeclaredLost": 0,
            # Same reasoning: an empty list states "no breaks", where an
            # absent key would only state "no reporting".
            "breaks": [],
            "chainFormat": 3,
        }

    def test_legacy_chain_verifies_and_reports_format_1(self):
        api_key, events = _chain("legacy_v1")
        result = verify_chain(events, api_key)
        assert result.valid is True
        assert result.chain_format == 1


class TestTamperDetection:
    def test_edited_prompt_breaks_the_signature(self):
        api_key, events = _chain()
        events[1]["prompt"] = events[1]["prompt"] + " (edited)"
        result = verify_chain(events, api_key)
        assert result.valid is False
        assert result.broken_at == 1
        assert result.reason == "Signature mismatch at event 1"
        # Everything before the break did verify, and the result says so.
        assert result.events_verified == 1

    def test_edited_response_breaks_the_signature(self):
        api_key, events = _chain()
        events[0]["response"] = "tampered"
        result = verify_chain(events, api_key)
        assert result.valid is False
        assert result.broken_at == 0

    def test_forged_signature_is_rejected(self):
        api_key, events = _chain()
        events[0]["sdk_sig"] = "0" * 64
        result = verify_chain(events, api_key)
        assert result.valid is False
        assert result.broken_at == 0
        assert result.reason == "Signature mismatch at event 0"

    def test_wrong_api_key_rejects_a_genuine_chain(self):
        _, events = _chain()
        result = verify_chain(events, "not-the-signing-key")
        assert result.valid is False
        assert result.broken_at == 0

    def test_deleted_event_inside_the_chain_is_detected(self):
        api_key, events = _signed_chain(3)
        without_middle = [events[0], events[2]]
        result = verify_chain(without_middle, api_key)
        assert result.valid is False
        assert result.broken_at == 1
        assert "seq_no gap at event 1" in (result.reason or "")

    def test_truncating_the_front_of_a_chain_is_NOT_detectable(self):
        """Documented limit, identical in both languages.

        Chain verification proves the events it is given are genuine, in
        order, and unmodified. It cannot prove they are ALL the events: a
        suffix starting at seq_no 2 with a matching prev_sig is internally
        consistent, and nothing inside the export says the session began at
        1. Detecting a dropped prefix needs the session's known start, which
        is what the server-side sequence guard and the sealed ledger are
        for. Asserted here so nobody mistakes silence for coverage.
        """
        api_key, events = _chain()
        assert verify_chain(events[1:], api_key).valid is True

    def test_broken_prev_sig_link_is_detected(self):
        api_key, events = _chain()
        events[1]["prev_sig"] = "f" * 64
        result = verify_chain(events, api_key)
        assert result.valid is False
        assert result.broken_at == 1
        assert "Chain break at event 1" in (result.reason or "")

    def test_seq_gap_is_detected(self):
        api_key, events = _chain()
        events[1]["seq_no"] = 5
        result = verify_chain(events, api_key)
        assert result.valid is False
        assert result.broken_at == 1
        assert result.reason == "seq_no gap at event 1: expected 2, got 5"

    def test_missing_seq_no_is_detected(self):
        api_key, events = _chain()
        del events[1]["seq_no"]
        result = verify_chain(events, api_key)
        assert result.valid is False
        assert result.reason == "Missing seq_no at event 1"

    def test_invalid_initial_seq_no_is_detected(self):
        api_key, events = _chain()
        events[0]["seq_no"] = 0
        result = verify_chain(events, api_key)
        assert result.valid is False
        assert result.broken_at == 0
        assert result.reason == "Invalid initial seq_no: 0"

    def test_session_mismatch_is_detected(self):
        api_key, events = _chain()
        events[1]["sdk_session_id"] = "22222222-2222-2222-2222-222222222222"
        result = verify_chain(events, api_key)
        assert result.valid is False
        assert result.broken_at == 1
        assert "Session ID mismatch at event 1" in (result.reason or "")

    def test_missing_session_id_on_first_event_is_detected(self):
        api_key, events = _chain()
        del events[0]["sdk_session_id"]
        result = verify_chain(events, api_key)
        assert result.valid is False
        assert result.broken_at == 0
        assert result.reason == "First event missing sdk_session_id"

    def test_backdated_timestamp_is_detected(self):
        api_key, events = _chain()
        events[1]["timestamp_sdk"] = events[0]["timestamp_sdk"] - 1
        result = verify_chain(events, api_key)
        assert result.valid is False
        assert result.broken_at == 1
        assert "Timestamp decreased at event 1" in (result.reason or "")

    def test_reordered_events_are_rejected(self):
        api_key, events = _chain()
        result = verify_chain(list(reversed(events)), api_key)
        assert result.valid is False


class TestEveryBreakReported:
    """One run, the full damage report: `breaks` lists every independent break,
    while `broken_at` / `reason` / `events_verified` keep their first-break
    meaning for existing readers."""

    def test_three_independent_breaks_reported_in_one_run(self):
        api_key, events = _signed_chain(7)
        events[1]["prompt"] = "tampered"          # content edit -> bad signature
        del events[3]                             # deletion -> seq gap
        events[-1]["sdk_sig"] = "0" * 64          # forged signature
        result = verify_chain(events, api_key)
        assert result.valid is False
        assert [b["reason"] for b in result.breaks] == [
            "Signature mismatch at event 1",
            "seq_no gap at event 3: expected 4, got 5",
            "Signature mismatch at event 5",
        ]
        assert [b["index"] for b in result.breaks] == [1, 3, 5]

    def test_first_break_still_names_broken_at_and_reason(self):
        api_key, events = _signed_chain(7)
        events[1]["prompt"] = "tampered"
        del events[3]
        result = verify_chain(events, api_key)
        assert result.broken_at == result.breaks[0]["index"] == 1
        assert result.reason == result.breaks[0]["reason"]
        # Backward-compatible meaning: events verified before the FIRST break.
        assert result.events_verified == 1

    def test_single_break_yields_a_single_entry_list(self):
        api_key, events = _chain()
        events[1]["prompt"] = events[1]["prompt"] + " (edited)"
        result = verify_chain(events, api_key)
        assert result.breaks == [{"index": 1, "reason": "Signature mismatch at event 1"}]

    def test_forged_sdk_sig_severs_the_link_to_its_successor(self):
        """An edited sdk_sig is two facts, and both are reported: the event's
        own signature no longer verifies, and its successor's prev_sig was
        minted against the value that is no longer there. Re-anchoring on the
        stored sdk_sig is what keeps the report at those two facts instead of
        failing every event downstream."""
        api_key, events = _signed_chain(4)
        events[1]["sdk_sig"] = "0" * 64
        result = verify_chain(events, api_key)
        assert [b["reason"] for b in result.breaks] == [
            "Signature mismatch at event 1",
            "Chain break at event 2: prev_sig does not match prior event's sdk_sig",
        ]

    def test_foreign_session_event_does_not_derail_the_chain(self):
        """A foreign-session event is reported and skipped: the events around
        it still link to each other, so the one insertion is the one break."""
        api_key, events = _signed_chain(3)
        foreign = dict(events[1], sdk_session_id="99999999-9999-9999-9999-999999999999")
        result = verify_chain([events[0], foreign, events[1], events[2]], api_key)
        assert result.valid is False
        assert len(result.breaks) == 1
        assert "Session ID mismatch at event 1" in result.breaks[0]["reason"]

    def test_gap_tally_still_covers_only_the_prefix_before_the_first_break(self):
        """Scanning past a break must not change the loss tally a caller acts
        on: markers are counted only while nothing has broken yet, exactly the
        prefix rule that held when scanning stopped at the first break."""
        from obsvr import sender
        from obsvr.audit_gap import AUDIT_GAP_OPERATION

        sender._reset_sender()
        api_key = "test-api-key"
        events = [
            {"prompt": "prompt-0", "response": "r0"},
            {"prompt": "prompt-1", "response": "r1"},
            {"prompt": "obsvr:audit-gap/1 dropped=7 reason=queue_overflow", "response": ""},
        ]
        for event in events:
            sender.sign_event(event, api_key)
        # `operation` is outside the signature preimage, so stamping it after
        # signing leaves a marker whose own signature verifies.
        events[2]["operation"] = AUDIT_GAP_OPERATION
        assert verify_chain(events, api_key).events_declared_lost == 7

        events[0]["prompt"] = "tampered"
        result = verify_chain(events, api_key)
        assert result.valid is False
        # The marker's own signature still verified, but it sits past the
        # first break, so it is outside the tally - as it always was.
        assert result.gap_markers == 0
        assert result.events_declared_lost == 0


def _apply(mutations, events, api_key):
    """Apply a fixture case's mutations. Twin of the TypeScript applier in
    sdk-typescript/tests/unit/verify-chain-conformance.test.ts - both must interpret the
    same op vocabulary identically or the shared cases mean two things."""
    for m in mutations:
        op = m["op"]
        if op == "set":
            events[m["index"]][m["field"]] = m["value"]
        elif op == "delete":
            events[m["index"]].pop(m["field"], None)
        elif op == "drop_event":
            events.pop(m["index"])
        elif op == "reverse":
            events.reverse()
        elif op == "api_key":
            api_key = m["value"]
        else:
            raise AssertionError(f"unknown mutation op in fixture: {op}")
    return events, api_key


class TestChainVerificationConformance:
    """Cross-language verdicts, driven by the shared fixture.

    Every case in signing_vectors.json's `chain_verification.cases` must
    produce the same verdict here as in the TypeScript suite
    (sdk-typescript/tests/unit/verify-chain-conformance.test.ts). The cases live in the
    fixture rather than in either test file precisely so neither language can
    quietly drift its own expectations.
    """

    def test_every_fixture_case_produces_the_pinned_verdict(self):
        v = _load_vectors()
        cases = v["chain_verification"]["cases"]
        assert len(cases) > 0

        for case in cases:
            api_key, events = _chain(case.get("events"))
            events, api_key = _apply(case["mutations"], events, api_key)
            result = verify_chain(events, api_key)
            expect = case["expect"]

            assert result.valid is expect["valid"], f"{case['id']}: valid"
            assert result.events_verified == expect["events_verified"], (
                f"{case['id']}: events_verified"
            )
            assert result.broken_at == expect.get("broken_at"), f"{case['id']}: broken_at"
            assert result.reason == expect.get("reason"), f"{case['id']}: reason"
            assert result.chain_format == expect.get("chain_format"), (
                f"{case['id']}: chain_format"
            )
