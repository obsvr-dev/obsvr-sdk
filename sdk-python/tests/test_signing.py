"""Cross-language signing parity tests.

Asserts the Python signer produces byte-identical signatures to the shared
vectors in conformance/fixtures/signing_vectors.json (twin:
sdk-typescript/tests/unit/signing-vectors.test.ts). If either language's signing logic
drifts, these vectors fail in that language's suite.

The vectors pin THREE things: the signing-key derivation, the format-2
content-hash preimage (including the boundary cases format 1 collided on -
that collision is itself pinned under ``legacy_digest``, so the defect the
format change closed stays demonstrable), and the chained signatures under
both formats. Format 1 vectors are frozen forever: chains signed before the
change are existing evidence.
"""
import hashlib
import hmac as hmac_mod
import json
from pathlib import Path

from obsvr import sender
from obsvr.chain_format import (
    CHAIN_FORMAT_CONTENT_ONLY,
    CHAIN_FORMAT_CURRENT,
    CHAIN_FORMAT_DECISION_FIELDS,
    CHAIN_FORMAT_LEGACY,
    content_hash,
    decision_fields_of,
    decision_hash,
    signature_payload,
)
from obsvr.sender import derive_signing_key, sign_event

VECTORS_PATH = (
    Path(__file__).parent / "../../conformance/fixtures/signing_vectors.json"
).resolve()


def _load_vectors():
    with open(VECTORS_PATH) as f:
        return json.load(f)


def _sign(key, fmt, session, seq, ts, prompt, response, prev, decision=None):
    payload = signature_payload(
        fmt, session, seq, ts, prompt, response, prev or None, decision
    )
    return hmac_mod.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


class TestSigningVectors:
    def test_signing_key_derivation_matches(self):
        v = _load_vectors()
        key = derive_signing_key(v["api_key"])
        assert key.hex() == v["signing_key_hex"]

    def test_content_hash_matches_every_pinned_case_in_both_formats(self):
        v = _load_vectors()
        for case in v["content_hash"]["cases"]:
            assert (
                content_hash(CHAIN_FORMAT_CURRENT, case["prompt"], case["response"])
                == case["digest"]
            ), case["id"]
            assert (
                content_hash(CHAIN_FORMAT_LEGACY, case["prompt"], case["response"])
                == case["legacy_digest"]
            ), case["id"]

    def test_format_2_binds_the_boundary_must_differ_pairs_differ(self):
        v = _load_vectors()
        by_id = {c["id"]: c for c in v["content_hash"]["cases"]}
        for a, b in v["content_hash"]["must_differ"]:
            assert by_id[a]["digest"] != by_id[b]["digest"], (a, b)

    def test_format_1_did_not_bind_the_boundary_legacy_pairs_collide(self):
        # The pinned demonstration of the defect format 2 closed. If this
        # ever fails, the legacy implementation drifted - which would break
        # existing evidence, so the collision is asserted, not just
        # remembered.
        v = _load_vectors()
        by_id = {c["id"]: c for c in v["content_hash"]["cases"]}
        for a, b in v["content_hash"]["equal_under_legacy"]:
            assert by_id[a]["legacy_digest"] == by_id[b]["legacy_digest"], (a, b)

    def test_event_signatures_match_shared_vectors(self):
        v = _load_vectors()
        key = derive_signing_key(v["api_key"])
        prev = ""
        for expected in v["events"]:
            assert expected["chain_format"] == CHAIN_FORMAT_CURRENT
            sig = _sign(
                key,
                CHAIN_FORMAT_CURRENT,
                v["session_id"],
                expected["seq_no"],
                expected["timestamp_sdk"],
                expected["prompt"],
                expected["response"],
                prev,
                # Format 4 signs the decision and classification fields carried on
                # the vector event itself. Read them the way the SDK does.
                decision_fields_of(expected),
            )
            assert sig == expected["sdk_sig"], f"seq {expected['seq_no']} mismatch"
            assert expected["prev_sig"] == prev
            prev = sig

    def test_frozen_format_3_signatures_still_reproduce(self):
        v = _load_vectors()
        key = derive_signing_key(v["api_key"])
        prev = ""
        for expected in v["legacy_v3_events"]["events"]:
            sig = _sign(
                key,
                CHAIN_FORMAT_DECISION_FIELDS,
                v["session_id"],
                expected["seq_no"],
                expected["timestamp_sdk"],
                expected["prompt"],
                expected["response"],
                prev,
                decision_fields_of(expected, CHAIN_FORMAT_DECISION_FIELDS),
            )
            assert sig == expected["sdk_sig"]
            prev = sig

    def test_user_id_coercion_matches_every_pinned_case(self):
        # A non-string user_id is coerced to ONE canonical string at the
        # event boundary before anything stores or signs it; the fixture pins
        # both the string and the decision digest over it, and the TS suite
        # pins the same cases through its own boundary. `raw` arrives here
        # through the same JSON parse a stored export goes through, which is
        # exactly where the two runtimes' scalar renderings part company.
        from obsvr.events import _principal_string

        v = _load_vectors()
        for case in v["user_id_coercion"]["cases"]:
            assert _principal_string(case["raw"]) == case["canonical"], case["id"]
            assert (
                decision_hash({"user_id": case["canonical"]}) == case["digest"]
            ), case["id"]

    def test_frozen_format_1_signatures_still_reproduce(self):
        v = _load_vectors()
        key = derive_signing_key(v["api_key"])
        prev = ""
        for expected in v["legacy_v1_events"]["events"]:
            sig = _sign(
                key,
                CHAIN_FORMAT_LEGACY,
                v["session_id"],
                expected["seq_no"],
                expected["timestamp_sdk"],
                expected["prompt"],
                expected["response"],
                prev,
                # Format 3 signs the decision fields, and they are carried on
                # the vector event itself. Read them the way the SDK does.
                decision_fields_of(expected),
            )
            assert sig == expected["sdk_sig"], f"seq {expected['seq_no']} mismatch"
            assert expected["prev_sig"] == prev
            prev = sig


class TestSignerBehavior:
    def test_sign_event_stamps_all_chain_fields(self):
        sender._reset_sender()
        e1 = {"prompt": "a", "response": "b"}
        sign_event(e1, "k")
        assert e1["seq_no"] == 1
        assert "sdk_session_id" in e1
        assert "timestamp_sdk" in e1
        assert e1["chain_format"] == CHAIN_FORMAT_CURRENT
        assert "prev_sig" not in e1  # first event has no predecessor
        assert len(e1["sdk_sig"]) == 64

    def test_sequence_increments_and_chains(self):
        sender._reset_sender()
        e1 = {"prompt": "a", "response": "b"}
        e2 = {"prompt": "c", "response": "d"}
        sign_event(e1, "k")
        sign_event(e2, "k")
        assert e2["seq_no"] == 2
        assert e2["prev_sig"] == e1["sdk_sig"]
        assert e2["sdk_sig"] != e1["sdk_sig"]

    def test_same_session_across_events(self):
        sender._reset_sender()
        e1 = {"prompt": "a", "response": "b"}
        e2 = {"prompt": "c", "response": "d"}
        sign_event(e1, "k")
        sign_event(e2, "k")
        assert e1["sdk_session_id"] == e2["sdk_session_id"]

    def test_reset_clears_chain(self):
        sender._reset_sender()
        e1 = {"prompt": "a", "response": "b"}
        sign_event(e1, "k")
        sender._reset_sender()
        e2 = {"prompt": "a", "response": "b"}
        sign_event(e2, "k")
        assert e2["seq_no"] == 1
        assert "prev_sig" not in e2
