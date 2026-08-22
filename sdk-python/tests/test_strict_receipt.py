"""Twin consumer of the Obsvr-authored strict-receipt fixture."""

import copy
import json
from pathlib import Path

import pytest

from obsvr.device_identity import DeviceSigner, load_device_signer
from obsvr.strict_receipt import (
    StrictReceiptValidationError,
    build_strict_receipt_body,
    canonicalize_strict_receipt_body,
    sign_strict_receipt,
    strict_receipt_hash,
    strict_receipt_key_id,
)
from obsvr.strict_receipt_verify import (
    verify_strict_receipt,
    verify_strict_receipt_chain,
)

FIXTURE = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "conformance"
        / "fixtures"
        / "strict_receipts.json"
    ).read_text(encoding="utf-8")
)


@pytest.fixture()
def signer(tmp_path):
    seed = tmp_path / "public-test-seed.key"
    seed.write_text(FIXTURE["public_test_key"]["seed_hex"], encoding="ascii")
    return load_device_signer(str(seed))


def _envelopes(signer, include_public_key=True):
    return [
        sign_strict_receipt(_input_body(vector), signer, include_public_key)
        for vector in FIXTURE["vectors"]
    ]


def _input_body(vector):
    body = copy.deepcopy(vector["body"])
    body["evaluation"]["rule_ids"] = vector["input_rule_ids"]
    if vector.get("input_required_fields") is not None:
        body["suspension"]["required_fields"] = vector["input_required_fields"]
    return body


def _resign(chain, index, signer, mutate):
    body = copy.deepcopy(chain[index]["body"])
    mutate(body)
    chain[index] = sign_strict_receipt(body, signer, True)


def test_fixture_is_local_and_full_key_identity_is_pinned(signer):
    assert FIXTURE["claimable"] is False
    assert "not official AARM conformance vectors" in FIXTURE["description"]
    assert strict_receipt_key_id(signer.raw_public_key) == FIXTURE["public_test_key"][
        "key_id"
    ]


@pytest.mark.parametrize("vector", FIXTURE["vectors"], ids=lambda item: item["id"])
def test_canonical_bytes_hash_and_signature(vector, signer):
    body = _input_body(vector)
    envelope = sign_strict_receipt(body, signer, True)
    assert canonicalize_strict_receipt_body(body).encode(
        "utf-8"
    ) == vector["canonical"].encode("utf-8")
    assert strict_receipt_hash(body) == vector["receipt_hash"]
    assert envelope["receipt_hash"] == vector["receipt_hash"]
    assert envelope["signature"] == {
        "algorithm": "Ed25519",
        "key_id": FIXTURE["public_test_key"]["key_id"],
        "value": vector["signature"],
    }
    assert envelope["body"] == json.loads(vector["canonical"])


def test_outcomes_suspensions_resolutions_clock_and_optional_thread_are_covered():
    vectors = FIXTURE["vectors"]
    assert {vector["body"]["evaluation"]["outcome"] for vector in vectors} == {
        "ALLOW",
        "DENY",
        "MODIFY",
        "STEP_UP",
        "DEFER",
    }
    assert "thread_id" not in vectors[0]["body"]["context"]
    assert vectors[1]["body"]["clock_regression_clamped"] is True
    assert vectors[3]["body"]["suspension"]["approval_action_hash"] == "5" * 64
    assert vectors[5]["body"]["suspension"]["required_fields"] == [
        "missing_上下文",
        "tool_result",
    ]
    assert sum(v["body"]["record_type"] == "resolution" for v in vectors) == 2


def test_self_asserted_pinned_and_unknown_key_trust(signer):
    assert verify_strict_receipt(_envelopes(signer)[0]) == {
        "schema_valid": True,
        "hash_valid": True,
        "signature_valid": True,
        "semantic_valid": True,
        "identity_binding_valid": True,
        "key_trust": "self_asserted",
    }
    without_hint = _envelopes(signer, False)[0]
    assert verify_strict_receipt(
        without_hint,
        pinned_public_key_b64=FIXTURE["public_test_key"]["public_key_b64"],
    ) == {
        "schema_valid": True,
        "hash_valid": True,
        "signature_valid": True,
        "semantic_valid": True,
        "identity_binding_valid": True,
        "key_trust": "pinned",
    }
    unknown = verify_strict_receipt(without_hint)
    assert unknown["signature_valid"] is False
    assert unknown["identity_binding_valid"] is False
    assert unknown["key_trust"] == "unknown"


def test_body_hash_signature_and_three_way_key_tampering(signer):
    original = _envelopes(signer)[0]
    body_tamper = copy.deepcopy(original)
    body_tamper["body"]["action"]["name"] = "tampered"
    assert verify_strict_receipt(body_tamper)["hash_valid"] is False
    assert verify_strict_receipt(body_tamper)["signature_valid"] is True
    hash_tamper = copy.deepcopy(original)
    hash_tamper["receipt_hash"] = "0" + hash_tamper["receipt_hash"][1:]
    assert verify_strict_receipt(hash_tamper)["signature_valid"] is False
    signature_tamper = copy.deepcopy(original)
    signature_tamper["signature"]["value"] = (
        "0" + signature_tamper["signature"]["value"][1:]
    )
    assert verify_strict_receipt(signature_tamper)["hash_valid"] is True
    assert verify_strict_receipt(signature_tamper)["signature_valid"] is False
    signature_key_tamper = copy.deepcopy(original)
    signature_key_tamper["signature"]["key_id"] = "sha256:" + "0" * 64
    key_axes = verify_strict_receipt(signature_key_tamper)
    assert key_axes["signature_valid"] is False
    assert key_axes["identity_binding_valid"] is False
    pinned_mismatch = verify_strict_receipt(
        original,
        pinned_public_key_b64="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )
    assert pinned_mismatch["key_trust"] == "pinned"
    assert pinned_mismatch["identity_binding_valid"] is False
    malformed_pin = verify_strict_receipt(
        original, pinned_public_key_b64="not-base64"
    )
    assert malformed_pin["key_trust"] == "pinned"
    assert malformed_pin["signature_valid"] is False
    assert malformed_pin["identity_binding_valid"] is False


def test_strict_signing_rejects_malformed_wrong_key_and_public_mismatch(
    signer, tmp_path
):
    other_path = tmp_path / "other-seed.key"
    other_path.write_text("11" * 32, encoding="ascii")
    other = load_device_signer(str(other_path))
    body = _input_body(FIXTURE["vectors"][0])
    malformed = DeviceSigner(lambda _message: b"bad", signer.raw_public_key)
    wrong_key = DeviceSigner(
        lambda message: bytes.fromhex(other.sign_bytes(message)),
        signer.raw_public_key,
    )
    mismatched = DeviceSigner(
        lambda message: bytes.fromhex(signer.sign_bytes(message)),
        signer.raw_public_key,
    )
    mismatched.public_key_b64 = other.public_key_b64
    with pytest.raises(StrictReceiptValidationError, match="invalid Ed25519"):
        sign_strict_receipt(body, malformed, True)
    with pytest.raises(StrictReceiptValidationError, match="self-verification"):
        sign_strict_receipt(body, wrong_key, True)
    with pytest.raises(StrictReceiptValidationError, match="does not match"):
        sign_strict_receipt(body, mismatched, True)


def _semantic_cases():
    def unknown(body):
        body["extra"] = True

    def clock_missing(body):
        del body["clock_regression_clamped"]

    def clock_type(body):
        body["clock_regression_clamped"] = 1

    def sequence(body):
        body.update(sequence=0, receipt_id=f'{body["session_id"]}:0')

    def modify_missing(body):
        del body["action"]["effective_arguments_hash"]

    def step_required(body):
        body["suspension"]["required_fields"] = ["x"]

    def defer_approval(body):
        body["suspension"]["approval_request_id"] = "bad"

    return [
        ("unknown_body_key", 0, unknown),
        ("clock_flag_missing", 0, clock_missing),
        ("clock_flag_wrong_type", 0, clock_type),
        ("invalid_sequence", 0, sequence),
        ("invalid_timestamp", 0, lambda b: b.update(timestamp_ms=2**53)),
        ("receipt_id_mismatch", 0, lambda b: b.update(receipt_id="wrong")),
        ("genesis_previous_hash", 0, lambda b: b.update(previous_receipt_hash="0" * 64)),
        ("modify_missing_effective_hash", 2, modify_missing),
        ("non_modify_effective_hash", 0, lambda b: b["action"].update(effective_arguments_hash="b" * 64)),
        ("authorization_mismatch", 0, lambda b: b.update(execution_authorized=False)),
        ("step_up_missing_suspension", 3, lambda b: b.pop("suspension")),
        ("step_up_required_fields", 3, step_required),
        ("approval_hash_missing", 3, lambda b: b["suspension"].pop("approval_action_hash")),
        ("approval_hash_malformed", 3, lambda b: b["suspension"].update(approval_action_hash="bad")),
        ("suspension_expired_before_receipt", 3, lambda b: b["suspension"].update(expires_at_ms=b["timestamp_ms"] - 1)),
        ("defer_empty_required_fields", 5, lambda b: b["suspension"].update(required_fields=[])),
        ("defer_approval_fields", 5, defer_approval),
        ("resolution_nonfinal", 4, lambda b: (b["evaluation"].update(outcome="STEP_UP"), b.update(execution_authorized=False))),
        ("resolution_missing", 4, lambda b: b.pop("resolution")),
        ("resolution_method_outcome", 4, lambda b: b["resolution"].update(method="approval_denied")),
        ("resolution_timestamp_after_receipt", 4, lambda b: b["resolution"].update(resolved_at_ms=b["timestamp_ms"] + 1)),
    ]


@pytest.mark.parametrize("case", _semantic_cases(), ids=lambda item: item[0])
def test_semantic_refusals(case):
    case_id, index, mutate = case
    assert case_id in FIXTURE["negative_case_ids"]
    body = copy.deepcopy(FIXTURE["vectors"][index]["body"])
    mutate(body)
    with pytest.raises(StrictReceiptValidationError):
        build_strict_receipt_body(body)


def test_valid_chain_is_accepted_self_asserted_or_pinned(signer):
    valid = _envelopes(signer)
    assert verify_strict_receipt_chain(valid) == {"valid": True, "errors": []}
    assert verify_strict_receipt_chain(
        valid, pinned_public_key_b64=FIXTURE["public_test_key"]["public_key_b64"]
    ) == {"valid": True, "errors": []}


def test_empty_and_malformed_chains_are_rejected_without_throwing():
    assert verify_strict_receipt_chain([]) == {
        "valid": False,
        "errors": ["empty_chain"],
    }
    result = verify_strict_receipt_chain(
        [None, {}, {"schema": "obsvr-strict-receipt-envelope-v1"}]
    )
    assert result["valid"] is False
    assert "receipt_schema_invalid:index-0" in result["errors"]
    assert "receipt_semantic_invalid:index-1" in result["errors"]


def test_reordering_and_receipt_tampering_are_not_hidden(signer):
    reordered = _envelopes(signer)
    reordered[1], reordered[2] = reordered[2], reordered[1]
    assert any(
        error.startswith("sequence_order_invalid")
        for error in verify_strict_receipt_chain(reordered)["errors"]
    )
    tampered = _envelopes(signer)
    tampered[1]["body"]["action"]["name"] = "tampered"
    assert f'receipt_hash_invalid:{tampered[1]["body"]["receipt_id"]}' in (
        verify_strict_receipt_chain(tampered)["errors"]
    )
    approval_binding = _envelopes(signer)
    approval_binding[3]["body"]["suspension"]["approval_action_hash"] = "8" * 64
    assert f'receipt_hash_invalid:{approval_binding[3]["body"]["receipt_id"]}' in (
        verify_strict_receipt_chain(approval_binding)["errors"]
    )


def _chain_cases(signer):
    def previous(chain):
        _resign(chain, 1, signer, lambda b: b.update(previous_receipt_hash="0" * 64))

    def timestamp(chain):
        _resign(chain, 1, signer, lambda b: b.update(timestamp_ms=chain[0]["body"]["timestamp_ms"] - 1))

    def session(chain):
        _resign(chain, 1, signer, lambda b: b.update(session_id="other", receipt_id="other:2"))

    def resolution(chain, key, value):
        _resign(chain, 4, signer, lambda b: b["resolution"].update({key: value}))

    def prior_not_suspended(chain):
        def mutate(body):
            body["resolution"].update(resolves_receipt_hash=chain[0]["receipt_hash"], suspension_id="other")
            body["action"] = copy.deepcopy(chain[0]["body"]["action"])

        _resign(chain, 4, signer, mutate)

    return [
        ("previous_hash_mismatch", previous, "previous_hash_mismatch"),
        ("timestamp_regression", timestamp, "timestamp_regression"),
        ("session_mismatch", session, "session_mismatch"),
        ("resolution_reference_invalid", lambda c: resolution(c, "resolves_receipt_hash", "0" * 64), "resolution_reference_invalid"),
        ("resolution_suspension_mismatch", lambda c: resolution(c, "suspension_id", "other"), "resolution_suspension_mismatch"),
        ("resolution_method_mismatch", lambda c: resolution(c, "method", "context_supplied"), "resolution_method_mismatch"),
        ("resolution_time_invalid", lambda c: resolution(c, "resolved_at_ms", c[3]["body"]["timestamp_ms"] - 1), "resolution_time_invalid"),
        ("resolution_after_expiry", lambda c: _resign(c, 4, signer, lambda b: (b["resolution"].update(resolved_at_ms=c[3]["body"]["suspension"]["expires_at_ms"] + 1), b.update(timestamp_ms=c[3]["body"]["suspension"]["expires_at_ms"] + 1))), "resolution_after_expiry"),
        ("resolution_action_mismatch", lambda c: _resign(c, 4, signer, lambda b: b["action"].update(action_id="other")), "resolution_action_mismatch"),
        ("resolution_initiator_mismatch", lambda c: _resign(c, 4, signer, lambda b: b["initiator"].update(agent_id="other")), "resolution_initiator_mismatch"),
        ("resolution_prior_not_suspended", prior_not_suspended, "resolution_prior_not_suspended"),
    ]


def test_chain_links_time_session_and_resolution_continuity(signer):
    for case_id, mutate, expected in _chain_cases(signer):
        assert case_id in FIXTURE["negative_case_ids"]
        chain = _envelopes(signer)
        mutate(chain)
        assert any(
            error.startswith(expected)
            for error in verify_strict_receipt_chain(chain)["errors"]
        )


def test_duplicate_resolution_is_rejected(signer):
    chain = _envelopes(signer)[:5]
    body = copy.deepcopy(chain[4]["body"])
    body["sequence"] = 6
    body["receipt_id"] = f'{body["session_id"]}:6'
    body["previous_receipt_hash"] = chain[4]["receipt_hash"]
    body["timestamp_ms"] += 1
    body["resolution"]["resolved_at_ms"] = body["timestamp_ms"]
    chain.append(sign_strict_receipt(body, signer, True))
    assert (
        f'duplicate_resolution:{body["receipt_id"]}'
        in verify_strict_receipt_chain(chain)["errors"]
    )
