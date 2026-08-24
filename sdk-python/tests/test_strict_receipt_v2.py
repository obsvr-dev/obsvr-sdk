"""Twin tests for strict receipt profile 2.0 and offline verification."""

import copy
import json
from pathlib import Path

import pytest

from obsvr.device_identity import DeviceSigner, load_device_signer
from obsvr.strict_receipt import sign_strict_receipt
from obsvr.strict_receipt_v2 import (
    StrictReceiptV2ValidationError,
    build_strict_receipt_v2_body,
    canonicalize_strict_receipt_v2_body,
    sign_strict_receipt_v2,
    strict_receipt_v2_hash,
    strict_receipt_v2_key_id,
)
from obsvr.strict_receipt_v2_verify import (
    verify_strict_receipt_v2,
    verify_strict_receipt_v2_chain,
)
from obsvr.strict_receipt_verify import verify_strict_receipt

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = json.loads(
    (ROOT / "conformance/fixtures/strict_receipts_v2.json").read_text("utf-8")
)
V1_FIXTURE = json.loads(
    (ROOT / "conformance/fixtures/strict_receipts.json").read_text("utf-8")
)


@pytest.fixture()
def signer(tmp_path):
    seed = tmp_path / "public-test-seed.key"
    seed.write_text(FIXTURE["public_test_key"]["seed_hex"], encoding="ascii")
    return load_device_signer(str(seed))


def _input_body(vector):
    body = copy.deepcopy(vector["body"])
    body["evaluation"]["rule_ids"] = copy.deepcopy(vector["input_rule_ids"])
    return body


def _envelopes(signer):
    return [
        sign_strict_receipt_v2(_input_body(vector), signer, True)
        for vector in FIXTURE["vectors"]
    ]


def test_fixture_key_and_non_conformance_status_are_pinned(signer):
    assert FIXTURE["claimable"] is False
    assert "not official AARM conformance vectors" in FIXTURE["description"]
    assert (
        strict_receipt_v2_key_id(signer.raw_public_key)
        == FIXTURE["public_test_key"]["key_id"]
    )


@pytest.mark.parametrize("vector", FIXTURE["vectors"], ids=lambda item: item["id"])
def test_canonical_bytes_hash_and_signature(vector, signer):
    body = _input_body(vector)
    envelope = sign_strict_receipt_v2(body, signer, True)
    assert canonicalize_strict_receipt_v2_body(body) == vector["canonical"]
    assert strict_receipt_v2_hash(body) == vector["receipt_hash"]
    assert envelope["receipt_hash"] == vector["receipt_hash"]
    assert envelope["signature"]["value"] == vector["signature"]
    assert envelope["body"] == json.loads(vector["canonical"])
    assert "target" not in envelope["body"]["action"]
    assert len(envelope["body"]["action"]["target_hash"]) == 64
    assert envelope["body"]["tenant_id"] == "tenant-北"


def test_embedded_integrity_is_visible_but_only_a_valid_pin_is_trusted(
    signer, tmp_path
):
    chain = _envelopes(signer)
    embedded_only = verify_strict_receipt_v2_chain(chain)
    assert embedded_only == {
        "valid": False,
        "errors": [
            f"receipt_key_untrusted:{receipt['body']['receipt_id']}"
            for receipt in chain
        ],
    }
    assert verify_strict_receipt_v2_chain(
        chain,
        pinned_public_key_b64=FIXTURE["public_test_key"]["public_key_b64"],
    ) == {"valid": True, "errors": []}
    assert verify_strict_receipt_v2(chain[0]) == {
        "schema_valid": True,
        "hash_valid": True,
        "signature_valid": True,
        "semantic_valid": True,
        "identity_binding_valid": True,
        "key_trust": "self_asserted",
    }
    invalid_pin = verify_strict_receipt_v2(chain[0], pinned_public_key_b64="bad")
    assert invalid_pin["key_trust"] == "unknown"
    assert invalid_pin["signature_valid"] is False
    assert invalid_pin["identity_binding_valid"] is False

    attacker_path = tmp_path / "attacker.key"
    attacker_path.write_text("11" * 32, encoding="ascii")
    attacker = load_device_signer(str(attacker_path))
    attacker_body = _input_body(FIXTURE["vectors"][0])
    attacker_body["initiator"]["key_id"] = strict_receipt_v2_key_id(
        attacker.raw_public_key
    )
    attacker_receipt = sign_strict_receipt_v2(attacker_body, attacker, True)
    assert verify_strict_receipt_v2(attacker_receipt)["signature_valid"] is True
    assert (
        f"receipt_key_untrusted:{attacker_body['receipt_id']}"
        in (verify_strict_receipt_v2_chain([attacker_receipt])["errors"])
    )


def test_tenant_is_bound_into_bytes_hash_signature_and_chain(signer):
    original = sign_strict_receipt_v2(_input_body(FIXTURE["vectors"][0]), signer, True)
    other_body = _input_body(FIXTURE["vectors"][0])
    other_body["tenant_id"] = "tenant-other"
    other = sign_strict_receipt_v2(other_body, signer, True)
    assert other["receipt_hash"] != original["receipt_hash"]
    assert other["signature"]["value"] != original["signature"]["value"]
    tampered = copy.deepcopy(original)
    tampered["body"]["tenant_id"] = "tenant-other"
    assert verify_strict_receipt_v2(tampered)["hash_valid"] is False

    chain = _envelopes(signer)
    second = _input_body(FIXTURE["vectors"][1])
    second["tenant_id"] = "tenant-other"
    chain[1] = sign_strict_receipt_v2(second, signer, True)
    assert (
        f"tenant_mismatch:{second['receipt_id']}"
        in (verify_strict_receipt_v2_chain(chain)["errors"])
    )


def test_exact_keys_target_privacy_bounds_and_scalars_are_enforced(signer):
    raw_target = _input_body(FIXTURE["vectors"][0])
    raw_target["action"]["target"] = "raw-target"
    with pytest.raises(StrictReceiptV2ValidationError):
        build_strict_receipt_v2_body(raw_target)
    unknown = _input_body(FIXTURE["vectors"][0])
    unknown["extra"] = True
    with pytest.raises(StrictReceiptV2ValidationError):
        build_strict_receipt_v2_body(unknown)
    wrong_engine = _input_body(FIXTURE["vectors"][0])
    wrong_engine["evaluation"]["engine_version"] = "obsvr-intent/1"
    with pytest.raises(StrictReceiptV2ValidationError, match="engine_version"):
        build_strict_receipt_v2_body(wrong_engine)
    noncanonical = _envelopes(signer)[0]
    noncanonical["body"]["evaluation"]["rule_ids"] = ["rule-z", "rule-a"]
    assert verify_strict_receipt_v2(noncanonical)["semantic_valid"] is False
    oversized_set = _input_body(FIXTURE["vectors"][0])
    oversized_set["evaluation"]["rule_ids"] = ["duplicate"] * 65
    with pytest.raises(StrictReceiptV2ValidationError, match="exceeds 64 items"):
        build_strict_receipt_v2_body(oversized_set)
    for tenant in ("x" * 256, "🚀" * 64):
        bounded = _input_body(FIXTURE["vectors"][0])
        bounded["tenant_id"] = tenant
        assert build_strict_receipt_v2_body(bounded)["tenant_id"] == tenant
    for tenant in ("x" * 257, "🚀" * 65, "\ud800"):
        rejected = _input_body(FIXTURE["vectors"][0])
        rejected["tenant_id"] = tenant
        with pytest.raises(StrictReceiptV2ValidationError):
            build_strict_receipt_v2_body(rejected)


def test_v1_v2_domains_and_verifiers_remain_isolated(signer):
    v2 = sign_strict_receipt_v2(_input_body(FIXTURE["vectors"][0]), signer, True)
    v1_body = copy.deepcopy(V1_FIXTURE["vectors"][0]["body"])
    v1_body["evaluation"]["rule_ids"] = V1_FIXTURE["vectors"][0]["input_rule_ids"]
    v1 = sign_strict_receipt(v1_body, signer, True)
    assert verify_strict_receipt(v1)["schema_valid"] is True
    assert verify_strict_receipt(v2)["schema_valid"] is False
    assert verify_strict_receipt_v2(v1)["schema_valid"] is False
    assert v1["receipt_hash"] != v2["receipt_hash"]


def test_signer_self_verification_and_public_key_binding(signer, tmp_path):
    other_seed = tmp_path / "other.key"
    other_seed.write_text("11" * 32, encoding="ascii")
    other = load_device_signer(str(other_seed))
    body = _input_body(FIXTURE["vectors"][0])
    malformed = DeviceSigner(lambda _message: b"bad", signer.raw_public_key)
    wrong = DeviceSigner(
        lambda message: bytes.fromhex(other.sign_bytes(message)),
        signer.raw_public_key,
    )
    mismatch = DeviceSigner(
        lambda message: bytes.fromhex(signer.sign_bytes(message)),
        signer.raw_public_key,
    )
    mismatch.public_key_b64 = other.public_key_b64
    with pytest.raises(StrictReceiptV2ValidationError, match="invalid Ed25519"):
        sign_strict_receipt_v2(body, malformed)
    with pytest.raises(StrictReceiptV2ValidationError, match="self-verification"):
        sign_strict_receipt_v2(body, wrong)
    with pytest.raises(StrictReceiptV2ValidationError, match="does not match"):
        sign_strict_receipt_v2(body, mismatch)


def test_reordering_and_tampering_are_not_hidden(signer):
    reordered = _envelopes(signer)
    reordered[0], reordered[1] = reordered[1], reordered[0]
    assert any(
        error.startswith("sequence_order_invalid")
        for error in verify_strict_receipt_v2_chain(reordered)["errors"]
    )
    tampered = _envelopes(signer)
    tampered[1]["body"]["action"]["name"] = "tampered"
    assert (
        f"receipt_hash_invalid:{tampered[1]['body']['receipt_id']}"
        in (verify_strict_receipt_v2_chain(tampered)["errors"])
    )


def test_duplicate_receipts_and_cross_identity_splicing_are_rejected(signer, tmp_path):
    duplicate = _envelopes(signer)
    duplicate.insert(1, copy.deepcopy(duplicate[0]))
    assert (
        f"duplicate_receipt:{duplicate[1]['body']['receipt_id']}"
        in verify_strict_receipt_v2_chain(duplicate)["errors"]
    )

    spliced = _envelopes(signer)
    second = _input_body(FIXTURE["vectors"][1])
    second["initiator"]["agent_id"] = "other-agent"
    spliced[1] = sign_strict_receipt_v2(second, signer, True)
    assert (
        f"initiator_mismatch:{second['receipt_id']}"
        in verify_strict_receipt_v2_chain(spliced)["errors"]
    )

    other_path = tmp_path / "other-splice.key"
    other_path.write_text("11" * 32, encoding="ascii")
    other = load_device_signer(str(other_path))
    second["initiator"]["agent_id"] = spliced[0]["body"]["initiator"]["agent_id"]
    second["initiator"]["key_id"] = strict_receipt_v2_key_id(other.raw_public_key)
    spliced[1] = sign_strict_receipt_v2(second, other, True)
    assert (
        f"signer_key_mismatch:{second['receipt_id']}"
        in verify_strict_receipt_v2_chain(spliced)["errors"]
    )


def test_duplicate_resolution_is_rejected(signer):
    chain = _envelopes(signer)
    duplicate = copy.deepcopy(chain[2]["body"])
    duplicate["sequence"] = 4
    duplicate["receipt_id"] = f"{duplicate['session_id']}:4"
    duplicate["timestamp_ms"] += 100
    duplicate["previous_receipt_hash"] = chain[2]["receipt_hash"]
    chain.append(sign_strict_receipt_v2(duplicate, signer, True))
    assert (
        f"duplicate_resolution:{duplicate['receipt_id']}"
        in (verify_strict_receipt_v2_chain(chain)["errors"])
    )


def test_exact_expiry_boundaries_check_both_signed_timestamps(signer):
    pin = FIXTURE["public_test_key"]["public_key_b64"]
    at_expiry = _envelopes(signer)
    expiry = at_expiry[1]["body"]["suspension"]["expires_at_ms"]
    exact = copy.deepcopy(at_expiry[2]["body"])
    exact["resolution"]["resolved_at_ms"] = expiry
    exact["timestamp_ms"] = expiry
    at_expiry[2] = sign_strict_receipt_v2(exact, signer, True)
    assert (
        f"resolution_after_expiry:{exact['receipt_id']}"
        in (
            verify_strict_receipt_v2_chain(at_expiry, pinned_public_key_b64=pin)[
                "errors"
            ]
        )
    )

    forged_timestamp = _envelopes(signer)
    forged = copy.deepcopy(forged_timestamp[2]["body"])
    forged["resolution"]["resolved_at_ms"] = expiry - 1
    forged["timestamp_ms"] = expiry
    forged_timestamp[2] = sign_strict_receipt_v2(forged, signer, True)
    assert (
        f"resolution_after_expiry:{forged['receipt_id']}"
        in (
            verify_strict_receipt_v2_chain(forged_timestamp, pinned_public_key_b64=pin)[
                "errors"
            ]
        )
    )

    expired = _envelopes(signer)
    expired_body = copy.deepcopy(expired[2]["body"])
    expired_body["resolution"]["method"] = "expired"
    expired_body["resolution"]["resolved_at_ms"] = expiry
    expired_body["timestamp_ms"] = expiry
    expired_body["evaluation"]["outcome"] = "DENY"
    expired_body["evaluation"]["reason_code"] = "approval_expired"
    expired_body["execution_authorized"] = False
    expired[2] = sign_strict_receipt_v2(expired_body, signer, True)
    assert verify_strict_receipt_v2_chain(expired, pinned_public_key_b64=pin) == {
        "valid": True,
        "errors": [],
    }

    early = _envelopes(signer)
    early_body = copy.deepcopy(expired_body)
    early_body["resolution"]["resolved_at_ms"] = expiry - 1
    early[2] = sign_strict_receipt_v2(early_body, signer, True)
    assert (
        f"resolution_before_expiry:{early_body['receipt_id']}"
        in (verify_strict_receipt_v2_chain(early, pinned_public_key_b64=pin)["errors"])
    )


def test_referenced_time_and_resolution_outcome_semantics(signer):
    pin = FIXTURE["public_test_key"]["public_key_b64"]
    wrong_outcome = _envelopes(signer)
    denied_grant = copy.deepcopy(wrong_outcome[2]["body"])
    denied_grant["evaluation"]["outcome"] = "DENY"
    denied_grant["execution_authorized"] = False
    wrong_outcome[2] = sign_strict_receipt_v2(denied_grant, signer, True)
    assert (
        f"resolution_outcome_mismatch:{denied_grant['receipt_id']}"
        in (
            verify_strict_receipt_v2_chain(wrong_outcome, pinned_public_key_b64=pin)[
                "errors"
            ]
        )
    )

    before_prior = _envelopes(signer)
    before = copy.deepcopy(before_prior[2]["body"])
    before["timestamp_ms"] = before_prior[1]["body"]["timestamp_ms"] - 1
    before["resolution"]["resolved_at_ms"] = before["timestamp_ms"]
    before_prior[2] = sign_strict_receipt_v2(before, signer, True)
    assert (
        f"resolution_time_invalid:{before['receipt_id']}"
        in (
            verify_strict_receipt_v2_chain(before_prior, pinned_public_key_b64=pin)[
                "errors"
            ]
        )
    )

    nonfinal_context = copy.deepcopy(before_prior[2]["body"])
    nonfinal_context["resolution"]["method"] = "context_supplied"
    nonfinal_context["evaluation"]["outcome"] = "STEP_UP"
    nonfinal_context["execution_authorized"] = False
    with pytest.raises(StrictReceiptV2ValidationError, match="outcome must be final"):
        build_strict_receipt_v2_body(nonfinal_context)
    allowed_expiry = copy.deepcopy(before_prior[2]["body"])
    allowed_expiry["resolution"]["method"] = "expired"
    allowed_expiry["evaluation"]["outcome"] = "ALLOW"
    allowed_expiry["execution_authorized"] = True
    with pytest.raises(StrictReceiptV2ValidationError, match="requires DENY"):
        build_strict_receipt_v2_body(allowed_expiry)
