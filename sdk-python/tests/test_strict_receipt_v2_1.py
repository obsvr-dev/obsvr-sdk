"""Paired fixture and adversarial tests for strict receipt profile 2.1."""

import copy
import json
from pathlib import Path

import pytest

from obsvr.device_identity import load_device_signer
from obsvr.strict_receipt_v2 import sign_strict_receipt_v2
from obsvr.strict_receipt_v2_1 import (
    canonicalize_strict_receipt_v2_1_body,
    sign_strict_receipt_v2_1,
    strict_receipt_v2_1_hash,
)
from obsvr.strict_receipt_v2_1_verify import (
    verify_strict_receipt_v2_1,
    verify_strict_receipt_v2_1_chain,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = json.loads(
    (ROOT / "conformance/fixtures/strict_receipts_v2_1.json").read_text("utf-8")
)
V20 = json.loads(
    (ROOT / "conformance/fixtures/strict_receipts_v2.json").read_text("utf-8")
)


@pytest.fixture()
def signer(tmp_path):
    seed = tmp_path / "public-test-seed.key"
    seed.write_text(FIXTURE["public_test_key"]["seed_hex"], encoding="ascii")
    return load_device_signer(str(seed))


def _body():
    return copy.deepcopy(FIXTURE["vector"]["body"])


def _modify_body():
    result = _body()
    patch = FIXTURE["modify_vector"]["body_patch"]
    result["receipt_id"] = patch["receipt_id"]
    result["session_id"] = patch["session_id"]
    result["action"]["action_id"] = patch["action_id"]
    result["action"]["effective_arguments_hash"] = patch["effective_arguments_hash"]
    result["evaluation"]["requested_outcome"] = patch["requested_outcome"]
    result["evaluation"]["outcome"] = patch["outcome"]
    result["outcome"] = patch["outcome"]
    result["execution_authorized"] = patch["execution_authorized"]
    result.pop("suspension")
    return result


def _trust(**overrides):
    result = {
        "trusted_agent_keys": [
            {
                "tenant_id": "tenant-21",
                "agent_ref_hash": "b" * 64,
                "key_id": FIXTURE["public_test_key"]["key_id"],
                "public_key_b64": FIXTURE["public_test_key"]["public_key_b64"],
                "status": "active",
            }
        ],
        "allowed_evaluator_manifest_hashes": [FIXTURE["evaluator_manifest_hash"]],
    }
    result.update(overrides)
    return result


def _signed(signer):
    return sign_strict_receipt_v2_1(_body(), signer)


def test_cross_language_canonical_hash_signature_and_status(signer):
    envelope = _signed(signer)
    assert FIXTURE["claimable"] is False
    assert "not official AARM conformance vectors" in FIXTURE["description"]
    assert (
        canonicalize_strict_receipt_v2_1_body(_body()) == FIXTURE["vector"]["canonical"]
    )
    assert strict_receipt_v2_1_hash(_body()) == FIXTURE["vector"]["receipt_hash"]
    assert envelope["receipt_hash"] == FIXTURE["vector"]["receipt_hash"]
    assert envelope["signature"]["value"] == FIXTURE["vector"]["signature"]


def test_integrity_is_separate_from_registry_and_evaluator_trust(signer):
    envelope = _signed(signer)
    unknown = verify_strict_receipt_v2_1(
        envelope,
        **_trust(trusted_agent_keys=[]),
    )
    assert unknown["integrity_valid"] is True
    assert unknown["key_trust"] == "unknown"
    assert unknown["evaluator_trust"] == "allowlisted"
    assert unknown["trusted"] is False
    trusted = verify_strict_receipt_v2_1(envelope, **_trust())
    assert trusted["integrity_valid"] is True
    assert trusted["key_trust"] == "trusted"
    assert trusted["trusted"] is True
    revoked = copy.deepcopy(_trust()["trusted_agent_keys"])
    revoked[0]["status"] = "revoked"
    assert (
        verify_strict_receipt_v2_1(envelope, **_trust(trusted_agent_keys=revoked))[
            "trusted"
        ]
        is False
    )
    assert (
        verify_strict_receipt_v2_1(
            envelope, **_trust(allowed_evaluator_manifest_hashes=[])
        )["evaluator_trust"]
        == "unknown"
    )


def test_modify_effective_bytes_are_pinned_and_unambiguous(signer):
    modified = sign_strict_receipt_v2_1(_modify_body(), signer)
    assert (
        canonicalize_strict_receipt_v2_1_body(modified["body"])
        == FIXTURE["modify_vector"]["canonical"]
    )
    assert modified["receipt_hash"] == FIXTURE["modify_vector"]["receipt_hash"]
    assert modified["signature"]["value"] == FIXTURE["modify_vector"]["signature"]
    tampered = copy.deepcopy(modified)
    tampered["body"]["action"]["effective_arguments_hash"] = "6" * 64
    assert verify_strict_receipt_v2_1(tampered, **_trust())["hash_valid"] is False
    missing = _modify_body()
    missing["action"].pop("effective_arguments_hash")
    with pytest.raises(ValueError, match="effective_arguments_hash"):
        sign_strict_receipt_v2_1(missing, signer)
    unchanged = _modify_body()
    unchanged["action"]["effective_arguments_hash"] = unchanged["action"][
        "arguments_hash"
    ]
    with pytest.raises(ValueError, match="must differ"):
        sign_strict_receipt_v2_1(unchanged, signer)
    non_modify = _body()
    non_modify["action"]["effective_arguments_hash"] = "5" * 64
    with pytest.raises(ValueError, match="only for MODIFY"):
        sign_strict_receipt_v2_1(non_modify, signer)


@pytest.mark.parametrize(
    "path",
    (
        ("identity", "requester", "requester_ref_hash"),
        ("identity", "delegation_chain", 0, "delegation_id_hash"),
        ("evaluation", "effective_policy", "artifact_hash"),
        ("evaluation", "detectors", 0, "result_hash"),
        ("evaluation", "evaluator_manifest_hash"),
    ),
)
def test_requester_delegation_policy_detector_and_manifest_tampering(path, signer):
    envelope = _signed(signer)
    cursor = envelope["body"]
    for component in path[:-1]:
        cursor = cursor[component]
    cursor[path[-1]] = "9" * 64
    result = verify_strict_receipt_v2_1(envelope, **_trust())
    assert result["hash_valid"] is False
    assert result["trusted"] is False


def test_registry_binding_is_tenant_agent_key_and_tuple_specific(signer):
    envelope = _signed(signer)
    base = _trust()["trusted_agent_keys"][0]
    changed = [
        {**base, "tenant_id": "other"},
        {**base, "agent_ref_hash": "8" * 64},
        {**base, "public_key_b64": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="},
    ]
    for entry in changed:
        assert (
            verify_strict_receipt_v2_1(envelope, **_trust(trusted_agent_keys=[entry]))[
                "trusted"
            ]
            is False
        )
    duplicate = verify_strict_receipt_v2_1(
        envelope, **_trust(trusted_agent_keys=[base, copy.deepcopy(base)])
    )
    assert duplicate["key_trust"] == "malformed"
    assert duplicate["trusted"] is False


def _resolution(target):
    result = copy.deepcopy(target["body"])
    result["record_type"] = "resolution"
    result["receipt_id"] = "session-21:2"
    result["sequence"] = 2
    result["previous_receipt_hash"] = target["receipt_hash"]
    result["timestamp_ms"] += 100
    result.pop("suspension")
    result["evaluation"] = {
        **result["evaluation"],
        "requested_outcome": "ALLOW",
        "outcome": "ALLOW",
    }
    result["outcome"] = "ALLOW"
    result["execution_authorized"] = True
    result["resolution"] = {
        "resolves_receipt_hash": target["receipt_hash"],
        "suspension_id": "approval-21",
        "method": "approval_granted",
        "resolver_ref_hash": "4" * 64,
        "resolved_at_ms": result["timestamp_ms"],
    }
    return result


def test_resolution_preserves_original_identity_and_delegation_bytes(signer):
    target = _signed(signer)
    resolved = sign_strict_receipt_v2_1(_resolution(target), signer)
    assert verify_strict_receipt_v2_1_chain([target, resolved], **_trust()) == {
        "valid": True,
        "errors": [],
    }
    changed = _resolution(target)
    changed["identity"]["requester"]["requester_ref_hash"] = "8" * 64
    changed["identity"]["delegation_chain"][0]["delegator_ref_hash"] = "8" * 64
    resigned = sign_strict_receipt_v2_1(changed, signer)
    assert (
        "resolution_identity_mismatch:session-21:2"
        in verify_strict_receipt_v2_1_chain([target, resigned], **_trust())["errors"]
    )
    changed_time = _resolution(target)
    changed_time["identity"]["receipt_time_ms"] = changed_time["timestamp_ms"]
    resigned_time = sign_strict_receipt_v2_1(changed_time, signer)
    assert (
        "resolution_identity_mismatch:session-21:2"
        in verify_strict_receipt_v2_1_chain([target, resigned_time], **_trust())[
            "errors"
        ]
    )


def test_unknown_key_and_evaluator_are_not_chain_trusted(signer):
    assert (
        "receipt_key_untrusted:session-21:1"
        in verify_strict_receipt_v2_1_chain(
            [_signed(signer)], **_trust(trusted_agent_keys=[])
        )["errors"]
    )
    assert (
        "receipt_evaluator_untrusted:session-21:1"
        in verify_strict_receipt_v2_1_chain(
            [_signed(signer)], **_trust(allowed_evaluator_manifest_hashes=[])
        )["errors"]
    )


def test_profile_2_0_bytes_hash_and_signature_are_unchanged(signer):
    body = copy.deepcopy(V20["vectors"][0]["body"])
    body["evaluation"]["rule_ids"] = copy.deepcopy(V20["vectors"][0]["input_rule_ids"])
    envelope = sign_strict_receipt_v2(body, signer, True)
    assert envelope["receipt_hash"] == V20["vectors"][0]["receipt_hash"]
    assert envelope["signature"]["value"] == V20["vectors"][0]["signature"]
