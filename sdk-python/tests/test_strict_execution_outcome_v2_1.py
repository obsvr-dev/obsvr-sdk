"""Cross-language and adversarial tests for signed terminal outcomes."""

import copy
import hashlib
import json
from pathlib import Path

import pytest

from obsvr.device_identity import load_device_signer
from obsvr.strict_execution_outcome_v2_1 import (
    canonicalize_strict_execution_outcome_v2_1_body,
    sign_strict_execution_outcome_v2_1,
    strict_execution_outcome_v2_1_hash,
    strict_execution_result_v2_1_hash,
    strict_execution_start_v2_1_hash,
    verify_strict_execution_outcome_v2_1,
)
from obsvr.strict_receipt_v2_1 import sign_strict_receipt_v2_1

ROOT = Path(__file__).resolve().parents[2]
DECISION = json.loads(
    (ROOT / "conformance/fixtures/strict_receipts_v2_1.json").read_text("utf-8")
)
OUTCOME = json.loads(
    (ROOT / "conformance/fixtures/strict_execution_outcomes_v2_1.json").read_text(
        "utf-8"
    )
)


@pytest.fixture()
def signer(tmp_path):
    seed = tmp_path / "public-test-seed.key"
    seed.write_text(DECISION["public_test_key"]["seed_hex"], encoding="ascii")
    return load_device_signer(str(seed))


def _signer(tmp_path, seed_hex):
    seed = tmp_path / f"seed-{seed_hex[:8]}.key"
    seed.write_text(seed_hex, encoding="ascii")
    return load_device_signer(str(seed))


def _decision_body():
    body = copy.deepcopy(DECISION["vector"]["body"])
    patch = OUTCOME["decision_patch"]
    body["evaluation"].update(copy.deepcopy(patch["evaluation"]))
    body["outcome"] = patch["outcome"]
    body["execution_authorized"] = patch["execution_authorized"]
    for field in patch["remove"]:
        body.pop(field, None)
    return body


def _decision(signer):
    return sign_strict_receipt_v2_1(_decision_body(), signer)


def _outcome_body():
    return copy.deepcopy(OUTCOME["vector"]["body"])


def _trust(**overrides):
    result = {
        "trusted_agent_keys": [
            {
                "tenant_id": "tenant-21",
                "agent_ref_hash": "b" * 64,
                "key_id": DECISION["public_test_key"]["key_id"],
                "public_key_b64": DECISION["public_test_key"]["public_key_b64"],
                "status": "active",
            }
        ],
        "allowed_evaluator_manifest_hashes": [DECISION["evaluator_manifest_hash"]],
    }
    result.update(overrides)
    return result


def test_cross_language_start_result_body_hash_signature_and_trust(signer):
    admitted = _decision(signer)
    assert admitted["receipt_hash"] == OUTCOME["decision_receipt_hash"]
    assert (
        strict_execution_result_v2_1_hash(OUTCOME["result_projection"])
        == OUTCOME["vector"]["body"]["result_hash"]
    )
    body = _outcome_body()
    assert (
        strict_execution_start_v2_1_hash(
            {
                "tenant_id": body["tenant_id"],
                "session_id": body["session_id"],
                "action_id": body["action_id"],
                "decision_receipt_hash": body["decision_receipt_hash"],
                "operation_fingerprint": body["operation_fingerprint"],
                "attempt": 1,
                "started_at_ms": body["started_at_ms"],
            }
        )
        == body["execution_start_hash"]
    )
    assert (
        hashlib.sha256(
            canonicalize_strict_execution_outcome_v2_1_body(body).encode("utf-8")
        ).hexdigest()
        == OUTCOME["vector"]["canonical_sha256"]
    )
    assert strict_execution_outcome_v2_1_hash(body) == OUTCOME["vector"]["outcome_hash"]
    envelope = sign_strict_execution_outcome_v2_1(body, signer, admitted)
    assert envelope["signature"]["value"] == OUTCOME["vector"]["signature"]
    assert verify_strict_execution_outcome_v2_1(envelope, admitted, **_trust()) == {
        "schema_valid": True,
        "semantic_valid": True,
        "hash_valid": True,
        "signature_valid": True,
        "decision_integrity_valid": True,
        "decision_binding_valid": True,
        "signer_binding_valid": True,
        "integrity_valid": True,
        "decision_trusted": True,
        "trusted": True,
    }


def test_success_failure_and_uncertainty_are_unambiguous(signer):
    admitted = _decision(signer)
    for patch in OUTCOME["terminal_error_patches"]:
        body = _outcome_body()
        body.update(patch)
        body.pop("result_hash")
        envelope = sign_strict_execution_outcome_v2_1(body, signer, admitted)
        assert verify_strict_execution_outcome_v2_1(envelope, admitted, **_trust())[
            "trusted"
        ]
    failed_with_result = _outcome_body()
    failed_with_result.update(status="failed", error_code="provider_rejected")
    with pytest.raises(ValueError, match="cannot contain result_hash"):
        sign_strict_execution_outcome_v2_1(failed_with_result, signer, admitted)
    success_with_error = _outcome_body()
    success_with_error["error_code"] = "provider_rejected"
    with pytest.raises(ValueError, match="cannot contain error_code"):
        sign_strict_execution_outcome_v2_1(success_with_error, signer, admitted)


def test_tampering_mismatched_admission_and_wrong_signer_are_rejected(signer, tmp_path):
    admitted = _decision(signer)
    envelope = sign_strict_execution_outcome_v2_1(_outcome_body(), signer, admitted)
    tampered = copy.deepcopy(envelope)
    tampered["body"]["result_hash"] = "7" * 64
    result = verify_strict_execution_outcome_v2_1(tampered, admitted, **_trust())
    assert not result["hash_valid"]
    assert not result["trusted"]
    wrong_body = _decision_body()
    wrong_body["action"]["action_id"] = "different-action"
    wrong_decision = sign_strict_receipt_v2_1(wrong_body, signer)
    with pytest.raises(ValueError, match="does not bind"):
        sign_strict_execution_outcome_v2_1(_outcome_body(), signer, wrong_decision)
    wrong_signer = _signer(
        tmp_path,
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    )
    with pytest.raises(ValueError, match="signer does not match"):
        sign_strict_execution_outcome_v2_1(_outcome_body(), wrong_signer, admitted)
    too_early = _outcome_body()
    too_early["started_at_ms"] = admitted["body"]["timestamp_ms"] - 1
    too_early["completed_at_ms"] = admitted["body"]["timestamp_ms"]
    too_early["execution_start_hash"] = strict_execution_start_v2_1_hash(
        {
            "tenant_id": too_early["tenant_id"],
            "session_id": too_early["session_id"],
            "action_id": too_early["action_id"],
            "decision_receipt_hash": too_early["decision_receipt_hash"],
            "operation_fingerprint": too_early["operation_fingerprint"],
            "attempt": 1,
            "started_at_ms": too_early["started_at_ms"],
        }
    )
    with pytest.raises(ValueError, match="does not bind"):
        sign_strict_execution_outcome_v2_1(too_early, signer, admitted)


def test_integrity_remains_distinct_from_external_decision_trust(signer):
    admitted = _decision(signer)
    envelope = sign_strict_execution_outcome_v2_1(_outcome_body(), signer, admitted)
    result = verify_strict_execution_outcome_v2_1(
        envelope, admitted, **_trust(trusted_agent_keys=[])
    )
    assert result["integrity_valid"]
    assert not result["decision_trusted"]
    assert not result["trusted"]
