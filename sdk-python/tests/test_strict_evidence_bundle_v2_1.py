"""Cross-language and adversarial tests for portable strict evidence bundles."""

import copy
import json
from pathlib import Path

import pytest

from obsvr.device_identity import load_device_signer
from obsvr.strict_evidence_bundle_v2_1 import (
    create_strict_evidence_bundle_v2_1,
    verify_strict_evidence_bundle_v2_1,
)
from obsvr.strict_execution_outcome_v2_1 import (
    sign_strict_execution_outcome_v2_1,
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


def _signer(tmp_path, seed_hex=None):
    seed = tmp_path / f"seed-{(seed_hex or 'public')[:8]}.key"
    seed.write_text(
        seed_hex or DECISION["public_test_key"]["seed_hex"], encoding="ascii"
    )
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


def _trust():
    return {
        "trusted_agent_keys": [
            {
                "tenant_id": "tenant-21",
                "agent_ref_hash": "b" * 64,
                "key_id": DECISION["public_test_key"]["key_id"],
                "public_key_b64": DECISION["public_test_key"]["public_key_b64"],
                "status": "active",
            }
        ],
        "allowed_evaluator_manifest_hashes": [
            DECISION["evaluator_manifest_hash"]
        ],
    }


def _evidence(tmp_path):
    signer = _signer(tmp_path)
    receipt = sign_strict_receipt_v2_1(_decision_body(), signer)
    outcome = sign_strict_execution_outcome_v2_1(
        copy.deepcopy(OUTCOME["vector"]["body"]), signer, receipt
    )
    return signer, receipt, outcome


def test_complete_portable_bundle_is_pinned_across_languages(tmp_path):
    signer, receipt, outcome = _evidence(tmp_path)
    bundle = create_strict_evidence_bundle_v2_1(
        [receipt], [outcome], signer, **_trust()
    )
    assert bundle["body"]["complete"]
    assert bundle["body"]["head_receipt_hash"] == receipt["receipt_hash"]
    assert bundle["body"]["coverage"] == [
        {
            "sequence": 1,
            "receipt_hash": receipt["receipt_hash"],
            "record_type": "decision",
            "execution_authorized": True,
            "execution_status": "succeeded",
            "outcome_hash": outcome["outcome_hash"],
        }
    ]
    assert bundle["body"]["policy_continuity"]["receipt_count"] == 1
    verified = verify_strict_evidence_bundle_v2_1(bundle, **_trust())
    assert verified["trusted"] and verified["complete"]
    assert verified["errors"] == []
    assert (
        bundle["bundle_hash"]
        == "bb61c84ef82eb3f93d1c68a4c7c8c97d3ad285e0a879f0fda233f7adbe23ed8c"
    )
    assert bundle["signature"]["value"] == (
        "256d1046b8ae2610d32204f7c0789446a657b0662baf9fa2cbc9aabaccfe3a640"
        "72ee74079e32c558942da7439e3b8f4f942a053eb7c5b865343dcc085da250e"
    )


def test_missing_outcome_remains_visible_in_a_trusted_bundle(tmp_path):
    signer, receipt, _ = _evidence(tmp_path)
    bundle = create_strict_evidence_bundle_v2_1([receipt], [], signer, **_trust())
    assert bundle["body"]["coverage"][0]["execution_status"] == "missing"
    verified = verify_strict_evidence_bundle_v2_1(bundle, **_trust())
    assert verified["trusted"] and not verified["complete"]


def test_tampering_and_wrong_head_signer_are_rejected(tmp_path):
    signer, receipt, outcome = _evidence(tmp_path)
    bundle = create_strict_evidence_bundle_v2_1(
        [receipt], [outcome], signer, **_trust()
    )
    tampered = copy.deepcopy(bundle)
    tampered["body"]["coverage"][0]["execution_status"] = "failed"
    assert not verify_strict_evidence_bundle_v2_1(tampered, **_trust())["trusted"]
    wrong = _signer(
        tmp_path,
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    )
    with pytest.raises(ValueError, match="must match the head receipt signer"):
        create_strict_evidence_bundle_v2_1(
            [receipt], [outcome], wrong, **_trust()
        )


def test_hostile_component_and_envelope_mutations_are_rejected(tmp_path):
    signer, receipt, outcome = _evidence(tmp_path)
    bundle = create_strict_evidence_bundle_v2_1(
        [receipt], [outcome], signer, **_trust()
    )

    receipt_tamper = copy.deepcopy(bundle)
    receipt_tamper["body"]["receipts"][0]["body"]["action"]["name"] = (
        "substituted_action"
    )
    verified = verify_strict_evidence_bundle_v2_1(receipt_tamper, **_trust())
    assert not verified["trusted"] and not verified["complete"]
    assert "bundle_components_untrusted" in verified["errors"]

    outcome_tamper = copy.deepcopy(bundle)
    value = outcome_tamper["body"]["execution_outcomes"][0]["signature"]["value"]
    outcome_tamper["body"]["execution_outcomes"][0]["signature"]["value"] = (
        ("1" if value[0] == "0" else "0") + value[1:]
    )
    verified = verify_strict_evidence_bundle_v2_1(outcome_tamper, **_trust())
    assert not verified["trusted"]
    assert "bundle_components_untrusted" in verified["errors"]

    extra_envelope_key = copy.deepcopy(bundle)
    extra_envelope_key["unexpected"] = True
    verified = verify_strict_evidence_bundle_v2_1(extra_envelope_key, **_trust())
    assert not verified["schema_valid"] and not verified["trusted"]

    extra_body_key = copy.deepcopy(bundle)
    extra_body_key["body"]["unexpected"] = True
    verified = verify_strict_evidence_bundle_v2_1(extra_body_key, **_trust())
    assert not verified["semantic_valid"] and not verified["trusted"]

    malformed_key = copy.deepcopy(bundle)
    malformed_key["public_key_b64"] = "not-a-public-key"
    verified = verify_strict_evidence_bundle_v2_1(malformed_key, **_trust())
    assert not verified["schema_valid"]
    assert not verified["signature_valid"]
    assert not verified["signer_binding_valid"]
    assert not verified["trusted"]

    malformed_signature = copy.deepcopy(bundle)
    malformed_signature["signature"]["value"] = "00"
    verified = verify_strict_evidence_bundle_v2_1(
        malformed_signature, **_trust()
    )
    assert not verified["schema_valid"]
    assert not verified["signature_valid"]
    assert not verified["trusted"]


def test_duplicate_foreign_partial_and_untrusted_evidence_is_refused(tmp_path):
    signer, receipt, outcome = _evidence(tmp_path)
    with pytest.raises(ValueError, match="duplicate execution outcomes"):
        create_strict_evidence_bundle_v2_1(
            [receipt], [outcome, copy.deepcopy(outcome)], signer, **_trust()
        )

    foreign = copy.deepcopy(outcome)
    foreign["body"]["decision_receipt_hash"] = "f" * 64
    with pytest.raises(ValueError, match="outside the bundle"):
        create_strict_evidence_bundle_v2_1(
            [receipt], [foreign], signer, **_trust()
        )

    partial_body = _decision_body()
    partial_body["sequence"] = 2
    partial_body["previous_receipt_hash"] = receipt["receipt_hash"]
    partial = sign_strict_receipt_v2_1(partial_body, signer)
    with pytest.raises(ValueError, match="receipt chain is not trusted"):
        create_strict_evidence_bundle_v2_1(
            [partial], [], signer, **_trust()
        )

    bundle = create_strict_evidence_bundle_v2_1(
        [receipt], [outcome], signer, **_trust()
    )
    verified = verify_strict_evidence_bundle_v2_1(
        bundle,
        trusted_agent_keys=[],
        allowed_evaluator_manifest_hashes=_trust()[
            "allowed_evaluator_manifest_hashes"
        ],
    )
    assert not verified["trusted"] and not verified["complete"]
    verified = verify_strict_evidence_bundle_v2_1(
        bundle,
        trusted_agent_keys=_trust()["trusted_agent_keys"],
        allowed_evaluator_manifest_hashes=[],
    )
    assert not verified["trusted"] and not verified["complete"]
