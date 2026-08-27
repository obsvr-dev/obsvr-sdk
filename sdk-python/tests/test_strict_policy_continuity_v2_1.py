"""Policy timeline reconstruction tests for strict receipt profile 2.1."""

import copy
import json
from pathlib import Path

import pytest

from obsvr.device_identity import load_device_signer
from obsvr.strict_policy_continuity_v2_1 import (
    StrictPolicyContinuityV21Error,
    reconstruct_strict_policy_continuity_v2_1,
)
from obsvr.strict_receipt_v2_1 import sign_strict_receipt_v2_1

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = json.loads(
    (ROOT / "conformance/fixtures/strict_receipts_v2_1.json").read_text("utf-8")
)


@pytest.fixture()
def signer(tmp_path):
    seed = tmp_path / "public-test-seed.key"
    seed.write_text(FIXTURE["public_test_key"]["seed_hex"], encoding="ascii")
    return load_device_signer(str(seed))


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


def _policy_chain(signer):
    first = sign_strict_receipt_v2_1(
        copy.deepcopy(FIXTURE["vector"]["body"]), signer
    )
    following = copy.deepcopy(first["body"])
    following["receipt_id"] = "session-21:2"
    following["sequence"] = 2
    following["previous_receipt_hash"] = first["receipt_hash"]
    following["action"]["action_id"] = "action-22"
    following["evaluation"]["effective_policy"]["version"] = "policy-v2"
    following["evaluation"]["effective_policy"]["artifact_hash"] = "7" * 64
    return [first, sign_strict_receipt_v2_1(following, signer)]


def test_reconstructs_trusted_snapshots_and_explicit_transition(signer):
    receipts = _policy_chain(signer)
    report = reconstruct_strict_policy_continuity_v2_1(receipts, **_trust())

    assert report["schema"] == "obsvr-strict-policy-continuity-v2-1"
    assert report["profile_version"] == "2.1"
    assert report["tenant_id"] == "tenant-21"
    assert report["session_id"] == "session-21"
    assert report["first_sequence"] == 1
    assert report["last_sequence"] == 2
    assert report["receipt_count"] == 2
    assert [item["receipt_hash"] for item in report["snapshots"]] == [
        item["receipt_hash"] for item in receipts
    ]
    assert report["transitions"] == [
        {
            "at_sequence": 2,
            "receipt_hash": receipts[1]["receipt_hash"],
            "from_policy_version": FIXTURE["vector"]["body"]["evaluation"][
                "effective_policy"
            ]["version"],
            "from_policy_artifact_hash": FIXTURE["vector"]["body"]["evaluation"][
                "effective_policy"
            ]["artifact_hash"],
            "from_evaluator_manifest_hash": FIXTURE["evaluator_manifest_hash"],
            "to_policy_version": "policy-v2",
            "to_policy_artifact_hash": "7" * 64,
            "to_evaluator_manifest_hash": FIXTURE["evaluator_manifest_hash"],
        }
    ]
    assert (
        report["timeline_hash"]
        == "2f4fad842cd5798f9a1094c887b89d99a15ab46c848bd69882348f2c4fd2e34c"
    )


def test_refuses_incomplete_tampered_and_untrusted_histories(signer):
    receipts = _policy_chain(signer)
    with pytest.raises(StrictPolicyContinuityV21Error, match="empty_chain"):
        reconstruct_strict_policy_continuity_v2_1([], **_trust())
    with pytest.raises(
        StrictPolicyContinuityV21Error, match="sequence_order_invalid"
    ):
        reconstruct_strict_policy_continuity_v2_1([receipts[1]], **_trust())
    tampered = copy.deepcopy(receipts)
    tampered[1]["body"]["evaluation"]["effective_policy"][
        "version"
    ] = "quiet-rewrite"
    with pytest.raises(StrictPolicyContinuityV21Error, match="receipt_hash_invalid"):
        reconstruct_strict_policy_continuity_v2_1(tampered, **_trust())
    with pytest.raises(
        StrictPolicyContinuityV21Error, match="receipt_evaluator_untrusted"
    ):
        reconstruct_strict_policy_continuity_v2_1(
            receipts,
            **_trust(allowed_evaluator_manifest_hashes=[]),
        )
