import copy
import json
from pathlib import Path

from obsvr.coverage_attestation import (
    build_coverage_attestation_body,
    coverage_attestation_body_hash,
    sign_coverage_attestation,
    verify_coverage_attestation,
)
from obsvr.device_identity import load_device_signer


FIXTURE = json.loads(
    (
        Path(__file__).parents[2]
        / "conformance"
        / "fixtures"
        / "coverage_attestation.json"
    ).read_text()
)


def _snapshot():
    out = {}
    for binding in FIXTURE["bindings"]:
        entry = {
            "bound": binding["bound"],
            "enforcement_depth": binding["enforcement_depth"],
            "exclusions": binding["exclusions"],
        }
        for field in ("integration_version", "initialized_at_ms"):
            if field in binding:
                entry[field] = binding[field]
        out.setdefault(binding["integration"], {})[binding["symbol"]] = entry
    return out


def test_pins_canonical_body_and_reports_insufficient_enforcement_depth():
    body = build_coverage_attestation_body(FIXTURE["input"], _snapshot())
    assert coverage_attestation_body_hash(body) == FIXTURE["expected_body_hash"]
    assert body["coverage_complete"] is False
    assert body["failures"] == [
        {
            "integration": "langchain.models",
            "symbol": "langchain.callbacks",
            "reason": "insufficient_depth",
            "required_depth": "enforce",
            "actual_depth": "observe",
        }
    ]


def test_signs_verifies_and_detects_tampering(tmp_path):
    key_path = tmp_path / "key"
    key_path.write_text("00" * 32)
    signer = load_device_signer(str(key_path))
    envelope = sign_coverage_attestation(FIXTURE["input"], signer, _snapshot())
    assert verify_coverage_attestation(envelope, signer.raw_public_key) == {
        "valid": True,
        "reason": "valid",
        "body_hash": FIXTURE["expected_body_hash"],
    }
    tampered = copy.deepcopy(envelope)
    tampered["body"]["workload_id"] = "other-worker"
    assert verify_coverage_attestation(tampered, signer.raw_public_key)["reason"] == (
        "body_hash_mismatch"
    )


def test_legacy_unknown_depth_is_not_enforcement_coverage():
    snapshot = _snapshot()
    snapshot["action:contract.send"]["contract.send"]["enforcement_depth"] = (
        "unknown"
    )
    body = build_coverage_attestation_body(FIXTURE["input"], snapshot)
    assert {
        "integration": "action:contract.send",
        "symbol": "contract.send",
        "reason": "insufficient_depth",
        "required_depth": "enforce",
        "actual_depth": "unknown",
    } in body["failures"]


def test_rejects_extra_fields_and_rewritten_derived_coverage_results(tmp_path):
    key_path = tmp_path / "key"
    key_path.write_text("00" * 32)
    signer = load_device_signer(str(key_path))
    envelope = sign_coverage_attestation(FIXTURE["input"], signer, _snapshot())

    extra = copy.deepcopy(envelope)
    extra["body"]["trusted"] = True
    assert verify_coverage_attestation(extra, signer.raw_public_key) == {
        "valid": False,
        "reason": "invalid_body",
    }

    rewritten = copy.deepcopy(envelope)
    rewritten["body"]["coverage_complete"] = True
    rewritten["body"]["failures"] = []
    assert verify_coverage_attestation(rewritten, signer.raw_public_key) == {
        "valid": False,
        "reason": "invalid_body",
    }
