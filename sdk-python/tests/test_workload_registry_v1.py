import copy

import pytest

from obsvr.device_identity import load_device_signer
from obsvr.workload_registry_v1 import WorkloadRegistryV1, build_workload_registration_v1, sign_workload_registration_v1, verify_workload_registration_v1, workload_registration_v1_hash

REGISTRATION = {"workload_id": "spotdraft-contract-ai", "owner_ref_hash": "1" * 64, "environment": "production", "deployment_id": "deploy-7", "autonomy": "supervised", "entry_points": ["contract.review"], "capabilities": ["contract.read", "contract.redline"], "providers": ["openai"], "models": ["gpt-5"], "tools": ["contract.send"], "mcp_servers": [], "data_zones": ["customer-contracts"], "external_side_effects": ["email.send"], "required_approvals": ["external-send"], "policy_pack_hashes": ["2" * 64], "coverage_attestation_hash": "3" * 64, "registered_at_ms": 1_788_131_200_000}


def test_is_content_addressed_consistently():
    assert workload_registration_v1_hash(REGISTRATION) == "47df34cfc47fe72aaa57abc64d0c55854708aee7ee775141e7de09351b58db0e"
    assert build_workload_registration_v1({**REGISTRATION, "capabilities": ["contract.redline", "contract.read"]}) == build_workload_registration_v1(REGISTRATION)


def test_accepts_only_signed_registrations_and_detects_tampering(tmp_path):
    path = tmp_path / "key"
    path.write_text("11" * 32)
    signer = load_device_signer(str(path))
    envelope = sign_workload_registration_v1(REGISTRATION, signer)
    assert verify_workload_registration_v1(envelope, signer.raw_public_key)
    registry = WorkloadRegistryV1()
    registry.register(envelope, signer.raw_public_key)
    assert len(registry.snapshot()) == 1
    tampered = copy.deepcopy(envelope)
    tampered["body"]["autonomy"] = "autonomous"
    assert not verify_workload_registration_v1(tampered, signer.raw_public_key)


def test_rejects_raw_inventory_fields_and_empty_control_bindings():
    with pytest.raises(ValueError, match="unsupported field"):
        build_workload_registration_v1({**REGISTRATION, "prompt": "secret"})
    with pytest.raises(ValueError, match="must be nonempty"):
        build_workload_registration_v1({**REGISTRATION, "policy_pack_hashes": []})
