import json

import pytest

from obsvr.coverage_attestation import sign_coverage_attestation
from obsvr.deployment_proof_client import (
    DeploymentProofPublishError,
    publish_deployment_proofs,
)
from obsvr.device_identity import load_device_signer
from obsvr.workload_registry_v1 import sign_workload_registration_v1


def _proofs(tmp_path):
    path = tmp_path / "key"
    path.write_text("33" * 32)
    signer = load_device_signer(str(path))
    now = 1_788_131_200_000
    coverage = sign_coverage_attestation(
        {
            "attestation_id": "att-1",
            "workload_id": "contract-ai",
            "environment": "production",
            "sdk_language": "python",
            "sdk_version": "0.17.0",
            "generated_at_ms": now,
            "valid_until_ms": now + 60_000,
            "required": [],
            "policy_pack_hashes": ["a" * 64],
        },
        signer,
        {},
    )
    workload = sign_workload_registration_v1(
        {
            "workload_id": "contract-ai",
            "owner_ref_hash": "b" * 64,
            "environment": "production",
            "deployment_id": "deploy-1",
            "autonomy": "supervised",
            "entry_points": ["contract.review"],
            "capabilities": ["control"],
            "providers": ["openai"],
            "models": ["gpt-5"],
            "tools": ["send_email"],
            "mcp_servers": [],
            "data_zones": ["contracts"],
            "external_side_effects": ["email"],
            "required_approvals": ["send_email"],
            "policy_pack_hashes": ["a" * 64],
            "coverage_attestation_hash": coverage["body_hash"],
            "registered_at_ms": now,
        },
        signer,
    )
    return signer, coverage, workload


def test_publishes_exact_coverage_before_workload_over_pinned_requests(tmp_path):
    signer, coverage, workload = _proofs(tmp_path)
    requests = []

    def transport(target, headers, body, _timeout, _limit):
        requests.append((target.parts.path, headers, json.loads(body)))
        if target.parts.path.endswith("/coverage/attestations"):
            payload = {
                "ok": True,
                "body_hash": coverage["body_hash"],
                "coverage_complete": True,
                "trust": "pinned",
            }
        else:
            payload = {
                "ok": True,
                "body_hash": workload["body_hash"],
                "workload_id": "contract-ai",
                "deployment_id": "deploy-1",
                "trust": "pinned",
            }
        return 202, json.dumps(payload).encode()

    result = publish_deployment_proofs(
        coverage,
        workload,
        ingest_url="https://ingest.example.test/base",
        api_key="api-test",
        signer=signer,
        resolver=lambda _host: ["8.8.8.8"],
        trusted_pinned_transport=transport,
    )
    assert result == {
        "coverage": {
            "disposition": "accepted",
            "kind": "coverage",
            "body_hash": coverage["body_hash"],
            "trust": "pinned",
        },
        "workload": {
            "disposition": "accepted",
            "kind": "workload",
            "body_hash": workload["body_hash"],
            "trust": "pinned",
        },
    }
    assert [item[0] for item in requests] == [
        "/base/coverage/attestations",
        "/base/workloads/registrations",
    ]
    assert requests[0][1]["X-API-Key"] == "api-test"
    assert requests[0][1]["X-Obsvr-Device-Public-Key"] == signer.public_key_b64
    assert requests[0][1]["Idempotency-Key"] == coverage["body_hash"]
    assert requests[0][2] == coverage


def test_rejected_coverage_prevents_workload_registration(tmp_path):
    signer, coverage, workload = _proofs(tmp_path)
    paths = []

    def transport(target, _headers, _body, _timeout, _limit):
        paths.append(target.parts.path)
        return 403, json.dumps(
            {"ok": False, "error": "coverage_key_revoked"}
        ).encode()

    result = publish_deployment_proofs(
        coverage,
        workload,
        ingest_url="https://ingest.example.test",
        api_key="api-test",
        signer=signer,
        resolver=lambda _host: ["8.8.8.8"],
        trusted_pinned_transport=transport,
    )
    assert result["coverage"]["disposition"] == "rejected"
    assert result["coverage"]["http_status"] == 403
    assert result["workload"]["disposition"] == "not_attempted"
    assert paths == ["/coverage/attestations"]


def test_refuses_mismatched_bindings_and_unsafe_endpoint_before_transport(tmp_path):
    signer, coverage, workload = _proofs(tmp_path)
    workload["body"]["coverage_attestation_hash"] = "f" * 64
    calls = []

    def transport(*_args):
        calls.append(True)

    with pytest.raises(DeploymentProofPublishError, match="same coverage hash"):
        publish_deployment_proofs(
            coverage,
            workload,
            ingest_url="https://ingest.example.test",
            api_key="api-test",
            signer=signer,
            resolver=lambda _host: ["8.8.8.8"],
            trusted_pinned_transport=transport,
        )
    with pytest.raises(DeploymentProofPublishError, match="static security"):
        publish_deployment_proofs(
            coverage,
            None,
            ingest_url="http://169.254.169.254",
            api_key="api-test",
            signer=signer,
            trusted_pinned_transport=transport,
        )
    assert calls == []
