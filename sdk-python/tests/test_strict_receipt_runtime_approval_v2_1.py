import copy
import json

import pytest

from obsvr.action_context_v2 import action_target_hash
from obsvr.device_identity import load_device_signer
from obsvr.intent_alignment_v2 import intent_policy_v2_hash
from obsvr.strict_admission_v2_1 import STRICT_RECEIPT_V2_1_ADMISSION_SCHEMA
from obsvr.strict_evaluation_evidence_v2_1 import (
    create_trusted_evaluation_evidence_provider_v2_1,
)
from obsvr.strict_identity_evidence_v2_1 import (
    create_strict_identity_evidence_v2_1_authority,
)
from obsvr.strict_receipt_coordinator_v2_1 import (
    StrictReceiptCoordinatorV21,
    create_trusted_intent_decision_provider_v2_1,
)
from obsvr.strict_receipt_runtime_v2_1 import (
    StrictReceiptRuntimeV21,
    StrictReceiptRuntimeV21Error,
    bind_strict_v2_1_json_arguments,
)
from obsvr.strict_receipt_v2_1 import strict_receipt_v2_1_key_id

B = "b" * 64
C = "c" * 64
TARGET = action_target_hash("prod")
POLICY = {
    "schema": "obsvr-intent-policy-v2",
    "profile_version": "2.0",
    "intent_scopes": [
        {
            "intent_id": "deploy",
            "allowed_actions": [{"kind": "tool", "name": "send"}],
            "allowed_targets": ["prod"],
            "allowed_requested_scopes": ["write"],
            "allowed_data_classifications": ["confidential"],
        }
    ],
}


def _decision(action_id, arguments_hash):
    return {
        "action_id": action_id,
        "active_intents": ["deploy"],
        "current_action": {
            "kind": "tool",
            "name": "send",
            "arguments_hash": arguments_hash,
            "target_hash": TARGET,
            "data_classifications": ["confidential"],
            "requested_scopes": ["write"],
        },
        "run_id": "run-1",
        "thread_id": "thread-1",
    }


class Store:
    def __init__(self):
        self.checkpoints = []

    def save(self, checkpoint):
        self.checkpoints.append(copy.deepcopy(checkpoint))


def _setup(tmp_path, base, approval_verifier):
    path = tmp_path / "runtime-approval-v21-seed.key"
    path.write_text("00" * 32, encoding="ascii")
    signer = load_device_signer(str(path))
    subject = StrictReceiptCoordinatorV21(
        signer=signer,
        policy=POLICY,
        tenant_id="tenant-1",
        session_id="session-1",
        sdk_language="python",
        clock=lambda: 1_000,
        defer_ttl_ms=500,
        identity_authority=create_strict_identity_evidence_v2_1_authority(),
        identity_snapshot=lambda timestamp: {
            "schema": "obsvr-strict-identity-evidence-v2-1",
            "profile_version": "2.1",
            "relationship": "direct",
            "receipt_time_ms": timestamp,
            "requester": {
                "requester_ref_hash": B,
                "principal_type": "agent",
                "role_ids": ["worker"],
                "privilege_scopes": ["write"],
            },
            "initiator": {
                "agent_ref_hash": B,
                "key_id": strict_receipt_v2_1_key_id(signer.raw_public_key),
                "role_ids": ["worker"],
                "privilege_scopes": ["write"],
            },
            "delegation_chain": [],
        },
        intent_decision_provider=create_trusted_intent_decision_provider_v2_1(
            lambda _context: copy.deepcopy(base)
        ),
        evaluation_evidence_provider=(
            create_trusted_evaluation_evidence_provider_v2_1(
                lambda: {
                    "effective_policy": {
                        "version": "policy-1",
                        "artifact_hash": intent_policy_v2_hash(POLICY),
                        "matched_rule_ids": ["deploy"],
                    },
                    "detector_requirements": [],
                    "detector_results": [],
                }
            )
        ),
        approval_verifier=approval_verifier,
        pid=lambda: 7,
        prepared_token_factory=lambda: "prepared-token",
    )
    store = Store()

    def transport(_target, headers, _body, _timeout, _limit):
        receipt_hash = headers["Idempotency-Key"]
        body = json.dumps(
            {
                "schema": STRICT_RECEIPT_V2_1_ADMISSION_SCHEMA,
                "ok": True,
                "status": "accepted",
                "receipt_hash": receipt_hash,
                "accepted_at_ms": 10,
            }
        ).encode()
        return 200, body

    runtime = StrictReceiptRuntimeV21(
        coordinator=subject,
        admission_config={
            "ingest_url": "https://example.com",
            "api_key": "key",
            "max_attempts": 1,
            "resolver": lambda _host: ["8.8.8.8"],
            "trusted_pinned_transport": transport,
        },
        checkpoint_store=store,
    )
    return runtime, store


def _verifier(evidence, expected):
    if evidence.get("token") != "trusted-secret":
        raise ValueError("untrusted approval")
    return {
        "request_id": expected["request_id"],
        "action_hash": expected["action_hash"],
        "principal_id": "reviewer-1",
        "decision": expected["decision"],
        "source_hash": C,
        "expires_at_ms": 1_400,
    }


def _suspend(runtime, bound, action_id, request_id):
    result = runtime.run_decision(
        decision=_decision(action_id, bound.arguments_hash),
        action={
            "runtime_action_id": action_id,
            "original_arguments": bound,
            "invoke": lambda _value: pytest.fail("suspended action must not run"),
        },
    )
    assert result["status"] == "nonexecuted"
    assert result["receipt"]["body"]["suspension"]["suspension_id"] == request_id
    return result


def test_approval_resolution_executes_exact_suspended_action_once(tmp_path):
    bound = bind_strict_v2_1_json_arguments({"message": "approved"})
    runtime, store = _setup(tmp_path, {
        "action_taken": "blocked", "approval_required": True,
        "approval_request_id": "approval-1",
        "approval_action_hash": bound.arguments_hash,
        "approval_expires_at_ms": 1_500,
    }, _verifier)
    suspended = _suspend(runtime, bound, "approved-action", "approval-1")
    invokes = []
    resolution = {"suspended_receipt_hash": suspended["receipt_hash"],
        "method": "approval_granted",
        "approval_evidence": {"token": "trusted-secret"}}
    action = {"original_arguments": bound,
        "invoke": lambda value: invokes.append(value) or value["message"]}
    result = runtime.run_approval(resolution=resolution, action=action)
    assert result["status"] == "executed"
    assert result["value"] == "approved"
    assert result["receipt"]["body"]["record_type"] == "resolution"
    assert result["receipt"]["body"]["resolution"][
        "resolves_receipt_hash"] == suspended["receipt_hash"]
    assert result["receipt"]["body"]["resolution"][
        "approval_evidence_hash"] == C
    assert result["execution_outcome"]["body"][
        "decision_receipt_hash"] == result["receipt_hash"]
    assert invokes == [{"message": "approved"}]
    checkpoints = [item for item in store.checkpoints
        if item["receipt"]["body"]["record_type"] == "resolution"]
    assert [item["phase"] for item in checkpoints] == [
        "prepared", "remote_accepted", "committed", "invocation_started", "terminal"]
    assert "trusted-secret" not in json.dumps(checkpoints)
    assert runtime.run_approval(resolution=resolution, action=action) is result
    assert invokes == [{"message": "approved"}]
    with pytest.raises(StrictReceiptRuntimeV21Error, match="different approval input"):
        runtime.run_approval(resolution={**resolution,
            "approval_evidence": {"token": "different"}}, action=action)


def test_approval_denial_is_admitted_without_invocation(tmp_path):
    bound = bind_strict_v2_1_json_arguments({"message": "denied"})
    runtime, _store = _setup(tmp_path, {
        "action_taken": "blocked", "approval_required": True,
        "approval_request_id": "approval-2",
        "approval_action_hash": bound.arguments_hash,
        "approval_expires_at_ms": 1_500,
    }, lambda _evidence, expected: {
        "request_id": expected["request_id"], "action_hash": expected["action_hash"],
        "principal_id": "reviewer-1", "decision": expected["decision"],
        "source_hash": C, "expires_at_ms": 1_400})
    suspended = _suspend(runtime, bound, "denied-action", "approval-2")
    invokes = []
    denied = runtime.run_approval(resolution={
        "suspended_receipt_hash": suspended["receipt_hash"],
        "method": "approval_denied", "approval_evidence": {"token": "denied"}},
        action={"original_arguments": bound,
            "invoke": lambda _value: invokes.append(True)})
    assert denied["status"] == "nonexecuted"
    assert denied["reason"] == "not_authorized"
    assert denied["receipt"]["body"]["record_type"] == "resolution"
    assert denied["receipt"]["body"]["outcome"] == "DENY"
    assert invokes == []
