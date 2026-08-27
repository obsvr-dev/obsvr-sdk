"""Authenticated profile-2.1 recovery and reconciliation tests."""

import copy
import json

import pytest

from obsvr.action_context_v2 import action_target_hash
from obsvr.device_identity import load_device_signer
from obsvr.intent_alignment_v2 import intent_policy_v2_hash
from obsvr.strict_evaluation_evidence_v2_1 import (
    create_trusted_evaluation_evidence_provider_v2_1,
)
from obsvr.strict_identity_evidence_v2_1 import (
    create_strict_identity_evidence_v2_1_authority,
)
from obsvr.strict_receipt_coordinator_v2_1 import (
    create_trusted_intent_decision_provider_v2_1,
)
from obsvr.strict_receipt_coordinator_v2_1_recovery import (
    RecoverableStrictReceiptCoordinatorV21,
)
from obsvr.strict_receipt_reconcile_v2_1 import reconcile_strict_receipt_v2_1
from obsvr.strict_receipt_v2_1 import strict_receipt_v2_1_key_id

A = "a" * 64
B = "b" * 64
TARGET = action_target_hash("prod")
PARITY_RECEIPT_HASH = "2f22fc808f9ddb6f49f3c853bec7c57c32bc26a1a325089bb2044cfc5556ff1c"
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


def make_signer(tmp_path, seed="00"):
    path = tmp_path / f"v21-recovery-{seed}.key"
    path.write_text(seed * 32, encoding="ascii")
    return load_device_signer(str(path))


def action(action_id="action-1"):
    return {
        "action_id": action_id,
        "active_intents": ["deploy"],
        "current_action": {
            "kind": "tool",
            "name": "send",
            "arguments_hash": A,
            "target_hash": TARGET,
            "data_classifications": ["confidential"],
            "requested_scopes": ["write"],
        },
        "run_id": "run-1",
        "thread_id": "thread-1",
    }


def options(device_signer, pid=7):
    return {
        "signer": device_signer,
        "policy": POLICY,
        "tenant_id": "tenant-1",
        "session_id": "session-1",
        "sdk_language": "python",
        "sdk_version": "0.11.2",
        "clock": lambda: 1_000,
        "defer_ttl_ms": 500,
        "identity_authority": create_strict_identity_evidence_v2_1_authority(),
        "identity_snapshot": lambda timestamp: {
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
                "key_id": strict_receipt_v2_1_key_id(device_signer.raw_public_key),
                "role_ids": ["worker"],
                "privilege_scopes": ["write"],
            },
            "delegation_chain": [],
        },
        "intent_decision_provider": create_trusted_intent_decision_provider_v2_1(
            lambda _context: {"action_taken": "allowed"}
        ),
        "evaluation_evidence_provider": (
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
        "pid": lambda: pid,
        "prepared_token_factory": lambda: "prepared-token",
    }


def transport(status, value, captured=None):
    def call(target, headers, body, _timeout, _limit):
        if captured is not None:
            captured.update(target=target, headers=headers, body=json.loads(body))
        return status, json.dumps(value).encode()

    return call


def test_restore_blocks_and_only_exact_accepted_commits(tmp_path):
    signer = make_signer(tmp_path)
    original = RecoverableStrictReceiptCoordinatorV21(**options(signer))
    committed = original.prepare_decision(action())
    assert committed["receipt_hash"] == PARITY_RECEIPT_HASH
    original.commit_prepared(committed["token"], committed["receipt_hash"])
    prepared = original.prepare_decision(action("pending"))
    checkpoint = original.export_recovery_checkpoint()
    assert {
        "hash": checkpoint["checkpoint_hash"],
        "signature": checkpoint["signature"]["value"],
    } == {
        "hash": "19883b822ca1dac5f1a04570fd4138e5952201f2275e94e838276c9dc1fbbbab",
        "signature": (
            "bef41c34e306df6a1a2c2f93841bcb83efccd61f898da4ac88e89e2125a93ef5"
            "bfc639da0d8cd83a427c63704d94f4157dd7fde119d8b471c9df0b40616b470c"
        ),
    }
    restored = RecoverableStrictReceiptCoordinatorV21(
        **options(signer),
        recovery_checkpoint=checkpoint,
        expected_origin_pid=7,
    )
    assert (
        checkpoint["document"]["prepared"]["result"]["receipt"]["receipt_hash"]
        == prepared["receipt_hash"]
    )
    assert restored.inspect_state()["sequence"] == 1
    assert restored.inspect_state()["head_receipt_hash"] == committed["receipt_hash"]
    assert restored.inspect_state()["freeze_reason"] == (
        "restart_reconciliation_required"
    )
    with pytest.raises(ValueError, match="requires accepted reconciliation"):
        restored.prepare_decision(action("other"))
    receipt = checkpoint["document"]["prepared"]["result"]["receipt"]
    absent = reconcile_strict_receipt_v2_1(
        receipt,
        ingest_url="http://127.0.0.1:8080",
        api_key="test",
        max_attempts=1,
        resolver=lambda *_args: ["127.0.0.1"],
        trusted_pinned_transport=transport(
            404,
            {
                "schema": "obsvr-strict-receipt-reconciliation-v2-1",
                "ok": True,
                "status": "absent",
                "session_id": "session-1",
                "receipt_hash": receipt["receipt_hash"],
            },
        ),
    )
    with pytest.raises(ValueError, match="trusted accepted"):
        restored.reconcile_recovered_accepted(absent)
    captured = {}
    accepted = reconcile_strict_receipt_v2_1(
        receipt,
        ingest_url="http://127.0.0.1:8080",
        api_key="test",
        max_attempts=1,
        resolver=lambda *_args: ["127.0.0.1"],
        trusted_pinned_transport=transport(
            200,
            {
                "schema": "obsvr-strict-receipt-reconciliation-v2-1",
                "ok": True,
                "status": "accepted",
                "session_id": "session-1",
                "receipt_hash": receipt["receipt_hash"],
                "accepted_at_ms": 2_000,
            },
            captured,
        ),
    )
    assert captured["target"].parts.path.endswith(
        "/ingest/strict-receipts/v2-1/reconcile"
    )
    assert captured["headers"]["Idempotency-Key"] == receipt["receipt_hash"]
    assert captured["body"] == {
        "schema": "obsvr-strict-receipt-ingest-v2-1",
        "tenant_id": "tenant-1",
        "session_id": "session-1",
        "receipt": receipt,
    }
    assert restored.reconcile_recovered_accepted(accepted) == receipt
    assert restored.inspect_state()["sequence"] == 2
    next_receipt = restored.prepare_decision(action("next"))["value"]["receipt"]
    assert next_receipt["body"]["sequence"] == 3
    assert next_receipt["body"]["previous_receipt_hash"] == receipt["receipt_hash"]


def test_restore_rejects_tamper_key_binding_and_pid(tmp_path):
    signer = make_signer(tmp_path)
    subject = RecoverableStrictReceiptCoordinatorV21(**options(signer))
    subject.prepare_decision(action())
    checkpoint = subject.export_recovery_checkpoint()
    changed = copy.deepcopy(checkpoint)
    changed["document"]["tenant_id"] = "evil"
    with pytest.raises(ValueError):
        RecoverableStrictReceiptCoordinatorV21(
            **options(signer), recovery_checkpoint=changed, expected_origin_pid=7
        )
    with pytest.raises(ValueError, match="invalid checkpoint envelope"):
        RecoverableStrictReceiptCoordinatorV21(
            **options(make_signer(tmp_path, "01")),
            recovery_checkpoint=checkpoint,
            expected_origin_pid=7,
        )
    wrong_tenant = options(signer)
    wrong_tenant["tenant_id"] = "other"
    with pytest.raises(ValueError, match="tenant/session/sdk/profile"):
        RecoverableStrictReceiptCoordinatorV21(
            **wrong_tenant, recovery_checkpoint=checkpoint, expected_origin_pid=7
        )
    for field, value in (("session_id", "other"), ("sdk_version", "other")):
        wrong_binding = options(signer)
        wrong_binding[field] = value
        with pytest.raises(ValueError, match="tenant/session/sdk/profile"):
            RecoverableStrictReceiptCoordinatorV21(
                **wrong_binding,
                recovery_checkpoint=checkpoint,
                expected_origin_pid=7,
            )
    wrong_profile = copy.deepcopy(checkpoint)
    wrong_profile["document"]["profile_version"] = "2.0"
    with pytest.raises(ValueError):
        RecoverableStrictReceiptCoordinatorV21(
            **options(signer),
            recovery_checkpoint=wrong_profile,
            expected_origin_pid=7,
        )
    with pytest.raises(ValueError, match="origin PID"):
        RecoverableStrictReceiptCoordinatorV21(
            **options(signer), recovery_checkpoint=checkpoint, expected_origin_pid=8
        )


@pytest.mark.parametrize(
    "status,value", [(409, {}), (200, {"schema": "wrong"}), (503, {})]
)
def test_nonaccepted_reconciliation_stays_frozen(tmp_path, status, value):
    signer = make_signer(tmp_path)
    original = RecoverableStrictReceiptCoordinatorV21(**options(signer))
    original.prepare_decision(action())
    checkpoint = original.export_recovery_checkpoint()
    restored = RecoverableStrictReceiptCoordinatorV21(
        **options(signer), recovery_checkpoint=checkpoint, expected_origin_pid=7
    )
    receipt = checkpoint["document"]["prepared"]["result"]["receipt"]
    result = reconcile_strict_receipt_v2_1(
        receipt,
        ingest_url="http://127.0.0.1:8080",
        api_key="test",
        max_attempts=1,
        resolver=lambda *_args: ["127.0.0.1"],
        trusted_pinned_transport=transport(status, value),
    )
    assert result.value["status"] != "accepted"
    with pytest.raises(ValueError, match="trusted accepted"):
        restored.reconcile_recovered_accepted(result)
    assert restored.inspect_state()["frozen"] is True


def test_restores_approval_without_persisting_raw_evidence(tmp_path):
    signer = make_signer(tmp_path)
    times = iter((1_000, 1_100))
    approval_options = options(signer)
    approval_options["clock"] = lambda: next(times)
    approval_options["intent_decision_provider"] = (
        create_trusted_intent_decision_provider_v2_1(
            lambda _context: {
                "action_taken": "blocked",
                "approval_required": True,
                "approval_request_id": "approval-1",
                "approval_action_hash": A,
                "approval_expires_at_ms": 1_500,
            }
        )
    )
    approval_options["approval_verifier"] = lambda _evidence, expected: {
        "request_id": expected["request_id"],
        "action_hash": expected["action_hash"],
        "principal_id": "reviewer-1",
        "decision": expected["decision"],
        "source_hash": B,
        "expires_at_ms": 1_400,
    }
    original = RecoverableStrictReceiptCoordinatorV21(**approval_options)
    pending = original.prepare_decision(action("approval-action"))
    original.commit_prepared(pending["token"], pending["receipt_hash"])
    prepared = original.prepare_approval_resolution(
        {
            "suspended_receipt_hash": pending["receipt_hash"],
            "method": "approval_granted",
            "approval_evidence": {"token": "must-not-persist"},
        }
    )
    checkpoint = original.export_recovery_checkpoint()
    assert checkpoint["document"]["prepared"]["kind"] == "resolution"
    assert "must-not-persist" not in json.dumps(checkpoint)
    restored = RecoverableStrictReceiptCoordinatorV21(
        **approval_options, recovery_checkpoint=checkpoint, expected_origin_pid=7
    )
    receipt = prepared["value"]
    accepted = reconcile_strict_receipt_v2_1(
        receipt,
        ingest_url="http://127.0.0.1:8080",
        api_key="test",
        max_attempts=1,
        resolver=lambda *_args: ["127.0.0.1"],
        trusted_pinned_transport=transport(
            200,
            {
                "schema": "obsvr-strict-receipt-reconciliation-v2-1",
                "ok": True,
                "status": "accepted",
                "session_id": "session-1",
                "receipt_hash": receipt["receipt_hash"],
                "accepted_at_ms": 2_000,
            },
        ),
    )
    assert restored.reconcile_recovered_accepted(accepted) == receipt
    assert restored.inspect_state()["sequence"] == 2
    assert restored.inspect_state()["head_receipt_hash"] == receipt["receipt_hash"]
    with pytest.raises(ValueError, match="already resolved"):
        restored.prepare_approval_resolution(
            {
                "suspended_receipt_hash": pending["receipt_hash"],
                "method": "approval_granted",
                "approval_evidence": {},
            }
        )
