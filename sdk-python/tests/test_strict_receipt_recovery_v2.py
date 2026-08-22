import copy
import json

import pytest

from obsvr.device_identity import load_device_signer
from obsvr.strict_receipt_coordinator_v2_recovery import (
    RecoverableStrictReceiptCoordinatorV2,
)
from obsvr.strict_receipt_reconcile_v2 import reconcile_strict_receipt_v2
from obsvr.strict_receipt_recovery_v2 import verify_strict_recovery_v2
from obsvr.strict_receipt_runtime_v2 import (
    StrictReceiptRuntimeV2,
    bind_strict_v2_json_arguments,
    create_trusted_strict_v2_admission,
)

A = "a" * 64
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


def signer(tmp_path):
    path = tmp_path / "recovery.key"
    path.write_text("00" * 32, encoding="ascii")
    return load_device_signer(str(path))


def options(device_signer, pid, tenant="tenant-1"):
    return {
        "signer": device_signer,
        "policy": POLICY,
        "sdk_language": "python",
        "sdk_version": "0.test",
        "tenant_id": tenant,
        "session_id": "session-1",
        "clock": lambda: 1000,
        "defer_ttl_ms": 500,
        "approval_verifier": lambda *_args: (_ for _ in ()).throw(ValueError("unused")),
        "pid": lambda: pid,
    }


def decision(arguments_hash=A):
    return {
        "context": {
            "agent_id": "agent-1",
            "active_intents": ["deploy"],
            "privilege_scope": ["write"],
            "current_action": {
                "kind": "tool",
                "name": "send",
                "arguments_hash": arguments_hash,
                "target": "prod",
                "requested_scopes": ["write"],
                "data_classifications": ["confidential"],
            },
            "run_id": "run-1",
        },
        "base_result": {"action_taken": "allowed"},
        "policy_version": "policy-1",
        "rule_ids": ["rule-1"],
        "action_id": "action-1",
    }


def response(value):
    return 200, json.dumps(value).encode()


def test_authenticated_restart_accept_commits_without_action_api(tmp_path):
    device_signer = signer(tmp_path)
    original = RecoverableStrictReceiptCoordinatorV2(**options(device_signer, 41))
    prepared = original.prepare_decision(**decision())
    checkpoint = original.export_recovery_checkpoint()
    serialized = json.dumps(checkpoint, separators=(",", ":"))
    assert '"target":"prod"' not in serialized
    assert "raw-arguments" not in serialized

    restored = RecoverableStrictReceiptCoordinatorV2(
        recovery_checkpoint=checkpoint,
        expected_origin_pid=41,
        **options(device_signer, 42),
    )
    assert restored.inspect_state()["frozen"] is True
    with pytest.raises(ValueError, match="requires reconciliation"):
        restored.prepare_decision(**decision())
    proof = reconcile_strict_receipt_v2(
        prepared["value"]["receipt"],
        ingest_url="https://example.com",
        api_key="key",
        max_attempts=1,
        resolver=lambda _host: ["8.8.8.8"],
        trusted_pinned_transport=lambda *_args: response(
            {
                "schema": "obsvr-strict-receipt-reconciliation-v2",
                "ok": True,
                "status": "accepted",
                "session_id": "session-1",
                "receipt_hash": prepared["receipt_hash"],
                "accepted_at_ms": 1010,
            }
        ),
    )
    assert (
        restored.reconcile_recovered_accepted(proof)["receipt_hash"]
        == prepared["receipt_hash"]
    )
    assert restored.inspect_state()["sequence"] == 1
    committed = verify_strict_recovery_v2(
        restored.export_recovery_checkpoint(), device_signer
    )
    assert "prepared" not in committed
    assert committed["origin_pid"] == 42


def test_runtime_persists_before_admission_commit_and_invoke(tmp_path):
    device_signer = signer(tmp_path)
    subject = RecoverableStrictReceiptCoordinatorV2(**options(device_signer, 1))
    bound = bind_strict_v2_json_arguments({"message": "safe"})
    events = []

    class Store:
        def save(self, checkpoint):
            document = verify_strict_recovery_v2(checkpoint, device_signer)
            events.append(
                "save-prepared" if "prepared" in document else "save-committed"
            )

    def admit(receipt, _config):
        events.append("admit")
        return {
            "schema": "obsvr-strict-receipt-admission-v2",
            "tenant_id": "tenant-1",
            "session_id": "session-1",
            "disposition": "accepted",
            "status": "accepted",
            "receipt_hash": receipt["receipt_hash"],
            "accepted_at_ms": 1001,
            "attempts": 1,
        }

    runtime = StrictReceiptRuntimeV2(
        coordinator=subject,
        admission_config={"ingest_url": "https://unused", "api_key": "key"},
        trusted_admission=create_trusted_strict_v2_admission(admit),
        recovery_store=Store(),
    )
    result = runtime.run_decision(
        decision=decision(bound.arguments_hash),
        action={
            "runtime_action_id": "action-1",
            "original_arguments": bound,
            "invoke": lambda _value: events.append("invoke") or "done",
        },
    )
    assert result["status"] == "executed"
    assert events == ["save-prepared", "admit", "save-committed", "invoke"]


def test_runtime_checkpoint_failure_aborts_before_admission(tmp_path):
    device_signer = signer(tmp_path)
    subject = RecoverableStrictReceiptCoordinatorV2(**options(device_signer, 1))
    bound = bind_strict_v2_json_arguments({"message": "safe"})
    calls = {"admit": 0, "invoke": 0}

    class Store:
        def save(self, _checkpoint):
            raise OSError("disk unavailable")

    def admit(_receipt, _config):
        calls["admit"] += 1
        raise AssertionError("must not admit")

    runtime = StrictReceiptRuntimeV2(
        coordinator=subject,
        admission_config={"ingest_url": "https://unused", "api_key": "key"},
        trusted_admission=create_trusted_strict_v2_admission(admit),
        recovery_store=Store(),
    )
    result = runtime.run_decision(
        decision=decision(bound.arguments_hash),
        action={
            "runtime_action_id": "action-1",
            "original_arguments": bound,
            "invoke": lambda _value: calls.__setitem__("invoke", calls["invoke"] + 1),
        },
    )
    assert result["reason"] == "recovery_persist_failed"
    assert calls == {"admit": 0, "invoke": 0}
    assert subject.inspect_state()["sequence"] == 0
    assert "prepared" not in subject.inspect_state()


def test_tamper_identity_drift_and_absent_stay_frozen(tmp_path):
    device_signer = signer(tmp_path)
    original = RecoverableStrictReceiptCoordinatorV2(**options(device_signer, 7))
    prepared = original.prepare_decision(**decision())
    checkpoint = original.export_recovery_checkpoint()
    tampered = copy.deepcopy(checkpoint)
    tampered["document"]["session_id"] = "other"
    with pytest.raises(ValueError):
        verify_strict_recovery_v2(tampered, device_signer)
    with pytest.raises(ValueError, match="origin PID"):
        RecoverableStrictReceiptCoordinatorV2(
            recovery_checkpoint=checkpoint,
            expected_origin_pid=9,
            **options(device_signer, 8),
        )
    with pytest.raises(ValueError, match="tenant/session/sdk"):
        RecoverableStrictReceiptCoordinatorV2(
            recovery_checkpoint=checkpoint,
            expected_origin_pid=7,
            **options(device_signer, 8, "other"),
        )
    restored = RecoverableStrictReceiptCoordinatorV2(
        recovery_checkpoint=checkpoint,
        expected_origin_pid=7,
        **options(device_signer, 8),
    )
    absent = reconcile_strict_receipt_v2(
        prepared["value"]["receipt"],
        ingest_url="https://example.com",
        api_key="key",
        max_attempts=1,
        resolver=lambda _host: ["8.8.8.8"],
        trusted_pinned_transport=lambda *_args: (
            404,
            json.dumps(
                {
                    "schema": "obsvr-strict-receipt-reconciliation-v2",
                    "ok": True,
                    "status": "absent",
                    "session_id": "session-1",
                    "receipt_hash": prepared["receipt_hash"],
                }
            ).encode(),
        ),
    )
    with pytest.raises(ValueError, match="trusted accepted"):
        restored.reconcile_recovered_accepted(absent)
    assert restored.inspect_state()["frozen"] is True
