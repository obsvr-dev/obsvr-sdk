"""Focused tests for trusted profile-2.1 decision coordination."""

import copy

import pytest

from obsvr.action_context_v2 import action_target_hash
from obsvr.device_identity import DeviceSigner, load_device_signer
from obsvr.intent_alignment_v2 import intent_policy_v2_hash
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
from obsvr.strict_receipt_prepared_state import DEFINITIVE_NO_STORE
from obsvr.strict_receipt_v2_1 import strict_receipt_v2_1_key_id

A = "a" * 64
B = "b" * 64
C = "c" * 64
D = "d" * 64
TARGET = action_target_hash("prod")
PARITY_HASH = "2f22fc808f9ddb6f49f3c853bec7c57c32bc26a1a325089bb2044cfc5556ff1c"
PARITY_SIGNATURE = (
    "9be900fe817f00b5ac06c319a5591a1b91272950630d2bfed21540c75655352b"
    "1f8ffd47f13c46fd3a7ce9da4277bf55cdce926a9513fd488b95c4caf37f750f"
)
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
    path = tmp_path / f"v21-coordinator-{seed}.key"
    path.write_text(seed * 32, encoding="ascii")
    return load_device_signer(str(path))


def identity(timestamp, device_signer):
    return {
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
    }


def action(action_id="action-1", active_intents=None):
    return {
        "action_id": action_id,
        "active_intents": active_intents or ["deploy"],
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


def evaluation_snapshot(**overrides):
    snapshot = {
        "effective_policy": {
            "version": "policy-1",
            "artifact_hash": intent_policy_v2_hash(POLICY),
            "matched_rule_ids": ["deploy"],
        },
        "detector_requirements": [],
        "detector_results": [],
    }
    snapshot.update(overrides)
    return snapshot


def coordinator(
    tmp_path,
    *,
    clock=lambda: 1_000,
    base=None,
    snapshot=None,
    device_signer=None,
    identity_snapshot=None,
    tenant_id="tenant-1",
    pid=lambda: 7,
):
    signer = device_signer or make_signer(tmp_path)
    base_result = base or {"action_taken": "allowed"}
    evidence = snapshot or evaluation_snapshot()
    return StrictReceiptCoordinatorV21(
        signer=signer,
        policy=POLICY,
        tenant_id=tenant_id,
        session_id="session-1",
        sdk_language="python",
        clock=clock,
        defer_ttl_ms=500,
        identity_authority=create_strict_identity_evidence_v2_1_authority(),
        identity_snapshot=lambda timestamp: (identity_snapshot or identity)(
            timestamp, signer
        ),
        intent_decision_provider=(
            create_trusted_intent_decision_provider_v2_1(
                lambda _context: copy.deepcopy(base_result)
            )
        ),
        evaluation_evidence_provider=(
            create_trusted_evaluation_evidence_provider_v2_1(
                lambda: copy.deepcopy(evidence)
            )
        ),
        pid=pid,
        prepared_token_factory=lambda: "prepared-token",
    )


def test_derives_identity_and_rejects_caller_authority_fields(tmp_path):
    subject = coordinator(tmp_path)
    for field in (
        "agent_id",
        "requester",
        "roles",
        "delegation",
        "session_id",
        "prior_actions",
        "base_result",
        "policy_version",
        "rule_ids",
        "evaluator",
        "detectors",
    ):
        forged = {**action(), field: "forged"}
        with pytest.raises(ValueError, match=f"unsupported field: {field}"):
            subject.prepare_decision(forged)
    prepared = subject.prepare_decision(action())
    assert prepared["value"]["action_context"]["agent"] == {
        "agent_id": B,
        "active_intents": ["deploy"],
        "role": "worker",
        "privilege_scope": ["write"],
    }
    assert (
        prepared["value"]["receipt"]["body"]["identity"]["initiator"]["agent_ref_hash"]
        == B
    )
    assert '"target":"prod"' not in str(prepared)


def test_binds_policy_rules_signer_and_reason(tmp_path):
    wrong_policy = evaluation_snapshot(
        effective_policy={
            "version": "policy-1",
            "artifact_hash": C,
            "matched_rule_ids": ["deploy"],
        }
    )
    with pytest.raises(ValueError, match="artifact_hash does not match"):
        coordinator(tmp_path, snapshot=wrong_policy).prepare_decision(action())
    wrong_rules = evaluation_snapshot(
        effective_policy={
            "version": "policy-1",
            "artifact_hash": intent_policy_v2_hash(POLICY),
            "matched_rule_ids": [],
        }
    )
    with pytest.raises(ValueError, match="matched_rule_ids do not match"):
        coordinator(tmp_path, snapshot=wrong_rules).prepare_decision(action())
    wrong = make_signer(tmp_path, "01")
    with pytest.raises(ValueError, match="signer does not match"):
        coordinator(
            tmp_path,
            identity_snapshot=lambda timestamp, _signer: identity(timestamp, wrong),
        ).prepare_decision(action())
    prepared = coordinator(tmp_path).prepare_decision(action())
    assert prepared["value"]["intent_evaluation"]["reason_code"] == ("intent_aligned")
    assert prepared["value"]["evaluation_evidence"]["decision_reason_codes"] == [
        "intent_aligned"
    ]
    assert prepared["value"]["receipt"]["body"]["evaluation"][
        "decision_reason_codes"
    ] == ["intent_aligned"]


def test_detector_fail_close_controls_authorization(tmp_path):
    evaluation_outage = evaluation_snapshot(
        detector_requirements=[
            {
                "detector_id": "pii",
                "detector_manifest_hash": C,
                "required": True,
                "purpose": "evaluation",
            }
        ],
        detector_results=[],
    )
    deferred = coordinator(tmp_path, snapshot=evaluation_outage).prepare_decision(
        action()
    )["value"]["receipt"]["body"]
    assert deferred["outcome"] == "DEFER"
    assert deferred["execution_authorized"] is False
    assert deferred["evaluation"]["requested_outcome"] == "ALLOW"
    assert deferred["evaluation"]["reason_code"] == ("required_detector_uncertain")
    assert deferred["suspension"]["type"] == "context"

    transform_outage = evaluation_snapshot(
        detector_requirements=[
            {
                "detector_id": "redactor",
                "detector_manifest_hash": C,
                "required": True,
                "purpose": "transform",
            }
        ],
        detector_results=[],
    )
    denied = coordinator(
        tmp_path,
        base={"action_taken": "redacted", "modified_arguments_hash": D},
        snapshot=transform_outage,
    ).prepare_decision(action())["value"]["receipt"]["body"]
    assert denied["outcome"] == "DENY"
    assert denied["execution_authorized"] is False
    assert denied["evaluation"]["requested_outcome"] == "MODIFY"
    assert denied["evaluation"]["reason_code"] == ("required_transform_unavailable")
    assert "effective_arguments_hash" not in denied["action"]


def test_modify_approval_and_context_suspension(tmp_path):
    modified = coordinator(
        tmp_path,
        base={"action_taken": "redacted", "modified_arguments_hash": D},
    ).prepare_decision(action())["value"]["receipt"]["body"]
    assert modified["outcome"] == "MODIFY"
    assert modified["execution_authorized"] is True
    assert modified["action"]["effective_arguments_hash"] == D

    approval = coordinator(
        tmp_path,
        base={
            "action_taken": "blocked",
            "approval_required": True,
            "approval_request_id": "approval-1",
            "approval_action_hash": A,
            "approval_expires_at_ms": 1_500,
        },
    ).prepare_decision(action())["value"]["receipt"]["body"]
    assert approval["outcome"] == "STEP_UP"
    assert approval["execution_authorized"] is False
    assert approval["suspension"] == {
        "suspension_id": "approval-1",
        "type": "approval",
        "expires_at_ms": 1_500,
    }

    deferred = coordinator(tmp_path).prepare_decision(
        action("defer", ["deploy", "other"])
    )["value"]["receipt"]["body"]
    assert deferred["outcome"] == "DEFER"
    assert deferred["execution_authorized"] is False
    assert deferred["suspension"]["type"] == "context"
    assert deferred["suspension"]["expires_at_ms"] == 1_500


def test_two_phase_state_retry_and_approval_reuse(tmp_path):
    base = {
        "action_taken": "blocked",
        "approval_required": True,
        "approval_request_id": "approval-1",
        "approval_action_hash": A,
        "approval_expires_at_ms": 1_500,
    }
    subject = coordinator(tmp_path, base=base)
    first = subject.prepare_decision(action("one"))
    assert subject.prepare_decision(action("one")) == first
    assert subject.inspect_state()["sequence"] == 0
    assert subject.inspect_state()["head_receipt_hash"] is None
    with pytest.raises(ValueError, match="token mismatch"):
        subject.commit_prepared("wrong", first["receipt_hash"])
    with pytest.raises(ValueError, match="hash mismatch"):
        subject.commit_prepared(first["token"], C)
    subject.commit_prepared(first["token"], first["receipt_hash"])
    assert subject.inspect_state()["sequence"] == 1
    assert subject.inspect_state()["head_receipt_hash"] == first["receipt_hash"]
    with pytest.raises(ValueError, match="already committed"):
        subject.prepare_decision(action("one"))
    with pytest.raises(ValueError, match="already pending"):
        subject.prepare_decision(action("two"))


def test_sequence_linking_and_freeze(tmp_path):
    times = iter((1_000, 1_001))
    subject = coordinator(tmp_path, clock=lambda: next(times))
    first = subject.prepare_decision(action("one"))
    subject.commit_prepared(first["token"], first["receipt_hash"])
    second = subject.prepare_decision(action("two"))
    assert second["value"]["receipt"]["body"]["sequence"] == 2
    assert second["value"]["receipt"]["body"]["timestamp_ms"] == 1_001
    assert (
        second["value"]["receipt"]["body"]["previous_receipt_hash"]
        == first["receipt_hash"]
    )
    subject.freeze_prepared(second["token"], second["receipt_hash"], "lost_ack")
    with pytest.raises(ValueError, match="frozen"):
        subject.prepare_decision(action("two"))


def test_abort_capability_and_tenant_binding(tmp_path):
    subject = coordinator(tmp_path)
    prepared = subject.prepare_decision(action())
    with pytest.raises(ValueError, match="definitive_no_store"):
        subject.abort_prepared(prepared["token"], prepared["receipt_hash"], object())
    subject.abort_prepared(
        prepared["token"], prepared["receipt_hash"], DEFINITIVE_NO_STORE
    )
    assert "prepared" not in subject.inspect_state()
    left = coordinator(tmp_path, tenant_id="tenant-1").prepare_decision(action())[
        "value"
    ]["receipt"]
    right = coordinator(tmp_path, tenant_id="tenant-2").prepare_decision(action())[
        "value"
    ]["receipt"]
    assert left["receipt_hash"] == PARITY_HASH
    assert left["signature"]["value"] == PARITY_SIGNATURE
    assert left["receipt_hash"] != right["receipt_hash"]


def test_state_survives_clock_signer_and_process_failures(tmp_path):
    times = iter((1_000, 999))
    subject = coordinator(tmp_path, clock=lambda: next(times))
    first = subject.prepare_decision(action("one"))
    subject.commit_prepared(first["token"], first["receipt_hash"])
    with pytest.raises(ValueError, match="clock regressed"):
        subject.prepare_decision(action("two"))
    assert subject.inspect_state()["sequence"] == 1
    assert subject.inspect_state()["head_receipt_hash"] == first["receipt_hash"]
    assert "prepared" not in subject.inspect_state()

    valid = make_signer(tmp_path, "02")
    broken = DeviceSigner(lambda _message: bytes(64), valid.raw_public_key)
    unsigned = coordinator(tmp_path, device_signer=broken)
    with pytest.raises(ValueError, match="self-verification"):
        unsigned.prepare_decision(action())
    assert unsigned.inspect_state()["sequence"] == 0
    assert unsigned.inspect_state()["head_receipt_hash"] is None
    assert "prepared" not in unsigned.inspect_state()

    process = [7]
    forked = coordinator(tmp_path, pid=lambda: process[0])
    process[0] = 8
    with pytest.raises(ValueError, match="process boundary"):
        forked.prepare_decision(action())
