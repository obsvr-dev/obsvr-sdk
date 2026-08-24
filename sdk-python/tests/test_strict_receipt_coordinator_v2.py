"""Focused tests for tenant-bound two-phase strict v2 coordination."""

import json

import pytest

from obsvr.device_identity import DeviceSigner, load_device_signer
from obsvr.strict_receipt_coordinator_v2 import StrictReceiptCoordinatorV2
from obsvr.strict_receipt_coordinator_v2_support import (
    decision_v2_fingerprint,
    resolution_v2_fingerprint,
    timeout_v2_fingerprint,
)
from obsvr.strict_receipt_prepared_state import DEFINITIVE_NO_STORE
from obsvr.strict_receipt_v2_verify import (
    verify_strict_receipt_v2,
    verify_strict_receipt_v2_chain,
)

A = "a" * 64
B = "b" * 64
D = "d" * 64
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
    path = tmp_path / f"v2-coordinator-{seed}.key"
    path.write_text(seed * 32, encoding="ascii")
    return load_device_signer(str(path))


def context(arguments_hash=A):
    return {
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
        "thread_id": "thread-1",
    }


def coordinator(tmp_path, clock, signer=None, **extras):
    def verifier(evidence, expected):
        if not isinstance(evidence, dict) or evidence.get("token") != "trusted":
            raise ValueError("untrusted approval evidence")
        return {
            "request_id": expected["request_id"],
            "action_hash": expected["action_hash"],
            "principal_id": "reviewer-1",
            "decision": expected["decision"],
            "source_hash": D,
            "expires_at_ms": evidence["expires_at_ms"],
        }

    return StrictReceiptCoordinatorV2(
        signer=signer or make_signer(tmp_path),
        policy=POLICY,
        sdk_language="python",
        sdk_version="0.test",
        tenant_id="tenant-1",
        session_id="session-1",
        clock=clock,
        defer_ttl_ms=500,
        approval_verifier=verifier,
        **extras,
    )


def prepare(subject, action_id, base_result, arguments_hash=A):
    return subject.prepare_decision(
        context=context(arguments_hash),
        base_result=base_result,
        policy_version="policy-1",
        rule_ids=["rule-b", "rule-a"],
        action_id=action_id,
    )


def test_v2_only_tenant_binding_and_commit_boundary(tmp_path):
    signer = make_signer(tmp_path)
    subject = coordinator(tmp_path, lambda: 1000, signer)
    first = prepare(subject, "action-1", {"action_taken": "allowed"})
    assert subject.inspect_state()["sequence"] == 0
    body = first["value"]["receipt"]["body"]
    assert body["schema"] == "obsvr-strict-receipt-v2"
    assert body["profile_version"] == "2.0"
    assert body["tenant_id"] == "tenant-1"
    assert body["evaluation"]["engine_version"] == "obsvr-intent/2"
    assert "target_hash" in body["action"]
    assert '"target":"prod"' not in json.dumps(first, separators=(",", ":"))
    axes = verify_strict_receipt_v2(
        first["value"]["receipt"],
        pinned_public_key_b64=signer.public_key_b64,
    )
    assert all(
        axes[key]
        for key in (
            "schema_valid",
            "hash_valid",
            "signature_valid",
            "semantic_valid",
            "identity_binding_valid",
        )
    )
    assert prepare(subject, "action-1", {"action_taken": "allowed"}) == first
    subject.commit_prepared(first["token"], first["receipt_hash"])
    assert subject.inspect_state()["sequence"] == 1
    with pytest.raises(ValueError, match="already committed"):
        prepare(subject, "action-1", {"action_taken": "allowed"})


def test_monotonic_time_and_chain_linkage(tmp_path):
    signer = make_signer(tmp_path)
    times = iter((1000, 900))
    subject = coordinator(tmp_path, lambda: next(times), signer)
    first = prepare(subject, "one", {"action_taken": "allowed"})
    one = subject.commit_prepared(first["token"], first["receipt_hash"])
    second = prepare(subject, "two", {"action_taken": "blocked"}, B)
    two = subject.commit_prepared(second["token"], second["receipt_hash"])
    assert two["receipt"]["body"]["timestamp_ms"] == 1000
    assert two["receipt"]["body"]["clock_regression_clamped"] is True
    assert two["receipt"]["body"]["previous_receipt_hash"] == first["receipt_hash"]
    assert verify_strict_receipt_v2_chain(
        [one["receipt"], two["receipt"]],
        pinned_public_key_b64=signer.public_key_b64,
    ) == {"valid": True, "errors": []}


def test_trusted_approval_and_exact_prepared_retry(tmp_path):
    signer = make_signer(tmp_path)
    times = iter((1000, 1100, 1100))
    subject = coordinator(tmp_path, lambda: next(times), signer)
    pending = prepare(
        subject,
        "approval",
        {
            "action_taken": "blocked",
            "approval_required": True,
            "approval_request_id": "request-1",
            "approval_action_hash": A,
            "approval_expires_at_ms": 1500,
        },
    )
    decision = subject.commit_prepared(pending["token"], pending["receipt_hash"])
    with pytest.raises(ValueError, match="untrusted approval evidence"):
        subject.prepare_resolution(
            suspended_receipt_hash=pending["receipt_hash"],
            method="approval_granted",
            context=context(),
            base_result={"action_taken": "allowed"},
            policy_version="policy-1",
            rule_ids=[],
            approval_evidence_value={"principal_id": "attacker"},
        )
    kwargs = {
        "suspended_receipt_hash": pending["receipt_hash"],
        "method": "approval_granted",
        "context": context(),
        "base_result": {"action_taken": "allowed"},
        "policy_version": "policy-1",
        "rule_ids": [],
        "approval_evidence_value": {"token": "trusted", "expires_at_ms": 1500},
    }
    resolution = subject.prepare_resolution(**kwargs)
    assert subject.prepare_resolution(**kwargs) == resolution
    resolved = subject.commit_prepared(resolution["token"], resolution["receipt_hash"])
    assert verify_strict_receipt_v2_chain(
        [decision["receipt"], resolved],
        pinned_public_key_b64=signer.public_key_b64,
    ) == {"valid": True, "errors": []}


def test_exact_expiry_abort_and_freeze(tmp_path):
    times = iter((1000, 1499, 1500, 1500))
    subject = coordinator(tmp_path, lambda: next(times))
    pending = prepare(
        subject,
        "approval",
        {
            "action_taken": "blocked",
            "approval_required": True,
            "approval_request_id": "request-1",
            "approval_action_hash": A,
            "approval_expires_at_ms": 1500,
        },
    )
    subject.commit_prepared(pending["token"], pending["receipt_hash"])
    with pytest.raises(ValueError, match="not expired"):
        subject.prepare_timeout(
            suspended_receipt_hash=pending["receipt_hash"],
            policy_version="policy-1",
            rule_ids=[],
        )
    timeout = subject.prepare_timeout(
        suspended_receipt_hash=pending["receipt_hash"],
        policy_version="policy-1",
        rule_ids=[],
    )
    assert timeout["value"]["body"]["resolution"]["method"] == "expired"
    subject.abort_prepared(
        timeout["token"], timeout["receipt_hash"], DEFINITIVE_NO_STORE
    )
    retry = subject.prepare_timeout(
        suspended_receipt_hash=pending["receipt_hash"],
        policy_version="policy-1",
        rule_ids=[],
    )
    subject.freeze_prepared(retry["token"], retry["receipt_hash"])
    with pytest.raises(ValueError, match="frozen"):
        subject.prepare_timeout(
            suspended_receipt_hash=pending["receipt_hash"],
            policy_version="policy-1",
            rule_ids=[],
        )


def test_approval_is_refused_at_exact_expiry_without_advancing(tmp_path):
    times = iter((1000, 1500))
    subject = coordinator(tmp_path, lambda: next(times))
    pending = prepare(
        subject,
        "approval",
        {
            "action_taken": "blocked",
            "approval_required": True,
            "approval_request_id": "request-1",
            "approval_action_hash": A,
            "approval_expires_at_ms": 1500,
        },
    )
    subject.commit_prepared(pending["token"], pending["receipt_hash"])
    with pytest.raises(ValueError, match="expired"):
        subject.prepare_resolution(
            suspended_receipt_hash=pending["receipt_hash"],
            method="approval_granted",
            context=context(),
            base_result={"action_taken": "allowed"},
            policy_version="policy-1",
            rule_ids=[],
            approval_evidence_value={"token": "trusted", "expires_at_ms": 1500},
        )
    assert subject.inspect_state()["sequence"] == 1
    assert "prepared" not in subject.inspect_state()


def test_history_duplicate_approval_and_prepared_state_drift(tmp_path):
    subject = coordinator(tmp_path, lambda: 1000)
    with pytest.raises(ValueError, match="caller session_id"):
        subject.prepare_decision(
            context={**context(), "session_id": "caller"},
            base_result={"action_taken": "allowed"},
            policy_version="p",
            rule_ids=[],
            action_id="bad",
        )
    with pytest.raises(ValueError, match="caller prior_actions"):
        subject.prepare_decision(
            context={**context(), "prior_actions": []},
            base_result={"action_taken": "allowed"},
            policy_version="p",
            rule_ids=[],
            action_id="bad",
        )
    first = prepare(
        subject,
        "one",
        {
            "action_taken": "blocked",
            "approval_required": True,
            "approval_request_id": "request-1",
            "approval_action_hash": A,
            "approval_expires_at_ms": 1500,
        },
    )
    with pytest.raises(ValueError, match="token mismatch"):
        subject.commit_prepared("wrong", first["receipt_hash"])
    with pytest.raises(ValueError, match="hash mismatch"):
        subject.commit_prepared(first["token"], B)
    with pytest.raises(ValueError, match="different receipt"):
        prepare(subject, "two", {"action_taken": "allowed"})
    subject.commit_prepared(first["token"], first["receipt_hash"])
    with pytest.raises(ValueError, match="already pending"):
        prepare(
            subject,
            "two",
            {
                "action_taken": "blocked",
                "approval_required": True,
                "approval_request_id": "request-1",
                "approval_action_hash": A,
                "approval_expires_at_ms": 1500,
            },
        )


def test_defer_resolution_validation_and_raw_target_absence(tmp_path):
    times = iter((1000, 1100, 1100))
    subject = coordinator(tmp_path, lambda: next(times))
    pending = prepare(subject, "defer", {"action_taken": "hook_error"})
    subject.commit_prepared(pending["token"], pending["receipt_hash"])
    with pytest.raises(ValueError, match="outside required_fields"):
        subject.prepare_resolution(
            suspended_receipt_hash=pending["receipt_hash"],
            method="context_supplied",
            context={**context(), "thread_id": "changed"},
            base_result={"action_taken": "allowed"},
            policy_version="p",
            rule_ids=[],
            resolver_principal_id="reviewer",
            resolution_source_hash=D,
        )
    resolved = subject.prepare_resolution(
        suspended_receipt_hash=pending["receipt_hash"],
        method="context_supplied",
        context=context(),
        base_result={"action_taken": "allowed"},
        policy_version="p",
        rule_ids=[],
        resolver_principal_id="reviewer",
        resolution_source_hash=D,
    )
    assert resolved["value"]["body"]["evaluation"]["outcome"] == "ALLOW"
    assert '"target":"prod"' not in json.dumps(resolved, separators=(",", ":"))


def test_resolution_identity_target_outcome_and_source_drift(tmp_path):
    subject = coordinator(tmp_path, lambda: 1100)
    pending = prepare(
        subject,
        "approval",
        {
            "action_taken": "blocked",
            "approval_required": True,
            "approval_request_id": "request-1",
            "approval_action_hash": A,
            "approval_expires_at_ms": 1500,
        },
    )
    subject.commit_prepared(pending["token"], pending["receipt_hash"])

    def approval(**overrides):
        value = {
            "suspended_receipt_hash": pending["receipt_hash"],
            "method": "approval_granted",
            "context": context(),
            "base_result": {"action_taken": "allowed"},
            "policy_version": "p",
            "rule_ids": [],
            "approval_evidence_value": {
                "token": "trusted",
                "expires_at_ms": 1500,
            },
        }
        value.update(overrides)
        return value

    with pytest.raises(ValueError, match="does not match"):
        subject.prepare_resolution(
            **approval(context={**context(), "agent_id": "other"})
        )
    with pytest.raises(ValueError, match="does not match"):
        subject.prepare_resolution(
            **approval(
                context={
                    **context(),
                    "current_action": {
                        **context()["current_action"],
                        "target": "other",
                    },
                }
            )
        )
    with pytest.raises(ValueError, match="approval source"):
        subject.prepare_resolution(**approval(resolver_principal_id="caller"))
    with pytest.raises(ValueError, match="requires DENY"):
        subject.prepare_resolution(
            **approval(
                method="approval_denied", base_result={"action_taken": "allowed"}
            )
        )
    with pytest.raises(ValueError, match="requires DENY"):
        subject.prepare_resolution(
            **approval(
                method="cancelled",
                base_result={"action_taken": "allowed"},
                approval_evidence_value=None,
                resolver_principal_id="reviewer",
                resolution_source_hash=D,
            )
        )


def test_tenant_bound_fingerprints_and_process_refusal(tmp_path):
    decision = {
        "context": context(),
        "base_result": {"action_taken": "allowed"},
        "policy_version": "p",
        "rule_ids": [],
        "action_id": "one",
    }
    assert decision_v2_fingerprint(
        input_value=decision, tenant_id="tenant-a", session_id="session-1"
    ) != decision_v2_fingerprint(
        input_value=decision, tenant_id="tenant-b", session_id="session-1"
    )
    resolution = {
        "suspended_receipt_hash": A,
        "method": "cancelled",
        "context": context(),
        "base_result": {"action_taken": "blocked"},
        "policy_version": "p",
        "rule_ids": [],
        "resolver_principal_id": "reviewer",
        "resolution_source_hash": D,
    }
    assert resolution_v2_fingerprint(
        input_value=resolution, tenant_id="tenant-a", session_id="session-1"
    ) != resolution_v2_fingerprint(
        input_value=resolution, tenant_id="tenant-b", session_id="session-1"
    )
    timeout = {"suspended_receipt_hash": A, "policy_version": "p", "rule_ids": []}
    assert timeout_v2_fingerprint(
        input_value=timeout, tenant_id="tenant-a", session_id="session-1"
    ) != timeout_v2_fingerprint(
        input_value=timeout, tenant_id="tenant-b", session_id="session-1"
    )
    pid = [1]
    subject = coordinator(tmp_path, lambda: 1000, pid=lambda: pid[0])
    pid[0] = 2
    with pytest.raises(ValueError, match="process boundary"):
        subject.inspect_state()


def test_signer_failure_does_not_reserve_sequence_or_chain_state(tmp_path):
    valid = make_signer(tmp_path)
    broken = DeviceSigner(lambda _message: bytes(64), valid.raw_public_key)
    subject = coordinator(tmp_path, lambda: 1000, broken)
    with pytest.raises(ValueError, match="self-verification"):
        prepare(subject, "one", {"action_taken": "allowed"})
    assert subject.inspect_state()["sequence"] == 0
    assert subject.inspect_state()["head_receipt_hash"] is None
    assert "prepared" not in subject.inspect_state()
