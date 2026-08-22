"""Idempotency, concurrency, and lifecycle tests for the strict runtime."""

import threading

import pytest

from obsvr.strict_receipt_runtime import StrictReceiptRuntime
from tests.strict_receipt_runtime_support import (
    HASH_A,
    accepted,
    action,
    context,
    coordinator,
    decision,
)


def test_provider_start_is_at_most_once_even_when_it_throws(tmp_path):
    state = coordinator(tmp_path, lambda: 1000)
    admissions = []
    invocations = []

    def admit(receipt, _config):
        admissions.append(receipt["receipt_hash"])
        return accepted(receipt["receipt_hash"])

    def invoke(_value):
        invocations.append("started")
        raise RuntimeError("provider failed after start")

    runtime = StrictReceiptRuntime(
        coordinator=state, admission=admit, admission_config=None
    )
    request = {
        "decision": decision("once", {"action_taken": "allowed"}),
        "action": action("once", invoke),
    }
    first = runtime.run_decision(**request)
    retry = runtime.run_decision(**request)
    assert first["status"] == "invocation_failed"
    assert retry == first
    assert retry["error"] is first["error"]
    assert invocations == ["started"]
    assert len(admissions) == 1


def test_changed_decision_fingerprint_fails_before_preparation(tmp_path):
    state = coordinator(tmp_path, lambda: 1000)
    admissions = []
    invocations = []

    def admit(receipt, _config):
        admissions.append(receipt["receipt_hash"])
        return accepted(receipt["receipt_hash"])

    runtime = StrictReceiptRuntime(
        coordinator=state, admission=admit, admission_config=None
    )
    runtime.run_decision(
        decision=decision("fingerprint", {"action_taken": "allowed"}),
        action=action("fingerprint", lambda _value: invocations.append("started")),
    )
    with pytest.raises(RuntimeError, match="reused with different input"):
        runtime.run_decision(
            decision=decision("fingerprint", {"action_taken": "blocked"}),
            action=action(
                "fingerprint", lambda _value: invocations.append("unexpected")
            ),
        )
    assert state.inspect_state()["sequence"] == 1
    assert len(admissions) == 1
    assert invocations == ["started"]


def test_changed_resolution_fingerprint_fails_before_preparation(tmp_path):
    times = iter([1000, 1100])
    state = coordinator(tmp_path, lambda: next(times))
    admissions = []

    def admit(receipt, _config):
        admissions.append(receipt["receipt_hash"])
        return accepted(receipt["receipt_hash"])

    runtime = StrictReceiptRuntime(
        coordinator=state, admission=admit, admission_config=None
    )
    pending = runtime.run_decision(
        decision=decision(
            "resolution-fingerprint",
            {
                "action_taken": "blocked",
                "approval_required": True,
                "approval_request_id": "approval-1",
                "approval_action_hash": HASH_A,
                "approval_expires_at_ms": 1500,
            },
        ),
        action=action("resolution-fingerprint", lambda _value: None),
    )
    invocations = []
    request = {
        "suspended_receipt_hash": pending["receipt_hash"],
        "method": "approval_granted",
        "context": context(),
        "base_result": {"action_taken": "allowed"},
        "policy_version": "policy-1",
        "rule_ids": [],
        "approval_evidence_value": {
            "token": "trusted",
            "expires_at_ms": 1500,
        },
    }
    runtime.run_resolution(
        resolution=request,
        action=action(
            "resolution-fingerprint", lambda _value: invocations.append("started")
        ),
    )
    with pytest.raises(RuntimeError, match="reused with different input"):
        runtime.run_resolution(
            resolution={**request, "rule_ids": ["different"]},
            action=action(
                "resolution-fingerprint",
                lambda _value: invocations.append("unexpected"),
            ),
        )
    assert state.inspect_state()["sequence"] == 2
    assert len(admissions) == 2
    assert invocations == ["started"]


def test_caller_mutation_does_not_change_cached_receipt_or_status(tmp_path):
    state = coordinator(tmp_path, lambda: 1000)
    provider_value = {"provider": "value"}
    invocations = []
    runtime = StrictReceiptRuntime(
        coordinator=state,
        admission=lambda receipt, _config: accepted(receipt["receipt_hash"]),
        admission_config=None,
    )
    request = {
        "decision": decision("mutation", {"action_taken": "allowed"}),
        "action": action(
            "mutation", lambda _value: invocations.append("started") or provider_value
        ),
    }
    first = runtime.run_decision(**request)
    first["receipt"]["body"]["action"]["name"] = "caller-mutation"
    first["status"] = "nonexecuted"
    retry = runtime.run_decision(**request)
    assert retry["status"] == "executed"
    assert retry["receipt"]["body"]["action"]["name"] == "send"
    assert retry["value"] is provider_value
    assert invocations == ["started"]


def test_concurrent_call_and_lost_ack_duplicate_fail_closed(tmp_path):
    state = coordinator(tmp_path, lambda: 1000)
    entered = threading.Event()
    release = threading.Event()
    admissions = []
    invocations = []

    def admit(receipt, _config):
        admissions.append(receipt["receipt_hash"])
        entered.set()
        release.wait(timeout=2)
        return {
            "disposition": "uncertain",
            "receipt_hash": receipt["receipt_hash"],
            "reason": "retry_exhausted",
            "attempts": 1,
        }

    runtime = StrictReceiptRuntime(
        coordinator=state, admission=admit, admission_config=None
    )
    request = {
        "decision": decision("lost-ack", {"action_taken": "allowed"}),
        "action": action("lost-ack", lambda value: invocations.append(value)),
    }
    output = []
    worker = threading.Thread(
        target=lambda: output.append(runtime.run_decision(**request))
    )
    worker.start()
    assert entered.wait(timeout=2)
    with pytest.raises(RuntimeError, match="runtime is busy"):
        runtime.run_decision(**request)
    release.set()
    worker.join(timeout=2)
    assert output[0]["reason"] == "admission_uncertain"
    with pytest.raises(ValueError, match="session is frozen"):
        runtime.run_decision(**request)
    assert len(admissions) == 1
    assert invocations == []


def test_resolution_and_timeout_are_admitted_before_execution(tmp_path):
    times = iter([1000, 1100])
    approval_state = coordinator(tmp_path, lambda: next(times))
    approval = StrictReceiptRuntime(
        coordinator=approval_state,
        admission=lambda receipt, _config: accepted(receipt["receipt_hash"]),
        admission_config=None,
    )
    pending = approval.run_decision(
        decision=decision(
            "approval",
            {
                "action_taken": "blocked",
                "approval_required": True,
                "approval_request_id": "approval-1",
                "approval_action_hash": HASH_A,
                "approval_expires_at_ms": 1500,
            },
        ),
        action=action("approval", lambda _value: None),
    )
    resolved = approval.run_resolution(
        resolution={
            "suspended_receipt_hash": pending["receipt_hash"],
            "method": "approval_granted",
            "context": context(),
            "base_result": {"action_taken": "allowed"},
            "policy_version": "policy-1",
            "rule_ids": [],
            "approval_evidence_value": {
                "token": "trusted",
                "expires_at_ms": 1500,
            },
        },
        action=action("approval", lambda _value: "resolved"),
    )
    assert resolved["status"] == "executed"
    assert resolved["value"] == "resolved"

    timeout_times = iter([1000, 1500])
    timeout_state = coordinator(tmp_path, lambda: next(timeout_times))
    timeout = StrictReceiptRuntime(
        coordinator=timeout_state,
        admission=lambda receipt, _config: accepted(receipt["receipt_hash"]),
        admission_config=None,
    )
    deferred = timeout.run_decision(
        decision=decision("timeout", {"action_taken": "hook_timeout"}),
        action=action("timeout", lambda _value: None),
    )
    timed_out = timeout.run_timeout(
        timeout={
            "suspended_receipt_hash": deferred["receipt_hash"],
            "policy_version": "policy-1",
            "rule_ids": [],
        }
    )
    assert timed_out["reason"] == "not_authorized"
    assert timeout_state.inspect_state()["sequence"] == 2
