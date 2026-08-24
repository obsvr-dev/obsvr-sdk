"""Adversarial orchestration tests for strict receipt admission and invocation."""

import pytest

from obsvr.strict_receipt_runtime import (
    STRICT_BOUND_ARGUMENTS,
    StrictReceiptRuntime,
)
from tests.strict_receipt_runtime_support import (
    HASH_A,
    HASH_B,
    HASH_D,
    accepted,
    action,
    context,
    coordinator,
    decision,
)


def test_exact_receipt_is_admitted_and_committed_before_invocation(tmp_path):
    events = []
    state = coordinator(tmp_path, lambda: 1000)

    def admit(receipt, config):
        events.append(f"admit:{config['marker']}:{state.inspect_state()['sequence']}")
        return accepted(receipt["receipt_hash"])

    runtime = StrictReceiptRuntime(
        coordinator=state,
        admission=admit,
        admission_config={"marker": "configured"},
    )

    def invoke(value):
        events.append(f"invoke:{state.inspect_state()['sequence']}")
        return value["value"]

    result = runtime.run_decision(
        decision=decision("allow", {"action_taken": "allowed"}),
        action=action("allow", invoke),
    )
    assert result["status"] == "executed"
    assert result["value"] == "original"
    assert events == ["admit:configured:0", "invoke:1"]


@pytest.mark.parametrize(
    "action_id,base_result",
    [
        ("deny", {"action_taken": "blocked"}),
        ("defer", {"action_taken": "hook_error"}),
        (
            "step",
            {
                "action_taken": "blocked",
                "approval_required": True,
                "approval_request_id": "approval-1",
                "approval_action_hash": HASH_A,
                "approval_expires_at_ms": 1500,
            },
        ),
    ],
)
def test_non_authorized_receipts_are_admitted_without_invocation(
    tmp_path, action_id, base_result
):
    state = coordinator(tmp_path, lambda: 1000)
    calls = []
    runtime = StrictReceiptRuntime(
        coordinator=state,
        admission=lambda receipt, _config: accepted(receipt["receipt_hash"]),
        admission_config=None,
    )
    result = runtime.run_decision(
        decision=decision(action_id, base_result),
        action=action(action_id, lambda value: calls.append(value)),
    )
    assert result["status"] == "nonexecuted"
    assert result["reason"] == "not_authorized"
    assert calls == []
    assert state.inspect_state()["sequence"] == 1


@pytest.mark.parametrize(
    "mode", ["definitive_no_store", "uncertain", "throw", "wrong_hash"]
)
def test_admission_failure_modes_never_invoke(tmp_path, mode):
    state = coordinator(tmp_path, lambda: 1000)
    calls = []

    def admit(receipt, _config):
        if mode == "throw":
            raise RuntimeError("lost acknowledgement")
        if mode == "wrong_hash":
            return accepted(HASH_B)
        if mode == "definitive_no_store":
            return {
                "disposition": "definitive_no_store",
                "receipt_hash": receipt["receipt_hash"],
                "http_status": 401,
                "attempts": 1,
            }
        return {
            "disposition": "uncertain",
            "receipt_hash": receipt["receipt_hash"],
            "reason": "retry_exhausted",
            "attempts": 3,
        }

    runtime = StrictReceiptRuntime(
        coordinator=state, admission=admit, admission_config=None
    )
    result = runtime.run_decision(
        decision=decision("blocked", {"action_taken": "allowed"}),
        action=action("blocked", lambda value: calls.append(value)),
    )
    assert result["status"] == "nonexecuted"
    assert calls == []
    assert state.inspect_state()["sequence"] == 0
    assert state.inspect_state()["frozen"] is (mode != "definitive_no_store")


def test_accepted_commit_failure_stays_frozen(tmp_path):
    state = coordinator(tmp_path, lambda: 1000)
    calls = []

    def admit(receipt, _config):
        def fail_commit(*_args):
            raise RuntimeError("commit storage failed")

        state._commit_decision = fail_commit
        return accepted(receipt["receipt_hash"])

    runtime = StrictReceiptRuntime(
        coordinator=state, admission=admit, admission_config=None
    )
    result = runtime.run_decision(
        decision=decision("commit-fail", {"action_taken": "allowed"}),
        action=action("commit-fail", lambda value: calls.append(value)),
    )
    assert result["status"] == "admitted"
    assert result["reason"] == "local_commit_failed"
    assert calls == []
    assert state.inspect_state()["freeze_reason"] == (
        "accepted_but_local_commit_failed"
    )


def test_modify_requires_trusted_effective_arguments(tmp_path):
    missing_state = coordinator(tmp_path, lambda: 1000)
    missing_calls = []
    missing_admissions = []
    missing = StrictReceiptRuntime(
        coordinator=missing_state,
        admission=lambda receipt, _config: (
            missing_admissions.append(receipt["receipt_hash"])
            or accepted(receipt["receipt_hash"])
        ),
        admission_config=None,
    )
    wrong_action = action("modify-missing", lambda value: missing_calls.append(value))
    wrong_action["effective_arguments"] = {
        "capability": STRICT_BOUND_ARGUMENTS,
        "arguments_hash": HASH_B,
        "value": {"value": "wrong-binding"},
    }
    missing_result = missing.run_decision(
        decision=decision(
            "modify-missing",
            {
                "action_taken": "redacted",
                "modified_arguments_hash": HASH_D,
            },
        ),
        action=wrong_action,
    )
    assert missing_result["reason"] == "effective_arguments_unavailable"
    assert missing_calls == []
    assert missing_admissions == []
    assert missing_state.inspect_state()["sequence"] == 0

    trusted_state = coordinator(tmp_path, lambda: 1000)
    trusted_calls = []
    trusted = StrictReceiptRuntime(
        coordinator=trusted_state,
        admission=lambda receipt, _config: accepted(receipt["receipt_hash"]),
        admission_config=None,
    )
    action_value = action(
        "modify-trusted", lambda value: trusted_calls.append(value) or value["value"]
    )
    action_value["effective_arguments"] = {
        "capability": STRICT_BOUND_ARGUMENTS,
        "arguments_hash": HASH_D,
        "value": {"value": "redacted"},
    }
    result = trusted.run_decision(
        decision=decision(
            "modify-trusted",
            {
                "action_taken": "redacted",
                "modified_arguments_hash": HASH_D,
            },
        ),
        action=action_value,
    )
    assert result["status"] == "executed"
    assert result["value"] == "redacted"
    assert trusted_calls == [{"value": "redacted"}]


@pytest.mark.parametrize("mode", ["missing", "untrusted", "mismatch"])
def test_allow_requires_bound_original_arguments(tmp_path, mode):
    state = coordinator(tmp_path, lambda: 1000)
    invocations = []
    admissions = []
    runtime = StrictReceiptRuntime(
        coordinator=state,
        admission=lambda receipt, _config: (
            admissions.append(receipt["receipt_hash"])
            or accepted(receipt["receipt_hash"])
        ),
        admission_config=None,
    )
    action_value = action("original-binding", lambda value: invocations.append(value))
    if mode == "missing":
        del action_value["original_arguments"]
    elif mode == "untrusted":
        action_value["original_arguments"]["capability"] = type(
            "FakeCapability", (), {"status": "trusted_bound_arguments"}
        )()
    else:
        action_value["original_arguments"]["arguments_hash"] = HASH_B
    result = runtime.run_decision(
        decision=decision("original-binding", {"action_taken": "allowed"}),
        action=action_value,
    )
    assert result["status"] == "nonexecuted"
    assert result["reason"] == "original_arguments_unavailable"
    assert invocations == []
    assert admissions == []
    assert state.inspect_state()["sequence"] == 0


def test_resolution_requires_bound_original_arguments(tmp_path):
    times = iter([1000, 1100])
    state = coordinator(tmp_path, lambda: next(times))
    admissions = []
    runtime = StrictReceiptRuntime(
        coordinator=state,
        admission=lambda receipt, _config: (
            admissions.append(receipt["receipt_hash"])
            or accepted(receipt["receipt_hash"])
        ),
        admission_config=None,
    )
    pending = runtime.run_decision(
        decision=decision(
            "resolution-binding",
            {
                "action_taken": "blocked",
                "approval_required": True,
                "approval_request_id": "approval-1",
                "approval_action_hash": HASH_A,
                "approval_expires_at_ms": 1500,
            },
        ),
        action=action("resolution-binding", lambda _value: None),
    )
    invocations = []
    wrong = action("resolution-binding", lambda value: invocations.append(value))
    wrong["original_arguments"]["arguments_hash"] = HASH_B
    result = runtime.run_resolution(
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
        action=wrong,
    )
    assert result["reason"] == "original_arguments_unavailable"
    assert invocations == []
    assert len(admissions) == 1
    assert state.inspect_state()["sequence"] == 1


def test_preflight_snapshot_survives_wrapper_replacement_during_admission(tmp_path):
    state = coordinator(tmp_path, lambda: 1000)
    original = {"value": "original"}
    invoked = []
    action_value = action(
        "snapshot", lambda value: invoked.append(value) or value["value"], original
    )

    def admit(receipt, _config):
        action_value["original_arguments"]["value"] = {"value": "swapped-field"}
        action_value["original_arguments"] = {
            "capability": STRICT_BOUND_ARGUMENTS,
            "arguments_hash": HASH_B,
            "value": {"value": "replacement"},
        }
        return accepted(receipt["receipt_hash"])

    runtime = StrictReceiptRuntime(
        coordinator=state, admission=admit, admission_config=None
    )
    result = runtime.run_decision(
        decision=decision("snapshot", {"action_taken": "allowed"}),
        action=action_value,
    )
    assert result["status"] == "executed"
    assert result["value"] == "original"
    assert invoked == [original]
