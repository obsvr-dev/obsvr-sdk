"""Focused lifecycle tests for the process-local strict receipt coordinator."""

import copy

import pytest

from obsvr.device_identity import DeviceSigner, load_device_signer
from obsvr.strict_receipt_coordinator import StrictReceiptCoordinator
from obsvr.strict_receipt_prepared_state import (
    DEFINITIVE_NO_STORE,
    PreparedReceiptState,
)
from obsvr.strict_receipt_verify import verify_strict_receipt_chain

HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
HASH_D = "d" * 64
POLICY = {
    "schema": "obsvr-intent-policy-v1",
    "profile_version": "1.0",
    "intent_scopes": [{
        "intent_id": "deploy",
        "allowed_actions": [{"kind": "tool", "name": "send"}],
        "allowed_targets": ["prod"],
        "allowed_requested_scopes": ["write"],
        "allowed_data_classifications": ["confidential"],
    }],
}


def make_signer(tmp_path, seed="00"):
    path = tmp_path / f"seed-{seed}.key"
    path.write_text(seed * 32, encoding="ascii")
    return load_device_signer(str(path))


def context(arguments_hash=HASH_A):
    return {
        "agent_id": "agent-1", "active_intents": ["deploy"],
        "privilege_scope": ["write"],
        "current_action": {
            "kind": "tool", "name": "send", "arguments_hash": arguments_hash,
            "target": "prod", "requested_scopes": ["write"],
            "data_classifications": ["confidential"],
        },
        "run_id": "run-1", "thread_id": "thread-1",
    }


def coordinator(tmp_path, clock, signer=None, **extras):
    policy = extras.pop("policy", POLICY)
    approval_verifier = extras.pop("approval_verifier", None)
    if approval_verifier is None:
        def approval_verifier(evidence, expected):
            if not isinstance(evidence, dict) or evidence.get("token") != "trusted":
                raise ValueError("untrusted approval evidence")
            return {
                "request_id": expected["request_id"],
                "action_hash": expected["action_hash"],
                "principal_id": "reviewer-1", "decision": expected["decision"],
                "source_hash": HASH_D,
                "expires_at_ms": evidence["expires_at_ms"],
            }
    return StrictReceiptCoordinator(
        signer=signer or make_signer(tmp_path), policy=policy,
        sdk_language="python", sdk_version="0.test", session_id="session-1",
        clock=clock, defer_ttl_ms=500, approval_verifier=approval_verifier,
        **extras,
    )


def decide(subject, action_id, base_result, arguments_hash=HASH_A):
    return subject.decide(
        context=context(arguments_hash), base_result=base_result,
        policy_version="policy-1", rule_ids=["rule-b", "rule-a"],
        action_id=action_id,
    )


def test_all_outcomes_clock_clamp_and_authorization(tmp_path):
    times = iter([1000, 900, 1100, 1200, 1300])
    subject = coordinator(tmp_path, lambda: next(times))
    results = [
        decide(subject, "allow", {"action_taken": "allowed"}),
        decide(subject, "deny", {"action_taken": "blocked"}, HASH_B),
        decide(subject, "modify", {
            "action_taken": "redacted", "modified_arguments_hash": HASH_D,
        }, HASH_C),
        decide(subject, "step", {
            "action_taken": "blocked", "approval_required": True,
            "approval_request_id": "approval-1",
            "approval_action_hash": HASH_A, "approval_expires_at_ms": 1600,
        }),
        decide(subject, "defer", {"action_taken": "hook_error"}, HASH_B),
    ]
    assert [item["evaluation"]["outcome"] for item in results] == [
        "ALLOW", "DENY", "MODIFY", "STEP_UP", "DEFER",
    ]
    assert [item["receipt"]["body"]["execution_authorized"] for item in results] == [
        True, False, True, False, False,
    ]
    assert results[1]["receipt"]["body"]["timestamp_ms"] == 1000
    assert results[1]["receipt"]["body"]["clock_regression_clamped"] is True
    assert verify_strict_receipt_chain(
        [item["receipt"] for item in results]
    ) == {"valid": True, "errors": []}


def test_idempotence_and_action_id_conflict(tmp_path):
    subject = coordinator(tmp_path, lambda: 1000)
    first = decide(subject, "same", {"action_taken": "allowed"})
    retry = decide(subject, "same", {"action_taken": "allowed"})
    assert retry == first
    retry["receipt"]["body"]["action"]["name"] = "caller-mutation"
    assert decide(subject, "same", {"action_taken": "allowed"}) == first
    with pytest.raises(ValueError, match="different input"):
        decide(subject, "same", {"action_taken": "blocked"})
    assert decide(subject, "next", {"action_taken": "allowed"}, HASH_B)[
        "receipt"
    ]["body"]["sequence"] == 2


def test_bound_approval_is_re_evaluated_and_consumed_once(tmp_path):
    times = iter([1000, 1100, 1200])
    subject = coordinator(tmp_path, lambda: next(times))
    pending = decide(subject, "step", {
        "action_taken": "blocked", "approval_required": True,
        "approval_request_id": "approval-1", "approval_action_hash": HASH_A,
        "approval_expires_at_ms": 1500,
    })
    receipt_hash = pending["receipt"]["receipt_hash"]
    with pytest.raises(ValueError, match="untrusted approval evidence"):
        subject.resolve(
            suspended_receipt_hash=receipt_hash, method="approval_granted",
            context=context(), base_result={"action_taken": "allowed"},
            policy_version="policy-1", rule_ids=[],
        )
    resolved = subject.resolve(
        suspended_receipt_hash=receipt_hash, method="approval_granted",
        context=context(), base_result={"action_taken": "allowed"},
        policy_version="policy-1", rule_ids=[],
        approval_evidence_value={"token": "trusted", "expires_at_ms": 1500},
    )
    assert resolved["body"]["evaluation"]["outcome"] == "ALLOW"
    assert resolved["body"]["execution_authorized"] is True
    assert verify_strict_receipt_chain(
        [pending["receipt"], resolved]
    ) == {"valid": True, "errors": []}
    with pytest.raises(ValueError, match="already resolved"):
        subject.resolve(
            suspended_receipt_hash=receipt_hash, method="approval_granted",
            context=context(), base_result={"action_taken": "allowed"},
            policy_version="policy-1", rule_ids=[],
            approval_evidence_value={"token": "trusted", "expires_at_ms": 1500},
        )


def test_caller_shaped_approval_data_is_not_trusted(tmp_path):
    times = iter([1000, 1100])
    subject = coordinator(tmp_path, lambda: next(times))
    pending = decide(subject, "step", {
        "action_taken": "blocked", "approval_required": True,
        "approval_request_id": "approval-1", "approval_action_hash": HASH_A,
        "approval_expires_at_ms": 1500,
    })
    with pytest.raises(ValueError, match="untrusted approval evidence"):
        subject.resolve(
            suspended_receipt_hash=pending["receipt"]["receipt_hash"],
            method="approval_granted", context=context(),
            base_result={"action_taken": "allowed"}, policy_version="policy-1",
            rule_ids=[], approval_evidence_value={
                "approval_request_id": "approval-1",
                "approval_action_hash": HASH_A,
                "resolver_principal_id": "attacker", "decision": "granted",
            },
        )


@pytest.mark.parametrize("field", ["request", "action", "decision", "expiry", "source"])
def test_wrong_trusted_approval_binding_is_rejected(tmp_path, field):
    def verifier(_evidence, expected):
        return {
            "request_id": "wrong" if field == "request" else expected["request_id"],
            "action_hash": HASH_B if field == "action" else expected["action_hash"],
            "principal_id": "reviewer-1",
            "decision": "denied" if field == "decision" else expected["decision"],
            "source_hash": "bad" if field == "source" else HASH_D,
            "expires_at_ms": 1600 if field == "expiry" else 1500,
        }

    times = iter([1000, 1100])
    subject = coordinator(
        tmp_path, lambda: next(times), approval_verifier=verifier
    )
    pending = decide(subject, "step", {
        "action_taken": "blocked", "approval_required": True,
        "approval_request_id": "approval-1", "approval_action_hash": HASH_A,
        "approval_expires_at_ms": 1500,
    })
    with pytest.raises(ValueError):
        subject.resolve(
            suspended_receipt_hash=pending["receipt"]["receipt_hash"],
            method="approval_granted", context=context(),
            base_result={"action_taken": "allowed"}, policy_version="policy-1",
            rule_ids=[], approval_evidence_value={"token": "anything"},
        )


def test_exact_expiry_and_clock_regression_cannot_authorize(tmp_path):
    times = iter([1000, 1500, 1400])
    subject = coordinator(tmp_path, lambda: next(times))
    pending = decide(subject, "step", {
        "action_taken": "blocked", "approval_required": True,
        "approval_request_id": "approval-1", "approval_action_hash": HASH_A,
        "approval_expires_at_ms": 1500,
    })
    decide(subject, "head-at-expiry", {"action_taken": "allowed"}, HASH_B)
    with pytest.raises(ValueError, match="expired"):
        subject.resolve(
            suspended_receipt_hash=pending["receipt"]["receipt_hash"],
            method="approval_granted", context=context(),
            base_result={"action_taken": "allowed"}, policy_version="policy-1",
            rule_ids=[], approval_evidence_value={
                "token": "trusted", "expires_at_ms": 1500,
            },
        )


def test_verifier_throw_does_not_advance_state(tmp_path):
    fail = [True]

    def verifier(_evidence, expected):
        if fail[0]:
            fail[0] = False
            raise ValueError("verification unavailable")
        return {
            "request_id": expected["request_id"],
            "action_hash": expected["action_hash"],
            "principal_id": "reviewer-1", "decision": expected["decision"],
            "source_hash": HASH_D, "expires_at_ms": 1500,
        }

    times = iter([1000, 1100, 1200])
    subject = coordinator(
        tmp_path, lambda: next(times), approval_verifier=verifier
    )
    pending = decide(subject, "step", {
        "action_taken": "blocked", "approval_required": True,
        "approval_request_id": "approval-1", "approval_action_hash": HASH_A,
        "approval_expires_at_ms": 1500,
    })
    request = {
        "suspended_receipt_hash": pending["receipt"]["receipt_hash"],
        "method": "approval_granted", "context": context(),
        "base_result": {"action_taken": "allowed"},
        "policy_version": "policy-1", "rule_ids": [],
        "approval_evidence_value": {"token": "trusted"},
    }
    with pytest.raises(ValueError, match="verification unavailable"):
        subject.resolve(**request)
    assert subject.resolve(**request)["body"]["sequence"] == 2


def test_defer_resolution_updates_one_prior_summary(tmp_path):
    times = iter([1000, 1100, 1200])
    policy = copy.deepcopy(POLICY)
    policy["intent_scopes"][0]["max_prior_actions"] = 1
    subject = coordinator(tmp_path, lambda: next(times), policy=policy)
    pending = decide(subject, "defer", {"action_taken": "hook_error"})
    resolved = subject.resolve(
        suspended_receipt_hash=pending["receipt"]["receipt_hash"],
        method="context_supplied", context=context(),
        base_result={"action_taken": "allowed"}, policy_version="policy-1",
        rule_ids=[], resolver_principal_id="worker-1",
        resolution_source_hash=HASH_D,
    )
    assert resolved["body"]["evaluation"]["outcome"] == "ALLOW"
    assert decide(subject, "after", {"action_taken": "allowed"}, HASH_B)[
        "evaluation"
    ]["outcome"] == "ALLOW"


def test_timeout_is_exactly_once_and_never_authorizes(tmp_path):
    times = iter([1000, 1499, 1500])
    subject = coordinator(tmp_path, lambda: next(times))
    pending = decide(subject, "defer", {"action_taken": "hook_timeout"})
    receipt_hash = pending["receipt"]["receipt_hash"]
    with pytest.raises(ValueError, match="has not expired"):
        subject.timeout(
            suspended_receipt_hash=receipt_hash,
            policy_version="policy-1", rule_ids=[],
        )
    timed_out = subject.timeout(
        suspended_receipt_hash=receipt_hash,
        policy_version="policy-1", rule_ids=[],
    )
    assert timed_out["body"]["evaluation"]["outcome"] == "DENY"
    assert timed_out["body"]["execution_authorized"] is False
    with pytest.raises(ValueError, match="already resolved"):
        subject.timeout(
            suspended_receipt_hash=receipt_hash,
            policy_version="policy-1", rule_ids=[],
        )


@pytest.mark.parametrize("mode", ["throw", "malformed", "wrong-key", "mismatch"])
def test_signer_failure_never_advances_state(tmp_path, mode):
    real = make_signer(tmp_path, "00")
    other = make_signer(tmp_path, "11")
    calls = 0

    def sign(message):
        nonlocal calls
        calls += 1
        if calls > 1:
            return bytes.fromhex(real.sign_bytes(message))
        if mode == "throw":
            raise RuntimeError("sign failed")
        if mode == "malformed":
            return b"bad"
        if mode == "wrong-key":
            return bytes.fromhex(other.sign_bytes(message))
        return bytes.fromhex(real.sign_bytes(message))

    adversarial = DeviceSigner(sign, real.raw_public_key)
    if mode == "mismatch":
        adversarial.public_key_b64 = other.public_key_b64
    subject = coordinator(tmp_path, lambda: 1000, signer=adversarial)
    with pytest.raises(Exception):
        decide(subject, "first", {"action_taken": "allowed"})
    if mode == "mismatch":
        adversarial.public_key_b64 = real.public_key_b64
    success = decide(subject, "second", {"action_taken": "allowed"})
    assert success["receipt"]["body"]["sequence"] == 1
    assert success["receipt"]["body"]["previous_receipt_hash"] is None


def test_pid_and_after_fork_reset_start_new_genesis(tmp_path):
    pid = [10]
    subject = coordinator(
        tmp_path, lambda: 1000, pid=lambda: pid[0],
        session_factory=lambda: "session-child",
    )
    decide(subject, "parent", {"action_taken": "allowed"})
    pid[0] = 11
    child = decide(subject, "child", {"action_taken": "allowed"})
    assert child["receipt"]["body"]["session_id"] == "session-child"
    assert child["receipt"]["body"]["sequence"] == 1
    subject._lock.acquire()  # Exercise the registered child callback's lock replacement.
    subject._after_fork_child()
    callback_child = decide(subject, "callback", {"action_taken": "allowed"})
    assert callback_child["receipt"]["body"]["sequence"] == 1


def test_prepare_is_idempotent_without_advancing_committed_state(tmp_path):
    subject = coordinator(
        tmp_path, lambda: 1000,
        prepared_token_factory=lambda: "opaque-token",
    )
    input_value = {
        "context": context(), "base_result": {"action_taken": "allowed"},
        "policy_version": "policy-1", "rule_ids": ["rule-a"],
        "action_id": "prepared",
    }
    first = subject.prepare_decision(**input_value)
    assert subject.inspect_state()["sequence"] == 0
    assert subject.inspect_state()["head_receipt_hash"] is None
    assert subject.prepare_decision(**input_value) == first
    with pytest.raises(ValueError, match="different receipt is already prepared"):
        subject.prepare_decision(**{**input_value, "action_id": "other"})
    with pytest.raises(ValueError, match="prepared token mismatch"):
        subject.commit_prepared("wrong", first["receipt_hash"])
    with pytest.raises(ValueError, match="prepared receipt hash mismatch"):
        subject.commit_prepared(first["token"], HASH_A)
    assert subject.commit_prepared(
        first["token"], first["receipt_hash"]
    ) == first["value"]
    state = subject.inspect_state()
    assert state["sequence"] == 1
    assert state["head_receipt_hash"] == first["receipt_hash"]


def test_no_store_capability_freeze_and_local_commit_failure():
    state = PreparedReceiptState(lambda: "opaque-token")
    commits = []
    prepared = state.prepare(
        fingerprint=HASH_A, receipt_hash=HASH_B, kind="decision", value="value",
        commit=lambda: commits.append("committed"),
    )
    with pytest.raises(ValueError, match="definitive_no_store capability"):
        state.abort(
            prepared["token"], prepared["receipt_hash"],
            type("FakeCapability", (), {"status": "definitive_no_store"})(),
        )
    state.freeze(prepared["token"], prepared["receipt_hash"], "delivery_unknown")
    with pytest.raises(ValueError, match="session is frozen"):
        state.retry(HASH_A, "decision")
    assert state.reconcile({
        "status": "stored", "token": prepared["token"],
        "receipt_hash": prepared["receipt_hash"],
    }) == "value"
    assert commits == ["committed"]

    aborted = state.prepare(
        fingerprint=HASH_C, receipt_hash=HASH_D, kind="decision", value="unused",
        commit=lambda: commits.append("unexpected"),
    )
    state.abort(aborted["token"], aborted["receipt_hash"], DEFINITIVE_NO_STORE)
    assert state.inspect() == {"frozen": False}
    assert commits == ["committed"]

    failed = PreparedReceiptState(lambda: "failed-token")
    def fail_commit():
        raise RuntimeError("local commit failed")
    pending = failed.prepare(
        fingerprint=HASH_A, receipt_hash=HASH_B, kind="decision", value=None,
        commit=fail_commit,
    )
    with pytest.raises(RuntimeError, match="local commit failed"):
        failed.commit(pending["token"], pending["receipt_hash"])
    assert failed.inspect()["freeze_reason"] == "accepted_but_local_commit_failed"
    with pytest.raises(ValueError, match="session is frozen"):
        failed.prepare(
            fingerprint=HASH_C, receipt_hash=HASH_D, kind="decision", value=None,
            commit=lambda: None,
        )


def test_prepare_resolution_and_timeout_do_not_advance_chains(tmp_path):
    approval_times = iter([1000, 1100])
    approval = coordinator(tmp_path, lambda: next(approval_times))
    pending = decide(approval, "step", {
        "action_taken": "blocked", "approval_required": True,
        "approval_request_id": "approval-1", "approval_action_hash": HASH_A,
        "approval_expires_at_ms": 1500,
    })
    prepared_resolution = approval.prepare_resolution(
        suspended_receipt_hash=pending["receipt"]["receipt_hash"],
        method="approval_granted", context=context(),
        base_result={"action_taken": "allowed"}, policy_version="policy-1",
        rule_ids=[], approval_evidence_value={
            "token": "trusted", "expires_at_ms": 1500,
        },
    )
    assert approval.inspect_state()["sequence"] == 1
    assert approval.commit_prepared(
        prepared_resolution["token"], prepared_resolution["receipt_hash"]
    )["body"]["sequence"] == 2

    timeout_times = iter([1000, 1500])
    timeout = coordinator(tmp_path, lambda: next(timeout_times))
    deferred = decide(timeout, "defer", {"action_taken": "hook_timeout"})
    prepared_timeout = timeout.prepare_timeout(
        suspended_receipt_hash=deferred["receipt"]["receipt_hash"],
        policy_version="policy-1", rule_ids=[],
    )
    assert timeout.inspect_state()["sequence"] == 1
    assert timeout.commit_prepared(
        prepared_timeout["token"], prepared_timeout["receipt_hash"]
    )["body"]["sequence"] == 2


def test_pid_change_clears_prepared_and_frozen_state(tmp_path):
    pid = [10]
    subject = coordinator(
        tmp_path, lambda: 1000, pid=lambda: pid[0],
        session_factory=lambda: "session-child",
    )
    parent = subject.prepare_decision(
        context=context(), base_result={"action_taken": "allowed"},
        policy_version="policy-1", rule_ids=[], action_id="parent",
    )
    subject.freeze_prepared(
        parent["token"], parent["receipt_hash"], "delivery_unknown"
    )
    pid[0] = 11
    child = subject.prepare_decision(
        context=context(), base_result={"action_taken": "allowed"},
        policy_version="policy-1", rule_ids=[], action_id="child",
    )
    body = child["value"]["receipt"]["body"]
    assert body["session_id"] == "session-child"
    assert body["sequence"] == 1
    assert body["previous_receipt_hash"] is None
    assert subject.inspect_state()["frozen"] is False
