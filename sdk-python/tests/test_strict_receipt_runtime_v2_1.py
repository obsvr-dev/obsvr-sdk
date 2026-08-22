import copy
import hashlib
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
from obsvr.tool_pinning import _canonical_json_for_hash

B = "b" * 64
C = "c" * 64
TARGET = action_target_hash("prod")
CHECKPOINT_SHA256 = "e005d13ddfe1e349bcf13fbda8f6c05305d61b3af192e8488d9c05c4f086197e"
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


def _decision(action_id, arguments_hash, active=None):
    return {
        "action_id": action_id,
        "active_intents": active or ["deploy"],
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


def _coordinator(tmp_path, base=None):
    path = tmp_path / "runtime-v21-seed.key"
    path.write_text("00" * 32, encoding="ascii")
    signer = load_device_signer(str(path))
    base_result = base or {"action_taken": "allowed"}
    return StrictReceiptCoordinatorV21(
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
            lambda _context: copy.deepcopy(base_result)
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
        pid=lambda: 7,
        prepared_token_factory=lambda: "prepared-token",
    )


def _accepted(receipt_hash, status="accepted"):
    return json.dumps(
        {
            "schema": STRICT_RECEIPT_V2_1_ADMISSION_SCHEMA,
            "ok": True,
            "status": status,
            "receipt_hash": receipt_hash,
            "accepted_at_ms": 10,
        }
    ).encode()


class Store:
    def __init__(self, events, fail_on=None):
        self.events = events
        self.fail_on = fail_on
        self.checkpoints = []

    def save(self, checkpoint):
        count = len(self.checkpoints) + 1
        if self.fail_on == count:
            raise OSError("disk failed")
        self.checkpoints.append(copy.deepcopy(checkpoint))
        self.events.append(f"persist:{checkpoint['phase']}")


def _setup(tmp_path, base=None, response=None, store=None):
    events = []
    subject = _coordinator(tmp_path, base)
    original_commit = subject.commit_prepared

    def commit(token, receipt_hash):
        events.append("commit")
        return original_commit(token, receipt_hash)

    subject.commit_prepared = commit
    checkpoint_store = store or Store(events)

    def transport(_target, headers, _body, _timeout, _limit):
        events.append("admit")
        if response is not None:
            return response(headers["Idempotency-Key"])
        return 200, _accepted(headers["Idempotency-Key"])

    runtime = StrictReceiptRuntimeV21(
        coordinator=subject,
        admission_config={
            "ingest_url": "https://example.com",
            "api_key": "key",
            "max_attempts": 1,
            "resolver": lambda _host: ["8.8.8.8"],
            "trusted_pinned_transport": transport,
        },
        checkpoint_store=checkpoint_store,
    )
    return subject, runtime, events, checkpoint_store


def test_ordering_checkpoint_parity_and_execution(tmp_path):
    bound = bind_strict_v2_1_json_arguments({"message": "hello"})
    _subject, runtime, events, store = _setup(tmp_path)
    result = runtime.run_decision(
        decision=_decision("action-1", bound.arguments_hash),
        action={
            "runtime_action_id": "action-1",
            "original_arguments": bound,
            "invoke": lambda value: events.append("invoke") or value["message"],
        },
    )
    assert result["status"] == "executed"
    assert result["value"] == "hello"
    assert events == [
        "persist:prepared",
        "admit",
        "persist:remote_accepted",
        "commit",
        "persist:committed",
        "persist:invocation_started",
        "invoke",
        "persist:terminal",
    ]
    assert "hello" not in json.dumps(store.checkpoints[0])
    assert "api_key" not in store.checkpoints[0]
    assert "provider_response" not in store.checkpoints[0]
    assert "error" not in store.checkpoints[0]
    assert (
        hashlib.sha256(
            _canonical_json_for_hash(store.checkpoints[0]).encode("utf-8")
        ).hexdigest()
        == CHECKPOINT_SHA256
    )


def test_modify_invokes_only_bound_effective_arguments(tmp_path):
    original = bind_strict_v2_1_json_arguments({"message": "unsafe"})
    effective = bind_strict_v2_1_json_arguments({"message": "redacted"})
    _subject, runtime, events, _store = _setup(
        tmp_path,
        {
            "action_taken": "redacted",
            "modified_arguments_hash": effective.arguments_hash,
        },
    )
    result = runtime.run_decision(
        decision=_decision("modify", original.arguments_hash),
        action={
            "runtime_action_id": "modify",
            "original_arguments": original,
            "effective_arguments": effective,
            "invoke": lambda value: events.append(f"value:{value['message']}") or value,
        },
    )
    assert result["status"] == "executed"
    assert "value:redacted" in events


def test_bound_arguments_hide_and_defend_the_hashed_snapshot(tmp_path):
    original = {"message": "signed", "nested": {"count": 1}}
    bound = bind_strict_v2_1_json_arguments(original)
    assert not hasattr(bound, "value")
    exposed = bound.snapshot()
    original["message"] = "mutated-original"
    original["nested"]["count"] = 2
    exposed["message"] = "mutated-copy"
    exposed["nested"]["count"] = 3
    _subject, runtime, _events, _store = _setup(tmp_path)
    invoked = []
    result = runtime.run_decision(
        decision=_decision("immutable", bound.arguments_hash),
        action={
            "runtime_action_id": "immutable",
            "original_arguments": bound,
            "invoke": lambda value: invoked.append(value) or value,
        },
    )
    assert result["status"] == "executed"
    assert invoked == [{"message": "signed", "nested": {"count": 1}}]


@pytest.mark.parametrize("outcome", ["DENY", "STEP_UP", "DEFER"])
def test_non_authorized_outcomes_are_admitted_but_never_invoked(tmp_path, outcome):
    bound = bind_strict_v2_1_json_arguments({"message": "hello"})
    active = ["deploy"]
    base = {"action_taken": "blocked"}
    if outcome == "STEP_UP":
        base = {
            "action_taken": "blocked",
            "approval_required": True,
            "approval_request_id": "approval-1",
            "approval_action_hash": bound.arguments_hash,
            "approval_expires_at_ms": 1_500,
        }
    elif outcome == "DEFER":
        base = {"action_taken": "allowed"}
        active = ["deploy", "other"]
    _subject, runtime, events, _store = _setup(tmp_path, base)
    invokes = []
    result = runtime.run_decision(
        decision=_decision(f"action-{outcome}", bound.arguments_hash, active),
        action={
            "runtime_action_id": f"action-{outcome}",
            "original_arguments": bound,
            "invoke": lambda _value: invokes.append(True),
        },
    )
    assert result["status"] == "nonexecuted"
    assert result["reason"] == "not_authorized"
    assert events == [
        "persist:prepared",
        "admit",
        "persist:remote_accepted",
        "commit",
        "persist:committed",
        "persist:terminal",
    ]
    assert invokes == []


def test_binding_failure_aborts_before_persistence_or_admission(tmp_path):
    signed = bind_strict_v2_1_json_arguments({"message": "signed"})
    wrong = bind_strict_v2_1_json_arguments({"message": "wrong"})
    subject, runtime, events, _store = _setup(tmp_path)
    result = runtime.run_decision(
        decision=_decision("binding", signed.arguments_hash),
        action={
            "runtime_action_id": "binding",
            "original_arguments": wrong,
            "invoke": lambda _value: pytest.fail("must not invoke"),
        },
    )
    assert result["reason"] == "binding_unavailable"
    assert events == []
    assert "prepared" not in subject.inspect_state()


def test_admission_and_commit_uncertainty_freeze_without_invoking(tmp_path):
    bound = bind_strict_v2_1_json_arguments({"message": "hello"})
    subject, runtime, _events, _store = _setup(
        tmp_path, response=lambda _hash: (503, b"")
    )
    result = runtime.run_decision(
        decision=_decision("uncertain", bound.arguments_hash),
        action={
            "runtime_action_id": "uncertain",
            "original_arguments": bound,
            "invoke": lambda _value: pytest.fail("must not invoke"),
        },
    )
    assert result["reason"] == "admission_uncertain"
    assert subject.inspect_state()["frozen"] is True

    subject2, runtime2, _events2, _store2 = _setup(tmp_path)
    subject2.commit_prepared = lambda *_args: (_ for _ in ()).throw(
        RuntimeError("commit failed")
    )
    result2 = runtime2.run_decision(
        decision=_decision("commit-fail", bound.arguments_hash),
        action={
            "runtime_action_id": "commit-fail",
            "original_arguments": bound,
            "invoke": lambda _value: pytest.fail("must not invoke"),
        },
    )
    assert result2["reason"] == "admission_uncertain"
    assert subject2.inspect_state()["frozen"] is True


def test_checkpoint_failures_before_and_after_admission_do_not_invoke(tmp_path):
    bound = bind_strict_v2_1_json_arguments({"message": "hello"})
    subject = _coordinator(tmp_path)
    events = []
    before = StrictReceiptRuntimeV21(
        coordinator=subject,
        admission_config={
            "ingest_url": "https://example.com",
            "api_key": "key",
            "resolver": lambda _host: ["8.8.8.8"],
            "trusted_pinned_transport": lambda *_args: events.append("admit"),
        },
        checkpoint_store=Store(events, fail_on=1),
    )
    result = before.run_decision(
        decision=_decision("before", bound.arguments_hash),
        action={
            "runtime_action_id": "before",
            "original_arguments": bound,
            "invoke": lambda _value: pytest.fail("must not invoke"),
        },
    )
    assert result["reason"] == "checkpoint_persist_failed"
    assert events == []

    subject2 = _coordinator(tmp_path)
    events2 = []
    store2 = Store(events2, fail_on=4)

    def transport(_target, headers, _body, _timeout, _limit):
        events2.append("admit")
        return 200, _accepted(headers["Idempotency-Key"])

    after = StrictReceiptRuntimeV21(
        coordinator=subject2,
        admission_config={
            "ingest_url": "https://example.com",
            "api_key": "key",
            "max_attempts": 1,
            "resolver": lambda _host: ["8.8.8.8"],
            "trusted_pinned_transport": transport,
        },
        checkpoint_store=store2,
    )
    result2 = after.run_decision(
        decision=_decision("after", bound.arguments_hash),
        action={
            "runtime_action_id": "after",
            "original_arguments": bound,
            "invoke": lambda _value: pytest.fail("must not invoke"),
        },
    )
    assert result2["reason"] == "checkpoint_persist_failed"
    with pytest.raises(StrictReceiptRuntimeV21Error, match="runtime is frozen"):
        after.run_decision(
            decision=_decision("next", bound.arguments_hash),
            action={
                "runtime_action_id": "next",
                "original_arguments": bound,
                "invoke": lambda _value: None,
            },
        )


@pytest.mark.parametrize("fail_on", [2, 3])
def test_each_preinvoke_journal_failure_freezes_without_invoking(tmp_path, fail_on):
    bound = bind_strict_v2_1_json_arguments({"message": "hello"})
    subject = _coordinator(tmp_path)
    events = []
    store = Store(events, fail_on=fail_on)

    def transport(_target, headers, _body, _timeout, _limit):
        return 200, _accepted(headers["Idempotency-Key"])

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
    invokes = []
    result = runtime.run_decision(
        decision=_decision(f"fail-{fail_on}", bound.arguments_hash),
        action={
            "runtime_action_id": f"fail-{fail_on}",
            "original_arguments": bound,
            "invoke": lambda _value: invokes.append(True),
        },
    )
    assert result["status"] == "nonexecuted"
    assert result["reason"] == "checkpoint_persist_failed"
    assert invokes == []
    with pytest.raises(StrictReceiptRuntimeV21Error, match="runtime is frozen"):
        runtime.run_decision(
            decision=_decision("next", bound.arguments_hash),
            action={
                "runtime_action_id": "next",
                "original_arguments": bound,
                "invoke": lambda _value: None,
            },
        )
