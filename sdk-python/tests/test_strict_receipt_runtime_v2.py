import threading

import pytest

from obsvr.strict_receipt_runtime_v2 import (
    StrictReceiptRuntimeV2,
    StrictReceiptRuntimeV2Error,
    bind_strict_v2_json_arguments,
    create_trusted_strict_v2_admission,
)

HASH = "c" * 64
TENANT = "tenant-1"
SESSION = "session-1"


def _receipt(action_id, arguments_hash, outcome="ALLOW", effective=None):
    action = {"action_id": action_id, "arguments_hash": arguments_hash}
    if effective is not None:
        action["effective_arguments_hash"] = effective
    return {
        "schema": "obsvr-strict-receipt-envelope-v2",
        "receipt_hash": HASH,
        "body": {
            "schema": "obsvr-strict-receipt-v2",
            "tenant_id": TENANT,
            "session_id": SESSION,
            "action": action,
            "evaluation": {"outcome": outcome},
            "execution_authorized": outcome in ("ALLOW", "MODIFY"),
        },
    }


class FakeCoordinator:
    def __init__(self):
        self.committed = 0
        self.aborted = 0
        self.frozen = 0
        self.fail_commit = False
        self.current = None

    def inspect_state(self):
        return {"tenant_id": TENANT, "session_id": SESSION}

    def prepare_decision(self, **value):
        action_taken = value["base_result"]["action_taken"]
        outcome = (
            "DENY"
            if action_taken == "blocked"
            else ("MODIFY" if action_taken == "redacted" else "ALLOW")
        )
        self.current = _receipt(
            value["action_id"],
            value["context"]["current_action"]["arguments_hash"],
            outcome,
            value["base_result"].get("modified_arguments_hash"),
        )
        return {
            "token": "tok",
            "receipt_hash": HASH,
            "kind": "decision",
            "value": {
                "evaluation": self.current["body"]["evaluation"],
                "receipt": self.current,
            },
        }

    def prepare_resolution(self, **value):
        action = value["context"]["current_action"]
        self.current = _receipt(
            action.get("action_id", "action-1"), action["arguments_hash"]
        )
        return {
            "token": "tok",
            "receipt_hash": HASH,
            "kind": "resolution",
            "value": self.current,
        }

    def prepare_timeout(self, **_value):
        self.current = _receipt("timeout-action", "a" * 64, "DENY")
        return {
            "token": "tok",
            "receipt_hash": HASH,
            "kind": "timeout",
            "value": self.current,
        }

    def commit_prepared(self, *_args):
        if self.fail_commit:
            raise RuntimeError("commit failed")
        self.committed += 1
        return self.current

    def abort_prepared(self, *_args):
        self.aborted += 1

    def freeze_prepared(self, *_args):
        self.frozen += 1


def _decision(action_id, arguments_hash, action_taken="allowed"):
    return {
        "action_id": action_id,
        "context": {"current_action": {"arguments_hash": arguments_hash}},
        "base_result": {"action_taken": action_taken},
        "policy_version": "v1",
        "rule_ids": [],
    }


def _response(receipt_hash=HASH, **changes):
    value = {
        "schema": "obsvr-strict-receipt-admission-v2",
        "tenant_id": TENANT,
        "session_id": SESSION,
        "receipt_hash": receipt_hash,
        "attempts": 1,
        "disposition": "accepted",
        "status": "accepted",
    }
    value.update(changes)
    return value


def _runtime(fake, admit):
    return StrictReceiptRuntimeV2(
        coordinator=fake,
        admission_config={"ingest_url": "https://example.com", "api_key": "key"},
        trusted_admission=create_trusted_strict_v2_admission(admit),
    )


def test_production_default_uses_concrete_pinned_v2_transport():
    fake = FakeCoordinator()
    bound = bind_strict_v2_json_arguments({"ok": True})
    transports = []

    def transport(_target, _headers, body, _timeout, _limit):
        transports.append(body)
        return 200, (
            '{"accepted_at_ms":1,"ok":true,"receipt_hash":"%s",'
            '"schema":"obsvr-strict-receipt-admission-v2","status":"accepted"}' % HASH
        ).encode()

    subject = StrictReceiptRuntimeV2(
        coordinator=fake,
        admission_config={
            "ingest_url": "https://example.com",
            "api_key": "key",
            "max_attempts": 1,
            "resolver": lambda _host: ["8.8.8.8"],
            "trusted_pinned_transport": transport,
        },
    )
    result = subject.run_decision(
        decision=_decision("action-1", bound.arguments_hash),
        action={
            "runtime_action_id": "action-1",
            "original_arguments": bound,
            "invoke": lambda _value: "ok",
        },
    )
    assert result["status"] == "executed"
    assert len(transports) == 1


def test_admit_commit_invoke_order_and_exact_retry_cache():
    fake = FakeCoordinator()
    order = []
    bound = bind_strict_v2_json_arguments({"prompt": "hello"})

    def admit(receipt, _config):
        order.append(f"admit:{fake.committed}")
        assert receipt["body"]["tenant_id"] == TENANT
        return _response()

    subject = _runtime(fake, admit)
    action = {
        "runtime_action_id": "action-1",
        "original_arguments": bound,
        "invoke": lambda value: (
            order.append(f"invoke:{fake.committed}") or value["prompt"]
        ),
    }
    value = _decision("action-1", bound.arguments_hash)
    first = subject.run_decision(decision=value, action=action)
    first["receipt"]["body"]["tenant_id"] = "mutated"
    second = subject.run_decision(decision=value, action=action)
    assert first["status"] == second["status"] == "executed"
    assert second["receipt"]["body"]["tenant_id"] == TENANT
    assert order == ["admit:0", "invoke:1"]


def test_argument_builder_snapshots_before_admission():
    fake = FakeCoordinator()
    source = {"value": 1}
    bound = bind_strict_v2_json_arguments(source)
    seen = []

    def admit(_receipt, _config):
        source["value"] = 99
        return _response()

    result = _runtime(fake, admit).run_decision(
        decision=_decision("action-1", bound.arguments_hash),
        action={
            "runtime_action_id": "action-1",
            "original_arguments": bound,
            "invoke": lambda value: seen.append(value),
        },
    )
    assert result["status"] == "executed"
    assert seen == [{"value": 1}]


def test_bad_argument_binding_aborts_before_admission():
    fake = FakeCoordinator()
    signed = bind_strict_v2_json_arguments({"a": 1})
    other = bind_strict_v2_json_arguments({"a": 2})
    calls = []
    result = _runtime(fake, lambda *_args: calls.append("admit")).run_decision(
        decision=_decision("action-1", signed.arguments_hash),
        action={
            "runtime_action_id": "action-1",
            "original_arguments": other,
            "invoke": lambda _value: calls.append("invoke"),
        },
    )
    assert result["reason"] == "original_arguments_unavailable"
    assert calls == []
    assert (fake.aborted, fake.frozen) == (1, 0)


def test_modify_uses_only_signed_effective_arguments():
    fake = FakeCoordinator()
    original = bind_strict_v2_json_arguments({"value": 1})
    effective = bind_strict_v2_json_arguments({"value": 2})
    seen = []
    value = _decision("action-1", original.arguments_hash, "redacted")
    value["base_result"]["modified_arguments_hash"] = effective.arguments_hash
    result = _runtime(fake, lambda *_args: _response()).run_decision(
        decision=value,
        action={
            "runtime_action_id": "action-1",
            "original_arguments": original,
            "effective_arguments": effective,
            "invoke": lambda arguments: seen.append(arguments["value"]),
        },
    )
    assert result["status"] == "executed"
    assert seen == [2]


def test_deny_and_timeout_are_admitted_but_never_invoke():
    fake = FakeCoordinator()
    bound = bind_strict_v2_json_arguments({"ok": True})
    invoked = []
    subject = _runtime(fake, lambda *_args: _response())
    denied = subject.run_decision(
        decision=_decision("action-1", bound.arguments_hash, "blocked"),
        action={
            "runtime_action_id": "action-1",
            "original_arguments": bound,
            "invoke": lambda _value: invoked.append(True),
        },
    )
    timeout = subject.run_timeout(timeout={})
    assert denied["reason"] == timeout["reason"] == "not_authorized"
    assert invoked == []


def test_resolution_binds_action_and_invokes_after_admission():
    fake = FakeCoordinator()
    bound = bind_strict_v2_json_arguments({"ok": True})
    invoked = []
    result = _runtime(fake, lambda *_args: _response()).run_resolution(
        resolution={
            "context": {
                "current_action": {
                    "action_id": "action-1",
                    "arguments_hash": bound.arguments_hash,
                }
            }
        },
        action={
            "runtime_action_id": "action-1",
            "original_arguments": bound,
            "invoke": lambda _value: invoked.append(True),
        },
    )
    assert result["status"] == "executed"
    assert invoked == [True]
    assert fake.committed == 1


@pytest.mark.parametrize(
    "reply,aborted,frozen,reason",
    [
        (
            _response(disposition="definitive_no_store", http_status=400),
            1,
            0,
            "definitive_no_store",
        ),
        (
            _response(disposition="uncertain", reason="retry_exhausted"),
            0,
            1,
            "admission_uncertain",
        ),
        (_response("d" * 64), 0, 1, "receipt_hash_mismatch"),
        (_response(tenant_id="other"), 0, 1, "tenant_mismatch"),
        (_response(schema="wrong"), 0, 1, "admission_schema_mismatch"),
    ],
)
def test_no_store_uncertainty_and_identity_drift(reply, aborted, frozen, reason):
    fake = FakeCoordinator()
    bound = bind_strict_v2_json_arguments({"ok": True})
    result = _runtime(fake, lambda *_args: reply).run_decision(
        decision=_decision("action-1", bound.arguments_hash),
        action={
            "runtime_action_id": "action-1",
            "original_arguments": bound,
            "invoke": lambda _value: pytest.fail("invoked"),
        },
    )
    assert result["reason"] == reason
    assert (fake.aborted, fake.frozen) == (aborted, frozen)


def test_commit_failure_and_provider_failure_never_duplicate_start():
    fake = FakeCoordinator()
    fake.fail_commit = True
    bound = bind_strict_v2_json_arguments({"ok": True})
    invoked = []
    result = _runtime(fake, lambda *_args: _response()).run_decision(
        decision=_decision("action-1", bound.arguments_hash),
        action={
            "runtime_action_id": "action-1",
            "original_arguments": bound,
            "invoke": lambda _value: invoked.append(True),
        },
    )
    assert result["status"] == "admitted"
    assert invoked == []

    fake = FakeCoordinator()
    starts = []
    subject = _runtime(fake, lambda *_args: _response())

    def fail(_value):
        starts.append(True)
        raise RuntimeError("provider failed")

    action = {
        "runtime_action_id": "action-1",
        "original_arguments": bound,
        "invoke": fail,
    }
    decision = _decision("action-1", bound.arguments_hash)
    assert (
        subject.run_decision(decision=decision, action=action)["status"]
        == "invocation_failed"
    )
    assert (
        subject.run_decision(decision=decision, action=action)["status"]
        == "invocation_failed"
    )
    with pytest.raises(StrictReceiptRuntimeV2Error):
        subject.run_decision(
            decision={**decision, "policy_version": "v2"}, action=action
        )
    assert len(starts) == 1


def test_concurrent_operation_fails_closed():
    fake = FakeCoordinator()
    bound = bind_strict_v2_json_arguments({"ok": True})
    entered = threading.Event()
    release = threading.Event()

    def admit(*_args):
        entered.set()
        release.wait(2)
        return _response()

    subject = _runtime(fake, admit)
    result = []
    thread = threading.Thread(
        target=lambda: result.append(
            subject.run_decision(
                decision=_decision("action-1", bound.arguments_hash),
                action={
                    "runtime_action_id": "action-1",
                    "original_arguments": bound,
                    "invoke": lambda _value: "ok",
                },
            )
        )
    )
    thread.start()
    assert entered.wait(1)
    with pytest.raises(StrictReceiptRuntimeV2Error):
        subject.run_decision(
            decision=_decision("action-2", bound.arguments_hash),
            action={
                "runtime_action_id": "action-2",
                "original_arguments": bound,
                "invoke": lambda _value: "bad",
            },
        )
    release.set()
    thread.join(2)
    assert result[0]["status"] == "executed"
