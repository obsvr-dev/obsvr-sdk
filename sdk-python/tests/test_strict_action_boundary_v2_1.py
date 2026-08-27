import pytest

from obsvr.action_context_v2 import action_target_hash
from obsvr.strict_action_boundary_v2_1 import (
    ObsvrStrictActionBoundaryV21Error,
    create_strict_action_boundary_v2_1,
    execute_strict_action_v2_1,
)
from obsvr.strict_execution_outcome_v2_1 import strict_execution_result_v2_1_hash
from tests.test_strict_receipt_runtime_v2_1 import _setup


TARGET = "prod"
ACTION = {
    "kind": "tool",
    "name": "send",
    "target": TARGET,
    "data_classifications": ["confidential"],
    "requested_scopes": ["write"],
}


def _boundary(tmp_path, base=None):
    _subject, runtime, events, store = _setup(tmp_path, base=base)
    contexts = []

    def context(action):
        contexts.append(action)
        return {
            "active_intents": ["deploy"],
            "run_id": "run-1",
            "thread_id": "thread-1",
        }

    return (
        create_strict_action_boundary_v2_1(runtime=runtime, context=context),
        contexts,
        events,
        store,
    )


def test_admits_exact_arguments_before_side_effect_and_signs_result(tmp_path):
    boundary, contexts, events, store = _boundary(tmp_path)
    calls = []

    def invoke(value):
        calls.append(value)
        events.append("invoke")
        return {"id": value["agreement_id"]}

    result = execute_strict_action_v2_1(
        boundary,
        action=ACTION,
        invocation={"agreement_id": "a-1"},
        invoke=invoke,
        result_projection=lambda value: {"id": value["id"]},
    )
    assert result == {"id": "a-1"}
    assert calls == [{"agreement_id": "a-1"}]
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
    assert contexts == [ACTION]
    receipt = store.checkpoints[0]["receipt"]
    assert receipt["body"]["action"]["target_hash"] == action_target_hash(TARGET)
    outcome = store.checkpoints[-1]["execution_outcome"]["body"]
    assert outcome["status"] == "succeeded"
    assert outcome["result_hash"] == strict_execution_result_v2_1_hash({"id": "a-1"})


@pytest.mark.parametrize(
    "base, expected_code, admitted",
    [
        ({"action_taken": "blocked"}, "not_authorized", True),
        (
            {"action_taken": "redacted", "modified_arguments_hash": "0" * 64},
            "admission_not_confirmed",
            False,
        ),
    ],
)
def test_never_invokes_without_execution_authorization(
    tmp_path, base, expected_code, admitted
):
    boundary, _contexts, _events, store = _boundary(tmp_path, base)
    calls = []
    with pytest.raises(ObsvrStrictActionBoundaryV21Error) as raised:
        execute_strict_action_v2_1(
            boundary,
            action=ACTION,
            invocation={"id": 1},
            invoke=lambda value: calls.append(value),
        )
    assert raised.value.code == expected_code
    assert calls == []
    if admitted:
        assert store.checkpoints[-1]["terminal_status"] == "nonexecuted"
    else:
        assert store.checkpoints == []


def test_unclassified_error_is_uncertain(tmp_path):
    boundary, _contexts, _events, store = _boundary(tmp_path)

    def fail(_value):
        raise RuntimeError("connection ended after send")

    with pytest.raises(ObsvrStrictActionBoundaryV21Error) as raised:
        execute_strict_action_v2_1(
            boundary, action=ACTION, invocation={"id": 1}, invoke=fail
        )
    assert raised.value.code == "admission_not_confirmed"
    terminal = store.checkpoints[-1]
    assert terminal["terminal_status"] == "invocation_uncertain"
    assert terminal["execution_outcome"]["body"]["error_code"] == (
        "action_error_unclassified"
    )


def test_definitive_local_failure_is_preserved(tmp_path):
    boundary, _contexts, _events, store = _boundary(tmp_path)
    failure = ValueError("validation rejected")

    def fail(_value):
        raise failure

    with pytest.raises(ValueError) as raised:
        execute_strict_action_v2_1(
            boundary,
            action=ACTION,
            invocation={"id": 1},
            invoke=fail,
            classify_error=lambda _error: {
                "status": "failed",
                "error_code": "local_validation_failed",
            },
        )
    assert raised.value is failure
    terminal = store.checkpoints[-1]
    assert terminal["terminal_status"] == "invocation_failed"
    assert terminal["execution_outcome"]["body"]["error_code"] == (
        "local_validation_failed"
    )


def test_rejects_forged_capability_and_non_json_arguments_before_invocation(tmp_path):
    calls = []
    with pytest.raises(ObsvrStrictActionBoundaryV21Error):
        execute_strict_action_v2_1(
            object(),
            action=ACTION,
            invocation={"id": 1},
            invoke=lambda value: calls.append(value),
        )
    boundary, _contexts, _events, store = _boundary(tmp_path)
    circular = {}
    circular["self"] = circular
    with pytest.raises(ObsvrStrictActionBoundaryV21Error) as raised:
        execute_strict_action_v2_1(
            boundary,
            action=ACTION,
            invocation=circular,
            invoke=lambda value: calls.append(value),
        )
    assert raised.value.code == "context_unavailable"
    assert calls == []
    assert store.checkpoints == []
