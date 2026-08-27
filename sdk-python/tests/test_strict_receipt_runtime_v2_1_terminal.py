"""Terminal classification checks for the strict 2.1 runtime."""

from obsvr.strict_receipt_runtime_v2_1 import bind_strict_v2_1_json_arguments
from tests.test_strict_receipt_runtime_v2_1 import _decision, _setup


def test_unclassified_invocation_error_is_signed_as_uncertain(tmp_path):
    bound = bind_strict_v2_1_json_arguments({"message": "hello"})
    _subject, runtime, _events, store = _setup(tmp_path)
    failure = RuntimeError("connection disappeared")
    result = runtime.run_decision(
        decision=_decision("error", bound.arguments_hash),
        action={
            "runtime_action_id": "error",
            "original_arguments": bound,
            "invoke": lambda _value: (_ for _ in ()).throw(failure),
        },
    )
    assert result["status"] == "invocation_uncertain"
    assert result["execution_outcome"]["body"]["status"] == "uncertain"
    assert result["execution_outcome"]["body"]["error_code"] == (
        "action_error_unclassified"
    )
    assert store.checkpoints[-1]["terminal_status"] == "invocation_uncertain"
