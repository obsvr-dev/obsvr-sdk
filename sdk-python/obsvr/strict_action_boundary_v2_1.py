"""Provider-neutral strict profile-2.1 boundary for governed side effects."""

from __future__ import annotations

import copy
import uuid
import weakref
from typing import Any, Callable, Dict, Optional

from .action_context_v2 import action_target_hash
from .strict_receipt_runtime_v2_1 import (
    assert_strict_receipt_runtime_v2_1,
    bind_strict_v2_1_json_arguments,
    run_trusted_strict_receipt_runtime_v2_1,
)


class ObsvrStrictActionBoundaryV21Error(RuntimeError):
    """A side effect could not cross the strict boundary safely."""

    def __init__(self, code: str, receipt_hash: str | None = None) -> None:
        self.code = code
        self.receipt_hash = receipt_hash
        suffix = f" ({receipt_hash})" if receipt_hash else ""
        super().__init__(f"obsvr strict action boundary: {code}{suffix}")


class StrictActionBoundaryV21Capability:
    __slots__ = ("profile_version", "__weakref__")

    def __init__(self) -> None:
        self.profile_version = "2.1"


_CAPABILITIES: "weakref.WeakKeyDictionary[Any, Dict[str, Any]]" = (
    weakref.WeakKeyDictionary()
)


def create_strict_action_boundary_v2_1(
    *,
    runtime: Any,
    context: Callable[[Dict[str, Any]], Dict[str, Any]],
) -> StrictActionBoundaryV21Capability:
    try:
        assert_strict_receipt_runtime_v2_1(runtime)
    except Exception:
        raise ObsvrStrictActionBoundaryV21Error("runtime_unavailable")
    if not callable(context):
        raise ObsvrStrictActionBoundaryV21Error("context_unavailable")
    capability = StrictActionBoundaryV21Capability()
    _CAPABILITIES[capability] = {"runtime": runtime, "context": context}
    return capability


def assert_strict_action_boundary_v2_1(value: Any) -> None:
    if not isinstance(value, StrictActionBoundaryV21Capability) or (
        value not in _CAPABILITIES
    ):
        raise ObsvrStrictActionBoundaryV21Error("runtime_unavailable")


def execute_strict_action_v2_1(
    capability: StrictActionBoundaryV21Capability,
    *,
    action: Dict[str, Any],
    invocation: Any,
    invoke: Callable[[Any], Any],
    result_projection: Optional[Callable[[Any], Any]] = None,
    classify_error: Optional[Callable[[Any], Dict[str, str]]] = None,
) -> Any:
    assert_strict_action_boundary_v2_1(capability)
    binding = _CAPABILITIES[capability]
    try:
        trusted_action = copy.deepcopy(action)
        context = copy.deepcopy(binding["context"](copy.deepcopy(trusted_action)))
        original = bind_strict_v2_1_json_arguments(invocation)
        target_hash = action_target_hash(trusted_action["target"])
        decision = {
            "action_id": str(uuid.uuid4()),
            "active_intents": context["active_intents"],
            "current_action": {
                "kind": trusted_action["kind"],
                "name": trusted_action["name"],
                "arguments_hash": original.arguments_hash,
                "target_hash": target_hash,
                "data_classifications": trusted_action["data_classifications"],
                "requested_scopes": trusted_action["requested_scopes"],
            },
            "run_id": context["run_id"],
            **(
                {"thread_id": context["thread_id"]}
                if "thread_id" in context
                else {}
            ),
        }
    except Exception as error:
        raise ObsvrStrictActionBoundaryV21Error("context_unavailable") from error
    if not callable(invoke):
        raise ObsvrStrictActionBoundaryV21Error("context_unavailable")
    runtime_action = {
        "runtime_action_id": decision["action_id"],
        "original_arguments": original,
        "invoke": invoke,
        **(
            {"result_projection": result_projection}
            if result_projection is not None
            else {}
        ),
        **({"classify_error": classify_error} if classify_error is not None else {}),
    }
    try:
        result = run_trusted_strict_receipt_runtime_v2_1(
            binding["runtime"], decision=decision, action=runtime_action
        )
    except Exception as error:
        raise ObsvrStrictActionBoundaryV21Error("runtime_unavailable") from error

    if result["status"] == "executed":
        return result["value"]
    if result["status"] == "invocation_failed":
        raise result["error"]
    if result["status"] == "nonexecuted" and result.get("reason") == "not_authorized":
        raise ObsvrStrictActionBoundaryV21Error(
            "not_authorized", result.get("receipt_hash")
        )
    raise ObsvrStrictActionBoundaryV21Error(
        "admission_not_confirmed", result.get("receipt_hash")
    )


__all__ = [
    "ObsvrStrictActionBoundaryV21Error",
    "StrictActionBoundaryV21Capability",
    "create_strict_action_boundary_v2_1",
    "execute_strict_action_v2_1",
]
