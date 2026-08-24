"""Private capability implementations for strict v2 runtime adapters."""

import copy
import hashlib
from typing import Any, Callable, Dict

from .tool_pinning import _canonical_json_for_hash


class BoundArguments:
    def __init__(self, value: Any) -> None:
        self._value = copy.deepcopy(value)
        canonical = _canonical_json_for_hash(self._value).encode("utf-8")
        self.arguments_hash = hashlib.sha256(canonical).hexdigest()

    def snapshot(self) -> Any:
        return copy.deepcopy(self._value)


class TrustedAdmission:
    def __init__(self, admit: Callable[[Dict[str, Any], Any], Dict[str, Any]]) -> None:
        self.admit = admit


def runtime_operation_fingerprint(
    kind: str,
    input_value: Dict[str, Any],
    action: Dict[str, Any],
    tenant_id: str,
    session_id: str,
) -> str:
    original = action.get("original_arguments")
    effective = action.get("effective_arguments")
    document = {
        "schema": "obsvr-strict-runtime-operation-v2",
        "kind": kind,
        "tenant_id": tenant_id,
        "session_id": session_id,
        "runtime_action_id": action.get("runtime_action_id"),
        "input": input_value,
        "original_arguments_hash": (
            original.arguments_hash if isinstance(original, BoundArguments) else None
        ),
        "effective_arguments_hash": (
            effective.arguments_hash if isinstance(effective, BoundArguments) else None
        ),
    }
    return hashlib.sha256(
        _canonical_json_for_hash(document).encode("utf-8")
    ).hexdigest()
