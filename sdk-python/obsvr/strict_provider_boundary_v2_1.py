"""Trusted profile-2.1 boundary for ordinary synchronous provider calls."""

from __future__ import annotations

import copy
import hashlib
import uuid
import weakref
from typing import Any, Callable, Dict, Optional
from urllib.parse import unquote, urlsplit

from .action_context_v2 import action_target_hash
from .provider_attribution import read_base_url
from .ssrf import assert_backend_url_static
from .strict_receipt_runtime_v2_1 import (
    assert_strict_receipt_runtime_v2_1,
    bind_strict_v2_1_json_arguments,
    run_trusted_strict_receipt_runtime_v2_1,
)
from .tool_pinning import _canonical_json_for_hash


class ObsvrStrictProviderBoundaryV21Error(RuntimeError):
    """A provider call could not cross the strict boundary safely."""

    def __init__(self, code: str, receipt_hash: str | None = None) -> None:
        self.code = code
        self.receipt_hash = receipt_hash
        suffix = f" ({receipt_hash})" if receipt_hash else ""
        super().__init__(f"obsvr strict provider boundary: {code}{suffix}")


class StrictProviderBoundaryV21Capability:
    __slots__ = ("profile_version", "__weakref__")

    def __init__(self) -> None:
        self.profile_version = "2.1"


_CAPABILITIES: "weakref.WeakKeyDictionary[Any, Dict[str, Any]]" = (
    weakref.WeakKeyDictionary()
)


def create_strict_provider_boundary_v2_1(
    *,
    runtime: Any,
    context: Callable[[Dict[str, Any]], Dict[str, Any]],
) -> StrictProviderBoundaryV21Capability:
    try:
        assert_strict_receipt_runtime_v2_1(runtime)
    except Exception:
        raise ObsvrStrictProviderBoundaryV21Error("runtime_unavailable")
    if not callable(context):
        raise ObsvrStrictProviderBoundaryV21Error("context_unavailable")
    capability = StrictProviderBoundaryV21Capability()
    _CAPABILITIES[capability] = {
        "runtime": runtime,
        "context": context,
    }
    return capability


def assert_strict_provider_boundary_v2_1(value: Any) -> None:
    if not isinstance(value, StrictProviderBoundaryV21Capability) or (
        value not in _CAPABILITIES
    ):
        raise ObsvrStrictProviderBoundaryV21Error("runtime_unavailable")


def strict_provider_surface_unsupported_v2_1() -> None:
    raise ObsvrStrictProviderBoundaryV21Error("unsupported_surface")


_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})
_TRUSTED_PROVIDER_HOSTS = frozenset(
    {
        "api.openai.com",
        "api.anthropic.com",
        "generativelanguage.googleapis.com",
        "api.groq.com",
    }
)
_AMBIGUOUS_TRANSPORT_CODES = frozenset(
    {
        "ECONNABORTED",
        "ECONNRESET",
        "ETIMEDOUT",
        "UND_ERR_CONNECT_TIMEOUT",
        "UND_ERR_HEADERS_TIMEOUT",
        "UND_ERR_SOCKET",
    }
)


def _provider_response_value(value: Any) -> Any:
    for method_name in ("model_dump", "to_dict"):
        method = getattr(value, method_name, None)
        if callable(method):
            return method()
    if value is None or isinstance(value, (str, int, float, bool, list, dict)):
        return copy.deepcopy(value)
    instance = getattr(value, "__dict__", None)
    if isinstance(instance, dict) and instance:
        return copy.deepcopy(instance)
    common = {
        field: copy.deepcopy(getattr(value, field))
        for field in ("id", "model", "usage", "choices", "content")
        if hasattr(value, field)
    }
    if common:
        return common
    raise TypeError("provider response has no deterministic projection")


def _provider_result_projection(call: Dict[str, Any], value: Any) -> Dict[str, str]:
    canonical = _canonical_json_for_hash(_provider_response_value(value))
    return {
        "schema": "obsvr-strict-provider-result-v2-1",
        "provider": call["provider"],
        "operation": call["operation"],
        "response_hash": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    }


def _classify_provider_error(error: Any) -> Dict[str, str]:
    current = error
    for _depth in range(4):
        if current is None:
            break
        if getattr(current, "code", None) in _AMBIGUOUS_TRANSPORT_CODES or (
            current.__class__.__name__ == "AbortError"
        ):
            return {
                "status": "uncertain",
                "error_code": "provider_transport_ambiguous",
            }
        if isinstance(getattr(current, "status", None), int):
            return {"status": "failed", "error_code": "provider_rejected"}
        current = getattr(current, "__cause__", None) or getattr(
            current, "__context__", None
        )
    return {"status": "failed", "error_code": "provider_call_failed"}


def _read_strict_provider_base_url(client: Any) -> Optional[str]:
    direct = read_base_url(client)
    if direct:
        return direct
    try:
        value = client._api_client._http_options.base_url
    except Exception:
        return None
    return value if isinstance(value, str) and value else None


def strict_provider_target_v2_1(client: Any) -> str:
    base_url = _read_strict_provider_base_url(client)
    if not base_url:
        raise ObsvrStrictProviderBoundaryV21Error("context_unavailable")
    try:
        raw_parts = urlsplit(base_url)
        for segment in raw_parts.path.split("/"):
            decoded = unquote(segment)
            if decoded in (".", ".."):
                raise ValueError("ambiguous path")
        loopback = (raw_parts.hostname or "").lower() in _LOOPBACK
        parts = assert_backend_url_static(base_url, allow_private_network=loopback)
        hostname = (parts.hostname or "").lower()
        port = parts.port
    except Exception as error:
        raise ObsvrStrictProviderBoundaryV21Error("context_unavailable") from error
    if (
        not hostname
        or (hostname not in _LOOPBACK and hostname not in _TRUSTED_PROVIDER_HOSTS)
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or (
            parts.scheme != "https"
            and not (parts.scheme == "http" and hostname in _LOOPBACK)
        )
    ):
        raise ObsvrStrictProviderBoundaryV21Error("context_unavailable")
    rendered_host = f"[{hostname}]" if ":" in hostname else hostname.lower()
    if port is not None and not (
        (parts.scheme == "https" and port == 443)
        or (parts.scheme == "http" and port == 80)
    ):
        rendered_host = f"{rendered_host}:{port}"
    path = parts.path or "/"
    if path != "/":
        path = path.rstrip("/") or "/"
    return f"{parts.scheme}://{rendered_host}{path}"


def execute_strict_provider_call_v2_1(
    capability: StrictProviderBoundaryV21Capability,
    *,
    call: Dict[str, Any],
    invocation: Dict[str, Any],
    invoke: Callable[[Dict[str, Any]], Any],
) -> Any:
    assert_strict_provider_boundary_v2_1(capability)
    binding = _CAPABILITIES[capability]
    trusted_call = copy.deepcopy(call)
    try:
        context = copy.deepcopy(binding["context"](copy.deepcopy(trusted_call)))
    except Exception as error:
        raise ObsvrStrictProviderBoundaryV21Error("context_unavailable") from error

    action_id = str(uuid.uuid4())
    try:
        original = bind_strict_v2_1_json_arguments(invocation)
    except Exception as error:
        raise ObsvrStrictProviderBoundaryV21Error("context_unavailable") from error
    action = {
        "runtime_action_id": action_id,
        "original_arguments": original,
        "invoke": invoke,
        "result_projection": lambda value: _provider_result_projection(
            trusted_call, value
        ),
        "classify_error": _classify_provider_error,
    }
    try:
        result = run_trusted_strict_receipt_runtime_v2_1(
            binding["runtime"],
            decision={
                "action_id": action_id,
                "active_intents": context["active_intents"],
                "current_action": {
                    "kind": "model_call",
                    "name": trusted_call["operation"],
                    "arguments_hash": original.arguments_hash,
                    "target_hash": action_target_hash(trusted_call["target"]),
                    "data_classifications": trusted_call["data_classifications"],
                    "requested_scopes": sorted(
                        set(context.get("requested_scopes") or []) | {"model:invoke"}
                    ),
                },
                "run_id": context["run_id"],
                **(
                    {"thread_id": context["thread_id"]}
                    if "thread_id" in context
                    else {}
                ),
            },
            action=action,
        )
    except ObsvrStrictProviderBoundaryV21Error:
        raise
    except Exception as error:
        raise ObsvrStrictProviderBoundaryV21Error("runtime_unavailable") from error

    if result["status"] == "executed":
        return result["value"]
    if result["status"] == "invocation_failed":
        raise result["error"]
    if result["status"] == "nonexecuted" and result.get("reason") == "not_authorized":
        raise ObsvrStrictProviderBoundaryV21Error(
            "not_authorized", result.get("receipt_hash")
        )
    raise ObsvrStrictProviderBoundaryV21Error(
        "admission_not_confirmed", result.get("receipt_hash")
    )


__all__ = [
    "ObsvrStrictProviderBoundaryV21Error",
    "StrictProviderBoundaryV21Capability",
    "create_strict_provider_boundary_v2_1",
]
