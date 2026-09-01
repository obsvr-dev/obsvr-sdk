"""Explicit, bounded publication of signed coverage and workload proofs."""

from __future__ import annotations

import json
import queue
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

from .coverage_attestation import verify_coverage_attestation
from .device_identity import DeviceSigner
from .external_backend import _pinned_request
from .ssrf import (
    AllowedBackendTarget,
    SsrfError,
    assert_backend_url_static,
    resolve_backend_url_allowed,
)
from .tool_pinning import _canonical_json_for_hash
from .workload_registry_v1 import verify_workload_registration_v1

_MAX_REQUEST_BYTES = 1_048_576
_MAX_RESPONSE_BYTES = 65_536
_MAX_TIMEOUT_MS = 60_000
_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_TRUST = frozenset({"pinned", "self_presented"})

PinnedTransport = Callable[
    [AllowedBackendTarget, Dict[str, str], bytes, float, int],
    Tuple[int, Optional[bytes]],
]


class DeploymentProofPublishError(ValueError):
    """A local proof or publication configuration is invalid."""


def _positive_integer(value: Any, fallback: int, maximum: int, field: str) -> int:
    resolved = fallback if value is None else value
    if (
        isinstance(resolved, bool)
        or not isinstance(resolved, int)
        or resolved <= 0
        or resolved > maximum
        or resolved > _MAX_SAFE_INTEGER
    ):
        raise DeploymentProofPublishError(
            f"{field} is outside its supported positive range"
        )
    return resolved


def _nonblank(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DeploymentProofPublishError(f"{field} must be a nonblank string")
    return value


def _endpoint(value: Any, path: str) -> Tuple[str, bool]:
    raw = _nonblank(value, "ingest_url")
    try:
        host = (urlsplit(raw).hostname or "").lower()
    except ValueError:
        host = ""
    allow_loopback = host in _LOCAL_HOSTS
    try:
        parsed = assert_backend_url_static(raw, allow_loopback)
        port = parsed.port
    except (SsrfError, TypeError, ValueError):
        raise DeploymentProofPublishError(
            "ingest_url failed static security validation"
        ) from None
    if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
        raise DeploymentProofPublishError(
            "ingest_url must be an absolute HTTP(S) URL without credentials, query, or fragment"
        )
    if parsed.scheme == "http" and not allow_loopback:
        raise DeploymentProofPublishError(
            "ingest_url must use HTTPS unless it targets loopback"
        )
    hostname = parsed.hostname or ""
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    authority = hostname if port is None else f"{hostname}:{port}"
    return (
        urlunsplit(
            (parsed.scheme, authority, parsed.path.rstrip("/") + path, "", "")
        ),
        allow_loopback,
    )


def _resolve_target_bounded(
    url: str,
    allow_loopback: bool,
    resolver: Optional[Callable[[str], List[str]]],
    timeout_s: float,
) -> AllowedBackendTarget:
    result: queue.Queue[Tuple[bool, Any]] = queue.Queue(maxsize=1)

    def resolve() -> None:
        try:
            result.put(
                (True, resolve_backend_url_allowed(url, allow_loopback, resolver))
            )
        except Exception as exc:
            result.put((False, exc))

    worker = threading.Thread(target=resolve, daemon=True)
    worker.start()
    worker.join(timeout_s)
    if worker.is_alive() or result.empty():
        raise TimeoutError("deployment proof DNS resolution timed out")
    ok, value = result.get_nowait()
    if not ok:
        raise value
    return value


def _parsed(raw: Optional[bytes]) -> Optional[Dict[str, Any]]:
    if not raw:
        return None
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _accepted(
    kind: str,
    response: Optional[Dict[str, Any]],
    envelope: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    if (
        not response
        or response.get("ok") is not True
        or response.get("body_hash") != envelope.get("body_hash")
        or response.get("trust") not in _TRUST
    ):
        return None
    if kind == "coverage" and not isinstance(response.get("coverage_complete"), bool):
        return None
    if kind == "workload" and (
        response.get("workload_id") != envelope["body"].get("workload_id")
        or response.get("deployment_id") != envelope["body"].get("deployment_id")
    ):
        return None
    return {
        "disposition": "accepted",
        "kind": kind,
        "body_hash": envelope["body_hash"],
        "trust": response["trust"],
    }


def _publish(
    kind: str,
    path: str,
    envelope: Dict[str, Any],
    *,
    ingest_url: str,
    api_key: str,
    signer: DeviceSigner,
    timeout_ms: int,
    max_response_bytes: int,
    trusted_pinned_transport: Optional[PinnedTransport],
    resolver: Optional[Callable[[str], List[str]]],
) -> Dict[str, Any]:
    url, allow_loopback = _endpoint(ingest_url, path)
    key = _nonblank(api_key, "api_key")
    timeout = _positive_integer(timeout_ms, 5_000, _MAX_TIMEOUT_MS, "timeout_ms")
    response_limit = _positive_integer(
        max_response_bytes,
        _MAX_RESPONSE_BYTES,
        _MAX_RESPONSE_BYTES,
        "max_response_bytes",
    )
    if trusted_pinned_transport is not None and not callable(trusted_pinned_transport):
        raise DeploymentProofPublishError(
            "trusted_pinned_transport must be callable"
        )
    try:
        body = _canonical_json_for_hash(envelope).encode("utf-8")
    except Exception:
        raise DeploymentProofPublishError(
            f"{kind} envelope cannot be serialized canonically"
        ) from None
    if len(body) > _MAX_REQUEST_BYTES:
        raise DeploymentProofPublishError(
            f"{kind} envelope exceeds the supported request size"
        )
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": key,
        "X-Obsvr-Device-Public-Key": signer.public_key_b64,
        "Idempotency-Key": envelope["body_hash"],
    }
    started = time.monotonic()
    try:
        target = _resolve_target_bounded(
            url, allow_loopback, resolver, timeout / 1000.0
        )
        remaining = timeout / 1000.0 - (time.monotonic() - started)
        if remaining <= 0:
            raise TimeoutError("deployment proof timeout budget exhausted")
        transport = trusted_pinned_transport or _pinned_request
        status, raw = transport(target, headers, body, remaining, response_limit)
    except Exception:
        return {
            "disposition": "uncertain",
            "kind": kind,
            "body_hash": envelope["body_hash"],
            "reason": "transport_error",
        }
    if 300 <= status < 400:
        return {
            "disposition": "uncertain",
            "kind": kind,
            "body_hash": envelope["body_hash"],
            "reason": "redirect",
        }
    parsed = _parsed(raw)
    if 200 <= status < 300:
        return _accepted(kind, parsed, envelope) or {
            "disposition": "uncertain",
            "kind": kind,
            "body_hash": envelope["body_hash"],
            "reason": "invalid_response",
        }
    if parsed and parsed.get("ok") is False and isinstance(parsed.get("error"), str) and parsed["error"]:
        return {
            "disposition": "rejected",
            "kind": kind,
            "body_hash": envelope["body_hash"],
            "http_status": status,
            "error": parsed["error"],
        }
    return {
        "disposition": "uncertain",
        "kind": kind,
        "body_hash": envelope["body_hash"],
        "reason": "invalid_response",
    }


def publish_coverage_attestation(
    envelope: Dict[str, Any],
    *,
    ingest_url: str,
    api_key: str,
    signer: DeviceSigner,
    timeout_ms: int = 5_000,
    max_response_bytes: int = _MAX_RESPONSE_BYTES,
    trusted_pinned_transport: Optional[PinnedTransport] = None,
    resolver: Optional[Callable[[str], List[str]]] = None,
) -> Dict[str, Any]:
    verification = verify_coverage_attestation(envelope, signer.raw_public_key)
    if verification.get("valid") is not True:
        raise DeploymentProofPublishError(
            f"coverage envelope is invalid: {verification.get('reason', 'unknown')}"
        )
    return _publish(
        "coverage",
        "/coverage/attestations",
        envelope,
        ingest_url=ingest_url,
        api_key=api_key,
        signer=signer,
        timeout_ms=timeout_ms,
        max_response_bytes=max_response_bytes,
        trusted_pinned_transport=trusted_pinned_transport,
        resolver=resolver,
    )


def publish_workload_registration(
    envelope: Dict[str, Any],
    *,
    ingest_url: str,
    api_key: str,
    signer: DeviceSigner,
    timeout_ms: int = 5_000,
    max_response_bytes: int = _MAX_RESPONSE_BYTES,
    trusted_pinned_transport: Optional[PinnedTransport] = None,
    resolver: Optional[Callable[[str], List[str]]] = None,
) -> Dict[str, Any]:
    if not verify_workload_registration_v1(envelope, signer.raw_public_key):
        raise DeploymentProofPublishError("workload envelope is invalid")
    return _publish(
        "workload",
        "/workloads/registrations",
        envelope,
        ingest_url=ingest_url,
        api_key=api_key,
        signer=signer,
        timeout_ms=timeout_ms,
        max_response_bytes=max_response_bytes,
        trusted_pinned_transport=trusted_pinned_transport,
        resolver=resolver,
    )


def publish_deployment_proofs(
    coverage: Dict[str, Any],
    workload: Optional[Dict[str, Any]],
    **options: Any,
) -> Dict[str, Any]:
    """Publish coverage first; never send a workload without accepted coverage."""
    if workload is not None and (
        workload.get("body", {}).get("coverage_attestation_hash")
        != coverage.get("body_hash")
        or workload.get("body", {}).get("workload_id")
        != coverage.get("body", {}).get("workload_id")
        or workload.get("body", {}).get("environment")
        != coverage.get("body", {}).get("environment")
        or workload.get("key_id") != coverage.get("key_id")
    ):
        raise DeploymentProofPublishError(
            "workload registration must bind the same coverage hash, workload, environment, and signer"
        )
    coverage_result = publish_coverage_attestation(coverage, **options)
    result: Dict[str, Any] = {"coverage": coverage_result}
    if workload is None:
        return result
    if coverage_result["disposition"] != "accepted":
        result["workload"] = {
            "disposition": "not_attempted",
            "kind": "workload",
            "body_hash": workload["body_hash"],
            "reason": "coverage_not_accepted",
        }
        return result
    result["workload"] = publish_workload_registration(workload, **options)
    return result


__all__ = [
    "DeploymentProofPublishError",
    "publish_coverage_attestation",
    "publish_workload_registration",
    "publish_deployment_proofs",
]
