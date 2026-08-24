"""DNS-pinned, bounded admission for strict v2 receipts."""

from __future__ import annotations

import json
import queue
import random
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

from .external_backend import _pinned_request
from .ssrf import (
    AllowedBackendTarget,
    assert_backend_url_static,
    resolve_backend_url_allowed,
)
from .tool_pinning import _canonical_json_for_hash

STRICT_RECEIPT_V2_INGEST_SCHEMA = "obsvr-strict-receipt-ingest-v2"
STRICT_RECEIPT_V2_ADMISSION_SCHEMA = "obsvr-strict-receipt-admission-v2"
STRICT_RECEIPT_V2_ENDPOINT = "/ingest/strict-receipts/v2"

_NO_STORE = frozenset({400, 401, 403, 413})
_RETRYABLE = frozenset({408, 429})
_LOCAL = frozenset({"localhost", "127.0.0.1", "::1"})
_HEX = frozenset("0123456789abcdef")
_MAX_REQUEST = 1_048_576
_MAX_RESPONSE = 1_048_576

PinnedTransport = Callable[
    [AllowedBackendTarget, Dict[str, str], bytes, float, int],
    Tuple[int, Optional[bytes]],
]


class StrictAdmissionV2ValidationError(ValueError):
    """Configuration or input cannot form a bounded v2 admission request."""


def _positive(value: Any, fallback: int, maximum: int, field: str) -> int:
    result = fallback if value is None else value
    if (
        isinstance(result, bool)
        or not isinstance(result, int)
        or result <= 0
        or result > maximum
    ):
        raise StrictAdmissionV2ValidationError(
            f"{field} is outside its supported positive range"
        )
    return result


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise StrictAdmissionV2ValidationError(f"{field} must be nonblank")
    return value


def _endpoint(value: Any) -> Tuple[str, bool]:
    raw = _text(value, "ingest_url")
    try:
        host = (urlsplit(raw).hostname or "").lower()
    except ValueError:
        host = ""
    loopback = host in _LOCAL
    try:
        parsed = assert_backend_url_static(raw, loopback)
        port = parsed.port
    except Exception:
        raise StrictAdmissionV2ValidationError(
            "ingest_url failed static security validation"
        ) from None
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise StrictAdmissionV2ValidationError(
            "ingest_url cannot contain credentials, query, or fragment"
        )
    if parsed.scheme == "http" and not loopback:
        raise StrictAdmissionV2ValidationError(
            "ingest_url must use HTTPS unless it targets loopback"
        )
    hostname = parsed.hostname or ""
    authority = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None:
        authority += f":{port}"
    path = parsed.path.rstrip("/") + STRICT_RECEIPT_V2_ENDPOINT
    return urlunsplit((parsed.scheme, authority, path, "", "")), loopback


def _identity(receipt: Any) -> Dict[str, Any]:
    if not isinstance(receipt, dict) or not isinstance(receipt.get("body"), dict):
        raise StrictAdmissionV2ValidationError(
            "receipt must be a valid strict v2 envelope"
        )
    body = receipt["body"]
    receipt_hash = receipt.get("receipt_hash")
    if (
        receipt.get("schema") != "obsvr-strict-receipt-envelope-v2"
        or body.get("schema") != "obsvr-strict-receipt-v2"
        or not isinstance(receipt_hash, str)
        or len(receipt_hash) != 64
        or any(char not in _HEX for char in receipt_hash)
    ):
        raise StrictAdmissionV2ValidationError(
            "receipt must be a valid strict v2 envelope"
        )
    return {
        "schema": STRICT_RECEIPT_V2_ADMISSION_SCHEMA,
        "tenant_id": _text(body.get("tenant_id"), "tenant_id"),
        "session_id": _text(body.get("session_id"), "session_id"),
        "receipt_hash": receipt_hash,
    }


def _resolve_bounded(
    url: str,
    loopback: bool,
    resolver: Optional[Callable[[str], List[str]]],
    timeout: float,
) -> AllowedBackendTarget:
    result: queue.Queue[Tuple[bool, Any]] = queue.Queue(maxsize=1)

    def work() -> None:
        try:
            result.put((True, resolve_backend_url_allowed(url, loopback, resolver)))
        except Exception as error:
            result.put((False, error))

    worker = threading.Thread(target=work, daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive() or result.empty():
        raise TimeoutError("strict v2 admission DNS resolution timed out")
    ok, value = result.get_nowait()
    if not ok:
        raise value
    return value


def _parsed(raw: Optional[bytes]) -> Optional[Dict[str, Any]]:
    if not raw:
        return None
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _accepted(value: Optional[Dict[str, Any]], receipt_hash: str) -> Optional[str]:
    if (
        value is None
        or set(value) != {"schema", "ok", "status", "receipt_hash", "accepted_at_ms"}
        or value.get("schema") != STRICT_RECEIPT_V2_ADMISSION_SCHEMA
        or value.get("ok") is not True
        or value.get("receipt_hash") != receipt_hash
        or value.get("status") not in ("accepted", "already_accepted")
        or isinstance(value.get("accepted_at_ms"), bool)
        or not isinstance(value.get("accepted_at_ms"), int)
        or value["accepted_at_ms"] < 0
    ):
        return None
    return value["status"]


def _no_store(value: Optional[Dict[str, Any]], receipt_hash: str) -> bool:
    return bool(
        value is not None
        and set(value) == {"schema", "ok", "status", "code", "stored", "receipt_hash"}
        and value.get("schema") == STRICT_RECEIPT_V2_ADMISSION_SCHEMA
        and value.get("ok") is False
        and value.get("status") == "rejected"
        and value.get("stored") is False
        and value.get("receipt_hash") == receipt_hash
        and isinstance(value.get("code"), str)
        and bool(value["code"])
    )


def _conflict(value: Optional[Dict[str, Any]], receipt_hash: str) -> bool:
    return bool(
        value is not None
        and set(value) == {"schema", "ok", "status", "code", "receipt_hash"}
        and value.get("schema") == STRICT_RECEIPT_V2_ADMISSION_SCHEMA
        and value.get("ok") is False
        and value.get("status") == "conflict"
        and value.get("receipt_hash") == receipt_hash
        and isinstance(value.get("code"), str)
        and bool(value["code"])
    )


def admit_strict_receipt_v2(
    receipt: Dict[str, Any],
    *,
    ingest_url: str,
    api_key: str,
    timeout_ms: int = 2_000,
    retry_deadline_ms: int = 10_000,
    max_attempts: int = 3,
    max_response_bytes: int = 65_536,
    retry_base_ms: int = 100,
    retry_max_ms: int = 2_000,
    trusted_pinned_transport: Optional[PinnedTransport] = None,
    resolver: Optional[Callable[[str], List[str]]] = None,
    clock_ms: Optional[Callable[[], float]] = None,
    sleep: Optional[Callable[[float], None]] = None,
    jitter: Optional[Callable[[], float]] = None,
) -> Dict[str, Any]:
    """Admit through a fresh socket pinned to each approved DNS snapshot."""
    identity = _identity(receipt)
    url, loopback = _endpoint(ingest_url)
    key = _text(api_key, "api_key")
    timeout = _positive(timeout_ms, 2_000, 60_000, "timeout_ms")
    deadline = _positive(retry_deadline_ms, 10_000, 300_000, "retry_deadline_ms")
    maximum = _positive(max_attempts, 3, 20, "max_attempts")
    response_limit = _positive(
        max_response_bytes, 65_536, _MAX_RESPONSE, "max_response_bytes"
    )
    retry_base = _positive(retry_base_ms, 100, 60_000, "retry_base_ms")
    retry_max = _positive(retry_max_ms, 2_000, 60_000, "retry_max_ms")
    if trusted_pinned_transport is not None and not callable(trusted_pinned_transport):
        raise StrictAdmissionV2ValidationError(
            "trusted_pinned_transport must be callable"
        )
    body = _canonical_json_for_hash(
        {
            "schema": STRICT_RECEIPT_V2_INGEST_SCHEMA,
            "tenant_id": identity["tenant_id"],
            "session_id": identity["session_id"],
            "receipt": receipt,
        }
    ).encode("utf-8")
    if len(body) > _MAX_REQUEST:
        raise StrictAdmissionV2ValidationError(
            "receipt ingest request exceeds its supported size"
        )
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": key,
        "Idempotency-Key": identity["receipt_hash"],
    }
    now = clock_ms or (lambda: time.monotonic() * 1000.0)
    sleeper = sleep or (lambda delay: time.sleep(delay / 1000.0))
    fraction = jitter or random.random
    started = now()
    attempts = 0
    while attempts < maximum and now() - started < deadline:
        attempts += 1
        remaining = deadline - (now() - started)
        status = 0
        raw = None
        try:
            timeout_s = max(0.001, min(timeout, remaining) / 1000.0)
            begun = time.monotonic()
            target = _resolve_bounded(url, loopback, resolver, timeout_s)
            transport_timeout = timeout_s - (time.monotonic() - begun)
            if transport_timeout <= 0:
                raise TimeoutError("strict v2 admission timeout exhausted")
            status, raw = (trusted_pinned_transport or _pinned_request)(
                target, headers, body, transport_timeout, response_limit
            )
        except Exception:
            status = 0
        value = _parsed(raw)
        if 300 <= status < 400:
            return {
                **identity,
                "attempts": attempts,
                "disposition": "uncertain",
                "reason": "redirect",
            }
        retryable = status == 0 or status in _RETRYABLE or status >= 500
        if not retryable:
            if 200 <= status < 300:
                accepted = _accepted(value, identity["receipt_hash"])
                if accepted is not None:
                    return {
                        **identity,
                        "attempts": attempts,
                        "disposition": "accepted",
                        "status": accepted,
                    }
                return {
                    **identity,
                    "attempts": attempts,
                    "disposition": "uncertain",
                    "reason": "invalid_response",
                }
            if status in _NO_STORE and _no_store(value, identity["receipt_hash"]):
                return {
                    **identity,
                    "attempts": attempts,
                    "disposition": "definitive_no_store",
                    "http_status": status,
                }
            if status == 409 and _conflict(value, identity["receipt_hash"]):
                return {
                    **identity,
                    "attempts": attempts,
                    "disposition": "uncertain",
                    "reason": "conflict",
                }
            return {
                **identity,
                "attempts": attempts,
                "disposition": "uncertain",
                "reason": "invalid_response",
            }
        if attempts >= maximum or now() - started >= deadline:
            break
        delay = min(retry_max, retry_base * (2 ** (attempts - 1)))
        sleeper(min(deadline - (now() - started), int(delay * fraction())))
    return {
        **identity,
        "attempts": attempts,
        "disposition": "uncertain",
        "reason": "retry_exhausted",
    }
