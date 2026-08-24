"""Bounded, idempotent HTTP admission for one strict receipt."""

from __future__ import annotations

import json
import math
import queue
import random
import threading
import time
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Literal,
    Optional,
    Tuple,
    TypedDict,
    Union,
    cast,
)
from urllib.error import HTTPError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request

from .external_backend import _pinned_request
from .ssrf import (
    AllowedBackendTarget,
    SsrfError,
    assert_backend_url_static,
    resolve_backend_url_allowed,
)
from .tool_pinning import _canonical_json_for_hash

STRICT_RECEIPT_INGEST_SCHEMA = "obsvr-strict-receipt-ingest-v1"
STRICT_RECEIPT_ADMISSION_SCHEMA = "obsvr-strict-receipt-admission-v1"

_DEFINITIVE_NO_STORE = frozenset({400, 401, 403, 413})
_RETRYABLE = frozenset({408, 429})
_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_HEX = frozenset("0123456789abcdef")
_MAX_TIMEOUT_MS = 60_000
_MAX_RETRY_DEADLINE_MS = 300_000
_MAX_ATTEMPTS = 20
_MAX_REQUEST_BYTES = 1_048_576
_MAX_RESPONSE_BYTES = 1_048_576
_MAX_RETRY_DELAY_MS = 60_000
_LOCAL_INGEST_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


class StrictAdmissionAccepted(TypedDict):
    disposition: Literal["accepted"]
    receipt_hash: str
    status: Literal["accepted", "already_accepted"]
    attempts: int


class StrictAdmissionDefinitiveNoStore(TypedDict):
    disposition: Literal["definitive_no_store"]
    receipt_hash: str
    http_status: Literal[400, 401, 403, 413]
    attempts: int


class StrictAdmissionUncertain(TypedDict):
    disposition: Literal["uncertain"]
    receipt_hash: str
    reason: Literal["redirect", "conflict", "invalid_response", "retry_exhausted"]
    attempts: int


StrictAdmissionResult = Union[
    StrictAdmissionAccepted,
    StrictAdmissionDefinitiveNoStore,
    StrictAdmissionUncertain,
]


class StrictAdmissionValidationError(ValueError):
    """Configuration or receipt input cannot form one bounded request."""


PinnedTransport = Callable[
    [AllowedBackendTarget, Dict[str, str], bytes, float, int],
    Tuple[int, Optional[bytes]],
]


def _positive_integer(value: Any, fallback: int, maximum: int, field: str) -> int:
    resolved = fallback if value is None else value
    if (
        isinstance(resolved, bool)
        or not isinstance(resolved, int)
        or resolved <= 0
        or resolved > _MAX_SAFE_INTEGER
        or resolved > maximum
    ):
        raise StrictAdmissionValidationError(
            f"{field} is outside its supported positive range"
        )
    return resolved


def _nonblank(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise StrictAdmissionValidationError(f"{field} must be a nonblank string")
    return value


def _endpoint(value: Any) -> str:
    raw = _nonblank(value, "ingest_url")
    try:
        host = (urlsplit(raw).hostname or "").lower()
    except ValueError:
        host = ""
    is_local = host in _LOCAL_INGEST_HOSTS
    try:
        parsed = assert_backend_url_static(raw, is_local)
        port = parsed.port
    except (SsrfError, TypeError, ValueError):
        raise StrictAdmissionValidationError(
            "ingest_url failed static security validation"
        ) from None
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise StrictAdmissionValidationError(
            "ingest_url must be an absolute HTTP(S) URL without credentials, query, or fragment"
        )
    if parsed.scheme == "http" and not is_local:
        raise StrictAdmissionValidationError(
            "ingest_url must use HTTPS unless it targets loopback"
        )
    hostname = parsed.hostname
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    authority = hostname if port is None else f"{hostname}:{port}"
    path = parsed.path.rstrip("/") + "/ingest/strict-receipts"
    return urlunsplit((parsed.scheme, authority, path, "", ""))


def _receipt_hash(receipt: Any) -> str:
    if not isinstance(receipt, dict):
        raise StrictAdmissionValidationError(
            "receipt must be a strict receipt envelope"
        )
    value = receipt.get("receipt_hash")
    if (
        receipt.get("schema") != "obsvr-strict-receipt-envelope-v1"
        or not isinstance(value, str)
        or len(value) != 64
        or any(char not in _HEX for char in value)
    ):
        raise StrictAdmissionValidationError(
            "receipt must be a strict receipt envelope with a valid receipt_hash"
        )
    return value


def _resolve_target_bounded(
    url: str,
    allow_loopback: bool,
    resolver: Optional[Callable[[str], List[str]]],
    timeout_s: float,
) -> AllowedBackendTarget:
    """Bound a potentially blocking system/custom resolver for one attempt."""
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
        raise TimeoutError("strict admission DNS resolution timed out")
    ok, value = result.get_nowait()
    if not ok:
        raise cast(Exception, value)
    return cast(AllowedBackendTarget, value)


def _status(response: Any) -> int:
    value = getattr(response, "status", None)
    if value is None and hasattr(response, "getcode"):
        value = response.getcode()
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _read_bounded(response: Any, limit: int) -> Optional[bytes]:
    headers = getattr(response, "headers", None)
    declared = headers.get("Content-Length") if headers is not None else None
    if declared is not None:
        try:
            if int(declared) < 0 or int(declared) > limit:
                return None
        except (TypeError, ValueError):
            return None
    try:
        body = response.read(limit + 1)
    except Exception:
        return None
    if not isinstance(body, bytes) or len(body) > limit:
        return None
    return body


def _parsed(body: Optional[bytes]) -> Optional[Dict[str, Any]]:
    if not body:
        return None
    try:
        value = json.loads(body.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _accepted(
    response: Optional[Dict[str, Any]], expected_hash: str
) -> Optional[Literal["accepted", "already_accepted"]]:
    if response is None or set(response) != {
        "schema",
        "ok",
        "status",
        "receipt_hash",
        "accepted_at_ms",
    }:
        return None
    accepted_at = response.get("accepted_at_ms")
    if (
        response.get("schema") != STRICT_RECEIPT_ADMISSION_SCHEMA
        or response.get("ok") is not True
        or response.get("receipt_hash") != expected_hash
        or response.get("status") not in ("accepted", "already_accepted")
        or isinstance(accepted_at, bool)
        or not isinstance(accepted_at, int)
        or accepted_at < 0
        or accepted_at > _MAX_SAFE_INTEGER
    ):
        return None
    return cast(Literal["accepted", "already_accepted"], response["status"])


def _explicit_no_store(response: Optional[Dict[str, Any]], expected_hash: str) -> bool:
    return bool(
        response is not None
        and set(response)
        == {"schema", "ok", "status", "code", "stored", "receipt_hash"}
        and response.get("schema") == STRICT_RECEIPT_ADMISSION_SCHEMA
        and response.get("ok") is False
        and response.get("status") == "rejected"
        and isinstance(response.get("code"), str)
        and bool(response["code"])
        and response.get("stored") is False
        and response.get("receipt_hash") == expected_hash
    )


def _explicit_conflict(response: Optional[Dict[str, Any]], expected_hash: str) -> bool:
    return bool(
        response is not None
        and set(response) == {"schema", "ok", "status", "code", "receipt_hash"}
        and response.get("schema") == STRICT_RECEIPT_ADMISSION_SCHEMA
        and response.get("ok") is False
        and response.get("status") == "conflict"
        and isinstance(response.get("code"), str)
        and bool(response["code"])
        and response.get("receipt_hash") == expected_hash
    )


def admit_strict_receipt(
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
    trusted_urlopen_fn: Optional[Callable[..., Any]] = None,
    trusted_pinned_transport: Optional[PinnedTransport] = None,
    resolver: Optional[Callable[[str], List[str]]] = None,
    clock_ms: Optional[Callable[[], float]] = None,
    sleep: Optional[Callable[[float], None]] = None,
    jitter: Optional[Callable[[], float]] = None,
) -> StrictAdmissionResult:
    """Admit one receipt, preserving identical bytes and idempotency on retry."""
    receipt_hash = _receipt_hash(receipt)
    url = _endpoint(ingest_url)
    key = _nonblank(api_key, "api_key")
    timeout = _positive_integer(timeout_ms, 2_000, _MAX_TIMEOUT_MS, "timeout_ms")
    deadline = _positive_integer(
        retry_deadline_ms, 10_000, _MAX_RETRY_DEADLINE_MS, "retry_deadline_ms"
    )
    attempts_limit = _positive_integer(max_attempts, 3, _MAX_ATTEMPTS, "max_attempts")
    response_limit = _positive_integer(
        max_response_bytes, 65_536, _MAX_RESPONSE_BYTES, "max_response_bytes"
    )
    retry_base = _positive_integer(
        retry_base_ms, 100, _MAX_RETRY_DELAY_MS, "retry_base_ms"
    )
    retry_max = _positive_integer(
        retry_max_ms, 2_000, _MAX_RETRY_DELAY_MS, "retry_max_ms"
    )
    if trusted_urlopen_fn is not None and not callable(trusted_urlopen_fn):
        raise StrictAdmissionValidationError("trusted_urlopen_fn must be callable")
    if trusted_pinned_transport is not None and not callable(trusted_pinned_transport):
        raise StrictAdmissionValidationError(
            "trusted_pinned_transport must be callable"
        )
    now = clock_ms or (lambda: time.monotonic() * 1000.0)
    sleeper = sleep or (lambda delay_ms: time.sleep(delay_ms / 1000.0))
    random_fraction = jitter or random.random
    try:
        body = _canonical_json_for_hash(
            {"schema": STRICT_RECEIPT_INGEST_SCHEMA, "receipt": receipt}
        ).encode("utf-8")
    except Exception:
        raise StrictAdmissionValidationError(
            "receipt cannot be serialized canonically"
        ) from None
    if len(body) > _MAX_REQUEST_BYTES:
        raise StrictAdmissionValidationError(
            "receipt ingest request exceeds its supported size"
        )
    started = now()
    attempts = 0
    allow_loopback = (urlsplit(url).hostname or "").lower() in _LOCAL_INGEST_HOSTS
    request_headers = {
        "Content-Type": "application/json",
        "X-API-Key": key,
        "Idempotency-Key": receipt_hash,
    }

    while attempts < attempts_limit and now() - started < deadline:
        attempts += 1
        remaining = deadline - (now() - started)
        response = None
        status = 0
        parsed = None
        try:
            timeout_s = max(0.001, min(timeout, remaining) / 1000.0)
            if trusted_urlopen_fn is not None:
                req = Request(url, data=body, headers=request_headers, method="POST")
                response = trusted_urlopen_fn(req, timeout=timeout_s)
                status = _status(response)
                parsed = _parsed(_read_bounded(response, response_limit))
            else:
                attempt_started = time.monotonic()
                target = _resolve_target_bounded(
                    url, allow_loopback, resolver, timeout_s
                )
                transport_timeout = timeout_s - (time.monotonic() - attempt_started)
                if transport_timeout <= 0:
                    raise TimeoutError("strict admission timeout budget exhausted")
                transport = trusted_pinned_transport or _pinned_request
                status, raw = transport(
                    target,
                    request_headers,
                    body,
                    transport_timeout,
                    response_limit,
                )
                response = True
                parsed = _parsed(raw)
        except HTTPError as error:
            response = error
            status = error.code
            parsed = _parsed(_read_bounded(response, response_limit))
        except Exception:
            response = None

        if response is not None:
            if 300 <= status < 400:
                return {
                    "disposition": "uncertain",
                    "receipt_hash": receipt_hash,
                    "reason": "redirect",
                    "attempts": attempts,
                }
            if 200 <= status < 300:
                accepted = _accepted(parsed, receipt_hash)
                if accepted is None:
                    return {
                        "disposition": "uncertain",
                        "receipt_hash": receipt_hash,
                        "reason": "invalid_response",
                        "attempts": attempts,
                    }
                return {
                    "disposition": "accepted",
                    "receipt_hash": receipt_hash,
                    "status": accepted,
                    "attempts": attempts,
                }
            if status in _DEFINITIVE_NO_STORE and _explicit_no_store(
                parsed, receipt_hash
            ):
                return {
                    "disposition": "definitive_no_store",
                    "receipt_hash": receipt_hash,
                    "http_status": cast(Literal[400, 401, 403, 413], status),
                    "attempts": attempts,
                }
            if status == 409:
                return {
                    "disposition": "uncertain",
                    "receipt_hash": receipt_hash,
                    "reason": "conflict"
                    if _explicit_conflict(parsed, receipt_hash)
                    else "invalid_response",
                    "attempts": attempts,
                }
            if status < 500 and status not in _RETRYABLE:
                return {
                    "disposition": "uncertain",
                    "receipt_hash": receipt_hash,
                    "reason": "invalid_response",
                    "attempts": attempts,
                }

        if attempts >= attempts_limit or now() - started >= deadline:
            break
        fraction = random_fraction()
        if (
            isinstance(fraction, bool)
            or not isinstance(fraction, (int, float))
            or not math.isfinite(fraction)
            or fraction < 0
            or fraction > 1
        ):
            raise StrictAdmissionValidationError(
                "jitter must return a number from 0 through 1"
            )
        ceiling = min(retry_max, retry_base * (2 ** (attempts - 1)))
        delay = math.floor(ceiling * (0.5 + float(fraction) / 2.0))
        budget = deadline - (now() - started)
        if budget <= 0:
            break
        sleeper(min(delay, budget))

    return {
        "disposition": "uncertain",
        "receipt_hash": receipt_hash,
        "reason": "retry_exhausted",
        "attempts": attempts,
    }
