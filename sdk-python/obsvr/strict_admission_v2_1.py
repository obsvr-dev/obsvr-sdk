"""DNS-pinned admission and prepared-state reconciliation for 2.1 decisions."""

from __future__ import annotations

import copy
import json
import random
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

from .external_backend import _pinned_request
from .ssrf import AllowedBackendTarget, assert_backend_url_static
from .strict_admission_v2 import _positive, _resolve_bounded, _text
from .strict_receipt_prepared_state import DEFINITIVE_NO_STORE
from .strict_receipt_v2_1_verify import verify_strict_receipt_v2_1
from .tool_pinning import _canonical_json_for_hash

STRICT_RECEIPT_V2_1_INGEST_SCHEMA = "obsvr-strict-receipt-ingest-v2-1"
STRICT_RECEIPT_V2_1_ADMISSION_SCHEMA = "obsvr-strict-receipt-admission-v2-1"
STRICT_RECEIPT_V2_1_ENDPOINT = "/ingest/strict-receipts/v2-1"
STRICT_RECEIPT_V2_1_MAX_REQUEST_BYTES = 262_144

_NO_STORE = frozenset({400, 401, 403, 413})
_RETRYABLE = frozenset({408, 429})
_LOCAL = frozenset({"localhost", "127.0.0.1", "::1"})
_HEX = frozenset("0123456789abcdef")
_MAX_RESPONSE = 1_048_576

PinnedTransport = Callable[
    [AllowedBackendTarget, Dict[str, str], bytes, float, int],
    Tuple[int, Optional[bytes]],
]


class StrictAdmissionV21ValidationError(ValueError):
    """Input cannot form an exact prepared profile-2.1 admission."""


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
        raise StrictAdmissionV21ValidationError(
            "ingest_url failed static security validation"
        ) from None
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise StrictAdmissionV21ValidationError(
            "ingest_url cannot contain credentials, query, or fragment"
        )
    if parsed.scheme == "http" and not loopback:
        raise StrictAdmissionV21ValidationError(
            "ingest_url must use HTTPS unless it targets loopback"
        )
    hostname = parsed.hostname or ""
    authority = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None:
        authority += f":{port}"
    path = parsed.path.rstrip("/") + STRICT_RECEIPT_V2_1_ENDPOINT
    return urlunsplit((parsed.scheme, authority, path, "", "")), loopback


def _identity(coordinator: Any, prepared: Any) -> Dict[str, Any]:
    if not isinstance(prepared, dict):
        raise StrictAdmissionV21ValidationError(
            "receipt is not the coordinator current prepared receipt"
        )
    state = coordinator.inspect_state()
    current = state.get("prepared") if isinstance(state, dict) else None
    if (
        state.get("frozen") is not False
        or not isinstance(current, dict)
        or prepared.get("kind") not in ("decision", "resolution")
        or current.get("kind") != prepared.get("kind")
        or prepared.get("token") != current.get("token")
        or prepared.get("receipt_hash") != current.get("receipt_hash")
    ):
        raise StrictAdmissionV21ValidationError(
            "receipt is not the coordinator current prepared receipt"
        )
    value = prepared.get("value")
    receipt = (
        value.get("receipt")
        if prepared.get("kind") == "decision" and isinstance(value, dict)
        else value
    )
    body = receipt.get("body") if isinstance(receipt, dict) else None
    verified = verify_strict_receipt_v2_1(
        receipt,
        trusted_agent_keys=[],
        allowed_evaluator_manifest_hashes=[],
    )
    receipt_hash = receipt.get("receipt_hash") if isinstance(receipt, dict) else None
    if (
        not verified["integrity_valid"]
        or not isinstance(body, dict)
        or body.get("record_type") != prepared.get("kind")
        or body.get("profile_version") != "2.1"
        or not isinstance(receipt_hash, str)
        or len(receipt_hash) != 64
        or any(char not in _HEX for char in receipt_hash)
        or receipt_hash != prepared.get("receipt_hash")
        or body.get("tenant_id") != state.get("tenant_id")
        or body.get("session_id") != state.get("session_id")
    ):
        raise StrictAdmissionV21ValidationError(
            "prepared receipt must be an intact strict profile-2.1 record"
        )
    return {
        "schema": STRICT_RECEIPT_V2_1_ADMISSION_SCHEMA,
        "tenant_id": _text(body.get("tenant_id"), "tenant_id"),
        "session_id": _text(body.get("session_id"), "session_id"),
        "receipt_hash": receipt_hash,
    }


def _parsed(raw: Optional[bytes], limit: int) -> Optional[Dict[str, Any]]:
    if not raw or len(raw) > limit:
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
        or value.get("schema") != STRICT_RECEIPT_V2_1_ADMISSION_SCHEMA
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
        and value.get("schema") == STRICT_RECEIPT_V2_1_ADMISSION_SCHEMA
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
        and value.get("schema") == STRICT_RECEIPT_V2_1_ADMISSION_SCHEMA
        and value.get("ok") is False
        and value.get("status") == "conflict"
        and value.get("receipt_hash") == receipt_hash
        and isinstance(value.get("code"), str)
        and bool(value["code"])
    )


def _assert_request_bytes(body: bytes) -> None:
    if len(body) > STRICT_RECEIPT_V2_1_MAX_REQUEST_BYTES:
        raise StrictAdmissionV21ValidationError(
            "receipt ingest request exceeds its supported size"
        )


def _finish(
    coordinator: Any, prepared: Dict[str, Any], result: Dict[str, Any]
) -> Dict[str, Any]:
    if result["disposition"] == "accepted":
        try:
            coordinator.commit_prepared(prepared["token"], prepared["receipt_hash"])
            return result
        except Exception:
            coordinator.freeze_prepared(
                prepared["token"],
                prepared["receipt_hash"],
                "accepted_but_local_commit_failed",
            )
            return {
                **result,
                "disposition": "uncertain",
                "reason": "local_commit_failed",
            }
    if result["disposition"] == "definitive_no_store":
        coordinator.abort_prepared(
            prepared["token"], prepared["receipt_hash"], DEFINITIVE_NO_STORE
        )
    else:
        coordinator.freeze_prepared(
            prepared["token"], prepared["receipt_hash"], result["reason"]
        )
    return result


def _transport_prepared_strict_receipt_v2_1(
    coordinator: Any,
    prepared: Dict[str, Any],
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
    """Transport only; the caller must reconcile prepared coordinator state."""
    identity = _identity(coordinator, prepared)
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
        raise StrictAdmissionV21ValidationError(
            "trusted_pinned_transport must be callable"
        )
    receipt = copy.deepcopy(
        prepared["value"]["receipt"]
        if prepared["kind"] == "decision"
        else prepared["value"]
    )
    body = _canonical_json_for_hash(
        {
            "schema": STRICT_RECEIPT_V2_1_INGEST_SCHEMA,
            "tenant_id": identity["tenant_id"],
            "session_id": identity["session_id"],
            "receipt": receipt,
        }
    ).encode("utf-8")
    _assert_request_bytes(body)
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
                raise TimeoutError("strict 2.1 admission timeout exhausted")
            status, raw = (trusted_pinned_transport or _pinned_request)(
                target, headers, body, transport_timeout, response_limit
            )
        except Exception:
            status = 0
        value = _parsed(raw, response_limit)
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
                result = (
                    {
                        **identity,
                        "attempts": attempts,
                        "disposition": "accepted",
                        "status": accepted,
                    }
                    if accepted is not None
                    else {
                        **identity,
                        "attempts": attempts,
                        "disposition": "uncertain",
                        "reason": "invalid_response",
                    }
                )
                return result
            if status in _NO_STORE and _no_store(value, identity["receipt_hash"]):
                return {
                    **identity,
                    "attempts": attempts,
                    "disposition": "definitive_no_store",
                    "http_status": status,
                }
            reason = (
                "conflict"
                if status == 409 and _conflict(value, identity["receipt_hash"])
                else "invalid_response"
            )
            return {
                **identity,
                "attempts": attempts,
                "disposition": "uncertain",
                "reason": reason,
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


def admit_prepared_strict_receipt_v2_1(
    coordinator: Any,
    prepared: Dict[str, Any],
    **options: Any,
) -> Dict[str, Any]:
    """Admit the prepared strict receipt and apply its local reconciliation."""
    return _finish(
        coordinator,
        prepared,
        _transport_prepared_strict_receipt_v2_1(coordinator, prepared, **options),
    )
