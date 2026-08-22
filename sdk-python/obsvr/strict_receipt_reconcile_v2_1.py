"""Read-only DNS-pinned reconciliation for profile-2.1 decisions."""

from __future__ import annotations

import json
import time
from typing import Any, Dict
from urllib.parse import urlsplit, urlunsplit
from weakref import WeakSet

from .external_backend import _pinned_request
from .ssrf import assert_backend_url_static, resolve_backend_url_allowed
from .strict_receipt_v2_1_verify import verify_strict_receipt_v2_1
from .tool_pinning import _canonical_json_for_hash

STRICT_RECONCILIATION_V2_1_SCHEMA = "obsvr-strict-receipt-reconciliation-v2-1"
STRICT_RECONCILIATION_V2_1_ENDPOINT = "/ingest/strict-receipts/v2-1/reconcile"
_LOCAL = frozenset({"localhost", "127.0.0.1", "::1"})
_ACCEPTED: WeakSet[Any] = WeakSet()
_MAX_REQUEST_BYTES = 262_144
_MAX_RESPONSE_BYTES = 1_048_576


class StrictReconciliationV21Result:
    def __init__(self, value: Dict[str, Any]) -> None:
        self.value = value


def _endpoint(raw: str):
    host = (urlsplit(raw).hostname or "").lower()
    loopback = host in _LOCAL
    parsed = assert_backend_url_static(raw, loopback)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("invalid reconciliation URL")
    if parsed.scheme == "http" and not loopback:
        raise ValueError("invalid reconciliation URL")
    hostname = parsed.hostname or ""
    authority = f"[{hostname}]" if ":" in hostname else hostname
    if parsed.port is not None:
        authority += f":{parsed.port}"
    return (
        urlunsplit(
            (
                parsed.scheme,
                authority,
                parsed.path.rstrip("/") + STRICT_RECONCILIATION_V2_1_ENDPOINT,
                "",
                "",
            )
        ),
        loopback,
    )


def _base(receipt, attempts, status, reason=None):
    value = {
        "schema": STRICT_RECONCILIATION_V2_1_SCHEMA,
        "status": status,
        "tenant_id": receipt["body"]["tenant_id"],
        "session_id": receipt["body"]["session_id"],
        "receipt_hash": receipt["receipt_hash"],
        "attempts": attempts,
    }
    if reason is not None:
        value["reason"] = reason
    return StrictReconciliationV21Result(value)


def _positive(value, fallback, maximum, field):
    normalized = fallback if value is None else value
    if (
        isinstance(normalized, bool)
        or not isinstance(normalized, int)
        or not 0 < normalized <= maximum
    ):
        raise ValueError(f"{field} is outside its supported positive range")
    return normalized


def _validate_receipt(receipt):
    result = verify_strict_receipt_v2_1(
        receipt, trusted_agent_keys=[], allowed_evaluator_manifest_hashes=[]
    )
    body = receipt.get("body", {}) if isinstance(receipt, dict) else {}
    if (
        not result["integrity_valid"]
        or body.get("profile_version") != "2.1"
        or body.get("record_type") != "decision"
    ):
        raise ValueError("receipt must be an intact profile-2.1 decision")


def reconcile_strict_receipt_v2_1(
    receipt: Dict[str, Any],
    *,
    ingest_url: str,
    api_key: str,
    timeout_ms: int = 2_000,
    max_attempts: int = 3,
    max_response_bytes: int = 65_536,
    resolver=None,
    trusted_pinned_transport=None,
    sleep=None,
    **_unused,
) -> StrictReconciliationV21Result:
    _validate_receipt(receipt)
    url, loopback = _endpoint(ingest_url)
    if not isinstance(api_key, str) or not api_key.strip():
        raise ValueError("api_key must be nonblank")
    body = _canonical_json_for_hash(
        {
            "schema": "obsvr-strict-receipt-ingest-v2-1",
            "tenant_id": receipt["body"]["tenant_id"],
            "session_id": receipt["body"]["session_id"],
            "receipt": receipt,
        }
    ).encode()
    if len(body) > _MAX_REQUEST_BYTES:
        raise ValueError("reconciliation request exceeds its supported size")
    timeout_ms = _positive(timeout_ms, 2_000, 60_000, "timeout_ms")
    max_attempts = _positive(max_attempts, 3, 20, "max_attempts")
    max_response_bytes = _positive(
        max_response_bytes, 65_536, _MAX_RESPONSE_BYTES, "max_response_bytes"
    )
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": api_key,
        "Idempotency-Key": receipt["receipt_hash"],
    }
    sleeper = sleep or (lambda delay: time.sleep(delay / 1000))
    for attempts in range(1, max_attempts + 1):
        try:
            target = resolve_backend_url_allowed(url, loopback, resolver)
            transport = trusted_pinned_transport or _pinned_request
            status, raw = transport(
                target, headers, body, timeout_ms / 1000, max_response_bytes
            )
            try:
                value = json.loads(raw.decode()) if raw else None
            except Exception:
                value = None
            if (
                status == 200
                and isinstance(value, dict)
                and set(value)
                == {
                    "schema",
                    "ok",
                    "status",
                    "session_id",
                    "receipt_hash",
                    "accepted_at_ms",
                }
                and value.get("schema") == STRICT_RECONCILIATION_V2_1_SCHEMA
                and value.get("ok") is True
                and value.get("status") == "accepted"
                and value.get("session_id") == receipt["body"]["session_id"]
                and value.get("receipt_hash") == receipt["receipt_hash"]
                and isinstance(value.get("accepted_at_ms"), int)
                and not isinstance(value.get("accepted_at_ms"), bool)
                and value["accepted_at_ms"] >= 0
            ):
                result = _base(receipt, attempts, "accepted")
                result.value["accepted_at_ms"] = value["accepted_at_ms"]
                _ACCEPTED.add(result)
                return result
            if (
                status == 404
                and isinstance(value, dict)
                and set(value)
                == {"schema", "ok", "status", "session_id", "receipt_hash"}
                and value.get("schema") == STRICT_RECONCILIATION_V2_1_SCHEMA
                and value.get("ok") is True
                and value.get("status") == "absent"
                and value.get("session_id") == receipt["body"]["session_id"]
                and value.get("receipt_hash") == receipt["receipt_hash"]
            ):
                return _base(receipt, attempts, "absent")
            if status == 409:
                return _base(receipt, attempts, "conflict")
            if status < 500 and status not in (408, 429):
                return _base(receipt, attempts, "unknown", "invalid_response")
        except Exception:
            pass
        if attempts < max_attempts:
            sleeper(0)
    return _base(receipt, max_attempts, "unknown", "retry_exhausted")


def assert_accepted_strict_reconciliation_v2_1(result, receipt):
    value = result.value if isinstance(result, StrictReconciliationV21Result) else {}
    if (
        result not in _ACCEPTED
        or value.get("status") != "accepted"
        or value.get("tenant_id") != receipt["body"]["tenant_id"]
        or value.get("session_id") != receipt["body"]["session_id"]
        or value.get("receipt_hash") != receipt["receipt_hash"]
    ):
        raise ValueError("trusted accepted profile-2.1 reconciliation is required")
