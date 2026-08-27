"""DNS-pinned transport for signed strict 2.1 execution outcomes."""

from __future__ import annotations

import copy
import json
import random
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit, urlunsplit

from .external_backend import _pinned_request
from .ssrf import AllowedBackendTarget, assert_backend_url_static
from .strict_admission_v2 import _positive, _resolve_bounded, _text
from .strict_execution_outcome_v2_1 import verify_strict_execution_outcome_v2_1
from .strict_runtime_recovery_v2_1 import reconcile_strict_runtime_execution_v2_1
from .tool_pinning import _canonical_json_for_hash

STRICT_EXECUTION_OUTCOME_V2_1_INGEST_SCHEMA = (
    "obsvr-strict-execution-outcome-ingest-v2-1"
)
STRICT_EXECUTION_OUTCOME_V2_1_ADMISSION_SCHEMA = (
    "obsvr-strict-execution-outcome-admission-v2-1"
)
STRICT_EXECUTION_OUTCOME_V2_1_ENDPOINT = "/ingest/strict-execution-outcomes/v2-1"
STRICT_EXECUTION_OUTCOME_V2_1_MAX_REQUEST_BYTES = 262_144

_NO_STORE = frozenset({400, 401, 403, 413})
_RETRYABLE = frozenset({408, 429})
_LOCAL = frozenset({"localhost", "127.0.0.1", "::1"})
_MAX_RESPONSE = 1_048_576

PinnedTransport = Callable[
    [AllowedBackendTarget, Dict[str, str], bytes, float, int],
    Tuple[int, Optional[bytes]],
]


class StrictExecutionOutcomeV21TransportError(ValueError):
    """An outcome cannot be safely submitted to hosted strict ingest."""


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
        raise StrictExecutionOutcomeV21TransportError(
            "ingest_url failed static security validation"
        ) from None
    if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
        raise StrictExecutionOutcomeV21TransportError(
            "ingest_url cannot contain credentials, query, or fragment"
        )
    if parsed.scheme == "http" and not loopback:
        raise StrictExecutionOutcomeV21TransportError(
            "ingest_url must use HTTPS unless it targets loopback"
        )
    hostname = parsed.hostname or ""
    authority = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None:
        authority += f":{port}"
    path = parsed.path.rstrip("/") + STRICT_EXECUTION_OUTCOME_V2_1_ENDPOINT
    return urlunsplit((parsed.scheme, authority, path, "", "")), loopback


def _parsed(raw: Optional[bytes], limit: int) -> Optional[Dict[str, Any]]:
    if not raw or len(raw) > limit:
        return None
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _accepted(value: Optional[Dict[str, Any]], outcome_hash: str) -> Optional[str]:
    if (
        value is None
        or set(value) != {"schema", "ok", "status", "outcome_hash", "accepted_at_ms"}
        or value.get("schema") != STRICT_EXECUTION_OUTCOME_V2_1_ADMISSION_SCHEMA
        or value.get("ok") is not True
        or value.get("outcome_hash") != outcome_hash
        or value.get("status") not in ("accepted", "already_accepted")
        or isinstance(value.get("accepted_at_ms"), bool)
        or not isinstance(value.get("accepted_at_ms"), int)
        or value["accepted_at_ms"] < 0
    ):
        return None
    return value["status"]


def _rejected(
    value: Optional[Dict[str, Any]], outcome_hash: str, status: str
) -> bool:
    fields = {"schema", "ok", "status", "code", "outcome_hash"}
    if status == "rejected":
        fields.add("stored")
    return bool(
        value is not None
        and set(value) == fields
        and value.get("schema") == STRICT_EXECUTION_OUTCOME_V2_1_ADMISSION_SCHEMA
        and value.get("ok") is False
        and value.get("status") == status
        and value.get("outcome_hash") == outcome_hash
        and (status != "rejected" or value.get("stored") is False)
        and isinstance(value.get("code"), str)
        and bool(value["code"])
    )


def _assert_request_bytes(body: bytes) -> None:
    if len(body) > STRICT_EXECUTION_OUTCOME_V2_1_MAX_REQUEST_BYTES:
        raise StrictExecutionOutcomeV21TransportError(
            "execution outcome ingest request exceeds its supported size"
        )


def submit_strict_execution_outcome_v2_1(
    outcome: Dict[str, Any],
    decision: Dict[str, Any],
    *,
    ingest_url: str,
    api_key: str,
    trusted_agent_keys: Sequence[Dict[str, Any]] = (),
    allowed_evaluator_manifest_hashes: Sequence[str] = (),
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
    """Submit one signed outcome without changing the local execution result."""
    verification = verify_strict_execution_outcome_v2_1(
        outcome,
        decision,
        trusted_agent_keys=trusted_agent_keys,
        allowed_evaluator_manifest_hashes=allowed_evaluator_manifest_hashes,
    )
    if not verification["integrity_valid"]:
        raise StrictExecutionOutcomeV21TransportError(
            "execution outcome must be intact and bound to its decision receipt"
        )
    identity = {
        "schema": STRICT_EXECUTION_OUTCOME_V2_1_ADMISSION_SCHEMA,
        "tenant_id": _text(outcome["body"].get("tenant_id"), "tenant_id"),
        "session_id": _text(outcome["body"].get("session_id"), "session_id"),
        "outcome_hash": outcome["outcome_hash"],
    }
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
        raise StrictExecutionOutcomeV21TransportError(
            "trusted_pinned_transport must be callable"
        )
    body = _canonical_json_for_hash(
        {
            "schema": STRICT_EXECUTION_OUTCOME_V2_1_INGEST_SCHEMA,
            "tenant_id": identity["tenant_id"],
            "session_id": identity["session_id"],
            "outcome": copy.deepcopy(outcome),
        }
    ).encode("utf-8")
    _assert_request_bytes(body)
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": key,
        "Idempotency-Key": identity["outcome_hash"],
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
                raise TimeoutError("strict outcome transport timeout exhausted")
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
                accepted = _accepted(value, identity["outcome_hash"])
                return (
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
            if status in _NO_STORE and _rejected(
                value, identity["outcome_hash"], "rejected"
            ):
                return {
                    **identity,
                    "attempts": attempts,
                    "disposition": "definitive_no_store",
                    "http_status": status,
                }
            reason = (
                "conflict"
                if status == 409
                and _rejected(value, identity["outcome_hash"], "conflict")
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


def submit_strict_runtime_terminal_journal_v2_1(
    journal: Dict[str, Any], **options: Any
) -> Dict[str, Any]:
    """Validate a terminal journal and submit its exact signed outcome."""
    trusted_keys = options.get("trusted_agent_keys", ())
    manifest_hashes = options.get("allowed_evaluator_manifest_hashes", ())
    recovered = reconcile_strict_runtime_execution_v2_1(
        journal,
        trusted_agent_keys=trusted_keys,
        allowed_evaluator_manifest_hashes=manifest_hashes,
    )
    outcome = recovered["journal"].get("execution_outcome")
    if recovered["status"] != "resolved" or outcome is None:
        raise StrictExecutionOutcomeV21TransportError(
            "runtime journal does not contain a signed terminal execution outcome"
        )
    return submit_strict_execution_outcome_v2_1(
        outcome, recovered["journal"]["receipt"], **options
    )


__all__ = [
    "STRICT_EXECUTION_OUTCOME_V2_1_INGEST_SCHEMA",
    "STRICT_EXECUTION_OUTCOME_V2_1_ADMISSION_SCHEMA",
    "STRICT_EXECUTION_OUTCOME_V2_1_ENDPOINT",
    "STRICT_EXECUTION_OUTCOME_V2_1_MAX_REQUEST_BYTES",
    "StrictExecutionOutcomeV21TransportError",
    "submit_strict_execution_outcome_v2_1",
    "submit_strict_runtime_terminal_journal_v2_1",
]
