"""Audit event builder + emitter.

Field mapping is identical to the TS SDK's buildAuditEvent /
buildIntegrationEvent (sdk/src/integrations/core.ts) and matches the
ingest RawEventSchema (snake_case, compliance fields, truncation marker).
"""

import json
import uuid
from typing import Any, Dict, Optional

from . import sender
from .agent_run import with_run_metadata
from .config import ResolvedConfig
from .policy import DEFAULT_COMPLIANCE

# keep metadata under the ingest 10 KB canonical cap (with headroom), or
# the canonicalizer replaces it wholesale with {"_truncated": true}, destroying
# trace_id / agent_run_id / the span envelope and orphaning the event.
_METADATA_BUDGET_CHARS = 9000
_RESERVED_META_KEYS = (
    "trace_id",
    "agent_run_id",
    "agent_run_name",
    "obsvr_span",
    "obsvr_telemetry",
    "obsvr_external_backend",
)


def _trim_metadata_to_budget(md: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not md:
        return md
    if len(json.dumps(md, default=str)) <= _METADATA_BUDGET_CHARS:
        return md
    # 1. The span attribute bag is the usual culprit — collapse it first.
    span = md.get("obsvr_span")
    if isinstance(span, dict) and "attributes" in span:
        md = {**md, "obsvr_span": {**span, "attributes": {"_trimmed": True}}}
        if len(json.dumps(md, default=str)) <= _METADATA_BUDGET_CHARS:
            md["_obsvr_metadata_trimmed"] = True
            return md
    # 2. Still over: keep only the reserved grouping/provenance keys.
    trimmed: Dict[str, Any] = {"_obsvr_metadata_trimmed": True}
    for k in _RESERVED_META_KEYS:
        if k in md:
            trimmed[k] = md[k]
    return trimmed

TRUNCATION_MARKER = " [TRUNCATED]"


def truncate(text: Optional[str], max_chars: int) -> str:
    if text is None:
        return ""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + TRUNCATION_MARKER


def classify_error(error: Any) -> str:
    """Same taxonomy as the TS proxy wrapper."""
    if not isinstance(error, BaseException):
        return "api_error"
    message = str(error).lower()
    name = type(error).__name__.lower()
    if "rate limit" in message or "429" in message or "ratelimit" in name:
        return "rate_limit"
    if "timeout" in message or "timeout" in name or "timed out" in message:
        return "timeout"
    if (
        "auth" in message
        or "401" in message
        or "403" in message
        or "unauthorized" in message
    ):
        return "auth_error"
    return "api_error"


def infer_provider_from_string(identifier: str) -> str:
    """Infer a provider label from an arbitrary identifier string."""
    s = identifier.lower()
    if "azure" in s:
        return "azure_openai"
    if "bedrock" in s:
        return "bedrock"
    if "vertex" in s:
        return "vertex_ai"
    if "together" in s:
        return "together"
    if "cloudflare" in s or "workersai" in s:
        return "cloudflare"
    if "openai" in s:
        return "openai"
    if "anthropic" in s or "claude" in s:
        return "anthropic"
    if "google" in s or "gemini" in s or "genai" in s:
        return "google"
    return "unknown"


def _with_provider_detail(
    md: Optional[Dict[str, Any]], provider: str
) -> Optional[Dict[str, Any]]:
    """preserve MCP identity in metadata.provider_detail (ingest coerces
    the "mcp" provider enum to "unknown")."""
    if provider != "mcp":
        return md
    out = dict(md or {})
    out.setdefault("provider_detail", "mcp")
    return out


def build_audit_event(
    config: ResolvedConfig,
    *,
    provider: str,
    model: str,
    operation: str,
    source: str,
    prompt: str,
    response: str = "",
    user_input: Optional[str] = None,
    input_tokens: Optional[int] = None,
    output_tokens: Optional[int] = None,
    total_tokens: Optional[int] = None,
    latency_ms: Optional[float] = None,
    time_to_first_token_ms: Optional[float] = None,
    success: bool = True,
    status_code: Optional[int] = None,
    error: Any = None,
    request_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    options: Optional[Dict[str, Any]] = None,
    compliance: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    opts = options or {}
    comp = compliance or DEFAULT_COMPLIANCE

    # Final canary safety net (parity with TS buildIntegrationEvent): NO event
    # may carry a raw canary token in its content on ANY path — a model
    # echoing a planted token into its OUTPUT is the primary leak surface, and
    # some integrations have no post-call scan. Scrub prompt/response/
    # user_input; stamp evidence (ids/hash-prefixes, never the token). Zero
    # cost until a canary is minted.
    _canary_tel: Optional[Dict[str, Any]] = None
    from .canary import canary_registry_size

    if canary_registry_size() > 0:
        from .canary import (
            CANARY_REDACTION_PLACEHOLDER,
            canary_leak_telemetry,
            scan_for_canary,
        )

        _hits: list = []
        _leak_surface: Optional[str] = None

        def _scrub(v: Optional[str], surface: str) -> Optional[str]:
            nonlocal _leak_surface
            if not v:
                return v
            leak = scan_for_canary(v)
            if leak["leaked"]:
                _hits.extend(leak["hits"])
                if _leak_surface is None:
                    _leak_surface = surface
                return CANARY_REDACTION_PLACEHOLDER
            return v

        prompt = _scrub(prompt, "prompt")
        response = _scrub(response, "response")
        if user_input is not None:
            user_input = _scrub(user_input, "user_input")
        if _hits:
            _canary_tel = canary_leak_telemetry(_hits, _leak_surface or "response")

    error_message: Optional[str] = None
    if error is not None:
        m = str(error)
        error_message = m[:500] if len(m) > 500 else m

    _event = {
        # Core fields
        "request_id": request_id or str(uuid.uuid4()),
        # Environment fields
        "environment": config.environment,
        "service_name": opts.get("service_name") or config.default_service_name,
        "region": opts.get("region") or config.default_region or "unknown",
        # Identity fields
        "user_id": opts.get("user_id"),
        # Network fields
        "client_ip": None,
        "user_agent": None,
        # LLM call fields
        "provider": provider,
        "model": model or "unknown",
        "operation": operation,
        "source": opts.get("source")
        or source
        or config.default_source
        or "integration",
        # Content fields
        "prompt": truncate(prompt, config.max_payload_chars),
        "response": truncate(response or "", config.max_payload_chars),
        "user_input": (
            truncate(user_input, config.max_payload_chars)
            if user_input is not None
            else None
        ),
        # Usage fields
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
        # Performance fields
        "latency_ms": round(latency_ms) if latency_ms is not None else None,
        "time_to_first_token_ms": time_to_first_token_ms,
        # Success/status fields
        "success": success,
        "status_code": status_code
        if status_code is not None
        else (200 if success else 500),
        "error_type": classify_error(error) if error is not None else None,
        "error_message": error_message,
        # Metadata. with_run_metadata stamps agent_run_id when this event is
        # built inside an agent_run(...) scope, so proxy calls, integration
        # events, and spans all group into one run. No-op (byte-identical)
        # outside a run scope; a caller-set agent_run_id always wins.
        # ingest coerces provider "mcp" → "unknown"; stamp provider_detail
        # so provider-level analytics can recover the MCP identity.
        "metadata": with_run_metadata(
            _with_provider_detail(
                metadata if metadata is not None else opts.get("metadata"), provider
            )
        ),
        # Compliance fields
        "event_type": comp["event_type"],
        "policy_version": comp["policy_version"],
        "action_taken": comp["action_taken"],
        "action_reason": comp["action_reason"],
        "action_source": comp["action_source"],
        "redacted_types": comp["redacted_types"],
        "blocked_types": comp["blocked_types"],
        # Optional compliance detail (parity with TS: rule_id/policy_reason
        # identify WHICH rule fired, not just that one did)
        "rule_id": comp.get("rule_id"),
        "policy_reason": comp.get("policy_reason"),
        # What shadow-mode rules would have done (EV-21); informational only
        "shadow_outcome": comp.get("shadow_outcome"),
        # Canonical decision record (ADR-2, additive — never part of the
        # HMAC chain preimage; sealed by the ledger's v7 Merkle leaf)
        "decision_input_hash": comp.get("decision_input_hash"),
        "engine_version": comp.get("engine_version"),
        # External policy backend provenance (ADR-4, additive)
        "external_backend": comp.get("external_backend"),
    }
    # external_backend has NO top-level ingest schema field and is stripped;
    # mirror it onto the preserved metadata channel so the ADR-4 provenance
    # survives (parity with the TS sender's normalizeWireShape).
    _external = comp.get("external_backend")
    if _external is not None:
        _md = dict(_event.get("metadata") or {})
        _md.setdefault("obsvr_external_backend", _external)
        _event["metadata"] = _md
    if bool(getattr(config, "policy_floor", None)):
        # Anti-tamper floor evidence: floor_version is a pure function of
        # config.policy_floor, so it is stamped HERE for EVERY event under an
        # active floor (matching the proxy wrap path and the TS
        # buildIntegrationEvent) — so a change to the floor is auditable from
        # the allowed-event stream on every integration path, not just blocks.
        # Any call-specific floor_override_ignored already merged into metadata
        # by the caller (block path) is preserved: it is a separate key and
        # setdefault never clobbers an existing floor_version.
        from .rules import derive_floor_version

        _md = dict(_event.get("metadata") or {})
        _tel = dict(_md.get("obsvr_telemetry") or {})
        _tel.setdefault("floor_version", derive_floor_version(config.policy_floor))
        _md["obsvr_telemetry"] = _tel
        _event["metadata"] = _md
    if _canary_tel is not None:
        # Stamp the canary evidence the scrub caught; surface a clean event as
        # a policy_flag so a leak never reads as "allowed" (TS parity).
        _md = dict(_event.get("metadata") or {})
        _md["obsvr_telemetry"] = {**(_md.get("obsvr_telemetry") or {}), **_canary_tel}
        _event["metadata"] = _md
        if _event["action_taken"] == "allowed":
            _event["event_type"] = "policy_flag"
            if not _event.get("rule_id"):
                _event["rule_id"] = "sdk:canary_leak"
            if not _event.get("policy_reason"):
                _event["policy_reason"] = "Canary token leaked in emitted content"
    # cap metadata so ingest doesn't replace it wholesale (losing grouping keys).
    _event["metadata"] = _trim_metadata_to_budget(_event.get("metadata"))
    # Drop keys whose value is None so the strict ingest schema (which wants
    # optional fields absent, not null) accepts the event. Signature fields
    # are added later by the sender and are never None.
    return {k: v for k, v in _event.items() if v is not None}


def emit_event(config: ResolvedConfig, **params: Any) -> Optional[Dict[str, Any]]:
    """Build and fire-and-forget send an audit event. Never raises."""
    if config.disabled:
        return None
    try:
        event = build_audit_event(config, **params)
        sender.send_audit_async(config, event)
        return event
    except Exception:
        return None


def blocked_call_error(compliance: Dict[str, Any]) -> RuntimeError:
    """Standard blocked-call error (same message as the TS SDK)."""
    reason = (
        "PII detected"
        if compliance.get("action_reason") == "pii_detected"
        else "policy violation"
    )
    return RuntimeError(f"[obsvr] Request blocked by policy ({reason})")
