"""Optional OpenTelemetry mirror (parity with sdk-typescript/src/proxy/otel-mirror.ts).

When otel={"enabled": True} and the opentelemetry-api package is installed
(optional, never a hard dependency), every audit event is mirrored as a
retroactive OTel span with GenAI semantic-convention attributes plus obsvr
governance outcomes. If the package is missing this module logs once and
stays inert. Failures never affect the audit path.
"""

import logging
import time
from typing import Any, Dict, Optional

_otel: Any = ...  # sentinel: unresolved
_warned = False


def _resolve() -> Optional[Any]:
    global _otel, _warned
    if _otel is not ...:
        return _otel
    try:
        from opentelemetry import trace  # type: ignore
        from opentelemetry.trace import StatusCode  # type: ignore
        _otel = (trace, StatusCode)
    except Exception:
        _otel = None
        if not _warned:
            _warned = True
            logging.getLogger("obsvr").warning("otel.enabled is set but opentelemetry-api is not installed - OTel mirroring disabled")
    return _otel


def _token_attributes(event: Dict[str, Any]) -> Dict[str, int]:
    """The GenAI usage attributes, present only when the count is actually known.

    ``or 0`` was doubly wrong here: it fabricated a count for an unread value AND
    rewrote a genuine zero as the same fabrication, so the two were
    indistinguishable in the exported span even when the event itself had them
    right.
    """
    attrs: Dict[str, int] = {}
    for field, key in (
        ("input_tokens", "gen_ai.usage.input_tokens"),
        ("output_tokens", "gen_ai.usage.output_tokens"),
    ):
        value = event.get(field)
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            attrs[key] = value
    return attrs


def mirror_to_otel(config: Any, event: Dict[str, Any]) -> None:
    """Mirror one audit event as a retroactive span. Fire-and-forget."""
    otel_cfg = getattr(config, "otel", None)
    if not otel_cfg or not otel_cfg.get("enabled"):
        return
    resolved = _resolve()
    if not resolved:
        return
    trace, StatusCode = resolved
    try:
        tracer = trace.get_tracer(otel_cfg.get("tracer_name", "obsvr-sdk"))
        end_ns = int((event.get("timestamp_sdk") or time.time() * 1000) * 1_000_000)
        latency_ms = event.get("latency_ms") or 0
        start_ns = end_ns - int(max(0, latency_ms) * 1_000_000)
        span = tracer.start_span(
            f"obsvr.{event.get('operation') or 'llm_call'}",
            start_time=start_ns,
            attributes={
                "gen_ai.system": event.get("provider") or "unknown",
                "gen_ai.request.model": event.get("model") or "unknown",
                # The two token attributes are OMITTED when the count is
                # unknown, and that is the whole point: a span reporting 0 for a
                # measurement that never happened is the same lie the extractors
                # were fixed to stop telling, in a different sink. An absent
                # attribute is how the GenAI semantic conventions say "not
                # recorded"; a zero is a claim. Twin:
                # sdk-typescript/src/proxy/otel-mirror.ts.
                **_token_attributes(event),
                "obsvr.event_type": event.get("event_type") or "llm_call",
                "obsvr.action_taken": event.get("action_taken") or "allowed",
                "obsvr.action_reason": event.get("action_reason") or "none",
                "obsvr.rule_id": event.get("rule_id") or "",
                "obsvr.pii_detected": event.get("action_reason") == "pii_detected",
                "obsvr.seq_no": event.get("seq_no") or 0,
                "obsvr.sdk_session_id": event.get("sdk_session_id") or "",
                "obsvr.environment": event.get("environment") or "",
            },
        )
        if event.get("success") is False or event.get("action_taken") == "blocked":
            span.set_status(StatusCode.ERROR)
        else:
            span.set_status(StatusCode.OK)
        span.end(end_time=end_ns)
    except Exception:
        pass  # never break the audit path


def _reset_otel_mirror() -> None:
    global _otel, _warned
    _otel = ...
    _warned = False
