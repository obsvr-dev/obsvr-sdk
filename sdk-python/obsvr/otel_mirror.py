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
                # Current GenAI semantic conventions use provider.name. Keep
                # system during the compatibility window for existing users.
                "gen_ai.provider.name": event.get("provider") or "unknown",
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


def _strict_checkpoint_attributes(checkpoint: Dict[str, Any]):
    if checkpoint.get("phase") not in ("committed", "terminal"):
        return None
    receipt = checkpoint.get("receipt")
    if not isinstance(receipt, dict) or not isinstance(receipt.get("body"), dict):
        return None
    body = receipt["body"]
    if (
        checkpoint.get("receipt_hash") != receipt.get("receipt_hash")
        or checkpoint.get("tenant_id") != body.get("tenant_id")
        or checkpoint.get("session_id") != body.get("session_id")
    ):
        return None
    try:
        policy = body["evaluation"]["effective_policy"]
        attributes = {
            "obsvr.strict.profile_version": body["profile_version"],
            "obsvr.strict.receipt_hash": receipt["receipt_hash"],
            "obsvr.strict.receipt_sequence": body["sequence"],
            "obsvr.strict.record_type": body["record_type"],
            "obsvr.strict.execution_authorized": body["execution_authorized"],
            "obsvr.strict.decision_outcome": body["outcome"],
            "obsvr.strict.policy_version": policy["version"],
            "obsvr.strict.policy_artifact_hash": policy["artifact_hash"],
            "obsvr.strict.evaluator_manifest_hash": body["evaluation"][
                "evaluator_manifest_hash"
            ],
            "obsvr.strict.journal_phase": checkpoint["phase"],
        }
    except (KeyError, TypeError):
        return None
    supported = all(
        isinstance(value, bool)
        or (isinstance(value, str) and bool(value))
        or (
            isinstance(value, int)
            and not isinstance(value, bool)
            and 0 <= value <= 9_007_199_254_740_991
        )
        for value in attributes.values()
    )
    if not supported:
        return None
    if checkpoint.get("terminal_status") is not None:
        attributes["obsvr.strict.terminal_status"] = checkpoint["terminal_status"]
    outcome = checkpoint.get("execution_outcome")
    if isinstance(outcome, dict) and isinstance(outcome.get("body"), dict):
        outcome_body = outcome["body"]
        outcome_hash = outcome.get("outcome_hash")
        outcome_status = outcome_body.get("status")
        if (
            isinstance(outcome_hash, str)
            and len(outcome_hash) == 64
            and all(character in "0123456789abcdef" for character in outcome_hash)
            and outcome_status in ("succeeded", "failed", "uncertain")
            and outcome_body.get("decision_receipt_hash")
            == receipt["receipt_hash"]
            and outcome_body.get("decision_sequence") == body["sequence"]
        ):
            attributes["obsvr.strict.execution_outcome_hash"] = outcome_hash
            attributes["obsvr.strict.execution_status"] = outcome_status
    return attributes


def correlate_strict_runtime_checkpoint_v2_1_to_otel(
    checkpoint: Dict[str, Any]
) -> bool:
    """Attach durable strict evidence references to the current OTel span."""
    try:
        attributes = _strict_checkpoint_attributes(checkpoint)
        resolved = _resolve() if attributes else None
        if not resolved:
            return False
        trace, _ = resolved
        span = trace.get_current_span()
        if not span.is_recording():
            return False
        span.set_attributes(attributes)
        return True
    except Exception:
        return False


class _StrictOtelCheckpointStoreV21:
    def __init__(self, checkpoint_store: Any) -> None:
        save = getattr(checkpoint_store, "save", None)
        if not callable(save):
            raise TypeError("durable checkpoint store is required")
        self._save = save

    def save(self, checkpoint: Dict[str, Any]) -> None:
        self._save(checkpoint)
        correlate_strict_runtime_checkpoint_v2_1_to_otel(checkpoint)


def with_strict_otel_correlation_v2_1(checkpoint_store: Any):
    """Decorate a durable store with non-fatal active-span correlation."""
    return _StrictOtelCheckpointStoreV21(checkpoint_store)


def _reset_otel_mirror() -> None:
    global _otel, _warned
    _otel = ...
    _warned = False
