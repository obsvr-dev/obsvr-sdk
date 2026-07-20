"""Span primitive (DASHBOARD_TELEMETRY.md M3): a generic execution-graph node.

Mirror of sdk/src/proxy/span.ts. A span carries a typed identity plus an open
`attributes` bag, so new node kinds never require a schema change. Parent links
come from an explicit `with_span` scope (contextvars, the Python equivalent of
AsyncLocalStorage), never inferred. The envelope rides event metadata under the
reserved `obsvr_span` key, so the signed schema is untouched.
"""

import contextvars
import time
import uuid
from contextlib import contextmanager
from typing import Any, Dict, Iterator, Optional

RESERVED_SPAN_KEY = "obsvr_span"

_current_span: contextvars.ContextVar[Optional[Dict[str, Any]]] = contextvars.ContextVar(
    "obsvr_current_span", default=None
)


def generate_span_id() -> str:
    return str(uuid.uuid4())


def current_span() -> Optional[Dict[str, Any]]:
    return _current_span.get()


def current_span_id() -> Optional[str]:
    s = _current_span.get()
    return s.get("span_id") if s else None


@contextmanager
def with_span(
    name: str, kind: str = "chain", trace_id: Optional[str] = None
) -> Iterator[Dict[str, Any]]:
    """Run a block inside a named span scope. Governed calls made within it
    link to this span as their parent (deterministic, developer-declared).

    Trace grouping: the scope carries a ``trace_id`` so every span emitted within
    it groups into one trace. Precedence: an explicit ``trace_id`` wins, else the
    enclosing scope's trace_id is inherited, else this root scope's own span_id
    becomes the trace_id. Pass ``trace_id`` set to your run id to align child
    spans with the governed calls in that run.

    Example:
        with obsvr.with_span("plan_step", "agent", trace_id=run_id):
            client.chat.completions.create(...)  # parent_span_id = plan_step
    """
    parent = _current_span.get()
    span_id = generate_span_id()
    ctx: Dict[str, Any] = {
        "span_id": span_id,
        "trace_id": trace_id or (parent.get("trace_id") if parent else None) or span_id,
        "kind": kind,
        "name": name,
    }
    token = _current_span.set(ctx)
    try:
        yield ctx
    finally:
        _current_span.reset(token)


def span_envelope_for(
    kind: str, name: str, attributes: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Build the span envelope for an event, using the enclosing with_span
    scope (if any) as the deterministic parent."""
    parent = _current_span.get()
    env: Dict[str, Any] = {"span_id": generate_span_id(), "span_kind": kind, "span_name": name}
    if parent and parent.get("span_id"):
        env["parent_span_id"] = parent["span_id"]
    if attributes:
        env["attributes"] = attributes
    return env


def with_span_metadata(
    metadata: Optional[Dict[str, Any]], envelope: Dict[str, Any]
) -> Dict[str, Any]:
    """Nest the span envelope under the reserved metadata key."""
    merged = dict(metadata or {})
    merged[RESERVED_SPAN_KEY] = envelope
    return merged


def _emit_span_event(
    span_id: str,
    parent_id: Optional[str],
    trace_id: Optional[str],
    kind: str,
    name: str,
    ok: bool,
    attributes: Dict[str, Any],
) -> None:
    """Emit a standalone execution span as a SIGNED audit event (M3B).
    Mirror of the TS emitSpanEvent: same pipeline, event_class execution_span,
    respects disabled + sampling. Never raises."""
    try:
        from . import events
        from .config import try_get_config
        from .policy import DEFAULT_COMPLIANCE
        from .sender import should_sample

        config = try_get_config()
        if config is None or getattr(config, "disabled", False):
            return
        if not should_sample(getattr(config, "sample_rate", 1.0)):
            return
        envelope: Dict[str, Any] = {
            "span_id": span_id,
            "span_kind": kind,
            "span_name": name,
            "event_class": "execution_span",
            "attributes": attributes,
        }
        if parent_id:
            envelope["parent_span_id"] = parent_id
        # Trace grouping: stamp the scope's trace_id into metadata so ingest
        # links this execution span to its run/trace (the timeline and agent-run
        # analytics group on trace_id / agent_run_id). Else spans are orphaned.
        metadata = with_span_metadata({}, envelope)
        if trace_id:
            metadata["trace_id"] = trace_id
        events.emit_event(
            config,
            provider="unknown",
            model="unknown",
            operation=name,
            source="span",
            prompt="",
            response="",
            success=ok,
            status_code=200 if ok else 500,
            compliance={**DEFAULT_COMPLIANCE, "event_type": "span"},
            metadata=metadata,
        )
    except Exception:
        return


def emit_span(
    kind: str,
    name: str,
    ok: bool,
    span_id: Optional[str] = None,
    parent_span_id: Optional[str] = None,
    trace_id: Optional[str] = None,
    attributes: Optional[Dict[str, Any]] = None,
) -> None:
    """Low-level span emitter for start/end-style integration callbacks
    (mirror of the TS ``emitSpan``). Same signed pipeline and trace_id
    precedence as ``span()``: explicit > enclosing scope > self-root.
    Integrations MUST use this path so their spans are signed and classed
    identically to ``obsvr.span()`` output."""
    resolved_span_id = span_id or generate_span_id()
    parent = _current_span.get()
    resolved_trace_id = (
        trace_id or (parent.get("trace_id") if parent else None) or resolved_span_id
    )
    resolved_parent = parent_span_id or (parent.get("span_id") if parent else None)
    _emit_span_event(
        resolved_span_id, resolved_parent, resolved_trace_id, kind, name, ok,
        dict(attributes or {}),
    )


@contextmanager
def span(
    name: str,
    kind: str = "chain",
    attributes: Optional[Dict[str, Any]] = None,
    trace_id: Optional[str] = None,
) -> Iterator[Dict[str, Any]]:
    """Run a block as a recorded execution span. Opens a scope (children link to
    it), times it, and emits a signed execution-span event on exit. Mirror of
    the TS `span()`.

    Example:
        with obsvr.span("vector_search", "retrieval",
                        {"gen_ai.retrieval.document_count": 5}):
            docs = retriever.search(q)
    """
    parent = _current_span.get()
    parent_id = parent.get("span_id") if parent else None
    span_id = generate_span_id()
    # Same trace precedence as with_span: explicit id, else inherited scope, else
    # this span roots its own single-node trace.
    resolved_trace_id = trace_id or (parent.get("trace_id") if parent else None) or span_id
    start = time.monotonic()
    ctx: Dict[str, Any] = {
        "span_id": span_id,
        "trace_id": resolved_trace_id,
        "kind": kind,
        "name": name,
    }
    token = _current_span.set(ctx)
    ok = True
    try:
        yield ctx
    except BaseException:
        ok = False
        raise
    finally:
        _current_span.reset(token)
        attrs = dict(attributes or {})
        attrs["duration_ms"] = round((time.monotonic() - start) * 1000)
        _emit_span_event(span_id, parent_id, resolved_trace_id, kind, name, ok, attrs)
