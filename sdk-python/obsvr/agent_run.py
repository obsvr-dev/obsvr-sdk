"""Agent-run context — the run-lifecycle counterpart to the span primitive.

Mirror of sdk/src/proxy/agent-run.ts + sdk/src/integrations/agent-run.ts. An
"agent run" is one agentic execution: a top-level agent invocation that fans out
into LLM calls, tool calls, and sub-steps. The dashboard groups these into a
single Runs-tab row keyed on ``agent_run_id``; the ingest run aggregator marks a
run complete on the terminal ``*.agent.run.finish`` operation.

Frameworks governed at the tool level (LlamaIndex, Vercel AI) have no
run-lifecycle hook, so their events carried no ``agent_run_id`` and never formed
a run. ``agent_run(...)`` supplies the missing, framework-agnostic run SCOPE:
wrap the agent invocation and every governed action inside auto-joins the run
via the ambient context read here.

Design mirrors span.py: a contextvars scope (the Python equivalent of
AsyncLocalStorage), deterministic and developer-declared, additive transport
(the run id rides event metadata, so the signed schema and its conformance
fixtures are untouched). ``with_run_metadata`` is applied in the single event
builder (events.build_audit_event) so proxy calls, integration events, and
spans inside a run all pick up ``agent_run_id``.
"""

import contextvars
import uuid
from contextlib import contextmanager
from typing import Any, Dict, Iterator, Optional

_current_run: contextvars.ContextVar[Optional[Dict[str, Any]]] = contextvars.ContextVar(
    "obsvr_current_agent_run", default=None
)

_DEFAULT_SOURCE = "agent"


def generate_run_id() -> str:
    """Generate a fresh run id."""
    return str(uuid.uuid4())


def current_agent_run() -> Optional[Dict[str, Any]]:
    """The enclosing agent run ({run_id, source, name}), if a scope is active."""
    return _current_run.get()


def current_agent_run_id() -> Optional[str]:
    """The enclosing run's id, if any."""
    run = _current_run.get()
    return run.get("run_id") if run else None


def with_run_metadata(metadata: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Stamp ``agent_run_id`` onto event metadata from the ambient run, when one
    is active and the caller has not already set it (an integration that manages
    its own run id always wins). Additive and non-destructive: returns metadata
    unchanged when no run is active, so events outside any run scope are
    byte-identical to before."""
    run = _current_run.get()
    if run is None:
        return metadata
    if metadata is not None and metadata.get("agent_run_id") is not None:
        return metadata
    merged = dict(metadata or {})
    merged["agent_run_id"] = run["run_id"]
    return merged


def _emit_run_event(source: str, run_id: str, name: str, phase: str, ok: bool) -> None:
    try:
        from . import events
        from .config import try_get_config

        config = try_get_config()
        if config is None:
            return
        events.emit_event(
            config,
            provider="unknown",
            model="unknown",
            operation=f"{source}.agent.run.{phase}",
            source=source,
            prompt="",
            response="",
            success=ok,
            metadata={"agent_run_id": run_id, "agent_run_name": name},
        )
    except Exception:
        return


@contextmanager
def agent_run(
    name: str,
    source: Optional[str] = None,
    run_id: Optional[str] = None,
) -> Iterator[Dict[str, Any]]:
    """Run a block as ONE agent run. Emits a signed ``<source>.agent.run.start``
    on entry and a terminal ``<source>.agent.run.finish`` on exit (success or
    failure), and binds an ambient run context so every governed action inside
    joins the run under one ``agent_run_id``. Deterministic and
    developer-declared: the run boundary is this explicit scope, never inferred.

    Example:
        with obsvr.agent_run("support-agent", source="llamaindex_py"):
            agent.chat(user_message)
    """
    from .span import with_span

    resolved_source = source or _DEFAULT_SOURCE
    resolved_run_id = run_id or generate_run_id()
    ctx: Dict[str, Any] = {"run_id": resolved_run_id, "source": resolved_source, "name": name}

    _emit_run_event(resolved_source, resolved_run_id, name, "start", True)

    token = _current_run.set(ctx)
    ok = True
    try:
        # Also open a span scope carrying trace_id = run_id, so spans and
        # governed calls inside group by trace, exactly like with_span.
        with with_span(name, "agent", trace_id=resolved_run_id):
            yield ctx
    except BaseException:
        ok = False
        raise
    finally:
        _current_run.reset(token)
        _emit_run_event(resolved_source, resolved_run_id, name, "finish", ok)
