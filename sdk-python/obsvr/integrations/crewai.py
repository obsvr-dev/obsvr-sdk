"""CrewAI integration — observe-only step callback + agent-level callbacks.

Captures agent step text (AgentAction / AgentFinish) via Crew/Agent
step_callback. PII policy applies to the stored copy.

New agent-level tracing adds run-level audit with tool restriction,
step limit, and output controls enforced by agent_policy.

Usage (composable constructor pattern)::

    from obsvr.integrations.crewai import make_step_callback
    crew = Crew(..., step_callback=make_step_callback())
    # chain an existing callback:
    crew = Crew(..., step_callback=make_step_callback(my_existing_cb))

    # Full run tracing with agent policy enforcement:
    from obsvr.integrations.crewai import make_crew_callbacks, make_task_callback
    run_ctx = {}
    before_kickoff, after_kickoff = make_crew_callbacks(run_context=run_ctx)
    crew = Crew(
        ...,
        before_kickoff=before_kickoff,
        after_kickoff=after_kickoff,
        step_callback=make_step_callback(run_context=run_ctx),
        task_callback=make_task_callback(run_context=run_ctx),
    )
"""

# Interception: constructor argument (composable, non-mutating). Pass
# make_step_callback() as step_callback= at Crew/Agent construction time —
# no live-object mutation. obsvr_step_callback kept as deprecated alias.

import uuid
from typing import Any, Callable, Dict, Optional, Tuple

from .. import sender as _sender
from ..config import try_get_config
from ..events import emit_event
from ..deobfuscate import redact_for_storage
from ..policy import apply_observe_policy

SOURCE = "crewai"


def _step_text(step: Any) -> str:
    if isinstance(step, str):
        return step
    for attr in ("text", "output", "log", "result", "return_values"):
        value = getattr(step, attr, None)
        if isinstance(value, str) and value:
            return value
    if isinstance(step, (list, tuple)):
        parts = [_step_text(item) for item in step]
        return "\n".join(p for p in parts if p)
    return ""


# ---------------------------------------------------------------------------
# Agent policy helpers
# ---------------------------------------------------------------------------


def _check_tool(tool_name: str, policy: Dict[str, Any]) -> Tuple[bool, str]:
    """Return (allowed, reason). reason is empty string when allowed."""
    denied = policy.get("denied_tools") or []
    allowed = policy.get("allowed_tools")  # None = all allowed
    if tool_name in denied:
        return False, "tool_denied"
    if allowed is not None and tool_name not in allowed:
        return False, "tool_not_in_allowlist"
    return True, ""


def _check_steps(count: int, policy: Dict[str, Any]) -> str:
    """Return 'allow', 'block', or 'escalate' based on step limit."""
    limit = policy.get("max_steps")
    if limit is None:
        return "allow"
    return "allow" if count < limit else policy.get("step_limit_action", "block")


# ---------------------------------------------------------------------------
# Internal audit helper
# ---------------------------------------------------------------------------


def _audit_step(step: Any, _metadata: Optional[Dict[str, Any]] = None) -> None:
    """Audit a single CrewAI agent step. Never raises."""
    try:
        config = try_get_config()
        if config is None:
            return
        if not _sender.should_sample(config.sample_rate):
            return
        text = _step_text(step)
        if not text:
            return

        observed = apply_observe_policy(text, config)
        # View-only hit (stored_redaction_via): the stored copy becomes a
        # whole-text placeholder — span redaction cannot locate the payload.
        stored = (
            redact_for_storage(text, observed.get("stored_redaction_via"))
            if observed["should_redact_stored"]
            else text
        )

        emit_event(
            config,
            provider="unknown",
            model="unknown",
            operation="crewai.step",
            source=SOURCE,
            prompt=stored,
            response="",
            compliance=observed["compliance"],
            metadata=_metadata,
        )
    except Exception:
        pass


# Deprecated alias — kept so existing direct callers remain functional.
obsvr_step_callback = _audit_step


def make_step_callback(
    existing_callback: Optional[Callable[[Any], None]] = None,
    run_context: Optional[Dict[str, Any]] = None,
) -> Callable[[Any], None]:
    """Return a composable step callback that chains audit → existing_callback.

    Pass the returned callable as ``step_callback=`` at construction time so
    no live Crew/Agent object is ever mutated::

        from obsvr.integrations.crewai import make_step_callback
        crew = Crew(..., step_callback=make_step_callback())

    To preserve an existing callback::

        crew = Crew(..., step_callback=make_step_callback(my_existing_cb))

    To enable agent-level tracing (share run_context with make_crew_callbacks)::

        run_ctx = {}
        crew = Crew(
            ...,
            step_callback=make_step_callback(run_context=run_ctx),
        )
    """
    ctx = run_context if run_context is not None else {}

    def _callback(step: Any) -> None:
        config = try_get_config()
        if config is not None:
            policy = getattr(config, "agent_policy", None) or {}
            agent_run_id = ctx.get("agent_run_id", "")
            step_index = ctx.get("step_count", 0)

            # Extract tool name from AgentAction (if present)
            tool_name = getattr(step, "tool", None)

            # Check tool policy
            if tool_name is not None:
                ok, reason = _check_tool(str(tool_name), policy)
                if not ok:
                    emit_event(
                        config,
                        provider="unknown",
                        model="unknown",
                        operation="crewai.agent.policy.tool_blocked",
                        source=SOURCE,
                        prompt="",
                        response="",
                        success=False,
                        metadata={
                            "agent_run_id": agent_run_id,
                            "tool_name": tool_name,
                            "reason": reason,
                            "step_index": step_index,
                        },
                    )
                    raise RuntimeError(
                        f"[obsvr] Tool blocked by agent policy: {tool_name}"
                    )

            # Check step limit
            count = ctx.get("step_count", 0)
            step_action = _check_steps(count, policy)

            if step_action == "block":
                emit_event(
                    config,
                    provider="unknown",
                    model="unknown",
                    operation="crewai.agent.policy.step_limit",
                    source=SOURCE,
                    prompt="",
                    response="",
                    success=False,
                    metadata={
                        "agent_run_id": agent_run_id,
                        "step_count": count,
                        "step_index": count,
                    },
                )
                raise RuntimeError("[obsvr] Step limit reached")

            if step_action == "escalate":
                emit_event(
                    config,
                    provider="unknown",
                    model="unknown",
                    operation="crewai.agent.policy.step_limit",
                    source=SOURCE,
                    prompt="",
                    response="",
                    metadata={
                        "agent_run_id": agent_run_id,
                        "step_count": count,
                        "step_index": count,
                        "escalated": True,
                    },
                )

            # Increment step counter
            ctx["step_count"] = count + 1

            # Build metadata for step event
            step_metadata: Optional[Dict[str, Any]] = None
            if agent_run_id or tool_name is not None:
                step_metadata = {
                    "agent_run_id": agent_run_id,
                    "step_index": step_index,
                }
                if tool_name is not None:
                    step_metadata["tool_name"] = str(tool_name)
            _audit_step(step, _metadata=step_metadata)
        else:
            _audit_step(step)

        if callable(existing_callback):
            existing_callback(step)

    return _callback


def make_crew_callbacks(
    run_context: Optional[Dict[str, Any]] = None,
    existing_before: Optional[Callable] = None,
    existing_after: Optional[Callable] = None,
) -> Tuple[Callable, Callable]:
    """Return (before_kickoff, after_kickoff) callbacks for run-level tracing.

    Use the same ``run_context`` dict with ``make_step_callback`` so all
    events share the same ``agent_run_id``::

        run_ctx = {}
        before_cb, after_cb = make_crew_callbacks(run_context=run_ctx)
        crew = Crew(
            ...,
            before_kickoff=before_cb,
            after_kickoff=after_cb,
            step_callback=make_step_callback(run_context=run_ctx),
        )
    """
    ctx = run_context if run_context is not None else {}

    def before_kickoff(crew: Any = None) -> Any:
        config = try_get_config()
        if config is not None:
            agent_run_id = str(uuid.uuid4())
            ctx["agent_run_id"] = agent_run_id
            ctx["step_count"] = 0

            policy = getattr(config, "agent_policy", None) or {}
            if not policy.get("allow_pii_access", True):
                ctx["strict_pii"] = True

            emit_event(
                config,
                provider="unknown",
                model="unknown",
                operation="crewai.agent.run.start",
                source=SOURCE,
                prompt="",
                response="",
                metadata={"agent_run_id": agent_run_id},
            )

        if callable(existing_before):
            return existing_before(crew)

    def after_kickoff(result: Any = None) -> Any:
        config = try_get_config()
        if config is not None:
            policy = getattr(config, "agent_policy", None) or {}
            output_policy = policy.get("output_policy") or {}
            denied_topics = output_policy.get("denied_topics") or []

            result_text = str(result) if result is not None else ""
            blocked_topic = None
            for topic in denied_topics:
                if topic.lower() in result_text.lower():
                    blocked_topic = topic
                    break

            agent_run_id = ctx.get("agent_run_id", "")

            if blocked_topic:
                emit_event(
                    config,
                    provider="unknown",
                    model="unknown",
                    operation="crewai.agent.policy.output_blocked",
                    source=SOURCE,
                    prompt="",
                    response=result_text,
                    success=False,
                    metadata={
                        "agent_run_id": agent_run_id,
                        "blocked_topic": blocked_topic,
                    },
                )
                if callable(existing_after):
                    existing_after(result)
                raise RuntimeError("[obsvr] Output blocked by agent policy")

            emit_event(
                config,
                provider="unknown",
                model="unknown",
                operation="crewai.agent.run.finish",
                source=SOURCE,
                prompt="",
                response=result_text,
                metadata={"agent_run_id": agent_run_id},
            )

        if callable(existing_after):
            return existing_after(result)

    return before_kickoff, after_kickoff


def make_task_callback(
    run_context: Optional[Dict[str, Any]] = None,
    existing: Optional[Callable] = None,
) -> Callable[[Any], None]:
    """Return a task callback that emits a task-complete event.

    Usage::

        run_ctx = {}
        crew = Crew(
            ...,
            task_callback=make_task_callback(run_context=run_ctx),
        )
    """
    ctx = run_context if run_context is not None else {}

    def _task_callback(task: Any) -> None:
        config = try_get_config()
        if config is not None:
            agent_run_id = ctx.get("agent_run_id", "")
            description = getattr(task, "description", None) or str(task)
            output = getattr(task, "output", None)
            output_text = str(output) if output is not None else ""

            emit_event(
                config,
                provider="unknown",
                model="unknown",
                operation="crewai.task.complete",
                source=SOURCE,
                prompt=description,
                response=output_text,
                metadata={
                    "agent_run_id": agent_run_id,
                    "task_description": description,
                },
            )

        if callable(existing):
            existing(task)

    return _task_callback
