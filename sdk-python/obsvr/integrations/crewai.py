"""CrewAI integration — a pre-execution tool gate, plus run/step/task audit.

TOOL POLICY ENFORCES HERE, through CrewAI's own ``before_tool_call`` hook.
``install_tool_gate_hook()`` registers a hook that CrewAI consults BEFORE
executing any tool, on both executor paths (native function-calling and the
ReAct text loop). A denied tool never runs: the hook refuses by the hook
system's own contract — it RETURNS ``False``, and CrewAI hands the agent a
"Tool execution blocked by hook" observation as the tool result and carries
on. The refusal is recorded as ``action_taken: "blocked"`` with the rule that
fired, which on this path is the truth. The hook never raises: an exception
inside a CrewAI hook is swallowed by the dispatcher and the tool RUNS, so the
returned-sentinel contract is the only one that does not fail open.

The gate is process-global (that is the scope CrewAI offers for tool hooks);
uninstall with the returned handle when it should stop applying::

    from obsvr.integrations.crewai import install_tool_gate_hook
    uninstall = install_tool_gate_hook()
    try:
        crew.kickoff()
    finally:
        uninstall()   # optional — leave installed for process-wide policy

Per-tool governance without a global hook — and with the full pre-call
policy net (PII, floor, canary, session taint) rather than allow/deny alone —
is ``obsvr.integrations.tools.govern_tool``; the two mechanisms compose.

The STEP CALLBACK is audit, not enforcement: CrewAI invokes it only after the
step it reports. When no gate hook is installed, a denied tool that already
ran on the ReAct path is recorded as ``action_taken: "not_evaluated"`` with
the reason — never as a block the callback cannot deliver. When the gate hook
IS installed, the hook speaks for tool policy and the step callback stays
silent on it. The step limit and the post-run output policy still raise.

Usage (composable constructor pattern)::

    from obsvr.integrations.crewai import make_step_callback
    crew = Crew(..., step_callback=make_step_callback())
    # chain an existing callback:
    crew = Crew(..., step_callback=make_step_callback(my_existing_cb))

    # Full run tracing:
    from obsvr.integrations.crewai import make_crew_callbacks, make_task_callback
    run_ctx = {}
    before_cb, after_cb = make_crew_callbacks(run_context=run_ctx)
    crew = Crew(
        ...,
        before_kickoff_callbacks=[before_cb],
        after_kickoff_callbacks=[after_cb],
        step_callback=make_step_callback(run_context=run_ctx),
        task_callback=make_task_callback(run_context=run_ctx),
    )

The kickoff kwargs are ``before_kickoff_callbacks`` / ``after_kickoff_callbacks``,
plural and list-valued. The singular ``before_kickoff=`` / ``after_kickoff=``
this docstring used to show are not Crew fields on current releases, and
Crew's pydantic config is ``extra="ignore"`` — the kwargs are DISCARDED with
nothing raised, and the run-level audit silently never happens.
"""

# Interception: constructor argument (composable, non-mutating). Pass
# make_step_callback() as step_callback= at Crew/Agent construction time —
# no live-object mutation. obsvr_step_callback kept as deprecated alias.

import uuid
from typing import Any, Callable, Dict, Optional, Tuple

from .. import sender as _sender
from ..agent_policy import check_steps, unrecognized_step_action_meta
from ..config import try_get_config
from ..events import (
    emit_event,
    step_limit_compliance,
    tool_denied_compliance,
    tool_gate_not_evaluated_compliance,
)
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


# ---------------------------------------------------------------------------
# Pre-execution tool gate (CrewAI before_tool_call hook)
# ---------------------------------------------------------------------------

# How many obsvr tool-gate hooks are currently registered. The step callback
# consults this: when a gate hook is active, the hook is the authority on tool
# policy and the callback must not also emit a post-hoc verdict about the same
# call. Module-global on purpose — CrewAI's tool hooks are process-global, so
# per-instance state would misdescribe the scope of what is installed.
_active_tool_gate_hooks = 0


def _tool_gate_hook_active() -> bool:
    return _active_tool_gate_hooks > 0


def make_tool_gate_hook(
    run_context: Optional[Dict[str, Any]] = None,
) -> Callable[[Any], Optional[bool]]:
    """A ``before_tool_call`` hook enforcing the agent-policy tool list.

    CrewAI runs it before the tool executes, on both executor paths. Refusal
    is by RETURNED SENTINEL: ``False`` blocks (CrewAI raises its own
    ``HookAborted`` internally and hands the agent a blocked-tool observation);
    ``None`` allows. The hook never raises — the hook dispatcher swallows
    exceptions and RUNS the tool, so a raise-based refusal here would fail
    open. For the same reason an internal failure of this hook allows rather
    than blocks, matching the SDK's default fail-open posture for hook errors.

    Prefer :func:`install_tool_gate_hook`, which also registers it.
    """
    ctx = run_context if run_context is not None else {}

    def _tool_gate(context: Any) -> Optional[bool]:
        try:
            config = try_get_config()
            if config is None:
                return None
            policy = getattr(config, "agent_policy", None) or {}
            tool_name = str(getattr(context, "tool_name", "") or "unknown_tool")
            ok, reason = _check_tool(tool_name, policy)
            if ok:
                return None
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
                    "agent_run_id": ctx.get("agent_run_id", ""),
                    "tool_name": tool_name,
                    "reason": reason,
                    "step_index": ctx.get("step_count", 0),
                },
                compliance=tool_denied_compliance(),
            )
            return False  # the sentinel: CrewAI does not run the tool
        except Exception:
            # A raise would be swallowed fail-open by the dispatcher anyway;
            # failing open EXPLICITLY keeps the contract visible here.
            return None

    return _tool_gate


def install_tool_gate_hook(
    run_context: Optional[Dict[str, Any]] = None,
) -> Callable[[], None]:
    """Register the pre-execution tool gate. Returns an uninstall callable.

    Registration is global — the only scope CrewAI's tool hooks offer — so
    the gate applies to every crew in the process until uninstalled. The
    uninstall handle is idempotent.
    """
    try:
        from crewai.hooks.tool_hooks import (
            register_before_tool_call_hook,
            unregister_before_tool_call_hook,
        )
        # Registration alone is NOT the capability. A run of releases ships
        # the register/unregister half with no dispatcher and no executor
        # call site (measured: run_before_tool_call_hooks absent, and
        # tool_utils consults nothing), so a hook accepted there is never
        # asked. The consumer side — the executor's own import of the
        # dispatcher — is what feature-detection requires.
        from crewai.utilities import tool_utils as _tool_utils

        if not callable(getattr(_tool_utils, "run_before_tool_call_hooks", None)):
            raise ImportError(
                "before_tool_call hooks can be registered but are never "
                "dispatched by the tool executor on this build"
            )
    except ImportError as e:
        # Feature-detected, not version-compared: forks, backports and
        # vendored builds lie about versions; attribute presence does not.
        # Failing LOUDLY here is the point — a silent no-op install would be
        # a gate the caller believes in and does not have.
        raise ImportError(
            "[obsvr] this CrewAI build has no working before_tool_call hook "
            "system, so the pre-execution gate cannot install. Gate the "
            "tools themselves instead: obsvr.govern_tool"
        ) from e

    global _active_tool_gate_hooks
    hook = make_tool_gate_hook(run_context=run_context)
    register_before_tool_call_hook(hook)
    _active_tool_gate_hooks += 1
    removed = False

    def _uninstall() -> None:
        global _active_tool_gate_hooks
        nonlocal removed
        if removed:
            return
        removed = True
        unregister_before_tool_call_hook(hook)
        _active_tool_gate_hooks -= 1

    return _uninstall


# ---------------------------------------------------------------------------
# Internal audit helper
# ---------------------------------------------------------------------------


def _audit_step(step: Any, _metadata: Optional[Dict[str, Any]] = None) -> None:
    """Audit a single CrewAI agent step. Never raises."""
    try:
        config = try_get_config()
        if config is None:
            return
        # Sampling gates the EMISSION of clean allowed events, never the PII
        # scan. Returning here skipped apply_observe_policy below, so a sub-1.0
        # sample_rate silently dropped the scan and the redaction of the stored
        # copy on a fraction of traffic. Carry the decision to the emit site,
        # the same posture wrap.py ``_emit_audit`` already takes.
        should_audit = _sender.should_sample(config.sample_rate)
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

        # Allowed: emit only when sampled in. Anything the scan acted on is
        # enforcement evidence and is always recorded.
        compliance = observed["compliance"]
        if not (
            should_audit
            or compliance.get("action_taken", "allowed") != "allowed"
            or compliance.get("action_reason", "none") != "none"
        ):
            return

        emit_event(
            config,
            provider="unknown",
            model="unknown",
            operation="crewai.step",
            source=SOURCE,
            prompt=stored,
            response="",
            compliance=compliance,
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

            # Check tool policy. A step that carries a tool name arrives only
            # AFTER the step happened: CrewAI's ReAct loop reports the
            # AgentAction once the tool call was resolved, and the native path
            # never delivers a tool name at all. When a pre-execution gate has
            # already ruled on this call — the hook, or a govern_tool wrapper
            # that owns this tool's name — the callback says nothing about
            # tool policy: a second, post-hoc verdict beside a real one is a
            # contradiction on the record. Without either gate there is no
            # refusal to record — only the honest absence of one — and
            # raising would not stop anything either: the executor treats
            # anything but its own ToolExecutionFailedError as retryable, so
            # a raise from this callback re-runs the whole task (and the
            # denied tool's side effect) up to max_retry_limit more times.
            from .tools import is_tool_governed

            if (
                tool_name is not None
                and not _tool_gate_hook_active()
                and not is_tool_governed(str(tool_name))
            ):
                ok, reason = _check_tool(str(tool_name), policy)
                if not ok:
                    emit_event(
                        config,
                        provider="unknown",
                        model="unknown",
                        operation="crewai.agent.policy.tool_not_evaluated",
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
                        compliance=tool_gate_not_evaluated_compliance(
                            surface="crewai.step_callback",
                            gate="tool_gate",
                            reason=(
                                f"tool policy would have refused this call "
                                f"({reason}), but the step callback is "
                                f"delivered after the tool has already run "
                                f"and cannot bind it"
                            ),
                        ),
                    )

            # Check step limit
            count = ctx.get("step_count", 0)
            step_action, invalid_step_action = check_steps(count, policy)

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
                        **unrecognized_step_action_meta(invalid_step_action),
                    },
                    compliance=step_limit_compliance(),
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
            before_kickoff_callbacks=[before_cb],
            after_kickoff_callbacks=[after_cb],
            step_callback=make_step_callback(run_context=run_ctx),
        )

    The kwargs are plural and list-valued; singular ``before_kickoff=`` /
    ``after_kickoff=`` kwargs do not exist on current Crew releases and are
    silently discarded by its ``extra="ignore"`` pydantic config.

    Both callbacks honour Crew's replace-through contract: CrewAI assigns each
    callback's return value over the thing it was handed
    (``normalized = before_callback(normalized)``, ``result = after_callback(result)``),
    so these hand back what they received — before: the inputs dict, after: the
    ``CrewOutput`` — or the chained callback's non-None return.
    """
    ctx = run_context if run_context is not None else {}

    def before_kickoff(inputs: Any = None) -> Any:
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
            chained = existing_before(inputs)
            if chained is not None:
                return chained
        # Crew replaces its inputs with this return value; None would
        # discard the caller's inputs dict.
        return inputs

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
            chained = existing_after(result)
            if chained is not None:
                return chained
        # Crew replaces the run's CrewOutput with this return value; None
        # would hand the caller None instead of their result.
        return result

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
