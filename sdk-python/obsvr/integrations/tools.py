"""Framework-agnostic tool governance — govern the tool itself.

``govern_tool(tool)`` wraps a tool object from ANY agent framework so that
every invocation is governed at the point of execution, before the tool's own
code runs:

  1. allow/deny against ``agent_policy`` (``denied_tools`` / ``allowed_tools``)
     — a denied tool RAISES the SDK's typed policy error before its function
     runs, so the side effect never exists;
  2. the full pre-call policy net — ``policy_rules``, the ``policy_floor``,
     PII block/redact, ``on_pre_call``, canary and session-taint gates
     (including ``destructive_tools``) — the SAME pipeline ``obsvr.wrap()``
     and the MCP integration run, not an integration-grade subset;
  3. a signed audit event per call (``tool.call`` / ``tool.policy.tool_blocked``)
     carrying the sealed tool-content digest of the descriptor and arguments.

This is the Python twin of the TypeScript SDK's ``obsvrGovernTool``
(``integrations/tools.ts``), and it exists for the same reason: most agent
frameworks either surface no pre-execution tool callback at all, or change it
across versions. Wrapping the tool's own callable is the one boundary every
framework converges on — its dispatch has to call SOMETHING, and this is the
something::

    from obsvr.integrations.tools import govern_tool
    safe_search = govern_tool(search_tool)
    agent = Agent(..., tools=[safe_search])

Where the gate physically sits, per framework shape (first match wins):

    on_invoke_tool     openai-agents ``FunctionTool`` (input is argument 1)
    _run / _arun       crewai and langchain ``BaseTool`` subclasses (what
                       structured-tool conversion captures)
    execute            execute-shaped tool objects
    call / acall       llamaindex ``FunctionTool``
    invoke / ainvoke   structured tools exposing only the public surface
    run / arun         run-shaped tool objects
    func               plain function-holder shapes
    (bare callable)    a plain function is wrapped and returned directly

PLUS ``func`` alongside whichever attr matched, whenever the object stores
its callable in a ``func`` field: entry points fan out (crewai's ``Tool.run``
calls ``self.func`` directly, bypassing ``_run``), and the stored callable is
where they converge. A reentrancy guard keeps a delegating entry point from
being gated or audited twice for one invocation.

A governed tool also DECLINES RESULT CACHING where the framework offers a say
(``cache_function``). A result cache serves a repeat call from the framework's
own memory without entering the callable, so a cached answer would escape this
gate entirely — and escape it invisibly, since no execution happens for a
side-effect instrument to count. Measured on CrewAI: allowed once, denied
after, the caller still received the cached output. See :func:`_never_cache`.

A refusal is a RAISE of ``ObsvrPolicyError`` from inside the tool's callable.
What the framework does with it is the framework's contract — CrewAI converts
it into a failed-tool observation and the run continues; LangChain propagates
it out of the tool — but in every case the guarantee is the same: the tool
body was never entered. An unrecognized tool shape is returned unchanged,
never broken; a wrapped tool is a shallow COPY where the object permits it,
so the caller's original is not mutated.
"""

import contextvars
import copy
import functools
import inspect
import json
from typing import Any, Callable, Dict, Optional, Set, Tuple

from ..capability_hints import declares_destructive
from ..config import try_get_config
from ..errors import ObsvrPolicyError
from ..events import (
    blocked_call_error,
    emit_event,
    tool_denied_compliance,
)
from ..policy import apply_pre_call_policy, blocked_prompt_for_storage
from ..tool_content_hash import safe_tool_content_hash, tool_content_metadata

SOURCE = "obsvr_tool"

#: Names of every tool a governor wraps, for the audit rails that would
#: otherwise re-judge a governed call after the fact (CrewAI's step callback
#: consults this so it never stamps ``not_evaluated`` beside the wrapper's own
#: verdict). Process-lifetime by design — a governed name stays the wrapper's
#: to speak for.
_GOVERNED_TOOL_NAMES: Set[str] = set()


def is_tool_governed(tool_name: str) -> bool:
    """Whether a tool of this name has been wrapped by :func:`govern_tool`."""
    return tool_name in _GOVERNED_TOOL_NAMES


def governed_tool_names() -> Set[str]:
    """A copy of the governed-name registry.

    For audit rails whose framework renames tools before dispatch and so
    cannot ask about a name they can only recognize after normalizing it
    (CrewAI sanitizes, and the transform is not invertible).
    """
    return set(_GOVERNED_TOOL_NAMES)


def register_governed_tool_name(tool_name: str) -> None:
    """Record that a pre-execution gate outside this module speaks for a name.

    For integration-owned gates whose refusal lives in the framework's own
    pre-invocation surface (openai-agents' tool input guardrails) rather than
    in a wrapped callable. One registry serves every audit rail that must not
    stamp ``not_evaluated`` beside a real gate's own verdict, whichever
    mechanism the gate is. Process-lifetime, like the wrapper's own entries.
    """
    _GOVERNED_TOOL_NAMES.add(tool_name)

#: Exec-attr resolution table: (sync_attr, async_attr) in priority order.
#: ORDER IS THE CONTRACT (the TS twin learned this the hard way: three shapes
#: appended late were silent no-ops until added). ``_run`` outranks the public
#: ``run``/``invoke`` because crewai's structured-tool conversion captures the
#: BOUND ``_run`` (``base_tool.py: func=self._run``) — gating anything shallower
#: leaves that captured reference ungoverned.
_EXEC_ATTR_PAIRS: Tuple[Tuple[str, Optional[str]], ...] = (
    ("on_invoke_tool", None),
    ("_run", "_arun"),
    ("execute", None),
    ("call", "acall"),
    ("invoke", "ainvoke"),
    ("run", "arun"),
    ("func", None),
)


def _resolve_exec_attrs(tool: Any) -> Tuple[str, ...]:
    """The attrs to gate on this object.

    The first present pair, both halves — PLUS ``func`` whenever the object
    stores its callable in a field, because public entry points fan out and
    the stored callable is where they converge: crewai's ``Tool.run`` and
    ``Tool.arun`` call ``self.func`` directly without passing through
    ``_run``, so a gate on ``_run`` alone covers the ReAct dispatch (which
    captures ``_run``) and MISSES the native dispatch (which captures
    ``run``). Measured live before this was learned: the same governed tool
    blocked on ReAct and executed on native. The per-call reentrancy guard
    below keeps an entry point that DOES delegate inward from being gated
    and audited twice.
    """
    for sync_attr, async_attr in _EXEC_ATTR_PAIRS:
        if callable(getattr(tool, sync_attr, None)):
            attrs = [sync_attr]
            if async_attr and callable(getattr(tool, async_attr, None)):
                attrs.append(async_attr)
            if sync_attr != "func" and callable(getattr(tool, "func", None)):
                attrs.append("func")
            return tuple(attrs)
    return ()


def _resolve_tool_name(tool: Any, explicit: Optional[str]) -> str:
    if explicit:
        return explicit
    for source in (
        getattr(tool, "name", None),
        getattr(getattr(tool, "metadata", None), "name", None),
        getattr(tool, "__name__", None),
    ):
        if isinstance(source, str) and source:
            return source
    return "unknown_tool"


def _descriptor_of(tool: Any, tool_name: str) -> Dict[str, Any]:
    """Best-effort descriptor under the evidence contract's wire names.

    The schema is included when the tool carries one that can be projected to
    JSON; a tool carrying none contributes no schema rather than a guessed one
    (same posture as the TS twin).
    """
    descriptor: Dict[str, Any] = {"name": tool_name}
    description = getattr(tool, "description", None)
    if isinstance(description, str) and description:
        descriptor["description"] = description
    schema = getattr(tool, "args_schema", None)
    try:
        if schema is not None and hasattr(schema, "model_json_schema"):
            descriptor["inputSchema"] = schema.model_json_schema()
        elif isinstance(schema, dict):
            descriptor["inputSchema"] = schema
    except Exception:
        pass  # sealed evidence: a missing schema beats a wrong one
    return descriptor


def _input_of(exec_attr: str, args: tuple, kwargs: dict) -> Any:
    """The tool input, normalized across calling conventions.

    ``on_invoke_tool(run_context, input)`` carries the input at position 1;
    every other shape carries it at position 0 or as keyword arguments.
    """
    if exec_attr == "on_invoke_tool" and len(args) >= 2:
        return args[1]
    if kwargs and not args:
        return kwargs
    if len(args) == 1 and not kwargs:
        return args[0]
    payload: Dict[str, Any] = {}
    if args:
        payload["args"] = list(args)
    if kwargs:
        payload["kwargs"] = kwargs
    return payload


def _input_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value if value is not None else {}, default=str)
    except Exception:
        return str(value)


def _check_tool(tool_name: str, policy: Dict[str, Any]) -> Tuple[bool, str]:
    """Return (allowed, reason). reason is empty string when allowed."""
    denied = policy.get("denied_tools") or []
    allowed = policy.get("allowed_tools")  # None = all allowed
    if tool_name in denied:
        return False, "tool_denied"
    if allowed is not None and tool_name not in allowed:
        return False, "tool_not_in_allowlist"
    return True, ""


def _gate(
    tool: Any,
    tool_name: str,
    exec_attr: str,
    args: tuple,
    kwargs: dict,
    options: Dict[str, Any],
) -> None:
    """Run every check that must precede the tool body. Raises to refuse."""
    config = try_get_config()
    if config is None:
        return

    raw_input = _input_of(exec_attr, args, kwargs)
    input_text = _input_text(raw_input)
    content_meta = tool_content_metadata(
        safe_tool_content_hash(
            tool_name=tool_name,
            descriptor=_descriptor_of(tool, tool_name),
            args=raw_input,
        )
    )
    event_options = options or None

    # 1) allow/deny — refuse a denied tool before it runs.
    policy = getattr(config, "agent_policy", None) or {}
    ok, reason = _check_tool(tool_name, policy)
    if not ok:
        compliance = tool_denied_compliance()
        emit_event(
            config,
            provider="unknown",
            model="unknown",
            operation="tool.policy.tool_blocked",
            source=SOURCE,
            prompt="",
            response="",
            success=False,
            metadata={"tool_name": tool_name, "reason": reason, **content_meta},
            compliance=compliance,
            options=event_options,
        )
        raise blocked_call_error(compliance)

    # 2) the full pre-call net, exactly as the MCP boundary runs it: gated on
    # the same trigger list, blocking on the same decision, honouring
    # fail_mode the same way. This is deliberately NOT the observe-only
    # subset the callback integrations run — a wrapped tool is a real
    # enforcement boundary, so it gets the real pipeline.
    from ..canary import canary_registry_size
    from ..session_taint import session_taint_size

    compliance_out: Optional[Dict[str, Any]] = None
    stored_prompt = input_text
    if (
        config.policy_floor
        or config.pii_policy is not None
        or config.on_pre_call is not None
        or canary_registry_size() > 0
        or session_taint_size() > 0
    ):
        try:
            result = apply_pre_call_policy(
                input_text,
                config,
                provider="unknown",
                operation="tool.call",
                metadata=(options or {}).get("metadata"),
                tool_name=tool_name,
                tool_declared_destructive=declares_destructive(tool),
            )
            compliance_out = result["compliance"]
            stored_prompt = result["redacted_prompt"]
            if result["decision"] == "block":
                emit_event(
                    config,
                    provider="unknown",
                    model="unknown",
                    operation="tool.call",
                    source=SOURCE,
                    prompt=blocked_prompt_for_storage(
                        input_text, compliance_out, result.get("security_normalized")
                    ),
                    response="",
                    success=False,
                    status_code=403,
                    metadata={"tool_name": tool_name, **content_meta},
                    compliance=compliance_out,
                    options=event_options,
                )
                raise blocked_call_error(compliance_out)
        except ObsvrPolicyError:
            raise
        except Exception as e:
            # Parity with the MCP boundary: an engine that cannot render a
            # verdict is not approval under fail_mode="closed"; under the
            # default "open" the evaluation error does not block the tool.
            if getattr(config, "fail_mode", "open") == "closed":
                raise blocked_call_error(
                    {
                        "event_type": "blocked_call",
                        "policy_version": "none",
                        "action_taken": "blocked",
                        "action_reason": "policy_violation",
                        "action_source": "policy_rules",
                        "redacted_types": [],
                        "blocked_types": [],
                    }
                ) from e
            compliance_out = None
            stored_prompt = input_text

    # 3) signed tool.call audit event.
    emit_event(
        config,
        provider="unknown",
        model="unknown",
        operation="tool.call",
        source=SOURCE,
        prompt=stored_prompt,
        response="",
        metadata={"tool_name": tool_name, **content_meta},
        compliance=compliance_out
        or {
            "event_type": "tool_call",
            "policy_version": "none",
            "action_taken": "allowed",
            "action_reason": "none",
            "action_source": "policy_rules",
            "redacted_types": [],
            "blocked_types": [],
        },
        options=event_options,
    )


def _wrap_callable(
    tool: Any,
    tool_name: str,
    exec_attr: str,
    original: Callable[..., Any],
    options: Dict[str, Any],
    inflight: "contextvars.ContextVar[bool]",
) -> Callable[..., Any]:
    """Gate one callable. ``inflight`` is shared across every gated attr of
    one governed object: an outer entry point that delegates to an inner
    gated attr (crewai's ``_run`` → ``func``) must be gated ONCE — a second
    verdict and a second audit event for one invocation is how a step budget
    silently drifts."""
    if inspect.iscoroutinefunction(original):

        @functools.wraps(original)
        async def gated_async(*args: Any, **kwargs: Any) -> Any:
            if inflight.get():
                return await original(*args, **kwargs)
            token = inflight.set(True)
            try:
                _gate(tool, tool_name, exec_attr, args, kwargs, options)
                return await original(*args, **kwargs)
            finally:
                inflight.reset(token)

        return gated_async

    @functools.wraps(original)
    def gated(*args: Any, **kwargs: Any) -> Any:
        if inflight.get():
            return original(*args, **kwargs)
        token = inflight.set(True)
        try:
            _gate(tool, tool_name, exec_attr, args, kwargs, options)
            return original(*args, **kwargs)
        finally:
            inflight.reset(token)

    return gated


def _never_cache(_args: Any = None, _result: Any = None) -> bool:
    """Decline memoization of a governed tool's result.

    A framework result cache answers a repeat call out of its own memory
    WITHOUT invoking the tool's callable — which is the only place this
    governor sits. Measured on CrewAI with the crew's cache enabled: a tool
    run while allowed and re-requested after the policy denied it was served
    the cached output, the tool body was never entered, and so the
    side-effect instrument read ZERO while the caller still received the
    content — a block that never happened, reported as one.

    Refusing to cache is what keeps "every invocation is governed" literally
    true: the call reaches the callable every time, so the gate rules every
    time. Frameworks that consult a ``cache_function`` to decide whether to
    store a result (CrewAI reads it at every cache-write site) therefore get
    a permanent no from a governed tool.
    """
    return False


def _refuse_result_caching(tool: Any) -> bool:
    """Neutralize a framework's result cache for this tool. Returns applied."""
    if not hasattr(tool, "cache_function"):
        return False
    try:
        object.__setattr__(tool, "cache_function", _never_cache)
        return True
    except Exception:
        # A container that will not accept the override still gets the gate;
        # it just keeps whatever caching it had. Never break the caller's tool
        # over a defence-in-depth measure.
        return False


def _copy_tool(tool: Any) -> Any:
    """A shallow copy when the object permits one, else the object itself.

    pydantic models copy through ``model_copy``; most plain objects through
    ``copy.copy``. An object that refuses both is gated in place — documented,
    and strictly better than returning it ungoverned.
    """
    try:
        if hasattr(tool, "model_copy"):
            return tool.model_copy()
        return copy.copy(tool)
    except Exception:
        return tool


def govern_tool(tool: Any, name: Optional[str] = None, **options: Any) -> Any:
    """Wrap a framework tool so its execution is governed by obsvr.

    Returns an object of the same type whose execute callable(s) are gated;
    the original is not mutated when the object supports copying. A tool whose
    shape is not recognized is returned unchanged (never breaks the caller) —
    unless it is itself callable, in which case the callable is wrapped.

    ``name=`` pins the audit name for tools that carry none of their own.
    Remaining keyword options (``user_id=``, ``service_name=``,
    ``metadata=``) attach the audit principal to every event, the same way
    the other integrations accept them.
    """
    exec_attrs = _resolve_exec_attrs(tool)
    tool_name = _resolve_tool_name(tool, name)

    if not exec_attrs:
        if callable(tool):
            original = tool
            inflight: "contextvars.ContextVar[bool]" = contextvars.ContextVar(
                "obsvr_tool_gate_inflight", default=False
            )
            _GOVERNED_TOOL_NAMES.add(tool_name)
            return _wrap_callable(
                original, tool_name, "__call__", original, options, inflight
            )
        return tool

    governed = _copy_tool(tool)
    _refuse_result_caching(governed)
    inflight = contextvars.ContextVar("obsvr_tool_gate_inflight", default=False)
    for attr in exec_attrs:
        original = getattr(governed, attr)
        wrapped = _wrap_callable(
            governed, tool_name, attr, original, options, inflight
        )
        # object.__setattr__ so pydantic/frozen containers cannot veto the
        # gate: the instance attribute shadows the class method (or replaces
        # the stored field value, for `func`), which is exactly what the
        # conversion helpers that capture the BOUND callable read.
        object.__setattr__(governed, attr, wrapped)
    _GOVERNED_TOOL_NAMES.add(tool_name)
    return governed


def govern_tools(tools: Any, **options: Any) -> list:
    """Wrap several tools at once. Names are read from each tool."""
    return [govern_tool(t, **options) for t in tools]
