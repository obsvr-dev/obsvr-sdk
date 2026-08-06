"""PydanticAI integration — governance at the toolset boundary.

PydanticAI runs every tool call through a toolset's ``call_tool`` method, and
ships ``WrapperToolset`` precisely so a toolset can be wrapped to intercept
that call. ``ObsvrToolset`` subclasses it (when PydanticAI is installed) and
governs each call before delegating:

- tool allow/deny (``agent_policy``),
- built-in PII scan + structured rules + the pre-call hook (HITL) on the tool
  arguments.

A block **raises** from ``call_tool`` before the wrapped toolset is reached, so
the tool never executes. The raise is not a ``ModelRetry``, so PydanticAI does
not turn it into a retry prompt and does not hand it back to the model: it
propagates and ends the run. That is the intended shape for a policy refusal —
a denied tool should not become something the model is invited to route around
— but it is a run-ending exception rather than a recoverable tool failure, and
calling code should expect to catch it.

WHICH TOOLS A WRAPPER COVERS. ``ObsvrToolset`` governs the toolset it wraps,
and that is the whole story only when every tool lives in that toolset. Usually
none does: an agent keeps its OWN function toolset for ``@agent.tool``,
``@agent.tool_plain`` and ``Agent(tools=[...])``, and PydanticAI combines that
with anything passed to ``Agent(toolsets=[...])`` as SIBLINGS. A combined
toolset dispatches each call to whichever sibling owns the tool, so a wrapper
around one never sees a call into another. Measured on a real agent graph, one
policy, one tool name: refused through ``Agent(toolsets=[ObsvrToolset(...)])``,
and executed — payload returned to the caller — with the same tool registered
through ``@agent.tool``.

:func:`govern_agent` binds one level up, to the toolset the agent assembles for
its tool manager, which is the single object every dispatch passes through. Use
it whenever tools can reach the agent by more than one route.

Usage::

    from pydantic_ai import Agent
    from pydantic_ai.toolsets import FunctionToolset
    from obsvr.integrations.pydantic_ai import ObsvrToolset, govern_agent
    import obsvr

    obsvr.init(api_key="...", ingest_url="https://...",
               agent_policy={"denied_tools": ["shell_exec"]})

    # Covers every tool the agent can dispatch, however it was registered.
    agent = govern_agent(Agent("openai:gpt-4o"))

    # Or govern one toolset, where that toolset holds every tool there is.
    agent = Agent("openai:gpt-4o", toolsets=[ObsvrToolset(FunctionToolset([...]))])
"""

# Interception: PydanticAI WrapperToolset.call_tool override (non-mutating),
# either around a toolset the caller owns or around the toolset the agent
# assembles for its tool manager. The wrapped toolset is delegated to; a policy
# block raises before delegation, stopping the tool from ever executing.

import dataclasses
import json
from typing import Any, Dict, Optional, Tuple

from ..config import try_get_config
from ..binding_report import record_binding
from ..events import emit_event, tool_denied_compliance
from ..policy import (
    apply_outbound_redaction,
    apply_pre_call_policy,
    assert_redaction_applied,
    blocked_prompt_for_storage,
    outbound_redaction_blocked_compliance,
    redact_arguments,
    redact_builtin_pii,
)

SOURCE = "pydantic_ai"
PROVIDER = "pydantic_ai"

try:  # real base when PydanticAI is installed; a shim duck-types it otherwise
    from pydantic_ai.toolsets import WrapperToolset as _WrapperToolset  # type: ignore

    _HAS_PYDANTIC_AI = True
    record_binding("pydantic_ai", "pydantic_ai.toolsets.WrapperToolset")
except Exception as _exc:  # pragma: no cover - PydanticAI not installed
    _HAS_PYDANTIC_AI = False
    record_binding("pydantic_ai", "pydantic_ai.toolsets.WrapperToolset", _exc)

    class _WrapperToolset:  # type: ignore
        """Minimal stand-in duck-typing PydanticAI's WrapperToolset."""

        def __init__(self, wrapped: Any) -> None:
            object.__setattr__(self, "wrapped", wrapped)

        def __getattr__(self, item: str) -> Any:
            return getattr(object.__getattribute__(self, "wrapped"), item)


class PydanticAIToolBlockedError(RuntimeError):
    """Raised when a tool call is blocked by policy (denylist/allowlist/PII/hook)."""


def _check_tool(tool_name: str, policy: Dict[str, Any]) -> Tuple[bool, str]:
    denied = policy.get("denied_tools") or []
    allowed = policy.get("allowed_tools")
    if tool_name in denied:
        return False, "tool_denied"
    if allowed is not None and tool_name not in allowed:
        return False, "tool_not_in_allowlist"
    return True, ""


def _args_prompt(tool_name: str, tool_args: Any) -> str:
    try:
        return f"{tool_name}({json.dumps(tool_args or {}, default=str)})"
    except Exception:
        return f"{tool_name}(...)"


@dataclasses.dataclass(init=False, eq=False)
class ObsvrToolset(_WrapperToolset):  # type: ignore[misc]
    """Governing wrapper around any PydanticAI toolset.

    ``options`` may carry ``user_id`` / ``service_name`` / ``metadata`` (threaded
    into the rules-eval identity and attached to the audit as the principal).
    """

    # PydanticAI rebuilds a toolset tree with ``dataclasses.replace`` — that is
    # what ``WrapperToolset.visit_and_replace`` does, and the agent runs it over
    # its own tree. ``replace`` reconstructs through ``__init__`` from the
    # DECLARED FIELDS, so anything held outside them is dropped: measured, a
    # rebuilt toolset came back with its options at ``{}``, and every audit
    # event it went on to emit carried no caller principal. Enforcement was
    # unaffected, which is exactly why it stayed invisible — the tool was still
    # refused, the record just stopped saying on whose behalf. Declaring the
    # options as a FIELD is what carries them through the rebuild.
    _obsvr_options: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def __init__(
        self, wrapped: Any, _obsvr_options: Optional[Dict[str, Any]] = None, **options: Any
    ) -> None:
        try:
            super().__init__(wrapped)
        except TypeError:  # pragma: no cover - shim path / alternate ctor
            object.__setattr__(self, "wrapped", wrapped)
        merged = dict(_obsvr_options or {})
        merged.update(options)
        # object.__setattr__ so a frozen-dataclass base still accepts the field.
        object.__setattr__(self, "_obsvr_options", merged)

    def _identity_meta(self) -> Optional[Dict[str, Any]]:
        opts = getattr(self, "_obsvr_options", {}) or {}
        meta = dict(opts.get("metadata") or {})
        if opts.get("user_id") is not None:
            meta["user_id"] = opts["user_id"]
        if opts.get("service_name") is not None:
            meta["service_name"] = opts["service_name"]
        return meta or None

    async def call_tool(self, name: str, tool_args: Any, *args: Any, **kwargs: Any) -> Any:
        cfg = try_get_config()
        wrapped = object.__getattribute__(self, "wrapped")
        if cfg is None:
            return await wrapped.call_tool(name, tool_args, *args, **kwargs)

        opts = getattr(self, "_obsvr_options", {}) or None
        tool_name = str(name or "unknown")
        policy = getattr(cfg, "agent_policy", None) or {}

        ok, reason = _check_tool(tool_name, policy)
        if not ok:
            emit_event(
                cfg, provider=PROVIDER, model="unknown",
                operation="pydantic_ai.tool.policy.tool_blocked", source=SOURCE,
                prompt="", response="", success=False, status_code=403,
                metadata={"tool_name": tool_name, "reason": reason},
                compliance=tool_denied_compliance(), options=opts,
            )
            raise PydanticAIToolBlockedError(
                f"[obsvr] Tool blocked by policy: {tool_name} ({reason})"
            )

        prompt_text = _args_prompt(tool_name, tool_args)
        result = apply_pre_call_policy(
            prompt_text, cfg, provider=PROVIDER, operation="pydantic_ai.tool.call",
            metadata=self._identity_meta(), tool_name=tool_name,
        )
        compliance = result["compliance"]
        if result["decision"] == "block":
            emit_event(
                cfg, provider=PROVIDER, model="unknown", operation="pydantic_ai.tool.call",
                source=SOURCE,
                prompt=blocked_prompt_for_storage(
                    prompt_text, compliance, result.get("security_normalized")
                ),
                response="", success=False, status_code=403, compliance=compliance,
                metadata={"tool_name": tool_name}, options=opts,
            )
            raise PydanticAIToolBlockedError(
                f"[obsvr] Tool call blocked by policy: {tool_name}"
            )

        stored_prompt = result["redacted_prompt"]
        if result["decision"] == "redact":
            # ENFORCEMENT APPLICATION, not a record of one. The pipeline's
            # redacted copy is of the SCANNED TEXT and cannot be handed to a
            # tool that takes arguments, so the arguments themselves are
            # rewritten and the stored prompt is then derived from THOSE — the
            # record describes what the tool received because it is built from
            # it. Fails closed exactly as the wrap() path does.
            redacted_state: Dict[str, Any] = {}

            def _apply_redaction() -> None:
                redacted_args = redact_arguments(tool_args, redact_builtin_pii)
                assert_redaction_applied(redacted_args, compliance)
                redacted_state["args"] = redacted_args

            not_redacted = apply_outbound_redaction(_apply_redaction)
            if not_redacted is not None:
                compliance = outbound_redaction_blocked_compliance(
                    compliance, not_redacted
                )
                emit_event(
                    cfg, provider=PROVIDER, model="unknown",
                    operation="pydantic_ai.tool.call", source=SOURCE,
                    prompt=blocked_prompt_for_storage(
                        prompt_text, compliance, result.get("security_normalized")
                    ),
                    response="", success=False, status_code=403,
                    compliance=compliance,
                    metadata={"tool_name": tool_name}, options=opts,
                )
                raise PydanticAIToolBlockedError(
                    f"[obsvr] Tool call blocked by policy: {tool_name}"
                )
            tool_args = redacted_state["args"]
            stored_prompt = _args_prompt(tool_name, tool_args)

        emit_event(
            cfg, provider=PROVIDER, model="unknown", operation="pydantic_ai.tool.call",
            source=SOURCE, prompt=stored_prompt, response="",
            compliance=compliance, metadata={"tool_name": tool_name}, options=opts,
        )
        return await wrapped.call_tool(name, tool_args, *args, **kwargs)


def govern_toolset(toolset: Any, **options: Any) -> ObsvrToolset:
    """Convenience: wrap a toolset in an ``ObsvrToolset``."""
    return ObsvrToolset(toolset, **options)


_AGENT_GOVERNED_ATTR = "_obsvr_agent_governed"


def govern_agent(agent: Any, **options: Any) -> Any:
    """Govern EVERY tool an agent can dispatch, however it was registered.

    ``ObsvrToolset`` governs the toolset it wraps, which is the whole story only
    when every tool lives in that toolset. It usually does not. An agent keeps
    its own function toolset for ``@agent.tool``, ``@agent.tool_plain`` and
    ``Agent(tools=[...])``, and PydanticAI combines that with the toolsets
    passed to ``Agent(toolsets=[...])`` as SIBLINGS — a combined toolset
    dispatches each call to the toolset that owns the tool, so a wrapper around
    one sibling never sees a call to another. Measured on a real agent graph
    with the tool denied: through ``Agent(toolsets=[ObsvrToolset(...)])`` it was
    refused, and the same policy against the same tool registered with
    ``@agent.tool`` executed it and returned its payload to the caller.

    This binds one level up, to the assembled toolset the agent hands its tool
    manager — the single object every tool call is dispatched through, whoever
    owns the tool. Registration style stops mattering, and so does the order
    tools were added: tools registered AFTER this call are governed too,
    because the tree is assembled per run and wrapped as it is assembled.

    The seam is feature-detected, not version-compared — forks, backports and
    vendored builds report whatever version they like. Where it is absent this
    raises rather than returning an agent that quietly governs nothing, and
    names the wrapper as the alternative.

    Idempotent. Returns the agent, so it reads as ``agent = govern_agent(agent)``.
    """
    if getattr(agent, _AGENT_GOVERNED_ATTR, False):
        return agent

    assemble = getattr(agent, "_get_toolset", None)
    if not callable(assemble):
        raise ImportError(
            "[obsvr] This PydanticAI build does not expose the toolset-assembly "
            "seam govern_agent() binds to (Agent._get_toolset). Wrap the "
            "toolset instead — obsvr.integrations.pydantic_ai.ObsvrToolset — "
            "and register every tool in it, or gate the tool's own callable "
            "with obsvr.govern_tool."
        )

    def governed_assemble(*args: Any, **kwargs: Any) -> Any:
        return ObsvrToolset(assemble(*args, **kwargs), **options)

    try:
        object.__setattr__(agent, "_get_toolset", governed_assemble)
        object.__setattr__(agent, _AGENT_GOVERNED_ATTR, True)
    except Exception as exc:  # noqa: BLE001 - a container that refuses the bind
        raise ImportError(
            "[obsvr] Could not bind the tool gate to this PydanticAI agent "
            f"({type(exc).__name__}). Wrap the toolset instead — "
            "obsvr.integrations.pydantic_ai.ObsvrToolset."
        ) from exc
    return agent
