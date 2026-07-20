"""PydanticAI integration — governance via a toolset wrapper.

PydanticAI runs every tool call through its toolset's ``call_tool`` method, and
ships ``WrapperToolset`` precisely so a toolset can be wrapped to intercept that
call. ``ObsvrToolset`` subclasses it (when PydanticAI is installed) and governs
each tool call before delegating:

- tool allow/deny (``agent_policy``),
- built-in PII scan + structured rules + the pre-call hook (HITL) on the tool
  arguments.

A block **raises** from ``call_tool`` — the wrapped toolset's ``call_tool`` is
never reached, so the tool never executes and the error propagates up through
the agent run (PydanticAI surfaces it as a tool failure). All other toolset
behavior (tool discovery, entering/exiting, name-conflict handling) is
inherited unchanged from ``WrapperToolset``.

Usage::

    from pydantic_ai import Agent
    from pydantic_ai.toolsets import FunctionToolset
    from obsvr.integrations.pydantic_ai import ObsvrToolset
    import obsvr

    obsvr.init(api_key="...", ingest_url="https://...",
               agent_policy={"denied_tools": ["shell_exec"]})
    tools = FunctionToolset([...])
    agent = Agent("openai:gpt-4o", toolsets=[ObsvrToolset(tools)])
"""

# Interception: PydanticAI WrapperToolset.call_tool override (non-mutating).
# The wrapped toolset is delegated to; a policy block raises before delegation,
# stopping the tool from ever executing.

import json
from typing import Any, Dict, Optional, Tuple

from ..config import try_get_config
from ..events import emit_event
from ..policy import apply_pre_call_policy, blocked_prompt_for_storage

SOURCE = "pydantic_ai"
PROVIDER = "pydantic_ai"

try:  # real base when PydanticAI is installed; a shim duck-types it otherwise
    from pydantic_ai.toolsets import WrapperToolset as _WrapperToolset  # type: ignore

    _HAS_PYDANTIC_AI = True
except Exception:  # pragma: no cover - PydanticAI not installed
    _HAS_PYDANTIC_AI = False

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


class ObsvrToolset(_WrapperToolset):  # type: ignore[misc]
    """Governing wrapper around any PydanticAI toolset.

    ``options`` may carry ``user_id`` / ``service_name`` / ``metadata`` (threaded
    into the rules-eval identity and attached to the audit as the principal).
    """

    def __init__(self, wrapped: Any, **options: Any) -> None:
        try:
            super().__init__(wrapped)
        except TypeError:  # pragma: no cover - shim path / alternate ctor
            object.__setattr__(self, "wrapped", wrapped)
        # object.__setattr__ so a frozen-dataclass base still accepts the field.
        object.__setattr__(self, "_obsvr_options", options)

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
                metadata={"tool_name": tool_name, "reason": reason}, options=opts,
            )
            raise PydanticAIToolBlockedError(
                f"[obsvr] Tool blocked by policy: {tool_name} ({reason})"
            )

        prompt_text = _args_prompt(tool_name, tool_args)
        result = apply_pre_call_policy(
            prompt_text, cfg, provider=PROVIDER, operation="pydantic_ai.tool.call",
            metadata=self._identity_meta(),
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

        emit_event(
            cfg, provider=PROVIDER, model="unknown", operation="pydantic_ai.tool.call",
            source=SOURCE, prompt=result["redacted_prompt"], response="",
            compliance=compliance, metadata={"tool_name": tool_name}, options=opts,
        )
        return await wrapped.call_tool(name, tool_args, *args, **kwargs)


def govern_toolset(toolset: Any, **options: Any) -> ObsvrToolset:
    """Convenience: wrap a toolset in an ``ObsvrToolset``."""
    return ObsvrToolset(toolset, **options)
