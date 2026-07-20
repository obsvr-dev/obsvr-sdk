"""smolagents integration — governs tool execution.

A smolagents ``CodeAgent`` / ``ToolCallingAgent`` executes a tool by calling the
tool object (``tool(**kwargs)`` -> ``Tool.__call__`` -> ``Tool.forward``).
``govern_tool`` returns a wrapper that duck-types the smolagents ``Tool``
interface (``name`` / ``description`` / ``inputs`` / ``output_type``) and
intercepts ``__call__``:

- tool allow/deny (``agent_policy``),
- built-in PII scan + structured rules + the pre-call hook (HITL) on the tool
  arguments.

A block **raises** before the wrapped tool is called, so the tool body never
runs. ``govern_agent`` wraps every tool held by an agent in place, so the whole
agent is governed with one call.

Usage::

    from smolagents import CodeAgent
    from obsvr.integrations.smolagents import govern_agent
    import obsvr

    obsvr.init(api_key="...", ingest_url="https://...",
               agent_policy={"denied_tools": ["python_interpreter"]})
    agent = CodeAgent(tools=[...], model=...)
    govern_agent(agent)   # every tool call is now policy-checked and audited
"""

# Interception: tool-call wrapper (non-mutating on the tool object). The wrapped
# Tool is delegated to via __call__; a policy block raises before delegation so
# the tool never executes.

import json
from typing import Any, Dict, Optional, Tuple

from ..config import try_get_config
from ..events import emit_event
from ..policy import apply_pre_call_policy, blocked_prompt_for_storage

try:  # real Tool reference when smolagents is installed
    from smolagents import Tool as _SmolTool  # type: ignore  # noqa: F401

    _HAS_SMOLAGENTS = True
except Exception:  # pragma: no cover - smolagents not installed
    _SmolTool = None  # type: ignore
    _HAS_SMOLAGENTS = False

SOURCE = "smolagents"
PROVIDER = "smolagents"
_WRAPPED_ATTR = "_obsvr_smol_wrapped"


class SmolagentsToolBlockedError(RuntimeError):
    """Raised when a tool call is blocked by policy (denylist/allowlist/PII/hook)."""


def _check_tool(tool_name: str, policy: Dict[str, Any]) -> Tuple[bool, str]:
    denied = policy.get("denied_tools") or []
    allowed = policy.get("allowed_tools")
    if tool_name in denied:
        return False, "tool_denied"
    if allowed is not None and tool_name not in allowed:
        return False, "tool_not_in_allowlist"
    return True, ""


def _call_prompt(tool_name: str, args: Any, kwargs: Dict[str, Any]) -> str:
    try:
        payload: Dict[str, Any] = dict(kwargs)
        if args:
            payload["_args"] = list(args)
        return f"{tool_name}({json.dumps(payload, default=str)})"
    except Exception:
        return f"{tool_name}(...)"


class ObsvrGovernedTool:
    """Delegating governance wrapper around a smolagents Tool."""

    def __init__(self, tool: Any, **options: Any) -> None:
        object.__setattr__(self, "_wrapped", tool)
        object.__setattr__(self, "_options", options or {})
        # Mirror the Tool metadata so the agent treats this like the real tool.
        for attr in ("name", "description", "inputs", "output_type"):
            if hasattr(tool, attr):
                object.__setattr__(self, attr, getattr(tool, attr))
        object.__setattr__(self, _WRAPPED_ATTR, True)

    def __getattr__(self, item: str) -> Any:
        return getattr(object.__getattribute__(self, "_wrapped"), item)

    def _identity_meta(self) -> Optional[Dict[str, Any]]:
        opts = object.__getattribute__(self, "_options")
        meta = dict(opts.get("metadata") or {})
        if opts.get("user_id") is not None:
            meta["user_id"] = opts["user_id"]
        if opts.get("service_name") is not None:
            meta["service_name"] = opts["service_name"]
        return meta or None

    def _govern(self, args: Any, kwargs: Dict[str, Any]) -> None:
        cfg = try_get_config()
        if cfg is None:
            return
        wrapped = object.__getattribute__(self, "_wrapped")
        opts = object.__getattribute__(self, "_options") or None
        tool_name = str(getattr(wrapped, "name", None) or "unknown")
        policy = getattr(cfg, "agent_policy", None) or {}

        ok, reason = _check_tool(tool_name, policy)
        if not ok:
            emit_event(
                cfg, provider=PROVIDER, model="unknown",
                operation="smolagents.tool.policy.tool_blocked", source=SOURCE,
                prompt="", response="", success=False, status_code=403,
                metadata={"tool_name": tool_name, "reason": reason}, options=opts,
            )
            raise SmolagentsToolBlockedError(
                f"[obsvr] Tool blocked by policy: {tool_name} ({reason})"
            )

        prompt_text = _call_prompt(tool_name, args, kwargs)
        result = apply_pre_call_policy(
            prompt_text, cfg, provider=PROVIDER, operation="smolagents.tool.call",
            metadata=self._identity_meta(),
        )
        compliance = result["compliance"]
        if result["decision"] == "block":
            emit_event(
                cfg, provider=PROVIDER, model="unknown", operation="smolagents.tool.call",
                source=SOURCE,
                prompt=blocked_prompt_for_storage(
                    prompt_text, compliance, result.get("security_normalized")
                ),
                response="", success=False, status_code=403, compliance=compliance,
                metadata={"tool_name": tool_name}, options=opts,
            )
            raise SmolagentsToolBlockedError(
                f"[obsvr] Tool call blocked by policy: {tool_name}"
            )

        emit_event(
            cfg, provider=PROVIDER, model="unknown", operation="smolagents.tool.call",
            source=SOURCE, prompt=result["redacted_prompt"], response="",
            compliance=compliance, metadata={"tool_name": tool_name}, options=opts,
        )

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        self._govern(args, kwargs)
        return object.__getattribute__(self, "_wrapped")(*args, **kwargs)

    def forward(self, *args: Any, **kwargs: Any) -> Any:
        self._govern(args, kwargs)
        return object.__getattribute__(self, "_wrapped").forward(*args, **kwargs)


def govern_tool(tool: Any, **options: Any) -> Any:
    """Wrap a single smolagents Tool for governance. Idempotent."""
    if getattr(tool, _WRAPPED_ATTR, False):
        return tool
    return ObsvrGovernedTool(tool, **options)


def govern_agent(agent: Any, **options: Any) -> Any:
    """Wrap every tool held by a smolagents agent in place. Returns the agent.

    smolagents keeps tools in ``agent.tools`` (a name -> Tool dict). Each tool is
    replaced with a governed wrapper, so the agent's own execution path invokes
    obsvr governance with no further changes.
    """
    tools = getattr(agent, "tools", None)
    if isinstance(tools, dict):
        for key, tool in list(tools.items()):
            tools[key] = govern_tool(tool, **options)
    elif isinstance(tools, list):
        agent.tools = [govern_tool(t, **options) for t in tools]
    return agent
