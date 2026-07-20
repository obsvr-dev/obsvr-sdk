"""Google ADK (Agent Development Kit) integration — governance via callbacks.

ADK exposes first-class callback hooks on ``Agent`` / ``LlmAgent``:

- ``before_tool_callback(tool, args, tool_context)`` — returning a **dict**
  makes ADK use that dict as the tool result and SKIP the tool entirely. That
  is a real, enforceable block: the tool body never runs.
- ``before_model_callback(callback_context, llm_request)`` — returning an
  ``LlmResponse`` short-circuits the model call; the request never leaves.
- ``before_agent_callback(callback_context)`` — returning ``types.Content``
  skips the agent invocation.

This integration builds those callbacks. Enforcement runs the same obsvr
pipeline as every other integration (tool allow/deny, built-in PII scan,
structured rules, and the pre-call hook / HITL).

Deliberately SYNCHRONOUS: ADK awaits a callback's return value only when it is
a coroutine, so a plain sync callback returning a value (dict / LlmResponse /
None) is handled correctly on both ADK's sync and async execution paths — with
no event-loop bridge to get wrong. The enforcement decision is pure and
deterministic (audit delivery is fire-and-forget off-thread), so there is
nothing to await.

Usage::

    from google.adk.agents import Agent
    from obsvr.integrations.adk import (
        make_before_tool_callback,
        make_before_model_callback,
    )
    import obsvr

    obsvr.init(api_key="...", ingest_url="https://...",
               agent_policy={"denied_tools": ["delete_database"]})
    agent = Agent(
        name="assistant",
        model="gemini-2.0-flash",
        tools=[...],
        before_tool_callback=make_before_tool_callback(),
        before_model_callback=make_before_model_callback(),
    )
"""

# Interception: ADK before_tool_callback / before_model_callback / before_agent_callback
# (non-mutating). Registered through ADK's official callback constructor args;
# a block short-circuits execution via the framework's documented contract
# (dict result for tools, LlmResponse for the model).

import json
import uuid
from typing import Any, Callable, Dict, Optional, Tuple

from ..config import try_get_config
from ..events import emit_event
from ..policy import apply_pre_call_policy, blocked_prompt_for_storage, blocked_user_input_for_storage

try:  # real LlmResponse when ADK is installed; a dict short-circuits otherwise
    from google.adk.models import LlmResponse as _LlmResponse  # type: ignore
except Exception:  # pragma: no cover - ADK not installed
    _LlmResponse = None  # type: ignore

try:
    from google.genai import types as _genai_types  # type: ignore
except Exception:  # pragma: no cover
    _genai_types = None  # type: ignore

SOURCE = "google_adk"
PROVIDER = "adk"


def _check_tool(tool_name: str, policy: Dict[str, Any]) -> Tuple[bool, str]:
    denied = policy.get("denied_tools") or []
    allowed = policy.get("allowed_tools")
    if tool_name in denied:
        return False, "tool_denied"
    if allowed is not None and tool_name not in allowed:
        return False, "tool_not_in_allowlist"
    return True, ""


def _tool_name(tool: Any) -> str:
    name = getattr(tool, "name", None)
    if not name and isinstance(tool, dict):
        name = tool.get("name")
    return str(name or "unknown")


def _args_prompt(tool_name: str, args: Any) -> str:
    try:
        return f"{tool_name}({json.dumps(args or {}, default=str)})"
    except Exception:
        return f"{tool_name}(...)"


def _llm_request_text(llm_request: Any) -> Tuple[str, str]:
    """Return (full_prompt, last_user_text) from an ADK LlmRequest."""
    contents = getattr(llm_request, "contents", None)
    if contents is None and isinstance(llm_request, dict):
        contents = llm_request.get("contents")
    if not isinstance(contents, list):
        return "", ""
    lines = []
    last_user = ""
    for c in contents:
        role = getattr(c, "role", None) or (c.get("role") if isinstance(c, dict) else None) or "user"
        parts = getattr(c, "parts", None) or (c.get("parts") if isinstance(c, dict) else None) or []
        text = "\n".join(
            (getattr(p, "text", None) or (p.get("text") if isinstance(p, dict) else None) or "")
            for p in parts
        ).strip()
        lines.append(f"{role}: {text}")
        if role in ("user", "human") and text:
            last_user = text
    return "\n".join(lines), last_user


def _identity_meta(options: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    meta = dict(options.get("metadata") or {})
    if options.get("user_id") is not None:
        meta["user_id"] = options["user_id"]
    if options.get("service_name") is not None:
        meta["service_name"] = options["service_name"]
    return meta or None


def _blocked_llm_response(message: str) -> Any:
    """Build a short-circuit LlmResponse (real when ADK present, else a dict)."""
    if _LlmResponse is not None and _genai_types is not None:
        try:
            return _LlmResponse(
                content=_genai_types.Content(
                    role="model", parts=[_genai_types.Part(text=message)]
                )
            )
        except Exception:  # pragma: no cover - defensive across ADK versions
            pass
    return {"obsvr_blocked": True, "content": message}


# ---------------------------------------------------------------------------
# before_tool_callback — the strongest control (skips the tool body)
# ---------------------------------------------------------------------------


def make_before_tool_callback(**options: Any) -> Callable[[Any, Any, Any], Optional[Dict[str, Any]]]:
    """Return a ``before_tool_callback``. Returns a dict (blocked result) to
    stop a tool, or ``None`` to let ADK execute it."""

    def before_tool_callback(tool: Any, args: Any, tool_context: Any = None) -> Optional[Dict[str, Any]]:
        cfg = try_get_config()
        if cfg is None:
            return None
        opts = options or None
        tool_name = _tool_name(tool)
        policy = getattr(cfg, "agent_policy", None) or {}

        ok, reason = _check_tool(tool_name, policy)
        if not ok:
            emit_event(
                cfg, provider=PROVIDER, model="unknown",
                operation="adk.tool.policy.tool_blocked", source=SOURCE,
                prompt="", response="", success=False, status_code=403,
                metadata={"tool_name": tool_name, "reason": reason}, options=opts,
            )
            return {"obsvr_blocked": True, "error": f"Tool '{tool_name}' blocked by policy: {reason}"}

        prompt_text = _args_prompt(tool_name, args)
        result = apply_pre_call_policy(
            prompt_text, cfg, provider=PROVIDER, operation="adk.tool.call",
            metadata=_identity_meta(options),
        )
        compliance = result["compliance"]
        if result["decision"] == "block":
            emit_event(
                cfg, provider=PROVIDER, model="unknown", operation="adk.tool.call",
                source=SOURCE,
                prompt=blocked_prompt_for_storage(
                    prompt_text, compliance, result.get("security_normalized")
                ),
                response="", success=False, status_code=403, compliance=compliance,
                metadata={"tool_name": tool_name}, options=opts,
            )
            return {"obsvr_blocked": True, "error": f"Tool '{tool_name}' call blocked by policy"}

        emit_event(
            cfg, provider=PROVIDER, model="unknown", operation="adk.tool.call",
            source=SOURCE, prompt=result["redacted_prompt"], response="",
            compliance=compliance, metadata={"tool_name": tool_name}, options=opts,
        )
        return None  # ADK proceeds to run the tool

    return before_tool_callback


# ---------------------------------------------------------------------------
# before_model_callback — governs the LLM request before it leaves
# ---------------------------------------------------------------------------


def make_before_model_callback(**options: Any) -> Callable[[Any, Any], Any]:
    """Return a ``before_model_callback``. Returns an LlmResponse (blocked) to
    short-circuit the model call, or ``None`` to proceed."""

    def before_model_callback(callback_context: Any, llm_request: Any = None) -> Any:
        cfg = try_get_config()
        if cfg is None:
            return None
        opts = options or None
        prompt_text, user_text = _llm_request_text(llm_request)
        result = apply_pre_call_policy(
            prompt_text, cfg, provider=PROVIDER, operation="adk.model.request",
            scan_text=user_text or prompt_text, metadata=_identity_meta(options),
        )
        compliance = result["compliance"]
        if result["decision"] == "block":
            emit_event(
                cfg, provider=PROVIDER, model="unknown", operation="adk.model.request",
                source=SOURCE,
                prompt=blocked_prompt_for_storage(
                    prompt_text, compliance, result.get("security_normalized")
                ),
                response="",
                user_input=blocked_user_input_for_storage(user_text, result),
                success=False,
                status_code=403, compliance=compliance, options=opts,
            )
            return _blocked_llm_response("[obsvr] Request blocked by policy")

        emit_event(
            cfg, provider=PROVIDER, model="unknown", operation="adk.model.request",
            source=SOURCE, prompt=result["redacted_prompt"], response="",
            user_input=user_text, compliance=compliance, options=opts,
        )
        return None

    return before_model_callback


# ---------------------------------------------------------------------------
# before_agent_callback — run-level start marker
# ---------------------------------------------------------------------------


def make_before_agent_callback(**options: Any) -> Callable[[Any], Any]:
    """Return a ``before_agent_callback`` that emits a run-start audit event.
    Always returns ``None`` (never skips the agent)."""

    def before_agent_callback(callback_context: Any = None) -> Any:
        cfg = try_get_config()
        if cfg is None:
            return None
        emit_event(
            cfg, provider=PROVIDER, model="unknown", operation="adk.agent.run.start",
            source=SOURCE, prompt="", response="",
            metadata={"agent_run_id": str(uuid.uuid4())}, options=options or None,
        )
        return None

    return before_agent_callback
