"""Microsoft Agent Framework (MAF) integration — governing agent middleware.

MAF runs each agent invocation through a middleware chain: a middleware receives
an ``AgentRunContext`` and a ``next`` callable, and either calls ``await
next(context)`` to proceed or short-circuits. The real termination mechanism is
``context.terminate = True`` combined with NOT calling ``next`` — obsvr uses
exactly that.

``obsvr_agent_middleware`` (function middleware) and ``ObsvrAgentMiddleware``
(class middleware) both run the obsvr pre-call pipeline (built-in PII scan,
structured rules, the pre-call hook / HITL) on the run input BEFORE the agent
executes. On a BLOCK the middleware sets ``context.terminate = True``, sets a
blocked result, and returns without calling ``next`` — the agent never runs.

Usage::

    from agent_framework import ChatAgent
    from obsvr.integrations.agent_framework import obsvr_agent_middleware
    import obsvr

    obsvr.init(api_key="...", ingest_url="https://...",
               pii_policy={"rules": {"ssn": "block"}})
    agent = ChatAgent(chat_client=..., middleware=[obsvr_agent_middleware])
"""

# Interception: MAF agent middleware (non-mutating). Registered through MAF's
# official middleware chain; a block terminates the run via context.terminate
# without invoking next(), so the agent never executes.

from typing import Any, Awaitable, Callable, Dict, Optional

from ..config import try_get_config
from ..events import emit_event
from ..deobfuscate import redact_for_storage
from ..policy import apply_pre_call_policy, blocked_prompt_for_storage, blocked_user_input_for_storage

try:  # real result type when MAF is installed; a marker is used otherwise
    from agent_framework import AgentRunResponse as _AgentRunResponse  # type: ignore
    from agent_framework import ChatMessage as _ChatMessage  # type: ignore
    from agent_framework import Role as _Role  # type: ignore

    _HAS_MAF = True
except Exception:  # pragma: no cover - MAF not installed
    _AgentRunResponse = None  # type: ignore
    _ChatMessage = None  # type: ignore
    _Role = None  # type: ignore
    _HAS_MAF = False

SOURCE = "microsoft_agent_framework"
PROVIDER = "agent_framework"


def _message_text(m: Any) -> str:
    text = getattr(m, "text", None)
    if isinstance(text, str) and text:
        return text
    contents = getattr(m, "contents", None) or []
    parts = [getattr(c, "text", None) for c in contents]
    return "\n".join(p for p in parts if isinstance(p, str) and p)


def _input_text(context: Any) -> tuple:
    """Return (full_prompt, last_user_text) from an AgentRunContext."""
    msgs = getattr(context, "messages", None)
    if msgs is None:
        msgs = getattr(context, "input_messages", None)
    if not isinstance(msgs, (list, tuple)):
        return "", ""
    lines = []
    last_user = ""
    for m in msgs:
        role_l = str(getattr(m, "role", None) or "user").lower()
        text = _message_text(m)
        lines.append(f"{role_l}: {text}")
        if ("user" in role_l or "human" in role_l) and text:
            last_user = text
    return "\n".join(lines), last_user


def _blocked_response(message: str) -> Any:
    if _AgentRunResponse is not None and _ChatMessage is not None and _Role is not None:
        try:
            return _AgentRunResponse(messages=[_ChatMessage(role=_Role.ASSISTANT, text=message)])
        except Exception:  # pragma: no cover - defensive across MAF versions
            pass
    return {"obsvr_blocked": True, "text": message}


def _identity_meta(options: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    meta = dict(options.get("metadata") or {})
    if options.get("user_id") is not None:
        meta["user_id"] = options["user_id"]
    if options.get("service_name") is not None:
        meta["service_name"] = options["service_name"]
    return meta or None


async def _govern(context: Any, options: Dict[str, Any]) -> bool:
    """Run the pre-call pipeline. Returns True if BLOCKED (caller must not
    proceed); False to proceed. Sets context.terminate / context.result on block."""
    cfg = try_get_config()
    if cfg is None:
        return False
    opts = options or None
    prompt_text, user_text = _input_text(context)
    result = apply_pre_call_policy(
        prompt_text, cfg, provider=PROVIDER, operation="agent_framework.agent.run",
        scan_text=user_text or prompt_text, metadata=_identity_meta(options),
    )
    compliance = result["compliance"]
    if result["decision"] == "block":
        emit_event(
            cfg, provider=PROVIDER, model="unknown", operation="agent_framework.agent.run",
            source=SOURCE,
            prompt=blocked_prompt_for_storage(
                prompt_text, compliance, result.get("security_normalized")
            ),
            response="",
            user_input=blocked_user_input_for_storage(user_text, result),
            success=False,
            status_code=403, compliance=compliance, options=opts,
        )
        # MiddlewareTermination: stop the chain and hand back a blocked result.
        try:
            context.terminate = True
        except Exception:
            pass
        try:
            context.result = _blocked_response("[obsvr] Agent run blocked by policy")
        except Exception:
            pass
        return True

    emit_event(
        cfg, provider=PROVIDER, model="unknown", operation="agent_framework.agent.run",
        source=SOURCE, prompt=result["redacted_prompt"], response="",
        user_input=user_text, compliance=compliance, options=opts,
    )
    return False


async def obsvr_agent_middleware(
    context: Any, next: Callable[[Any], Awaitable[None]]
) -> None:
    """Function-style MAF agent middleware. Governs the run pre-execution."""
    blocked = await _govern(context, {})
    if blocked:
        return  # terminate: do NOT call next -> the agent never runs
    await next(context)


def make_agent_middleware(**options: Any) -> Callable[[Any, Callable[[Any], Awaitable[None]]], Awaitable[None]]:
    """Build a function middleware bound to caller-identity ``options``."""

    async def middleware(context: Any, next: Callable[[Any], Awaitable[None]]) -> None:
        blocked = await _govern(context, options)
        if blocked:
            return
        await next(context)

    return middleware


class ObsvrAgentMiddleware:
    """Class-style MAF agent middleware (``async def process(context, next)``)."""

    def __init__(self, **options: Any) -> None:
        self._options = options

    async def process(self, context: Any, next: Callable[[Any], Awaitable[None]]) -> None:
        blocked = await _govern(context, self._options)
        if blocked:
            return
        await next(context)

    # Some MAF versions invoke middleware objects directly.
    async def __call__(self, context: Any, next: Callable[[Any], Awaitable[None]]) -> None:
        await self.process(context, next)
