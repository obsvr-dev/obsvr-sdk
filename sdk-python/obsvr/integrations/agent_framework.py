"""Microsoft Agent Framework (MAF) integration — governing agent middleware.

MAF runs each agent invocation through a middleware chain: a middleware receives
an ``AgentContext`` and a ZERO-ARGUMENT ``call_next`` callable, and either awaits
``call_next()`` to proceed or short-circuits by not calling it. Short-circuiting
is the real block — the agent never runs — and the caller is handed whatever the
middleware left on ``context.result``.

``obsvr_agent_middleware`` (function middleware) and ``ObsvrAgentMiddleware``
(class middleware) both run the obsvr pre-call pipeline (built-in PII scan,
structured rules, the pre-call hook / HITL) on the run input BEFORE the agent
executes. On a BLOCK the middleware sets ``context.result`` to a blocked
``AgentResponse`` and returns without calling ``call_next``.

WHY THE PARAMETER ANNOTATIONS ARE LOAD-BEARING. MAF decides whether a callable
is agent middleware or function middleware by inspecting its FIRST PARAMETER'S
ANNOTATION NAME — ``categorize_middleware`` accepts a bare callable only if a
decorator left a ``_middleware_type`` marker or if
``first_param.annotation.__name__ == "AgentContext"``. Annotating the parameter
``Any`` matches neither, and categorization runs at AGENT CONSTRUCTION, so
``Agent(client=..., middleware=[...])`` raised before any call was made. The
annotations below are therefore part of the registration contract, not
documentation; do not relax them to ``Any``.

Usage::

    from agent_framework import Agent
    from obsvr.integrations.agent_framework import obsvr_agent_middleware
    import obsvr

    obsvr.init(api_key="...", ingest_url="https://...",
               pii_policy={"rules": {"ssn": "block"}})
    agent = Agent(client=..., middleware=[obsvr_agent_middleware])
"""

# Interception: MAF agent middleware (non-mutating). Registered through MAF's
# official middleware chain; a block short-circuits the chain by not invoking
# call_next() and leaving a blocked result on the context, so the agent never
# executes. Nothing MAF owns is patched — the class middleware subclasses MAF's
# own published AgentMiddleware base.

import time
from typing import Any, Awaitable, Callable, Dict, Optional

from ..config import try_get_config
from ..events import emit_event
from ..policy import apply_pre_call_policy, blocked_prompt_for_storage, blocked_user_input_for_storage
from ..binding_report import record_binding

# Each symbol is bound in its OWN try block. They used to share one, so a single
# upstream rename nulled all of them together — the framework renamed two names
# at its 1.0 GA and the third, which still exists, was lost as collateral. A
# per-symbol bind makes the next such rename partial instead of total.
#
# The GA names are tried first and the pre-GA (1.0.0b*) spellings second, so a
# caller still on a prerelease keeps working without the GA path paying for it.

try:  # renamed from AgentRunResponse at the 1.0 GA
    from agent_framework import AgentResponse as _AgentResponse  # type: ignore

    record_binding("agent_framework", "AgentResponse")
except Exception:  # pragma: no cover - MAF absent or pre-GA
    try:
        from agent_framework import AgentRunResponse as _AgentResponse  # type: ignore

        record_binding("agent_framework", "AgentRunResponse (pre-GA)")
    except Exception as _exc:
        _AgentResponse = None  # type: ignore
        record_binding("agent_framework", "AgentResponse", _exc)

try:  # renamed from ChatMessage at the 1.0 GA
    from agent_framework import Message as _Message  # type: ignore

    record_binding("agent_framework", "Message")
except Exception:  # pragma: no cover - MAF absent or pre-GA
    try:
        from agent_framework import ChatMessage as _Message  # type: ignore

        record_binding("agent_framework", "ChatMessage (pre-GA)")
    except Exception as _exc:
        _Message = None  # type: ignore
        record_binding("agent_framework", "Message", _exc)

try:
    from agent_framework import AgentContext as _MafAgentContext  # type: ignore

    record_binding("agent_framework", "AgentContext")
except Exception as _exc:  # pragma: no cover - MAF not installed
    _MafAgentContext = None  # type: ignore
    record_binding("agent_framework", "AgentContext", _exc)

try:
    from agent_framework import AgentMiddleware as _MafAgentMiddleware  # type: ignore

    record_binding("agent_framework", "AgentMiddleware")
except Exception as _exc:  # pragma: no cover - MAF not installed
    _MafAgentMiddleware = None  # type: ignore
    record_binding("agent_framework", "AgentMiddleware", _exc)

#: Why each optional bind failed, for diagnostics. A bare False flag cannot tell
#: an absent package from a renamed symbol from a broken transitive dependency,
#: and those need different fixes.
_HAS_MAF = _AgentResponse is not None and _Message is not None

# `Role` is deliberately NOT imported. It is a NewType over str rather than an
# enum, so `Role.ASSISTANT` does not exist and a message role is just the string
# "assistant".


class _AgentContextPlaceholder:
    """Stand-in used only for the parameter annotation when MAF is absent.

    MAF's classifier compares the annotation's ``__name__`` STRING, not class
    identity, so a class of this name satisfies it. That keeps the annotations
    honest with zero import-time dependency on MAF: with the package installed
    the real type is used, and without it the module still imports.
    """


AgentContext = _MafAgentContext if _MafAgentContext is not None else _AgentContextPlaceholder
if _MafAgentContext is None:
    _AgentContextPlaceholder.__name__ = "AgentContext"

#: MAF's own next-handler type: zero arguments. Passing the context to it raises
#: TypeError, which used to fire on every ALLOWED run.
NextHandler = Callable[[], Awaitable[None]]

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
    """Return (full_prompt, last_user_text) from an AgentContext."""
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
    """A blocked result in the shape MAF's contract promises the caller.

    ``Message`` takes (role, contents) positionally; it has no ``text=``
    constructor keyword — ``text`` is a read-only property computed from
    ``contents``. Passing it raised TypeError, so even with the class names
    corrected the block path would have failed here.
    """
    if _AgentResponse is not None and _Message is not None:
        try:
            return _AgentResponse(messages=[_Message("assistant", [message])])
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


async def _govern(context: Any, options: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Run the pre-call pipeline.

    Returns None if BLOCKED (the caller must not proceed; the blocked event is
    emitted here and ``context.result`` is set). Otherwise returns the pending
    record the post-run emit needs.
    """
    cfg = try_get_config()
    if cfg is None:
        return None
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
        # The block IS "return without awaiting call_next" — the chain stops and
        # the agent never runs. There is no `terminate` flag on AgentContext;
        # writing one silently created an attribute MAF never reads, which made
        # the block look deliberate when it was working by accident.
        try:
            context.result = _blocked_response("[obsvr] Agent run blocked by policy")
        except Exception:
            pass
        return None

    # NOT emitted here. The allowed-path event used to fire at this point with
    # response="" and no latency, which meant the record asserted success
    # BEFORE the agent ran: a run that raised afterwards was filed as having
    # succeeded, and the response was never captured at all. The verdict is
    # carried out to _run_governed and the event is emitted once the outcome
    # exists. The BLOCK above still emits here, correctly — there the outcome
    # is known, because the agent never runs.
    return {
        "cfg": cfg,
        "prompt": result["redacted_prompt"],
        "user_input": user_text,
        "compliance": compliance,
        "options": opts,
        "started": time.perf_counter(),
    }


def _result_text(context: Any) -> str:
    """The agent's own output, read off the context after the run.

    Defensive across MAF versions on purpose: this runs in the post-run path,
    so a shape it does not recognise must cost the response text and nothing
    else — never the event.
    """
    result = getattr(context, "result", None)
    if result is None:
        return ""
    try:
        msgs = getattr(result, "messages", None)
        if isinstance(msgs, (list, tuple)) and msgs:
            return _message_text(msgs[-1])
        text = getattr(result, "text", None)
        if isinstance(text, str):
            return text
        if isinstance(result, dict):
            return str(result.get("text") or "")
        return str(result)
    except Exception:  # pragma: no cover - defensive
        return ""


async def _run_governed(
    context: Any, call_next: NextHandler, options: Dict[str, Any]
) -> None:
    """Govern, run, then record what actually happened.

    One event per run, emitted AFTER the outcome exists. A run that raises is
    recorded as a failure rather than left with the success the old pre-call
    emit had already asserted, and the exception still propagates — obsvr
    reports the outcome, it does not swallow it.
    """
    pending = await _govern(context, options)
    if pending is None:
        return  # blocked: the agent never runs, and _govern already recorded it

    try:
        await call_next()
    except Exception as exc:
        _emit_run(pending, context, success=False, error=exc)
        raise
    _emit_run(pending, context, success=True, error=None)


def _emit_run(
    pending: Dict[str, Any], context: Any, *, success: bool, error: Any
) -> None:
    emit_event(
        pending["cfg"],
        provider=PROVIDER,
        model="unknown",
        operation="agent_framework.agent.run",
        source=SOURCE,
        prompt=pending["prompt"],
        response=_result_text(context) if success else "",
        user_input=pending["user_input"],
        success=success,
        error=error,
        latency_ms=int((time.perf_counter() - pending["started"]) * 1000),
        compliance=pending["compliance"],
        options=pending["options"],
    )


async def obsvr_agent_middleware(context: AgentContext, call_next: NextHandler) -> None:
    """Function-style MAF agent middleware. Governs the run pre-execution."""
    await _run_governed(context, call_next, {})


def make_agent_middleware(**options: Any) -> Callable[..., Awaitable[None]]:
    """Build a function middleware bound to caller-identity ``options``."""

    async def middleware(context: AgentContext, call_next: NextHandler) -> None:
        await _run_governed(context, call_next, options)

    return middleware


# Subclassing MAF's published base is what routes this through
# categorize_middleware's isinstance branch, which never inspects __name__.
# Without a real base the classifier fell through to the bare-callable path and
# raised AttributeError on an instance that has no __name__.
_MiddlewareBase: Any = _MafAgentMiddleware if _MafAgentMiddleware is not None else object


class ObsvrAgentMiddleware(_MiddlewareBase):
    """Class-style MAF agent middleware (``async def process(context, call_next)``).

    No ``__call__`` passthrough: defining one makes the INSTANCE callable, which
    sent it down the bare-callable classification path and produced an
    AttributeError about a missing ``__name__`` instead of registering.
    """

    def __init__(self, **options: Any) -> None:
        self._options = options

    async def process(self, context: AgentContext, call_next: NextHandler) -> None:
        await _run_governed(context, call_next, self._options)
