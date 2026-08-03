"""LlamaIndex (Python) integration — LLM audit handler plus a tool gate.

Two independent pieces, and they sit at different boundaries:

``ObsvrLlamaIndexHandler`` pairs CBEventType.LLM on_event_start/on_event_end by
event_id using EventPayload.PROMPT/MESSAGES/RESPONSE/COMPLETION payload keys. It
OBSERVES: it audits LLM traffic and applies the stored-copy PII policy, and it
refuses nothing.

``govern_agent(agent)`` is the tool gate, and it ENFORCES — a denied tool's body
is never entered.

REGISTRATION. ``obsvr.init()`` already adds the handler to
``Settings.callback_manager`` whenever ``llama_index`` is importable, so the
normal setup is init() alone — do not add it a second time. Adding it yourself
is harmless (the call is recorded once either way, see obsvr/dedupe.py) but
unnecessary. If you opted out with ``obsvr.init(auto=False)``, register it
manually::

    from llama_index.core import Settings
    from obsvr.integrations.llamaindex import ObsvrLlamaIndexHandler

    Settings.callback_manager.add_handler(ObsvrLlamaIndexHandler())

THE HANDLER CARRIES NO TOOL POLICY, AND CANNOT. ``agent_policy`` has no effect on
it: it refuses nothing and emits no policy event, so an operator must not read
its events as evidence that a tool was permitted by a gate.

That is not a design preference, it is the framework's shape. A callback fires
around an operation rather than at its boundary, so a check hung off one arrives
too late to prevent anything — and on this framework it does not arrive at all:
``CBEventType.FUNCTION_CALL`` has ZERO dispatch sites at llama-index-core
0.14.23 (the enum survives in ``callbacks/schema.py``; nothing raises it). The
newer instrumentation system is no better as a gate: every handler exception is
swallowed by ``Dispatcher`` (four ``except BaseException: pass`` blocks around
``handle``, ``span_enter``, ``span_drop`` and ``span_exit``), so a refusal raised
from a span handler is a no-op. Refusal has to live in the tool.

**So the gate is on the tools, and ``govern_agent`` is how it reaches all of
them.** See that function for what it binds to and why the tool LIST is not
enough.

Pinned by ``tests/test_enforcement_reporting_invariant.py``, which grades this
surface's gate against a driver modelling the framework's real ordering.
"""

# Interception: LlamaIndex Python BaseCallbackHandler API (non-mutating) for the
# audit handler. The tool gate replaces `get_tools` on one agent instance and the
# execute callables on the tools it hands back — no class is mutated.

import time
from typing import Any, Callable, Dict, List, Optional

from .. import sender as _sender
from ..binding_report import record_binding
from ..config import try_get_config
from ..events import emit_event, infer_provider_from_model
from ..deobfuscate import redact_for_storage
from ..policy import apply_observe_policy
from ..token_usage import read_token_usage
from ..dedupe import claim_emission
from .tools import govern_tool

try:  # pragma: no cover - exercised only when llama-index-core is installed
    from llama_index.core.callbacks.base_handler import (  # type: ignore
        BaseCallbackHandler,
    )

    record_binding(
        "llamaindex", "llama_index.core.callbacks.base_handler.BaseCallbackHandler"
    )
except ImportError as _exc:  # shim base class so import never fails
    record_binding(
        "llamaindex",
        "llama_index.core.callbacks.base_handler.BaseCallbackHandler",
        _exc,
    )

    class BaseCallbackHandler:  # type: ignore
        def __init__(
            self, event_starts_to_ignore=None, event_ends_to_ignore=None
        ) -> None:
            self.event_starts_to_ignore = event_starts_to_ignore or []
            self.event_ends_to_ignore = event_ends_to_ignore or []


SOURCE = "llamaindex_py"

#: LlamaIndex ``FunctionTool`` keeps the callable THREE times over, beside the
#: public ``call``/``acall`` pair the resolution table already finds: ``_fn``
#: (what ``call`` invokes), ``_async_fn`` (what ``acall`` invokes, a separate
#: closure over the original rather than a read of ``_fn``), and ``_real_fn``
#: (the undecorated function, which ``CodeActAgent`` hands to the model as a
#: name to call from generated Python — a route that never touches the tool
#: object at all). ``fn`` / ``async_fn`` / ``real_fn`` are read-only properties
#: over these three, so gating the private names gates the public reads too,
#: including ``to_langchain_tool``'s export. Non-FunctionTool shapes carry none
#: of them and skip the lot.
_LLAMAINDEX_FN_ATTRS = ("_fn", "_async_fn", "_real_fn")

#: The two halves this gate needs, probed by attribute presence rather than by
#: version string. ``get_tools`` is where an agent assembles the tools it will
#: offer and dispatch; ``_call_tool`` is the dispatch that consumes them. A
#: build carrying one without the other would take the install and never
#: consult it — the shape that shipped as a silent no-op on CrewAI.
_GATE_CAPABILITY_ATTRS = ("get_tools", "_call_tool")


def _enum_value(value: Any) -> Any:
    return getattr(value, "value", value)


def _payload_get(payload: Any, name: str) -> Any:
    """Get a payload entry keyed by an EventPayload enum OR a plain string."""
    if not isinstance(payload, dict):
        return None
    for key, value in payload.items():
        if key == name or _enum_value(key) == name:
            return value
    return None


def _get(obj: Any, key: str) -> Any:
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)


def _messages_to_prompt(messages: Any) -> str:
    lines = []
    for msg in messages or []:
        role = _get(msg, "role")
        role = str(_enum_value(role)) if role is not None else "unknown"
        content = _get(msg, "content")
        lines.append(f"{role}: {content if isinstance(content, str) else ''}")
    return "\n".join(lines)


def _last_user_text(messages: Any) -> Optional[str]:
    for msg in reversed(list(messages or [])):
        role = _get(msg, "role")
        role = str(_enum_value(role)) if role is not None else ""
        if role in ("user", "human"):
            content = _get(msg, "content")
            if isinstance(content, str):
                return content
    return None


def _extract_response_text(payload: Any) -> str:
    response = _payload_get(payload, "response")
    if response is not None:
        message = _get(response, "message")
        content = _get(message, "content")
        if isinstance(content, str):
            return content
        text = _get(response, "text")
        if isinstance(text, str):
            return text
        if isinstance(response, str):
            return response
        return str(response)
    completion = _payload_get(payload, "completion")
    if completion is not None:
        text = _get(completion, "text")
        if isinstance(text, str):
            return text
        if isinstance(completion, str):
            return completion
        return str(completion)
    return ""


def _raw_provider_response(payload: Any) -> Any:
    """The provider's own wire payload, which LlamaIndex keeps on
    ``response.raw``.

    This is the provider response itself rather than a LlamaIndex abstraction
    over it, so the model snapshot and the token counts can both be read from
    it with the same readers every other integration uses.
    """
    response = _payload_get(payload, "response")
    if response is None:
        return None
    return _get(response, "raw")


def _resolved_model(payload: Any) -> Optional[str]:
    """Provider-RESOLVED model snapshot. OpenAI puts the serving model on the
    raw response as ``model``, Gemini as ``model_version``/``modelVersion``."""
    raw = _raw_provider_response(payload)
    if raw is None:
        return None
    for key in ("model", "model_version", "modelVersion"):
        candidate = _get(raw, key)
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return None


def _extract_usage(payload: Any) -> Dict[str, Optional[int]]:
    """Token counts for a LlamaIndex LLM call.

    There was no token-reading code on this path at all — not a reader that
    broke, one that was never written — so LlamaIndex traffic could never be
    metered or counted against a token budget, at any version, in either
    language. The counts sit on the provider's raw response in its own wire
    format.
    """
    raw = _raw_provider_response(payload)
    if raw is None:
        return read_token_usage(None)
    for key in ("usage", "usage_metadata", "usageMetadata"):
        container = _get(raw, key)
        if container is not None:
            usage = read_token_usage(container)
            if any(v is not None for v in usage.values()):
                return usage
    return read_token_usage(None)


class ObsvrLlamaIndexHandler(BaseCallbackHandler):
    """Register on Settings.callback_manager to audit LLM events."""

    def __init__(self, **options: Any) -> None:
        try:
            super().__init__(event_starts_to_ignore=[], event_ends_to_ignore=[])
        except TypeError:
            pass
        self._runs: Dict[str, Dict[str, Any]] = {}
        self._options = options

    def on_event_start(
        self,
        event_type: Any,
        payload: Any = None,
        event_id: str = "",
        parent_id: str = "",
        **kwargs: Any,
    ) -> str:
        try:
            if _enum_value(event_type) != "llm":
                return event_id
            config = try_get_config()
            if config is None:
                return event_id
            # Sampling gates the EMISSION of clean allowed events, never the PII
            # scan. Returning here skipped apply_observe_policy below, so a
            # sub-1.0 sample_rate silently dropped the scan and the redaction of
            # the stored copy on a fraction of traffic. Carry the decision to the
            # emit site, the same posture wrap.py ``_emit_audit`` already takes.
            should_audit = _sender.should_sample(config.sample_rate)

            messages = _payload_get(payload, "messages")
            prompt = _payload_get(payload, "prompt")
            user_text: Optional[str] = None
            if isinstance(prompt, str) and prompt:
                prompt_text = prompt
            elif messages:
                prompt_text = _messages_to_prompt(messages)
                user_text = _last_user_text(messages)
            else:
                prompt_text = ""

            serialized = _payload_get(payload, "serialized")
            model = _get(serialized, "model")
            if not isinstance(model, str) or not model:
                model = "unknown"

            observed = apply_observe_policy(prompt_text, config)
            self._runs[event_id or "default"] = {
                "prompt": prompt_text,
                "user_text": user_text,
                "model": model,
                "start_time": time.time(),
                "compliance": observed["compliance"],
                "redact": observed["should_redact_stored"],
                # View-only hit: stored copies use a whole-text placeholder.
                "redact_via": observed.get("stored_redaction_via"),
                # Allowed: emit only when sampled in. Anything the scan acted on
                # is enforcement evidence and is always recorded.
                "audit_this_call": (
                    should_audit
                    or observed["compliance"].get("action_taken", "allowed") != "allowed"
                    or observed["compliance"].get("action_reason", "none") != "none"
                ),
            }
        except Exception:
            pass
        return event_id

    def on_event_end(
        self,
        event_type: Any,
        payload: Any = None,
        event_id: str = "",
        **kwargs: Any,
    ) -> None:
        try:
            if _enum_value(event_type) != "llm":
                return
            state = self._runs.pop(event_id or "default", None)
            if state is None:
                return
            # Sampled out and the scan found nothing: the run was still
            # governed, only this clean record is dropped.
            if not state.get("audit_this_call", True):
                return
            config = try_get_config()
            if config is None:
                return

            text = _extract_response_text(payload)
            prompt = state["prompt"]
            user_text = state["user_text"]
            if state["redact"]:
                via = state.get("redact_via")
                prompt = redact_for_storage(prompt, via)
                text = redact_for_storage(text, via)
                if user_text is not None:
                    user_text = redact_for_storage(user_text, via)

            # init() auto-wires a handler and a caller may register one too;
            # both then see this same event_id. Claiming it here records the
            # call exactly once however many handlers are attached — and,
            # unlike letting one handler win, it still records the call when a
            # caller REPLACES the callback manager obsvr wired into rather than
            # adding to it, which would otherwise emit nothing at all.
            if not claim_emission(f"llamaindex.llm:{event_id}" if event_id else None):
                return

            # The llm-start payload carries no model on newer llama-index-core,
            # so state["model"] is "unknown" at capture time and the provider
            # inferred from it was "unknown" too — every LlamaIndex call
            # unattributable in any per-provider report. The real model only
            # appears at llm-end on the provider's raw response.
            resolved = _resolved_model(payload)
            model = state["model"] if state["model"] != "unknown" else (resolved or "unknown")
            usage = _extract_usage(payload)
            # A backfilled model is the SERVED SNAPSHOT, not the configured
            # alias, because the llm-start payload carried none to record. Say
            # so rather than leaving a reader to infer it.
            alias_unavailable = state["model"] == "unknown" and model != "unknown"
            emit_event(
                config,
                provider=infer_provider_from_model(model),
                model=model,
                input_tokens=usage["input_tokens"],
                output_tokens=usage["output_tokens"],
                total_tokens=usage["total_tokens"],
                operation="llamaindex.llm",
                source=SOURCE,
                prompt=prompt,
                response=text,
                user_input=user_text,
                latency_ms=(time.time() - state["start_time"]) * 1000,
                metadata={"model_alias_unavailable": True} if alias_unavailable else None,
                compliance=state["compliance"],
                options=self._options or None,
            )
        except Exception:
            pass

    # Required abstract methods on the real base class — no-ops here.
    def start_trace(self, trace_id: Optional[str] = None) -> None:
        pass

    def end_trace(
        self,
        trace_id: Optional[str] = None,
        trace_map: Optional[Dict[str, Any]] = None,
    ) -> None:
        pass


# ---------------------------------------------------------------------------
# Tool gate
# ---------------------------------------------------------------------------


def _tool_name_of(tool: Any) -> Optional[str]:
    """The name this framework dispatches the tool under.

    ``get_tools`` consumers key on ``tool.metadata.name`` and the model is shown
    the same string, so that is the name a policy has to be written against.
    """
    metadata = getattr(tool, "metadata", None)
    for source in (
        getattr(metadata, "name", None),
        getattr(metadata, "get_name", None),
    ):
        if callable(source):
            try:
                source = source()
            except Exception:
                continue
        if isinstance(source, str) and source:
            return source
    return None


def _descriptor_fields(tool: Any) -> Dict[str, Any]:
    """Descriptor fields for the sealed tool-content digest.

    LlamaIndex keeps the description and the argument schema on the tool's
    ``metadata`` rather than on the tool, so the framework-agnostic reader finds
    neither and would seal a name-only digest.
    """
    metadata = getattr(tool, "metadata", None)
    descriptor: Dict[str, Any] = {}
    description = getattr(metadata, "description", None)
    if isinstance(description, str) and description:
        descriptor["description"] = description
    schema = getattr(metadata, "fn_schema", None)
    try:
        if schema is not None and hasattr(schema, "model_json_schema"):
            descriptor["inputSchema"] = schema.model_json_schema()
    except Exception:
        pass  # a missing schema beats a wrong one, same posture as the twin
    return descriptor


def _govern_llamaindex_tool(tool: Any, options: Dict[str, Any]) -> Any:
    """One tool, gated at every callable this framework can reach."""
    return govern_tool(
        tool,
        name=_tool_name_of(tool),
        extra_exec_attrs=_LLAMAINDEX_FN_ATTRS,
        descriptor=_descriptor_fields(tool),
        **options,
    )


def _supports_tool_gate(agent: Any) -> bool:
    return all(callable(getattr(agent, attr, None)) for attr in _GATE_CAPABILITY_ATTRS)


def govern_agent(agent: Any, **options: Any) -> Callable[[], None]:
    """Govern every tool this agent will dispatch, wherever the tool came from.

    Binds to the agent's ``get_tools`` — the point where a workflow agent
    ASSEMBLES the tools for a turn, and the only thing every dispatch on this
    framework crosses. ``BaseWorkflowAgent.get_tools`` and
    ``AgentWorkflow.get_tools`` are both consulted twice per turn, once to offer
    the tool list to the model and once to resolve the name the model picked, so
    a governed list is both what the model is shown and what the executor runs.

    GOVERNING THE TOOL LIST IS NOT ENOUGH, AND THAT IS WHY THIS EXISTS. An
    agent's tools do not all come from the ``tools=`` argument a caller can wrap
    by hand. Measured live, denied tool, one policy:

    - ``tool_retriever=`` supplies tools per turn from an object index; a
      wrapper applied to ``tools=`` never sees them, and the denied tool RAN.
    - in a multi-agent ``AgentWorkflow``, the handoff target's own tools are
      read straight off that agent; governing the agent the caller happens to
      hold left the worker's copy ungoverned, and the denied tool RAN and
      returned its payload.
    - a handoff tool is BUILT FRESH inside ``get_tools`` on every call, so it
      cannot be wrapped before the fact at all.

    Each of those is assembled inside ``get_tools`` and therefore governed here.

    Pass the object you run. For a single agent that is the ``FunctionAgent`` /
    ``ReActAgent`` / ``CodeActAgent``; for a multi-agent graph it is the
    ``AgentWorkflow``, whose own ``get_tools`` covers every member — its member
    agents are bound as well, so running one of them directly is governed too.

    NOT COVERED, stated rather than implied:

    - ``CodeActAgent``'s code path. The agent hands the model the raw functions
      by name and executes model-written Python through the caller's own
      ``code_execute_fn``; the tool objects are never invoked. The gate reaches
      ``real_fn``, so a denied tool called by name from generated code is still
      refused, but arbitrary generated code is not a tool call and no tool
      allow/deny list bounds it. Govern that sandbox, not this list.
    - tools invoked outside an agent — ``llm.predict_and_call(tools=[...])``,
      ``tools.calling.call_tool`` — which never consult ``get_tools``. Wrap
      those with ``obsvr.govern_tool`` at the call site; they dispatch on the
      tool object and the gate holds there (measured live).

    Returns an idempotent detach handle. Raises ``ImportError`` LOUDLY on an
    object that carries no ``get_tools``/``_call_tool`` pair, rather than
    installing a gate that is never consulted.
    """
    targets: List[Any] = [agent]
    members = getattr(agent, "agents", None)
    if isinstance(members, dict):
        # A multi-agent workflow reads each member's `tools` itself rather than
        # calling the member's `get_tools`, so the two are separate convergence
        # points and binding both double-gates nothing.
        targets.extend(members.values())

    unsupported = [t for t in targets if not _supports_tool_gate(t)]
    if unsupported:
        raise ImportError(
            "[obsvr] this llama-index build exposes no agent tool-assembly "
            f"seam to gate: {type(unsupported[0]).__name__} carries no "
            f"{'/'.join(_GATE_CAPABILITY_ATTRS)} pair. Refusing to install a "
            "gate that would never be consulted — wrap the tools themselves "
            "with obsvr.govern_tool instead."
        )

    restore: List[Any] = []

    # Wrapped per assembly rather than memoized. A handoff tool is rebuilt on
    # every `get_tools` call, so an identity-keyed cache would hold a strong
    # reference to a new object each turn and grow for the life of the run;
    # re-wrapping is a shallow copy and a few closures, and the governed-name
    # registry is a set that takes the repeat without noticing.
    def _govern_all(tools: Any) -> List[Any]:
        return [_govern_llamaindex_tool(tool, options) for tool in tools or []]

    for target in targets:
        original = target.get_tools

        async def _governed_get_tools(
            *args: Any, _original: Any = original, **kwargs: Any
        ) -> Any:
            return _govern_all(await _original(*args, **kwargs))

        object.__setattr__(target, "get_tools", _governed_get_tools)
        restore.append(target)

    detached = False

    def _detach() -> None:
        nonlocal detached
        if detached:
            return
        detached = True
        for target in restore:
            # Delete the shadowing instance attribute so the class method is
            # reached again, rather than pinning a bound method in __dict__.
            try:
                object.__delattr__(target, "get_tools")
            except Exception:
                pass

    return _detach
