"""LlamaIndex (Python) integration — observe-only callback handler.

Pairs CBEventType.LLM on_event_start/on_event_end by event_id using
EventPayload.PROMPT/MESSAGES/RESPONSE/COMPLETION payload keys.

REGISTRATION. ``obsvr.init()`` already adds this handler to
``Settings.callback_manager`` whenever ``llama_index`` is importable, so the
normal setup is init() alone — do not add it a second time. Adding it yourself
is harmless (the call is recorded once either way, see obsvr/dedupe.py) but
unnecessary. If you opted out with ``obsvr.init(auto=False)``, register it
manually::

    from llama_index.core import Settings
    from obsvr.integrations.llamaindex import ObsvrLlamaIndexHandler

    Settings.callback_manager.add_handler(ObsvrLlamaIndexHandler())

NO TOOL POLICY, AND THAT IS A DECISION RATHER THAN AN OMISSION. This integration
carries no tool allow/deny list, no step limit and no destructive-capability
gate. ``agent_policy`` has no effect here: nothing is refused and no policy event
is emitted, so an operator must not read this handler's events as evidence that a
tool was permitted by a gate.

It is a callback handler, and a callback handler is the wrong place for a gate —
that is the lesson the rest of this package paid for. Observability callbacks
fire around an operation, not at its boundary, so a check hung off one either
arrives too late to prevent anything or is never delivered at all. Adding a gate
here that could not refuse would produce exactly the false record this SDK now
goes out of its way not to emit.

**To govern LlamaIndex tools, gate the tools themselves.** The TypeScript SDK's
``obsvrGovernTool`` wraps a tool's own execute function and refuses before
delegating, which is the shape that works; it is verified enforcing. Python has
no equivalent yet, so on this side a LlamaIndex tool cannot be gated by obsvr
at all — put a capability that must be refused behind the MCP integration
instead, where the gate sits on ``call_tool``.

Pinned by ``tests/test_enforcement_reporting_invariant.py``, which fails if a
tool-policy helper appears in this module without the grading being updated.
"""

# Interception: LlamaIndex Python BaseCallbackHandler API (non-mutating). Register via Settings.callback_manager.add_handler() — no internals modified.

import time
from typing import Any, Dict, Optional

from .. import sender as _sender
from ..config import try_get_config
from ..events import emit_event, infer_provider_from_model
from ..deobfuscate import redact_for_storage
from ..policy import apply_observe_policy
from ..token_usage import read_token_usage
from ..dedupe import claim_emission

try:  # pragma: no cover - exercised only when llama-index-core is installed
    from llama_index.core.callbacks.base_handler import (  # type: ignore
        BaseCallbackHandler,
    )
except ImportError:  # shim base class so import never fails

    class BaseCallbackHandler:  # type: ignore
        def __init__(
            self, event_starts_to_ignore=None, event_ends_to_ignore=None
        ) -> None:
            self.event_starts_to_ignore = event_starts_to_ignore or []
            self.event_ends_to_ignore = event_ends_to_ignore or []


SOURCE = "llamaindex_py"


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
            if not _sender.should_sample(config.sample_rate):
                return event_id

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
