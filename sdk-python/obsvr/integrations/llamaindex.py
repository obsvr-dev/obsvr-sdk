"""LlamaIndex (Python) integration — observe-only callback handler.

Pairs CBEventType.LLM on_event_start/on_event_end by event_id using
EventPayload.PROMPT/MESSAGES/RESPONSE/COMPLETION payload keys.

REGISTRATION. ``obsvr.init()`` already adds this handler to
``Settings.callback_manager`` whenever ``llama_index`` is importable, so the
normal setup is init() alone — do not add it a second time. Adding it yourself
is harmless (the duplicate is inert, see _claim_governing_handler) but
unnecessary. If you opted out with ``obsvr.init(auto=False)``, register it
manually::

    from llama_index.core import Settings
    from obsvr.integrations.llamaindex import ObsvrLlamaIndexHandler

    Settings.callback_manager.add_handler(ObsvrLlamaIndexHandler())
"""

# Interception: LlamaIndex Python BaseCallbackHandler API (non-mutating). Register via Settings.callback_manager.add_handler() — no internals modified.

import time
from typing import Any, Dict, Optional

from .. import sender as _sender
from ..config import try_get_config
from ..events import emit_event, infer_provider_from_string
from ..deobfuscate import redact_for_storage
from ..policy import apply_observe_policy

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

#: The handler that governs this process. See _claim_governing_handler.
_GOVERNING: Any = None


def _claim_governing_handler(handler: Any) -> bool:
    """Whether ``handler`` is the one that emits, or an inert duplicate.

    obsvr.init() auto-registers a handler on Settings.callback_manager whenever
    ``llama_index`` is importable, and this module's own docstring tells the
    reader to add one too — so following the documented setup put TWO handlers
    on the callback manager and emitted every LLM event twice, with distinct
    request_ids that made the pair look like two real calls. Duplicate evidence
    for one governed call is a defect in a governance product: it inflates any
    count taken over the trail, and now that tokens ARE captured on this path
    it would double every cost and quota figure derived from it.

    obsvr never mutates the callback manager it registers into, so it cannot
    remove the duplicate from the outside. The stance is the one
    instance_guard.py takes for a duplicated module: the incumbent keeps the
    slot and later arrivals are inert, so exactly one record is produced no
    matter how many times obsvr was registered or in what order.
    """
    global _GOVERNING
    if _GOVERNING is None:
        _GOVERNING = handler
    return _GOVERNING is handler


def _reset_governing_handler() -> None:
    """Test seam: forget the incumbent so each test starts clean."""
    global _GOVERNING
    _GOVERNING = None


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


class ObsvrLlamaIndexHandler(BaseCallbackHandler):
    """Register on Settings.callback_manager to audit LLM events."""

    def __init__(self, **options: Any) -> None:
        try:
            super().__init__(event_starts_to_ignore=[], event_ends_to_ignore=[])
        except TypeError:
            pass
        self._runs: Dict[str, Dict[str, Any]] = {}
        self._options = options
        self._governs = _claim_governing_handler(self)

    def on_event_start(
        self,
        event_type: Any,
        payload: Any = None,
        event_id: str = "",
        parent_id: str = "",
        **kwargs: Any,
    ) -> str:
        if not self._governs:
            return event_id
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
        if not self._governs:
            return
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

            emit_event(
                config,
                provider=infer_provider_from_string(state["model"]),
                model=state["model"],
                operation="llamaindex.llm",
                source=SOURCE,
                prompt=prompt,
                response=text,
                user_input=user_text,
                latency_ms=(time.time() - state["start_time"]) * 1000,
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
