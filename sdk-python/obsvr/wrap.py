"""obsvr.wrap(client) - transparent client interception for Python.

Parity with sdk-typescript/src/proxy/wrapper.ts: a recursive attribute proxy walks the
client object; when an auditable method path is reached the call is routed
through the full governance pipeline:

    pii scan -> policy rules -> pre-call hook (fail_mode honored)
    -> provider call -> post-call policy -> signed audit emit

Auditable method paths (duck-typed, same as TS). The version beside each is the
FIRST release of that client to expose it, established by walking every
published release with one environment apiece rather than read off a changelog.
They differ by path, so a client that satisfies the extra's floor still will not
have all of them — which is why they are listed per path here instead of as one
range. The extras floor at openai>=1.66.0 and anthropic>=0.16.0.

    chat.completions.create       openai 1.0.0    OpenAI / Azure OpenAI
    beta.chat.completions.parse   openai 1.40.0   chat beta namespace
    responses.create              openai 1.66.0   the openai extra's floor
    responses.parse               openai 1.66.0
    chat.completions.parse        openai 1.92.0   structured outputs
    beta.chat.completions.create  openai 1.92.0   chat beta namespace
    beta.responses.create         openai 2.45.0   ABOVE the declared floor
    beta.messages.create          anthropic 0.8.0 (see note)
    beta.messages.parse           anthropic 0.68.0  tool-runner model turns
    messages.create               anthropic 0.16.0  the anthropic extra's floor
    messages.parse                anthropic 0.77.0  structured outputs
    *.with_raw_response.*         openai / anthropic (see note)
    generate_content              google-generativeai  (legacy client)
    generate_content_async        google-generativeai  (legacy client)
    start_chat().send_message     google-generativeai  (legacy client)
    start_chat().send_message_async google-generativeai (legacy client)
    models.generate_content       google-genai          (current sync client)
    models.generate_content_stream google-genai         (current sync stream)
    aio.models.generate_content   google-genai          (current async client)
    aio.models.generate_content_stream google-genai     (current async stream)
    beta.messages.tool_runner     anthropic>=0.68.0
    beta.sessions.events.tool_runner anthropic>=0.103.0 (async client)

Note on beta.messages.create: present from 0.8.0, then ABSENT 0.16.0 through
0.35.0, then present again from 0.36.0. That gap is upstream — the beta
namespace was dropped when that API graduated — not a coverage regression here.
Raise the anthropic extra to >=0.36.0 if the beta namespace has to be covered.

The `gemini` extra includes both Google distributions. The legacy
`google-generativeai` model object and the maintained `google-genai` Client use
different paths, but both need an explicit `obsvr.wrap()`; construct-time auto
registration remains limited to the OpenAI and Anthropic clients.

Sync and async client methods are both supported: if the underlying method is
a coroutine function the wrapper is async, otherwise sync. The wrapped object
delegates every other attribute untouched.

The ``with_raw_response`` accessors return the provider's raw response object.
obsvr parses its cached typed view for response policy and audit extraction,
but returns the original raw object unchanged. ``with_streaming_response``
defers the request until context entry, so it uses a dedicated governed context
manager that preserves that lifecycle and observes whichever response-reading
surface the caller chooses.
"""

import copy as _copy
import inspect
import logging
import time
import weakref
from typing import Any, Callable, Dict, List, NamedTuple, Optional

from .config import ResolvedConfig, get_config, is_initialized
from .events import build_audit_event, blocked_call_error, classify_error
from .span import span_envelope_for, with_span_metadata
from .deobfuscate import redact_for_storage
from .stored_content import redact_unscanned_for_storage
from .policy import (
    apply_pre_call_policy,
    apply_post_call_policy,
    blocked_prompt_for_storage,
    apply_outbound_redaction,
    assert_redaction_applied,
    outbound_redaction_blocked_compliance,
    outbound_redactor,
)
from .sender import send_audit_async, should_emit
from .metering import record_token_usage_for_rules as _record_token_usage_for_rules
from .metering import stamp_cost as _stamp_cost
from .token_usage import read_token_usage
from .provider_attribution import resolve_destination
from .strict_provider_boundary_v2_1 import (
    ObsvrStrictProviderBoundaryV21Error,
    assert_strict_provider_boundary_v2_1,
    execute_strict_provider_call_v2_1,
    strict_provider_target_v2_1,
    strict_provider_surface_unsupported_v2_1,
)


def _emit_audit(config: Any, event: Dict[str, Any], compliance: Dict[str, Any] = None) -> None:
    """Emit an audit event. In enforce mode, sampling (config.sample_rate)
    applies ONLY to clean allowed events; monitor mode emits every event.
    Governed events (blocked / redacted / flagged / PII-detected) and errors are
    forensic evidence and are NEVER dropped — EV-2 requires every governed call
    to emit exactly one audit event.

    Mirrors the TS sender for enforcement actions and errors. It does NOT mirror
    it for allowed-but-FLAGGED events, and the header used to say it did. This
    gate is a three-way test (``success is False`` OR ``action_taken`` is not
    ``allowed`` OR ``action_reason`` is set); the TypeScript gate at
    ``wrapper.ts`` keys on ``action_taken`` alone. So an event carrying
    ``action_reason: "pii_detected"`` with ``action_taken: "allowed"`` — a
    detect_only PII finding — is sampled out there and kept here. Measured at
    ``sample_rate=0`` with an identical prompt and policy: Python 1 event,
    TypeScript 0."""
    c = compliance or {}
    governed = (
        event.get("success") is False
        or c.get("action_taken", "allowed") != "allowed"
        or c.get("action_reason", "none") not in ("none", None)
        or c.get("detector_failure") is not None
    )
    if should_emit(config, governed=governed):
        send_audit_async(config, event)




#: COVERAGE BOUNDARY. Mirrors the TypeScript AUDITABLE_METHODS table, which
#: carries the full statement of what is excluded because it bears no chat text
#: (embeddings, images, audio, files, fine-tuning) versus what is text-bearing
#: but genuinely out of reach of a method-path table (batch surfaces,
#: ``count_tokens`` and batch surfaces).
#:
#: The ``.stream()`` helpers are governed, in their own table below, because
#: they return a manager rather than a response and so cannot share this one.
#: Provider tool runners use their own interception table below because they
#: snapshot callbacks and retain a client for later model turns.
#:
#: The beta namespaces are enumerated rather than matched by stripping a
#: leading ``beta.`` segment, so a provider shipping a new beta namespace does
#: not silently widen governance without review.
AUDITABLE_METHODS = {
    "chat.completions.create",   # OpenAI / Azure OpenAI
    "chat.completions.parse",    # OpenAI structured outputs
    "completions.create",        # OpenAI legacy text completions
    "responses.create",          # OpenAI Responses API
    "responses.parse",           # OpenAI Responses structured outputs
    "responses.compact",         # OpenAI Responses compaction
    "messages.create",           # Anthropic
    "messages.parse",            # Anthropic structured outputs
    "messages.with_raw_response.create",  # Anthropic raw response
    "generate_content",          # Google Gemini, google-generativeai only
    "generate_content_async",    # Google Gemini async, google-generativeai only
    "models.generate_content",  # Google Gemini, maintained google-genai client
    "models.generate_content_stream",  # Google Gemini sync iterator
    "aio.models.generate_content",  # Google Gemini maintained async client
    "aio.models.generate_content_stream",  # Google Gemini async iterator
    "send_message",              # Google Gemini ChatSession sync
    "send_message_async",        # Google Gemini ChatSession async
    "send_message_stream",       # Google Gemini chat stream
    "beta.messages.create",      # Anthropic beta
    "beta.messages.parse",       # Anthropic beta structured outputs / tool runner
    "beta.messages.with_raw_response.create",  # Anthropic beta raw response
    "beta.responses.create",     # OpenAI Responses beta
    "beta.responses.compact",    # OpenAI Responses beta compaction
    "beta.responses.with_raw_response.create",  # OpenAI beta raw response
    "beta.chat.completions.create",  # OpenAI chat beta
    "beta.chat.completions.parse",   # OpenAI chat beta
    "beta.chat.completions.with_raw_response.create",  # OpenAI beta raw response
    "beta.chat.completions.with_raw_response.parse",  # OpenAI beta raw parse
    "chat.completions.with_raw_response.create",  # OpenAI raw response
    "chat.completions.with_raw_response.parse",  # OpenAI raw structured output
    "completions.with_raw_response.create",  # OpenAI raw text completion
    "responses.with_raw_response.create",  # OpenAI Responses raw response
    "responses.with_raw_response.parse",  # OpenAI Responses raw structured output
    "responses.with_raw_response.compact",  # OpenAI Responses raw compaction
    "beta.responses.with_raw_response.compact",  # OpenAI beta raw compaction
}

_STRICT_V2_1_DIRECT_METHODS = {
    "chat.completions.create",
    "chat.completions.parse",
    "responses.create",
    "responses.parse",
    "messages.create",
    "messages.parse",
    "generate_content",
    "models.generate_content",
}

#: Named iterator methods on the maintained Google client. They enter the
#: ordinary pre-call pipeline above, but unlike OpenAI/Anthropic streams they do
#: not carry ``stream=True`` in kwargs: the method name selects streaming.
_DIRECT_STREAM_METHODS = {
    "models.generate_content_stream",
    "aio.models.generate_content_stream",
    "send_message_stream",
}

#: The ``.stream()`` helpers, which are the same request as ``create`` and
#: return a context manager instead of a response. Their own table because the
#: return type decides how the call is wrapped, not whether it is governed.
#:
#: These were outside the boundary entirely, and the consequence was not the
#: missing audit event the old comment here described. On one wrapped client a
#: ``pii_policy`` block refused ``create(stream=True)`` and let
#: ``messages.stream(...)`` through — same policy, same prompt, opposite
#: outcomes on the wire. Mirrors STREAM_RUNNER_METHODS in
#: sdk-typescript/src/proxy/wrapper.ts.
STREAM_HELPER_METHODS = {
    "messages.stream",           # Anthropic
    "beta.messages.stream",      # Anthropic beta
    "chat.completions.stream",   # OpenAI
    "responses.stream",          # OpenAI Responses
}

#: Provider accessors that return a response context manager immediately and
#: defer the actual HTTP request until ``with`` / ``async with`` entry. They
#: cannot use the ordinary call pipeline (which would record success before the
#: request) or the stream-helper wrapper (whose entered object is an event
#: iterator rather than a raw APIResponse).
DEFERRED_RESPONSE_METHODS = {
    "messages.with_streaming_response.create",
    "beta.messages.with_streaming_response.create",
    "beta.responses.with_streaming_response.create",
    "beta.chat.completions.with_streaming_response.create",
    "beta.chat.completions.with_streaming_response.parse",
    "chat.completions.with_streaming_response.create",
    "chat.completions.with_streaming_response.parse",
    "completions.with_streaming_response.create",
    "responses.with_streaming_response.create",
    "responses.with_streaming_response.parse",
}

#: Factory methods whose return object contains governed calls. The factory
#: itself performs no provider request and emits no event; its result must stay
#: behind the proxy so the later request cannot escape through a raw object.
GOVERNED_FACTORY_METHODS = {
    "start_chat",
    "chats.create",
    "aio.chats.create",
}

#: Provider-managed loops that snapshot local tool callbacks at construction.
#: The Messages runner also owns the initial model request, so it receives the
#: normal pre-call pipeline and a run-level audit event. The managed-session
#: runner attaches to an already-created remote session; only its local tools
#: are on this boundary, and each is governed by its own ``tool.call`` event.
TOOL_RUNNER_METHODS = {
    "beta.messages.tool_runner": True,
    "beta.sessions.events.tool_runner": False,
}

#: Every method path that makes ``wrap()`` a governed wrapper. Keep the three
#: tables separate above because their return shapes require different
#: interception pipelines, but coverage reporting must consider all of them.
_GOVERNED_METHODS = (
    AUDITABLE_METHODS
    | STREAM_HELPER_METHODS
    | DEFERRED_RESPONSE_METHODS
    | GOVERNED_FACTORY_METHODS
    | set(TOOL_RUNNER_METHODS)
)

#: Attribute names that may lead to an auditable method. Everything else is
#: returned untouched, so we never wrap unrelated objects. "beta" earns its
#: place here for the two beta paths above: without it ``client.beta`` is
#: returned raw and every path beneath it is unreachable, which would leave
#: those entries as dead code.
_TRAVERSABLE = {
    "aio", "beta", "chat", "chats", "completions", "events", "messages", "models",
    "responses", "sessions",
    "with_raw_response", "with_streaming_response",
}


def _detect_provider(client: Any) -> str:
    """Duck-typed provider detection (mirror of TS detectProvider)."""
    if client is None:
        return "unknown"
    if hasattr(client, "chat") and hasattr(getattr(client, "chat"), "completions"):
        return "openai"
    if hasattr(client, "responses") and hasattr(getattr(client, "responses"), "create"):
        return "openai"
    if hasattr(client, "generate_content"):
        return "google"
    if hasattr(client, "send_message"):
        return "google"
    models = getattr(client, "models", None)
    if models is not None and hasattr(models, "generate_content"):
        return "google"
    if (
        hasattr(client, "send_message")
        and hasattr(client, "model")
        and hasattr(getattr(client, "model"), "generate_content")
    ):
        return "google"
    name = type(client).__name__.lower()
    if "openai" in name:
        return "openai"
    if "anthropic" in name:
        return "anthropic"
    if "google" in name or "gemini" in name or "generativemodel" in name:
        return "google"
    if hasattr(client, "messages") and hasattr(getattr(client, "messages"), "create"):
        return "anthropic"
    return "unknown"


# ── Prompt / response extractors ─────────────────────────────────────────────

def _append_string_leaves(value: Any, parts: List[str]) -> None:
    """Collect strings from a provider-bound structured content value."""
    if isinstance(value, str):
        parts.append(value)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _append_string_leaves(item, parts)
    elif isinstance(value, dict):
        for item in value.values():
            _append_string_leaves(item, parts)


def _redact_string_leaves(value: Any, redact_fn: Callable[[str], str]) -> Any:
    """Copy a structured content value while redacting every string leaf."""
    if isinstance(value, str):
        return redact_fn(value)
    if isinstance(value, list):
        return [_redact_string_leaves(item, redact_fn) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_string_leaves(item, redact_fn) for item in value)
    if isinstance(value, dict):
        return {
            key: _redact_string_leaves(item, redact_fn)
            for key, item in value.items()
        }
    return value


def _append_content_text(value: Any, parts: List[str]) -> None:
    """Collect text-bearing content fields without treating schema labels as prompt."""
    if isinstance(value, str):
        parts.append(value)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _append_content_text(item, parts)
        return
    keys = ("text", "content", "input", "output")
    if isinstance(value, dict):
        for key in keys:
            if key in value:
                _append_content_text(value[key], parts)
        return
    for key in keys:
        item = getattr(value, key, None)
        if item is not None:
            _append_content_text(item, parts)

def _extract_prompt_text(provider: str, args: tuple, kwargs: dict) -> str:
    """Pull all visible prompt text for PII/policy scanning."""
    parts: List[str] = []

    prompt = kwargs.get("prompt")
    if isinstance(prompt, str):
        parts.append(prompt)
    elif isinstance(prompt, (list, tuple)):
        parts.extend(item for item in prompt if isinstance(item, str))

    # Gemini accepts a positional string or list
    if provider == "google" and args:
        first = args[0]
        if isinstance(first, str):
            return first
        if isinstance(first, list):
            for item in first:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    for p in item.get("parts", []):
                        if isinstance(p, str):
                            parts.append(p)
                        elif isinstance(p, dict) and isinstance(p.get("text"), str):
                            parts.append(p["text"])
            return "\n".join(parts)

    system = kwargs.get("system")
    if isinstance(system, str):
        parts.append(system)
    elif isinstance(system, (list, tuple)):
        for block in system:
            _append_content_text(block, parts)

    messages = kwargs.get("messages")
    if isinstance(messages, list):
        for msg in messages:
            content = msg.get("content") if isinstance(msg, dict) else getattr(msg, "content", None)
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                _append_content_text(content, parts)

    # OpenAI Responses API: instructions + input (bare string or message list)
    instructions = kwargs.get("instructions")
    if isinstance(instructions, str):
        parts.append(instructions)
    input_val = kwargs.get("input")
    if isinstance(input_val, str):
        parts.append(input_val)
    elif isinstance(input_val, list):
        for item in input_val:
            output = item.get("output") if isinstance(item, dict) else getattr(item, "output", None)
            if output is not None:
                _append_string_leaves(output, parts)
            content = item.get("content") if isinstance(item, dict) else getattr(item, "content", None)
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and isinstance(block.get("text"), str):
                        parts.append(block["text"])

    contents = kwargs.get("contents")
    if contents is not None:
        text = _google_content_text(contents)
        if text:
            parts.append(text)
    content = kwargs.get("content")
    if provider == "google" and content is not None:
        text = _google_content_text(content)
        if text:
            parts.append(text)
    message = kwargs.get("message")
    if message is not None:
        text = _google_content_text(message)
        if text:
            parts.append(text)
    if provider == "google":
        system_instruction = _google_config_system_instruction(kwargs.get("config"))
        if system_instruction is not None:
            text = _google_content_text(system_instruction)
            if text:
                parts.append(text)

    return "\n".join(parts)


def _google_context_carriers(target: Any) -> List[Any]:
    carriers: List[Any] = []
    for candidate in (
        target,
        getattr(target, "_model", None),
        getattr(target, "model", None),
    ):
        if candidate is not None and all(candidate is not item for item in carriers):
            carriers.append(candidate)
    return carriers


def _google_cached_context_text(target: Any) -> str:
    for carrier in _google_context_carriers(target):
        cached = getattr(carrier, "_cached_content", None)
        if cached is None:
            cached = getattr(carrier, "cached_content", None)
        if cached is None:
            continue
        raw = getattr(cached, "_raw_cached_content", None) or cached
        parts: List[str] = []
        for attr in ("system_instruction", "systemInstruction", "contents"):
            value = raw.get(attr) if isinstance(raw, dict) else getattr(raw, attr, None)
            text = _google_content_text(value)
            if text:
                parts.append(text)
        if parts:
            return "\n".join(parts)
        raise RuntimeError(
            "[obsvr] Google cached context is opaque and cannot be verified"
        )
    return ""


def _google_chat_context_text(target: Any) -> str:
    """Text retained by a chat object and sent with the next message."""
    parts: List[str] = []
    seen = set()
    for carrier in _google_context_carriers(target):
        for name in (
            "_history",
            "_curated_history",
            "_comprehensive_history",
            "historyInternal",
        ):
            value = getattr(carrier, name, None)
            if value is not None and id(value) not in seen:
                seen.add(id(value))
                text = _google_content_text(value)
                if text:
                    parts.append(text)
        for name in ("_system_instruction", "system_instruction", "systemInstruction"):
            value = getattr(carrier, name, None)
            if value is not None and id(value) not in seen:
                seen.add(id(value))
                text = _google_content_text(value)
                if text:
                    parts.append(text)
        for name in ("_tools", "tools"):
            value = getattr(carrier, name, None)
            if value is not None and id(value) not in seen:
                seen.add(id(value))
                leaves: List[str] = []
                to_dict = getattr(value, "to_dict", None)
                _append_string_leaves(to_dict() if callable(to_dict) else value, leaves)
                parts.extend(leaves)
        for name in ("config", "_config", "params"):
            value = getattr(carrier, name, None)
            if value is None or id(value) in seen:
                continue
            seen.add(id(value))
            system = _google_config_system_instruction(value)
            if system is not None:
                text = _google_content_text(system)
                if text:
                    parts.append(text)
            history = (
                value.get("history")
                if isinstance(value, dict)
                else getattr(value, "history", None)
            )
            if history is not None and id(history) not in seen:
                seen.add(id(history))
                text = _google_content_text(history)
                if text:
                    parts.append(text)
    cached = _google_cached_context_text(target)
    if cached:
        parts.append(cached)
    return "\n".join(parts)


def _redact_google_chat_context(target: Any, redact_fn: Callable[[str], str]) -> None:
    """Redact chat-owned context without mutating the factory arguments."""
    for carrier in _google_context_carriers(target):
        if (
            getattr(carrier, "_cached_content", None) is not None
            or getattr(carrier, "cached_content", None) is not None
        ):
            raise TypeError("Google cached context cannot be redacted in place")
        for name in (
            "history",
            "_history",
            "_curated_history",
            "_comprehensive_history",
            "historyInternal",
        ):
            value = getattr(carrier, name, None)
            if value is not None:
                setattr(carrier, name, _redact_google_content(value, redact_fn))
        if all(
            getattr(carrier, name, None) is None
            for name in ("_history", "_curated_history", "_comprehensive_history", "historyInternal")
        ):
            history = getattr(carrier, "history", None)
            if history is not None:
                setattr(carrier, "history", _redact_google_content(history, redact_fn))
        for name in ("_system_instruction", "system_instruction", "systemInstruction"):
            value = getattr(carrier, name, None)
            if value is not None:
                setattr(carrier, name, _redact_google_content(value, redact_fn))
        for name in ("config", "_config"):
            value = getattr(carrier, name, None)
            if value is not None:
                setattr(carrier, name, _redact_google_config(value, redact_fn))
        params = getattr(carrier, "params", None)
        if isinstance(params, dict):
            setattr(
                carrier,
                "params",
                {
                    **params,
                    **(
                        {
                            "systemInstruction": _redact_google_content(
                                params["systemInstruction"], redact_fn
                            )
                        }
                        if "systemInstruction" in params
                        else {}
                    ),
                    **(
                        {"history": _redact_google_content(params["history"], redact_fn)}
                        if "history" in params
                        else {}
                    ),
                },
            )


def _last_user_message(kwargs: dict) -> Optional[str]:
    # "input" is the Responses API's message list; same role/content shape.
    for key in ("messages", "input"):
        items = kwargs.get(key)
        if not isinstance(items, list):
            continue
        for msg in reversed(items):
            role = msg.get("role") if isinstance(msg, dict) else getattr(msg, "role", None)
            if role == "user":
                content = msg.get("content") if isinstance(msg, dict) else getattr(msg, "content", None)
                if isinstance(content, str):
                    return content
                if isinstance(content, list):
                    text: List[str] = []
                    _append_content_text(content, text)
                    return " ".join(text)
    # Responses API bare-string input IS the user message.
    if isinstance(kwargs.get("input"), str):
        return kwargs["input"]
    if kwargs.get("contents") is not None:
        return _google_content_text(kwargs["contents"]) or None
    if kwargs.get("content") is not None:
        return _google_content_text(kwargs["content"]) or None
    return None


def _last_user_message_text(provider: str, args: tuple, kwargs: dict) -> str:
    """Text of the LAST user turn only — the scope the PII/rules DECISION scans.

    Parity with the TS wrapper's extractLastUserMessageText: governance decides
    on the latest user turn (each turn is governed once, when it arrives), while
    the full conversation is still stored and is what multi-turn injection
    accumulates over. Falls back to the full extraction for shapes with no
    identifiable user turn (e.g. a bare Gemini string).
    """
    # Gemini positional string / list
    if provider == "google" and args:
        first = args[0]
        if isinstance(first, str):
            return first

    # "input" is the Responses API's message list; same role/content shape.
    for key in ("messages", "input"):
        items = kwargs.get(key)
        if not isinstance(items, list):
            continue
        for msg in reversed(items):
            role = msg.get("role") if isinstance(msg, dict) else getattr(msg, "role", None)
            if role == "user":
                content = (
                    msg.get("content") if isinstance(msg, dict)
                    else getattr(msg, "content", None)
                )
                if isinstance(content, str):
                    return content
                if isinstance(content, list):
                    text: List[str] = []
                    _append_content_text(content, text)
                    return " ".join(text)

    # Responses API bare-string input: the whole input is the user turn.
    if isinstance(kwargs.get("input"), str):
        return kwargs["input"]

    # Gemini contents: last user turn's text parts
    contents = kwargs.get("contents")
    if isinstance(contents, str):
        return contents
    if isinstance(contents, list):
        for item in reversed(contents):
            role = item.get("role") if isinstance(item, dict) else getattr(item, "role", None)
            if role == "user":
                return _google_content_text(item)

    if provider == "google" and kwargs.get("content") is not None:
        return _google_content_text(kwargs["content"])

    # No identifiable user turn — fall back to the full prompt text.
    return _extract_prompt_text(provider, args, kwargs)


def _redact_text_blocks(blocks: list, redact_fn: Callable[[str], str]) -> list:
    """Redact text, tool input, and tool result content into NEW blocks."""
    out = []
    for block in blocks:
        keys = ("text", "content", "input", "output")
        if isinstance(block, dict):
            updates = {
                key: _redact_string_leaves(block[key], redact_fn)
                for key in keys if key in block
            }
            out.append({**block, **updates} if updates else block)
            continue
        updates = {
            key: _redact_string_leaves(getattr(block, key), redact_fn)
            for key in keys if getattr(block, key, None) is not None
        }
        if not updates:
            out.append(block)
            continue
        try:
            clone = _copy.copy(block)
            for key, value in updates.items():
                setattr(clone, key, value)
            out.append(clone)
        except Exception as err:
            raise TypeError("content block could not be copied for outbound redaction") from err
    return out


def _google_content_text(value: Any) -> str:
    """Text from legacy/current Gemini ``contents`` without importing Google.

    Current ``google-genai`` accepts strings, nested lists, Content/Part
    pydantic models, and their dict twins. Duck-typing keeps this SDK free of a
    mandatory provider dependency while covering the real public shapes.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return "\n".join(filter(None, (_google_content_text(item) for item in value)))
    if isinstance(value, dict):
        text = value.get("text")
        if isinstance(text, str):
            return text
        parts = value.get("parts")
        if parts is not None:
            return _google_content_text(parts)
        out: List[str] = []
        for key in ("function_response", "functionResponse"):
            item = value.get(key)
            if isinstance(item, dict):
                _append_string_leaves(item.get("response"), out)
        for key in ("function_call", "functionCall"):
            item = value.get(key)
            if isinstance(item, dict):
                _append_string_leaves(item.get("args"), out)
        return "\n".join(out)
    serialized = _google_model_dict(value)
    if serialized is not None:
        return _google_content_text(serialized)
    text = getattr(value, "text", None)
    if isinstance(text, str):
        return text
    parts = getattr(value, "parts", None)
    return _google_content_text(parts) if parts is not None else ""


def _google_config_system_instruction(config: Any) -> Any:
    """Read the maintained client's text-bearing config field, if present."""
    if isinstance(config, dict):
        return config.get("system_instruction", config.get("systemInstruction"))
    return getattr(config, "system_instruction", None)


def _rebuild_google_model(value: Any, updates: Dict[str, Any]) -> Any:
    """Copy a real google-genai Content/Part with selected fields replaced."""
    model_copy = getattr(value, "model_copy", None)
    if callable(model_copy):
        return model_copy(update=updates)
    try:
        clone = _copy.copy(value)
        for key, replacement in updates.items():
            setattr(clone, key, replacement)
        return clone
    except Exception as err:
        raise TypeError("Gemini content could not be copied for outbound redaction") from err


def _google_model_dict(value: Any) -> Optional[Dict[str, Any]]:
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        try:
            return to_dict()
        except Exception:
            pass
    for attr in ("_raw_part", "_raw_content"):
        raw = getattr(value, attr, None)
        raw_to_dict = getattr(type(raw), "to_dict", None)
        if raw is not None and callable(raw_to_dict):
            return raw_to_dict(raw)
    return None


def _redact_google_content(value: Any, redact_fn: Callable[[str], str]) -> Any:
    """Redact every text-bearing google-genai/legacy contents shape into copies."""
    if isinstance(value, str):
        return redact_fn(value)
    if isinstance(value, list):
        return [_redact_google_content(item, redact_fn) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_google_content(item, redact_fn) for item in value)
    if isinstance(value, dict):
        if isinstance(value.get("text"), str):
            return {**value, "text": redact_fn(value["text"])}
        if value.get("parts") is not None:
            return {
                **value,
                "parts": _redact_google_content(value["parts"], redact_fn),
            }
        out = dict(value)
        for key in ("function_response", "functionResponse"):
            item = value.get(key)
            if isinstance(item, dict) and "response" in item:
                out[key] = {
                    **item,
                    "response": _redact_string_leaves(item["response"], redact_fn),
                }
        for key in ("function_call", "functionCall"):
            item = value.get(key)
            if isinstance(item, dict) and "args" in item:
                out[key] = {
                    **item,
                    "args": _redact_string_leaves(item["args"], redact_fn),
                }
        return out
    from_dict = getattr(value, "from_dict", None)
    serialized = _google_model_dict(value)
    if serialized is not None and callable(from_dict):
        return from_dict(_redact_google_content(serialized, redact_fn))
    text = getattr(value, "text", None)
    if isinstance(text, str):
        return _rebuild_google_model(value, {"text": redact_fn(text)})
    parts = getattr(value, "parts", None)
    if parts is not None:
        return _rebuild_google_model(
            value, {"parts": _redact_google_content(parts, redact_fn)}
        )
    return value


def _redact_google_config(config: Any, redact_fn: Callable[[str], str]) -> Any:
    """Copy/redact ``GenerateContentConfig.system_instruction`` only."""
    system_instruction = _google_config_system_instruction(config)
    if system_instruction is None:
        return config
    replacement = _redact_google_content(system_instruction, redact_fn)
    if isinstance(config, dict):
        key = "system_instruction" if "system_instruction" in config else "systemInstruction"
        return {**config, key: replacement}
    return _rebuild_google_model(config, {"system_instruction": replacement})


def _rebuild_message(msg: Any, new_content: Any) -> Any:
    """Return a COPY of ``msg`` carrying ``new_content`` — never ``msg`` itself.

    A dict message becomes a plain dict, which is what the provider reads
    anyway; note this deliberately does not preserve a dict SUBCLASS, because a
    subclass that raises on ``__setitem__`` is precisely the shape a caller uses
    to say "do not write to me".

    A message OBJECT is copied with ``copy.copy`` so the provider's own type
    survives — substituting a dict would be rejected by a client that validates
    its argument. If the copy or assignment fails, redaction fails closed. The
    original must never be forwarded under an event that claims its content was
    removed.
    """
    if isinstance(msg, dict):
        return {**msg, "content": new_content}
    try:
        clone = _copy.copy(msg)
        setattr(clone, "content", new_content)
        return clone
    except Exception as err:
        raise TypeError("message could not be copied for outbound redaction") from err


def _redact_messages_in_place(
    provider: str, kwargs: dict, redact_fn: Callable[[str], str]
) -> None:
    """Redact every text-bearing kwarg shape the scanner reads
    (_extract_prompt_text), symmetrically: what gets scanned outbound gets
    redacted outbound, or the provider receives the PII the stored copy
    hides. Covers string and content-block-list message content, string
    system, Responses API instructions/input, and Gemini contents/parts.

    "In place" means the KWARGS DICT, which ``**kwargs`` already made fresh at
    the call boundary — never the caller's own containers inside it. Rebinding
    ``kwargs["system"]`` was always safe for that reason; walking into
    ``messages`` and assigning ``msg["content"]`` was not, because that list and
    those dicts are the caller's. A conversation history is normally a list the
    application keeps and appends to, so one redacted turn rewrote the
    application's own history and every later turn sent the placeholder in place
    of text it believed it still held. The message-OBJECT branch was worse
    still: it called ``setattr`` on the caller's model instance, catching the
    failure when the object was frozen — so the only cases it did not corrupt
    were the ones that refused to be corrupted.

    Every container is therefore rebuilt and rebound onto ``kwargs``. Twin of
    the TypeScript ``redactMessagesInPlace``, which had the same defect for the
    same reason: a shallow copy at the top level that looks like a copy.

    A consequence worth stating, because it moved a documented fail mode: an
    unwritable caller message is no longer an application failure. It used to
    make the write raise, which resolved closed and refused the call — obsvr
    blocking a caller for protecting the very object obsvr was about to
    corrupt. Copying redacts it successfully instead. Application failure still
    fails closed; what changed is what counts as one.
    """
    prompt = kwargs.get("prompt")
    if isinstance(prompt, str):
        kwargs["prompt"] = redact_fn(prompt)
    elif isinstance(prompt, list):
        kwargs["prompt"] = [
            redact_fn(item) if isinstance(item, str) else item for item in prompt
        ]
    elif isinstance(prompt, tuple):
        kwargs["prompt"] = tuple(
            redact_fn(item) if isinstance(item, str) else item for item in prompt
        )

    messages = kwargs.get("messages")
    if isinstance(messages, list):
        rebuilt = []
        for msg in messages:
            content = msg.get("content") if isinstance(msg, dict) else getattr(msg, "content", None)
            if isinstance(content, str):
                rebuilt.append(_rebuild_message(msg, redact_fn(content)))
            elif isinstance(content, list):
                rebuilt.append(_rebuild_message(msg, _redact_text_blocks(content, redact_fn)))
            else:
                rebuilt.append(msg)
        kwargs["messages"] = rebuilt
    if isinstance(kwargs.get("system"), str):
        kwargs["system"] = redact_fn(kwargs["system"])
    elif isinstance(kwargs.get("system"), list):
        kwargs["system"] = _redact_text_blocks(kwargs["system"], redact_fn)
    elif isinstance(kwargs.get("system"), tuple):
        kwargs["system"] = tuple(
            _redact_text_blocks(list(kwargs["system"]), redact_fn)
        )

    # OpenAI Responses API: instructions + input (bare string or message list)
    if isinstance(kwargs.get("instructions"), str):
        kwargs["instructions"] = redact_fn(kwargs["instructions"])
    input_val = kwargs.get("input")
    if isinstance(input_val, str):
        kwargs["input"] = redact_fn(input_val)
    elif isinstance(input_val, list):
        rebuilt_input = []
        for item in input_val:
            if isinstance(item, dict):
                output = (
                    _redact_string_leaves(item["output"], redact_fn)
                    if "output" in item else None
                )
                content = item.get("content")
                if isinstance(content, str):
                    rebuilt_input.append({
                        **item,
                        **({"output": output} if "output" in item else {}),
                        "content": redact_fn(content),
                    })
                elif isinstance(content, list):
                    rebuilt_input.append(
                        {
                            **item,
                            **({"output": output} if "output" in item else {}),
                            "content": _redact_text_blocks(content, redact_fn),
                        }
                    )
                elif "output" in item:
                    rebuilt_input.append({**item, "output": output})
                else:
                    rebuilt_input.append(item)
            else:
                rebuilt_input.append(item)
        kwargs["input"] = rebuilt_input

    # Gemini keyword contents
    contents = kwargs.get("contents")
    if contents is not None:
        kwargs["contents"] = _redact_google_content(contents, redact_fn)
    content = kwargs.get("content")
    if provider == "google" and content is not None:
        kwargs["content"] = _redact_google_content(content, redact_fn)
    if provider == "google" and kwargs.get("config") is not None:
        kwargs["config"] = _redact_google_config(kwargs["config"], redact_fn)


def _redact_positional_inputs(args: tuple, redact_fn: Callable[[str], str]) -> tuple:
    """Redacted twin of the positional shapes _extract_prompt_text reads
    (Gemini's positional string / contents list). Strings are immutable, so
    the possibly-rebuilt args tuple is returned; list args mutate in place."""
    if not args:
        return args
    first = args[0]
    if isinstance(first, str):
        return (redact_fn(first),) + args[1:]
    if isinstance(first, list):
        return (_redact_google_content(first, redact_fn),) + args[1:]
    return args


def _extract_model(provider: str, target: Any, kwargs: dict) -> str:
    model = kwargs.get("model")
    if isinstance(model, str):
        return model
    if provider == "google":
        model_target = getattr(target, "model", None)
        return str(
            getattr(target, "model_name", None)
            or getattr(target, "_model_name", None)
            or getattr(target, "_model", None)
            or getattr(model_target, "model_name", None)
            or getattr(model_target, "_model_name", None)
            or "gemini"
        )
    return "unknown"


def _response_for_observation(method_path: str, result: Any) -> Any:
    """Return the typed view of a raw provider response when available.

    Stainless-backed OpenAI and Anthropic clients deliberately return a
    ``LegacyAPIResponse`` from ``with_raw_response``. Its cached ``parse()``
    view is the same typed response the ordinary method returns, so policy,
    usage, and telemetry extraction can inspect it while the caller still gets
    the original raw object. Parsing remains best-effort: callers choose this
    accessor partly to handle unusual successful bodies themselves, and
    observation must not turn such a response into a new application error.
    """
    if ".with_raw_response." not in method_path:
        return result
    parse = getattr(result, "parse", None)
    if not callable(parse):
        return result
    try:
        return parse()
    except Exception:
        return result


def _extract_response_text(provider: str, result: Any) -> str:
    try:
        if provider == "openai":
            choices = getattr(result, "choices", None) or (result.get("choices") if isinstance(result, dict) else None)
            if choices:
                first = choices[0]
                text = getattr(first, "text", None) or (first.get("text") if isinstance(first, dict) else None)
                if isinstance(text, str):
                    return text
                message = getattr(first, "message", None) or (first.get("message") if isinstance(first, dict) else None)
                if message is not None:
                    content = getattr(message, "content", None) or (message.get("content") if isinstance(message, dict) else None)
                    return content or ""
            # Responses API: output_text convenience property, else walk
            # output[].content[].text (message items).
            output_text = getattr(result, "output_text", None) or (result.get("output_text") if isinstance(result, dict) else None)
            if isinstance(output_text, str) and output_text:
                return output_text
            output = getattr(result, "output", None) or (result.get("output") if isinstance(result, dict) else None)
            if isinstance(output, list):
                parts = []
                for item in output:
                    content = getattr(item, "content", None) or (item.get("content") if isinstance(item, dict) else None)
                    if isinstance(content, list):
                        for b in content:
                            text = getattr(b, "text", None) or (b.get("text") if isinstance(b, dict) else None)
                            if isinstance(text, str):
                                parts.append(text)
                return "".join(parts)
        elif provider == "anthropic":
            content = getattr(result, "content", None) or (result.get("content") if isinstance(result, dict) else None)
            if isinstance(content, list):
                return "".join(
                    (getattr(b, "text", None) or (b.get("text") if isinstance(b, dict) else "") or "")
                    for b in content
                )
        elif provider == "google":
            text = getattr(result, "text", None)
            if isinstance(text, str):
                return text
            if callable(text):
                return str(text())
    except Exception:
        pass
    return ""


def _extract_usage(provider: str, result: Any) -> Dict[str, Optional[int]]:
    """Token counts off a provider response, whatever shape it arrives in.

    The Gemini fallback used to be reachable only for attribute-shaped results:
    ``usage`` was read from dict OR attribute, but ``usage_metadata`` was read
    with a bare ``getattr``, which always returns None on a dict. A dict-shaped
    Gemini response therefore reported no tokens at all.
    """
    usage = getattr(result, "usage", None)
    if usage is None and isinstance(result, dict):
        usage = result.get("usage")
    if usage is None:
        usage = getattr(result, "usage_metadata", None)
        if usage is None and isinstance(result, dict):
            usage = result.get("usage_metadata") or result.get("usageMetadata")
    return read_token_usage(usage)


def _tel_get(obj: Any, *names: str) -> Any:
    """Attribute-or-key accessor for provider response/usage objects."""
    for n in names:
        v = getattr(obj, n, None) if not isinstance(obj, dict) else obj.get(n)
        if v is not None:
            return v
    return None


def _extract_telemetry(provider: str, kwargs: dict, result: Any) -> Dict[str, Any]:
    """Curated call telemetry (telemetry design notes, milestone 1): request shape,
    response metadata, cost-detail tokens. Provider-tolerant, best-effort,
    never raises. Mirrors sdk-typescript/src/proxy/extractors/telemetry.ts.
    """
    def _num(v: Any) -> Optional[float]:
        return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None

    def _s(v: Any) -> Optional[str]:
        return v.strip()[:128] if isinstance(v, str) and v.strip() else None

    try:
        if provider == "anthropic":
            usage = _tel_get(result, "usage") or {}
            vals = {
                "request_temperature": _num(kwargs.get("temperature")),
                "request_top_p": _num(kwargs.get("top_p")),
                "request_max_tokens": _num(kwargs.get("max_tokens")),
                "request_stream": True if kwargs.get("stream") is True else None,
                "finish_reason": _s(_tel_get(result, "stop_reason")),
                "response_id": _s(_tel_get(result, "id")),
                "cache_read_tokens": _num(_tel_get(usage, "cache_read_input_tokens")),
                "cache_write_tokens": _num(_tel_get(usage, "cache_creation_input_tokens")),
            }
        elif provider == "google":
            gen = kwargs.get("generation_config") or kwargs.get("generationConfig") or {}
            meta = _tel_get(result, "usage_metadata", "usageMetadata") or {}
            cands = _tel_get(result, "candidates") or []
            finish = _tel_get(cands[0], "finish_reason", "finishReason") if cands else None
            vals = {
                "request_temperature": _num(_tel_get(gen, "temperature")),
                "request_top_p": _num(_tel_get(gen, "top_p", "topP")),
                "request_max_tokens": _num(_tel_get(gen, "max_output_tokens", "maxOutputTokens")),
                "request_stream": True if kwargs.get("stream") is True else None,
                "finish_reason": _s(str(finish)) if finish is not None else None,
                "cache_read_tokens": _num(_tel_get(meta, "cached_content_token_count")),
            }
        else:  # openai + openai-compatible (default)
            usage = _tel_get(result, "usage") or {}
            prompt_details = _tel_get(usage, "prompt_tokens_details") or {}
            completion_details = _tel_get(usage, "completion_tokens_details") or {}
            choices = _tel_get(result, "choices") or []
            finish = _tel_get(choices[0], "finish_reason") if choices else None
            vals = {
                "request_temperature": _num(kwargs.get("temperature")),
                "request_top_p": _num(kwargs.get("top_p")),
                "request_max_tokens": _num(
                    kwargs.get("max_tokens") or kwargs.get("max_completion_tokens")
                ),
                "request_stream": True if kwargs.get("stream") is True else None,
                "finish_reason": _s(finish),
                "response_id": _s(_tel_get(result, "id")),
                "system_fingerprint": _s(_tel_get(result, "system_fingerprint")),
                "reasoning_tokens": _num(_tel_get(completion_details, "reasoning_tokens")),
                "cache_read_tokens": _num(_tel_get(prompt_details, "cached_tokens")),
            }
        return {k: v for k, v in vals.items() if v is not None}
    except Exception:
        return {}


def _merge_telemetry(
    metadata: Optional[Dict[str, Any]], telemetry: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """Nest telemetry under the reserved metadata key (ingest lifts it back
    out to first-class summary fields). Never overwrites caller keys.

    It also never overwrites the RESERVED key, which it used to: assigning the
    channel wholesale discarded whatever an earlier step had already put there.
    Nothing lost a field to it by luck rather than design -- ``build_audit_event``
    re-derives ``floor_version``, and the canary bundle is stamped downstream --
    but "never overwrites" was written on a function that replaced the one
    channel every other evidence producer writes to.
    """
    if not telemetry:
        return metadata
    merged = dict(metadata or {})
    merged["obsvr_telemetry"] = {
        **(merged.get("obsvr_telemetry") or {}),
        **telemetry,
    }
    return merged


def _merge_post_call(event: Dict[str, Any], post: Dict[str, Any]) -> None:
    """Merge a post-call policy outcome onto the built event (twin of the TS
    mergePostCallOutcome): redacted STORED response, compliance overlay, and
    the response-side PII verdict as response_pii_* telemetry keys. The
    response returned to the caller is never modified."""
    if post.get("decision") == "redact_response" and post.get("redacted_response") is not None:
        event["response"] = post["redacted_response"]
    for k, v in (post.get("compliance") or {}).items():
        event[k] = v
    response_pii = post.get("response_pii")
    if response_pii:
        metadata = event.get("metadata") or {}
        telemetry = dict(metadata.get("obsvr_telemetry") or {})
        telemetry["response_pii_detected"] = response_pii["detected"]
        telemetry["response_pii_types"] = response_pii["types"]
        telemetry["response_pii_action"] = response_pii["action"]
        if response_pii.get("via") is not None:
            # Server-side normalizer mirror: which view defeated the obfuscation (key
            # absent for overt matches — TS mergePostCallOutcome parity).
            telemetry["response_pii_via"] = response_pii["via"]
        metadata["obsvr_telemetry"] = telemetry
        event["metadata"] = metadata

    canary_telemetry = post.get("canary_telemetry")
    if canary_telemetry:
        # CRITICAL canary evidence rides the reserved obsvr_telemetry channel
        # so it survives metadata trimming; only ids + hash prefixes, never a
        # token. TS mergePostCallOutcome parity.
        metadata = event.get("metadata") or {}
        telemetry = dict(metadata.get("obsvr_telemetry") or {})
        telemetry.update(canary_telemetry)
        metadata["obsvr_telemetry"] = telemetry
        event["metadata"] = metadata


# ── The interceptor ──────────────────────────────────────────────────────────


def _collect_metadata(options: Dict[str, Any], kwargs: dict) -> Dict[str, Any]:
    """Per-call metadata for policy context and event attribution.

    Sources, later wins: wrap() options (user_id, tenant_id, ...) then the
    obsvr_metadata kwarg, which is stripped before the request reaches the
    provider (the provider SDK would reject an unknown parameter).
    """
    meta: Dict[str, Any] = {}
    for k in ("user_id", "tenant_id", "session_id", "trace_id", "agent_run_id"):
        if options.get(k) is not None:
            meta[k] = options[k]
    extra = kwargs.pop("obsvr_metadata", None)
    if isinstance(extra, dict):
        meta.update(extra)
    return meta


def _extract_chunk_text(provider: str, chunk: Any) -> str:
    """Best-effort text delta from one streaming chunk (OpenAI/Anthropic)."""
    try:
        if provider == "openai":
            choices = getattr(chunk, "choices", None) or []
            if choices:
                legacy_text = getattr(choices[0], "text", None)
                if isinstance(legacy_text, str):
                    return legacy_text
                delta = getattr(choices[0], "delta", None)
                content = getattr(delta, "content", None) if delta else None
                return content or ""
        elif provider == "anthropic":
            delta = getattr(chunk, "delta", None)
            text = getattr(delta, "text", None) if delta else None
            return text or ""
        elif provider == "google":
            return _extract_response_text(provider, chunk)
    except Exception:
        pass
    return ""


def _extract_chunk_usage(chunk: Any) -> Dict[str, Optional[int]]:
    """Usage from a final streaming chunk when the provider includes it.

    Reads dict-shaped chunks as well as attribute-shaped ones; the old bare
    ``getattr`` silently missed every provider that yields plain dicts.
    """
    usage = getattr(chunk, "usage", None)
    if usage is None and isinstance(chunk, dict):
        usage = chunk.get("usage")
    if usage is None:
        usage = getattr(chunk, "usage_metadata", None)
        if usage is None and isinstance(chunk, dict):
            usage = chunk.get("usage_metadata") or chunk.get("usageMetadata")
    return read_token_usage(usage)


def _emit_stream_event(
    config: Any, provider: str, model: str, operation: str,
    options: Dict[str, Any], compliance: Dict[str, Any], stored_prompt: str,
    user_input: Optional[str], response_text: str,
    usage: Dict[str, Optional[int]], start: float,
    metadata: Optional[Dict[str, Any]] = None,
    error: Any = None,
) -> None:
    latency_ms = (time.monotonic() - start) * 1000
    event = build_audit_event(
        config, provider=provider, model=model, operation=operation,
        source="python_wrap", prompt=stored_prompt, response=response_text,
        success=error is None, latency_ms=latency_ms,
        input_tokens=usage["input_tokens"], output_tokens=usage["output_tokens"],
        total_tokens=usage["total_tokens"],
        options=options, compliance=compliance, user_input=user_input,
        metadata=metadata or None,
    )
    if error is not None:
        event["error_type"] = classify_error(error)
    else:
        post = apply_post_call_policy(response_text, event, config)
        _merge_post_call(event, post)
        _record_token_usage_for_rules(config, event)
        _stamp_cost(config, event)
    _emit_audit(config, event, compliance)


class _GovernedStream:
    """A governed stream that is still a STREAM, not a bare generator.

    THE DEFECT THIS FIXES. The streaming paths are generator functions, and
    returning one handed the caller a plain generator. A provider's stream object
    is also a context manager, so the documented, extremely common shape::

        with client.chat.completions.create(..., stream=True) as stream:
            for chunk in stream: ...

    raised ``TypeError: 'generator' object does not support the context manager
    protocol`` the moment obsvr was in the path. Calling ``obsvr.init()`` before
    constructing a client was therefore enough to break every caller written that
    way, including all LangChain streaming, which uses exactly that form. Not a
    governance defect — working code stopped working.

    Iteration goes through the accumulating generator, so the audit event is
    unaffected. Everything else delegates to the real stream: entering and
    exiting the context manager operate on the provider's object, where they
    close the underlying HTTP response, and ``__enter__`` hands back THIS object
    so chunks read inside the ``with`` block are still accumulated.

    Note ``close()`` also delegates. A bare generator has a ``close()`` of its
    own, so the previous return value satisfied ``hasattr(stream, "close")``
    while closing only the generator and leaving the provider's response open.
    """

    __slots__ = ("_obsvr_stream", "_obsvr_iter")

    def __init__(self, stream: Any, iterator: Any) -> None:
        object.__setattr__(self, "_obsvr_stream", stream)
        object.__setattr__(self, "_obsvr_iter", iterator)

    def __iter__(self) -> Any:
        return object.__getattribute__(self, "_obsvr_iter")

    def __next__(self) -> Any:
        return next(object.__getattribute__(self, "_obsvr_iter"))

    def __enter__(self) -> "_GovernedStream":
        stream = object.__getattribute__(self, "_obsvr_stream")
        enter = getattr(type(stream), "__enter__", None)
        if enter is not None:
            enter(stream)
        # Deliberately not the provider's return value: chunks have to keep
        # flowing through the accumulator or the audit event loses the response.
        return self

    def __exit__(self, *exc_info: Any) -> Any:
        stream = object.__getattribute__(self, "_obsvr_stream")
        exit_ = getattr(type(stream), "__exit__", None)
        if exit_ is not None:
            return exit_(stream, *exc_info)
        close = getattr(stream, "close", None)
        if callable(close):
            close()
        return False

    def __getattr__(self, name: str) -> Any:
        # Reached only for names not in __slots__, so this cannot recurse.
        return getattr(object.__getattribute__(self, "_obsvr_stream"), name)


class _GovernedAsyncStream:
    """The async twin of :class:`_GovernedStream`.

    ``async with`` on the async streaming path failed the same way, for the same
    reason: an async generator is not an async context manager.
    """

    __slots__ = ("_obsvr_stream", "_obsvr_iter")

    def __init__(self, stream: Any, iterator: Any) -> None:
        object.__setattr__(self, "_obsvr_stream", stream)
        object.__setattr__(self, "_obsvr_iter", iterator)

    def __aiter__(self) -> Any:
        return object.__getattribute__(self, "_obsvr_iter")

    async def __anext__(self) -> Any:
        return await object.__getattribute__(self, "_obsvr_iter").__anext__()

    async def __aenter__(self) -> "_GovernedAsyncStream":
        stream = object.__getattribute__(self, "_obsvr_stream")
        aenter = getattr(type(stream), "__aenter__", None)
        if aenter is not None:
            await aenter(stream)
        return self

    async def __aexit__(self, *exc_info: Any) -> Any:
        stream = object.__getattribute__(self, "_obsvr_stream")
        aexit = getattr(type(stream), "__aexit__", None)
        if aexit is not None:
            return await aexit(stream, *exc_info)
        close = getattr(stream, "close", None)
        if callable(close):
            result = close()
            if hasattr(result, "__await__"):
                await result
        return False

    def __getattr__(self, name: str) -> Any:
        return getattr(object.__getattribute__(self, "_obsvr_stream"), name)


def _wrap_stream_sync(
    stream: Any, config: Any, provider: str, model: str, operation: str,
    options: Dict[str, Any], compliance: Dict[str, Any], stored_prompt: str,
    user_input: Optional[str], start: float, metadata: Optional[Dict[str, Any]] = None,
):
    """Yield chunks unchanged while accumulating text; emit one audit event
    when the stream ends (or errors). Parity with the TS streaming wrap."""
    parts: list = []
    usage = {"input_tokens": None, "output_tokens": None, "total_tokens": None}
    try:
        for chunk in stream:
            parts.append(_extract_chunk_text(provider, chunk))
            u = _extract_chunk_usage(chunk)
            if u["total_tokens"] is not None or u["input_tokens"] is not None:
                usage = u
            yield chunk
    except Exception as err:
        _emit_stream_event(config, provider, model, operation, options,
                           compliance, stored_prompt, user_input,
                           "".join(parts), usage, start, metadata=metadata, error=err)
        raise
    _emit_stream_event(config, provider, model, operation, options,
                       compliance, stored_prompt, user_input,
                       "".join(parts), usage, start, metadata=metadata)


async def _wrap_stream_async(
    stream: Any, config: Any, provider: str, model: str, operation: str,
    options: Dict[str, Any], compliance: Dict[str, Any], stored_prompt: str,
    user_input: Optional[str], start: float, metadata: Optional[Dict[str, Any]] = None,
):
    parts: list = []
    usage = {"input_tokens": None, "output_tokens": None, "total_tokens": None}
    try:
        async for chunk in stream:
            parts.append(_extract_chunk_text(provider, chunk))
            u = _extract_chunk_usage(chunk)
            if u["total_tokens"] is not None or u["input_tokens"] is not None:
                usage = u
            yield chunk
    except Exception as err:
        _emit_stream_event(config, provider, model, operation, options,
                           compliance, stored_prompt, user_input,
                           "".join(parts), usage, start, metadata=metadata, error=err)
        raise
    _emit_stream_event(config, provider, model, operation, options,
                       compliance, stored_prompt, user_input,
                       "".join(parts), usage, start, metadata=metadata)


#: Attributes on a provider stream object that yield TEXT rather than events.
#: Read through the accumulator so a caller who never touches the raw event
#: stream still produces a response on the audit record.
_STREAM_TEXT_ITERABLES = frozenset({"text_stream", "text_deltas"})

#: Terminal getters that consume the remainder of a stream and return the
#: finished object. A caller who uses one of these instead of iterating is the
#: other documented shape, and it would otherwise record an empty response.
_STREAM_FINAL_GETTERS = frozenset(
    {"get_final_message", "get_final_text", "get_final_completion", "until_done"}
)


class _AccumulatingStream:
    """The provider's stream object, with every text-bearing surface counted.

    Delegates everything. The three surfaces it does not simply hand back are
    the ones that carry the response: iteration, the text-only iterables, and
    the terminal getters. Whichever the caller uses, the audit event gets a
    response; a caller who uses none of them gets an event with an empty one,
    which is true rather than assumed.
    """

    __slots__ = ("_obsvr_stream", "_obsvr_provider", "_obsvr_sink")

    def __init__(self, stream: Any, provider: str, sink: "_StreamSink") -> None:
        object.__setattr__(self, "_obsvr_stream", stream)
        object.__setattr__(self, "_obsvr_provider", provider)
        object.__setattr__(self, "_obsvr_sink", sink)

    def __iter__(self) -> Any:
        stream = object.__getattribute__(self, "_obsvr_stream")
        provider = object.__getattribute__(self, "_obsvr_provider")
        sink = object.__getattribute__(self, "_obsvr_sink")
        for event in stream:
            sink.note_event(provider, event)
            yield event

    async def __aiter__(self) -> Any:
        stream = object.__getattribute__(self, "_obsvr_stream")
        provider = object.__getattribute__(self, "_obsvr_provider")
        sink = object.__getattribute__(self, "_obsvr_sink")
        async for event in stream:
            sink.note_event(provider, event)
            yield event

    def __getattr__(self, name: str) -> Any:
        stream = object.__getattribute__(self, "_obsvr_stream")
        provider = object.__getattribute__(self, "_obsvr_provider")
        sink = object.__getattribute__(self, "_obsvr_sink")
        value = getattr(stream, name)

        if name in _STREAM_TEXT_ITERABLES:
            def _counted() -> Any:
                for piece in value:
                    sink.note_text(piece)
                    yield piece

            async def _counted_async() -> Any:
                async for piece in value:
                    sink.note_text(piece)
                    yield piece

            return _counted_async() if hasattr(value, "__aiter__") else _counted()

        if name in _STREAM_FINAL_GETTERS and callable(value):
            if inspect.iscoroutinefunction(value):
                async def _final_async(*a: Any, **k: Any) -> Any:
                    result = await value(*a, **k)
                    sink.note_final(provider, result)
                    return result
                return _final_async

            def _final(*a: Any, **k: Any) -> Any:
                result = value(*a, **k)
                sink.note_final(provider, result)
                return result
            return _final

        return value


class _StreamSink:
    """Collects what a governed ``.stream()`` produced and emits ONE event.

    Emission is idempotent: a caller who exits the context manager after
    already draining the stream must not produce a second record of one call.
    """

    __slots__ = ("parts", "usage", "emitted")

    def __init__(self) -> None:
        self.parts: List[str] = []
        self.usage: Dict[str, Optional[int]] = {
            "input_tokens": None, "output_tokens": None, "total_tokens": None
        }
        self.emitted = False

    def note_event(self, provider: str, event: Any) -> None:
        text = _extract_chunk_text(provider, event)
        if text:
            self.parts.append(text)
        u = _extract_chunk_usage(event)
        if u["total_tokens"] is not None or u["input_tokens"] is not None:
            self.usage = u

    def note_text(self, piece: Any) -> None:
        if isinstance(piece, str) and piece:
            self.parts.append(piece)

    def note_final(self, provider: str, result: Any) -> None:
        # A terminal getter returns the assembled object, which is a better
        # answer than the concatenation when both exist — it is what the
        # provider says it sent.
        if isinstance(result, str):
            if result:
                self.parts = [result]
            return
        text = _extract_response_text(provider, result)
        if text:
            self.parts = [text]
        u = _extract_usage(provider, result)
        if u["total_tokens"] is not None or u["input_tokens"] is not None:
            self.usage = u

    def text(self) -> str:
        return "".join(self.parts)


class _GovernedStreamManager:
    """A governed ``.stream()`` helper.

    THE HOLE THIS CLOSES. ``messages.stream()`` and its three siblings were not
    in the method table, so the proxy handed back the provider's own bound
    method and the pre-call pipeline never ran. On the SAME wrapped client, a
    ``pii_policy`` of ``{"ssn": "block"}`` refused ``create(stream=True)`` and
    did not refuse ``messages.stream(...)``: the request left the process with
    the SSN in it. That is an enforcement hole, not only the audit-coverage
    hole the coverage-boundary comment described.

    WHY THIS IS SO MUCH SIMPLER THAN THE TYPESCRIPT TWIN. There, the obstacle
    is that governance is asynchronous while ``.stream()`` must return its
    runner synchronously, so ``runner-wrapper.ts`` returns a stand-in and
    replays onto the real runner once governance resolves. Here the pipeline is
    synchronous and so is the helper, so the call is simply governed and then
    made — there is no window to defer across. The two SDKs reach the same
    guarantee by different means because the constraint is different, and this
    is the whole of it.

    Everything the provider owns is delegated: this enters and exits the real
    manager, hands back the real stream (behind the accumulator), and forwards
    every other attribute.
    """

    __slots__ = ("_obsvr_manager", "_obsvr_emit", "_obsvr_provider", "_obsvr_sink")

    def __init__(self, manager: Any, provider: str, emit: Callable) -> None:
        object.__setattr__(self, "_obsvr_manager", manager)
        object.__setattr__(self, "_obsvr_provider", provider)
        object.__setattr__(self, "_obsvr_emit", emit)
        object.__setattr__(self, "_obsvr_sink", _StreamSink())

    def _wrapped(self, stream: Any) -> "_AccumulatingStream":
        return _AccumulatingStream(
            stream,
            object.__getattribute__(self, "_obsvr_provider"),
            object.__getattribute__(self, "_obsvr_sink"),
        )

    def _settle(self, error: Any = None) -> None:
        sink = object.__getattribute__(self, "_obsvr_sink")
        if sink.emitted:
            return
        sink.emitted = True
        object.__getattribute__(self, "_obsvr_emit")(sink, error)

    def __enter__(self) -> "_AccumulatingStream":
        manager = object.__getattribute__(self, "_obsvr_manager")
        return self._wrapped(type(manager).__enter__(manager))

    def __exit__(self, *exc_info: Any) -> Any:
        manager = object.__getattribute__(self, "_obsvr_manager")
        try:
            return type(manager).__exit__(manager, *exc_info)
        finally:
            self._settle(exc_info[1] if len(exc_info) > 1 else None)

    async def __aenter__(self) -> "_AccumulatingStream":
        manager = object.__getattribute__(self, "_obsvr_manager")
        return self._wrapped(await type(manager).__aenter__(manager))

    async def __aexit__(self, *exc_info: Any) -> Any:
        manager = object.__getattribute__(self, "_obsvr_manager")
        try:
            return await type(manager).__aexit__(manager, *exc_info)
        finally:
            self._settle(exc_info[1] if len(exc_info) > 1 else None)

    def __getattr__(self, name: str) -> Any:
        return getattr(object.__getattribute__(self, "_obsvr_manager"), name)

    def __repr__(self) -> str:
        return f"<obsvr-governed {object.__getattribute__(self, '_obsvr_manager')!r}>"


def _note_raw_response_piece(sink: "_StreamSink", piece: Any) -> None:
    if isinstance(piece, bytes):
        sink.note_text(piece.decode("utf-8", errors="replace"))
    elif isinstance(piece, str):
        sink.note_text(piece)


class _ObservedStreamingResponse:
    """Delegating view over a provider ``APIResponse``.

    The caller keeps the raw-response interface (status, headers, read/parse,
    and iterators). The handful of methods that consume body content also feed
    the audit sink; every other attribute is returned untouched.
    """

    __slots__ = ("_obsvr_response", "_obsvr_provider", "_obsvr_sink")

    def __init__(self, response: Any, provider: str, sink: "_StreamSink") -> None:
        object.__setattr__(self, "_obsvr_response", response)
        object.__setattr__(self, "_obsvr_provider", provider)
        object.__setattr__(self, "_obsvr_sink", sink)

    def __getattr__(self, name: str) -> Any:
        response = object.__getattribute__(self, "_obsvr_response")
        provider = object.__getattribute__(self, "_obsvr_provider")
        sink = object.__getattribute__(self, "_obsvr_sink")
        value = getattr(response, name)

        if name == "parse" and callable(value):
            if inspect.iscoroutinefunction(value):
                async def _parse_async(*a: Any, **k: Any) -> Any:
                    result = await value(*a, **k)
                    sink.note_final(provider, result)
                    return result
                return _parse_async

            def _parse(*a: Any, **k: Any) -> Any:
                result = value(*a, **k)
                sink.note_final(provider, result)
                return result
            return _parse

        if name == "read" and callable(value):
            if inspect.iscoroutinefunction(value):
                async def _read_async(*a: Any, **k: Any) -> Any:
                    result = await value(*a, **k)
                    _note_raw_response_piece(sink, result)
                    return result
                return _read_async

            def _read(*a: Any, **k: Any) -> Any:
                result = value(*a, **k)
                _note_raw_response_piece(sink, result)
                return result
            return _read

        if name in {"iter_text", "iter_lines", "iter_bytes"} and callable(value):
            def _iter(*a: Any, **k: Any) -> Any:
                iterable = value(*a, **k)
                if hasattr(iterable, "__aiter__"):
                    async def _async_iter() -> Any:
                        async for piece in iterable:
                            _note_raw_response_piece(sink, piece)
                            yield piece
                    return _async_iter()

                def _sync_iter() -> Any:
                    for piece in iterable:
                        _note_raw_response_piece(sink, piece)
                        yield piece
                return _sync_iter()
            return _iter

        return value


class _GovernedResponseManager:
    """Govern a response-context accessor without advancing its request."""

    __slots__ = ("_obsvr_manager", "_obsvr_emit", "_obsvr_provider", "_obsvr_sink")

    def __init__(self, manager: Any, provider: str, emit: Callable) -> None:
        object.__setattr__(self, "_obsvr_manager", manager)
        object.__setattr__(self, "_obsvr_provider", provider)
        object.__setattr__(self, "_obsvr_emit", emit)
        object.__setattr__(self, "_obsvr_sink", _StreamSink())

    def _wrapped(self, response: Any) -> _ObservedStreamingResponse:
        return _ObservedStreamingResponse(
            response,
            object.__getattribute__(self, "_obsvr_provider"),
            object.__getattribute__(self, "_obsvr_sink"),
        )

    def _settle(self, error: Any = None) -> None:
        sink = object.__getattribute__(self, "_obsvr_sink")
        if sink.emitted:
            return
        sink.emitted = True
        object.__getattribute__(self, "_obsvr_emit")(sink, error)

    def __enter__(self) -> _ObservedStreamingResponse:
        manager = object.__getattribute__(self, "_obsvr_manager")
        try:
            return self._wrapped(type(manager).__enter__(manager))
        except Exception as error:
            self._settle(error)
            raise

    def __exit__(self, *exc_info: Any) -> Any:
        manager = object.__getattribute__(self, "_obsvr_manager")
        try:
            return type(manager).__exit__(manager, *exc_info)
        finally:
            self._settle(exc_info[1] if len(exc_info) > 1 else None)

    async def __aenter__(self) -> _ObservedStreamingResponse:
        manager = object.__getattribute__(self, "_obsvr_manager")
        try:
            response = await type(manager).__aenter__(manager)
            return self._wrapped(response)
        except Exception as error:
            self._settle(error)
            raise

    async def __aexit__(self, *exc_info: Any) -> Any:
        manager = object.__getattribute__(self, "_obsvr_manager")
        try:
            return await type(manager).__aexit__(manager, *exc_info)
        finally:
            self._settle(exc_info[1] if len(exc_info) > 1 else None)

    def __getattr__(self, name: str) -> Any:
        return getattr(object.__getattribute__(self, "_obsvr_manager"), name)


class _GovernedToolRunner:
    """Delegating sync/async runner that settles one model-run event."""

    __slots__ = ("_obsvr_runner", "_obsvr_emit", "_obsvr_provider", "_obsvr_sink")

    def __init__(self, runner: Any, provider: str, emit: Callable) -> None:
        object.__setattr__(self, "_obsvr_runner", runner)
        object.__setattr__(self, "_obsvr_provider", provider)
        object.__setattr__(self, "_obsvr_emit", emit)
        object.__setattr__(self, "_obsvr_sink", _StreamSink())

    def _settle(self, error: Any = None) -> None:
        sink = object.__getattribute__(self, "_obsvr_sink")
        if sink.emitted:
            return
        sink.emitted = True
        object.__getattribute__(self, "_obsvr_emit")(sink, error)

    def _observe(self, item: Any) -> Any:
        provider = object.__getattribute__(self, "_obsvr_provider")
        sink = object.__getattribute__(self, "_obsvr_sink")
        if any(callable(getattr(item, name, None)) for name in _STREAM_FINAL_GETTERS):
            return _AccumulatingStream(item, provider, sink)
        sink.note_final(provider, item)
        return item

    def __iter__(self) -> Any:
        runner = object.__getattribute__(self, "_obsvr_runner")
        try:
            for item in runner:
                yield self._observe(item)
        except Exception as error:
            self._settle(error)
            raise
        else:
            self._settle()

    def __next__(self) -> Any:
        runner = object.__getattribute__(self, "_obsvr_runner")
        try:
            return self._observe(next(runner))
        except StopIteration:
            self._settle()
            raise
        except Exception as error:
            self._settle(error)
            raise

    async def __aiter__(self) -> Any:
        runner = object.__getattribute__(self, "_obsvr_runner")
        try:
            async for item in runner:
                yield self._observe(item)
        except Exception as error:
            self._settle(error)
            raise
        else:
            self._settle()

    async def __anext__(self) -> Any:
        runner = object.__getattribute__(self, "_obsvr_runner")
        try:
            return self._observe(await runner.__anext__())
        except StopAsyncIteration:
            self._settle()
            raise
        except Exception as error:
            self._settle(error)
            raise

    def __getattr__(self, name: str) -> Any:
        runner = object.__getattribute__(self, "_obsvr_runner")
        value = getattr(runner, name)
        if name != "until_done" or not callable(value):
            return value
        if _is_async_callable(value):
            async def _until_done_async(*args: Any, **kwargs: Any) -> Any:
                try:
                    result = await value(*args, **kwargs)
                    self._observe(result)
                    self._settle()
                    return result
                except Exception as error:
                    self._settle(error)
                    raise
            return _until_done_async

        def _until_done(*args: Any, **kwargs: Any) -> Any:
            try:
                result = value(*args, **kwargs)
                self._observe(result)
                self._settle()
                return result
            except Exception as error:
                self._settle(error)
                raise
        return _until_done

    def __repr__(self) -> str:
        runner = object.__getattribute__(self, "_obsvr_runner")
        return f"<obsvr-governed {runner!r}>"


def _governed_stream_helper(
    original: Callable,
    target: Any,
    provider: str,
    method_path: str,
    options: Dict[str, Any],
    args: tuple,
    kwargs: dict,
) -> Any:
    """Govern one ``.stream()`` helper call, then make it."""
    config = get_config()
    operation = method_path

    pre = _govern_before_call(target, provider, operation, options, args, kwargs)

    start = time.monotonic()
    try:
        manager = original(*pre.args, **pre.kwargs)
    except Exception as err:
        latency_ms = (time.monotonic() - start) * 1000
        event = build_audit_event(
            config,
            provider=provider, model=pre.model, operation=operation,
            source="python_wrap", prompt=pre.stored_prompt, response="",
            success=False, error=err, latency_ms=latency_ms,
            options=options, compliance=pre.compliance,
            user_input=pre.user_input, metadata=pre.metadata or None,
        )
        event["error_type"] = classify_error(err)
        _emit_audit(config, event, pre.compliance)
        raise

    def _emit(sink: "_StreamSink", error: Any) -> None:
        _emit_stream_event(
            config, provider, pre.model, operation, options, pre.compliance,
            pre.stored_prompt, pre.user_input, sink.text(), sink.usage, start,
            metadata=pre.metadata, error=error,
        )

    return _GovernedStreamManager(manager, provider, _emit)


def _governed_deferred_response(
    original: Callable,
    target: Any,
    provider: str,
    method_path: str,
    options: Dict[str, Any],
    args: tuple,
    kwargs: dict,
) -> Any:
    """Govern a ``with_streaming_response`` accessor before context entry."""
    config = get_config()
    pre = _govern_before_call(target, provider, method_path, options, args, kwargs)
    start = time.monotonic()
    try:
        manager = original(*pre.args, **pre.kwargs)
    except Exception as error:
        _emit_stream_event(
            config, provider, pre.model, method_path, options, pre.compliance,
            pre.stored_prompt, pre.user_input, "",
            {"input_tokens": None, "output_tokens": None, "total_tokens": None},
            start, metadata=pre.metadata, error=error,
        )
        raise

    def _emit(sink: "_StreamSink", error: Any) -> None:
        _emit_stream_event(
            config, provider, pre.model, method_path, options, pre.compliance,
            pre.stored_prompt, pre.user_input, sink.text(), sink.usage, start,
            metadata=pre.metadata, error=error,
        )

    return _GovernedResponseManager(manager, provider, _emit)


def _governed_tool_runner(
    original: Callable,
    target: Any,
    provider: str,
    method_path: str,
    options: Dict[str, Any],
    args: tuple,
    kwargs: dict,
    governs_model_request: bool,
) -> Any:
    """Govern a provider runner before it snapshots prompts or tools."""
    from .integrations.provider_tool_runners import govern_runner_tools

    original = _runner_method_with_governed_client(original, target, options)

    call_kwargs = dict(kwargs)
    if "tools" in call_kwargs:
        call_kwargs["tools"] = list(call_kwargs["tools"])

    if not governs_model_request:
        if "tools" in call_kwargs:
            call_kwargs["tools"] = govern_runner_tools(
                call_kwargs["tools"], options
            )
        return original(*args, **call_kwargs)

    if "messages" in call_kwargs and not isinstance(call_kwargs["messages"], list):
        call_kwargs["messages"] = list(call_kwargs["messages"])

    config = get_config()
    pre = _govern_before_call(
        target, provider, method_path, options, args, call_kwargs
    )
    if "tools" in pre.kwargs:
        pre.kwargs["tools"] = govern_runner_tools(pre.kwargs["tools"], options)

    start = time.monotonic()
    try:
        runner = original(*pre.args, **pre.kwargs)
    except Exception as error:
        _emit_stream_event(
            config, provider, pre.model, method_path, options, pre.compliance,
            pre.stored_prompt, pre.user_input, "",
            {"input_tokens": None, "output_tokens": None, "total_tokens": None},
            start, metadata=pre.metadata, error=error,
        )
        raise

    def _emit(sink: "_StreamSink", error: Any) -> None:
        _emit_stream_event(
            config, provider, pre.model, method_path, options, pre.compliance,
            pre.stored_prompt, pre.user_input, sink.text(), sink.usage, start,
            metadata=pre.metadata, error=error,
        )

    return _GovernedToolRunner(runner, provider, _emit)


class _RunnerResourceReceiver:
    """Provider resource receiver that replaces only its retained client."""

    __slots__ = ("_target", "_governed_client")

    def __init__(self, target: Any, governed_client: Any):
        object.__setattr__(self, "_target", target)
        object.__setattr__(self, "_governed_client", governed_client)

    def __getattribute__(self, name: str) -> Any:
        if name == "_client":
            return object.__getattribute__(self, "_governed_client")
        if name in {"_target", "_governed_client"}:
            return object.__getattribute__(self, name)
        return getattr(object.__getattribute__(self, "_target"), name)


def _runner_method_with_governed_client(
    original: Callable, target: Any, options: Dict[str, Any]
) -> Callable:
    """Rebind a provider runner method so every retained model turn is governed."""
    try:
        raw_client = getattr(target, "_client")
    except Exception:  # noqa: BLE001 - test doubles and older resources omit it
        return original

    function = getattr(original, "__func__", None)
    if raw_client is None or function is None:
        return original

    receiver = _RunnerResourceReceiver(target, wrap(raw_client, **options))
    return function.__get__(receiver, type(target))


class _PreCall:
    """Everything the pre-call pipeline decided, for a call that is going out.

    Returned only when the call is permitted: a block raises out of
    :func:`_govern_before_call` rather than being reported here, so no caller
    can proceed by forgetting to check a flag.
    """

    __slots__ = ("compliance", "stored_prompt", "metadata", "args", "kwargs",
                 "model", "user_input")

    def __init__(self, compliance, stored_prompt, metadata, args, kwargs, model,
                 user_input):
        self.compliance = compliance
        self.stored_prompt = stored_prompt
        self.metadata = metadata
        self.args = args
        self.kwargs = kwargs
        self.model = model
        self.user_input = user_input


class _PreCallPlan:
    """A provider-free governance result consumed by the legacy wrapper."""

    __slots__ = (
        "disposition",
        "pre",
        "event",
        "error",
        "compliance",
        "classifications",
        "args",
        "kwargs",
    )

    def __init__(
        self,
        disposition,
        *,
        pre=None,
        event=None,
        error=None,
        compliance=None,
        classifications=(),
        args=(),
        kwargs=None,
    ):
        self.disposition = disposition
        self.pre = pre
        self.event = event
        self.error = error
        self.compliance = compliance
        self.classifications = tuple(sorted(set(classifications)))
        self.args = args
        self.kwargs = kwargs if kwargs is not None else {}


def _plan_classifications(compliance):
    return tuple(
        sorted(
            set(compliance.get("detected_types") or ())
            | set(compliance.get("redacted_types") or ())
            | set(compliance.get("blocked_types") or ())
        )
    )


def _build_direct_call_pre_call_plan(
    target: Any,
    provider: str,
    operation: str,
    options: Dict[str, Any],
    args: tuple,
    kwargs: dict,
) -> "_PreCallPlan":
    """Everything that must happen BEFORE the provider is contacted.

    Extracted so the request-shaped entry points share one implementation
    rather than one intention. ``create`` and the ``.stream()`` helpers are the
    same call with different return types, and the helpers had no pipeline at
    all — a second copy of this logic is how they would come to disagree again,
    which is the failure this SDK keeps finding in other people's code.

    A block or a redaction that could not be applied is returned as a blocked
    plan; the provider is never called. The compatibility consumer below emits
    the existing audit event and raises the stored policy error.
    """
    config = get_config()

    metadata = _collect_metadata(options, kwargs)
    request_text = _extract_prompt_text(provider, args, kwargs)
    retained_text = _google_chat_context_text(target) if provider == "google" else ""
    prompt_text = "\n".join(part for part in (retained_text, request_text) if part)
    model = _extract_model(provider, target, kwargs)

    policy = apply_pre_call_policy(
        prompt_text, config, provider=provider, operation=operation,
        metadata=metadata, model=model,
        scan_text=prompt_text,
        turn_text=_last_user_message_text(provider, args, kwargs),
    )
    compliance = policy["compliance"]
    security_normalized = policy.get("security_normalized")
    if security_normalized is not None:
        # Server-side normalizer mirror: seal which view defeated the obfuscation, so
        # "detection survived obfuscation" is itself on the audit record.
        metadata = {**(metadata or {}), "security_normalized": security_normalized}
    canary_telemetry = policy.get("canary_telemetry")
    if canary_telemetry is not None:
        # CRITICAL canary evidence on the reserved telemetry channel.
        _md = dict(metadata or {})
        _md["obsvr_telemetry"] = {**(_md.get("obsvr_telemetry") or {}), **canary_telemetry}
        metadata = _md
    floor_telemetry = policy.get("floor_telemetry")
    if floor_telemetry is not None:
        # Anti-tamper floor evidence (floor_version / floor_override_ignored).
        _md = dict(metadata or {})
        _md["obsvr_telemetry"] = {**(_md.get("obsvr_telemetry") or {}), **floor_telemetry}
        metadata = _md
    # Store the redacted prompt ONLY when we actually redacted; allowed/detect_only
    # keep the raw prompt (parity with TS) so detect_only still surfaces content.
    stored_prompt = policy["redacted_prompt"] if policy["decision"] == "redact" else prompt_text
    # ... and then vet what the DECISION never looked at. The scan above sees the
    # last user turn; `prompt_text` is every role concatenated, so system
    # instructions, earlier turns, assistant replies and tool results reached the
    # record raw under every configuration. This is what makes "still stored (and
    # redacted if configured)" true. It changes no verdict and no outbound bytes.
    stored_prompt, _stored_tel = redact_unscanned_for_storage(
        stored_prompt, _last_user_message_text(provider, args, kwargs), config
    )
    if _stored_tel is not None:
        _md = dict(metadata or {})
        _md["obsvr_telemetry"] = {**(_md.get("obsvr_telemetry") or {}), **_stored_tel}
        metadata = _md

    if policy["decision"] == "block":
        from .canary import CANARY_REDACTION_PLACEHOLDER
        event = build_audit_event(
            config,
            provider=provider, model=model, operation=operation,
            source="python_wrap",
            # Non-PII blocks store "[BLOCKED_BY_POLICY]"; PII blocks store the
            # redacted form — never the raw offending prompt (parity with TS).
            # A view-only hit stores a whole-text placeholder (no locatable span).
            # A canary block stores the canary placeholder (redact_builtin_pii
            # does not know the canary format, so it would leak the token).
            prompt=(
                CANARY_REDACTION_PLACEHOLDER
                if canary_telemetry is not None
                else blocked_prompt_for_storage(prompt_text, compliance, security_normalized)
            ),
            response="", status_code=403, success=False,
            options=options, compliance=compliance,
            # The block was triggered BY this content; ship it redacted, never raw.
            user_input=(
                CANARY_REDACTION_PLACEHOLDER
                if canary_telemetry is not None
                else redact_for_storage(
                    _last_user_message_text(provider, args, kwargs), security_normalized
                )
            ),
            metadata=metadata or None,
        )
        return _PreCallPlan(
            "blocked",
            event=event,
            error=blocked_call_error(compliance),
            compliance=compliance,
            classifications=_plan_classifications(compliance),
            args=args,
            kwargs=kwargs,
        )

    if policy["decision"] == "redact":
        # Enforcement application: a redaction that cannot be carried out blocks
        # the call rather than forwarding the content it was told to remove.
        _redacted_args = args
        # Presidio joins the OUTBOUND rewrite when one of the six types only it
        # can locate is what policy asked to remove. Until now it produced the
        # stored copy alone, so those types were scrubbed from the record and
        # forwarded to the provider under an event that said `redacted`.
        _redactor = outbound_redactor(config, compliance.get("redacted_types"))

        def _apply_redaction() -> None:
            nonlocal _redacted_args
            _redact_messages_in_place(provider, kwargs, _redactor)
            _redacted_args = _redact_positional_inputs(args, _redactor)
            if provider == "google":
                _redact_google_chat_context(target, _redactor)
            redacted_request = _extract_prompt_text(provider, _redacted_args, kwargs)
            redacted_retained = (
                _google_chat_context_text(target) if provider == "google" else ""
            )
            assert_redaction_applied(
                "\n".join(
                    part for part in (redacted_retained, redacted_request) if part
                ),
                compliance,
            )

        _not_redacted = apply_outbound_redaction(_apply_redaction)
        if _not_redacted is not None:
            compliance = outbound_redaction_blocked_compliance(compliance, _not_redacted)
            event = build_audit_event(
                config,
                provider=provider, model=model, operation=operation,
                source="python_wrap",
                prompt=blocked_prompt_for_storage(prompt_text, compliance, security_normalized),
                response="", status_code=403, success=False,
                options=options, compliance=compliance,
                user_input=redact_for_storage(
                    _last_user_message_text(provider, args, kwargs), security_normalized
                ),
                metadata=metadata or None,
            )
            return _PreCallPlan(
                "blocked",
                event=event,
                error=blocked_call_error(compliance),
                compliance=compliance,
                classifications=_plan_classifications(compliance),
                args=args,
                kwargs=kwargs,
            )
        args = _redacted_args

    return _PreCallPlan(
        "ready",
        pre=_PreCall(
            compliance=compliance,
            stored_prompt=stored_prompt,
            metadata=metadata,
            args=args,
            kwargs=kwargs,
            model=model,
            user_input=_last_user_message(kwargs),
        ),
        classifications=_plan_classifications(compliance),
        args=args,
        kwargs=kwargs,
    )


def _consume_pre_call_plan(plan: "_PreCallPlan", config: Any) -> "_PreCall":
    if plan.disposition == "ready" and plan.pre is not None:
        return plan.pre
    if plan.disposition != "blocked" or plan.event is None or plan.error is None:
        raise RuntimeError("obsvr: invalid pre-call governance plan")
    _emit_audit(config, plan.event, plan.compliance)
    raise plan.error


def _govern_before_call(target, provider, operation, options, args, kwargs):
    """Compatibility consumer preserving the legacy blocking exception."""
    return _consume_pre_call_plan(
        _build_direct_call_pre_call_plan(
            target, provider, operation, options, args, kwargs
        ),
        get_config(),
    )


def _governed_call(
    original: Callable,
    target: Any,
    provider: str,
    method_path: str,
    options: Dict[str, Any],
    args: tuple,
    kwargs: dict,
) -> Any:
    """Run the full governance pipeline around one provider call (sync)."""
    config = get_config()
    operation = method_path

    plan = _build_direct_call_pre_call_plan(
        target, provider, operation, options, args, kwargs
    )
    pre = _consume_pre_call_plan(plan, config)
    compliance = pre.compliance
    stored_prompt = pre.stored_prompt
    metadata = pre.metadata
    args = pre.args
    kwargs = pre.kwargs
    model = pre.model

    strict_capability = options.get("strict_receipt_v2_1")
    if strict_capability is not None and (
        kwargs.get("stream") or method_path in _DIRECT_STREAM_METHODS
    ):
        strict_provider_surface_unsupported_v2_1()

    start = time.monotonic()
    try:
        if strict_capability is not None:
            root_client = options.get("_obsvr_strict_root_client")
            recorded_provider, _attribution = resolve_destination(root_client, provider)
            strict_target = strict_provider_target_v2_1(root_client)
            invoked = {"args": args, "kwargs": kwargs}

            def _invoke_strict(invocation):
                nonlocal args, kwargs
                if strict_provider_target_v2_1(root_client) != strict_target:
                    raise ObsvrStrictProviderBoundaryV21Error(
                        "context_unavailable"
                    )
                args = tuple(invocation["args"])
                kwargs = dict(invocation["kwargs"])
                value = original(*args, **kwargs)
                if inspect.isawaitable(value):
                    close = getattr(value, "close", None)
                    if callable(close):
                        close()
                    strict_provider_surface_unsupported_v2_1()
                return value

            result = execute_strict_provider_call_v2_1(
                strict_capability,
                call={
                    "provider": recorded_provider,
                    "operation": method_path,
                    "model": model,
                    "target": strict_target,
                    "data_classifications": list(plan.classifications),
                },
                invocation=invoked,
                invoke=_invoke_strict,
            )
        else:
            result = original(*args, **kwargs)
    except Exception as err:
        if isinstance(err, ObsvrStrictProviderBoundaryV21Error):
            raise
        latency_ms = (time.monotonic() - start) * 1000
        event = build_audit_event(
            config,
            provider=provider, model=model, operation=operation,
            source="python_wrap", prompt=stored_prompt, response="",
            success=False, error=err, latency_ms=latency_ms,
            options=options, compliance=compliance,
            user_input=_last_user_message(kwargs), metadata=metadata or None,
        )
        event["error_type"] = classify_error(err)
        _emit_audit(config, event, compliance)
        raise

    # Streaming: hand back a wrapped iterator that accumulates chunks and
    # emits one audit event when the stream ends. Non-iterable results fall
    # through to the normal single-event path.
    if (
        (kwargs.get("stream") or method_path in _DIRECT_STREAM_METHODS)
        and hasattr(result, "__iter__")
        and not hasattr(result, "choices")
    ):
        return _GovernedStream(
            result,
            _wrap_stream_sync(
                result, config, provider, model, operation, options,
                compliance, stored_prompt, _last_user_message(kwargs), start,
                metadata,
            ),
        )

    latency_ms = (time.monotonic() - start) * 1000
    observed_result = _response_for_observation(method_path, result)
    response_text = _extract_response_text(provider, observed_result)
    usage = _extract_usage(provider, observed_result)
    metadata = _merge_telemetry(
        metadata, _extract_telemetry(provider, kwargs, observed_result)
    )
    metadata = with_span_metadata(metadata, span_envelope_for("llm_call", operation))

    event = build_audit_event(
        config,
        provider=provider, model=model, operation=operation,
        source="python_wrap", prompt=stored_prompt, response=response_text,
        success=True, latency_ms=latency_ms,
        input_tokens=usage["input_tokens"], output_tokens=usage["output_tokens"],
        total_tokens=usage["total_tokens"],
        options=options, compliance=compliance,
        user_input=_last_user_message(kwargs), metadata=metadata or None,
    )
    post = apply_post_call_policy(response_text, event, config)
    _merge_post_call(event, post)
    _record_token_usage_for_rules(config, event)
    _stamp_cost(config, event)
    _emit_audit(config, event, compliance)
    return result


async def _governed_call_async(
    original: Callable,
    target: Any,
    provider: str,
    method_path: str,
    options: Dict[str, Any],
    args: tuple,
    kwargs: dict,
) -> Any:
    """Async twin of _governed_call for AsyncOpenAI / AsyncAnthropic clients."""
    config = get_config()
    operation = method_path

    pre = _govern_before_call(target, provider, operation, options, args, kwargs)
    compliance = pre.compliance
    stored_prompt = pre.stored_prompt
    metadata = pre.metadata
    args = pre.args
    kwargs = pre.kwargs
    model = pre.model

    start = time.monotonic()
    try:
        result = await original(*args, **kwargs)
    except Exception as err:
        latency_ms = (time.monotonic() - start) * 1000
        event = build_audit_event(
            config, provider=provider, model=model, operation=operation,
            source="python_wrap", prompt=stored_prompt, response="",
            success=False, error=err, latency_ms=latency_ms,
            options=options, compliance=compliance,
            user_input=_last_user_message(kwargs), metadata=metadata or None,
        )
        event["error_type"] = classify_error(err)
        _emit_audit(config, event, compliance)
        raise

    if (
        (kwargs.get("stream") or method_path in _DIRECT_STREAM_METHODS)
        and hasattr(result, "__aiter__")
        and not hasattr(result, "choices")
    ):
        return _GovernedAsyncStream(
            result,
            _wrap_stream_async(
                result, config, provider, model, operation, options,
                compliance, stored_prompt, _last_user_message(kwargs), start,
                metadata,
            ),
        )

    latency_ms = (time.monotonic() - start) * 1000
    observed_result = _response_for_observation(method_path, result)
    response_text = _extract_response_text(provider, observed_result)
    usage = _extract_usage(provider, observed_result)
    metadata = _merge_telemetry(
        metadata, _extract_telemetry(provider, kwargs, observed_result)
    )
    metadata = with_span_metadata(metadata, span_envelope_for("llm_call", operation))

    event = build_audit_event(
        config, provider=provider, model=model, operation=operation,
        source="python_wrap", prompt=stored_prompt, response=response_text,
        success=True, latency_ms=latency_ms,
        input_tokens=usage["input_tokens"], output_tokens=usage["output_tokens"],
        total_tokens=usage["total_tokens"],
        options=options, compliance=compliance,
        user_input=_last_user_message(kwargs), metadata=metadata or None,
    )
    post = apply_post_call_policy(response_text, event, config)
    _merge_post_call(event, post)
    _record_token_usage_for_rules(config, event)
    _emit_audit(config, event, compliance)
    return result


# ── Recursive attribute proxy ────────────────────────────────────────────────

class _ObsvrProxyState(NamedTuple):
    target: Any
    path: List[str]
    provider: str
    options: Dict[str, Any]


_OBSVR_PROXY_STATES: "weakref.WeakKeyDictionary[Any, _ObsvrProxyState]" = (
    weakref.WeakKeyDictionary()
)


def _obsvr_proxy_state(proxy: Any) -> _ObsvrProxyState:
    try:
        return _OBSVR_PROXY_STATES[proxy]
    except (KeyError, TypeError) as error:
        raise RuntimeError("obsvr: invalid governed proxy state") from error


class _ObsvrProxy:
    """Attribute proxy mirroring the TS recursive Proxy.

    Wraps only the attribute chains that can reach an auditable method;
    everything else passes through by reference.
    """

    __slots__ = ("__weakref__",)

    def __getattribute__(self, name: str) -> Any:
        if name.startswith("_obsvr_"):
            raise AttributeError("obsvr proxy internals are not public")
        return object.__getattribute__(self, name)

    def __init__(self, target: Any, path: List[str], provider: str, options: Dict[str, Any]):
        _OBSVR_PROXY_STATES[self] = _ObsvrProxyState(target, path, provider, options)

    def __getattr__(self, name: str) -> Any:
        state = _obsvr_proxy_state(self)
        target = state.target
        path = state.path
        provider = state.provider
        options = state.options

        value = getattr(target, name)
        method_path = ".".join(path + [name])
        strict_capability = options.get("strict_receipt_v2_1")

        if (
            strict_capability is not None
            and callable(value)
            and method_path not in _STRICT_V2_1_DIRECT_METHODS
        ):
            return lambda *_args, **_kwargs: strict_provider_surface_unsupported_v2_1()

        if method_path in AUDITABLE_METHODS and callable(value):
            if _is_async_callable(value):
                if strict_capability is not None:
                    async def strict_async_unsupported(*_args: Any, **_kwargs: Any) -> Any:
                        strict_provider_surface_unsupported_v2_1()
                    return strict_async_unsupported
                async def async_intercepted(*args: Any, **kwargs: Any) -> Any:
                    return await _governed_call_async(
                        value, target, provider, method_path, options, args, kwargs
                    )
                return async_intercepted

            def intercepted(*args: Any, **kwargs: Any) -> Any:
                return _governed_call(
                    value, target, provider, method_path, options, args, kwargs
                )
            return intercepted

        if method_path in STREAM_HELPER_METHODS and callable(value):
            if strict_capability is not None:
                return lambda *_args, **_kwargs: strict_provider_surface_unsupported_v2_1()
            # Not split by iscoroutinefunction: the helper itself is synchronous
            # on both the sync and async clients — it is the MANAGER it returns
            # that differs, and _GovernedStreamManager speaks both protocols.
            def intercepted_stream(*args: Any, **kwargs: Any) -> Any:
                return _governed_stream_helper(
                    value, target, provider, method_path, options, args, kwargs
                )
            return intercepted_stream

        if method_path in DEFERRED_RESPONSE_METHODS and callable(value):
            if strict_capability is not None:
                return lambda *_args, **_kwargs: strict_provider_surface_unsupported_v2_1()
            # These methods are synchronous even on async clients: they return
            # an AsyncResponseContextManager whose request starts at __aenter__.
            def intercepted_response(*args: Any, **kwargs: Any) -> Any:
                return _governed_deferred_response(
                    value, target, provider, method_path, options, args, kwargs
                )
            return intercepted_response

        if method_path in GOVERNED_FACTORY_METHODS and callable(value):
            if strict_capability is not None:
                return lambda *_args, **_kwargs: strict_provider_surface_unsupported_v2_1()
            def intercepted_factory(*args: Any, **kwargs: Any) -> Any:
                result = value(*args, **kwargs)
                if provider == "google" and getattr(result, "_responder", None) is not None:
                    raise RuntimeError(
                        "[obsvr] Google automatic responder sessions are not "
                        "supported by this enforcement boundary"
                    )
                return _ObsvrProxy(result, [], provider, options)
            return intercepted_factory

        if method_path in TOOL_RUNNER_METHODS and callable(value):
            if strict_capability is not None:
                return lambda *_args, **_kwargs: strict_provider_surface_unsupported_v2_1()
            def intercepted_tool_runner(*args: Any, **kwargs: Any) -> Any:
                return _governed_tool_runner(
                    value, target, provider, method_path, options, args, kwargs,
                    TOOL_RUNNER_METHODS[method_path],
                )
            return intercepted_tool_runner

        # Strict mode must not return an unknown resource object raw: a method
        # below it could otherwise bypass the deny-by-default execution gate.
        primitive = isinstance(
            value, (str, bytes, bytearray, int, float, complex, bool, type(None))
        )
        if (
            (strict_capability is not None and not primitive and not callable(value))
            or (name in _TRAVERSABLE and value is not None and not callable(value))
        ):
            return _ObsvrProxy(value, path + [name], provider, options)

        return value

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(_obsvr_proxy_state(self).target, name, value)

    def __repr__(self) -> str:
        return f"<obsvr-wrapped {_obsvr_proxy_state(self).target!r}>"


def _is_async_callable(value: Any) -> bool:
    """Whether calling ``value`` produces a coroutine.

    ``inspect.iscoroutinefunction`` alone answers this WRONG for the async
    clients, and wrong in the direction that fabricates evidence. Both provider
    SDKs decorate ``create`` with a ``@required_args`` validator that is itself
    a plain function, so the async ``messages.create`` and
    ``chat.completions.create`` report False — the SYNC pipeline then ran on an
    async client and emitted an event with ``success: True``, an empty response
    and zero latency at the moment the coroutine was CONSTRUCTED, before the
    provider had been contacted and while the call could still fail. Nothing
    later corrected it. ``responses.create`` carries no such decorator, which is
    why that path was right and its siblings were not.

    ``inspect.unwrap`` follows the ``functools.wraps`` chain to the real
    coroutine function underneath. It is asked SECOND, so a genuinely
    synchronous method wrapped in a synchronous decorator still answers False.
    """
    if inspect.iscoroutinefunction(value):
        return True
    try:
        return inspect.iscoroutinefunction(inspect.unwrap(value))
    except Exception:  # noqa: BLE001 - a wrapper cycle is not an async method
        return False


def _resolves_to_callable(client: Any, path: str) -> bool:
    """Does ``path`` resolve to a callable on this client? Never raises.

    Walked on the RAW client, so it is unaffected by ``_TRAVERSABLE`` — that set
    decides what the PROXY descends into, and asking it here would report a
    client as covered because the proxy is willing to walk toward a method the
    client does not have.
    """
    cur = client
    for segment in path.split("."):
        if cur is None:
            return False
        try:
            cur = getattr(cur, segment)
        except Exception:  # noqa: BLE001 - a property that raises is not a surface
            # Provider SDKs build sub-resources in lazy properties. One that
            # raises on read is not a governed surface, and this probe must
            # never be the thing that breaks wrap().
            return False
    return callable(cur)


# Clients already reported. Weak, so holding one here cannot keep it alive.
_ungoverned_reported: "weakref.WeakSet[Any]" = weakref.WeakSet()


def _report_ungoverned_client(client: Any, provider: str, config: ResolvedConfig) -> None:
    """Report a ``wrap()`` that matched nothing.

    A configuration that is ACCEPTED is a configuration that is IN FORCE — the
    rule ``init()`` already applies to an unreadable config key, applied to the
    one remaining acceptance that silently governed nothing. Wrapping a client
    whose shape carries no auditable method returned a proxy that forwards every
    call through: no policy, no event, and nothing said. A caller reasonably
    concludes they are covered.

    WHY WARN, AND WHY ONCE PER CLIENT. Through the ``obsvr`` logger at WARNING,
    which is where every other init-time misconfiguration in this SDK speaks —
    a coverage gap must be visible without debug mode. Once per CLIENT rather
    than per call, because the condition is a property of the object: ``wrap()``
    decides it once, and a library that reprints it on every request is its own
    bug. Not once per process either — two differently-shaped clients are two
    separate gaps and each is worth naming.

    WHY NOT RAISE BY DEFAULT. Refusing turns a harmless wrap into an outage for
    a caller who was passing a client obsvr simply does not intercept: a
    framework object governed elsewhere, or a provider surface that is a
    documented coverage boundary. ``require_governed_surface`` is there for the
    deployment that wants the opposite trade, and it refuses at ``wrap()``
    rather than at first call so the failure lands at startup.

    Twin: ``reportUngovernedClient`` in sdk-typescript/src/proxy/wrapper.ts.
    """
    label = type(client).__name__
    message = (
        f"wrap() matched no governed method on this client ({label}; detected "
        f"shape: {provider}). The object it returned forwards every call "
        f"straight through - no policy runs and no audit event is emitted for "
        f"it, so this client is NOT covered. obsvr intercepts these paths: "
        f"{', '.join(sorted(_GOVERNED_METHODS))}. Wrap the provider client "
        f"itself (obsvr.wrap(OpenAI())), or govern this object through its own "
        f"integration. Pass require_governed_surface=True to obsvr.init() to "
        f"make this raise instead."
    )
    if getattr(config, "require_governed_surface", False):
        # RuntimeError, matching the "call init() before wrap()" refusal this
        # same function already raises — one wrap()-time failure type.
        raise RuntimeError(f"obsvr: {message}")
    try:
        if client in _ungoverned_reported:
            return
        _ungoverned_reported.add(client)
    except TypeError:
        # Not weak-referenceable or not hashable: report every time rather than
        # not at all. Silence is the failure this exists to remove.
        pass
    logging.getLogger("obsvr").warning("WARNING: %s", message)


def wrap(client: Any, **options: Any) -> Any:
    """Wrap an LLM client for automatic governance + audit.

    Usage:
        import obsvr
        from openai import OpenAI

        obsvr.init(api_key="...", ingest_url="https://...")
        client = obsvr.wrap(OpenAI())
        client.chat.completions.create(model="gpt-4o", messages=[...])

    Supported (duck-typed): OpenAI/AzureOpenAI (chat.completions.create,
    responses.create), Anthropic (messages.create), legacy Gemini
    GenerativeModel (generate_content), and the maintained google-genai Client
    (models.generate_content / aio.models.generate_content).
    Sync and async clients both work. Pass options like user_id=, region=,
    source= to stamp every audit event from this wrapper.

    A client on which no governed method path resolves is still wrapped and
    still works — but it is not covered, and that is reported once per client
    at WARNING rather than left to be inferred from absent traffic. Pass
    ``require_governed_surface=True`` to ``init()`` to make it raise instead.
    """
    if not is_initialized():
        raise RuntimeError("obsvr: call init() before wrap()")

    strict_capability = options.get("strict_receipt_v2_1")
    if strict_capability is not None:
        assert_strict_provider_boundary_v2_1(strict_capability)

    config: ResolvedConfig = get_config()
    if config.disabled:
        if strict_capability is not None:
            strict_provider_surface_unsupported_v2_1()
        return client

    # A copy that yielded to another SDK instance in this process passes the
    # client through: one governing instance, never two interceptions of the
    # same call. The stand-down was already reported once at init().
    from .config import _MODULE_INSTANCE_ID
    from .instance_guard import is_governing_instance

    if not is_governing_instance(_MODULE_INSTANCE_ID):
        if strict_capability is not None:
            strict_provider_surface_unsupported_v2_1()
        return client

    # ALREADY GOVERNED. register.py patches the openai and anthropic client
    # classes so construction already returns a governed client, and both
    # READMEs document init() and wrap() side by side — so a caller who
    # follows the documentation was wrapping a wrapped client and getting TWO
    # audit events for every call, plus double-counted cost and quota wherever
    # metering is on. TypeScript has carried a WRAPPED_MARKER check for
    # exactly this; this side had none. Same defect class as the framework
    # double-registration already fixed: one governed call, one audit record.
    #
    # The options this call carries survive that de-duplication. Under
    # auto-instrumentation the client a caller holds is ALREADY governed, so
    # ``wrap(client, user_id=...)`` is the documented way to attribute it and
    # was the one path where the principal never reached the pipeline: with
    # require_principal on, a call the caller had attributed was refused as
    # unattributed. Governance stays single-layer — the new proxy is built
    # around the INNER target, never around the proxy — while the options
    # merge, later winning, the way every other option channel resolves. A
    # wrap() that passes none returns the same object it was given.
    prior_options: Dict[str, Any] = {}
    prior_path: List[str] = []
    if isinstance(client, _ObsvrProxy):
        if not options:
            return client
        state = _obsvr_proxy_state(client)
        prior_options = state.options or {}
        prior_path = list(state.path or [])
        client = state.target

    # The client's SHAPE, which selects the extractors downstream.
    provider = _detect_provider(client)

    # WHERE the calls will go, which is what the record must name. Resolved
    # ONCE, at wrap time: a client's base URL is fixed when it is constructed,
    # so re-deriving it per call would buy nothing. The decision rides on the
    # options dict because that already reaches every emit site; `provider`
    # itself must stay the shape, or an Anthropic-shaped client on a non-vendor
    # host would lose its extractor along with its label.
    from .provider_attribution import (
        ATTRIBUTION_OPTION_KEY,
        RECORDED_PROVIDER_OPTION_KEY,
        resolve_destination,
    )

    # COVERAGE, decided here rather than discovered from missing traffic. The
    # proxy is built either way — a client with no governed method still gets a
    # transparent pass-through, which is what it got before — but the caller is
    # told instead of left to infer coverage from the fact that wrap() returned.
    if not any(_resolves_to_callable(client, p) for p in _GOVERNED_METHODS):
        _report_ungoverned_client(client, provider, config)

    recorded_provider, attribution = resolve_destination(client, provider)
    options = {**prior_options, **dict(options or {})}
    options["_obsvr_strict_root_client"] = client
    # Re-resolved from the client rather than carried over, so the reserved
    # destination keys can never be set by a caller passing them as options.
    options[RECORDED_PROVIDER_OPTION_KEY] = recorded_provider
    options[ATTRIBUTION_OPTION_KEY] = attribution

    # Gemini: generate_content sits directly on the model object
    if provider == "google" and hasattr(client, "generate_content"):
        return _ObsvrProxy(client, prior_path, provider, options)

    return _ObsvrProxy(client, prior_path, provider, options)
