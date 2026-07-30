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
    messages.create               anthropic 0.16.0  the anthropic extra's floor
    messages.parse                anthropic 0.77.0  structured outputs
    generate_content              google-generativeai  (see note)

Note on beta.messages.create: present from 0.8.0, then ABSENT 0.16.0 through
0.35.0, then present again from 0.36.0. That gap is upstream — the beta
namespace was dropped when that API graduated — not a coverage regression here.
Raise the anthropic extra to >=0.36.0 if the beta namespace has to be covered.

Note on generate_content: this is the LEGACY Google client, distribution
google-generativeai, declared as the `gemini` extra. Google's current SDK is a
separate distribution with a different response shape and is NOT governed here
— there is no detection for it and no adapter. Unlike the two clients above it
is not reached by obsvr.init() either; it needs an explicit obsvr.wrap().

Sync and async client methods are both supported: if the underlying method is
a coroutine function the wrapper is async, otherwise sync. The wrapped object
delegates every other attribute untouched.
"""

import copy as _copy
import inspect
import time
from typing import Any, Callable, Dict, List, Optional

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
    outbound_redaction_blocked_compliance,
    redact_builtin_pii,
)
from .sender import send_audit_async, should_sample
from .metering import record_token_usage_for_rules as _record_token_usage_for_rules
from .metering import stamp_cost as _stamp_cost
from .token_usage import read_token_usage


def _emit_audit(config: Any, event: Dict[str, Any], compliance: Dict[str, Any] = None) -> None:
    """Emit an audit event. Sampling (config.sample_rate) applies ONLY to clean
    allowed events. Governed events (blocked / redacted / flagged / PII-detected)
    and errors are forensic evidence and are NEVER dropped — EV-2 requires every
    governed call to emit exactly one audit event.

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
    )
    if governed or should_sample(config.sample_rate):
        send_audit_async(config, event)




#: COVERAGE BOUNDARY. Mirrors the TypeScript AUDITABLE_METHODS table, which
#: carries the full statement of what is excluded because it bears no chat text
#: (embeddings, images, audio, files, fine-tuning) versus what is text-bearing
#: but genuinely out of reach of a method-path table (the batch surfaces,
#: ``count_tokens``, and Gemini's ``start_chat``, whose ChatSession calls a
#: module-level function rather than a property on the proxied model, so no
#: property read on the proxy ever happens).
#:
#: CORRECTION, and it was a real one. This comment used to list the
#: ``.stream()`` helpers and the tool runners among the out-of-reach surfaces.
#: That is false, and TypeScript disproves it: the obstacle was never
#: reachability, it is that those helpers return their runner object
#: SYNCHRONOUSLY while the audited-method wrapper is async, so listing them in
#: a method table hands the caller a promise where the provider's contract
#: promises a stream object. TypeScript solved it with a deferred runner that
#: returns a stand-in immediately and reaches the provider only once governance
#: resolves, and now governs four ``.stream()`` paths and both tool runners.
#:
#: So on this side they are UNBUILT, not unreachable — the equivalent mechanism
#: has not been written here. The distinction matters because the old wording
#: closed the question. Measured: a real ``messages.stream()`` call through a
#: wrapped client emits ZERO events while its text accumulates normally.
#:
#: This is silent ABSENCE, not silent fabrication: no event is emitted, so
#: nothing claims the call was approved. It is a coverage hole, and it does not
#: put a false verdict on the record.
#:
#: The beta namespaces are enumerated rather than matched by stripping a
#: leading ``beta.`` segment, so a provider shipping a new beta namespace does
#: not silently widen governance without review.
AUDITABLE_METHODS = {
    "chat.completions.create",   # OpenAI / Azure OpenAI
    "chat.completions.parse",    # OpenAI structured outputs
    "responses.create",          # OpenAI Responses API
    "responses.parse",           # OpenAI Responses structured outputs
    "messages.create",           # Anthropic
    "messages.parse",            # Anthropic structured outputs
    "generate_content",          # Google Gemini, google-generativeai only
    "beta.messages.create",      # Anthropic beta
    "beta.responses.create",     # OpenAI Responses beta
    "beta.chat.completions.create",  # OpenAI chat beta
    "beta.chat.completions.parse",   # OpenAI chat beta
}

#: Attribute names that may lead to an auditable method. Everything else is
#: returned untouched, so we never wrap unrelated objects. "beta" earns its
#: place here for the two beta paths above: without it ``client.beta`` is
#: returned raw and every path beneath it is unreachable, which would leave
#: those entries as dead code.
_TRAVERSABLE = {"beta", "chat", "completions", "messages", "responses"}


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

def _extract_prompt_text(provider: str, args: tuple, kwargs: dict) -> str:
    """Pull all visible prompt text for PII/policy scanning."""
    parts: List[str] = []

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

    messages = kwargs.get("messages")
    if isinstance(messages, list):
        for msg in messages:
            content = msg.get("content") if isinstance(msg, dict) else getattr(msg, "content", None)
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and isinstance(block.get("text"), str):
                        parts.append(block["text"])

    # OpenAI Responses API: instructions + input (bare string or message list)
    instructions = kwargs.get("instructions")
    if isinstance(instructions, str):
        parts.append(instructions)
    input_val = kwargs.get("input")
    if isinstance(input_val, str):
        parts.append(input_val)
    elif isinstance(input_val, list):
        for item in input_val:
            content = item.get("content") if isinstance(item, dict) else getattr(item, "content", None)
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and isinstance(block.get("text"), str):
                        parts.append(block["text"])

    contents = kwargs.get("contents")
    if isinstance(contents, list):
        for item in contents:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                for p in item.get("parts", []):
                    if isinstance(p, str):
                        parts.append(p)
                    elif isinstance(p, dict) and isinstance(p.get("text"), str):
                        parts.append(p["text"])

    return "\n".join(parts)


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
    # Responses API bare-string input IS the user message.
    if isinstance(kwargs.get("input"), str):
        return kwargs["input"]
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
                    return " ".join(
                        b["text"] for b in content
                        if isinstance(b, dict) and isinstance(b.get("text"), str)
                    )

    # Responses API bare-string input: the whole input is the user turn.
    if isinstance(kwargs.get("input"), str):
        return kwargs["input"]

    # Gemini contents: last user turn's text parts
    contents = kwargs.get("contents")
    if isinstance(contents, list):
        for item in reversed(contents):
            if isinstance(item, dict) and item.get("role") == "user":
                return " ".join(
                    p["text"] for p in item.get("parts", [])
                    if isinstance(p, dict) and isinstance(p.get("text"), str)
                )

    # No identifiable user turn — fall back to the full prompt text.
    return _extract_prompt_text(provider, args, kwargs)


def _redact_text_blocks(blocks: list, redact_fn: Callable[[str], str]) -> list:
    """Redact {"text": ...} content blocks (Anthropic / Responses) into a NEW
    list of NEW dicts. See _redact_messages_in_place for why nothing here is
    written through: these blocks belong to the caller."""
    out = []
    for block in blocks:
        if isinstance(block, dict) and isinstance(block.get("text"), str):
            out.append({**block, "text": redact_fn(block["text"])})
        else:
            out.append(block)
    return out


def _redact_content_items(items: list, redact_fn: Callable[[str], str]) -> list:
    """Redact a Gemini contents list into a NEW list: string items and dict
    items with parts (string parts or {"text": ...} parts)."""
    out = []
    for item in items:
        if isinstance(item, str):
            out.append(redact_fn(item))
        elif isinstance(item, dict) and isinstance(item.get("parts"), list):
            parts = []
            for p in item["parts"]:
                if isinstance(p, str):
                    parts.append(redact_fn(p))
                elif isinstance(p, dict) and isinstance(p.get("text"), str):
                    parts.append({**p, "text": redact_fn(p["text"])})
                else:
                    parts.append(p)
            out.append({**item, "parts": parts})
        else:
            out.append(item)
    return out


def _rebuild_message(msg: Any, new_content: Any) -> Any:
    """Return a COPY of ``msg`` carrying ``new_content`` — never ``msg`` itself.

    A dict message becomes a plain dict, which is what the provider reads
    anyway; note this deliberately does not preserve a dict SUBCLASS, because a
    subclass that raises on ``__setitem__`` is precisely the shape a caller uses
    to say "do not write to me".

    A message OBJECT is copied with ``copy.copy`` so the provider's own type
    survives — substituting a dict would be rejected by a client that validates
    its argument. If the copy or the assignment fails, the ORIGINAL is returned
    untouched and this message goes out unredacted: the stored copy is still
    scrubbed by the event-build net, and corrupting a caller's object is not an
    acceptable price for redacting one field.
    """
    if isinstance(msg, dict):
        return {**msg, "content": new_content}
    try:
        clone = _copy.copy(msg)
        setattr(clone, "content", new_content)
        return clone
    except Exception:
        return msg


def _redact_messages_in_place(kwargs: dict, redact_fn: Callable[[str], str]) -> None:
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
                content = item.get("content")
                if isinstance(content, str):
                    rebuilt_input.append({**item, "content": redact_fn(content)})
                elif isinstance(content, list):
                    rebuilt_input.append(
                        {**item, "content": _redact_text_blocks(content, redact_fn)}
                    )
                else:
                    rebuilt_input.append(item)
            else:
                rebuilt_input.append(item)
        kwargs["input"] = rebuilt_input

    # Gemini keyword contents
    contents = kwargs.get("contents")
    if isinstance(contents, list):
        kwargs["contents"] = _redact_content_items(contents, redact_fn)


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
        _redact_content_items(first, redact_fn)
    return args


def _extract_model(provider: str, target: Any, kwargs: dict) -> str:
    model = kwargs.get("model")
    if isinstance(model, str):
        return model
    if provider == "google":
        return str(
            getattr(target, "model_name", None)
            or getattr(target, "_model_name", None)
            or "gemini"
        )
    return "unknown"


def _extract_response_text(provider: str, result: Any) -> str:
    try:
        if provider == "openai":
            choices = getattr(result, "choices", None) or (result.get("choices") if isinstance(result, dict) else None)
            if choices:
                first = choices[0]
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
                delta = getattr(choices[0], "delta", None)
                content = getattr(delta, "content", None) if delta else None
                return content or ""
        elif provider == "anthropic":
            delta = getattr(chunk, "delta", None)
            text = getattr(delta, "text", None) if delta else None
            return text or ""
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

    metadata = _collect_metadata(options, kwargs)
    prompt_text = _extract_prompt_text(provider, args, kwargs)
    model = _extract_model(provider, target, kwargs)

    policy = apply_pre_call_policy(
        prompt_text, config, provider=provider, operation=operation,
        metadata=metadata, model=model,
        scan_text=_last_user_message_text(provider, args, kwargs),
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
        _emit_audit(config, event, compliance)
        raise blocked_call_error(compliance)

    if policy["decision"] == "redact":
        # Enforcement application: a redaction that cannot be carried out blocks
        # the call rather than forwarding the content it was told to remove.
        _redacted_args = args

        def _apply_redaction() -> None:
            nonlocal _redacted_args
            _redact_messages_in_place(kwargs, redact_builtin_pii)
            _redacted_args = _redact_positional_inputs(args, redact_builtin_pii)

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
            _emit_audit(config, event, compliance)
            raise blocked_call_error(compliance)
        args = _redacted_args

    start = time.monotonic()
    try:
        result = original(*args, **kwargs)
    except Exception as err:
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
    if kwargs.get("stream") and hasattr(result, "__iter__") and not hasattr(result, "choices"):
        return _GovernedStream(
            result,
            _wrap_stream_sync(
                result, config, provider, model, operation, options,
                compliance, stored_prompt, _last_user_message(kwargs), start,
                metadata,
            ),
        )

    latency_ms = (time.monotonic() - start) * 1000
    response_text = _extract_response_text(provider, result)
    usage = _extract_usage(provider, result)
    metadata = _merge_telemetry(metadata, _extract_telemetry(provider, kwargs, result))
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
    metadata = _collect_metadata(options, kwargs)
    prompt_text = _extract_prompt_text(provider, args, kwargs)
    model = _extract_model(provider, target, kwargs)

    policy = apply_pre_call_policy(
        prompt_text, config, provider=provider, operation=operation,
        metadata=metadata, model=model,
        scan_text=_last_user_message_text(provider, args, kwargs),
    )
    compliance = policy["compliance"]
    security_normalized = policy.get("security_normalized")
    if security_normalized is not None:
        # Server-side normalizer mirror: seal which view defeated the obfuscation.
        metadata = {**(metadata or {}), "security_normalized": security_normalized}
    canary_telemetry = policy.get("canary_telemetry")
    if canary_telemetry is not None:
        _md = dict(metadata or {})
        _md["obsvr_telemetry"] = {**(_md.get("obsvr_telemetry") or {}), **canary_telemetry}
        metadata = _md
    floor_telemetry = policy.get("floor_telemetry")
    if floor_telemetry is not None:
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
            config, provider=provider, model=model, operation=operation,
            source="python_wrap",
            # A view-only hit stores a whole-text placeholder (no locatable span);
            # a canary block stores the canary placeholder (never the raw token).
            prompt=(
                CANARY_REDACTION_PLACEHOLDER
                if canary_telemetry is not None
                else blocked_prompt_for_storage(prompt_text, compliance, security_normalized)
            ),
            response="", status_code=403, success=False,
            options=options, compliance=compliance,
            user_input=(
                CANARY_REDACTION_PLACEHOLDER
                if canary_telemetry is not None
                else redact_for_storage(
                    _last_user_message_text(provider, args, kwargs), security_normalized
                )
            ),
            metadata=metadata or None,
        )
        _emit_audit(config, event, compliance)
        raise blocked_call_error(compliance)

    if policy["decision"] == "redact":
        # Enforcement application: a redaction that cannot be carried out blocks
        # the call rather than forwarding the content it was told to remove.
        _redacted_args = args

        def _apply_redaction() -> None:
            nonlocal _redacted_args
            _redact_messages_in_place(kwargs, redact_builtin_pii)
            _redacted_args = _redact_positional_inputs(args, redact_builtin_pii)

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
            _emit_audit(config, event, compliance)
            raise blocked_call_error(compliance)
        args = _redacted_args

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

    if kwargs.get("stream") and hasattr(result, "__aiter__") and not hasattr(result, "choices"):
        return _GovernedAsyncStream(
            result,
            _wrap_stream_async(
                result, config, provider, model, operation, options,
                compliance, stored_prompt, _last_user_message(kwargs), start,
                metadata,
            ),
        )

    latency_ms = (time.monotonic() - start) * 1000
    response_text = _extract_response_text(provider, result)
    usage = _extract_usage(provider, result)
    metadata = _merge_telemetry(metadata, _extract_telemetry(provider, kwargs, result))
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

class _ObsvrProxy:
    """Attribute proxy mirroring the TS recursive Proxy.

    Wraps only the attribute chains that can reach an auditable method;
    everything else passes through by reference.
    """

    __slots__ = ("_obsvr_target", "_obsvr_path", "_obsvr_provider", "_obsvr_options")

    def __init__(self, target: Any, path: List[str], provider: str, options: Dict[str, Any]):
        object.__setattr__(self, "_obsvr_target", target)
        object.__setattr__(self, "_obsvr_path", path)
        object.__setattr__(self, "_obsvr_provider", provider)
        object.__setattr__(self, "_obsvr_options", options)

    def __getattr__(self, name: str) -> Any:
        target = object.__getattribute__(self, "_obsvr_target")
        path = object.__getattribute__(self, "_obsvr_path")
        provider = object.__getattribute__(self, "_obsvr_provider")
        options = object.__getattribute__(self, "_obsvr_options")

        value = getattr(target, name)
        method_path = ".".join(path + [name])

        if method_path in AUDITABLE_METHODS and callable(value):
            if inspect.iscoroutinefunction(value):
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

        # Keep walking only down chains that can reach an auditable method
        if name in _TRAVERSABLE and value is not None and not callable(value):
            return _ObsvrProxy(value, path + [name], provider, options)

        return value

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(object.__getattribute__(self, "_obsvr_target"), name, value)

    def __repr__(self) -> str:
        return f"<obsvr-wrapped {object.__getattribute__(self, '_obsvr_target')!r}>"


def wrap(client: Any, **options: Any) -> Any:
    """Wrap an LLM client for automatic governance + audit.

    Usage:
        import obsvr
        from openai import OpenAI

        obsvr.init(api_key="...", ingest_url="https://...")
        client = obsvr.wrap(OpenAI())
        client.chat.completions.create(model="gpt-4o", messages=[...])

    Supported (duck-typed): OpenAI/AzureOpenAI (chat.completions.create,
    responses.create), Anthropic (messages.create), Gemini GenerativeModel
    (generate_content).
    Sync and async clients both work. Pass options like user_id=, region=,
    source= to stamp every audit event from this wrapper.
    """
    if not is_initialized():
        raise RuntimeError("obsvr: call init() before wrap()")
    # ALREADY GOVERNED -> hand it straight back. register.py patches the openai
    # and anthropic client classes so construction already returns a governed
    # client, and both READMEs document init() and wrap() side by side — so a
    # caller who follows the documentation was wrapping a wrapped client and
    # getting TWO audit events for every call, plus double-counted cost and
    # quota wherever metering is on. TypeScript has carried a WRAPPED_MARKER
    # check for exactly this; this side had none. Same defect class as the
    # framework double-registration already fixed: one governed call, one
    # audit record.
    if isinstance(client, _ObsvrProxy):
        return client

    config: ResolvedConfig = get_config()
    if config.disabled:
        return client

    # A copy that yielded to another SDK instance in this process passes the
    # client through: one governing instance, never two interceptions of the
    # same call. The stand-down was already reported once at init().
    from .config import _MODULE_INSTANCE_ID
    from .instance_guard import is_governing_instance

    if not is_governing_instance(_MODULE_INSTANCE_ID):
        return client

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

    recorded_provider, attribution = resolve_destination(client, provider)
    options = dict(options or {})
    options[RECORDED_PROVIDER_OPTION_KEY] = recorded_provider
    options[ATTRIBUTION_OPTION_KEY] = attribution

    # Gemini: generate_content sits directly on the model object
    if provider == "google" and hasattr(client, "generate_content"):
        return _ObsvrProxy(client, [], provider, options)

    return _ObsvrProxy(client, [], provider, options)
