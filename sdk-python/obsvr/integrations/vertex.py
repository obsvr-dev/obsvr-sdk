"""Google Vertex AI (Python) integration — governs a GenerativeModel.

Parity with sdk-typescript/src/integrations/vertex.ts. Wraps a Vertex AI
``GenerativeModel`` (``vertexai.generative_models.GenerativeModel`` or
``google.cloud.aiplatform``'s equivalent) and governs ``generate_content``
(and its streaming form ``generate_content`` with ``stream=True``, plus
``generate_content_async`` when present).

Real enforcement, both sides of the call:

- PRE-call: the complete provider-bound prompt is scanned/rule-checked. A
  ``block`` verdict raises *before* the model is ever called; a ``redact``
  verdict sends a redacted copy or fails closed when configured model state
  cannot be rewritten safely.
- POST-call: the model OUTPUT is run through the post-call policy; a redact
  verdict rewrites the returned candidates' text in place so the caller gets
  the governed output.

Usage::

    import vertexai, obsvr
    from vertexai.generative_models import GenerativeModel
    from obsvr.integrations.vertex import wrap_vertex

    obsvr.init(api_key="...", ingest_url="https://...")
    vertexai.init(project="...", location="...")
    model = wrap_vertex(GenerativeModel("gemini-1.5-pro"))
    model.generate_content("Summarize this document ...")
"""

# Interception: delegating object wrapper (non-mutating). The underlying
# GenerativeModel is never modified; wrap_vertex returns a wrapper whose
# generate_content methods run the obsvr pipeline, delegating every other
# attribute to the real model.

import copy
import inspect
import time
from typing import Any, Dict, List, Optional

from .. import sender as _sender
from ..config import try_get_config
from ..events import blocked_call_error, emit_event
from ..deobfuscate import redact_for_storage
from ..token_usage import read_token_usage
from ..policy import (
    apply_post_call_policy,
    apply_pre_call_policy,
    blocked_prompt_for_storage,
    blocked_user_input_for_storage,
    apply_outbound_redaction,
    assert_redaction_applied,
    outbound_redaction_blocked_compliance,
    redact_builtin_pii,
)

from ..binding_report import record_binding

try:  # stable namespace in current google-cloud-aiplatform releases
    from vertexai.generative_models import (  # type: ignore  # noqa: F401
        GenerativeModel as _RealGenerativeModel,
    )

    record_binding("vertex", "vertexai.generative_models.GenerativeModel")
except Exception as _stable_bind_exc:  # pragma: no cover - version-dependent import
    try:  # declared floor exposed the same model through the preview namespace
        from vertexai.preview.generative_models import (  # type: ignore  # noqa: F401
            GenerativeModel as _RealGenerativeModel,
        )

        record_binding("vertex", "vertexai.preview.generative_models.GenerativeModel")
    except Exception:  # pragma: no cover - Vertex SDK not installed
        _RealGenerativeModel = None  # type: ignore
        record_binding(
            "vertex", "vertexai.generative_models.GenerativeModel", _stable_bind_exc
        )

SOURCE = "vertex_py"
PROVIDER = "vertex_ai"
_WRAPPED_ATTR = "_obsvr_vertex_wrapped"

_GOVERNED_METHODS = {
    "generate_content",
    "generate_content_async",
    "send_message",
    "send_message_async",
}
_GOVERNED_FACTORIES = {"start_chat"}


# ---------------------------------------------------------------------------
# Request extraction — Vertex "contents" mirror the Gemini shape.
# ---------------------------------------------------------------------------


def _part_text(part: Any) -> str:
    if isinstance(part, str):
        return part
    if isinstance(part, dict):
        t = part.get("text")
        return t if isinstance(t, str) else ""
    t = getattr(part, "text", None)
    return t if isinstance(t, str) else ""


def _content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, (list, tuple)):
        return "\n".join(filter(None, (_content_text(item) for item in content)))
    if isinstance(content, dict):
        text = content.get("text")
        if isinstance(text, str):
            return text
        parts = content.get("parts")
        if parts is not None:
            return _content_text(parts)
        structured: List[str] = []
        for key in ("function_response", "functionResponse"):
            value = content.get(key)
            if isinstance(value, dict):
                _append_string_leaves(value.get("response"), structured)
        for key in ("function_call", "functionCall"):
            value = content.get(key)
            if isinstance(value, dict):
                _append_string_leaves(value.get("args"), structured)
        return "\n".join(structured)
    else:
        serialized = _content_dict(content)
        if serialized is not None:
            return _content_text(serialized)
        parts = getattr(content, "parts", None)
    if isinstance(parts, list):
        return "\n".join(t for t in (_part_text(p) for p in parts) if t)
    return ""


def _append_string_leaves(value: Any, out: List[str]) -> None:
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _append_string_leaves(item, out)
    elif isinstance(value, dict):
        for item in value.values():
            _append_string_leaves(item, out)


def _all_string_text(value: Any) -> str:
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        value = to_dict()
    out: List[str] = []
    _append_string_leaves(value, out)
    return "\n".join(out)


def _content_role(content: Any) -> str:
    if isinstance(content, dict):
        return str(content.get("role") or "user")
    return str(getattr(content, "role", None) or "user")


def _normalize_contents(request: Any) -> List[Any]:
    """generate_content accepts a str, a Part/Content, or a list of them."""
    if request is None:
        return []
    if isinstance(request, (list, tuple)):
        return list(request)
    return [request]


def _extract_prompt(request: Any) -> str:
    contents = _normalize_contents(request)
    parts: List[str] = []
    for c in contents:
        if isinstance(c, str):
            parts.append(f"user: {c}")
        else:
            parts.append(f"{_content_role(c)}: {_content_text(c)}")
    return "\n".join(p for p in parts if p.strip() not in ("user:", ""))


def _extract_last_user(request: Any) -> str:
    contents = _normalize_contents(request)
    for c in reversed(contents):
        if isinstance(c, str):
            return c
        if _content_role(c) in ("user", "human"):
            return _content_text(c)
    # No explicit user role: fall back to the last content's text.
    if contents:
        last = contents[-1]
        return last if isinstance(last, str) else _content_text(last)
    return ""


def _rebuild_content(value: Any, updates: Dict[str, Any]) -> Any:
    model_copy = getattr(value, "model_copy", None)
    if callable(model_copy):
        return model_copy(update=updates)
    try:
        clone = copy.copy(value)
        for key, replacement in updates.items():
            setattr(clone, key, replacement)
        return clone
    except Exception as err:
        raise TypeError("Vertex content could not be copied for outbound redaction") from err


def _content_dict(value: Any) -> Optional[Dict[str, Any]]:
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


def _redact_content(value: Any) -> Any:
    if isinstance(value, str):
        return redact_builtin_pii(value)
    if isinstance(value, list):
        return [_redact_content(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_content(item) for item in value)
    if isinstance(value, dict):
        if isinstance(value.get("text"), str):
            return {**value, "text": redact_builtin_pii(value["text"])}
        if value.get("parts") is not None:
            return {**value, "parts": _redact_content(value["parts"])}
        out = dict(value)
        for key in ("function_response", "functionResponse"):
            item = value.get(key)
            if isinstance(item, dict) and "response" in item:
                out[key] = {
                    **item,
                    "response": _redact_string_leaves(item["response"]),
                }
        for key in ("function_call", "functionCall"):
            item = value.get(key)
            if isinstance(item, dict) and "args" in item:
                out[key] = {**item, "args": _redact_string_leaves(item["args"])}
        return out
    from_dict = getattr(value, "from_dict", None)
    serialized = _content_dict(value)
    if serialized is not None and callable(from_dict):
        return from_dict(_redact_content(serialized))
    text = getattr(value, "text", None)
    if isinstance(text, str):
        return _rebuild_content(value, {"text": redact_builtin_pii(text)})
    parts = getattr(value, "parts", None)
    if parts is not None:
        return _rebuild_content(value, {"parts": _redact_content(parts)})
    return value


def _redact_string_leaves(value: Any) -> Any:
    if isinstance(value, str):
        return redact_builtin_pii(value)
    if isinstance(value, list):
        return [_redact_string_leaves(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_string_leaves(item) for item in value)
    if isinstance(value, dict):
        return {key: _redact_string_leaves(item) for key, item in value.items()}
    return value


def _redact_request(request: Any) -> Any:
    """Return provider-compatible redacted copies without mutating caller input."""
    return _redact_content(request)


def _model_system_instruction(model: Any) -> Any:
    for candidate in (model, getattr(model, "_model", None)):
        if candidate is None:
            continue
        for attr in ("_system_instruction", "system_instruction"):
            value = getattr(candidate, attr, None)
            if value is not None:
                return value
    return None


def _retained_history(model: Any) -> Any:
    for attr in ("_history", "history"):
        value = getattr(model, attr, None)
        if value is not None:
            return value
    return None


def _model_carriers(model: Any) -> List[Any]:
    carriers: List[Any] = []
    for candidate in (model, getattr(model, "_model", None)):
        if candidate is not None and all(candidate is not item for item in carriers):
            carriers.append(candidate)
    return carriers


def _cached_context_text(model: Any) -> str:
    for carrier in _model_carriers(model):
        cached = getattr(carrier, "_cached_content", None)
        if cached is None:
            cached = getattr(carrier, "cached_content", None)
        if cached is None:
            continue
        raw = getattr(cached, "_raw_cached_content", None) or cached
        parts: List[str] = []
        for attr in ("system_instruction", "systemInstruction", "contents"):
            value = raw.get(attr) if isinstance(raw, dict) else getattr(raw, attr, None)
            text = _content_text(value)
            if text:
                parts.append(text)
        if parts:
            return "\n".join(parts)
        raise RuntimeError(
            "[obsvr] Vertex cached context is opaque and cannot be verified"
        )
    return ""


def _tools_context_text(model: Any) -> str:
    parts: List[str] = []
    for carrier in _model_carriers(model):
        for attr in ("_tools", "tools"):
            value = getattr(carrier, attr, None)
            if value is not None:
                text = _all_string_text(value)
                if text:
                    parts.append(text)
    return "\n".join(parts)


def _redact_model_context(model: Any) -> None:
    for carrier in _model_carriers(model):
        if (
            getattr(carrier, "_cached_content", None) is not None
            or getattr(carrier, "cached_content", None) is not None
        ):
            raise TypeError("Vertex cached context cannot be redacted in place")
        history = getattr(carrier, "_history", None)
        if history is not None:
            setattr(carrier, "_history", _redact_content(history))
        for attr in ("_system_instruction", "system_instruction"):
            value = getattr(carrier, attr, None)
            if value is not None:
                raise TypeError(
                    "Vertex model system instructions cannot be redacted "
                    "without mutation"
                )
        for attr in ("_tools", "tools"):
            value = getattr(carrier, attr, None)
            if value is not None:
                raise TypeError(
                    "Vertex model tools cannot be redacted without mutation"
                )


# ---------------------------------------------------------------------------
# Response extraction
# ---------------------------------------------------------------------------


def _candidates(response: Any) -> List[Any]:
    if isinstance(response, dict):
        cands = response.get("candidates")
    else:
        cands = getattr(response, "candidates", None)
    return cands if isinstance(cands, list) else []


def _extract_response_text(response: Any) -> str:
    # Aggregated .text convenience accessor (present on real GenerationResponse).
    direct = getattr(response, "text", None) if not isinstance(response, dict) else response.get("text")
    if isinstance(direct, str) and direct:
        return direct
    out: List[str] = []
    for cand in _candidates(response):
        content = cand.get("content") if isinstance(cand, dict) else getattr(cand, "content", None)
        t = _content_text(content)
        if t:
            out.append(t)
    return "\n".join(out)


def _usage(response: Any) -> Dict[str, Optional[int]]:
    um = getattr(response, "usage_metadata", None) if not isinstance(response, dict) else response.get("usage_metadata")
    return read_token_usage(um)


def _resolved_model(response: Any) -> Optional[str]:
    v = getattr(response, "model_version", None) if not isinstance(response, dict) else response.get("model_version")
    return v.strip() if isinstance(v, str) and v.strip() else None


def _redact_response_inplace(response: Any, via: Optional[str] = None) -> None:
    # A view-only hit (via present) has no locatable span: text fields become
    # whole-text placeholders instead of a silently no-op span redaction.
    for cand in _candidates(response):
        content = cand.get("content") if isinstance(cand, dict) else getattr(cand, "content", None)
        parts = content.get("parts") if isinstance(content, dict) else getattr(content, "parts", None)
        if isinstance(parts, list):
            for p in parts:
                if isinstance(p, dict) and isinstance(p.get("text"), str):
                    p["text"] = redact_for_storage(p["text"], via)
                elif isinstance(getattr(p, "text", None), str):
                    try:
                        p.text = redact_for_storage(p.text, via)
                    except Exception:
                        pass


# ---------------------------------------------------------------------------
# The wrapper
# ---------------------------------------------------------------------------


class _GovernedGenerativeModel:
    def __init__(self, model: Any, options: Dict[str, Any]) -> None:
        object.__setattr__(self, "_model", model)
        object.__setattr__(self, "_options", options or {})

    def __getattr__(self, name: str) -> Any:
        target = getattr(object.__getattribute__(self, "_model"), name)
        if name in _GOVERNED_FACTORIES and callable(target):
            def governed_factory(*args: Any, **kwargs: Any) -> Any:
                result = target(*args, **kwargs)
                if getattr(result, "_responder", None) is not None:
                    raise RuntimeError(
                        "[obsvr] Vertex automatic responder sessions are not "
                        "supported by this enforcement boundary"
                    )
                return _GovernedGenerativeModel(
                    result, object.__getattribute__(self, "_options")
                )

            return governed_factory
        if name not in _GOVERNED_METHODS or not callable(target):
            return target
        return self._make_governed(name, target)

    def _model_hint(self) -> str:
        m = object.__getattribute__(self, "_model")
        for candidate in (m, getattr(m, "_model", None)):
            if candidate is None:
                continue
            for attr in ("_model_name", "model_name", "_model_id"):
                v = getattr(candidate, attr, None)
                if isinstance(v, str) and v:
                    return v.split("/")[-1]
        return "unknown"

    def _identity_meta(self) -> Optional[Dict[str, Any]]:
        opts = object.__getattribute__(self, "_options")
        meta = dict(opts.get("metadata") or {})
        if opts.get("user_id") is not None:
            meta["user_id"] = opts["user_id"]
        if opts.get("service_name") is not None:
            meta["service_name"] = opts["service_name"]
        return meta or None

    def _complete_prompt(self, request: Any) -> str:
        model = object.__getattribute__(self, "_model")
        parts: List[str] = []
        system_text = _content_text(_model_system_instruction(model))
        if system_text:
            parts.append(f"system: {system_text}")
        history_text = _extract_prompt(_retained_history(model))
        if history_text:
            parts.append(history_text)
        cached_text = _cached_context_text(model)
        if cached_text:
            parts.append(f"cached: {cached_text}")
        tools_text = _tools_context_text(model)
        if tools_text:
            parts.append(f"tools: {tools_text}")
        request_text = _extract_prompt(request)
        if request_text:
            parts.append(request_text)
        return "\n".join(parts)

    def _make_governed(self, name: str, original: Any) -> Any:
        options = object.__getattribute__(self, "_options") or None
        operation = name

        def governed(*args: Any, **kwargs: Any) -> Any:
            cfg = try_get_config()
            if cfg is None:
                return original(*args, **kwargs)
            # sampling gates ONLY audit emission, never enforcement.
            should_audit = _sender.should_emit(cfg)

            request_key = "content" if name.startswith("send_message") else "contents"
            request = args[0] if args else kwargs.get(request_key)
            is_stream = bool(kwargs.get("stream"))
            model = self._model_hint()
            prompt_text = self._complete_prompt(request)
            user_text = _extract_last_user(request)
            identity_meta = self._identity_meta()

            policy = apply_pre_call_policy(
                prompt_text,
                cfg,
                provider=PROVIDER,
                operation=operation,
                model=model,
                scan_text=prompt_text,
                metadata=identity_meta,
            )
            compliance = policy["compliance"]

            if policy["decision"] == "block":
                emit_event(
                    cfg,
                    provider=PROVIDER,
                    model=model,
                    operation=operation,
                    source=SOURCE,
                    prompt=blocked_prompt_for_storage(
                        prompt_text, compliance, policy.get("security_normalized")
                    ),
                    response="",
                    user_input=blocked_user_input_for_storage(user_text, policy),
                    latency_ms=0,
                    success=False,
                    status_code=403,
                    compliance=compliance,
                    options=options,
                )
                raise blocked_call_error(compliance)

            if policy["decision"] == "redact":
                # Enforcement application: a redaction that cannot be carried
                # out blocks the call rather than forwarding the content it was
                # told to remove.
                def _apply_redaction() -> None:
                    nonlocal args, request, prompt_text
                    new_request = _redact_request(request)
                    if args:
                        args = (new_request,) + tuple(args[1:])
                    else:
                        kwargs[request_key] = new_request
                    _redact_model_context(
                        object.__getattribute__(self, "_model")
                    )
                    request = new_request
                    prompt_text = self._complete_prompt(request)
                    assert_redaction_applied(prompt_text, compliance)

                _not_redacted = apply_outbound_redaction(_apply_redaction)
                if _not_redacted is not None:
                    compliance = outbound_redaction_blocked_compliance(
                        compliance, _not_redacted
                    )
                    emit_event(
                        cfg,
                        provider=PROVIDER,
                        model=model,
                        operation=operation,
                        source=SOURCE,
                        prompt=blocked_prompt_for_storage(
                            prompt_text, compliance, policy.get("security_normalized")
                        ),
                        response="",
                        user_input=blocked_user_input_for_storage(user_text, policy),
                        latency_ms=0,
                        success=False,
                        status_code=403,
                        compliance=compliance,
                        options=options,
                    )
                    raise blocked_call_error(compliance)

            start = time.monotonic()
            try:
                result = original(*args, **kwargs)
            except BaseException as e:  # noqa: BLE001 - audit then re-raise
                emit_event(
                    cfg,
                    provider=PROVIDER,
                    model=model,
                    operation=operation,
                    source=SOURCE,
                    prompt=prompt_text,
                    response="",
                    user_input=user_text,
                    latency_ms=(time.monotonic() - start) * 1000,
                    success=False,
                    error=e,
                    compliance=compliance,
                    options=options,
                )
                raise

            if inspect.isawaitable(result):
                # `generate_content_async` is governed but returns a COROUTINE.
                # Handing that straight to the response extractor produced an
                # empty response and null token counts, ran the post-call policy
                # over "" so it never saw the answer, and emitted an event
                # claiming success for a call that had not happened yet — while
                # the caller awaited the coroutine and got an ungoverned answer.
                # Pre-call enforcement always survived; it is the record that did
                # not. This module has no other await, which is why one plain
                # `def` covered both a sync and an async method.
                return self._await_and_govern(
                    cfg, result, operation, model, prompt_text, user_text,
                    compliance, options, start, should_audit, is_stream,
                )

            if is_stream:
                return self._wrap_stream(cfg, result, operation, model, prompt_text, user_text, compliance, options, start, should_audit)

            return self._govern_response(cfg, result, operation, model, prompt_text, user_text, compliance, options, start, should_audit)

        return governed

    async def _await_and_govern(self, cfg, awaitable, operation, model, prompt_text,
                                user_text, compliance, options, start, should_audit,
                                is_stream):
        """Await the provider's coroutine, THEN govern what it produced.

        The failure path is here rather than around the original call because a
        coroutine raises when it is awaited, not when it is created, so the
        synchronous try/except above never sees an async failure.
        """
        try:
            resolved = await awaitable
        except BaseException as e:  # noqa: BLE001 - audit then re-raise
            emit_event(
                cfg, provider=PROVIDER, model=model, operation=operation,
                source=SOURCE, prompt=prompt_text, response="",
                user_input=user_text,
                latency_ms=(time.monotonic() - start) * 1000,
                success=False, error=e, compliance=compliance, options=options,
            )
            raise
        if is_stream:
            return self._wrap_async_stream(
                cfg, resolved, operation, model, prompt_text, user_text,
                compliance, options, start, should_audit,
            )
        return self._govern_response(
            cfg, resolved, operation, model, prompt_text, user_text,
            compliance, options, start, should_audit,
        )

    def _wrap_async_stream(self, cfg, result, operation, model, prompt_text, user_text,
                           compliance, options, start, should_audit=True):
        """Async twin of ``_wrap_stream``.

        The sync one drives ``for chunk in result``, which an async iterator does
        not answer to. Same accounting, same emission rule: errors and governed
        events always emit, a clean allowed stream only when sampled in.
        """
        governed = compliance.get("action_taken") != "allowed"

        if not hasattr(result, "__aiter__"):
            # Not actually an async stream. Govern it as a response rather than
            # guessing — silently returning it ungoverned is what this fixes.
            return self._govern_response(
                cfg, result, operation, model, prompt_text, user_text,
                compliance, options, start, should_audit,
            )

        async def agenerator():
            text = ""
            error: Optional[BaseException] = None
            try:
                async for chunk in result:
                    try:
                        text += _extract_response_text(chunk)
                    except Exception:
                        pass
                    yield chunk
            except BaseException as e:  # noqa: BLE001
                error = e
                raise
            finally:
                if error is not None or should_audit or governed:
                    emit_event(
                        cfg, provider=PROVIDER, model=model, operation=operation,
                        source=SOURCE, prompt=prompt_text, response=text,
                        user_input=user_text,
                        latency_ms=(time.monotonic() - start) * 1000,
                        success=error is None,
                        status_code=200 if error is None else 500,
                        error=error, compliance=compliance, options=options,
                    )

        return agenerator()

    def _govern_response(self, cfg, response, operation, model, prompt_text, user_text, compliance, options, start, should_audit=True):
        latency = (time.monotonic() - start) * 1000
        text = _extract_response_text(response)
        usage = _usage(response)
        resolved = _resolved_model(response)

        post = apply_post_call_policy(text, {}, cfg)
        final_text = text
        event_compliance = dict(compliance)
        if post["decision"] == "redact_response" and post.get("redacted_response") is not None:
            final_text = post["redacted_response"]
            _redact_response_inplace(response, (post.get("response_pii") or {}).get("via"))
            if event_compliance.get("action_taken") not in ("blocked", "redacted"):
                event_compliance["action_taken"] = "redacted"
            if event_compliance.get("action_reason") in (None, "none"):
                event_compliance["action_reason"] = "pii_detected"
            if event_compliance.get("action_source") in (None, "unknown"):
                event_compliance["action_source"] = "builtin"
            rp = post.get("response_pii") or {}
            merged = list(event_compliance.get("redacted_types") or [])
            for t in rp.get("types") or []:
                if t not in merged:
                    merged.append(t)
            event_compliance["redacted_types"] = merged

        # Post-call redaction (above) always runs; sampling gates only the emit
        # of allowed calls — a governed (blocked/redacted) event is always recorded.
        if should_audit or event_compliance.get("action_taken") != "allowed":
            emit_event(
                cfg,
                provider=PROVIDER,
                model=model,
                operation=operation,
                source=SOURCE,
                prompt=prompt_text,
                response=final_text,
                user_input=user_text,
                input_tokens=usage["input_tokens"],
                output_tokens=usage["output_tokens"],
                total_tokens=usage["total_tokens"],
                latency_ms=latency,
                compliance=event_compliance,
                options=options,
                metadata={"model_resolved": resolved} if resolved else None,
            )
        return response

    def _wrap_stream(self, cfg, result, operation, model, prompt_text, user_text, compliance, options, start, should_audit=True):
        governed = compliance.get("action_taken") != "allowed"

        def generator():
            text = ""
            error: Optional[BaseException] = None
            try:
                for chunk in result:
                    try:
                        text += _extract_response_text(chunk)
                    except Exception:
                        pass
                    yield chunk
            except BaseException as e:  # noqa: BLE001
                error = e
                raise
            finally:
                # Errors and governed events always emit; a clean allowed stream
                # is emitted only when sampled in.
                if error is not None or should_audit or governed:
                    emit_event(
                        cfg,
                        provider=PROVIDER,
                        model=model,
                        operation=operation,
                        source=SOURCE,
                        prompt=prompt_text,
                        response=text,
                        user_input=user_text,
                        latency_ms=(time.monotonic() - start) * 1000,
                        success=error is None,
                        status_code=200 if error is None else 500,
                        error=error,
                        compliance=compliance,
                        options=options,
                    )

        return generator()


def wrap_vertex(model: Any, **options: Any) -> Any:
    """Wrap a Vertex AI GenerativeModel for governance + audit.

    ``options`` may carry ``user_id`` / ``service_name`` / ``metadata``.
    Idempotent: re-wrapping an already-wrapped model is a no-op.
    """
    if getattr(model, _WRAPPED_ATTR, False):
        return model
    cfg = try_get_config()
    if cfg is None:
        return model
    wrapper = _GovernedGenerativeModel(model, options)
    object.__setattr__(wrapper, _WRAPPED_ATTR, True)
    return wrapper
