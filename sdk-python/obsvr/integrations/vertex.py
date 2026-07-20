"""Google Vertex AI (Python) integration — governs a GenerativeModel.

Parity with sdk/src/integrations/vertex.ts. Wraps a Vertex AI
``GenerativeModel`` (``vertexai.generative_models.GenerativeModel`` or
``google.cloud.aiplatform``'s equivalent) and governs ``generate_content``
(and its streaming form ``generate_content`` with ``stream=True``, plus
``generate_content_async`` when present).

Real enforcement, both sides of the call:

- PRE-call: the last user turn is scanned/rule-checked. A ``block`` verdict
  raises *before* the model is ever called; a ``redact`` verdict rewrites the
  request contents in place so the redacted prompt is what Vertex receives.
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

import time
from typing import Any, Dict, List, Optional

from .. import sender as _sender
from ..config import try_get_config
from ..events import blocked_call_error, emit_event
from ..deobfuscate import redact_for_storage
from ..policy import (
    apply_post_call_policy,
    apply_pre_call_policy,
    blocked_prompt_for_storage,
    blocked_user_input_for_storage,
    redact_builtin_pii,
)

try:  # real binding when the Vertex SDK is installed; interception works regardless
    from vertexai.generative_models import (  # type: ignore  # noqa: F401
        GenerativeModel as _RealGenerativeModel,
    )
except Exception:  # pragma: no cover - vertex SDK not installed
    _RealGenerativeModel = None  # type: ignore

SOURCE = "vertex_py"
PROVIDER = "vertex_ai"
_WRAPPED_ATTR = "_obsvr_vertex_wrapped"

_GOVERNED_METHODS = {"generate_content", "generate_content_async"}


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
    if isinstance(content, dict):
        parts = content.get("parts")
    else:
        parts = getattr(content, "parts", None)
    if isinstance(parts, list):
        return "\n".join(t for t in (_part_text(p) for p in parts) if t)
    return ""


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


def _redact_request_inplace(request: Any) -> Any:
    """Redact the request contents in place; returns the possibly-new request
    (a bare string can't be mutated, so a redacted copy is returned)."""
    if isinstance(request, str):
        return redact_builtin_pii(request)
    contents = _normalize_contents(request)
    for c in contents:
        if isinstance(c, dict):
            parts = c.get("parts")
            if isinstance(parts, list):
                for p in parts:
                    if isinstance(p, dict) and isinstance(p.get("text"), str):
                        p["text"] = redact_builtin_pii(p["text"])
                    elif isinstance(getattr(p, "text", None), str):
                        try:
                            p.text = redact_builtin_pii(p.text)
                        except Exception:
                            pass
        else:
            parts = getattr(c, "parts", None)
            if isinstance(parts, list):
                for p in parts:
                    if isinstance(getattr(p, "text", None), str):
                        try:
                            p.text = redact_builtin_pii(p.text)
                        except Exception:
                            pass
    return request


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
    if um is None:
        return {"input_tokens": None, "output_tokens": None, "total_tokens": None}

    def g(key: str) -> Optional[int]:
        if isinstance(um, dict):
            return um.get(key)
        return getattr(um, key, None)

    return {
        "input_tokens": g("prompt_token_count"),
        "output_tokens": g("candidates_token_count"),
        "total_tokens": g("total_token_count"),
    }


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
        if name not in _GOVERNED_METHODS or not callable(target):
            return target
        return self._make_governed(name, target)

    def _model_hint(self) -> str:
        m = object.__getattribute__(self, "_model")
        for attr in ("_model_name", "model_name", "_model_id"):
            v = getattr(m, attr, None)
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

    def _make_governed(self, name: str, original: Any) -> Any:
        options = object.__getattribute__(self, "_options") or None
        operation = name

        def governed(*args: Any, **kwargs: Any) -> Any:
            cfg = try_get_config()
            if cfg is None:
                return original(*args, **kwargs)
            # sampling gates ONLY audit emission, never enforcement.
            should_audit = _sender.should_sample(cfg.sample_rate)

            request = args[0] if args else kwargs.get("contents")
            is_stream = bool(kwargs.get("stream"))
            model = self._model_hint()
            prompt_text = _extract_prompt(request)
            user_text = _extract_last_user(request)
            identity_meta = self._identity_meta()

            policy = apply_pre_call_policy(
                prompt_text,
                cfg,
                provider=PROVIDER,
                operation=operation,
                model=model,
                scan_text=user_text or prompt_text,
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
                new_request = _redact_request_inplace(request)
                if args:
                    args = (new_request,) + tuple(args[1:])
                else:
                    kwargs["contents"] = new_request
                request = new_request
                prompt_text = _extract_prompt(request)

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

            if is_stream:
                return self._wrap_stream(cfg, result, operation, model, prompt_text, user_text, compliance, options, start, should_audit)

            return self._govern_response(cfg, result, operation, model, prompt_text, user_text, compliance, options, start, should_audit)

        return governed

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
