"""AWS Bedrock (Python) integration — governs a boto3 bedrock-runtime client.

Parity with sdk/src/integrations/bedrock.ts. Wraps a boto3
``bedrock-runtime`` client and governs the two request families:

- ``converse`` / ``converse_stream``                 (unified messages API)
- ``invoke_model`` / ``invoke_model_with_response_stream``
  (model-native JSON bodies: Anthropic ``messages``, Titan ``inputText``,
   Llama ``prompt`` — handled generically)

Real enforcement, both sides of the call:

- PRE-call: the input messages are scanned/rule-checked. A ``block`` verdict
  raises *before* boto3 is ever called (the request never leaves the process);
  a ``redact`` verdict rewrites the messages / re-encodes the InvokeModel body
  in place, so the redacted prompt is what Bedrock receives.
- POST-call: the model OUTPUT is run through the post-call policy. A redact
  verdict rewrites the RETURNED response in place (Converse content blocks are
  redacted; the InvokeModel body is re-encoded) so the caller receives the
  governed output, not the raw one.

The boto3 client is not an attribute-proxy target (its operation methods are
generated at runtime), so we return a delegating wrapper: the four governed
operations are intercepted, every other attribute passes through to the real
client untouched.

Usage::

    import boto3, obsvr
    from obsvr.integrations.bedrock import wrap_bedrock

    obsvr.init(api_key="...", ingest_url="https://...")
    client = wrap_bedrock(boto3.client("bedrock-runtime"))
    client.converse(modelId="anthropic.claude-3-5-sonnet-...", messages=[...])
"""

# Interception: delegating object wrapper (non-mutating). The underlying boto3
# client is never modified; wrap_bedrock returns a wrapper whose converse /
# converse_stream / invoke_model / invoke_model_with_response_stream methods run
# the obsvr pipeline, delegating all other attributes to the real client.

import json
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

try:  # real binding when botocore is installed; interception works regardless
    import botocore.exceptions as _botocore_exc  # type: ignore

    _BOTO_ERRORS: tuple = (_botocore_exc.BotoCoreError, _botocore_exc.ClientError)
except Exception:  # pragma: no cover - botocore not installed
    _botocore_exc = None  # type: ignore
    _BOTO_ERRORS = ()

SOURCE = "bedrock_py"
PROVIDER = "bedrock"
_WRAPPED_ATTR = "_obsvr_bedrock_wrapped"

# method name -> audit operation
_GOVERNED_OPERATIONS: Dict[str, str] = {
    "converse": "bedrock.converse",
    "converse_stream": "bedrock.converse_stream",
    "invoke_model": "bedrock.invoke_model",
    "invoke_model_with_response_stream": "bedrock.invoke_model_stream",
}


# ---------------------------------------------------------------------------
# A minimal StreamingBody stand-in. boto3's real StreamingBody is single-read;
# once we read it to scan/govern, the caller can no longer read it — so we hand
# back a fresh readable carrying the (possibly redacted) bytes.
# ---------------------------------------------------------------------------


class _StaticBody:
    """Re-readable body replacement (duck-types botocore StreamingBody.read)."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self, *_args: Any, **_kw: Any) -> bytes:
        return self._data


def _read_body_bytes(body: Any) -> bytes:
    if body is None:
        return b""
    if isinstance(body, (bytes, bytearray)):
        return bytes(body)
    if isinstance(body, str):
        return body.encode("utf-8")
    read = getattr(body, "read", None)
    if callable(read):
        raw = read()
        if isinstance(raw, str):
            return raw.encode("utf-8")
        return bytes(raw or b"")
    return b""


# ---------------------------------------------------------------------------
# Request extraction (port of bedrock.ts)
# ---------------------------------------------------------------------------


def _converse_content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts = [b.get("text", "") for b in content if isinstance(b, dict) and isinstance(b.get("text"), str)]
    return "\n".join(p for p in parts if p)


def _extract_converse_prompt(kwargs: Dict[str, Any]) -> str:
    parts: List[str] = []
    system = kwargs.get("system")
    if isinstance(system, list):
        sys = "\n".join(
            s.get("text", "") for s in system if isinstance(s, dict) and isinstance(s.get("text"), str)
        )
        if sys:
            parts.append(f"system: {sys}")
    messages = kwargs.get("messages")
    if isinstance(messages, list):
        for msg in messages:
            if isinstance(msg, dict):
                parts.append(f"{msg.get('role', 'user')}: {_converse_content_text(msg.get('content'))}")
    return "\n".join(parts)


def _extract_converse_last_user(kwargs: Dict[str, Any]) -> str:
    messages = kwargs.get("messages")
    if isinstance(messages, list):
        for msg in reversed(messages):
            if isinstance(msg, dict) and msg.get("role") == "user":
                return _converse_content_text(msg.get("content"))
    return _extract_converse_prompt(kwargs)


def _redact_converse_inplace(kwargs: Dict[str, Any]) -> None:
    system = kwargs.get("system")
    if isinstance(system, list):
        for s in system:
            if isinstance(s, dict) and isinstance(s.get("text"), str):
                s["text"] = redact_builtin_pii(s["text"])
    messages = kwargs.get("messages")
    if isinstance(messages, list):
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            content = msg.get("content")
            if isinstance(content, str):
                msg["content"] = redact_builtin_pii(content)
            elif isinstance(content, list):
                for b in content:
                    if isinstance(b, dict) and isinstance(b.get("text"), str):
                        b["text"] = redact_builtin_pii(b["text"])


def _decode_body(body: Any) -> Optional[Dict[str, Any]]:
    try:
        raw = _read_body_bytes(body)
        if not raw:
            return None
        parsed = json.loads(raw.decode("utf-8"))
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


def _extract_invoke_prompt(body: Optional[Dict[str, Any]]) -> str:
    if not body:
        return ""
    parts: List[str] = []
    if isinstance(body.get("system"), str) and body["system"]:
        parts.append(f"system: {body['system']}")
    messages = body.get("messages")
    if isinstance(messages, list):
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            content = msg.get("content")
            text = ""
            if isinstance(content, str):
                text = content
            elif isinstance(content, list):
                text = "\n".join(
                    p.get("text", "") for p in content if isinstance(p, dict) and isinstance(p.get("text"), str)
                )
            parts.append(f"{msg.get('role', 'user')}: {text}")
    if isinstance(body.get("inputText"), str):
        parts.append(body["inputText"])
    if isinstance(body.get("prompt"), str):
        parts.append(body["prompt"])
    return "\n".join(parts)


def _extract_invoke_last_user(body: Optional[Dict[str, Any]]) -> str:
    if not body:
        return ""
    messages = body.get("messages")
    if isinstance(messages, list):
        for msg in reversed(messages):
            if isinstance(msg, dict) and msg.get("role") == "user":
                content = msg.get("content")
                if isinstance(content, str):
                    return content
                if isinstance(content, list):
                    return " ".join(
                        p.get("text", "") for p in content if isinstance(p, dict) and isinstance(p.get("text"), str)
                    )
    if isinstance(body.get("inputText"), str):
        return body["inputText"]
    if isinstance(body.get("prompt"), str):
        return body["prompt"]
    return _extract_invoke_prompt(body)


def _redact_invoke_body_inplace(body: Dict[str, Any]) -> None:
    if isinstance(body.get("system"), str):
        body["system"] = redact_builtin_pii(body["system"])
    messages = body.get("messages")
    if isinstance(messages, list):
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            content = msg.get("content")
            if isinstance(content, str):
                msg["content"] = redact_builtin_pii(content)
            elif isinstance(content, list):
                for p in content:
                    if isinstance(p, dict) and isinstance(p.get("text"), str):
                        p["text"] = redact_builtin_pii(p["text"])
    if isinstance(body.get("inputText"), str):
        body["inputText"] = redact_builtin_pii(body["inputText"])
    if isinstance(body.get("prompt"), str):
        body["prompt"] = redact_builtin_pii(body["prompt"])


def _encode_body(body: Dict[str, Any]) -> bytes:
    return json.dumps(body).encode("utf-8")


# ---------------------------------------------------------------------------
# Response extraction
# ---------------------------------------------------------------------------


def _extract_converse_response_text(response: Dict[str, Any]) -> str:
    try:
        content = response["output"]["message"]["content"]
        return _converse_content_text(content)
    except Exception:
        return ""


def _converse_usage(response: Dict[str, Any]) -> Dict[str, Optional[int]]:
    u = response.get("usage") or {} if isinstance(response, dict) else {}
    return {
        "input_tokens": u.get("inputTokens"),
        "output_tokens": u.get("outputTokens"),
        "total_tokens": u.get("totalTokens"),
    }


def _extract_invoke_response_text(body: Optional[Dict[str, Any]]) -> str:
    if not body:
        return ""
    # Anthropic
    content = body.get("content")
    if isinstance(content, list):
        text = "".join(c.get("text", "") for c in content if isinstance(c, dict) and isinstance(c.get("text"), str))
        if text:
            return text
    # Titan
    results = body.get("results")
    if isinstance(results, list):
        text = "".join(
            r.get("outputText", "") for r in results if isinstance(r, dict) and isinstance(r.get("outputText"), str)
        )
        if text:
            return text
    # Llama
    if isinstance(body.get("generation"), str):
        return body["generation"]
    # Nova / Converse-shaped bodies
    try:
        return _converse_content_text(body["output"]["message"]["content"])
    except Exception:
        return ""


def _invoke_usage(body: Optional[Dict[str, Any]]) -> Dict[str, Optional[int]]:
    if not body:
        return {"input_tokens": None, "output_tokens": None, "total_tokens": None}
    u = body.get("usage") or {}
    inp = u.get("input_tokens", u.get("inputTokens"))
    out = u.get("output_tokens", u.get("outputTokens"))
    tot = u.get("total_tokens", u.get("totalTokens"))
    if tot is None and inp is not None and out is not None:
        tot = inp + out
    if inp is None and isinstance(body.get("inputTextTokenCount"), int):
        inp = body["inputTextTokenCount"]
    return {"input_tokens": inp, "output_tokens": out, "total_tokens": tot}


# ---------------------------------------------------------------------------
# The wrapper
# ---------------------------------------------------------------------------


class _GovernedBedrockClient:
    """Delegating wrapper around a boto3 bedrock-runtime client."""

    def __init__(self, client: Any, options: Dict[str, Any]) -> None:
        object.__setattr__(self, "_client", client)
        object.__setattr__(self, "_options", options or {})

    def __getattr__(self, name: str) -> Any:
        # Only reached for attributes not on the wrapper itself.
        target = getattr(object.__getattribute__(self, "_client"), name)
        operation = _GOVERNED_OPERATIONS.get(name)
        if operation is None or not callable(target):
            return target
        return self._make_governed(name, operation, target)

    def _identity_meta(self) -> Optional[Dict[str, Any]]:
        opts = object.__getattribute__(self, "_options")
        meta = dict(opts.get("metadata") or {})
        if opts.get("user_id") is not None:
            meta["user_id"] = opts["user_id"]
        if opts.get("service_name") is not None:
            meta["service_name"] = opts["service_name"]
        return meta or None

    def _make_governed(self, name: str, operation: str, original: Any) -> Any:
        options = object.__getattribute__(self, "_options") or None
        is_converse = name.startswith("converse")
        is_stream = name.endswith("stream")

        def governed(*args: Any, **kwargs: Any) -> Any:
            cfg = try_get_config()
            if cfg is None:
                return original(*args, **kwargs)
            # sampling gates ONLY audit emission, never enforcement —
            # the pre-call boundary and post-call response redaction must run for
            # every governed call. Blocked/redacted/error events always emit.
            should_audit = _sender.should_sample(cfg.sample_rate)

            model = str(kwargs.get("modelId") or "unknown")
            invoke_body: Optional[Dict[str, Any]] = None
            if is_converse:
                prompt_text = _extract_converse_prompt(kwargs)
                user_text = _extract_converse_last_user(kwargs)
            else:
                invoke_body = _decode_body(kwargs.get("body"))
                prompt_text = _extract_invoke_prompt(invoke_body)
                user_text = _extract_invoke_last_user(invoke_body)

            identity_meta = self._identity_meta()

            # --- PRE-call policy (real enforcement) ---
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
                if is_converse:
                    _redact_converse_inplace(kwargs)
                    prompt_text = _extract_converse_prompt(kwargs)
                elif invoke_body is not None:
                    _redact_invoke_body_inplace(invoke_body)
                    kwargs["body"] = _encode_body(invoke_body)
                    prompt_text = _extract_invoke_prompt(invoke_body)

            # --- Execute ---
            start = time.monotonic()
            try:
                response = original(*args, **kwargs)
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
                return self._wrap_stream(
                    cfg, response, name, operation, model, prompt_text, user_text, compliance, options, start, should_audit
                )

            return self._govern_response(
                cfg, response, is_converse, operation, model, prompt_text, user_text, compliance, options, start, should_audit
            )

        return governed

    def _govern_response(
        self,
        cfg: Any,
        response: Any,
        is_converse: bool,
        operation: str,
        model: str,
        prompt_text: str,
        user_text: str,
        compliance: Dict[str, Any],
        options: Optional[Dict[str, Any]],
        start: float,
        should_audit: bool = True,
    ) -> Any:
        latency = (time.monotonic() - start) * 1000
        resp_body: Optional[Dict[str, Any]] = None
        if is_converse:
            text = _extract_converse_response_text(response) if isinstance(response, dict) else ""
            usage = _converse_usage(response if isinstance(response, dict) else {})
        else:
            body_obj = response.get("body") if isinstance(response, dict) else getattr(response, "body", None)
            raw_bytes = _read_body_bytes(body_obj)
            resp_body = _decode_body(raw_bytes)
            text = _extract_invoke_response_text(resp_body)
            usage = _invoke_usage(resp_body)
            # We consumed the single-read body; hand back a fresh readable one.
            if isinstance(response, dict):
                response["body"] = _StaticBody(raw_bytes)

        # --- POST-call governance on the OUTPUT (real; rewrites what's returned) ---
        post = apply_post_call_policy(text, {}, cfg)
        final_text = text
        event_compliance = dict(compliance)
        if post["decision"] == "redact_response" and post.get("redacted_response") is not None:
            final_text = post["redacted_response"]
            # View-only hit (via present): span redaction cannot locate the
            # encoded payload — text fields become whole-text placeholders.
            resp_via = (post.get("response_pii") or {}).get("via")
            if is_converse:
                self._rewrite_converse_output(response, resp_via)
            elif resp_body is not None and isinstance(response, dict):
                _redact_invoke_response_inplace(resp_body, resp_via)
                response["body"] = _StaticBody(_encode_body(resp_body))
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
            )
        return response

    @staticmethod
    def _rewrite_converse_output(response: Any, via: Optional[str] = None) -> None:
        try:
            content = response["output"]["message"]["content"]
            for block in content:
                if isinstance(block, dict) and isinstance(block.get("text"), str):
                    block["text"] = redact_for_storage(block["text"], via)
        except Exception:
            pass

    def _wrap_stream(
        self,
        cfg: Any,
        response: Any,
        name: str,
        operation: str,
        model: str,
        prompt_text: str,
        user_text: str,
        compliance: Dict[str, Any],
        options: Optional[Dict[str, Any]],
        start: float,
        should_audit: bool = True,
    ) -> Any:
        governed = compliance.get("action_taken") != "allowed"
        stream_key = "stream" if name == "converse_stream" else "body"
        inner = response.get(stream_key) if isinstance(response, dict) else None
        if inner is None or not hasattr(inner, "__iter__"):
            # Unexpected shape: audit what we have (observe).
            if should_audit or governed:
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
                    compliance=compliance,
                    options=options,
                )
            return response

        is_invoke_stream = name == "invoke_model_with_response_stream"

        def generator() -> Any:
            text = ""
            error: Optional[BaseException] = None
            try:
                for event in inner:
                    try:
                        if is_invoke_stream:
                            parsed = _decode_body((event or {}).get("chunk", {}).get("bytes") if isinstance(event, dict) else None)
                            if parsed:
                                text += _stream_chunk_text(parsed)
                        else:
                            text += _stream_chunk_text(event if isinstance(event, dict) else {})
                    except Exception:
                        pass
                    yield event
            except BaseException as e:  # noqa: BLE001 - surface to caller, audit in finally
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

        if isinstance(response, dict):
            response[stream_key] = generator()
        return response


def _redact_invoke_response_inplace(body: Dict[str, Any], via: Optional[str] = None) -> None:
    content = body.get("content")
    if isinstance(content, list):
        for c in content:
            if isinstance(c, dict) and isinstance(c.get("text"), str):
                c["text"] = redact_for_storage(c["text"], via)
    results = body.get("results")
    if isinstance(results, list):
        for r in results:
            if isinstance(r, dict) and isinstance(r.get("outputText"), str):
                r["outputText"] = redact_for_storage(r["outputText"], via)
    if isinstance(body.get("generation"), str):
        body["generation"] = redact_for_storage(body["generation"], via)


def _stream_chunk_text(chunk: Dict[str, Any]) -> str:
    # ConverseStream
    delta = chunk.get("contentBlockDelta", {})
    if isinstance(delta, dict):
        d = delta.get("delta", {})
        if isinstance(d, dict) and isinstance(d.get("text"), str):
            return d["text"]
    # Anthropic invoke stream
    d = chunk.get("delta", {})
    if isinstance(d, dict) and isinstance(d.get("text"), str):
        return d["text"]
    # Titan
    if isinstance(chunk.get("outputText"), str):
        return chunk["outputText"]
    # Llama
    if isinstance(chunk.get("generation"), str):
        return chunk["generation"]
    return ""


def wrap_bedrock(client: Any, **options: Any) -> Any:
    """Wrap a boto3 bedrock-runtime client for governance + audit.

    ``options`` may carry ``user_id`` / ``service_name`` / ``metadata`` (threaded
    into the rules-eval identity and attached to the audit as the caller
    principal). Idempotent: re-wrapping an already-wrapped client is a no-op.
    """
    if getattr(client, _WRAPPED_ATTR, False):
        return client
    cfg = try_get_config()
    if cfg is None:
        return client
    wrapper = _GovernedBedrockClient(client, options)
    object.__setattr__(wrapper, _WRAPPED_ATTR, True)
    return wrapper
