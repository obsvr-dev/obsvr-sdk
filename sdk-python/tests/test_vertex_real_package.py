"""Vertex chat enforcement through official package object shapes."""

import asyncio
import importlib
import inspect
import types

import pytest
import vertexai
from google.auth.credentials import AnonymousCredentials

import obsvr
from obsvr.integrations import vertex as WRAP_MODULE

try:
    vertex_models = importlib.import_module("vertexai.generative_models")
    GenerativeModel = vertex_models.GenerativeModel
except (AttributeError, ModuleNotFoundError):
    vertex_models = pytest.importorskip("vertexai.preview.generative_models")
    GenerativeModel = vertex_models.GenerativeModel

Content = vertex_models.Content
Part = vertex_models.Part
preview_models = importlib.import_module("vertexai.preview.generative_models")

vertexai.init(
    project="test-project",
    location="us-central1",
    credentials=AnonymousCredentials(),
)


def _response(text="done"):
    part = types.SimpleNamespace(text=text)
    content = types.SimpleNamespace(role="model", parts=[part])
    candidate = types.SimpleNamespace(content=content)
    usage = types.SimpleNamespace(
        prompt_token_count=2,
        candidates_token_count=1,
        total_token_count=3,
    )
    return types.SimpleNamespace(
        text=text,
        candidates=[candidate],
        usage_metadata=usage,
        model_version="gemini-1.5-pro-002",
    )


def _model():
    return GenerativeModel("gemini-1.5-pro")


def _content(text):
    return Content(role="user", parts=[Part.from_text(text)])


def _to_dict(value):
    method = getattr(value, "to_dict", None)
    if callable(method):
        return method()
    for attr in ("_raw_part", "_raw_content"):
        raw = getattr(value, attr, None)
        method = getattr(type(raw), "to_dict", None)
        if raw is not None and callable(method):
            return method(raw)
    raise TypeError("official Vertex value is not serializable")


def _init(monkeypatch, **extra):
    obsvr.init(
        api_key="test",
        ingest_url="http://localhost:9",
        disabled=False,
        **extra,
    )
    events = []
    monkeypatch.setattr(
        WRAP_MODULE, "emit_event", lambda _config, **event: events.append(event)
    )
    return events


def test_real_vertex_chat_blocks_before_send(monkeypatch):
    events = _init(monkeypatch, pii_policy={"rules": {"ssn": "block"}})
    calls = []
    chat_type = type(_model().start_chat())

    def fake_send(self, content, **kwargs):
        calls.append(content)
        return _response()

    monkeypatch.setattr(chat_type, "send_message", fake_send)
    chat = WRAP_MODULE.wrap_vertex(_model()).start_chat()

    with pytest.raises(RuntimeError, match="blocked by policy"):
        chat.send_message("ssn 123-45-6789")

    assert calls == []
    assert events[0]["operation"] == "send_message"


def test_real_vertex_chat_blocks_retained_history(monkeypatch):
    _init(monkeypatch, pii_policy={"rules": {"ssn": "block"}})
    calls = []
    chat_type = type(_model().start_chat())

    def fake_send(self, content, **kwargs):
        calls.append(content)
        return _response()

    monkeypatch.setattr(chat_type, "send_message", fake_send)
    chat = WRAP_MODULE.wrap_vertex(_model()).start_chat()
    chat._model._history = [
        {"role": "user", "parts": [{"text": "old ssn 123-45-6789"}]},
        {"role": "model", "parts": [{"text": "acknowledged"}]},
    ]

    with pytest.raises(RuntimeError, match="blocked by policy"):
        chat.send_message("continue safely")

    assert calls == []


def test_real_vertex_chat_redacts_request_and_history_without_mutating_input(
    monkeypatch,
):
    events = _init(monkeypatch, pii_policy={"rules": {"email": "redact"}})
    calls = []
    chat_type = type(_model().start_chat())

    def fake_send(self, content, **kwargs):
        calls.append({"content": content, "history": self._history})
        return _response()

    monkeypatch.setattr(chat_type, "send_message", fake_send)
    history = [
        {"role": "user", "parts": [{"text": "old@example.com"}]},
        {"role": "model", "parts": [{"text": "acknowledged"}]},
    ]
    chat = WRAP_MODULE.wrap_vertex(_model()).start_chat()
    chat._model._history = history

    chat.send_message("new@example.com")

    assert history[0]["parts"][0]["text"] == "old@example.com"
    assert calls[0]["content"] == "[REDACTED_EMAIL]"
    assert "old@example.com" not in str(calls[0]["history"])
    assert "[REDACTED_EMAIL]" in str(calls[0]["history"])
    assert events[0]["operation"] == "send_message"
    assert "[REDACTED_EMAIL]" in events[0]["prompt"]


def test_real_vertex_async_chat_blocks_before_send(monkeypatch):
    _init(monkeypatch, pii_policy={"rules": {"ssn": "block"}})
    calls = []
    chat_type = type(_model().start_chat())

    async def fake_send(self, content, **kwargs):
        calls.append(content)
        return _response()

    monkeypatch.setattr(chat_type, "send_message_async", fake_send)
    chat = WRAP_MODULE.wrap_vertex(_model()).start_chat()

    async def run():
        await chat.send_message_async("ssn 123-45-6789")

    with pytest.raises(RuntimeError, match="blocked by policy"):
        asyncio.run(run())

    assert calls == []


def test_real_vertex_sync_stream_blocks_before_send(monkeypatch):
    _init(monkeypatch, pii_policy={"rules": {"ssn": "block"}})
    calls = []
    chat_type = type(_model().start_chat())

    def fake_send(self, content, **kwargs):
        calls.append((content, kwargs))
        return iter([_response()])

    monkeypatch.setattr(chat_type, "send_message", fake_send)

    with pytest.raises(RuntimeError, match="blocked by policy"):
        WRAP_MODULE.wrap_vertex(_model()).start_chat().send_message(
            "ssn 123-45-6789", stream=True
        )

    assert calls == []


def test_real_vertex_async_stream_blocks_before_send(monkeypatch):
    _init(monkeypatch, pii_policy={"rules": {"ssn": "block"}})
    calls = []
    chat_type = type(_model().start_chat())

    async def fake_send(self, content, **kwargs):
        calls.append((content, kwargs))
        return _response()

    monkeypatch.setattr(chat_type, "send_message_async", fake_send)

    async def run():
        await WRAP_MODULE.wrap_vertex(_model()).start_chat().send_message_async(
            "ssn 123-45-6789", stream=True
        )

    with pytest.raises(RuntimeError, match="blocked by policy"):
        asyncio.run(run())

    assert calls == []


def test_real_vertex_chat_content_keyword_is_governed(monkeypatch):
    _init(monkeypatch, pii_policy={"rules": {"ssn": "block"}})
    calls = []
    chat_type = type(_model().start_chat())

    def fake_send(self, content, **kwargs):
        calls.append(content)
        return _response()

    monkeypatch.setattr(chat_type, "send_message", fake_send)
    chat = WRAP_MODULE.wrap_vertex(_model()).start_chat()

    with pytest.raises(RuntimeError, match="blocked by policy"):
        chat.send_message(content="ssn 123-45-6789")

    assert calls == []


def test_generic_wrap_governs_vertex_content_keyword_and_history(monkeypatch):
    _init(monkeypatch, pii_policy={"rules": {"ssn": "block"}})
    calls = []
    chat_type = type(_model().start_chat())

    def fake_send(self, content, **kwargs):
        calls.append(content)
        return _response()

    monkeypatch.setattr(chat_type, "send_message", fake_send)
    chat = obsvr.wrap(_model()).start_chat(
        history=[_content("old ssn 123-45-6789")]
    )

    with pytest.raises(RuntimeError, match="blocked by policy"):
        chat.send_message(content="continue safely")

    assert calls == []


def test_real_vertex_content_and_part_are_redacted_without_mutation(monkeypatch):
    _init(monkeypatch, pii_policy={"rules": {"email": "redact"}})
    calls = []
    chat_type = type(_model().start_chat())

    def fake_send(self, content, **kwargs):
        calls.append(content)
        return _response()

    monkeypatch.setattr(chat_type, "send_message", fake_send)
    original = _content("person@example.com")
    WRAP_MODULE.wrap_vertex(_model()).start_chat().send_message(original)

    assert _to_dict(original)["parts"][0]["text"] == "person@example.com"
    assert _to_dict(calls[0])["parts"][0]["text"] == "[REDACTED_EMAIL]"


def test_real_vertex_function_response_payload_is_governed(monkeypatch):
    _init(monkeypatch, pii_policy={"rules": {"ssn": "block"}})
    calls = []
    chat_type = type(_model().start_chat())

    def fake_send(self, content, **kwargs):
        calls.append(content)
        return _response()

    monkeypatch.setattr(chat_type, "send_message", fake_send)
    tool_result = Part.from_function_response(
        name="lookup", response={"record": {"ssn": "123-45-6789"}}
    )

    with pytest.raises(RuntimeError, match="blocked by policy"):
        WRAP_MODULE.wrap_vertex(_model()).start_chat().send_message([tool_result])

    assert calls == []


def test_real_vertex_nested_system_instruction_is_governed(monkeypatch):
    _init(monkeypatch, pii_policy={"rules": {"ssn": "block"}})
    calls = []
    chat_type = type(_model().start_chat())

    def fake_send(self, content, **kwargs):
        calls.append(content)
        return _response()

    monkeypatch.setattr(chat_type, "send_message", fake_send)
    raw = _model()
    raw._system_instruction = _content("system ssn 123-45-6789")

    with pytest.raises(RuntimeError, match="blocked by policy"):
        obsvr.wrap(raw).start_chat().send_message("continue safely")

    assert calls == []


def test_real_vertex_local_cached_context_is_governed(monkeypatch):
    _init(monkeypatch, pii_policy={"rules": {"ssn": "block"}})
    calls = []
    raw = _model()
    raw._cached_content = types.SimpleNamespace(
        _raw_cached_content=types.SimpleNamespace(
            contents=[_content("cached ssn 123-45-6789")],
            system_instruction=None,
        )
    )
    monkeypatch.setattr(raw, "generate_content", lambda contents, **kwargs: calls.append(contents))

    with pytest.raises(RuntimeError, match="blocked by policy"):
        WRAP_MODULE.wrap_vertex(raw).generate_content("continue safely")

    assert calls == []


def test_real_vertex_opaque_cached_context_fails_closed(monkeypatch):
    _init(monkeypatch)
    calls = []
    raw = _model()
    raw._cached_content = types.SimpleNamespace(name="cachedContents/opaque")
    monkeypatch.setattr(raw, "generate_content", lambda contents, **kwargs: calls.append(contents))

    with pytest.raises(RuntimeError, match="cached context is opaque"):
        WRAP_MODULE.wrap_vertex(raw).generate_content("continue safely")

    assert calls == []


def test_generic_wrap_rejects_automatic_responder(monkeypatch):
    _init(monkeypatch)
    raw_model = _model()

    class Session:
        _responder = object()

    monkeypatch.setattr(raw_model, "start_chat", lambda **kwargs: Session())

    with pytest.raises(RuntimeError, match="automatic responder"):
        obsvr.wrap(raw_model).start_chat(responder=object())


def test_current_preview_responder_is_rejected_by_both_wrappers(monkeypatch):
    _init(monkeypatch)
    preview_model = preview_models.GenerativeModel("gemini-1.5-pro")
    if "responder" not in inspect.signature(preview_model.start_chat).parameters:
        pytest.skip("automatic responders are unavailable at this package version")

    with pytest.raises(RuntimeError, match="automatic responder"):
        WRAP_MODULE.wrap_vertex(preview_model).start_chat(responder=object())
    with pytest.raises(RuntimeError, match="automatic responder"):
        obsvr.wrap(preview_model).start_chat(responder=object())


def test_real_vertex_automatic_responder_fails_closed(monkeypatch):
    _init(monkeypatch)
    raw_model = _model()

    class Session:
        _responder = object()

    monkeypatch.setattr(raw_model, "start_chat", lambda **kwargs: Session())

    with pytest.raises(RuntimeError, match="automatic responder"):
        WRAP_MODULE.wrap_vertex(raw_model).start_chat(responder=object())
