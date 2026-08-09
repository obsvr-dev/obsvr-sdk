"""Maintained Google Gemini client: drive the real package shape without IO."""

import asyncio
import sys
import types as stdlib_types

import pytest

import obsvr
from obsvr import sender

genai = pytest.importorskip("google.genai")
google_types = pytest.importorskip("google.genai.types")
WRAP_MODULE = sys.modules["obsvr.wrap"]


class _Response:
    def __init__(self, text="real-package response"):
        self.text = text
        self.usage_metadata = stdlib_types.SimpleNamespace(
            prompt_token_count=2,
            candidates_token_count=3,
            total_token_count=5,
        )


def _init(monkeypatch, **extra):
    obsvr.init(
        api_key="test-key",
        ingest_url="http://localhost:9",
        disabled=False,
        **extra,
    )
    events = []
    monkeypatch.setattr(
        WRAP_MODULE, "send_audit_async", lambda _config, event: events.append(event)
    )
    return events


@pytest.fixture
def real_client():
    client = genai.Client(api_key="not-a-provider-key")
    yield client
    client.close()


def test_real_sync_resource_and_content_models_are_governed(
    monkeypatch, real_client
):
    events = _init(monkeypatch, pii_policy={"rules": {"email": "redact"}})
    calls = []

    def fake_generate(_resource, *, model, contents, config=None):
        calls.append({"model": model, "contents": contents, "config": config})
        return _Response()

    monkeypatch.setattr(type(real_client.models), "generate_content", fake_generate)
    original = google_types.Content(
        role="user", parts=[google_types.Part(text="mail real@example.com")]
    )
    config = google_types.GenerateContentConfig(
        system_instruction="mail system@example.com",
        response_mime_type="application/json",
        response_schema={"type": "object", "properties": {"ok": {"type": "boolean"}}},
    )

    result = obsvr.wrap(real_client).models.generate_content(
        model="gemini-2.5-flash", contents=original, config=config
    )

    assert result.text == "real-package response"
    assert original.parts[0].text == "mail real@example.com"
    assert isinstance(calls[0]["contents"], google_types.Content)
    assert calls[0]["contents"].parts[0].text == "mail [REDACTED_EMAIL]"
    assert config.system_instruction == "mail system@example.com"
    assert calls[0]["config"] is not config
    assert calls[0]["config"].system_instruction == "mail [REDACTED_EMAIL]"
    assert calls[0]["config"].response_mime_type == "application/json"
    assert calls[0]["config"].response_schema == config.response_schema
    assert events[0]["operation"] == "models.generate_content"
    assert events[0]["model"] == "gemini-2.5-flash"
    assert events[0]["total_tokens"] == 5


def test_real_sync_stream_resource_is_wrapped(monkeypatch, real_client):
    events = _init(monkeypatch)

    def fake_stream(_resource, *, model, contents, config=None):
        return iter((_Response("real "), _Response("stream")))

    monkeypatch.setattr(
        type(real_client.models), "generate_content_stream", fake_stream
    )

    chunks = list(
        obsvr.wrap(real_client).models.generate_content_stream(
            model="gemini-2.5-flash", contents="hello"
        )
    )

    assert [chunk.text for chunk in chunks] == ["real ", "stream"]
    assert len(events) == 1
    assert events[0]["operation"] == "models.generate_content_stream"
    assert events[0]["response"] == "real stream"


def test_real_async_stream_resource_is_wrapped(monkeypatch, real_client):
    events = _init(monkeypatch)

    async def fake_stream(_resource, *, model, contents, config=None):
        async def chunks():
            yield _Response("real async ")
            yield _Response("stream")

        return chunks()

    monkeypatch.setattr(
        type(real_client.aio.models), "generate_content_stream", fake_stream
    )

    async def run():
        stream = await obsvr.wrap(real_client).aio.models.generate_content_stream(
            model="gemini-2.5-flash", contents="hello"
        )
        return [chunk.text async for chunk in stream]

    assert asyncio.run(run()) == ["real async ", "stream"]
    assert len(events) == 1
    assert events[0]["operation"] == "aio.models.generate_content_stream"
    assert events[0]["response"] == "real async stream"


def test_real_async_resource_blocks_before_dispatch(monkeypatch, real_client):
    events = _init(monkeypatch, pii_policy={"rules": {"ssn": "block"}})
    calls = []

    async def fake_generate(_resource, *, model, contents, config=None):
        calls.append(contents)
        return _Response()

    monkeypatch.setattr(
        type(real_client.aio.models), "generate_content", fake_generate
    )

    async def run():
        await obsvr.wrap(real_client).aio.models.generate_content(
            model="gemini-2.5-flash", contents="ssn 123-45-6789"
        )

    with pytest.raises(RuntimeError, match="blocked by policy"):
        asyncio.run(run())

    assert calls == []
    assert events[0]["event_type"] == "blocked_call"
