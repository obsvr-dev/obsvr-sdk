"""Legacy Gemini model and chat enforcement against the official package."""

from __future__ import annotations

import asyncio
import sys
from types import SimpleNamespace
from typing import Any

import pytest

import obsvr

genai = pytest.importorskip("google.generativeai")
WRAP_MODULE = sys.modules["obsvr.wrap"]

SSN = "123-45-6789"
EMAIL = "real@example.com"


def _init(monkeypatch: pytest.MonkeyPatch, **extra: Any) -> list[dict[str, Any]]:
    obsvr.init(
        api_key="test-key",
        ingest_url="http://localhost:9",
        disabled=False,
        auto=False,
        **extra,
    )
    events: list[dict[str, Any]] = []
    monkeypatch.setattr(
        WRAP_MODULE,
        "send_audit_async",
        lambda _config, event: events.append(event),
    )
    return events


def _model() -> Any:
    return genai.GenerativeModel("gemini-pro")


def _response() -> Any:
    return SimpleNamespace(
        text="real-package response",
        usage_metadata=SimpleNamespace(
            prompt_token_count=2,
            candidates_token_count=3,
            total_token_count=5,
        ),
    )


def test_real_start_chat_sync_block_stops_before_send(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = _init(monkeypatch, pii_policy={"rules": {"ssn": "block"}})
    raw = _model()
    chat_type = type(raw.start_chat(history=[]))
    calls: list[Any] = []

    def fake_send(_chat: Any, content: Any, **_kwargs: Any) -> Any:
        calls.append(content)
        return _response()

    monkeypatch.setattr(chat_type, "send_message", fake_send)
    chat = obsvr.wrap(raw).start_chat(history=[])

    with pytest.raises(RuntimeError, match="blocked by policy"):
        chat.send_message(f"ssn {SSN}")

    assert calls == []
    assert events[0]["event_type"] == "blocked_call"


def test_real_start_chat_sync_redacts_provider_input_without_mutating_caller(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _init(monkeypatch, pii_policy={"rules": {"email": "redact"}})
    raw = _model()
    chat_type = type(raw.start_chat(history=[]))
    calls: list[Any] = []

    def fake_send(_chat: Any, content: Any, **_kwargs: Any) -> Any:
        calls.append(content)
        return _response()

    monkeypatch.setattr(chat_type, "send_message", fake_send)
    original = f"mail {EMAIL}"
    obsvr.wrap(raw).start_chat(history=[]).send_message(original)

    assert original == f"mail {EMAIL}"
    assert calls == ["mail [REDACTED_EMAIL]"]


def test_real_start_chat_async_block_stops_before_send(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = _init(monkeypatch, pii_policy={"rules": {"ssn": "block"}})
    raw = _model()
    chat_type = type(raw.start_chat(history=[]))
    calls: list[Any] = []

    async def fake_send(_chat: Any, content: Any, **_kwargs: Any) -> Any:
        calls.append(content)
        return _response()

    monkeypatch.setattr(chat_type, "send_message_async", fake_send)
    chat = obsvr.wrap(raw).start_chat(history=[])

    with pytest.raises(RuntimeError, match="blocked by policy"):
        asyncio.run(chat.send_message_async(f"ssn {SSN}"))

    assert calls == []
    assert events[0]["event_type"] == "blocked_call"


def test_real_start_chat_async_redacts_provider_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _init(monkeypatch, pii_policy={"rules": {"email": "redact"}})
    raw = _model()
    chat_type = type(raw.start_chat(history=[]))
    calls: list[Any] = []

    async def fake_send(_chat: Any, content: Any, **_kwargs: Any) -> Any:
        calls.append(content)
        return _response()

    monkeypatch.setattr(chat_type, "send_message_async", fake_send)
    chat = obsvr.wrap(raw).start_chat(history=[])
    result = asyncio.run(chat.send_message_async(f"mail {EMAIL}"))

    assert result.text == "real-package response"
    assert calls == ["mail [REDACTED_EMAIL]"]
