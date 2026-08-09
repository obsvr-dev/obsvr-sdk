"""Tests for obsvr.wrap() - the Python client interceptor.

Fake clients duck-type the three supported providers so no network or real
SDK is needed. Parity target: sdk-typescript/tests/unit/wrapper.test.ts behaviors.
"""
import asyncio
import sys
import types

import pytest

import obsvr
import obsvr.wrap  # ensure module is loaded; package attr shadows it
from obsvr import sender
from obsvr.config import _reset

WRAP_MODULE = sys.modules["obsvr.wrap"]


# ── Fake provider clients ────────────────────────────────────────────────────

class FakeUsage:
    prompt_tokens = 7
    completion_tokens = 5
    total_tokens = 12


class FakeMessage:
    content = "fake openai answer"


class FakeChoice:
    message = FakeMessage()


class FakeOpenAIResponse:
    choices = [FakeChoice()]
    usage = FakeUsage()


class FakeRawResponse:
    status_code = 200

    def __init__(self, parsed):
        self.parsed = parsed
        self.parse_calls = 0

    def parse(self):
        self.parse_calls += 1
        return self.parsed


class _RawCompletions:
    def __init__(self, owner):
        self.owner = owner

    def create(self, **kwargs):
        self.owner.calls.append(kwargs)
        return FakeRawResponse(FakeOpenAIResponse())


class FakeStreamingResponse:
    status_code = 200

    def parse(self):
        return FakeOpenAIResponse()


class _ResponseManager:
    def __init__(self, owner, kwargs):
        self.owner = owner
        self.kwargs = kwargs

    def __enter__(self):
        self.owner.calls.append(self.kwargs)
        return FakeStreamingResponse()

    def __exit__(self, *exc_info):
        return False


class _StreamingCompletions:
    def __init__(self, owner):
        self.owner = owner

    def create(self, **kwargs):
        return _ResponseManager(self.owner, kwargs)


class _Completions:
    def __init__(self):
        self.calls = []
        self.with_raw_response = _RawCompletions(self)
        self.with_streaming_response = _StreamingCompletions(self)

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return FakeOpenAIResponse()


class _Chat:
    def __init__(self):
        self.completions = _Completions()


class FakeOpenAI:
    def __init__(self):
        self.chat = _Chat()
        self.api_key = "not-a-real-key"


class _AsyncCompletions:
    def __init__(self):
        self.calls = []
        self.with_raw_response = _AsyncRawCompletions(self)
        self.with_streaming_response = _AsyncStreamingCompletions(self)

    async def create(self, **kwargs):
        self.calls.append(kwargs)
        return FakeOpenAIResponse()


class _AsyncRawCompletions:
    def __init__(self, owner):
        self.owner = owner

    async def create(self, **kwargs):
        self.owner.calls.append(kwargs)
        return FakeRawResponse(FakeOpenAIResponse())


class _AsyncResponseManager:
    def __init__(self, owner, kwargs):
        self.owner = owner
        self.kwargs = kwargs

    async def __aenter__(self):
        self.owner.calls.append(self.kwargs)
        return FakeAsyncStreamingResponse()

    async def __aexit__(self, *exc_info):
        return False


class _AsyncStreamingCompletions:
    def __init__(self, owner):
        self.owner = owner

    def create(self, **kwargs):
        return _AsyncResponseManager(self.owner, kwargs)


class FakeAsyncStreamingResponse:
    status_code = 200

    async def parse(self):
        return FakeOpenAIResponse()


class _AsyncChat:
    def __init__(self):
        self.completions = _AsyncCompletions()


class FakeAsyncOpenAI:
    def __init__(self):
        self.chat = _AsyncChat()


class FakeAnthropicContentBlock:
    text = "fake anthropic answer"


class FakeAnthropicResponse:
    content = [FakeAnthropicContentBlock()]
    usage = types.SimpleNamespace(input_tokens=3, output_tokens=4)


class _Messages:
    def __init__(self):
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return FakeAnthropicResponse()


class FakeAnthropic:
    def __init__(self):
        self.messages = _Messages()


class FakeGeminiResponse:
    text = "fake gemini answer"
    usage_metadata = types.SimpleNamespace(
        prompt_token_count=2, candidates_token_count=3, total_token_count=5
    )


class FakeResponsesAPIResult:
    output_text = "fake responses answer"
    usage = types.SimpleNamespace(input_tokens=9, output_tokens=6, total_tokens=15)


class _Responses:
    def __init__(self):
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return FakeResponsesAPIResult()


class FakeOpenAIResponses:
    """Duck-typed OpenAI client exposing only the Responses API surface."""

    def __init__(self):
        self.responses = _Responses()


class FakeGenerativeModel:
    model_name = "gemini-2.5-flash"

    def __init__(self):
        self.calls = []

    def generate_content(self, prompt, **kwargs):
        self.calls.append(prompt)
        return FakeGeminiResponse()

    async def generate_content_async(self, prompt, **kwargs):
        self.calls.append(prompt)
        return FakeGeminiResponse()

    def start_chat(self, **kwargs):
        return FakeChatSession(self, kwargs)


class FakeChatSession:
    def __init__(self, model, start_options):
        self.model = model
        self.start_options = start_options

    def send_message(self, prompt, **kwargs):
        self.model.calls.append(prompt)
        return FakeGeminiResponse()

    async def send_message_async(self, prompt, **kwargs):
        self.model.calls.append(prompt)
        return FakeGeminiResponse()


# ── Helpers ──────────────────────────────────────────────────────────────────

def _init(**extra):
    _reset()
    sender._reset_sender()
    extra.setdefault("disabled", False)
    obsvr.init(api_key="test-key", ingest_url="http://localhost:9", **extra)


def _captured_events(monkeypatch):
    """Capture events instead of hitting the network."""
    captured = []

    def fake_send(config, event):
        captured.append(event)

    monkeypatch.setattr(WRAP_MODULE, "send_audit_async", fake_send)
    return captured


# ── Tests ────────────────────────────────────────────────────────────────────

class TestWrapBasics:
    def test_requires_init(self):
        _reset()
        with pytest.raises(RuntimeError):
            obsvr.wrap(FakeOpenAI())

    def test_disabled_returns_unwrapped(self):
        _init(disabled=True)
        client = FakeOpenAI()
        assert obsvr.wrap(client) is client

    def test_non_audited_attributes_pass_through(self):
        _init()
        client = obsvr.wrap(FakeOpenAI())
        assert client.api_key == "not-a-real-key"


class TestOpenAIInterception:
    def test_call_passes_through_and_emits_event(self, monkeypatch):
        _init()
        captured = _captured_events(monkeypatch)
        client = obsvr.wrap(FakeOpenAI())
        result = client.chat.completions.create(
            model="gpt-4o", messages=[{"role": "user", "content": "hello"}]
        )
        assert result.choices[0].message.content == "fake openai answer"
        assert len(captured) == 1
        ev = captured[0]
        assert ev["provider"] == "openai"
        assert ev["model"] == "gpt-4o"
        assert ev["operation"] == "chat.completions.create"
        assert ev["prompt"] == "hello"
        assert ev["response"] == "fake openai answer"
        assert ev["input_tokens"] == 7 and ev["output_tokens"] == 5

    def test_pii_block_prevents_provider_call(self, monkeypatch):
        _init(pii_policy={"rules": {"ssn": "block"}})
        captured = _captured_events(monkeypatch)
        raw = FakeOpenAI()
        client = obsvr.wrap(raw)
        with pytest.raises(RuntimeError):
            client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": "my ssn is 123-45-6789"}],
            )
        assert raw.chat.completions.calls == []  # provider never contacted
        assert len(captured) == 1
        ev = captured[0]
        assert ev["event_type"] == "blocked_call"
        assert ev["action_taken"] == "blocked"
        # a policy block is a 403, not a 500 (server error).
        assert ev["status_code"] == 403
        # the block was triggered by the SSN — it must NEVER egress raw,
        # not in user_input (the previous leak) nor in the stored prompt.
        assert "123-45-6789" not in (ev.get("user_input") or "")
        assert "123-45-6789" not in (ev.get("prompt") or "")

    def test_pii_redact_modifies_outbound_messages(self, monkeypatch):
        _init(pii_policy={"rules": {"email": "redact"}})
        _captured_events(monkeypatch)
        raw = FakeOpenAI()
        client = obsvr.wrap(raw)
        client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "mail me at a@b.com please"}],
        )
        sent = raw.chat.completions.calls[0]["messages"][0]["content"]
        assert "a@b.com" not in sent
        assert "[REDACTED_EMAIL]" in sent

    def test_with_raw_response_is_governed_and_preserves_raw_object(self, monkeypatch):
        _init()
        captured = _captured_events(monkeypatch)
        raw = FakeOpenAI()
        client = obsvr.wrap(raw)

        result = client.chat.completions.with_raw_response.create(
            model="gpt-4o", messages=[{"role": "user", "content": "raw hello"}]
        )

        assert isinstance(result, FakeRawResponse)
        assert result.status_code == 200
        assert result.parse_calls == 1
        assert raw.chat.completions.calls[0]["messages"][0]["content"] == "raw hello"
        assert len(captured) == 1
        assert captured[0]["operation"] == "chat.completions.with_raw_response.create"
        assert captured[0]["response"] == "fake openai answer"

    def test_with_raw_response_block_prevents_provider_call(self, monkeypatch):
        _init(pii_policy={"rules": {"ssn": "block"}})
        captured = _captured_events(monkeypatch)
        raw = FakeOpenAI()
        client = obsvr.wrap(raw)

        with pytest.raises(RuntimeError, match="blocked by policy"):
            client.chat.completions.with_raw_response.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": "ssn 123-45-6789"}],
            )

        assert raw.chat.completions.calls == []
        assert len(captured) == 1
        assert captured[0]["event_type"] == "blocked_call"

    def test_with_streaming_response_is_deferred_and_governed(self, monkeypatch):
        _init()
        captured = _captured_events(monkeypatch)
        raw = FakeOpenAI()
        client = obsvr.wrap(raw)

        manager = client.chat.completions.with_streaming_response.create(
            model="gpt-4o", messages=[{"role": "user", "content": "stream raw hi"}]
        )

        assert raw.chat.completions.calls == []
        with manager as response:
            assert response.status_code == 200
            parsed = response.parse()
            assert parsed.choices[0].message.content == "fake openai answer"
            assert captured == []

        assert len(raw.chat.completions.calls) == 1
        assert len(captured) == 1
        assert captured[0]["operation"] == (
            "chat.completions.with_streaming_response.create"
        )
        assert captured[0]["response"] == "fake openai answer"

    def test_with_streaming_response_block_prevents_manager_creation(self, monkeypatch):
        _init(pii_policy={"rules": {"ssn": "block"}})
        captured = _captured_events(monkeypatch)
        raw = FakeOpenAI()
        client = obsvr.wrap(raw)

        with pytest.raises(RuntimeError, match="blocked by policy"):
            client.chat.completions.with_streaming_response.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": "ssn 123-45-6789"}],
            )

        assert raw.chat.completions.calls == []
        assert len(captured) == 1
        assert captured[0]["event_type"] == "blocked_call"

    def test_pre_call_hook_block(self, monkeypatch):
        _init(on_pre_call=lambda event: "block")
        captured = _captured_events(monkeypatch)
        raw = FakeOpenAI()
        client = obsvr.wrap(raw)
        with pytest.raises(RuntimeError):
            client.chat.completions.create(
                model="gpt-4o", messages=[{"role": "user", "content": "hi"}]
            )
        assert raw.chat.completions.calls == []
        assert captured[0]["action_taken"] == "blocked"
        # a non-PII (policy_violation) block stores the placeholder, not the
        # offending prompt; status 403.
        assert captured[0]["prompt"] == "[BLOCKED_BY_POLICY]"
        assert captured[0]["status_code"] == 403

    def test_provider_error_emits_failure_event(self, monkeypatch):
        _init()
        captured = _captured_events(monkeypatch)

        class Boom(FakeOpenAI):
            def __init__(self):
                super().__init__()
                def exploding_create(**kwargs):
                    raise ValueError("rate limit exceeded")
                self.chat.completions.create = exploding_create

        client = obsvr.wrap(Boom())
        with pytest.raises(ValueError):
            client.chat.completions.create(
                model="gpt-4o", messages=[{"role": "user", "content": "hi"}]
            )
        assert len(captured) == 1
        assert captured[0]["success"] is False
        assert captured[0]["error_type"] == "rate_limit"


class TestAsyncOpenAI:
    def test_async_call_intercepted(self, monkeypatch):
        _init()
        captured = _captured_events(monkeypatch)
        client = obsvr.wrap(FakeAsyncOpenAI())

        async def run():
            return await client.chat.completions.create(
                model="gpt-4o", messages=[{"role": "user", "content": "async hi"}]
            )

        result = asyncio.run(run())
        assert result.choices[0].message.content == "fake openai answer"
        assert len(captured) == 1
        assert captured[0]["prompt"] == "async hi"

    def test_async_with_raw_response_is_governed(self, monkeypatch):
        _init()
        captured = _captured_events(monkeypatch)
        raw = FakeAsyncOpenAI()
        client = obsvr.wrap(raw)

        async def run():
            return await client.chat.completions.with_raw_response.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": "async raw hi"}],
            )

        result = asyncio.run(run())
        assert isinstance(result, FakeRawResponse)
        assert result.parse_calls == 1
        assert len(captured) == 1
        assert captured[0]["response"] == "fake openai answer"

    def test_async_with_streaming_response_is_deferred_and_governed(self, monkeypatch):
        _init()
        captured = _captured_events(monkeypatch)
        raw = FakeAsyncOpenAI()
        client = obsvr.wrap(raw)

        async def run():
            manager = client.chat.completions.with_streaming_response.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": "async stream raw hi"}],
            )
            assert raw.chat.completions.calls == []
            async with manager as response:
                assert response.status_code == 200
                parsed = await response.parse()
                assert captured == []
                return parsed

        result = asyncio.run(run())
        assert result.choices[0].message.content == "fake openai answer"
        assert len(raw.chat.completions.calls) == 1
        assert len(captured) == 1
        assert captured[0]["operation"] == (
            "chat.completions.with_streaming_response.create"
        )
        assert captured[0]["response"] == "fake openai answer"


class TestAnthropicInterception:
    def test_messages_create_intercepted(self, monkeypatch):
        _init()
        captured = _captured_events(monkeypatch)
        client = obsvr.wrap(FakeAnthropic())
        result = client.messages.create(
            model="claude-sonnet-5",
            max_tokens=64,
            messages=[{"role": "user", "content": "hello claude"}],
        )
        assert result.content[0].text == "fake anthropic answer"
        ev = captured[0]
        assert ev["provider"] == "anthropic"
        assert ev["operation"] == "messages.create"
        assert ev["response"] == "fake anthropic answer"
        assert ev["input_tokens"] == 3 and ev["output_tokens"] == 4


class TestGeminiInterception:
    def test_generate_content_intercepted(self, monkeypatch):
        _init()
        captured = _captured_events(monkeypatch)
        model = obsvr.wrap(FakeGenerativeModel())
        result = model.generate_content("hello gemini")
        assert result.text == "fake gemini answer"
        ev = captured[0]
        assert ev["provider"] == "google"
        assert ev["model"] == "gemini-2.5-flash"
        assert ev["prompt"] == "hello gemini"
        assert ev["total_tokens"] == 5

    def test_generate_content_async_intercepted(self, monkeypatch):
        _init()
        captured = _captured_events(monkeypatch)
        raw = FakeGenerativeModel()
        model = obsvr.wrap(raw)

        result = asyncio.run(model.generate_content_async("hello async gemini"))

        assert result.text == "fake gemini answer"
        assert raw.calls == ["hello async gemini"]
        assert len(captured) == 1
        assert captured[0]["operation"] == "generate_content_async"
        assert captured[0]["prompt"] == "hello async gemini"

    def test_generate_content_async_block_prevents_provider_call(self, monkeypatch):
        _init(pii_policy={})
        captured = _captured_events(monkeypatch)
        raw = FakeGenerativeModel()
        model = obsvr.wrap(raw)

        async def run():
            await model.generate_content_async("my ssn is 123-45-6789")

        with pytest.raises(RuntimeError, match="blocked by policy"):
            asyncio.run(run())

        assert raw.calls == []
        assert len(captured) == 1
        assert captured[0]["event_type"] == "blocked_call"
        assert "123-45-6789" not in (captured[0].get("user_input") or "")

    def test_start_chat_keeps_sync_messages_governed(self, monkeypatch):
        _init()
        captured = _captured_events(monkeypatch)
        raw = FakeGenerativeModel()
        model = obsvr.wrap(raw)

        chat = model.start_chat(history=[])
        assert captured == []
        result = chat.send_message("hello chat")

        assert result.text == "fake gemini answer"
        assert raw.calls == ["hello chat"]
        assert len(captured) == 1
        assert captured[0]["operation"] == "send_message"
        assert captured[0]["model"] == "gemini-2.5-flash"
        assert captured[0]["prompt"] == "hello chat"

    def test_start_chat_sync_block_prevents_provider_call(self, monkeypatch):
        _init(pii_policy={"rules": {"ssn": "block"}})
        captured = _captured_events(monkeypatch)
        raw = FakeGenerativeModel()
        chat = obsvr.wrap(raw).start_chat()

        with pytest.raises(RuntimeError, match="blocked by policy"):
            chat.send_message("my ssn is 123-45-6789")

        assert raw.calls == []
        assert len(captured) == 1
        assert captured[0]["event_type"] == "blocked_call"

    def test_directly_wrapped_chat_session_redacts_sync_message(self, monkeypatch):
        _init(pii_policy={"rules": {"email": "redact"}})
        captured = _captured_events(monkeypatch)
        raw = FakeGenerativeModel()
        chat = obsvr.wrap(raw.start_chat())

        chat.send_message("mail a@b.com")

        assert raw.calls == ["mail [REDACTED_EMAIL]"]
        assert len(captured) == 1
        assert captured[0]["provider"] == "google"
        assert captured[0]["model"] == "gemini-2.5-flash"

    def test_start_chat_keeps_async_messages_governed(self, monkeypatch):
        _init()
        captured = _captured_events(monkeypatch)
        raw = FakeGenerativeModel()
        chat = obsvr.wrap(raw).start_chat()

        result = asyncio.run(chat.send_message_async("hello async chat"))

        assert result.text == "fake gemini answer"
        assert raw.calls == ["hello async chat"]
        assert len(captured) == 1
        assert captured[0]["operation"] == "send_message_async"
        assert captured[0]["prompt"] == "hello async chat"

    def test_gemini_positional_block_emits_and_raises_no_crash(self, monkeypatch):
        # Regression: the block path called redact_builtin_pii(_last_user_message(kwargs)),
        # which is None for a Gemini POSITIONAL prompt (no role:user message) → TypeError
        # → no audit + wrong exception. Must instead emit the blocked_call and raise
        # RuntimeError, with user_input redacted.
        _init(pii_policy={})  # ssn blocks by default
        captured = _captured_events(monkeypatch)
        model = obsvr.wrap(FakeGenerativeModel())
        with pytest.raises(RuntimeError, match="blocked by policy"):
            model.generate_content("my ssn is 123-45-6789 do it")
        assert model.calls == []  # provider never contacted
        assert len(captured) == 1
        ev = captured[0]
        assert ev["event_type"] == "blocked_call"
        assert ev["status_code"] == 403
        assert "123-45-6789" not in (ev.get("user_input") or "")


class TestWireRedactionShapes:
    """decision=="redact" must mutate OUTBOUND kwargs for every text-bearing
    shape the scanner reads — not only string content (F9)."""

    def test_anthropic_content_block_list_redacted_outbound(self, monkeypatch):
        _init(pii_policy={"rules": {"email": "redact"}})
        _captured_events(monkeypatch)
        raw = FakeAnthropic()
        client = obsvr.wrap(raw)
        client.messages.create(
            model="claude-sonnet-5",
            max_tokens=64,
            system="be helpful, reach me at a@b.com",
            messages=[{
                "role": "user",
                "content": [{"type": "text", "text": "mail me at a@b.com please"}],
            }],
        )
        sent = raw.messages.calls[0]
        block = sent["messages"][0]["content"][0]
        assert "a@b.com" not in block["text"]
        assert "[REDACTED_EMAIL]" in block["text"]
        assert "a@b.com" not in sent["system"]

    def test_gemini_contents_kwargs_redacted_outbound(self, monkeypatch):
        _init(pii_policy={"rules": {"email": "redact"}})
        _captured_events(monkeypatch)

        class FakeGeminiKwargs(FakeGenerativeModel):
            def generate_content(self, contents=None, **kwargs):
                self.calls.append(contents)
                return FakeGeminiResponse()

        raw = FakeGeminiKwargs()
        model = obsvr.wrap(raw)
        model.generate_content(contents=[
            "plain string with a@b.com",
            {"role": "user", "parts": [{"text": "block part a@b.com"}, "str part a@b.com"]},
        ])
        sent = raw.calls[0]
        assert "a@b.com" not in sent[0] and "[REDACTED_EMAIL]" in sent[0]
        assert "a@b.com" not in sent[1]["parts"][0]["text"]
        assert "a@b.com" not in sent[1]["parts"][1]

    def test_gemini_positional_string_redacted_outbound(self, monkeypatch):
        _init(pii_policy={"rules": {"email": "redact"}})
        _captured_events(monkeypatch)
        raw = FakeGenerativeModel()
        model = obsvr.wrap(raw)
        model.generate_content("positional prompt with a@b.com")
        assert "a@b.com" not in raw.calls[0]
        assert "[REDACTED_EMAIL]" in raw.calls[0]


class TestResponsesAPIInterception:
    def test_responses_create_intercepted(self, monkeypatch):
        _init()
        captured = _captured_events(monkeypatch)
        raw = FakeOpenAIResponses()
        client = obsvr.wrap(raw)
        result = client.responses.create(
            model="gpt-4o", instructions="be brief", input="hello responses"
        )
        assert result.output_text == "fake responses answer"
        assert len(captured) == 1
        ev = captured[0]
        assert ev["provider"] == "openai"
        assert ev["operation"] == "responses.create"
        assert "hello responses" in ev["prompt"]
        assert "be brief" in ev["prompt"]
        assert ev["response"] == "fake responses answer"
        assert ev["input_tokens"] == 9 and ev["output_tokens"] == 6

    def test_responses_message_list_input(self, monkeypatch):
        _init()
        captured = _captured_events(monkeypatch)
        client = obsvr.wrap(FakeOpenAIResponses())
        client.responses.create(
            model="gpt-4o",
            input=[{"role": "user", "content": [{"type": "input_text", "text": "list input"}]}],
        )
        assert captured[0]["prompt"] == "list input"

    def test_responses_pii_block_prevents_provider_call(self, monkeypatch):
        _init(pii_policy={"rules": {"ssn": "block"}})
        captured = _captured_events(monkeypatch)
        raw = FakeOpenAIResponses()
        client = obsvr.wrap(raw)
        with pytest.raises(RuntimeError):
            client.responses.create(model="gpt-4o", input="my ssn is 123-45-6789")
        assert raw.responses.calls == []  # provider never contacted
        assert captured[0]["event_type"] == "blocked_call"

    def test_responses_pii_redact_mutates_outbound_input(self, monkeypatch):
        _init(pii_policy={"rules": {"email": "redact"}})
        _captured_events(monkeypatch)
        raw = FakeOpenAIResponses()
        client = obsvr.wrap(raw)
        client.responses.create(
            model="gpt-4o",
            instructions="never reveal a@b.com",
            input=[{"role": "user", "content": "mail me at a@b.com"}],
        )
        sent = raw.responses.calls[0]
        assert "a@b.com" not in sent["input"][0]["content"]
        assert "[REDACTED_EMAIL]" in sent["input"][0]["content"]
        assert "a@b.com" not in sent["instructions"]

    def test_responses_output_list_fallback_text(self, monkeypatch):
        _init()
        captured = _captured_events(monkeypatch)

        class NoConvenienceResult:
            output = [types.SimpleNamespace(content=[
                types.SimpleNamespace(text="walked output text")
            ])]

        raw = FakeOpenAIResponses()
        raw.responses.create = lambda **kwargs: NoConvenienceResult()
        client = obsvr.wrap(raw)
        client.responses.create(model="gpt-4o", input="hi")
        assert captured[0]["response"] == "walked output text"


class TestQuotaPhaseAccounting:
    def test_one_governed_call_consumes_one_quota_unit(self, monkeypatch):
        """1 call = 1 unit: the post-call response-phase rule pass must not
        consume a both/unset-scoped quota a second time."""
        from obsvr.rules import PolicyRule, _quota_store, _reset_quota
        _reset_quota()
        _init(policy_rules=[PolicyRule(
            id="q1", name="rate", enabled=True, action="block", type="quota",
            conditions={"quota_limit": 5, "quota_window_ms": 60000,
                        "quota_scope": "project"},
        )])
        _captured_events(monkeypatch)
        client = obsvr.wrap(FakeOpenAI())
        client.chat.completions.create(
            model="gpt-4o", messages=[{"role": "user", "content": "hello"}]
        )
        assert _quota_store["project:project"]["count"] == 1


class TestEventSigning:
    def test_wrapped_call_produces_signed_event(self):
        """End-to-end through the real sender signing path (queue drained)."""
        _init()
        sender._reset_sender()
        client = obsvr.wrap(FakeOpenAI())

        signed = {}
        original_sign = sender.sign_event

        def spy_sign(event, api_key):
            original_sign(event, api_key)
            signed.update(event)

        sender.sign_event = spy_sign
        try:
            client.chat.completions.create(
                model="gpt-4o", messages=[{"role": "user", "content": "sign me"}]
            )
        finally:
            sender.sign_event = original_sign

        assert signed.get("seq_no") == 1
        assert len(signed.get("sdk_sig", "")) == 64


class TestSignedPrincipalMatchesEnforcedPrincipal:
    """The name on the record is the name policy decided for.

    ``_collect_metadata`` folds the per-call ``obsvr_metadata`` kwarg over the
    wrap-time options and hands the result to the policy layer, so a call may
    be evaluated, metered and taint-keyed under a principal the wrap-time
    options never named. The event has to carry that same principal: a record
    naming one user for a decision made about another is not an audit trail,
    and it is the class of split the shared enforcing-metadata view exists to
    prevent.
    """

    def test_per_call_principal_reaches_the_signed_event(self, monkeypatch):
        _init()
        captured = _captured_events(monkeypatch)
        client = obsvr.wrap(FakeOpenAI(), user_id="wraptime-alice")

        client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "hello"}],
            obsvr_metadata={"user_id": "percall-mallory"},
        )

        ev = captured[0]
        # Both halves, because they fail independently: the enforcing view has
        # to see the override at all, and the event has to sign the same one.
        assert ev["metadata"]["user_id"] == "percall-mallory"
        assert ev["user_id"] == "percall-mallory"

    def test_wrap_time_principal_still_signs_when_no_override(self, monkeypatch):
        # Without this, "the signed principal follows metadata" would also be
        # satisfied by a resolution that had stopped reading the options.
        _init()
        captured = _captured_events(monkeypatch)
        client = obsvr.wrap(FakeOpenAI(), user_id="wraptime-alice")

        client.chat.completions.create(
            model="gpt-4o", messages=[{"role": "user", "content": "hello"}]
        )

        ev = captured[0]
        assert ev["metadata"]["user_id"] == "wraptime-alice"
        assert ev["user_id"] == "wraptime-alice"

    def test_unattributed_call_signs_no_principal(self, monkeypatch):
        # And the absent case stays absent rather than becoming an empty
        # string: the decision digest's presence byte draws that line, and an
        # unset principal is pruned from the event rather than sent as null.
        _init()
        captured = _captured_events(monkeypatch)
        client = obsvr.wrap(FakeOpenAI())

        client.chat.completions.create(
            model="gpt-4o", messages=[{"role": "user", "content": "hello"}]
        )

        assert captured[0].get("user_id") is None
