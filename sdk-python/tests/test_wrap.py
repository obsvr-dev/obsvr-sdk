"""Tests for obsvr.wrap() - the Python client interceptor.

Fake clients duck-type the three supported providers so no network or real
SDK is needed. Parity target: sdk/tests/unit/wrapper.test.ts behaviors.
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


class _Completions:
    def __init__(self):
        self.calls = []

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

    async def create(self, **kwargs):
        self.calls.append(kwargs)
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
