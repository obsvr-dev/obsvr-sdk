"""Tests for the Google Vertex AI (Python) integration.

A fake GenerativeModel duck-types vertexai's GenerativeModel. The Vertex SDK is
not installed in this env, so the test exercises OUR interception logic against
a fake model; the wrapper binds to a real GenerativeModel identically.
"""
import pytest

import obsvr
from obsvr.integrations.vertex import wrap_vertex


class FakePart:
    def __init__(self, text):
        self.text = text


class FakeContent:
    def __init__(self, text, role="model"):
        self.role = role
        self.parts = [FakePart(text)]


class FakeCandidate:
    def __init__(self, text):
        self.content = FakeContent(text)


class FakeUsage:
    def __init__(self):
        self.prompt_token_count = 12
        self.candidates_token_count = 7
        self.total_token_count = 19


class FakeGenerationResponse:
    def __init__(self, text):
        self.candidates = [FakeCandidate(text)]
        self.usage_metadata = FakeUsage()
        self.model_version = "gemini-1.5-pro-002"

    @property
    def text(self):
        return self.candidates[0].content.parts[0].text


class FakeGenerativeModel:
    def __init__(
        self,
        response_text="Hello from Gemini",
        model_name="gemini-1.5-pro",
        system_instruction=None,
    ):
        self._model_name = model_name
        self._system_instruction = system_instruction
        self._response_text = response_text
        self.calls = []
        self.stream_calls = []

    def generate_content(self, contents, stream=False, **kwargs):
        if stream:
            self.stream_calls.append(contents)
            return iter([FakeGenerationResponse("Hel"), FakeGenerationResponse("lo")])
        self.calls.append(contents)
        return FakeGenerationResponse(self._response_text)

    def count_tokens(self, contents):
        return {"total_tokens": 5}


def _init(**extra):
    extra.setdefault("policy_refresh_interval_s", 0)
    obsvr.init(api_key="k", ingest_url="http://localhost:9", **extra)


def _contents(text="Hello"):
    return [{"role": "user", "parts": [{"text": text}]}]


def test_generate_content_allowed_passes_and_audits(sent):
    _init()
    fake = FakeGenerativeModel()
    model = wrap_vertex(fake)
    resp = model.generate_content(_contents("What is 2+2?"))
    assert resp.text == "Hello from Gemini"
    assert len(fake.calls) == 1
    ev = sent[0]
    assert ev["provider"] == "vertex_ai"
    assert ev["operation"] == "generate_content"
    assert ev["success"] is True


def test_string_prompt_supported(sent):
    _init()
    fake = FakeGenerativeModel()
    model = wrap_vertex(fake)
    model.generate_content("just a string prompt")
    assert len(fake.calls) == 1
    assert sent[0]["success"] is True


def test_pii_block_stops_execution(sent):
    _init(pii_policy={"rules": {"ssn": "block"}})
    fake = FakeGenerativeModel()
    model = wrap_vertex(fake)
    with pytest.raises(RuntimeError):
        model.generate_content(_contents("my ssn is 123-45-6789"))
    assert fake.calls == []  # never executed
    assert sent[0]["event_type"] == "blocked_call"


def test_model_system_instruction_block_stops_clean_request(sent):
    _init(pii_policy={"rules": {"ssn": "block"}})
    fake = FakeGenerativeModel(system_instruction=FakeContent("SSN 123-45-6789", "system"))
    model = wrap_vertex(fake)
    with pytest.raises(RuntimeError, match="blocked by policy"):
        model.generate_content(_contents("safe request"))
    assert fake.calls == []


def test_sensitive_earlier_turn_block_stops_clean_final_request(sent):
    _init(pii_policy={"rules": {"ssn": "block"}})
    fake = FakeGenerativeModel()
    model = wrap_vertex(fake)
    request = [
        {"role": "user", "parts": [{"text": "SSN 123-45-6789"}]},
        {"role": "model", "parts": [{"text": "noted"}]},
        {"role": "user", "parts": [{"text": "safe request"}]},
    ]
    with pytest.raises(RuntimeError, match="blocked by policy"):
        model.generate_content(request)
    assert fake.calls == []


def test_pre_call_hook_block_stops_execution(sent):
    _init(on_pre_call=lambda e: "block")
    fake = FakeGenerativeModel()
    model = wrap_vertex(fake)
    with pytest.raises(RuntimeError):
        model.generate_content(_contents("anything"))
    assert fake.calls == []


def test_redacts_input_before_send(sent):
    _init(pii_policy={"rules": {"email": "redact"}})
    fake = FakeGenerativeModel()
    model = wrap_vertex(fake)
    model.generate_content(_contents("mail me alice@example.com"))
    sent_text = fake.calls[0][0]["parts"][0]["text"]
    assert "alice@example.com" not in sent_text
    assert "[REDACTED_EMAIL]" in sent_text


def test_redacts_copy_without_mutating_caller_input(sent):
    _init(pii_policy={"rules": {"email": "redact"}})
    fake = FakeGenerativeModel()
    model = wrap_vertex(fake)
    request = _contents("mail me alice@example.com")

    model.generate_content(request)

    assert fake.calls[0][0]["parts"][0]["text"] == "mail me [REDACTED_EMAIL]"
    assert request[0]["parts"][0]["text"] == "mail me alice@example.com"


def test_unrewritable_model_system_redaction_fails_closed(sent):
    _init(pii_policy={"rules": {"email": "redact"}})
    fake = FakeGenerativeModel(
        system_instruction=FakeContent("email system@example.com", "system")
    )
    model = wrap_vertex(fake)

    with pytest.raises(RuntimeError, match="blocked by policy"):
        model.generate_content(_contents("safe request"))

    assert fake.calls == []
    assert sent[0]["action_taken"] == "blocked"
    assert sent[0]["redacted_types"] == []


def test_post_call_redacts_output(sent):
    _init(pii_policy={"default": "redact"})
    fake = FakeGenerativeModel(response_text="the ssn is 123-45-6789")
    model = wrap_vertex(fake)
    resp = model.generate_content(_contents("give me the record"))
    assert "123-45-6789" not in resp.text  # returned output governed
    assert sent[-1]["action_taken"] == "redacted"


def test_stream_accumulates_and_audits(sent):
    _init()
    fake = FakeGenerativeModel()
    model = wrap_vertex(fake)
    stream = model.generate_content(_contents("hi"), stream=True)
    chunks = list(stream)
    assert len(chunks) == 2
    assert sent[-1]["response"] == "Hello"


def test_non_governed_method_passes_through(sent):
    _init()
    model = wrap_vertex(FakeGenerativeModel())
    assert model.count_tokens("x") == {"total_tokens": 5}
    assert sent == []


def test_wrap_is_idempotent(sent):
    _init()
    fake = FakeGenerativeModel()
    once = wrap_vertex(fake)
    assert wrap_vertex(once) is once
