"""Tests for the AWS Bedrock (Python) integration.

A fake boto3 bedrock-runtime client duck-types the real client (converse /
invoke_model + streaming). boto3 is not installed in this env, so the test
exercises OUR interception logic against a fake client — exactly what the task
asks for. The wrapper binds to a real boto3 client identically.
"""
import copy
import json

import pytest

import obsvr
from obsvr.integrations.bedrock import wrap_bedrock


CONVERSE_RESPONSE = {
    "output": {"message": {"role": "assistant", "content": [{"text": "Hi there"}]}},
    "usage": {"inputTokens": 10, "outputTokens": 5, "totalTokens": 15},
    "ResponseMetadata": {"HTTPStatusCode": 200},
}


class FakeStreamingBody:
    def __init__(self, data: bytes):
        self._data = data

    def read(self, *_a, **_k):
        return self._data


class FakeBedrockClient:
    def __init__(self, invoke_text="The answer is 42", converse_response=None):
        self.converse_calls = []
        self.invoke_calls = []
        self.stream_calls = []
        self._invoke_text = invoke_text
        self._converse_response = converse_response or CONVERSE_RESPONSE

    def converse(self, **kwargs):
        self.converse_calls.append(copy.deepcopy(kwargs))
        return copy.deepcopy(self._converse_response)

    def invoke_model(self, **kwargs):
        self.invoke_calls.append(copy.deepcopy(kwargs))
        body = json.dumps({"content": [{"text": self._invoke_text}]}).encode("utf-8")
        return {"body": FakeStreamingBody(body), "contentType": "application/json"}

    def converse_stream(self, **kwargs):
        self.stream_calls.append(copy.deepcopy(kwargs))
        events = [
            {"contentBlockDelta": {"delta": {"text": "Hel"}}},
            {"contentBlockDelta": {"delta": {"text": "lo"}}},
        ]
        return {"stream": iter(events)}

    def list_foundation_models(self):
        return {"modelSummaries": []}


def _init(**extra):
    extra.setdefault("policy_refresh_interval_s", 0)
    obsvr.init(api_key="k", ingest_url="http://localhost:9", **extra)


def _converse_kwargs(text="Hello", model="anthropic.claude-3-5-sonnet-20241022-v2:0"):
    return {"modelId": model, "messages": [{"role": "user", "content": [{"text": text}]}]}


def _invoke_kwargs(text="Hello", model="anthropic.claude-3-5-sonnet-20241022-v2:0"):
    body = json.dumps({"messages": [{"role": "user", "content": text}]}).encode("utf-8")
    return {"modelId": model, "body": body}


# ── Converse ─────────────────────────────────────────────────────────────────

def test_converse_allowed_passes_and_audits(sent):
    _init()
    client = wrap_bedrock(FakeBedrockClient())
    resp = client.converse(**_converse_kwargs("What is 2+2?"))
    assert resp["output"]["message"]["content"][0]["text"] == "Hi there"
    assert len(client.converse_calls) == 1
    assert len(sent) == 1
    ev = sent[0]
    assert ev["provider"] == "bedrock"
    assert ev["operation"] == "bedrock.converse"
    assert ev["success"] is True


def test_converse_pii_block_stops_execution(sent):
    _init(pii_policy={"rules": {"ssn": "block"}})
    fake = FakeBedrockClient()
    client = wrap_bedrock(fake)
    with pytest.raises(RuntimeError):
        client.converse(**_converse_kwargs("my ssn is 123-45-6789"))
    assert fake.converse_calls == []  # never executed
    assert sent[0]["event_type"] == "blocked_call"
    assert sent[0]["action_taken"] == "blocked"


def test_converse_pre_call_hook_block_stops_execution(sent):
    _init(on_pre_call=lambda e: "block")
    fake = FakeBedrockClient()
    client = wrap_bedrock(fake)
    with pytest.raises(RuntimeError):
        client.converse(**_converse_kwargs("anything"))
    assert fake.converse_calls == []


def test_converse_redacts_input_before_send(sent):
    _init(pii_policy={"rules": {"email": "redact"}})
    fake = FakeBedrockClient()
    client = wrap_bedrock(fake)
    client.converse(**_converse_kwargs("email me at alice@example.com"))
    assert len(fake.converse_calls) == 1
    sent_text = fake.converse_calls[0]["messages"][0]["content"][0]["text"]
    assert "alice@example.com" not in sent_text
    assert "[REDACTED_EMAIL]" in sent_text


def test_converse_post_call_redacts_output(sent):
    resp = copy.deepcopy(CONVERSE_RESPONSE)
    resp["output"]["message"]["content"][0]["text"] = "the ssn is 123-45-6789"
    _init(pii_policy={"default": "redact"})
    client = wrap_bedrock(FakeBedrockClient(converse_response=resp))
    out = client.converse(**_converse_kwargs("give me the record"))
    returned = out["output"]["message"]["content"][0]["text"]
    assert "123-45-6789" not in returned  # returned output governed
    assert sent[-1]["action_taken"] == "redacted"
    assert "123-45-6789" not in sent[-1]["response"]


# ── InvokeModel ──────────────────────────────────────────────────────────────

def test_invoke_model_allowed_passes(sent):
    _init()
    fake = FakeBedrockClient()
    client = wrap_bedrock(fake)
    resp = client.invoke_model(**_invoke_kwargs("hello"))
    assert len(fake.invoke_calls) == 1
    body = json.loads(resp["body"].read())  # re-readable after governance
    assert body["content"][0]["text"] == "The answer is 42"
    assert sent[0]["operation"] == "bedrock.invoke_model"


def test_invoke_model_pii_block_stops_execution(sent):
    _init(pii_policy={"rules": {"ssn": "block"}})
    fake = FakeBedrockClient()
    client = wrap_bedrock(fake)
    with pytest.raises(RuntimeError):
        client.invoke_model(**_invoke_kwargs("ssn 123-45-6789"))
    assert fake.invoke_calls == []


def test_invoke_model_post_call_redacts_output(sent):
    _init(pii_policy={"default": "redact"})
    fake = FakeBedrockClient(invoke_text="contact 555-123-4567 now")
    client = wrap_bedrock(fake)
    resp = client.invoke_model(**_invoke_kwargs("give contact"))
    body = json.loads(resp["body"].read())
    assert "555-123-4567" not in body["content"][0]["text"]


# ── Streaming ────────────────────────────────────────────────────────────────

def test_converse_stream_block_stops_before_stream(sent):
    _init(on_pre_call=lambda e: "block")
    fake = FakeBedrockClient()
    client = wrap_bedrock(fake)
    with pytest.raises(RuntimeError):
        client.converse_stream(**_converse_kwargs("x"))
    assert fake.stream_calls == []


def test_converse_stream_accumulates_and_audits(sent):
    _init()
    client = wrap_bedrock(FakeBedrockClient())
    resp = client.converse_stream(**_converse_kwargs("hi"))
    chunks = list(resp["stream"])
    assert len(chunks) == 2
    assert sent[-1]["response"] == "Hello"


# ── Wrapper mechanics ────────────────────────────────────────────────────────

def test_non_governed_method_passes_through(sent):
    _init()
    client = wrap_bedrock(FakeBedrockClient())
    assert client.list_foundation_models() == {"modelSummaries": []}
    assert sent == []  # passthrough is not audited


def test_wrap_is_idempotent(sent):
    _init()
    fake = FakeBedrockClient()
    once = wrap_bedrock(fake)
    twice = wrap_bedrock(once)
    assert once is twice


# ── Canary-leak hygiene (blocked-event must never persist the raw token) ──────

def test_converse_canary_block_never_persists_token(sent):
    """A canary echoed in a Bedrock request blocks the call, and the blocked
    event stores placeholders — the raw token never lands in prompt/user_input
    (regression: the infra integrations stored user_input via redact_builtin_pii
    which does not know the canary format)."""
    from obsvr.canary import mint_canary, CANARY_REDACTION_PLACEHOLDER

    _init(pii_policy={})
    c = mint_canary()
    fake = FakeBedrockClient()
    client = wrap_bedrock(fake)
    with pytest.raises(RuntimeError):
        client.converse(**_converse_kwargs("leaked: " + c["token"]))
    assert fake.converse_calls == []  # never executed
    ev = sent[0]
    assert ev["event_type"] == "blocked_call"
    assert ev["rule_id"] == "sdk:canary_leak"
    assert ev["user_input"] == CANARY_REDACTION_PLACEHOLDER
    # The raw token appears NOWHERE in the emitted event.
    blob = json.dumps(ev, default=str)
    assert c["token"] not in blob
    assert c["token"][len("obsvr-cnry-"):] not in blob
