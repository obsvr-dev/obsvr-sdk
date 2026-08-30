"""Text-bearing OpenAI routes enforced against the installed package."""

import json

import httpx
import pytest

import obsvr
from obsvr import sender
from obsvr.config import _reset
from obsvr.errors import ObsvrPolicyError

openai = pytest.importorskip("openai")


@pytest.fixture(autouse=True)
def reset_obsvr(monkeypatch):
    _reset()
    sender._reset_sender()
    monkeypatch.setattr(sender, "send_audit_async", lambda *_args: None)
    import sys

    monkeypatch.setattr(
        sys.modules["obsvr.wrap"], "send_audit_async", lambda *_args: None
    )
    yield
    _reset()
    sender._reset_sender()


def _client(provider_calls, response_body=None):
    response_body = response_body or {
        "id": "cmpl-real-pkg-test",
        "object": "text_completion",
        "created": 1720000000,
        "model": "gpt-3.5-turbo-instruct",
        "choices": [
            {
                "index": 0,
                "text": "done",
                "finish_reason": "stop",
                "logprobs": None,
            }
        ],
        "usage": {"prompt_tokens": 7, "completion_tokens": 1, "total_tokens": 8},
    }

    def provider(request):
        provider_calls.append(request)
        return httpx.Response(200, content=json.dumps(response_body).encode())

    return openai.OpenAI(
        api_key="test-key-not-real",
        http_client=httpx.Client(transport=httpx.MockTransport(provider)),
    )


def _init_block():
    obsvr.init(
        api_key="test-key",
        ingest_url="http://localhost:9",
        policy_rules=[
            {
                "id": "r-block-launch",
                "name": "Block launch-code talk",
                "enabled": True,
                "action": "block",
                "type": "keyword",
                "conditions": {"keywords": ["launch codes"]},
            }
        ],
    )


def test_legacy_completion_blocks_before_http():
    _init_block()
    provider_calls = []
    raw = _client(provider_calls)

    try:
        with pytest.raises(ObsvrPolicyError):
            obsvr.wrap(raw).completions.create(
                model="gpt-3.5-turbo-instruct",
                prompt="tell me the launch codes",
            )
        assert provider_calls == []
    finally:
        raw.close()


def test_legacy_completion_redacts_before_http():
    obsvr.init(
        api_key="test-key",
        ingest_url="http://localhost:9",
        pii_policy={"rules": {"ssn": "redact"}},
    )
    provider_calls = []
    raw = _client(provider_calls)

    try:
        obsvr.wrap(raw).completions.create(
            model="gpt-3.5-turbo-instruct",
            prompt="customer 123-45-6789",
        )
        assert len(provider_calls) == 1
        outbound = json.loads(provider_calls[0].content)
        assert "[REDACTED_SSN]" in outbound["prompt"]
        assert "123-45-6789" not in outbound["prompt"]
    finally:
        raw.close()


@pytest.mark.parametrize("path", ["responses.compact", "beta.responses.compact"])
def test_response_compaction_blocks_before_http(path):
    _init_block()
    provider_calls = []
    raw = _client(provider_calls)
    wrapped = obsvr.wrap(raw)
    target = wrapped.responses if path == "responses.compact" else wrapped.beta.responses

    try:
        with pytest.raises(ObsvrPolicyError):
            target.compact(model="gpt-4o-mini", input="tell me the launch codes")
        assert provider_calls == []
    finally:
        raw.close()
