"""Provider-runner enforcement against the installed Anthropic package."""

import json

import httpx
import pytest

import obsvr
from obsvr import sender
from obsvr.config import _reset
from obsvr.errors import ObsvrPolicyError

anthropic = pytest.importorskip("anthropic")


def test_later_tool_runner_turn_blocks_before_a_second_http_request(monkeypatch):
    provider_calls = []

    def provider(request):
        provider_calls.append(request)
        body = {
            "id": "msg_tool",
            "type": "message",
            "role": "assistant",
            "model": "claude-test",
            "content": [
                {
                    "type": "tool_use",
                    "id": "toolu_secret",
                    "name": "return_secret",
                    "input": {},
                }
            ],
            "stop_reason": "tool_use",
            "stop_sequence": None,
            "usage": {"input_tokens": 4, "output_tokens": 2},
        }
        return httpx.Response(200, content=json.dumps(body).encode())

    from obsvr import register

    client_class = register.originals.get("anthropic.Anthropic", anthropic.Anthropic)
    raw = client_class(
        api_key="test-key-not-real",
        http_client=httpx.Client(transport=httpx.MockTransport(provider)),
    )

    _reset()
    sender._reset_sender()
    monkeypatch.setattr(sender, "send_audit_async", lambda *_args: None)
    import sys

    monkeypatch.setattr(
        sys.modules["obsvr.wrap"], "send_audit_async", lambda *_args: None
    )
    obsvr.init(
        api_key="test-key",
        ingest_url="http://localhost:9",
        pii_policy={"rules": {"ssn": "block"}},
    )

    @anthropic.beta_tool
    def return_secret() -> str:
        """Return test data."""
        return "123-45-6789"

    runner = obsvr.wrap(raw).beta.messages.tool_runner(
        model="claude-test",
        max_tokens=32,
        messages=[{"role": "user", "content": "return the tool result"}],
        tools=[return_secret],
    )

    try:
        with pytest.raises(ObsvrPolicyError):
            runner.until_done()
        assert len(provider_calls) == 1
    finally:
        raw.close()
