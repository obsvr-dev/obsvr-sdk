"""LlamaIndex's real model callback boundary with a local transport spy.

The official LLM decorator dispatches ``on_event_start`` before entering the
decorated model method and propagates handler errors. These tests prove the
obsvr handler uses that seam: denied content leaves the model body at zero
entries, while the allow control reaches it exactly once.
"""

from typing import Any, ClassVar

import pytest

import obsvr
from llama_index.core.callbacks import CallbackManager
from llama_index.core.llms import CompletionResponse, CustomLLM, LLMMetadata
from llama_index.core.llms.callbacks import llm_completion_callback

from obsvr.integrations.llamaindex import ObsvrLlamaIndexHandler


class _TransportSpyLLM(CustomLLM):
    transport_calls: ClassVar[int] = 0

    @property
    def metadata(self) -> LLMMetadata:
        return LLMMetadata(num_output=1)

    @llm_completion_callback()
    def complete(
        self, prompt: str, formatted: bool = False, **kwargs: Any
    ) -> CompletionResponse:
        type(self).transport_calls += 1
        return CompletionResponse(text="ok")

    @llm_completion_callback()
    def stream_complete(self, prompt: str, formatted: bool = False, **kwargs: Any):
        type(self).transport_calls += 1
        yield CompletionResponse(text="ok", delta="ok")


def _model() -> _TransportSpyLLM:
    manager = CallbackManager([ObsvrLlamaIndexHandler()])
    return _TransportSpyLLM(callback_manager=manager)


def test_pii_block_stops_the_real_llamaindex_model_boundary(sent):
    obsvr.init(api_key="test", sample_rate=1, pii_policy={"ssn": "block"})
    _TransportSpyLLM.transport_calls = 0

    with pytest.raises(obsvr.ObsvrPolicyError, match="Request blocked by policy"):
        _model().complete("my SSN is 123-45-6789")

    assert _TransportSpyLLM.transport_calls == 0
    assert len(sent) == 1
    assert sent[0]["source"] == "llamaindex_py"
    assert sent[0]["operation"] == "llamaindex.llm"
    assert sent[0]["action_taken"] == "blocked"
    assert sent[0]["success"] is False
    assert "123-45-6789" not in sent[0]["prompt"]


def test_permitted_prompt_reaches_the_real_llamaindex_model_once(sent):
    obsvr.init(api_key="test", sample_rate=1, pii_policy={"ssn": "block"})
    _TransportSpyLLM.transport_calls = 0

    response = _model().complete("hello")

    assert response.text == "ok"
    assert _TransportSpyLLM.transport_calls == 1
    assert len(sent) == 1
    assert sent[0]["action_taken"] == "allowed"


def test_unappliable_llamaindex_redaction_fails_closed(sent):
    obsvr.init(api_key="test", sample_rate=1, pii_policy={"ssn": "redact"})
    _TransportSpyLLM.transport_calls = 0

    with pytest.raises(obsvr.ObsvrPolicyError, match="Request blocked by policy"):
        _model().complete("my SSN is 123-45-6789")

    assert _TransportSpyLLM.transport_calls == 0
    assert len(sent) == 1
    assert sent[0]["action_taken"] == "blocked"
    assert sent[0]["redacted_types"] == []
    assert "ssn" in sent[0]["blocked_types"]
    assert "123-45-6789" not in sent[0]["prompt"]
