"""LangChain's real model boundary with a local transport spy.

The framework dispatches ``on_llm_start`` before ``_call`` and propagates a
handler error when ``raise_error`` is true. A configured block therefore has a
measurable contract: the model body stays at zero entries and a blocked record
is emitted. The allow control proves the test still reaches the real boundary.
"""

from typing import ClassVar

import pytest

import obsvr
from langchain_core.language_models.llms import LLM

from obsvr.integrations.langchain import ObsvrCallbackHandler


class _TransportSpyLLM(LLM):
    transport_calls: ClassVar[list[str]] = []

    @property
    def _llm_type(self) -> str:
        return "transport-spy"

    def _call(self, prompt: str, stop=None, run_manager=None, **kwargs) -> str:
        type(self).transport_calls.append(prompt)
        return "ok"


def _model() -> _TransportSpyLLM:
    return _TransportSpyLLM(callbacks=[ObsvrCallbackHandler()])


def test_pii_block_stops_the_real_langchain_model_boundary(sent):
    obsvr.init(api_key="test", sample_rate=1, pii_policy={"ssn": "block"})
    _TransportSpyLLM.transport_calls = []

    with pytest.raises(Exception, match="Request blocked by policy"):
        _model().invoke("my SSN is 123-45-6789")

    assert _TransportSpyLLM.transport_calls == []
    assert len(sent) == 1
    assert sent[0]["source"] == "langchain_py"
    assert sent[0]["operation"] == "langchain.llm"
    assert sent[0]["action_taken"] == "blocked"
    assert sent[0]["action_reason"] == "pii_detected"
    assert sent[0]["success"] is False
    assert "123-45-6789" not in sent[0]["prompt"]


def test_permitted_prompt_reaches_the_real_langchain_model_once(sent):
    obsvr.init(api_key="test", sample_rate=1, pii_policy={"ssn": "block"})
    _TransportSpyLLM.transport_calls = []

    assert _model().invoke("hello") == "ok"

    assert _TransportSpyLLM.transport_calls == ["hello"]
    assert len(sent) == 1
    assert sent[0]["action_taken"] == "allowed"


def test_unappliable_callback_redaction_fails_closed(sent):
    obsvr.init(api_key="test", sample_rate=1, pii_policy={"ssn": "redact"})
    _TransportSpyLLM.transport_calls = []

    with pytest.raises(Exception, match="Request blocked by policy"):
        _model().invoke("my SSN is 123-45-6789")

    assert _TransportSpyLLM.transport_calls == []
    assert len(sent) == 1
    assert sent[0]["source"] == "langchain_py"
    assert sent[0]["action_taken"] == "blocked"
    assert sent[0]["success"] is False
    assert "123-45-6789" not in sent[0]["prompt"]
    assert sent[0]["redacted_types"] == []
    assert "ssn" in sent[0]["blocked_types"]
