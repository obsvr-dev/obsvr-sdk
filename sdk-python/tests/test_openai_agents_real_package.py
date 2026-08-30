"""Model-boundary enforcement against the installed openai-agents package.

The package is optional in the default test environment, so this file skips
there and is also run explicitly in isolated minimum/current package lanes.
The stubs subclass the package's real Model/ModelProvider ABCs; a wrapper that
only duck-types the methods would fail the runner's ``isinstance(Model)``
resolution even if its direct unit tests passed.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

import pytest

agents = pytest.importorskip("agents")

import obsvr
from obsvr import sender
from agents import Agent, Runner, function_tool, set_tracing_disabled
from agents.items import ModelResponse
from agents.models.interface import Model, ModelProvider
from agents.usage import Usage
from openai.types.responses import (
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)
from obsvr.integrations.openai_agents import govern_model, govern_model_provider


SSN = "123-45-6789"


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sender, "send_audit_async", lambda _config, _event: None)
    set_tracing_disabled(True)
    yield
    set_tracing_disabled(False)


class CountingModel(Model):
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.stream_calls: list[dict[str, Any]] = []
        self.model = "gpt-4o-mini"

    async def get_response(
        self,
        system_instructions: str | None,
        input: Any,
        model_settings: Any,
        tools: list[Any],
        output_schema: Any,
        handoffs: list[Any],
        tracing: Any,
        *,
        previous_response_id: str | None,
        conversation_id: str | None,
        prompt: Any,
    ) -> ModelResponse:
        self.calls.append(
            {"system_instructions": system_instructions, "input": input, "prompt": prompt}
        )
        return ModelResponse(output=[], usage=Usage(), response_id=None)

    async def stream_response(
        self,
        system_instructions: str | None,
        input: Any,
        model_settings: Any,
        tools: list[Any],
        output_schema: Any,
        handoffs: list[Any],
        tracing: Any,
        *,
        previous_response_id: str | None,
        conversation_id: str | None,
        prompt: Any,
    ) -> AsyncIterator[Any]:
        self.stream_calls.append(
            {"system_instructions": system_instructions, "input": input, "prompt": prompt}
        )
        if False:
            yield None


class CountingProvider(ModelProvider):
    def __init__(self, model: Model) -> None:
        self.model = model

    def get_model(self, model_name: str | None) -> Model:
        return self.model


class ToolCallingModel(CountingModel):
    """Two-turn real-runner model: request one tool, then return a final answer."""

    async def get_response(
        self,
        system_instructions: str | None,
        input: Any,
        model_settings: Any,
        tools: list[Any],
        output_schema: Any,
        handoffs: list[Any],
        tracing: Any,
        *,
        previous_response_id: str | None,
        conversation_id: str | None,
        prompt: Any,
    ) -> ModelResponse:
        self.calls.append(
            {"system_instructions": system_instructions, "input": input, "prompt": prompt}
        )
        if len(self.calls) == 1:
            return ModelResponse(
                output=[
                    ResponseFunctionToolCall(
                        arguments='{"value":"contract-42"}',
                        call_id="call-1",
                        name="send_contract",
                        type="function_call",
                    )
                ],
                usage=Usage(),
                response_id="response-1",
            )
        return ModelResponse(
            output=[
                ResponseOutputMessage(
                    id="message-1",
                    content=[
                        ResponseOutputText(
                            annotations=[], text="done", type="output_text"
                        )
                    ],
                    role="assistant",
                    status="completed",
                    type="message",
                )
            ],
            usage=Usage(),
            response_id="response-2",
        )


def model_args(input_value: Any) -> tuple[Any, ...]:
    return (
        "Keep the answer concise.",
        input_value,
        object(),
        [],
        None,
        [],
        object(),
    )


def model_kwargs() -> dict[str, Any]:
    return {
        "previous_response_id": None,
        "conversation_id": None,
        "prompt": None,
    }


def test_block_stops_before_real_model_abc_method() -> None:
    obsvr.init(
        api_key="test", pii_policy={"rules": {"ssn": "block"}}, auto=False
    )
    raw = CountingModel()
    model = govern_model(raw)
    agent = Agent(name="governed-model-agent", instructions="Answer.", model=model)

    assert isinstance(model, Model)
    with pytest.raises(Exception, match="obsvr"):
        asyncio.run(Runner.run(agent, f"ssn {SSN}"))
    assert raw.calls == []


def test_auto_init_gates_future_real_agent_tool_execution() -> None:
    executions: list[str] = []

    @function_tool
    def send_contract(value: str) -> str:
        """Send one contract to its destination."""
        executions.append(value)
        return "sent"

    obsvr.init(
        api_key="test",
        agent_policy={"denied_tools": ["send_contract"]},
        auto=True,
    )
    model = ToolCallingModel()
    agent = agents.Agent(
        name="auto-governed-tool-agent",
        instructions="Call the requested tool.",
        model=model,
        tools=[send_contract],
    )

    result = asyncio.run(Runner.run(agent, "send contract-42"))

    assert result.final_output == "done"
    assert executions == [], "a denied auto-gated tool entered its callable"
    assert len(model.calls) == 2
    assert "blocked by agent policy" in str(model.calls[1]["input"])


def test_redaction_reaches_every_provider_bound_input_turn() -> None:
    obsvr.init(
        api_key="test", pii_policy={"rules": {"ssn": "redact"}}, auto=False
    )
    raw = CountingModel()
    model = govern_model(raw)
    input_value = [
        {"role": "user", "content": [{"type": "input_text", "text": f"old {SSN}"}]},
        {"role": "user", "content": [{"type": "input_text", "text": "continue"}]},
    ]
    args = list(model_args(input_value))
    args[0] = f"system {SSN}"
    kwargs = model_kwargs()
    kwargs["prompt"] = {"id": "pmpt_test", "variables": {"customer": SSN}}

    asyncio.run(model.get_response(*args, **kwargs))

    assert len(raw.calls) == 1
    assert SSN not in str(raw.calls[0])
    assert "[REDACTED_SSN]" in str(raw.calls[0])


def test_stream_block_stops_before_real_async_iterator_body() -> None:
    obsvr.init(
        api_key="test", pii_policy={"rules": {"ssn": "block"}}, auto=False
    )
    raw = CountingModel()
    model = govern_model(raw)

    async def consume() -> None:
        async for _ in model.stream_response(
            *model_args(f"ssn {SSN}"), **model_kwargs()
        ):
            pass

    with pytest.raises(Exception, match="obsvr"):
        asyncio.run(consume())
    assert raw.stream_calls == []


def test_provider_returns_a_real_governed_model_abc() -> None:
    raw = CountingModel()
    provider = govern_model_provider(CountingProvider(raw))

    assert isinstance(provider, ModelProvider)
    resolved = provider.get_model("gpt-4o-mini")
    assert isinstance(resolved, Model)
    assert resolved is not raw


def test_unlocatable_redaction_fails_closed_before_model_call() -> None:
    obsvr.init(
        api_key="test",
        on_pre_call=lambda _event: {"decision": "redact"},
        auto=False,
    )
    raw = CountingModel()
    model = govern_model(raw)

    with pytest.raises(Exception, match="obsvr"):
        asyncio.run(
            model.get_response(*model_args("ordinary text"), **model_kwargs())
        )
    assert raw.calls == []


def test_external_redaction_is_verified_before_model_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from obsvr import presidio

    def unchanged_sidecar(url: str, payload: dict[str, Any], _timeout: float) -> Any:
        if url.endswith("/analyze"):
            return [
                {
                    "entity_type": "PERSON",
                    "start": 0,
                    "end": len(str(payload.get("text") or "")),
                    "score": 0.99,
                }
            ]
        return {"text": payload["text"]}

    monkeypatch.setattr(presidio, "_post_json", unchanged_sidecar)
    obsvr.init(
        api_key="test",
        pii_policy={"rules": {"name": "redact"}},
        presidio_analyzer_url="http://presidio.test",
        presidio_anonymizer_url="http://presidio.test",
        auto=False,
    )
    raw = CountingModel()
    model = govern_model(raw)

    with pytest.raises(Exception, match="obsvr"):
        asyncio.run(model.get_response(*model_args("Alice"), **model_kwargs()))
    assert raw.calls == []
