"""Integration handler tests driven by fake framework stubs.

No real framework packages required — each test creates minimal stub objects
that satisfy the handler interfaces.
"""

import time
from typing import Any, Dict, List, Optional

import pytest

import obsvr
from obsvr import sender


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _init():
    obsvr.init(api_key="test", sample_rate=1)


def _init_pii():
    obsvr.init(api_key="test", sample_rate=1, pii_policy={})


# ---------------------------------------------------------------------------
# LangChain handler
# ---------------------------------------------------------------------------


class _FakeMsg:
    def __init__(self, role: str, content: str):
        self.role = role
        self.content = content


class _FakeLLMResult:
    def __init__(self, text: str, tokens: Optional[Dict] = None):
        self.generations = [[_FakeGen(text)]]
        self.llm_output = {"token_usage": tokens} if tokens else {}


class _FakeGen:
    def __init__(self, text: str):
        self.text = text


SERIALIZED_OPENAI = {"id": ["langchain", "chat_models", "openai", "ChatOpenAI"],
                     "kwargs": {"model": "gpt-4o-mini"}}


def test_langchain_llm_start_to_end(sent):
    _init()
    from obsvr.integrations.langchain import ObsvrCallbackHandler
    h = ObsvrCallbackHandler()
    h.on_llm_start(SERIALIZED_OPENAI, ["What is 2+2?"], run_id="run-1")
    h.on_llm_end(_FakeLLMResult("The answer is 4.",
                                {"prompt_tokens": 12, "completion_tokens": 6,
                                 "total_tokens": 18}),
                 run_id="run-1")
    assert len(sent) == 1
    e = sent[0]
    assert e["source"] == "langchain_py"
    assert e["provider"] == "openai"
    assert e["model"] == "gpt-4o-mini"
    assert e["prompt"] == "What is 2+2?"
    assert e["response"] == "The answer is 4."
    assert e["input_tokens"] == 12
    assert e["output_tokens"] == 6
    assert e["total_tokens"] == 18


def test_langchain_chat_model_start(sent):
    _init()
    from obsvr.integrations.langchain import ObsvrCallbackHandler
    h = ObsvrCallbackHandler()
    h.on_chat_model_start(
        {"id": ["langchain", "chat_models", "anthropic", "ChatAnthropic"]},
        [[_FakeMsg("user", "Hello Claude")]],
        run_id="run-2",
    )
    h.on_llm_end(_FakeLLMResult("Hi human"), run_id="run-2")
    assert len(sent) == 1
    e = sent[0]
    assert e["provider"] == "anthropic"
    assert "user: Hello Claude" in e["prompt"]
    assert e["response"] == "Hi human"
    assert e["user_input"] == "Hello Claude"


def test_langchain_llm_error(sent):
    _init()
    from obsvr.integrations.langchain import ObsvrCallbackHandler
    h = ObsvrCallbackHandler()
    h.on_llm_start(SERIALIZED_OPENAI, ["Hi"], run_id="run-3")
    h.on_llm_error(Exception("connection reset"), run_id="run-3")
    assert len(sent) == 1
    assert sent[0]["success"] is False
    assert sent[0]["error_message"] == "connection reset"


def test_langchain_observe_only_pii_downgrade(sent):
    _init_pii()
    from obsvr.integrations.langchain import ObsvrCallbackHandler
    h = ObsvrCallbackHandler()
    h.on_llm_start(SERIALIZED_OPENAI, ["my ssn is 123-45-6789"], run_id="run-4")
    h.on_llm_end(_FakeLLMResult("noted"), run_id="run-4")
    assert len(sent) == 1
    e = sent[0]
    assert e["event_type"] == "llm_call"       # not blocked_call
    assert e["action_taken"] == "redacted"
    assert e["action_reason"] == "pii_detected"
    assert "[REDACTED_SSN]" in e["prompt"]
    assert "123-45-6789" not in e["prompt"]


def test_langchain_ghost_end_ignored(sent):
    _init()
    from obsvr.integrations.langchain import ObsvrCallbackHandler
    h = ObsvrCallbackHandler()
    h.on_llm_end(_FakeLLMResult("x"), run_id="ghost")
    assert len(sent) == 0


def test_langchain_no_op_when_uninitialized(sent):
    from obsvr.integrations.langchain import ObsvrCallbackHandler
    h = ObsvrCallbackHandler()
    h.on_llm_start(SERIALIZED_OPENAI, ["Hi"], run_id="run-5")
    h.on_llm_end(_FakeLLMResult("x"), run_id="run-5")
    assert len(sent) == 0


# -- policy blocks must stop the chain (raise_error contract) ---------------
#
# langchain-core swallows handler exceptions when handler.raise_error is
# False, so blocks would be silently ignored. These tests pin the contract
# directly (langchain-core is not a test dependency): the attribute is True
# and every policy block raises.


class _AgentActionStub:
    tool = "delete_file"
    tool_input = {"path": "/etc"}


AGENT_SERIALIZED = {"id": ["langchain", "agents", "agent", "AgentExecutor"]}


def test_langchain_raise_error_contract_is_true():
    from obsvr.integrations.langchain import ObsvrCallbackHandler
    assert ObsvrCallbackHandler.raise_error is True
    assert ObsvrCallbackHandler().raise_error is True


def test_langchain_tool_block_raises(sent):
    obsvr.init(api_key="test", sample_rate=1,
               agent_policy={"denied_tools": ["delete_file"]})
    from obsvr.integrations.langchain import ObsvrCallbackHandler
    h = ObsvrCallbackHandler()
    with pytest.raises(ValueError, match=r"\[obsvr\] Tool blocked"):
        h.on_agent_action(_AgentActionStub(), run_id="run-t1")
    assert any(
        e["operation"] == "langchain.agent.policy.tool_blocked" for e in sent
    )


def test_langchain_output_block_raises(sent):
    obsvr.init(api_key="test", sample_rate=1,
               agent_policy={"output_policy": {"denied_topics": ["forbidden"]}})
    from obsvr.integrations.langchain import ObsvrCallbackHandler
    h = ObsvrCallbackHandler()
    h.on_chain_start(AGENT_SERIALIZED, {"input": "go"}, run_id="run-t2")
    with pytest.raises(ValueError, match=r"\[obsvr\] Output blocked"):
        h.on_chain_end({"output": "this covers a forbidden topic"}, run_id="run-t2")
    assert any(
        e["operation"] == "langchain.agent.policy.output_blocked" for e in sent
    )


def test_langchain_step_limit_block_raises(sent):
    obsvr.init(api_key="test", sample_rate=1, agent_policy={"max_steps": 1})
    from obsvr.integrations.langchain import ObsvrCallbackHandler

    class _Action:
        tool = "search"
        tool_input = "q"

    h = ObsvrCallbackHandler()
    h.on_chain_start(AGENT_SERIALIZED, {"input": "go"}, run_id="run-t3")
    h.on_agent_action(_Action(), run_id="run-t3")  # step 1: allowed
    with pytest.raises(ValueError, match=r"\[obsvr\] Step limit"):
        h.on_agent_action(_Action(), run_id="run-t3")


# ---------------------------------------------------------------------------
# LlamaIndex handler
# ---------------------------------------------------------------------------


class _FakeEventType:
    """Minimal enum-like CBEventType."""
    def __init__(self, value: str):
        self.value = value


class _FakePayloadKey:
    def __init__(self, value: str):
        self.value = value


LLM_EVENT = _FakeEventType("llm")
OTHER_EVENT = _FakeEventType("query")


def _payload(**kw):
    """Build a payload dict with plain string keys (handler must handle both)."""
    return kw


def test_llamaindex_start_to_end(sent):
    _init()
    from obsvr.integrations.llamaindex import ObsvrLlamaIndexHandler
    h = ObsvrLlamaIndexHandler()

    class FakeMsg:
        def __init__(self, role, content):
            self.role = role
            self.content = content

    class FakeResponse:
        def __init__(self, text):
            self.text = text

    h.on_event_start(
        LLM_EVENT,
        payload={"messages": [FakeMsg("user", "Hello LI")]},
        event_id="ev-1",
    )
    h.on_event_end(
        LLM_EVENT,
        payload={"response": FakeResponse("LI response")},
        event_id="ev-1",
    )
    assert len(sent) == 1
    e = sent[0]
    assert e["source"] == "llamaindex_py"
    assert "user: Hello LI" in e["prompt"]
    assert e["response"] == "LI response"


def test_llamaindex_prompt_style(sent):
    _init()
    from obsvr.integrations.llamaindex import ObsvrLlamaIndexHandler
    h = ObsvrLlamaIndexHandler()

    class FakeResponse:
        def __init__(self, text):
            self.text = text

    h.on_event_start(LLM_EVENT, payload={"prompt": "raw prompt"}, event_id="ev-2")
    h.on_event_end(LLM_EVENT, payload={"response": FakeResponse("ok")}, event_id="ev-2")
    assert sent[0]["prompt"] == "raw prompt"


def test_llamaindex_non_llm_ignored(sent):
    _init()
    from obsvr.integrations.llamaindex import ObsvrLlamaIndexHandler
    h = ObsvrLlamaIndexHandler()
    h.on_event_start(OTHER_EVENT, payload={"prompt": "hi"}, event_id="ev-3")
    h.on_event_end(OTHER_EVENT, payload={}, event_id="ev-3")
    assert len(sent) == 0


def test_llamaindex_pii_observe_only(sent):
    _init_pii()
    from obsvr.integrations.llamaindex import ObsvrLlamaIndexHandler
    h = ObsvrLlamaIndexHandler()

    class FakeMsg:
        def __init__(self, role, content):
            self.role = role
            self.content = content

    class FakeResponse:
        def __init__(self, text):
            self.text = text

    h.on_event_start(
        LLM_EVENT,
        payload={"messages": [FakeMsg("user", "ssn 123-45-6789")]},
        event_id="ev-4",
    )
    h.on_event_end(LLM_EVENT, payload={"response": FakeResponse("ok")}, event_id="ev-4")
    assert len(sent) == 1
    e = sent[0]
    assert "[REDACTED_SSN]" in e["prompt"]
    assert e["action_taken"] == "redacted"


def test_llamaindex_uninitialized_no_op(sent):
    from obsvr.integrations.llamaindex import ObsvrLlamaIndexHandler
    h = ObsvrLlamaIndexHandler()
    h.on_event_start(LLM_EVENT, payload={"prompt": "hi"}, event_id="ev-5")
    h.on_event_end(LLM_EVENT, payload={}, event_id="ev-5")
    assert len(sent) == 0


# ---------------------------------------------------------------------------
# CrewAI step callback
# ---------------------------------------------------------------------------


class _AgentFinish:
    def __init__(self, output: str):
        self.output = output


class _AgentAction:
    def __init__(self, log: str):
        self.log = log


def test_crewai_step_callback_agentfinish(sent):
    _init()
    from obsvr.integrations.crewai import obsvr_step_callback
    obsvr_step_callback(_AgentFinish("task done"))
    assert len(sent) == 1
    e = sent[0]
    assert e["source"] == "crewai"
    assert "task done" in e["prompt"]


def test_crewai_step_callback_agentaction(sent):
    _init()
    from obsvr.integrations.crewai import obsvr_step_callback
    obsvr_step_callback(_AgentAction("tool call log"))
    assert len(sent) == 1
    assert "tool call log" in sent[0]["prompt"]


def test_crewai_make_step_callback_chains(sent):
    _init()
    from obsvr.integrations.crewai import make_step_callback

    received = []
    existing = lambda s: received.append(s)
    cb = make_step_callback(existing_callback=existing)
    cb(_AgentFinish("done"))
    assert len(received) == 1
    assert len(sent) == 1


def test_crewai_pii_observe_only(sent):
    _init_pii()
    from obsvr.integrations.crewai import obsvr_step_callback
    obsvr_step_callback(_AgentFinish("ssn 123-45-6789"))
    assert len(sent) == 1
    assert "[REDACTED_SSN]" in sent[0]["prompt"]
    assert sent[0]["action_taken"] == "redacted"


def test_crewai_uninitialized_no_op(sent):
    from obsvr.integrations.crewai import obsvr_step_callback
    obsvr_step_callback(_AgentFinish("hi"))
    assert len(sent) == 0


# ---------------------------------------------------------------------------
# AutoGen hook
# ---------------------------------------------------------------------------


class _FakeAgent:
    """Minimal ConversableAgent stub with register_hook support."""

    def __init__(self):
        self._hooks: Dict[str, List] = {}
        self.llm_config = {"model": "gpt-4o"}

    def register_hook(self, hookpoint: str, fn):
        self._hooks.setdefault(hookpoint, []).append(fn)

    def _run_hook(self, hookpoint: str, *args, **kwargs):
        result = kwargs.get("message") or (args[0] if args else None)
        for fn in self._hooks.get(hookpoint, []):
            result = fn(*args, **kwargs)
        return result


def test_autogen_audits_outgoing_message(sent):
    _init()
    from obsvr.integrations.autogen import register_obsvr
    agent = _FakeAgent()
    register_obsvr(agent)
    ctx_msgs = [{"role": "user", "content": "What is the capital of France?"}]
    agent._run_hook("process_all_messages_before_reply", ctx_msgs)
    agent._run_hook("process_message_before_send",
                    message={"role": "assistant", "content": "Paris"})
    assert len(sent) == 1
    e = sent[0]
    assert e["source"] == "autogen"
    assert e["response"] == "Paris"


def test_autogen_blocks_ssn(sent):
    _init_pii()
    from obsvr.integrations.autogen import register_obsvr
    agent = _FakeAgent()
    register_obsvr(agent)
    with pytest.raises(RuntimeError, match=r"\[obsvr\] Request blocked"):
        agent._run_hook(
            "process_message_before_send",
            message={"role": "assistant", "content": "ssn 123-45-6789"},
        )
    assert len(sent) == 1
    assert sent[0]["event_type"] == "blocked_call"
    assert sent[0]["status_code"] == 403


def test_autogen_redacts_email(sent):
    _init_pii()
    from obsvr.integrations.autogen import register_obsvr
    agent = _FakeAgent()
    register_obsvr(agent)
    msg = {"role": "assistant", "content": "mail john@example.com"}
    result = agent._run_hook("process_message_before_send", message=msg)
    assert len(sent) == 1
    assert sent[0]["action_taken"] == "redacted"


def test_autogen_uninitialized_no_op(sent):
    from obsvr.integrations.autogen import register_obsvr
    agent = _FakeAgent()
    register_obsvr(agent)
    agent._run_hook("process_message_before_send",
                    message={"role": "assistant", "content": "hi"})
    assert len(sent) == 0
