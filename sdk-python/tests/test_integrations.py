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


def test_langchain_observe_only_pii_storage_is_separate_from_outbound(sent):
    _init_pii()
    from obsvr.integrations.langchain import ObsvrCallbackHandler
    h = ObsvrCallbackHandler()
    h.on_llm_start(SERIALIZED_OPENAI, ["my ssn is 123-45-6789"], run_id="run-4")
    h.on_llm_end(_FakeLLMResult("noted"), run_id="run-4")
    assert len(sent) == 1
    e = sent[0]
    assert e["event_type"] == "llm_call"       # not blocked_call
    assert e["action_taken"] == "not_evaluated"
    assert e["action_reason"] == "pii_detected"
    assert "[REDACTED_SSN]" in e["prompt"]
    assert "123-45-6789" not in e["prompt"]
    assert e["metadata"]["obsvr_telemetry"]["stored_redaction_scope"] == "observe_only"
    assert e["metadata"]["obsvr_telemetry"]["stored_redaction_outbound_unmodified"] is True


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


class _LoopAction:
    tool = "search"
    tool_input = "q"


def test_langchain_loop_detection_blocks_and_emits(sent):
    """Twin: sdk-typescript/tests/unit/langchain-handler.test.ts. The detector is built at
    chain start from agent_policy and driven once per agent step, so the third
    step past a limit of 2 both emits LOOP_DETECTED and stops the run."""
    obsvr.init(
        api_key="test", sample_rate=1,
        agent_policy={
            "loop_detection": {"max_iterations": 2, "window_ms": 60000, "action": "block"}
        },
    )
    from obsvr.integrations.langchain import ObsvrCallbackHandler

    h = ObsvrCallbackHandler()
    h.on_chain_start(AGENT_SERIALIZED, {"input": "go"}, run_id="run-t4")
    h.on_agent_action(_LoopAction(), run_id="run-t4")
    h.on_agent_action(_LoopAction(), run_id="run-t4")
    with pytest.raises(ValueError, match=r"\[obsvr\] Loop detected"):
        h.on_agent_action(_LoopAction(), run_id="run-t4")

    loop_events = [e for e in sent if e["operation"] == "langchain.agent.loop_detected"]
    assert len(loop_events) == 1
    ev = loop_events[0]
    assert ev["reason_code"] == "LOOP_DETECTED"
    assert ev["event_type"] == "loop_detected"
    assert ev["action_taken"] == "blocked"
    assert ev["metadata"]["loop_iteration_count"] == 3
    assert ev["metadata"]["loop_action"] == "block"


def test_langchain_loop_detection_is_off_without_config(sent):
    """No loop_detection block means no detector and no event - the control is
    opt-in, and an unconfigured run must stay byte-identical to before."""
    obsvr.init(api_key="test", sample_rate=1, agent_policy={})
    from obsvr.integrations.langchain import ObsvrCallbackHandler

    h = ObsvrCallbackHandler()
    h.on_chain_start(AGENT_SERIALIZED, {"input": "go"}, run_id="run-t5")
    for _ in range(5):
        h.on_agent_action(_LoopAction(), run_id="run-t5")
    assert [e for e in sent if "loop_detected" in e["operation"]] == []


def test_langchain_loop_detection_ignores_a_thresholdless_block(sent):
    """A loop_detection block with no usable threshold builds no detector: a
    control that silently enforces nothing is worse than an absent one."""
    obsvr.init(
        api_key="test", sample_rate=1,
        agent_policy={"loop_detection": {"action": "block"}},
    )
    from obsvr.integrations.langchain import ObsvrCallbackHandler

    h = ObsvrCallbackHandler()
    h.on_chain_start(AGENT_SERIALIZED, {"input": "go"}, run_id="run-t6")
    for _ in range(5):
        h.on_agent_action(_LoopAction(), run_id="run-t6")
    assert [e for e in sent if "loop_detected" in e["operation"]] == []


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


def test_llamaindex_attributes_provider_and_tokens(sent):
    """Two defects at once, and neither was a reader that broke: the model was
    only read from the llm-start payload (absent on newer llama-index-core, so
    the provider inferred from it was always "unknown"), and there was no
    token-reading code on this path AT ALL. LlamaIndex traffic could therefore
    never be attributed to a provider in any report, nor metered, nor counted
    against a token budget."""
    _init()
    from obsvr.integrations.llamaindex import ObsvrLlamaIndexHandler
    h = ObsvrLlamaIndexHandler()

    class Raw:
        model = "gpt-4o-mini-2024-07-18"
        usage = {"prompt_tokens": 12, "completion_tokens": 1, "total_tokens": 13}

    class Msg:
        content = "four"

    class Resp:
        message = Msg()
        raw = Raw()

    h.on_event_start(LLM_EVENT, payload={"messages": []}, event_id="tok-1")
    h.on_event_end(LLM_EVENT, payload={"response": Resp()}, event_id="tok-1")

    assert len(sent) == 1
    ev = sent[0]
    assert ev["provider"] == "openai"
    assert ev["model"] == "gpt-4o-mini-2024-07-18"
    assert ev["input_tokens"] == 12
    assert ev["output_tokens"] == 1
    assert ev["total_tokens"] == 13


def test_llamaindex_gemini_shaped_usage(sent):
    _init()
    from obsvr.integrations.llamaindex import ObsvrLlamaIndexHandler
    h = ObsvrLlamaIndexHandler()

    class Raw:
        model_version = "gemini-2.5-flash"
        usage_metadata = {
            "prompt_token_count": 4,
            "candidates_token_count": 2,
            "total_token_count": 6,
        }

    class Msg:
        content = "ok"

    class Resp:
        message = Msg()
        raw = Raw()

    h.on_event_start(LLM_EVENT, payload={"messages": []}, event_id="gem-1")
    h.on_event_end(LLM_EVENT, payload={"response": Resp()}, event_id="gem-1")

    ev = sent[0]
    assert ev["provider"] == "google"
    assert ev["model"] == "gemini-2.5-flash"
    assert ev["input_tokens"] == 4
    assert ev["total_tokens"] == 6


def test_llamaindex_unknown_stays_unknown_and_counts_stay_absent(sent):
    """"unknown" has to keep meaning something. With no raw provider response
    there is nothing to infer from, and the counts stay absent rather than
    becoming a zero nobody measured."""
    _init()
    from obsvr.integrations.llamaindex import ObsvrLlamaIndexHandler
    h = ObsvrLlamaIndexHandler()

    class Resp:
        text = "ok"

    h.on_event_start(LLM_EVENT, payload={"messages": []}, event_id="unk-1")
    h.on_event_end(LLM_EVENT, payload={"response": Resp()}, event_id="unk-1")

    ev = sent[0]
    assert ev["provider"] == "unknown"
    assert ev["model"] == "unknown"
    assert "input_tokens" not in ev
    assert "total_tokens" not in ev


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
    assert e["action_taken"] == "not_evaluated"
    assert e["metadata"]["obsvr_telemetry"]["stored_redaction_scope"] == "observe_only"


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
    assert sent[0]["action_taken"] == "not_evaluated"
    assert sent[0]["metadata"]["obsvr_telemetry"]["stored_redaction_scope"] == "observe_only"


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


# ---------------------------------------------------------------------------
# LangChain: the per-run controls need a run, and finding one is not free
#
# Driven here against the argument shapes the two runtimes actually deliver,
# recorded from live runs: the graph runtime passes serialized=None with the
# identity in `name=` and graph markers in `metadata`, and dispatches a tool
# whose immediate parent is the node rather than the run; the classic executor
# passes serialized=None with name="AgentExecutor" and delivers BOTH pre-tool
# callbacks for one tool call.
# ---------------------------------------------------------------------------


class _ToolAction:
    tool = "search"
    tool_input = "q"


def _graph_root(h, run_id="g-root"):
    """The graph runtime's top-level chain start: serialized is None."""
    h.on_chain_start(None, {"messages": []}, run_id=run_id, parent_run_id=None,
                     tags=[], metadata={"ls_integration": "langgraph"},
                     name="LangGraph")


def _graph_node(h, run_id, parent, node="tools", step=1):
    h.on_chain_start(None, {}, run_id=run_id, parent_run_id=parent,
                     tags=[f"graph:step:{step}"],
                     metadata={"langgraph_node": node, "langgraph_step": step},
                     name=node)


def _tool_start(h, run_id, parent, name="search"):
    h.on_tool_start({"name": name, "description": "d"}, "q",
                    run_id=run_id, parent_run_id=parent, inputs={"q": "q"})


def test_langchain_opens_an_agent_run_when_serialized_is_none(sent):
    """The graph runtime never fills serialized in; the run must still open."""
    obsvr.init(api_key="test", sample_rate=1, agent_policy={})
    from obsvr.integrations.langchain import ObsvrCallbackHandler
    h = ObsvrCallbackHandler()
    _graph_root(h)
    starts = [e for e in sent if e["operation"] == "langchain.agent.run.start"]
    assert len(starts) == 1
    assert starts[0]["metadata"]["agent_run_id"]


def test_langchain_step_budget_survives_the_node_between_run_and_tool(sent):
    """The tool's parent is the dispatching node, and the budget is above it."""
    obsvr.init(api_key="test", sample_rate=1, agent_policy={"max_steps": 2})
    from obsvr.integrations.langchain import ObsvrCallbackHandler
    h = ObsvrCallbackHandler()
    _graph_root(h)
    for i in range(2):
        _graph_node(h, f"node-{i}", "g-root", step=i)
        _tool_start(h, f"tool-{i}", f"node-{i}")
        h.on_chain_end({}, run_id=f"node-{i}")
    calls = [e for e in sent if e["operation"] == "langchain.tool.call"]
    assert [e["metadata"]["step_index"] for e in calls] == [0, 1]
    # one run, and every tool call charged to it
    assert len({e["metadata"]["agent_run_id"] for e in calls}) == 1

    _graph_node(h, "node-2", "g-root", step=2)
    with pytest.raises(ValueError, match=r"\[obsvr\] Step limit"):
        _tool_start(h, "tool-2", "node-2")


def test_langchain_step_budget_is_per_run_not_per_handler(sent):
    """A second run on the same handler gets its own budget."""
    obsvr.init(api_key="test", sample_rate=1, agent_policy={"max_steps": 1})
    from obsvr.integrations.langchain import ObsvrCallbackHandler
    h = ObsvrCallbackHandler()
    for run in ("a", "b"):
        _graph_root(h, run_id=run)
        _graph_node(h, f"n-{run}", run)
        _tool_start(h, f"t-{run}", f"n-{run}")
        h.on_chain_end({}, run_id=f"n-{run}")
        h.on_chain_end({"output": "done"}, run_id=run)
    calls = [e for e in sent if e["operation"] == "langchain.tool.call"]
    assert [e["metadata"]["step_index"] for e in calls] == [0, 0]
    assert len({e["metadata"]["agent_run_id"] for e in calls}) == 2


def test_langchain_gates_after_a_classic_run_on_the_same_handler(sent):
    """The double-gate credit is spent per call, so it cannot disarm the gate.

    A handler-wide latch made this exact sequence fail open: the classic
    executor delivers on_agent_action, and every later on_tool_start — including
    every tool of every later graph run, which delivers no other pre-tool
    callback — returned before reaching the gate.
    """
    obsvr.init(api_key="test", sample_rate=1,
               agent_policy={"denied_tools": ["search"]})
    from obsvr.integrations.langchain import ObsvrCallbackHandler
    h = ObsvrCallbackHandler()

    # classic run: the legacy callback rules, and the tool callback follows
    h.on_chain_start(None, {"input": "go"}, run_id="c1", parent_run_id=None,
                     tags=[], name="AgentExecutor")
    with pytest.raises(ValueError, match=r"\[obsvr\] Tool blocked"):
        h.on_agent_action(_ToolAction(), run_id="c1", parent_run_id=None)

    # graph run on the SAME handler: only on_tool_start is delivered
    _graph_root(h, run_id="g1")
    _graph_node(h, "n1", "g1")
    with pytest.raises(ValueError, match=r"\[obsvr\] Tool blocked"):
        _tool_start(h, "t1", "n1")
    assert len([e for e in sent
                if e["operation"] == "langchain.agent.policy.tool_blocked"]) == 2


def test_langchain_charges_one_step_when_both_pre_tool_callbacks_arrive(sent):
    """The classic executor delivers both for one tool call; it costs one step."""
    obsvr.init(api_key="test", sample_rate=1, agent_policy={})
    from obsvr.integrations.langchain import ObsvrCallbackHandler
    h = ObsvrCallbackHandler()
    h.on_chain_start(None, {"input": "go"}, run_id="c1", parent_run_id=None,
                     tags=[], name="AgentExecutor")
    for i in range(2):
        h.on_agent_action(_ToolAction(), run_id="c1", parent_run_id=None)
        _tool_start(h, f"t{i}", "c1")
    calls = [e for e in sent if e["operation"] == "langchain.tool.call"]
    assert [e["metadata"]["step_index"] for e in calls] == [0, 1]


def test_langchain_leaves_a_plain_chain_alone(sent):
    """A chain that calls no tool is not announced as an agent run."""
    obsvr.init(api_key="test", sample_rate=1, agent_policy={})
    from obsvr.integrations.langchain import ObsvrCallbackHandler
    h = ObsvrCallbackHandler()
    h.on_chain_start(None, {"q": "hi"}, run_id="p1", parent_run_id=None,
                     tags=[], name="RunnableSequence")
    h.on_chain_end({"output": "hi"}, run_id="p1")
    assert [e["operation"] for e in sent] == []


def test_langchain_reads_the_tool_name_from_serialized_not_the_run_name(sent):
    """Under the graph runtimes the run name is the NODE, and matching it would
    compare "tools" against the policy and refuse nothing."""
    obsvr.init(api_key="test", sample_rate=1,
               agent_policy={"denied_tools": ["search"]})
    from obsvr.integrations.langchain import ObsvrCallbackHandler
    h = ObsvrCallbackHandler()
    _graph_root(h)
    _graph_node(h, "n1", "g-root")
    with pytest.raises(ValueError, match=r"Tool blocked by agent policy: search"):
        h.on_tool_start({"name": "search", "description": "d"}, "q",
                        run_id="t1", parent_run_id="n1", name="tools")


def test_langchain_records_a_gap_when_the_call_carries_no_tool_name(sent):
    """No name and a policy that names tools is a gap, not an allow."""
    obsvr.init(api_key="test", sample_rate=1,
               agent_policy={"denied_tools": ["search"]})
    from obsvr.integrations.langchain import ObsvrCallbackHandler
    h = ObsvrCallbackHandler()
    _graph_root(h)
    h.on_tool_start({}, "q", run_id="t1", parent_run_id="g-root")
    gaps = [e for e in sent
            if e["operation"] == "langchain.agent.policy.tool_not_evaluated"]
    assert len(gaps) == 1
    assert gaps[0]["action_taken"] == "not_evaluated"
    assert not [e for e in sent if e["action_taken"] == "blocked"]


def test_langchain_on_tool_start_is_not_a_coroutine():
    """langchain-core swallows an async handler's exception unconditionally.

    ``_run_coros`` logs and discards whatever a coroutine handler raises without
    consulting ``raise_error`` — an asymmetry the framework documents in its own
    source. A gate defined with ``async def`` would therefore refuse nothing on
    the sync dispatcher, which is the one an async agent reaches whenever the
    tool itself is synchronous.
    """
    import inspect
    from obsvr.integrations.langchain import ObsvrCallbackHandler
    for name in ("on_tool_start", "on_agent_action", "on_chain_start",
                 "on_chain_end"):
        assert not inspect.iscoroutinefunction(
            getattr(ObsvrCallbackHandler, name)
        ), f"{name} must stay synchronous"


def test_langchain_announces_a_named_agent_run_that_calls_no_tool(sent):
    """The classic executor identifies itself in the `name` keyword and nowhere
    else: `serialized` is None, tags are empty, and there is no graph metadata.

    Driven with no tool call on purpose. A run that calls one would be announced
    anyway, lazily, so a leg that calls a tool cannot tell whether reading the
    name matters — and reading it is the only thing that opens a run record for
    an agent that answered without reaching for anything.
    """
    obsvr.init(api_key="test", sample_rate=1, agent_policy={})
    from obsvr.integrations.langchain import ObsvrCallbackHandler
    h = ObsvrCallbackHandler()
    h.on_chain_start(None, {"input": "go"}, run_id="c1", parent_run_id=None,
                     tags=[], metadata=None, name="AgentExecutor")
    h.on_chain_end({"output": "answered without a tool"}, run_id="c1")
    ops = [e["operation"] for e in sent]
    assert ops == ["langchain.agent.run.start", "langchain.agent.run.finish"], ops
