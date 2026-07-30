"""``max_steps`` applies inside a conversation scope and is reported outside one.

The defect, measured live on two releases of the framework before this change:
registered without the run-level helper there is no conversation boundary for the
send hook to observe, so the step counter was per thread for the life of the
process. A second conversation inherited whatever the first spent, and in a
long-lived process the budget exhausted permanently — after which every tool call
was refused. That is not a step limit. It is a control that decays into a blanket
denial.

The repair STRICTLY WEAKENS an enforcement control, so both halves are pinned
here and neither is optional:

- unscoped: the limit is not applied, and each affected tool call carries
  ``not_evaluated`` with the reason. Silence would be the worse choice — a
  control that denies legitimate work gets switched off by whoever is on call,
  and then there is neither the control nor any evidence it is gone.
- scoped: the limit still refuses. Without this half the change is
  indistinguishable from deleting the control.

Everything here is offline and duck-typed. ``register_obsvr`` and
``patch_initiate_chat`` bind ``register_hook`` and ``initiate_chat``, so a
stand-in carrying exactly those two methods is the whole surface under test.
"""

import pytest

import obsvr
from obsvr.integrations import autogen as autogen_mod
from obsvr.integrations.autogen import (
    STEP_SCOPE_UNAVAILABLE_REASON,
    patch_initiate_chat,
    register_obsvr,
)


def tool_message(*names):
    """An assistant message asking for one or more tools, provider shape."""
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {
                "id": f"c{i}",
                "type": "function",
                "function": {"name": name, "arguments": "{}"},
            }
            for i, name in enumerate(names)
        ],
    }


class FakeAgent:
    """The two methods the integration binds, and nothing else."""

    def __init__(self, name="assistant"):
        self.name = name
        self._hooks = {}
        self.llm_config = {"model": "gpt-4o"}
        #: What this agent sends once a chat is under way.
        self.plan = []

    def register_hook(self, hookpoint, fn):
        self._hooks.setdefault(hookpoint, []).append(fn)

    def send(self, message):
        for fn in self._hooks.get("process_message_before_send", []):
            fn(sender=self, message=message)

    def initiate_chat(self, *args, **kwargs):
        for message in self.plan:
            self.send(message)
        return {"chat_history": []}


def step_events(sent):
    return [e for e in sent if e["operation"] == "autogen.agent.policy.step_limit"]


def not_evaluated_reason(event):
    return event["metadata"]["obsvr_telemetry"]["policy_not_evaluated"]


# ── unscoped: reported, not enforced ────────────────────────────────────────


def test_an_unscoped_budget_is_not_applied_and_says_so(sent):
    """Three tool calls against ``max_steps: 1``, and none of them is refused."""
    obsvr.init(api_key="test", sample_rate=1, agent_policy={"max_steps": 1})
    agent = register_obsvr(FakeAgent())

    for name in ("a", "b", "c"):
        agent.send(tool_message(name))

    events = step_events(sent)
    assert len(events) == 3, "one record per tool call, as the enforcing branch charges"
    assert {e["action_taken"] for e in events} == {"not_evaluated"}
    assert not [e for e in events if e["action_taken"] == "blocked"]

    first = events[0]
    assert first["metadata"]["max_steps"] == 1
    assert first["metadata"]["step_limit_scope"] == "process_thread"
    assert first["metadata"]["tool_name"] == "a"
    reason = not_evaluated_reason(first)
    assert reason["gate"] == "step_limit"
    assert reason["surface"] == "autogen.agent.policy.step_limit"
    assert reason["reason"] == STEP_SCOPE_UNAVAILABLE_REASON


def test_it_does_not_claim_the_budget_was_checked_and_had_room(sent):
    """``not_evaluated`` and ``allowed`` are different statements.

    ``allowed`` asserts that a gate looked and permitted. Nothing looked here, so
    recording ``allowed`` would be the same class of false claim as recording
    ``blocked`` — this is the assertion that stops the repair sliding into the
    other kind of lie.
    """
    obsvr.init(api_key="test", sample_rate=1, agent_policy={"max_steps": 1})
    agent = register_obsvr(FakeAgent())
    agent.send(tool_message("a"))

    assert step_events(sent)[0]["action_taken"] not in ("allowed", "blocked")


def test_an_unscoped_budget_does_not_decay_into_a_blanket_denial(sent):
    """The shape of the original defect: a later conversation still works.

    Two conversations, no run scope, a budget of one. Before the repair the
    second one had nothing left and every tool call in it was refused.
    """
    obsvr.init(api_key="test", sample_rate=1, agent_policy={"max_steps": 1})
    agent = register_obsvr(FakeAgent())
    agent.plan = [tool_message("a"), tool_message("b")]

    agent.initiate_chat()
    second = agent.initiate_chat()

    assert second is not None
    assert {e["action_taken"] for e in step_events(sent)} == {"not_evaluated"}


def test_batched_calls_each_get_their_own_record(sent):
    """The index and count travel, so the two configurations stay comparable."""
    obsvr.init(api_key="test", sample_rate=1, agent_policy={"max_steps": 1})
    agent = register_obsvr(FakeAgent())
    agent.send(tool_message("get_weather", "send_money"))

    events = step_events(sent)
    assert [e["metadata"]["tool_call_index"] for e in events] == [0, 1]
    assert [e["metadata"]["tool_call_count"] for e in events] == [2, 2]
    assert [e["metadata"]["tool_name"] for e in events] == ["get_weather", "send_money"]


def test_no_step_record_at_all_when_no_limit_is_configured(sent):
    """Control. The absence is only worth recording when a limit was asked for.

    Without this, "the unscoped path emits" would be satisfied by a path that
    emits unconditionally, which would put a not-evaluated step-limit record on
    every deployment that never configured one.
    """
    obsvr.init(api_key="test", sample_rate=1, agent_policy={"denied_tools": ["x"]})
    agent = register_obsvr(FakeAgent())
    agent.send(tool_message("a"))

    assert step_events(sent) == []


def test_a_message_carrying_no_tool_call_records_nothing(sent):
    """Control. A step is a tool call; ordinary chatter is not one."""
    obsvr.init(api_key="test", sample_rate=1, agent_policy={"max_steps": 1})
    agent = register_obsvr(FakeAgent())
    agent.send({"role": "assistant", "content": "just talking"})

    assert step_events(sent) == []


# ── scoped: still enforces. This is the half that makes the change a repair ──


def test_a_scoped_budget_still_refuses(sent):
    """NON-VACUITY FOR THE WHOLE CHANGE.

    If this passes while the unscoped tests also pass, the limit was narrowed. If
    this fails, the limit was removed. Nothing else in this file can tell those
    two apart.
    """
    obsvr.init(api_key="test", sample_rate=1, agent_policy={"max_steps": 1})
    agent = register_obsvr(FakeAgent())
    patch_initiate_chat(agent)
    agent.plan = [tool_message("a"), tool_message("b")]

    with pytest.raises(RuntimeError, match=r"\[obsvr\] Step limit"):
        agent.initiate_chat()

    blocked = [e for e in step_events(sent) if e["action_taken"] == "blocked"]
    assert len(blocked) == 1
    assert blocked[0]["metadata"]["step_count"] == 1
    assert "obsvr_telemetry" not in blocked[0].get("metadata", {}) or (
        "policy_not_evaluated"
        not in blocked[0]["metadata"].get("obsvr_telemetry", {})
    ), "a real refusal must not also carry a not-evaluated reason"


def test_each_scoped_conversation_gets_its_own_budget(sent):
    """The property the run scope exists to provide, still intact."""
    obsvr.init(api_key="test", sample_rate=1, agent_policy={"max_steps": 2})
    agent = register_obsvr(FakeAgent())
    patch_initiate_chat(agent)
    agent.plan = [tool_message("a"), tool_message("b")]

    agent.initiate_chat()
    agent.initiate_chat()

    assert step_events(sent) == [], (
        "two calls against a budget of two, twice — neither conversation should "
        "have inherited the other's spend"
    )


def test_a_nested_chat_hands_the_outer_scope_back(sent):
    """The hole the repair would otherwise have opened.

    The run wrapper used to zero the run context on the way out. Once an absent
    ``agent_run_id`` means "not enforced", that would drop the OUTER
    conversation's limit for the rest of its run — turning a fix into a new gap.
    """
    obsvr.init(api_key="test", sample_rate=1, agent_policy={"max_steps": 2})
    inner = register_obsvr(FakeAgent("inner"))
    patch_initiate_chat(inner)
    inner.plan = [tool_message("i")]

    outer = register_obsvr(FakeAgent("outer"))
    patch_initiate_chat(outer)

    calls = []

    class Nesting(FakeAgent):
        def initiate_chat(self, *args, **kwargs):
            self.send(tool_message("o1"))
            inner.initiate_chat()
            # Back in the outer conversation: the third charged step must be
            # refused by the outer budget of two.
            self.send(tool_message("o2"))
            calls.append("o2 sent")
            self.send(tool_message("o3"))
            calls.append("o3 sent")

    nesting = register_obsvr(Nesting("outer"))
    patch_initiate_chat(nesting)

    with pytest.raises(RuntimeError, match=r"\[obsvr\] Step limit"):
        nesting.initiate_chat()

    assert calls == ["o2 sent"], (
        "the outer conversation had spent two of two before o3, so o3 must be "
        "refused — a cleared scope would have let it through"
    )
    assert [e["action_taken"] for e in step_events(sent)] == ["blocked"]


# ── the weakening is confined to max_steps ──────────────────────────────────


def test_the_deny_gate_is_unaffected_by_the_missing_scope(sent):
    """The tool gate needs no run scope and did not lose one.

    Stated as a test because "the step limit is not applied without the helper"
    is one sentence away from being read as "nothing is applied without the
    helper", which is false and would understate the integration.
    """
    obsvr.init(
        api_key="test", sample_rate=1,
        agent_policy={"max_steps": 1, "denied_tools": ["send_money"]},
    )
    agent = register_obsvr(FakeAgent())

    with pytest.raises(RuntimeError, match=r"Tool blocked by agent policy: send_money"):
        agent.send(tool_message("send_money"))

    blocked = [e for e in sent if e["operation"] == "autogen.agent.policy.tool_blocked"]
    assert len(blocked) == 1
    assert blocked[0]["action_taken"] == "blocked"


def test_the_published_reason_is_the_one_the_event_carries():
    """One string, so the event and the documentation cannot drift apart.

    A weakened control described one way on the event and another way in the
    grading is the state this constant exists to make impossible.
    """
    assert "patch_initiate_chat" in STEP_SCOPE_UNAVAILABLE_REASON
    assert "max_steps" in STEP_SCOPE_UNAVAILABLE_REASON
    assert autogen_mod.STEP_SCOPE_UNAVAILABLE_REASON is STEP_SCOPE_UNAVAILABLE_REASON
