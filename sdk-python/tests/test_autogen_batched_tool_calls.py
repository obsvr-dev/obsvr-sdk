"""Every tool call in a message is gated, and each one costs a step.

The defect these pin: the send hook read ``tool_calls[0]`` and nothing else, so
enforcement depended on POSITION. With ``denied_tools: ["send_money"]``, a
message carrying ``[get_weather, send_money]`` was checked as ``get_weather``,
delivered, and the recipient then executed ``send_money`` — no event, no
exception, nothing in the trail to review. The same read handed ``max_steps`` a
free evasion, because a message cost one step no matter how many calls it
carried.

The control throughout is the first-position case, which always worked. A test
here failing while that control passes localises the fault to position.
"""

import pytest

import obsvr


class FakeAgent:
    """ConversableAgent's hook registry, and nothing else."""

    def __init__(self):
        self._hooks = {}
        self.llm_config = {"model": "gpt-4o"}

    def register_hook(self, hookpoint, fn):
        self._hooks.setdefault(hookpoint, []).append(fn)

    def send(self, message):
        """What the framework does: run the hooks, then deliver."""
        result = message
        for fn in self._hooks.get("process_message_before_send", []):
            result = fn(message=message)
        return result


def _tool_call(name, index):
    return {
        "id": f"call_{index}",
        "type": "function",
        "function": {"name": name, "arguments": '{"amount": 500}'},
    }


def _msg(*names):
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [_tool_call(n, i) for i, n in enumerate(names)],
    }


def _agent(**policy):
    obsvr.init(api_key="test", sample_rate=1, agent_policy=policy)
    from obsvr.integrations.autogen import register_obsvr

    return register_obsvr(FakeAgent())


def _blocks(sent):
    return [e for e in sent if e["operation"] == "autogen.agent.policy.tool_blocked"]


def _limits(sent):
    return [e for e in sent if e["operation"] == "autogen.agent.policy.step_limit"]


# ── position ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "names,index",
    [
        (("send_money",), 0),
        (("get_weather", "send_money"), 1),
        (("get_weather", "lookup_docs", "send_money"), 2),
    ],
    ids=["first", "second", "third"],
)
def test_a_denied_tool_is_refused_at_any_position(names, index, sent):
    agent = _agent(denied_tools=["send_money"])

    with pytest.raises(RuntimeError, match=r"\[obsvr\] Tool blocked"):
        agent.send(_msg(*names))

    blocked = _blocks(sent)
    assert len(blocked) == 1
    meta = blocked[0]["metadata"]
    assert meta["tool_name"] == "send_money"
    assert meta["tool_call_index"] == index, (
        "the event has to say WHICH call was refused; position is the whole bug"
    )
    assert meta["tool_call_count"] == len(names)
    assert blocked[0]["action_taken"] == "blocked"


def test_the_message_is_refused_whole_not_partially(sent):
    """A message is delivered atomically, so one denied call refuses all of it.

    Letting the benign calls through is not an option the transport offers —
    there is no way to deliver a message minus one of its tool calls.
    """
    agent = _agent(denied_tools=["send_money"])

    with pytest.raises(RuntimeError):
        agent.send(_msg("get_weather", "send_money"))


def test_an_allowed_batch_passes_through(sent):
    """The control that stops every assertion above passing vacuously.

    Without it, a gate that refused all batched messages would satisfy the
    position tests completely.
    """
    agent = _agent(denied_tools=["send_money"])

    agent.send(_msg("get_weather", "lookup_docs"))

    assert not _blocks(sent)


def test_an_allowlist_is_applied_to_every_call_not_just_the_first(sent):
    agent = _agent(allowed_tools=["get_weather"])

    with pytest.raises(RuntimeError, match=r"\[obsvr\] Tool blocked"):
        agent.send(_msg("get_weather", "send_money"))

    assert _blocks(sent)[0]["metadata"]["reason"] == "tool_not_in_allowlist"


# ── unreadable requests fail closed ──────────────────────────────────────────


@pytest.mark.parametrize(
    "calls",
    [
        [{"id": "c0", "type": "function", "function": {"arguments": "{}"}}],
        [{"id": "c0", "type": "function", "function": None}],
        [{"id": "c0", "type": "function", "function": {"name": ""}}],
        ["not-a-dict"],
    ],
    ids=["no-name", "no-function", "empty-name", "not-a-dict"],
)
def test_a_tool_call_with_no_readable_name_is_refused(calls, sent):
    """An uncheckable capability request is refused, not skipped.

    These used to fall through the name extraction silently, so a message could
    carry a tool call the gate never saw and never mentioned.
    """
    agent = _agent(denied_tools=["send_money"])

    with pytest.raises(RuntimeError, match="no readable name"):
        agent.send({"role": "assistant", "content": None, "tool_calls": calls})

    blocked = _blocks(sent)
    assert len(blocked) == 1
    assert blocked[0]["metadata"]["reason"] == "tool_name_unreadable"
    assert blocked[0]["metadata"]["unreadable_tool_calls"] == 1


def test_a_message_with_no_tool_calls_is_not_treated_as_unreadable(sent):
    """Ordinary chat must not trip the fail-closed path."""
    agent = _agent(denied_tools=["send_money"])

    agent.send({"role": "assistant", "content": "just talking"})

    assert not _blocks(sent)


# ── the step budget is charged per call ──────────────────────────────────────


def test_the_step_budget_is_charged_per_call_not_per_message(sent):
    """Three calls against a budget of two must stop at the third.

    Charging per message made a batch cost one step, so the same batching that
    defeated the tool gate also defeated the limit.
    """
    agent = _agent(max_steps=2)

    with pytest.raises(RuntimeError, match=r"\[obsvr\] Step limit"):
        agent.send(_msg("a", "b", "c"))

    limits = _limits(sent)
    assert len(limits) == 1
    assert limits[0]["metadata"]["step_count"] == 2
    assert limits[0]["metadata"]["tool_call_index"] == 2


def test_a_batch_inside_the_budget_is_delivered(sent):
    """Control: two calls against a budget of two must pass."""
    agent = _agent(max_steps=2)

    agent.send(_msg("a", "b"))

    assert not _limits(sent)


def test_the_budget_carries_across_messages(sent):
    """One call per message, three messages, budget of two: the third stops."""
    agent = _agent(max_steps=2)

    agent.send(_msg("a"))
    agent.send(_msg("b"))
    with pytest.raises(RuntimeError, match=r"\[obsvr\] Step limit"):
        agent.send(_msg("c"))


def test_a_step_limit_refusal_is_recorded_as_a_refusal(sent):
    """It used to land as a permitted llm_call, so refusal filters missed it.

    The event carried no compliance at all, inherited the default, and reported
    ``event_type: "llm_call"`` with ``reason_code: PERMITTED`` — a block that
    read as an ordinary allowed call to anyone reviewing refusals.
    """
    agent = _agent(max_steps=1)

    agent.send(_msg("a"))
    with pytest.raises(RuntimeError, match=r"\[obsvr\] Step limit"):
        agent.send(_msg("b"))

    limit = _limits(sent)[0]
    assert limit["event_type"] == "blocked_call", (
        "a blocked_call filter has to be able to find this"
    )
    assert limit["action_taken"] == "blocked"
    assert limit["action_reason"] == "policy_violation"
    assert limit["reason_code"] == "POLICY_VIOLATION"
    assert limit["success"] is False


def test_escalate_does_not_refuse_and_does_not_claim_to(sent):
    """``step_limit_action: "escalate"`` flags and continues."""
    agent = _agent(max_steps=1, step_limit_action="escalate")

    agent.send(_msg("a"))
    agent.send(_msg("b"))  # over the limit, must not raise

    escalated = [e for e in _limits(sent) if e["metadata"].get("escalated")]
    assert escalated
    assert escalated[0]["action_taken"] != "blocked"
