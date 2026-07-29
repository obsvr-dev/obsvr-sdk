"""An unrecognised ``step_limit_action`` blocks, and says that it did.

The defect: ``_check_steps`` returned ``policy["step_limit_action"]`` verbatim,
and every caller then tested it against the two dispositions it implements. A
value outside that pair — a typo, or a disposition from a newer config than the
installed SDK — matched neither branch, so the limit did nothing at all and
recorded nothing either. A run that blew straight through its budget was
indistinguishable from one that stayed inside it.

Measured live before the repair: with ``max_steps: 2`` and
``step_limit_action: "warn"``, a tool chain ran five times on both ag2 releases
under test.

There were four identical copies of that function, one per integration. There is
now one, and these tests drive it directly as well as through each caller — a
shared helper is only worth having if a caller cannot quietly stop using it.
"""

import pytest

import obsvr
from obsvr.agent_policy import (
    STEP_LIMIT_ACTIONS,
    check_steps,
    unrecognized_step_action_meta,
)


# ── the decision itself ──────────────────────────────────────────────────────


def test_no_limit_configured_allows():
    assert check_steps(99, {}) == ("allow", None)


def test_inside_the_limit_allows():
    assert check_steps(0, {"max_steps": 2}) == ("allow", None)
    assert check_steps(1, {"max_steps": 2}) == ("allow", None)


def test_at_the_limit_blocks_by_default():
    assert check_steps(2, {"max_steps": 2}) == ("block", None)


def test_a_recognised_action_is_honoured():
    assert check_steps(2, {"max_steps": 2, "step_limit_action": "escalate"}) == (
        "escalate",
        None,
    )
    assert check_steps(2, {"max_steps": 2, "step_limit_action": "block"}) == (
        "block",
        None,
    )


@pytest.mark.parametrize(
    "action",
    ["warn", "allow", "ALLOW", "Block", "", None, 0, [], "escalate ", "throttle"],
    ids=[
        "typo", "allow-is-not-a-disposition", "wrong-case-allow", "wrong-case-block",
        "empty", "none", "zero", "list", "trailing-space", "future-value",
    ],
)
def test_an_unrecognised_action_blocks_and_is_reported(action):
    """Fail CLOSED, and name what was ignored.

    ``"allow"`` is in this list on purpose. It is not one of the dispositions
    the callers implement, and reading it as "disable the limit" would let a
    plausible-looking config switch a control off — which is the exact failure
    being repaired, arrived at from the other direction.
    """
    verdict, unrecognised = check_steps(2, {"max_steps": 2, "step_limit_action": action})

    assert verdict == "block"
    assert unrecognised == str(action)
    assert verdict in ("allow",) + STEP_LIMIT_ACTIONS, (
        "the returned action must be one a caller's branches actually test"
    )


def test_the_vocabulary_is_exactly_what_the_callers_branch_on():
    """Guards the pair itself.

    If a disposition is added to ``STEP_LIMIT_ACTIONS`` without a branch in the
    callers, it stops being reported as unrecognised while still doing nothing —
    the original defect, reintroduced through the fix.
    """
    assert STEP_LIMIT_ACTIONS == ("block", "escalate")


def test_the_metadata_helper_is_empty_when_nothing_was_ignored():
    """Control: a clean config must not stamp a config-error key."""
    assert unrecognized_step_action_meta(None) == {}
    assert unrecognized_step_action_meta("") == {}


def test_the_metadata_helper_names_the_value_and_the_vocabulary():
    meta = unrecognized_step_action_meta("warn")
    assert meta["step_limit_action_unrecognized"] == "warn"
    assert meta["step_limit_action_supported"] == ["block", "escalate"]


# ── every caller, not just the decision ──────────────────────────────────────
#
# One shared definition is only an improvement if each integration is actually
# reaching it. These drive the four surfaces and assert the refusal is recorded.


def _limit_events(sent, source_op):
    return [e for e in sent if e["operation"] == source_op]


def test_autogen_blocks_on_an_unrecognised_action(sent):
    obsvr.init(api_key="test", sample_rate=1,
               agent_policy={"max_steps": 1, "step_limit_action": "warn"})
    from obsvr.integrations.autogen import register_obsvr

    class FakeAgent:
        def __init__(self):
            self._hooks = {}
            self.llm_config = {"model": "gpt-4o"}

        def register_hook(self, hookpoint, fn):
            self._hooks.setdefault(hookpoint, []).append(fn)

        def send(self, message):
            for fn in self._hooks.get("process_message_before_send", []):
                fn(message=message)

    agent = register_obsvr(FakeAgent())

    def msg(name):
        return {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {"id": "c0", "type": "function",
                 "function": {"name": name, "arguments": "{}"}}
            ],
        }

    agent.send(msg("a"))
    with pytest.raises(RuntimeError, match=r"\[obsvr\] Step limit"):
        agent.send(msg("b"))

    limit = _limit_events(sent, "autogen.agent.policy.step_limit")[0]
    assert limit["action_taken"] == "blocked"
    assert limit["metadata"]["step_limit_action_unrecognized"] == "warn"


def test_crewai_blocks_on_an_unrecognised_action(sent):
    """CrewAI's step limit is REACHABLE even though its tool gate is not.

    The step check runs on every step callback rather than being nested inside
    the tool-name branch, so unlike its tool gate this control does fire on
    current runtimes.
    """
    obsvr.init(api_key="test", sample_rate=1,
               agent_policy={"max_steps": 1, "step_limit_action": "warn"})
    from obsvr.integrations.crewai import make_step_callback

    ctx = {}
    callback = make_step_callback(run_context=ctx)

    class Step:
        output = "did a thing"

    callback(Step())
    ctx["step_count"] = 1
    with pytest.raises(RuntimeError, match=r"\[obsvr\] Step limit"):
        callback(Step())

    limit = _limit_events(sent, "crewai.agent.policy.step_limit")[0]
    assert limit["action_taken"] == "blocked", (
        "this used to inherit the default compliance and report as a permitted "
        "call, so refusal filters missed it"
    )
    assert limit["metadata"]["step_limit_action_unrecognized"] == "warn"


def test_openai_agents_blocks_on_an_unrecognised_action(sent):
    """It cannot halt the run, so the verdict stays ``not_evaluated``.

    Failing closed here means the limit is applied and the ignored config is
    named; it does not mean claiming a halt this surface cannot perform.
    """
    obsvr.init(api_key="test", sample_rate=1,
               agent_policy={"max_steps": 1, "step_limit_action": "warn"})
    from obsvr.integrations.openai_agents import ObsvrTracingProcessor

    class Trace:
        trace_id = "t1"

    class SpanData:
        type = "function"

        def __init__(self, name):
            self.name = name
            self.input = "{}"

    class Span:
        def __init__(self, span_id, name):
            self.trace_id = "t1"
            self.span_id = span_id
            self.span_data = SpanData(name)

    proc = ObsvrTracingProcessor()
    proc.on_trace_start(Trace())
    proc.on_span_end(Span("s1", "a"))
    proc.on_span_end(Span("s2", "b"))

    limit = _limit_events(sent, "openai_agents.agent.policy.step_limit")[0]
    assert limit["action_taken"] == "not_evaluated"
    assert limit["metadata"]["step_limit_action_unrecognized"] == "warn"


def test_no_integration_kept_a_private_copy():
    """The four copies are gone and must stay gone.

    Four identical definitions is four places for the next fix to be applied to
    three of — which is how this one survived: the defect was in all four and
    each looked like an isolated helper.
    """
    import pathlib

    integrations = pathlib.Path(__file__).resolve().parents[1] / "obsvr" / "integrations"
    offenders = [
        path.name for path in sorted(integrations.glob("*.py"))
        if "def _check_steps(" in path.read_text(encoding="utf-8")
    ]
    assert not offenders, (
        f"these modules reintroduced a local step-limit decision: {offenders} — "
        f"use agent_policy.check_steps so the fail-closed rule has one home"
    )
