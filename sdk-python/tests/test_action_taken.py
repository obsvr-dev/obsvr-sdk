"""The closed ``action_taken`` set, pinned against the shared fixture.

Twin: sdk-typescript/tests/unit/action-taken.test.ts. Neither language compares
itself to the other; both compare themselves to
``conformance/fixtures/action_taken.json``, which makes the agreement transitive
and means a divergence fails in the language that caused it.

WHY THIS FIXTURE EXISTS, recorded because the gap was invisible. ``not_evaluated``
was a live production value in both SDKs, emitted from several surfaces, and the
corpus pinned none of it — only ``allowed``, ``blocked`` and one ``null`` appeared
anywhere in 31 fixtures. The two languages agreed because they had been widened in
the same commit, which is agreement by coincidence. Python also had no enumeration
of the field at all, while its own comments called it a closed enum.
"""

import json
import pathlib

import pytest

import obsvr
from obsvr.events import (
    ACTION_TAKEN,
    step_limit_compliance,
    tool_denied_compliance,
    tool_gate_not_evaluated_compliance,
)

FIXTURE = (
    pathlib.Path(__file__).resolve().parents[2]
    / "conformance"
    / "fixtures"
    / "action_taken.json"
)


@pytest.fixture(scope="module")
def fixture():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_the_set_equals_the_fixture(fixture):
    assert list(ACTION_TAKEN) == fixture["verdicts"]


def test_the_fixture_is_stored_sorted(fixture):
    """So an order-sensitive comparison is safe on both sides.

    Without this, one language sorting at assertion time and the other not would
    hide a real difference behind a passing test.
    """
    assert fixture["verdicts"] == sorted(fixture["verdicts"])


def test_the_set_has_no_duplicates():
    assert len(set(ACTION_TAKEN)) == len(ACTION_TAKEN)


def test_every_verdict_carries_stated_semantics(fixture):
    """A pinned vocabulary with no meanings beside it is a spelling list.

    The distinction this field turns on — that `not_evaluated` is the absence of a
    decision and not a permissive one — is the thing a reader gets wrong, so it is
    written down where the set is pinned rather than only in a docstring.
    """
    documented = {entry["verdict"] for entry in fixture["semantics"]}
    assert documented == set(fixture["verdicts"])


def test_not_evaluated_is_pinned_with_the_three_things_it_must_not_do(fixture):
    """The value this fixture was written for, and the claims about it.

    Each of these was a real defect in this codebase: an event that claimed
    `allowed` about a call no gate saw, an event that claimed `blocked` about a
    call that completed, and a field left absent so the server minted `allowed`
    one layer down.
    """
    entry = next(e for e in fixture["semantics"] if e["verdict"] == "not_evaluated")
    assert "allowed" in entry["must_not_be_read_as"]
    assert "blocked" in entry["must_not_be_read_as"]
    assert "must_not_be_omitted" in entry
    assert "policy_not_evaluated" in entry["reason_travels_on"]


# ── containment: what the code actually emits stays inside the set ───────────


def test_the_shared_compliance_helpers_stay_inside_the_set():
    """CONTAINMENT. A closed set is only closed if nothing emits outside it."""
    verdicts = [
        tool_denied_compliance()["action_taken"],
        step_limit_compliance()["action_taken"],
        tool_gate_not_evaluated_compliance("s", "g", "r")["action_taken"],
    ]
    for verdict in verdicts:
        assert verdict in ACTION_TAKEN, verdict


def test_every_verdict_an_emitted_event_carries_is_in_the_set(sent):
    """Containment over a real emission path rather than over helpers alone.

    Drives the pre-call pipeline and the tool gate, then checks every event that
    actually reached the sender. A helper-only check would pass while an
    integration hand-built a compliance dict with a value nothing pins — which is
    how `not_evaluated` came to exist in four places at once.
    """
    obsvr.init(
        api_key="test", sample_rate=1,
        agent_policy={"denied_tools": ["send_money"]},
    )
    from obsvr.integrations import autogen as autogen_mod
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
                {"id": "c0", "type": "function", "function": {"name": name}}
            ],
        }

    agent.send(msg("get_weather"))
    with pytest.raises(RuntimeError):
        agent.send(msg("send_money"))

    autogen_mod._run_local.agent_run_id = None
    obsvr.init(api_key="test", sample_rate=1, agent_policy={"max_steps": 1})
    agent2 = register_obsvr(FakeAgent())
    agent2.send(msg("a"))

    assert sent, "no events reached the sender, so containment was not tested"
    seen = {e.get("action_taken") for e in sent if e.get("action_taken") is not None}
    assert seen, "no event carried a verdict"
    assert seen <= set(ACTION_TAKEN), seen - set(ACTION_TAKEN)
    # And the value this fixture exists for is genuinely reachable here, so the
    # assertion above is not passing over a set the code never exercises.
    assert "not_evaluated" in seen
