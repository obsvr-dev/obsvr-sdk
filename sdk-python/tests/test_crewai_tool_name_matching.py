"""CrewAI renames tools before dispatch — the gate must match the name anyway.

CrewAI sanitizes every tool name on its way to the executor: lowercased,
camelCase split, anything outside ``[a-z0-9_]`` replaced with an underscore.
So a tool hook is asked about ``delegate_work_to_coworker`` for the tool that
CrewAI's own documentation, the agent's prompt, and therefore the caller's
``denied_tools`` list all call "Delegate work to coworker".

Comparing those strings raw matched NOTHING, which is the worst shape a gate
can fail in: the denied tool ran, and no record was written to say a policy
had been consulted at all. Found live by denying CrewAI's auto-injected
delegation tool by its documented name and watching the marker file gain a
line. These pin the normalization on both sides.
"""

import pytest

from obsvr.integrations.crewai import _check_tool


DISPATCHED = "delegate_work_to_coworker"


@pytest.mark.parametrize(
    "written_by_the_caller",
    [
        "Delegate work to coworker",  # what CrewAI's docs and prompts call it
        "delegate_work_to_coworker",  # what shows up in logs
        "Delegate Work To Coworker",
    ],
)
def test_a_denied_tool_matches_however_the_policy_spells_it(written_by_the_caller):
    allowed, reason = _check_tool(
        DISPATCHED, {"denied_tools": [written_by_the_caller]}
    )
    assert allowed is False, f"{written_by_the_caller!r} did not deny {DISPATCHED!r}"
    assert reason == "tool_denied"


def test_normalization_does_not_deny_an_unrelated_tool():
    """The widened match must not become a loose one."""
    allowed, reason = _check_tool(
        "write_marker", {"denied_tools": ["Delegate work to coworker"]}
    )
    assert allowed is True and reason == ""


def test_an_allowlist_written_in_either_spelling_admits_the_tool():
    """The allowlist half fails the other way — a human-spelled entry that
    matched nothing would refuse EVERY tool, including the one it names."""
    allowed, _ = _check_tool(DISPATCHED, {"allowed_tools": ["Delegate work to coworker"]})
    assert allowed is True

    allowed, reason = _check_tool(
        "write_marker", {"allowed_tools": ["Delegate work to coworker"]}
    )
    assert allowed is False and reason == "tool_not_in_allowlist"


def test_camel_case_tools_are_reachable_by_their_declared_name():
    """Not a delegation-only problem: CrewAI splits camelCase too, so any tool
    named the way most codebases name things is affected."""
    allowed, _ = _check_tool("search_web", {"denied_tools": ["searchWeb"]})
    assert allowed is False


def test_matching_survives_crewai_moving_its_helper(monkeypatch):
    """The sanitizer is resolved from CrewAI at runtime, so the fallback is
    what runs the day that helper is renamed or moved. It must still match:
    falling back to the raw name would silently restore the very fail-open
    this normalization closes, and do it without a word."""
    from obsvr.integrations import crewai as crewai_mod

    monkeypatch.setattr(crewai_mod, "_sanitizer_cell", [crewai_mod._mirror_sanitize])
    allowed, _ = _check_tool(DISPATCHED, {"denied_tools": ["Delegate work to coworker"]})
    assert allowed is False, "the fallback must not quietly stop denying"
    allowed, _ = _check_tool("write_marker", {"denied_tools": ["Delegate work to coworker"]})
    assert allowed is True, "and must not become a loose match either"


# Whether the mirror still AGREES with CrewAI's own function needs CrewAI
# installed, so it is not asserted here — this suite runs with no framework
# present, and an install-gated skip in a suite that otherwise has none is how
# a check quietly stops running. It lives in the harness instead, where CrewAI
# is always installed: py/integrations/crewai-bypass, "the mirror still agrees
# with CrewAI's own sanitizer".
