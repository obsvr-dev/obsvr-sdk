"""Fail closed on a missing principal (opt-in).

``require_principal=True`` refuses a governed call whose enforcing metadata
carries no ``user_id`` at all, with ``PRINCIPAL_REQUIRED``, before any
scanning layer runs. An empty string is a supplied principal; only an absent
one refuses — the decision digest's presence byte draws the same
absent-vs-empty line. The flag arms the pre-call net by itself, the
enforcement-integrity gate still wins outright, and monitor mode converts
the refusal like any non-integrity block.
"""

import pytest

import obsvr
from obsvr import remote, sender
from obsvr.config import ResolvedConfig, _reset, get_config
from obsvr.errors import ObsvrPolicyError
from obsvr.integrations.tools import govern_tool
from obsvr.policy import apply_pre_call_policy
from obsvr.reason_codes import ReasonCode
from obsvr.subject import use_subject


@pytest.fixture
def sent(monkeypatch):
    captured = []
    monkeypatch.setattr(
        sender, "send_audit_async", lambda config, event: captured.append(event)
    )
    return captured


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    from obsvr.integrations import tools as tools_mod

    monkeypatch.setattr(tools_mod, "_GOVERNED_TOOL_NAMES", set())
    _reset()
    sender._reset_sender()
    yield
    _reset()


def _init(**kwargs):
    obsvr.init(api_key="k", policy_refresh_interval_s=0, **kwargs)


class _SpyTool:
    name = "helper"

    def __init__(self):
        self.calls = []

    def _run(self, note=""):
        self.calls.append(note)
        return "done"


def _blocked_tool_event(sent_events):
    blocked = [e for e in sent_events if e.get("action_taken") == "blocked"]
    assert blocked, "the refusal must reach the audit stream"
    return blocked[0]


class TestRefusal:
    def test_an_unattributed_call_is_refused_before_the_tool_runs(self, sent):
        # require_principal is the ONLY policy configured: this also proves
        # the flag arms the pre-call net at the tool boundary by itself.
        _init(require_principal=True)
        tool = _SpyTool()
        governed = govern_tool(tool)

        with pytest.raises(ObsvrPolicyError):
            governed._run(note="anything")

        assert tool.calls == [], "the side effect must not run unattributed"
        event = _blocked_tool_event(sent)
        assert event["reason_code"] == ReasonCode.PRINCIPAL_REQUIRED.value
        assert event["rule_id"] == "sdk:principal_required"

    def test_a_wrap_time_principal_passes(self, sent):
        _init(require_principal=True)
        tool = _SpyTool()
        governed = govern_tool(tool, user_id="alice")

        assert governed._run(note="hello") == "done"
        assert tool.calls == ["hello"]

    def test_an_ambient_subject_satisfies_the_requirement(self, sent):
        _init(require_principal=True)
        tool = _SpyTool()
        governed = govern_tool(tool)

        with use_subject("user:carol"):
            assert governed._run(note="hello") == "done"
        assert tool.calls == ["hello"]

    def test_an_empty_string_principal_counts_as_supplied(self, sent):
        """The absent-vs-empty line: "" is a supplied principal. A truthiness
        check (``if not user_id``) instead of ``is None`` fails here."""
        _init(require_principal=True)
        tool = _SpyTool()
        governed = govern_tool(tool, user_id="")

        assert governed._run(note="hello") == "done"
        assert tool.calls == ["hello"]

    def test_the_pipeline_draws_the_same_line_directly(self):
        cfg = ResolvedConfig(api_key="k", require_principal=True)
        refused = apply_pre_call_policy("hi", cfg, metadata=None)
        assert refused["decision"] == "block"
        assert refused["compliance"]["reason_code"] == (
            ReasonCode.PRINCIPAL_REQUIRED.value
        )
        empty = apply_pre_call_policy("hi", cfg, metadata={"user_id": ""})
        assert empty["decision"] == "allow"


class TestComposition:
    def test_the_integrity_gate_verdict_wins_outright(self, sent):
        """A paused project refuses with ITS verdict: one block, one reason,
        no principal re-labelling of a kill-switch refusal."""
        _init(require_principal=True)
        with remote._sync_lock:
            remote._sync["remote_disabled"] = True
        tool = _SpyTool()
        governed = govern_tool(tool)

        with pytest.raises(ObsvrPolicyError):
            governed._run(note="anything")

        assert tool.calls == []
        event = _blocked_tool_event(sent)
        assert event["rule_id"] == "sdk:project_paused_or_key_revoked"
        assert event["reason_code"] == ReasonCode.POLICY_VIOLATION.value
        assert event["reason_code"] != ReasonCode.PRINCIPAL_REQUIRED.value

    def test_monitor_mode_converts_the_refusal_and_keeps_the_evidence(self, sent):
        """Rolling the flag out in monitor mode first is the intended
        adoption path: the call runs, the record carries the would-be
        refusal."""
        _init(require_principal=True, enforcement_mode="monitor")
        tool = _SpyTool()
        governed = govern_tool(tool)

        assert governed._run(note="hello") == "done"
        assert tool.calls == ["hello"]
        events = [e for e in sent if e.get("operation") == "tool.call"]
        assert len(events) == 1
        assert events[0]["action_taken"] == "allowed"
        shadow = events[0]["shadow_outcome"]
        assert shadow["would"] == "block"
        assert shadow["reason_code"] == ReasonCode.PRINCIPAL_REQUIRED.value


class TestDefaultAndValidation:
    def test_the_default_is_off_and_anonymous_calls_run(self, sent):
        assert ResolvedConfig(api_key="k").require_principal is False
        _init()
        assert get_config().require_principal is False
        tool = _SpyTool()
        governed = govern_tool(tool)
        assert governed._run(note="hello") == "done"
        assert tool.calls == ["hello"]

    def test_a_non_boolean_flag_is_refused_at_init(self):
        with pytest.raises(ValueError, match="require_principal"):
            obsvr.init(api_key="k", require_principal="yes")
