"""Fail closed on a missing principal (opt-in).

``require_principal=True`` refuses a governed call whose enforcing metadata
carries no meaningful ``user_id``, with ``PRINCIPAL_REQUIRED``, before any
scanning layer runs. Empty and whitespace-only strings are unattributed. The
flag arms the pre-call net by itself, the
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
from obsvr.rules import PolicyRule
from obsvr.subject import use_subject
from obsvr.wrap import wrap


class _FakeCompletions:
    def __init__(self):
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)

        class _Msg:
            content = "ok"

        class _Choice:
            message = _Msg()

        class _Resp:
            choices = [_Choice()]

        return _Resp()


class _FakeOpenAI:
    """The shape obsvr.wrap() intercepts (chat.completions.create)."""

    def __init__(self):
        self.completions = _FakeCompletions()
        self.chat = self  # chat.completions.create
        self.api_key = "sk-fake"


@pytest.fixture
def sent(monkeypatch):
    captured = []
    _capture = lambda config, event: captured.append(event)
    # emit_event uses the module-qualified sender.send_audit_async; the wrap
    # path binds it directly (`from .sender import send_audit_async`), so patch
    # both names into one list to capture every surface.
    monkeypatch.setattr(sender, "send_audit_async", _capture)
    import importlib

    # obsvr.wrap the ATTRIBUTE is the wrap() function (re-exported); the module
    # lives in sys.modules under the same dotted name.
    _wrap_mod = importlib.import_module("obsvr.wrap")
    monkeypatch.setattr(_wrap_mod, "send_audit_async", _capture)
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

    @pytest.mark.parametrize("user_id", ["", "   "])
    def test_a_blank_principal_is_refused(self, sent, user_id):
        _init(require_principal=True)
        tool = _SpyTool()
        governed = govern_tool(tool, user_id=user_id)

        with pytest.raises(ObsvrPolicyError):
            governed._run(note="hello")
        assert tool.calls == []

    def test_the_pipeline_draws_the_same_line_directly(self):
        cfg = ResolvedConfig(api_key="k", require_principal=True)
        refused = apply_pre_call_policy("hi", cfg, metadata=None)
        assert refused["decision"] == "block"
        assert refused["compliance"]["reason_code"] == (
            ReasonCode.PRINCIPAL_REQUIRED.value
        )
        empty = apply_pre_call_policy("hi", cfg, metadata={"user_id": ""})
        assert empty["decision"] == "block"
        whitespace = apply_pre_call_policy("hi", cfg, metadata={"user_id": "   "})
        assert whitespace["decision"] == "block"


class TestAmbientReachesEnforcement:
    """The ambient use_subject() scope must reach the ENFORCING channel, not
    only the signed record. require_principal blocks in exactly one place —
    inside apply_pre_call_policy — so folding the ambient there covers every
    surface that routes through it (wrap, bedrock, vertex, haystack,
    pydantic_ai, autogen, mcp). Before the fold an ambient-only principal was
    named on the record but invisible to enforcement: the signed event
    refused a call FOR a missing principal while its own user_id field named
    that principal — a record contradicting its own reason, the defect this
    project treats as most serious.
    """

    def test_the_choke_point_admits_an_ambient_only_principal(self):
        # apply_pre_call_policy is what every governed surface calls; metadata
        # None is the shape the wrap and integration paths pass when no
        # explicit principal was supplied. Without the fold this refuses with
        # PRINCIPAL_REQUIRED while the record would have named the ambient user.
        cfg = ResolvedConfig(api_key="k", require_principal=True)
        with use_subject("user:alice"):
            result = apply_pre_call_policy("hi", cfg, metadata=None)
        assert result["decision"] == "allow"

    @pytest.mark.parametrize("user_id", ["", "   "])
    def test_an_explicit_blank_beats_the_ambient_principal_at_the_choke_point(
        self, user_id
    ):
        cfg = ResolvedConfig(api_key="k", require_principal=True)
        with use_subject("user:ambient"):
            result = apply_pre_call_policy(
                "hi", cfg, metadata={"user_id": user_id}
            )
        assert result["decision"] == "block"
        assert result["compliance"]["reason_code"] == (
            ReasonCode.PRINCIPAL_REQUIRED.value
        )

    @pytest.mark.parametrize("user_id", ["", "   "])
    def test_an_explicit_blank_tool_principal_cannot_fall_back_to_ambient(
        self, sent, user_id
    ):
        _init(require_principal=True)
        tool = _SpyTool()
        governed = govern_tool(tool, user_id=user_id)

        with use_subject("user:ambient"):
            with pytest.raises(ObsvrPolicyError):
                governed._run(note="hello")

        assert tool.calls == []
        event = _blocked_tool_event(sent)
        assert event["reason_code"] == ReasonCode.PRINCIPAL_REQUIRED.value
        assert event["user_id"] == user_id

    def test_the_wrap_path_admits_an_ambient_only_principal_and_names_it(self, sent):
        # End to end on the surface the bug reproduced against: an ambient-only
        # principal under require_principal. The call must succeed and the
        # signed event must name alice, with NO PRINCIPAL_REQUIRED refusal —
        # so the record can no longer contradict its own reason.
        _init(require_principal=True)
        client = wrap(_FakeOpenAI())
        with use_subject("user:alice"):
            client.chat.completions.create(
                model="gpt-4", messages=[{"role": "user", "content": "hi"}]
            )
        refusals = [
            e for e in sent if e.get("reason_code") == ReasonCode.PRINCIPAL_REQUIRED.value
        ]
        assert refusals == [], "an ambient principal must not be refused as absent"
        attributed = [e for e in sent if e.get("user_id")]
        assert attributed, "the governed call must be on the record"
        assert all(e["user_id"] == "alice" for e in attributed)

    def test_the_wrap_path_admits_a_principal_added_to_a_governed_client(self, sent):
        # Auto-instrumentation patches the client CLASS, so a client built
        # after init() is already governed and wrap(client, user_id=...) is
        # the documented way to attribute it. wrap() handed the governed
        # client straight back to avoid a second audit layer, which also threw
        # the options away — so this gate refused a call the caller HAD
        # attributed, and reported "no principal" about a principal it had
        # been given. _FakeOpenAI stands in for the patched class: the
        # already-governed client is what the caller holds either way.
        _init(require_principal=True)
        already_governed = wrap(_FakeOpenAI())
        client = wrap(already_governed, user_id="alice")

        client.chat.completions.create(
            model="gpt-4", messages=[{"role": "user", "content": "hi"}]
        )

        refusals = [
            e for e in sent if e.get("reason_code") == ReasonCode.PRINCIPAL_REQUIRED.value
        ]
        assert refusals == [], "a wrap-time principal must not be refused as absent"
        attributed = [e for e in sent if e.get("user_id")]
        assert attributed, "the governed call must be on the record"
        assert all(e["user_id"] == "alice" for e in attributed)

    def test_a_governed_client_wrapped_again_still_records_one_event(self, sent):
        # The guard the rebinding must not break: honouring the options costs
        # nothing if it re-introduces the duplicate audit the early return
        # exists to prevent.
        _init()
        client = wrap(wrap(_FakeOpenAI()), user_id="alice")

        client.chat.completions.create(
            model="gpt-4", messages=[{"role": "user", "content": "hi"}]
        )

        calls = [e for e in sent if e.get("event_type") == "llm_call"]
        assert len(calls) == 1, f"expected one audit event, got {len(calls)}"

    def test_a_real_block_under_an_ambient_principal_agrees_with_the_record(self, sent):
        # The contradiction, cornered: when a call IS blocked while an ambient
        # principal is active, the enforcing channel and the signed record must
        # name the SAME principal. Before the fold, require_principal (layer
        # 0.4) fired FIRST and the block read PRINCIPAL_REQUIRED — on an event
        # whose user_id said alice. After it, the ambient satisfies 0.4 and the
        # keyword rule is what blocks: the record names alice and the reason is
        # the rule, not a fabricated "no principal".
        rule = PolicyRule(
            id="k", name="no forbidden", enabled=True, action="block",
            type="keyword", conditions={"keywords": ["forbidden"]},
        )
        _init(require_principal=True, policy_rules=[rule], pii_policy={})
        client = wrap(_FakeOpenAI())
        with use_subject("user:alice"):
            with pytest.raises(ObsvrPolicyError):
                client.chat.completions.create(
                    model="gpt-4",
                    messages=[{"role": "user", "content": "a forbidden thing"}],
                )
        blocked = _blocked_tool_event(sent)
        assert blocked["reason_code"] == ReasonCode.KEYWORD_BLOCKED.value, (
            "an ambient principal must satisfy require_principal, so the block "
            "is the rule's — not a PRINCIPAL_REQUIRED refusal contradicting the "
            "record's own user_id"
        )
        assert blocked["user_id"] == "alice", (
            "the record must name the principal enforcement acted on"
        )


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
