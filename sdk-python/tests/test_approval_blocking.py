"""A require_approval block can hold the call until a human decides.

With ``approval_wait_ms > 0`` the governed call is HELD in the calling thread
while the grant channel is polled; it proceeds only when a covering grant
lands and is still live at the end of the pipeline. With the default 0 the
behaviour is exactly the fire-and-forget one: refuse, file the request, pass
on a retry once granted.

The grant source here is a fake ``poll_once``: the wait re-drives the same
/policies refresh the daemon uses, so replacing that one function stands in
for "a human approved after N polls" without any network. Twin (the wait
itself): sdk-typescript/tests/unit/approvals-wait.test.ts.
"""

import time
from datetime import datetime, timedelta, timezone

import pytest

import obsvr
from obsvr import remote, sender
from obsvr.config import _reset, ResolvedConfig, get_config
from obsvr.errors import ObsvrPolicyError
from obsvr.integrations.tools import govern_tool
from obsvr.reason_codes import ReasonCode
from obsvr.remote import _reset_approvals, await_approval, update_approvals
from obsvr.rules import PolicyRule

RULE = PolicyRule(
    id="r-appr",
    name="send_money needs approval",
    enabled=True,
    action="block",
    type="keyword",
    conditions={"keywords": ["send_money"], "require_approval": True},
)

FUTURE = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
GRANT = {"id": "g1", "rule_id": "r-appr", "expires_at": FUTURE}


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
    _reset_approvals()
    yield
    _reset()
    _reset_approvals()


def _init(**extra):
    # pii_policy={} arms the full pre-call net on the tool boundary;
    # policy_refresh_interval_s=0 keeps the daemon poll out of the way so the
    # fake grant source below is the only thing feeding the store.
    obsvr.init(
        api_key="k",
        ingest_url="http://localhost:9",
        policy_rules=[RULE],
        pii_policy={},
        policy_refresh_interval_s=0,
        **extra,
    )


class _SpyTool:
    """Side-effect spy: records, at execution time, whether the grant had
    already landed - which is exactly assertion (a)."""

    name = "helper"

    def __init__(self, state):
        self.state = state
        self.calls = []

    def _run(self, note=""):
        self.calls.append(self.state["landed"])
        return "done"


def _grant_source(monkeypatch, approve_after):
    """poll_once stand-in: undecided for N polls, then the grant lands.
    approve_after=None never approves."""
    state = {"polls": 0, "landed": False}

    def fake_poll(cfg):
        state["polls"] += 1
        if approve_after is not None and state["polls"] >= approve_after:
            update_approvals([GRANT])
            state["landed"] = True

    monkeypatch.setattr(remote, "poll_once", fake_poll)
    return state


class TestBlockingWait:
    def test_the_call_is_held_and_runs_exactly_once_after_the_grant(
        self, sent, monkeypatch
    ):
        """(a) the side effect did not run before the grant landed, and
        (b) it ran exactly once after."""
        state = _grant_source(monkeypatch, approve_after=3)
        _init(approval_wait_ms=5000, approval_poll_ms=20)
        tool = _SpyTool(state)
        governed = govern_tool(tool)

        assert governed._run(note="send_money now") == "done"

        # (a) + (b): one execution, and the grant was live when it happened.
        assert tool.calls == [True]
        assert state["polls"] >= 3
        # The resolution is on the record: the allowed event names the rule
        # and carries the granted-after-wait classification.
        allowed = [e for e in sent if e.get("operation") == "tool.call"]
        assert len(allowed) == 1
        assert allowed[0]["action_taken"] == "allowed"
        assert allowed[0]["rule_id"] == "r-appr"
        assert allowed[0]["reason_code"] == ReasonCode.APPROVAL_GRANTED.value

    def test_a_wait_nobody_answers_blocks_with_its_own_reason_code(
        self, sent, monkeypatch
    ):
        """(c) never-approving source: blocked, and the event carries the
        distinct timeout code rather than APPROVAL_REQUIRED."""
        state = _grant_source(monkeypatch, approve_after=None)
        _init(approval_wait_ms=150, approval_poll_ms=30)
        tool = _SpyTool(state)
        governed = govern_tool(tool)

        with pytest.raises(ObsvrPolicyError):
            governed._run(note="send_money now")

        assert tool.calls == []
        blocked = [e for e in sent if e.get("action_taken") == "blocked"]
        assert blocked, "the refused call must be on the record"
        assert blocked[0]["reason_code"] == ReasonCode.APPROVAL_TIMEOUT.value
        assert "approval_wait_timeout" in blocked[0]["policy_reason"]

    def test_a_kill_switch_mid_wait_aborts_the_hold_and_blocks(
        self, sent, monkeypatch
    ):
        """Degradation during the wait fails closed immediately: the block
        stands as APPROVAL_REQUIRED with the abort on the record."""
        state = {"polls": 0, "landed": False}

        def revoking_poll(cfg):
            state["polls"] += 1
            with remote._sync_lock:
                remote._sync["remote_disabled"] = True

        monkeypatch.setattr(remote, "poll_once", revoking_poll)
        _init(approval_wait_ms=5000, approval_poll_ms=20)
        tool = _SpyTool(state)
        governed = govern_tool(tool)

        start = time.monotonic()
        with pytest.raises(ObsvrPolicyError):
            governed._run(note="send_money now")
        assert time.monotonic() - start < 2.0, "the abort must not wait out the budget"

        assert tool.calls == []
        blocked = [e for e in sent if e.get("action_taken") == "blocked"]
        assert blocked[0]["reason_code"] == ReasonCode.APPROVAL_REQUIRED.value
        assert "approval_wait_aborted" in blocked[0]["policy_reason"]


class TestOptInDefault:
    def test_wait_disabled_is_byte_identical_to_the_fire_and_forget_path(
        self, sent, monkeypatch
    ):
        """(d) approval_wait_ms=0 (the default): no poll is driven, the call
        is refused immediately with APPROVAL_REQUIRED - today's behaviour."""
        state = _grant_source(monkeypatch, approve_after=1)
        _init()  # no approval kwargs at all
        tool = _SpyTool(state)
        governed = govern_tool(tool)

        with pytest.raises(ObsvrPolicyError):
            governed._run(note="send_money now")

        assert tool.calls == []
        assert state["polls"] == 0, "the wait must not run when disabled"
        blocked = [e for e in sent if e.get("action_taken") == "blocked"]
        assert blocked[0]["reason_code"] == ReasonCode.APPROVAL_REQUIRED.value
        assert "approval_required" in blocked[0]["policy_reason"]
        assert "approval_wait" not in blocked[0]["policy_reason"]

    def test_the_default_is_zero(self):
        """Mutation guard for (d): this test fails if the default ever moves
        off 0 - the change that would make a library upgrade start blocking
        production calls for minutes."""
        assert ResolvedConfig(api_key="k").approval_wait_ms == 0
        _init()
        assert get_config().approval_wait_ms == 0


class TestNonVacuity:
    def test_approval_wait_catches_a_premature_release(self, sent, monkeypatch):
        """Disarm the wait: patch await_approval to answer approved
        immediately, regardless of the grant source. Assertion (a) must go
        red - and it does so as a refusal, because the end-of-pipeline
        re-validation finds no live grant and keeps the call blocked. A
        broken wait cannot smuggle a call through."""
        state = _grant_source(monkeypatch, approve_after=3)
        _init(approval_wait_ms=5000, approval_poll_ms=20)
        tool = _SpyTool(state)
        governed = govern_tool(tool)

        monkeypatch.setattr(remote, "await_approval", lambda *a, **k: "approved")

        with pytest.raises(ObsvrPolicyError):
            governed._run(note="send_money now")
        assert tool.calls == [], "an unbacked approval must not release the call"
        blocked = [e for e in sent if e.get("action_taken") == "blocked"]
        assert "approval_expired_before_execution" in blocked[0]["policy_reason"]

    def test_a_grant_expiring_during_the_wait_is_not_spent(self, sent, monkeypatch):
        """The roadmap's revalidation requirement, driven directly: the grant
        lands mid-wait and is revoked before execution (a human clicking
        revoke, or an expiry landing between polls)."""
        state = {"polls": 0, "landed": False}

        def flicker_poll(cfg):
            state["polls"] += 1
            if state["polls"] == 2:
                update_approvals([GRANT])
                state["landed"] = True

        monkeypatch.setattr(remote, "poll_once", flicker_poll)

        # The hook runs after the wait; revoking inside it stands in for the
        # grant dying between "approved" and "sent".
        def revoking_hook(_event):
            update_approvals([])
            return {"decision": "allow"}

        _init(approval_wait_ms=5000, approval_poll_ms=20, on_pre_call=revoking_hook)
        tool = _SpyTool(state)
        governed = govern_tool(tool)

        with pytest.raises(ObsvrPolicyError):
            governed._run(note="send_money now")
        assert tool.calls == []
        blocked = [e for e in sent if e.get("action_taken") == "blocked"]
        assert "approval_expired_before_execution" in blocked[0]["policy_reason"]


class TestAwaitApprovalUnit:
    """The wait primitive on its own, no governed surface."""

    def test_a_grant_already_in_the_store_answers_without_polling(self, monkeypatch):
        polls = []
        monkeypatch.setattr(remote, "poll_once", lambda cfg: polls.append(1))
        update_approvals([GRANT])
        cfg = ResolvedConfig(api_key="k")
        verdict = await_approval(
            cfg, {"rule_id": "r-appr"}, timeout_s=1.0, poll_s=0.05
        )
        assert verdict == "approved"
        assert polls == []

    def test_an_empty_store_times_out(self, monkeypatch):
        monkeypatch.setattr(remote, "poll_once", lambda cfg: None)
        cfg = ResolvedConfig(api_key="k")
        start = time.monotonic()
        verdict = await_approval(
            cfg, {"rule_id": "r-appr"}, timeout_s=0.15, poll_s=0.05
        )
        assert verdict == "timeout"
        assert time.monotonic() - start < 1.0

    def test_a_raising_poll_resolves_closed_not_raised(self, monkeypatch):
        def broken_poll(cfg):
            raise RuntimeError("grant channel down")

        monkeypatch.setattr(remote, "poll_once", broken_poll)
        cfg = ResolvedConfig(api_key="k")
        verdict = await_approval(
            cfg, {"rule_id": "r-appr"}, timeout_s=0.15, poll_s=0.05
        )
        assert verdict in ("timeout", "unavailable")
