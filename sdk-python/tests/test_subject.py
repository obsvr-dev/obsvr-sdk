"""use_subject() — the ambient per-request subject.

Mirrors sdk-typescript/tests/unit/subject.test.ts (string parsing, scope
binding, nested merge) and adds what only Python has to pin: the
ContextVar propagation boundary matrix, and the enforcement half — two
ambient subjects driven through ONE governed tool attribute separately on
the signed events AND meter separate quota buckets.
"""

import asyncio
import concurrent.futures
import threading

import pytest

import obsvr
from obsvr import get_current_subject, parse_subject, use_subject
from obsvr.errors import ObsvrPolicyError
from obsvr.integrations.tools import govern_tool


# ── Parsing (twin of the TS parseSubject cases) ──────────────────────────────


def test_parses_user_alice():
    assert parse_subject("user:alice") == {"user_id": "alice"}


def test_parses_the_full_three_field_form():
    assert parse_subject("user:alice;tenant:acme;service=api") == {
        "user_id": "alice",
        "tenant_id": "acme",
        "service_name": "api",
    }


def test_treats_a_bare_token_as_user_id():
    assert parse_subject("alice") == {"user_id": "alice"}


def test_passes_a_dict_through_copied():
    subject = {"user_id": "bob", "tenant_id": "t1"}
    assert parse_subject(subject) == subject
    assert parse_subject(subject) is not subject


# ── Scoping ──────────────────────────────────────────────────────────────────


def test_binds_the_subject_only_within_the_scope():
    assert get_current_subject() is None
    with use_subject("user:alice"):
        assert get_current_subject() == {"user_id": "alice"}
    assert get_current_subject() is None


def test_nested_scope_merges_over_the_enclosing_subject():
    with use_subject("user:alice;tenant:acme"):
        with use_subject("user:bob"):
            # inner user_id overrides; enclosing tenant_id is retained
            assert get_current_subject() == {"user_id": "bob", "tenant_id": "acme"}
        assert get_current_subject() == {"user_id": "alice", "tenant_id": "acme"}


def test_the_previous_subject_is_restored_on_exception():
    """The token reset lives in a finally: a raise inside the scope must not
    leak this scope's identity into later, unrelated calls."""
    with use_subject("user:alice"):
        with pytest.raises(RuntimeError):
            with use_subject("user:bob"):
                raise RuntimeError("boom")
        assert get_current_subject() == {"user_id": "alice"}
    assert get_current_subject() is None


def test_reset_guard_catches_a_leaky_scope():
    """Non-vacuity for the test above: drive the same probe through a scope
    whose reset is NOT in a finally (the mutant this feature actually gets
    wrong) and require the restore assertion to fail."""
    from contextlib import contextmanager

    from obsvr import subject as subject_mod

    @contextmanager
    def leaky_use_subject(subject):
        parsed = subject_mod.parse_subject(subject)
        current = subject_mod._current_subject.get() or {}
        token = subject_mod._current_subject.set({**current, **parsed})
        yield
        subject_mod._current_subject.reset(token)  # unreached on a raise

    try:
        with pytest.raises(AssertionError):
            with use_subject("user:alice"):
                with pytest.raises(RuntimeError):
                    with leaky_use_subject("user:bob"):
                        raise RuntimeError("boom")
                assert get_current_subject() == {"user_id": "alice"}, (
                    "the raise left the inner subject bound"
                )
    finally:
        # Clean the deliberately leaked scope so later tests see no subject.
        subject_mod._current_subject.set(None)


# ── Propagation boundaries (the documented matrix, pinned) ───────────────────


def test_the_boundary_matrix_survives_and_loses_where_documented():
    """The subject survives plain await, asyncio.create_task and
    asyncio.to_thread; it is silently LOST across loop.run_in_executor,
    ThreadPoolExecutor.submit and threading.Thread. Both halves are pinned:
    the survives-list is the feature, and the loss cases are a documented
    limitation — a runtime change to either must surface here, not in a
    customer's misattributed audit trail."""

    async def scenario():
        results = {}

        async def read_after_await():
            await asyncio.sleep(0)
            return get_current_subject()

        def read_sync():
            return get_current_subject()

        with use_subject("user:alice"):
            # survives
            results["await"] = await read_after_await()
            results["create_task"] = await asyncio.create_task(read_after_await())
            results["to_thread"] = await asyncio.to_thread(read_sync)

            # silently lost
            loop = asyncio.get_running_loop()
            results["run_in_executor"] = await loop.run_in_executor(None, read_sync)

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                results["executor_submit"] = pool.submit(read_sync).result()

            thread_seen = {}

            def thread_body():
                thread_seen["subject"] = get_current_subject()

            t = threading.Thread(target=thread_body)
            t.start()
            t.join()
            results["thread"] = thread_seen["subject"]

        return results

    results = asyncio.run(scenario())
    alice = {"user_id": "alice"}
    assert results["await"] == alice
    assert results["create_task"] == alice
    assert results["to_thread"] == alice
    assert results["run_in_executor"] is None, (
        "run_in_executor now propagates the context — update the documented "
        "boundary matrix in obsvr/subject.py to match"
    )
    assert results["executor_submit"] is None, (
        "ThreadPoolExecutor.submit now propagates the context — update the "
        "documented boundary matrix in obsvr/subject.py to match"
    )
    assert results["thread"] is None, (
        "threading.Thread now propagates the context — update the documented "
        "boundary matrix in obsvr/subject.py to match"
    )


# ── Attribution and enforcement through one governed tool ────────────────────


class _RunShapedTool:
    name = "send_money"
    description = "moves money"

    def __init__(self):
        self.calls = []

    def _run(self, amount: int = 0):
        self.calls.append(amount)
        return f"sent {amount}"


@pytest.fixture
def sent(monkeypatch):
    from obsvr import sender

    captured = []
    monkeypatch.setattr(
        sender, "send_audit_async", lambda config, event: captured.append(event)
    )
    return captured


@pytest.fixture(autouse=True)
def _fresh_governed_names(monkeypatch):
    from obsvr.integrations import tools as tools_mod

    monkeypatch.setattr(tools_mod, "_GOVERNED_TOOL_NAMES", set())


def test_two_ambient_subjects_attribute_and_meter_separately(sent):
    """Guard ONCE, attribute per request: the same governed tool object,
    driven under two ambient subjects, yields two different user_ids on the
    signed events and meters two different quota buckets — and the second
    call by the same subject is refused out of that subject's own bucket."""
    from obsvr.rules import PolicyRule, _quota_store, _reset_quota
    from obsvr.session_taint import (
        _reset_session_taint,
        derive_session_key,
        mark_tainted,
    )

    _reset_quota()
    _reset_session_taint()
    try:
        obsvr.init(
            api_key="test",
            sample_rate=1,
            policy_rules=[
                PolicyRule(
                    id="q1", name="user-quota", enabled=True, action="block",
                    type="quota",
                    conditions={
                        "quota_limit": 1, "quota_window_ms": 60000,
                        "quota_scope": "user_id",
                    },
                )
            ],
            session_taint={"enabled": True, "action": "block"},
        )
        # Arm the pre-call net without touching the subjects under test.
        mark_tainted(
            derive_session_key({"user_id": "someone-else"}), "prompt_injection", 1.0
        )

        tool = _RunShapedTool()
        governed = govern_tool(tool)  # guarded once, with no identity of its own

        with use_subject("user:alice"):
            assert governed._run(amount=1) == "sent 1"
        with use_subject("user:bob"):
            assert governed._run(amount=2) == "sent 2"
        with use_subject("user:alice"):
            with pytest.raises(ObsvrPolicyError):
                governed._run(amount=3)

        assert tool.calls == [1, 2], "the spent subject's call still ran"
        assert "user_id:alice" in _quota_store
        assert "user_id:bob" in _quota_store
        assert "user_id:default" not in _quota_store, (
            "an ambient subject was metered into the shared bucket"
        )

        calls = [e for e in sent if e.get("operation") == "tool.call"]
        assert [e.get("user_id") for e in calls] == ["alice", "bob", "alice"]
        blocked = [e for e in sent if e.get("action_taken") == "blocked"]
        assert blocked and blocked[-1].get("user_id") == "alice"
    finally:
        _reset_session_taint()
        _reset_quota()


def test_an_explicit_user_id_wins_over_the_ambient_subject(sent):
    """Precedence twin of TS `options.user_id || ambientSubject?.user_id`:
    an identity stated on the wrapper is never overridden by the scope the
    call happens to run in."""
    obsvr.init(api_key="test", sample_rate=1)
    tool = _RunShapedTool()
    governed = govern_tool(tool, user_id="carol")

    with use_subject("user:alice"):
        assert governed._run(amount=1) == "sent 1"

    calls = [e for e in sent if e.get("operation") == "tool.call"]
    assert calls and calls[-1].get("user_id") == "carol"


def test_no_ambient_scope_leaves_the_closure_behaviour_unchanged(sent):
    """Outside any use_subject scope the event carries exactly what it
    carried before this feature existed: the wrap-time identity, or none."""
    obsvr.init(api_key="test", sample_rate=1)
    tool = _RunShapedTool()
    governed = govern_tool(tool)
    assert governed._run(amount=1) == "sent 1"
    calls = [e for e in sent if e.get("operation") == "tool.call"]
    assert calls and calls[-1].get("user_id") is None
