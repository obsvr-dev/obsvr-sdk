"""The audit chain does not fork across os.fork().

``_sdk_session_id`` and ``_seq_no`` are module state and ``fork()`` copies module
state, so a pre-forking application server -- the recommended deployment --
gave every worker the SAME session id and a sequence continuing from wherever
the parent had reached. N workers, N divergent chains, one claimed session.
Ingest already detects that shape as ``sequence_fork``; the detection existed and
the prevention did not.

These tests ACTUALLY FORK. Asserting that a handler is registered proves nothing
about what happens when it fires, and the registration is the easy half.

The invariant graded is the PAIR ``(session_id, seq_no)``, not the number. A
seq_no is only meaningful inside a session, so two children both starting at 1
is correct once their session ids differ; what must never happen is two events
sharing one pair.

These tests emit ``DeprecationWarning: this process is multi-threaded, use of
fork() may lead to deadlocks in the child``. That is EXPECTED and it is the
hazard under test rather than noise: the sender runs a daemon worker thread, so
any application that forks after an SDK call forks a multi-threaded process, and
a lock another thread held at that instant would be held forever in the child.
That is why the fork handler rebuilds the locks rather than only re-seeding the
session id.
"""
import json
import os
import sys

import pytest

import obsvr
from obsvr import sender


pytestmark = pytest.mark.skipif(
    not hasattr(os, "register_at_fork") or sys.platform == "win32",
    reason="fork() and register_at_fork are POSIX-only",
)


def _sign(tag, n=3):
    out = []
    for i in range(n):
        ev = {
            "request_id": f"{tag}-{i}",
            "prompt": "p",
            "response": "r",
            "operation": "chat.completions.create",
            "action_taken": "allowed",
        }
        sender.sign_event(ev, "test-api-key")
        out.append(ev)
    return out


def _fork_and_report(workers=2):
    """Fork `workers` children, each signing its own events, and collect them."""
    obsvr.init(
        api_key="test-api-key",
        ingest_url="http://127.0.0.1:9",  # closed: nothing is delivered
        policy_refresh_interval_s=0,
    )
    parent_events = _sign("parent", 2)
    parent = {
        "session_id": sender._sdk_session_id,
        "seq_nos": [e["seq_no"] for e in parent_events],
    }

    reports = []
    pipes = []
    for w in range(workers):
        r, wfd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(r)
            try:
                evs = _sign(f"child{w}", 3)
                payload = {
                    "session_id": sender._sdk_session_id,
                    "seq_nos": [e["seq_no"] for e in evs],
                    "chain_valid": bool(
                        getattr(obsvr.verify_chain(evs, "test-api-key"), "valid", False)
                    ),
                }
            except Exception as e:  # noqa: BLE001
                payload = {"error": f"{type(e).__name__}: {e}"}
            os.write(wfd, json.dumps(payload).encode())
            os.close(wfd)
            os._exit(0)
        os.close(wfd)
        pipes.append((pid, r))

    for pid, r in pipes:
        buf = b""
        while True:
            chunk = os.read(r, 65536)
            if not chunk:
                break
            buf += chunk
        os.close(r)
        os.waitpid(pid, 0)
        reports.append(json.loads(buf.decode()))

    return parent, reports


def test_each_forked_child_gets_its_own_session_id():
    parent, children = _fork_and_report()
    for c in children:
        assert "error" not in c, c
    ids = [c["session_id"] for c in children]
    assert len(set(ids)) == len(ids), "two children claimed the same session"
    assert parent["session_id"] not in ids, "a child inherited the parent's session"


def test_no_two_events_share_a_session_and_sequence():
    parent, children = _fork_and_report()
    pairs = [(parent["session_id"], s) for s in parent["seq_nos"]]
    for c in children:
        pairs += [(c["session_id"], s) for s in c["seq_nos"]]
    assert len(pairs) == len(set(pairs)), f"duplicate (session_id, seq_no): {pairs}"


def test_each_child_chain_verifies_independently():
    # A fresh session id is worthless if the chain it heads does not verify --
    # resetting the head without resetting the sequence would produce exactly
    # that, and would pass the two tests above.
    _parent, children = _fork_and_report()
    for c in children:
        assert c["chain_valid"] is True


def test_child_starts_a_new_chain_rather_than_continuing_the_parent():
    parent, children = _fork_and_report()
    # The parent reached seq 2. A child continuing it would start at 3.
    for c in children:
        assert min(c["seq_nos"]) == 1, "child continued the parent's sequence"
    assert max(parent["seq_nos"]) == 2


def test_the_parent_is_unaffected_by_the_fork():
    # Control: the whole point is to change the CHILD. A parent whose chain was
    # also reset would satisfy the tests above and be a worse bug.
    parent, _children = _fork_and_report()
    before = sender._sdk_session_id
    assert parent["session_id"] == before
    assert parent["seq_nos"] == [1, 2]
