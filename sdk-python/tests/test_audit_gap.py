"""Dropped events must leave a trace in the signed chain.

The behavior this file pins is the one that used to be invisible. Overflow
drops happen BEFORE a sequence number is assigned - this SDK even rolls the
chain head back on a losing race - so the events that survived a saturated
burst formed a contiguous, perfectly verifiable chain, and the record said
nothing was missing while most of the burst was. The sender now signs a gap
marker at the drop point, and the assertions below are about the two things
that make that marker evidence rather than a log line: it is IN the chain
(chained, signed, verifiable), and its count is INSIDE the signature preimage,
so editing the count breaks verification.

Twin: sdk/tests/unit/audit-gap.test.ts.
"""

import pytest

from obsvr import sender
from obsvr.audit_gap import AUDIT_GAP_METADATA_KEY, parse_audit_gap_prompt
from obsvr.config import ResolvedConfig
from obsvr.verify_chain import verify_chain

API_KEY = "test-key"


@pytest.fixture(autouse=True)
def _quiet_sender(monkeypatch):
    """No worker thread and no OTel: the queue fills and stays full, which is
    the overflow condition, and nothing drains it behind the test's back."""
    sender._reset_sender()
    monkeypatch.setattr(sender, "_ensure_worker", lambda: None)
    monkeypatch.setattr(sender, "_mirror", lambda config, event: None)
    yield
    sender._reset_sender()


def _config():
    return ResolvedConfig(api_key=API_KEY, ingest_url="https://ingest.example.com")


def _event(name):
    return {
        "request_id": name,
        "region": "us-east-1",
        "provider": "openai",
        "model": "gpt-4o",
        "operation": "chat.completion",
        "source": "test",
        "prompt": f"prompt-{name}",
        "response": "response",
        "success": True,
        "event_type": "llm_call",
        "policy_version": "v1",
        "action_taken": "allowed",
        "action_reason": "none",
        "action_source": "builtin",
        "redacted_types": [],
    }


def _saturate(config, over_by):
    """Fill the bounded queue past its bound; returns how many it dropped."""
    for i in range(sender.MAX_QUEUE_SIZE + over_by):
        sender.send_audit_async(config, _event(f"e{i}"))
    return sender.get_sender_stats()["dropped_overflow"]


def _drain():
    """Take everything the sender queued, in chain order, as the worker would."""
    drained = []
    while True:
        try:
            drained.append(sender._queue.get_nowait()[1])
            sender._queue.task_done()
        except Exception:
            return drained


def test_overflow_drop_is_an_undeclared_gap_until_a_marker_carries_it():
    dropped = _saturate(_config(), 40)

    assert dropped > 0
    assert sender.get_queue_size() == sender.MAX_QUEUE_SIZE
    # Counted but NOT yet on the record: this is the window the marker exists
    # to close, and a process that dies here still loses them.
    assert sender.get_pending_gap_count() == dropped
    assert sender.get_sender_stats()["gap_markers"] == 0


def test_one_marker_declares_the_whole_burst_on_the_next_enqueue():
    config = _config()
    dropped = _saturate(config, 40)
    chain = _drain()

    sender.send_audit_async(config, _event("after-the-gap"))
    chain += _drain()

    assert sender.get_pending_gap_count() == 0
    stats = sender.get_sender_stats()
    assert stats["gap_markers"] == 1
    assert stats["gap_events_declared"] == dropped

    # One marker for the burst, not one per dropped event.
    markers = [e for e in chain if parse_audit_gap_prompt(e.get("prompt"))]
    assert len(markers) == 1
    assert parse_audit_gap_prompt(markers[0]["prompt"]) == {
        "dropped": dropped,
        "reason": "queue_overflow",
    }
    assert markers[0]["operation"] == "audit.gap"


def test_marker_sits_between_the_last_survivor_and_the_first_event_after_the_loss():
    config = _config()
    _saturate(config, 5)
    chain = _drain()
    sender.send_audit_async(config, _event("after-the-gap"))
    chain += _drain()

    at = next(i for i, e in enumerate(chain) if parse_audit_gap_prompt(e.get("prompt")))
    assert at > 0
    assert chain[at + 1]["request_id"] == "after-the-gap"
    # Contiguous with both neighbours: the marker occupies the chain position
    # the loss happened at, it is not appended somewhere convenient.
    assert chain[at]["seq_no"] == chain[at - 1]["seq_no"] + 1
    assert chain[at + 1]["seq_no"] == chain[at]["seq_no"] + 1
    assert chain[at]["prev_sig"] == chain[at - 1]["sdk_sig"]
    assert chain[at + 1]["prev_sig"] == chain[at]["sdk_sig"]


def test_chain_verifies_and_reports_what_it_is_missing():
    config = _config()
    dropped = _saturate(config, 123)
    chain = _drain()
    sender.send_audit_async(config, _event("after-the-gap"))
    chain += _drain()

    result = verify_chain(chain, API_KEY)
    assert result.valid is True
    assert result.events_verified == len(chain)
    # The half that used to be missing: valid, and openly short by `dropped`.
    assert result.gap_markers == 1
    assert result.events_declared_lost == dropped


def test_editing_the_declared_count_breaks_verification():
    config = _config()
    _saturate(config, 9)
    chain = _drain()
    sender.send_audit_async(config, _event("after-the-gap"))
    chain += _drain()

    at = next(i for i, e in enumerate(chain) if parse_audit_gap_prompt(e.get("prompt")))
    # Rewriting the loss down to 1 is exactly the tamper the signature exists
    # to catch, and it is only caught because the count is in the preimage.
    chain[at]["prompt"] = "obsvr:audit-gap/1 dropped=1 reason=queue_overflow"

    result = verify_chain(chain, API_KEY)
    assert result.valid is False
    assert result.broken_at == at
    assert result.reason == f"Signature mismatch at event {at}"


def test_flush_declares_an_outstanding_gap_rather_than_losing_it_with_the_process():
    config = _config()
    dropped = _saturate(config, 7)
    assert sender.get_pending_gap_count() == dropped

    # No further enqueue: only the flush stands between the drops and oblivion,
    # and it runs against a FULL queue - the case the capacity rule would
    # otherwise refuse.
    sender.flush(timeout=0.05)

    assert sender.get_pending_gap_count() == 0
    assert sender.get_sender_stats()["gap_markers"] == 1
    chain = _drain()
    marker = next(e for e in chain if parse_audit_gap_prompt(e.get("prompt")))
    assert parse_audit_gap_prompt(marker["prompt"]) == {
        "dropped": dropped,
        "reason": "queue_overflow",
    }


def test_no_marker_when_nothing_was_dropped():
    config = _config()
    for i in range(10):
        sender.send_audit_async(config, _event(f"e{i}"))
    chain = _drain()

    assert sender.get_sender_stats()["gap_markers"] == 0
    assert [e for e in chain if parse_audit_gap_prompt(e.get("prompt"))] == []
    result = verify_chain(chain, API_KEY)
    assert result.valid is True
    assert result.events_declared_lost == 0


def test_marker_carries_a_structured_copy_of_the_claim_in_reserved_metadata():
    config = _config()
    dropped = _saturate(config, 3)
    sender.flush(timeout=0.05)
    chain = _drain()

    marker = next(e for e in chain if parse_audit_gap_prompt(e.get("prompt")))
    assert marker["metadata"][AUDIT_GAP_METADATA_KEY] == {
        "dropped": dropped,
        "reason": "queue_overflow",
    }
    assert marker["metadata"]["governance_event"] == "audit_gap"
    assert marker["event_type"] == "policy_flag"
    assert marker["policy_version"] == "none"


def test_an_ordinary_prompt_cannot_mint_a_loss_claim():
    # Without this, any caller could fabricate a declared gap by sending a
    # prompt that quotes the format.
    assert parse_audit_gap_prompt("note: obsvr:audit-gap/1 dropped=99 reason=queue_overflow") is None
    assert parse_audit_gap_prompt("obsvr:audit-gap/1 dropped=99 reason=queue_overflow extra") is None
    assert parse_audit_gap_prompt("summarize this") is None
    assert parse_audit_gap_prompt(None) is None
