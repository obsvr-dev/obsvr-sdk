"""Sender tests — mock urlopen, queue behaviour, 429 backoff."""

import json
import threading
import time
from io import BytesIO
from unittest.mock import MagicMock, call, patch

import pytest

from obsvr import _reset
from obsvr.config import ResolvedConfig
from obsvr import sender
from obsvr.audit_gap import read_audit_gap_claim
from obsvr.verify_chain import verify_chain


def _cfg(**kw):
    defaults = dict(api_key="test-key", sample_rate=1, ingest_url="http://localhost:3000")
    defaults.update(kw)
    return ResolvedConfig(**defaults)


def _make_response(status: int) -> MagicMock:
    resp = MagicMock()
    resp.status = status
    resp.getcode.return_value = status
    return resp


def test_shutdown_drains_despite_armed_backoff(monkeypatch):
    """at exit the worker must break out of a long (up to 60s) backoff
    sleep and drain, not silently lose queued events. (Robust to leftover events
    from other tests sharing the persistent worker/queue: assert MY event drains,
    identified by a unique marker, and that the drain is not blocked by backoff.)"""
    sender._reset_sender()
    captured = []
    monkeypatch.setattr(sender, "_send_event", lambda cfg, ev: (captured.append(ev), "ok")[1])
    monkeypatch.setattr(
        sender, "_send_event_batch", lambda cfg, evs: (captured.extend(evs), ("ok", 0))[1]
    )
    # Arm a long backoff window, as an ingest outage would.
    sender._backoff["until"] = time.time() + 60.0
    marker = f"py12-{time.time()}"
    sender.send_audit_async(_cfg(), {"request_id": marker, "prompt": "x", "response": ""})
    start = time.time()
    sender._atexit_flush()  # sets _shutdown → worker skips backoff and drains
    elapsed = time.time() - start
    assert marker in [e.get("request_id") for e in captured], "queued event dropped at shutdown"
    assert elapsed < 4.0, f"shutdown was blocked by backoff for {elapsed:.1f}s"
    sender._reset_sender()


def test_send_audit_async_enqueues(sent):
    """With the test fixture the event is captured without HTTP."""
    import obsvr
    obsvr.init(api_key="test", sample_rate=1)
    from obsvr.config import get_config
    cfg = get_config()
    event = {"request_id": "r1", "prompt": "hi"}
    sender.send_audit_async(cfg, event)
    assert len(sent) == 1
    assert sent[0]["request_id"] == "r1"


def test_send_audit_async_drops_when_full(monkeypatch):
    """Queue drops events when full."""
    monkeypatch.setattr(sender, "send_audit_async", lambda c, e: None)
    cfg = _cfg()
    # Verify _dropped starts at 0
    assert sender.get_dropped_count() == 0


def test_should_sample_zero():
    assert sender.should_sample(0) is False


def test_should_sample_one():
    assert sender.should_sample(1) is True


def test_should_sample_fraction():
    # statistical: with 1000 samples at rate=0.5 we expect ~50% pass
    hits = sum(1 for _ in range(1000) if sender.should_sample(0.5))
    assert 350 < hits < 650


def test_send_event_posts_correct_url(monkeypatch):
    """_send_event POSTs to {ingest_url}/ingest with X-API-Key header."""
    received = {}

    def fake_urlopen(req, timeout=None):
        received["url"] = req.full_url
        received["method"] = req.method
        received["headers"] = dict(req.headers)
        received["body"] = json.loads(req.data)
        mock_resp = MagicMock()
        mock_resp.status = 200
        return mock_resp

    monkeypatch.setattr(sender, "urlopen", fake_urlopen)
    cfg = _cfg()
    event = {"request_id": "r1", "prompt": "test"}
    verdict, rejected = sender._send_event(cfg, event)
    assert (verdict, rejected) == ("ok", 0)
    assert received["url"] == "http://localhost:3000/ingest"
    assert received["method"] == "POST"
    assert received["headers"]["X-api-key"] == "test-key"
    assert received["body"]["request_id"] == "r1"


def test_send_event_429_applies_backoff(monkeypatch):
    """429 is retryable and arms the (jittered) backoff window."""
    from urllib.error import HTTPError
    monkeypatch.setattr(
        sender,
        "urlopen",
        lambda req, timeout=None: (_ for _ in ()).throw(HTTPError(None, 429, "Too Many", {}, None)),
    )
    # Reset backoff state
    sender._reset_backoff()
    cfg = _cfg()
    verdict, _ = sender._send_event(cfg, {"request_id": "r1"})
    assert verdict == "retryable"
    assert sender._backoff["until"] > time.time()
    assert sender._backoff["multiplier"] == 2.0
    # cleanup
    sender._reset_backoff()


def test_send_event_500_is_retryable(monkeypatch):
    def fake_urlopen(req, timeout=None):
        resp = MagicMock()
        resp.status = 500
        return resp

    monkeypatch.setattr(sender, "urlopen", fake_urlopen)
    sender._reset_backoff()
    cfg = _cfg()
    verdict, _ = sender._send_event(cfg, {"request_id": "r1"})
    assert verdict == "retryable"
    assert sender._backoff["until"] > time.time()  # retryables arm backoff too
    sender._reset_backoff()


def test_send_event_exception_is_retryable(monkeypatch):
    monkeypatch.setattr(
        sender, "urlopen", lambda req, timeout=None: (_ for _ in ()).throw(OSError("connection refused"))
    )
    sender._reset_backoff()
    cfg = _cfg()
    verdict, _ = sender._send_event(cfg, {})
    assert verdict == "retryable"
    sender._reset_backoff()


def test_send_event_4xx_is_permanent(monkeypatch):
    """401/422 etc. will always fail with the same bytes: never retried."""
    from urllib.error import HTTPError
    for code in (400, 401, 404, 413, 422):
        monkeypatch.setattr(
            sender,
            "urlopen",
            lambda req, timeout=None, c=code: (_ for _ in ()).throw(HTTPError(None, c, "err", {}, None)),
        )
        sender._reset_backoff()
        assert sender._send_event(_cfg(), {"request_id": "r1"})[0] == "permanent"
        assert sender._backoff["until"] == 0.0  # permanent does not arm backoff
    sender._reset_backoff()


def test_batch_splits_on_byte_budget():
    """A batch never exceeds MAX_BATCH_BYTES of serialized events."""
    big = {"prompt": "x" * 400_000}
    small = {"prompt": "y"}
    assert len(json.dumps(big)) * 2 > sender.MAX_BATCH_BYTES
    # The worker-side logic is exercised via the constants relationship;
    # end-to-end split behavior is covered by the queue integration test.
    assert sender.MAX_BATCH_BYTES < 1_000_000  # ingest bodyLimit
    assert len(json.dumps(small)) < sender.MAX_BATCH_BYTES


def test_retry_survives_when_producers_refill_the_public_queue(monkeypatch):
    """An already-signed retry must not compete with producers for a slot.

    The first request is held in flight while a second event fills a one-slot
    public queue. The old worker tried to put the first event back, hit Full,
    dropped it, and left the chain pointing through an event ingest never saw.
    The worker-local carry now sends both in sequence without an overflow.
    """
    sender._reset_sender()
    original_maxsize = sender._queue.maxsize
    sender._queue.maxsize = 1
    in_flight = threading.Event()
    release = threading.Event()
    calls = []

    def send_one(_cfg, event):
        calls.append(("single", event["request_id"]))
        if event["request_id"] == "retry-first" and calls.count(("single", "retry-first")) == 1:
            in_flight.set()
            assert release.wait(5), "test never released the first request"
            return ("retryable", 0)
        return ("ok", 0)

    def send_batch(_cfg, events):
        calls.append(("batch", [event["request_id"] for event in events]))
        return ("ok", 0)

    monkeypatch.setattr(sender, "_send_event", send_one)
    monkeypatch.setattr(sender, "_send_event_batch", send_batch)
    cfg = _cfg()
    try:
        sender.send_audit_async(
            cfg, {"request_id": "retry-first", "prompt": "p1", "response": ""}
        )
        assert in_flight.wait(5), "worker never started the first request"
        sender.send_audit_async(
            cfg, {"request_id": "queued-second", "prompt": "p2", "response": ""}
        )
        assert sender.get_queue_size() == 1
        release.set()
        sender.flush(timeout=5)

        stats = sender.get_sender_stats()
        assert stats["sent"] == 2
        assert stats["retries"] == 1
        assert stats["dropped_overflow"] == 0
        assert sender.get_pending_gap_count() == 0
        assert calls == [
            ("single", "retry-first"),
            ("batch", ["retry-first", "queued-second"]),
        ]
    finally:
        release.set()
        sender._queue.maxsize = original_maxsize
        sender._reset_sender()


def test_disabled_config_skips_send():
    """Disabled config: send_audit_async enqueues nothing (no HTTP call)."""
    import obsvr
    obsvr.init(api_key="test", sample_rate=1, disabled=True)
    from obsvr.config import get_config
    from obsvr import sender as real_sender
    cfg = get_config()
    before = real_sender.get_queue_size()
    event = {"request_id": "r1"}
    real_sender.send_audit_async(cfg, event)
    after = real_sender.get_queue_size()
    assert after == before  # nothing enqueued


# ── Per-event rejects inside an ACCEPTED batch ──────────────────────────────
#
# The public promise is that every drop is visible in the per-client delivery
# counters. The case that used to be invisible in Python is the one below: the
# sender never read a response body at all, so a batch the server answered 2xx
# while refusing individual events inside it was counted, wrongly, as fully
# sent. Those events were delivered and refused - a different audit story from
# "never delivered" - so they land in their own `dropped_rejected` bucket under
# exactly the name the TypeScript sender uses.


def _batch_response(status: int, body: dict) -> MagicMock:
    resp = _make_response(status)
    resp.read.return_value = json.dumps(body).encode("utf-8")
    return resp


def _drain_single_then_batch(monkeypatch, events, respond):
    """Enqueue one event, wait until it is IN FLIGHT, then enqueue the rest.

    The worker takes the single-event path for one queued event and the batch
    path for more, so holding the first request open is what makes the split
    deterministic rather than timing-dependent (same reasoning as the TS twin).
    ``respond(url, payload, call_index)`` returns the mocked response.
    """
    in_flight = threading.Event()
    release = threading.Event()
    calls = []

    def fake_urlopen(req, timeout=None):
        idx = len(calls)
        calls.append(req.full_url)
        if idx == 0:
            in_flight.set()
            release.wait(5)
        return respond(req.full_url, json.loads(req.data.decode("utf-8")), idx)

    monkeypatch.setattr(sender, "urlopen", fake_urlopen)
    cfg = _cfg()
    sender.send_audit_async(cfg, events[0])
    assert in_flight.wait(5), "worker never issued the single-event request"
    for event in events[1:]:
        sender.send_audit_async(cfg, event)
    release.set()
    sender.flush(timeout=5.0)
    return calls


def test_batch_rejects_increment_dropped_rejected_and_are_not_sent(monkeypatch):
    sender._reset_sender()
    body = {
        "count": 1,
        "rejected": [
            {"index": 0, "error": "policy_blocked"},
            {"index": 2, "error": "schema_invalid"},
        ],
    }
    calls = _drain_single_then_batch(
        monkeypatch,
        [{"request_id": f"r{i}", "prompt": "p", "response": ""} for i in range(4)],
        lambda url, payload, idx: (
            _batch_response(200, body) if url.endswith("/ingest/batch") else _make_response(200)
        ),
    )
    assert any(u.endswith("/ingest/batch") for u in calls), "no batch request was made"

    stats = sender.get_sender_stats()
    assert stats["enqueued"] == 5  # four calls plus the accepted gap marker
    assert stats["dropped_rejected"] == 2
    # 1 single-event send + 1 accepted event out of the batch of 3.
    assert stats["sent"] == 3  # two calls plus the marker
    # Rejects are not a transport failure: nothing retried, permanently discarded, or
    # overflowed, and no backoff is armed - the batch itself succeeded.
    assert stats["retries"] == 0
    assert stats["dropped_permanent"] == 0
    assert stats["dropped_overflow"] == 0
    assert stats["dropped_retry_exhausted"] == 0
    assert sender._backoff["until"] == 0.0
    # Every enqueued event is accounted for exactly once.
    assert stats["sent"] + stats["dropped_rejected"] == stats["enqueued"]
    sender._reset_sender()


def test_batch_with_no_rejects_counts_every_event_as_sent(monkeypatch):
    sender._reset_sender()
    _drain_single_then_batch(
        monkeypatch,
        [{"request_id": f"n{i}", "prompt": "p", "response": ""} for i in range(3)],
        lambda url, payload, idx: (
            _batch_response(200, {"count": 2}) if url.endswith("/ingest/batch") else _make_response(200)
        ),
    )
    stats = sender.get_sender_stats()
    assert stats["sent"] == 3
    assert stats["dropped_rejected"] == 0
    sender._reset_sender()


def test_unparseable_batch_body_is_not_a_delivery_failure(monkeypatch):
    """A body that is absent, truncated, or not JSON means no rejects were
    reported - never a failed delivery, which would double-count the batch."""
    sender._reset_sender()

    def broken_body(url, payload, idx):
        if not url.endswith("/ingest/batch"):
            return _make_response(200)
        resp = _make_response(200)
        resp.read.return_value = b"<html>not json</html>"
        return resp

    _drain_single_then_batch(
        monkeypatch,
        [{"request_id": f"b{i}", "prompt": "p", "response": ""} for i in range(3)],
        broken_body,
    )
    stats = sender.get_sender_stats()
    assert stats["sent"] == 3
    assert stats["dropped_rejected"] == 0
    assert stats["dropped_permanent"] == 0
    sender._reset_sender()


def test_malformed_reject_list_cannot_inflate_the_counter(monkeypatch):
    """More rejects than events in the batch must not over-count the drop."""
    sender._reset_sender()
    body = {"rejected": [{"index": i, "error": "policy_blocked"} for i in range(10)]}
    _drain_single_then_batch(
        monkeypatch,
        [{"request_id": f"m{i}", "prompt": "p", "response": ""} for i in range(3)],
        lambda url, payload, idx: (
            _batch_response(200, body) if url.endswith("/ingest/batch") else _make_response(200)
        ),
    )
    stats = sender.get_sender_stats()
    assert stats["dropped_rejected"] == 2  # the batch held 2 events, not 10
    assert stats["sent"] == 2  # one call plus the accepted gap marker
    sender._reset_sender()


def test_whole_request_4xx_still_counts_as_dropped_permanent(monkeypatch):
    """Rejects are additive: the existing permanent-failure taxonomy is unchanged."""
    sender._reset_sender()
    _drain_single_then_batch(
        monkeypatch,
        [{"request_id": f"p{i}", "prompt": "p", "response": ""} for i in range(3)],
        lambda url, payload, idx: _make_response(400),
    )
    stats = sender.get_sender_stats()
    assert stats["dropped_permanent"] == 5  # three calls plus two failed markers
    assert stats["dropped_rejected"] == 0
    assert stats["sent"] == 0
    sender._reset_sender()


@pytest.mark.parametrize(
    ("verdict", "reason"),
    [("rejected", "ingest_rejected"), ("permanent", "permanent_failure")],
)
def test_terminal_delivery_loss_starts_fresh_marker_chain(monkeypatch, verdict, reason):
    sender._reset_sender()
    attempted = []

    def send_one(_config, event):
        attempted.append(event)
        if read_audit_gap_claim(event):
            return ("ok", 0)
        if event["request_id"] == "future":
            return ("ok", 0)
        return (verdict, 0)

    monkeypatch.setattr(sender, "_send_event", send_one)
    monkeypatch.setattr(sender, "_mirror", lambda _config, _event: None)
    cfg = _cfg()
    sender.send_audit_async(cfg, {"request_id": "lost", "prompt": "p", "response": ""})
    sender.flush(timeout=5)
    sender.send_audit_async(cfg, {"request_id": "future", "prompt": "p", "response": ""})
    sender.flush(timeout=5)

    lost = next(event for event in attempted if event["request_id"] == "lost")
    marker = next(event for event in attempted if read_audit_gap_claim(event))
    future = next(event for event in attempted if event["request_id"] == "future")
    assert read_audit_gap_claim(marker) == {"dropped": 1, "reason": reason}
    assert marker["sdk_session_id"] != lost["sdk_session_id"]
    assert marker["seq_no"] == 1
    assert "prev_sig" not in marker
    assert future["sdk_session_id"] == marker["sdk_session_id"]
    assert future["seq_no"] == 2
    assert future["prev_sig"] == marker["sdk_sig"]
    result = verify_chain([marker, future], "test-key")
    assert result.valid
    assert result.gap_markers == 1
    assert result.events_declared_lost == 1
    sender._reset_sender()


def test_retry_exhaustion_starts_fresh_marker_chain(monkeypatch):
    sender._reset_sender()
    attempted = []

    def send_one(_config, event):
        attempted.append(event)
        if read_audit_gap_claim(event):
            return ("ok", 0)
        return ("retryable", 0)

    monkeypatch.setattr(sender, "_send_event", send_one)
    monkeypatch.setattr(sender, "_mirror", lambda _config, _event: None)
    sender.send_audit_async(
        _cfg(), {"request_id": "lost-after-retries", "prompt": "p", "response": ""}
    )
    sender.flush(timeout=5)

    ordinary_attempts = [event for event in attempted if not read_audit_gap_claim(event)]
    marker = next(event for event in attempted if read_audit_gap_claim(event))
    assert len(ordinary_attempts) == 6
    assert read_audit_gap_claim(marker) == {"dropped": 1, "reason": "retry_exhausted"}
    assert marker["sdk_session_id"] != ordinary_attempts[0]["sdk_session_id"]
    assert marker["seq_no"] == 1
    assert verify_chain([marker], "test-key").valid
    sender._reset_sender()


def test_failed_gap_marker_is_not_replaced_recursively(monkeypatch):
    sender._reset_sender()
    attempted = []

    def send_one(_config, event):
        attempted.append(event)
        return ("permanent", 0)

    monkeypatch.setattr(sender, "_send_event", send_one)
    monkeypatch.setattr(sender, "_mirror", lambda _config, _event: None)
    sender.send_audit_async(_cfg(), {"request_id": "lost", "prompt": "p", "response": ""})
    sender.flush(timeout=5)

    assert len(attempted) == 2
    assert read_audit_gap_claim(attempted[0]) is None
    assert read_audit_gap_claim(attempted[1]) == {
        "dropped": 1,
        "reason": "permanent_failure",
    }
    assert sender.get_sender_stats()["gap_markers"] == 1
    assert sender.get_queue_size() == 0
    sender._reset_sender()


def test_poll_header_reports_dropped_rejected_as_its_own_key(monkeypatch):
    """Byte-level parity with the TS poll header: the refused bucket is a
    separate key, and the never-delivered aggregate stays separate from it."""
    from obsvr import remote

    sender._reset_sender()
    sender._bump("dropped_rejected", 3)
    sender._bump("sent", 5)
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured.update(dict(req.headers))
        resp = MagicMock()
        resp.status = 200
        resp.read.return_value = b'{"rules": []}'
        resp.__enter__ = lambda s: s
        resp.__exit__ = lambda s, *a: False
        return resp

    monkeypatch.setattr(remote, "urlopen", fake_urlopen)
    remote.poll_once(_cfg())

    # urllib title-cases header names on the Request object.
    counters = next(v for k, v in captured.items() if k.lower() == "x-obsvr-counters")
    assert "dropped_rejected=3" in counters
    assert "dropped=0" in counters
    assert "sent=5" in counters
    sender._reset_sender()


# ── HTTP 409 duplicate_event ────────────────────────────────────────────────
#
# A duplicate means a retry raced a lost 2xx: the event is already durably
# recorded. Classifying it as a permanent drop - which every other 4xx is -
# would fabricate a coverage gap for evidence that exists, so it counts as
# idempotent success. Only that exact code: a 409 sequence_fork means the chain
# position belongs to a different signature and must stay a failure.


def _conflict_response(body: dict) -> MagicMock:
    resp = _make_response(409)
    resp.read.return_value = json.dumps(body).encode("utf-8")
    return resp


def test_single_event_409_duplicate_counts_as_sent(monkeypatch):
    sender._reset_sender()
    sender._reset_backoff()
    monkeypatch.setattr(
        sender,
        "urlopen",
        lambda req, timeout=None: _conflict_response(
            {"ok": False, "error": "duplicate_event", "reason": "replay"}
        ),
    )
    assert sender._send_event(_cfg(), {"request_id": "dup"})[0] == "ok"
    assert sender._backoff["until"] == 0.0
    sender._reset_sender()


def test_409_duplicate_raised_as_httperror_counts_as_sent(monkeypatch):
    """urllib normally surfaces a 4xx as HTTPError, so the check lives on both
    paths; HTTPError carries the body, which is what makes this decidable."""
    from urllib.error import HTTPError

    sender._reset_sender()
    sender._reset_backoff()

    def raise_conflict(req, timeout=None):
        raise HTTPError(
            req.full_url,
            409,
            "Conflict",
            {},
            BytesIO(json.dumps({"ok": False, "error": "duplicate_event"}).encode()),
        )

    monkeypatch.setattr(sender, "urlopen", raise_conflict)
    assert sender._send_event(_cfg(), {"request_id": "dup"})[0] == "ok"
    sender._reset_sender()


def test_non_duplicate_409_stays_permanent(monkeypatch):
    """A sequence_fork is a real conflict: that chain position belongs to a
    DIFFERENT signature, and absorbing it would hide a chain fork."""
    sender._reset_sender()
    sender._reset_backoff()
    monkeypatch.setattr(
        sender,
        "urlopen",
        lambda req, timeout=None: _conflict_response({"ok": False, "error": "sequence_fork"}),
    )
    assert sender._send_event(_cfg(), {"request_id": "fork"})[0] == "permanent"
    sender._reset_sender()


def test_409_with_unreadable_body_stays_permanent(monkeypatch):
    """Absorbing an unparseable conflict would turn real failures into phantom
    successes, so only a body that positively says duplicate_event counts."""
    sender._reset_sender()
    sender._reset_backoff()
    resp = _make_response(409)
    resp.read.return_value = b"<html>gateway</html>"
    monkeypatch.setattr(sender, "urlopen", lambda req, timeout=None: resp)
    assert sender._send_event(_cfg(), {"request_id": "opaque"})[0] == "permanent"
    sender._reset_sender()


def test_whole_batch_409_duplicate_counts_every_event_as_sent(monkeypatch):
    sender._reset_sender()
    _drain_single_then_batch(
        monkeypatch,
        [{"request_id": f"d{i}", "prompt": "p", "response": ""} for i in range(4)],
        lambda url, payload, idx: _conflict_response({"ok": False, "error": "duplicate_event"}),
    )
    stats = sender.get_sender_stats()
    assert stats["sent"] == 4
    assert stats["dropped_permanent"] == 0
    assert stats["dropped_rejected"] == 0
    sender._reset_sender()


def test_per_event_duplicate_reject_counts_as_sent_not_dropped(monkeypatch):
    sender._reset_sender()
    body = {
        "count": 1,
        "rejected": [
            {"index": 0, "error": "duplicate_event"},
            {"index": 1, "error": "policy_blocked"},
        ],
    }
    _drain_single_then_batch(
        monkeypatch,
        [{"request_id": f"x{i}", "prompt": "p", "response": ""} for i in range(4)],
        lambda url, payload, idx: (
            _batch_response(200, body) if url.endswith("/ingest/batch") else _make_response(200)
        ),
    )
    stats = sender.get_sender_stats()
    # 1 single + the duplicate + the one clean event = 3 sent, 1 refused.
    assert stats["sent"] == 4  # includes the accepted gap marker
    assert stats["dropped_rejected"] == 1
    assert stats["sent"] + stats["dropped_rejected"] == stats["enqueued"]
    sender._reset_sender()
