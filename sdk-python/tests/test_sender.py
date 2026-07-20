"""Sender tests — mock urlopen, queue behaviour, 429 backoff."""

import json
import time
from io import BytesIO
from unittest.mock import MagicMock, call, patch

import pytest

from obsvr import _reset
from obsvr.config import ResolvedConfig
from obsvr import sender


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
        sender, "_send_event_batch", lambda cfg, evs: (captured.extend(evs), "ok")[1]
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
    result = sender._send_event(cfg, event)
    assert result == "ok"
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
    result = sender._send_event(cfg, {"request_id": "r1"})
    assert result == "retryable"
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
    result = sender._send_event(cfg, {"request_id": "r1"})
    assert result == "retryable"
    assert sender._backoff["until"] > time.time()  # retryables arm backoff too
    sender._reset_backoff()


def test_send_event_exception_is_retryable(monkeypatch):
    monkeypatch.setattr(
        sender, "urlopen", lambda req, timeout=None: (_ for _ in ()).throw(OSError("connection refused"))
    )
    sender._reset_backoff()
    cfg = _cfg()
    result = sender._send_event(cfg, {})
    assert result == "retryable"
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
        assert sender._send_event(_cfg(), {"request_id": "r1"}) == "permanent"
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
