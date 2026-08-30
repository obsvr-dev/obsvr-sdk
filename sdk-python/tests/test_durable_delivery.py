"""Durable audit outbox: persist before delivery, replay, and dead-letter."""

import threading

import pytest

from obsvr import durable_outbox, sender
from obsvr.config import ResolvedConfig


def _cfg(directory):
    return ResolvedConfig(
        api_key="test-key",
        ingest_url="http://localhost:3000",
        durable_delivery={
            "directory": str(directory),
            "max_bytes": 1024 * 1024,
            "fsync": True,
            "failure_mode": "error",
        },
    )


@pytest.fixture(autouse=True)
def _fresh_sender():
    sender._reset_sender()
    yield
    sender._reset_sender()


def test_persists_before_delivery_and_acknowledges_after_success(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path / "outbox")
    release = threading.Event()

    def delayed_success(_cfg, _event):
        release.wait(2)
        return "ok", 0

    monkeypatch.setattr(sender, "_send_event", delayed_success)
    sender.configure_durable_delivery(cfg)
    sender.send_audit_async(
        cfg, {"request_id": "durable-1", "prompt": "hello", "response": "world"}
    )

    assert len(list((tmp_path / "outbox" / "pending").glob("*.json"))) == 1
    assert sender.get_delivery_status()["durable"]["pending"] == 1

    release.set()
    sender.flush(2)
    assert list((tmp_path / "outbox" / "pending").glob("*.json")) == []
    assert sender.get_delivery_status()["durable"]["acknowledged"] == 1


def test_replays_a_record_from_a_previous_process(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path / "outbox")
    durable_outbox.configure(cfg.durable_delivery)
    event = {"request_id": "replay-1", "prompt": "p", "response": "r"}
    sender.sign_event(event, cfg.api_key)
    durable_outbox.persist(event)

    # Forget only process state. Caller-owned files remain on disk.
    durable_outbox.reset()
    monkeypatch.setattr(sender, "_send_event", lambda _cfg, _event: ("ok", 0))
    sender.configure_durable_delivery(cfg)
    sender.flush(2)

    assert list((tmp_path / "outbox" / "pending").glob("*.json")) == []
    status = sender.get_delivery_status()["durable"]
    assert status["replayed"] >= 1
    assert status["acknowledged"] == 1


def test_terminal_refusal_moves_event_and_gap_marker_to_dead_letters(
    tmp_path, monkeypatch
):
    cfg = _cfg(tmp_path / "outbox")
    monkeypatch.setattr(sender, "_send_event", lambda _cfg, _event: ("permanent", 0))
    sender.configure_durable_delivery(cfg)
    sender.send_audit_async(
        cfg, {"request_id": "dead-1", "prompt": "hello", "response": "world"}
    )
    sender.flush(2)

    assert list((tmp_path / "outbox" / "pending").glob("*.json")) == []
    assert len(list((tmp_path / "outbox" / "dead").glob("*.json"))) == 2
    assert sender.get_delivery_status()["durable"]["dead_letters"] == 2


def test_relative_directory_is_refused(tmp_path):
    del tmp_path
    cfg = _cfg("relative/outbox")
    with pytest.raises(ValueError, match="must be absolute"):
        sender.configure_durable_delivery(cfg)
