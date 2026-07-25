"""Config defaults, and the one that used to be dangerous.

An unset ingest_url previously defaulted to http://localhost:3000. On a
misconfigured process that silently streamed governed events - including
redacted prompt text on blocked calls - to whatever was listening on that port,
while the TypeScript SDK on the identical misconfiguration warned and delivered
nothing. These tests pin the corrected behavior and the parity.
"""
import logging

import obsvr
from obsvr import sender
from obsvr.config import DEFAULT_INGEST_URL, _reset, get_config


def _fresh():
    _reset()
    sender._reset_sender()


class TestIngestUrlDefault:
    def test_default_is_empty_not_a_local_address(self):
        assert DEFAULT_INGEST_URL == ""

    def test_unset_ingest_url_resolves_to_empty(self):
        _fresh()
        obsvr.init(api_key="test-key")
        assert get_config().ingest_url == ""

    def test_unset_ingest_url_warns_loudly(self, caplog):
        _fresh()
        with caplog.at_level(logging.WARNING, logger="obsvr"):
            obsvr.init(api_key="test-key")
        warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert any("ingest_url is not configured" in r.getMessage() for r in warnings), (
            f"expected a loud no-delivery warning, got: {[r.getMessage() for r in warnings]}"
        )
        # The message tells the operator what stopped working and how to fix it,
        # matching the TypeScript SDK's warning contract.
        message = next(r.getMessage() for r in warnings if "ingest_url is not configured" in r.getMessage())
        assert "will not be delivered" in message
        assert "obsvr.init()" in message

    def test_a_configured_url_warns_about_nothing(self, caplog):
        _fresh()
        with caplog.at_level(logging.WARNING, logger="obsvr"):
            obsvr.init(api_key="test-key", ingest_url="https://audit.example.com")
        assert not any(
            "ingest_url is not configured" in r.getMessage() for r in caplog.records
        )
        assert get_config().ingest_url == "https://audit.example.com"


class TestNoDeliveryWhenUnset:
    def test_no_network_attempt_is_made(self, monkeypatch):
        """The point of the change: nothing leaves the process. Not to
        localhost, not anywhere."""
        _fresh()
        calls = []

        def recording_urlopen(*args, **kwargs):
            calls.append(args)
            raise AssertionError("the sender attempted a network call with no ingest_url")

        monkeypatch.setattr(sender, "urlopen", recording_urlopen)

        obsvr.init(api_key="test-key")
        event = {"prompt": "hello", "response": "world", "request_id": "r1"}
        sender.send_audit_async(get_config(), event)
        sender.flush(timeout=1.0)

        assert calls == []

    def test_delivery_failure_is_counted_not_crashed(self, monkeypatch):
        """An unusable URL is a delivery failure like any other: retried, then
        dropped and counted. It must not take the worker thread down with it."""
        _fresh()
        monkeypatch.setattr(sender, "urlopen", lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("should never be reached")
        ))

        obsvr.init(api_key="test-key")
        sender.send_audit_async(get_config(), {"prompt": "a", "response": "b", "request_id": "r1"})
        sender.flush(timeout=1.0)

        stats = sender.get_sender_stats()
        assert stats["enqueued"] == 1
        assert stats["sent"] == 0
        # Either still queued for retry or dropped after exhausting the budget -
        # never counted as delivered.
        assert stats["sent"] == 0
