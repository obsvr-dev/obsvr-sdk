"""Enforcement claims, checked from OUTSIDE the SDK.

Every assertion in this file reads an instrument that is not an obsvr event: a
file the tool wrote, the arguments an inner callee received, the bytes a real
HTTP server was handed, the counters after a real refusal. Nothing here asks the
audit record whether the audit record is right.

That distinction is the whole reason the file exists. A suite that verifies the
SDK's own REPORTING passes just as happily when the report is wrong, and five
defects shipped behind exactly that: a tool that wrote raw PII while its event
said ``redacted``, a rejected event counted as delivered, a client class nothing
intercepted while interception reported success. Each was found by looking at
the world instead of the record, and each one below is pinned that way.

The rule for adding to this file: if the only way you can tell the protection
happened is by reading an obsvr event, it does not belong here — find the
instrument outside the SDK, or say plainly that the claim is unproven.
"""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import obsvr
from obsvr import sender
from obsvr.integrations.tools import govern_tool

RAW_EMAIL = "marcus.webb@fastmail.com"
REDACT_EMAIL_POLICY = {"default": "detect_only", "rules": {"email": "redact"}}


def _quiesce_sender(timeout=5.0):
    """Wait until the shared sender is genuinely idle, then zero it.

    ``_reset_sender()`` empties the QUEUE, but the worker thread is a process
    singleton shared with every other test file: an event it had already
    dequeued when the reset ran is not in the queue, and it lands in the next
    batch. That makes a single-event assertion read a batch of two, which
    travels the batch path and answers a different question.

    So: reset, then confirm nothing arrives during a quiet window, and reset
    again if something did. The stale events are addressed to an unreachable
    URL, so each retry fails immediately and the retry budget drains fast.
    """
    deadline = time.monotonic() + timeout
    while True:
        sender._reset_sender()
        time.sleep(0.05)
        if sender.get_queue_size() == 0 and not any(sender.get_sender_stats().values()):
            sender._reset_sender()
            return
        if time.monotonic() > deadline:
            pytest.skip("the shared sender queue never went quiet")


@pytest.fixture(autouse=True)
def _isolate_sender():
    """Every test here starts with an empty queue and zeroed counters."""
    _quiesce_sender()
    sender._loss_warned_at = 0.0
    yield
    sender._reset_sender()


@pytest.fixture
def no_delivery(monkeypatch):
    """Govern for real, deliver nowhere.

    The side-effect tests below measure a FILE and the arguments a callee
    received; delivery is not their instrument. Left on, their events queue
    against an unreachable ingest_url, retry, and get batched with the next
    test's event — which then travels the batch path and answers a different
    question than the one being asked. The policy pipeline and the gate are
    untouched: only the transport is.
    """
    monkeypatch.setattr(sender, "send_audit_async", lambda config, event: None)


def _init(**kwargs):
    obsvr.init(
        api_key="test-key",
        ingest_url="http://127.0.0.1:1",
        environment="development",
        auto=False,
        **kwargs,
    )


# ── The tool's side effect is the instrument ────────────────────────────────


def test_a_redacted_tool_call_writes_redacted_data_to_disk(tmp_path, no_delivery):
    """The record said ``redacted`` while the tool wrote the raw address.

    Measured on a file, because a file is what a tool actually does. The audit
    event is deliberately not consulted: it was already saying the right thing
    when this was broken.
    """
    _init(pii_policy=REDACT_EMAIL_POLICY)
    path = tmp_path / "escalations.jsonl"

    def escalate(reason: str) -> str:
        """Record an escalation."""
        path.write_text(json.dumps({"reason": reason}), encoding="utf-8")
        return "ok"

    govern_tool(escalate)(f"account update to {RAW_EMAIL}")

    written = path.read_text(encoding="utf-8")
    assert RAW_EMAIL not in written, (
        "the tool wrote raw PII to disk under a redact policy"
    )
    assert "[REDACTED_EMAIL]" in written


def test_a_redacted_tool_call_leaves_the_declared_shape_intact(tmp_path, no_delivery):
    """Redaction must not deform the arguments: a tool that receives a
    different SHAPE is a tool the redaction broke."""
    _init(pii_policy=REDACT_EMAIL_POLICY)
    seen = {}

    def escalate(ticket: dict) -> str:
        """Record an escalation."""
        seen["ticket"] = ticket
        return "ok"

    govern_tool(escalate)({"id": 42, "contacts": [RAW_EMAIL], "open": True})

    assert seen["ticket"]["id"] == 42
    assert seen["ticket"]["open"] is True
    assert isinstance(seen["ticket"]["contacts"], list)
    assert RAW_EMAIL not in seen["ticket"]["contacts"][0]


def test_a_blocked_tool_body_is_never_entered(tmp_path, no_delivery):
    """The strongest claim in the product, measured by a file that must not
    change: same tool, same call, policy the only difference."""
    _init(agent_policy={"denied_tools": ["issue_refund"]})
    path = tmp_path / "refunds.jsonl"
    path.write_text("", encoding="utf-8")

    def issue_refund(amount: str) -> str:
        """Issue a refund."""
        with path.open("a", encoding="utf-8") as handle:
            handle.write(amount + "\n")
        return "ok"

    with pytest.raises(Exception):
        govern_tool(issue_refund, name="issue_refund")("40.00")

    assert path.read_text(encoding="utf-8") == "", (
        "a denied tool's body ran: the side effect exists"
    )


def test_the_audited_payload_is_the_declared_surface_not_the_call_frame(no_delivery):
    """A framework passes its own machinery alongside the arguments. What the
    tool RECEIVES is the instrument here — the callee still gets everything the
    framework sent, while the record narrows to what the tool declares."""
    _init(pii_policy=REDACT_EMAIL_POLICY)
    received = {}

    class FrameworkTool:
        name = "lookup_order"
        args_schema = {"properties": {"order_id": {"type": "string"}}}

        def _run(self, order_id, run_manager=None, config=None, **kwargs):
            received["order_id"] = order_id
            received["run_manager"] = run_manager
            received["config"] = config
            return "ok"

    manager = object()
    graph_config = {"configurable": {"checkpoint_id": "not-a-real-uuid"}}
    govern_tool(FrameworkTool())._run(
        order_id="A-3390", run_manager=manager, config=graph_config
    )

    # Narrowing the AUDIT must not narrow the CALL.
    assert received["order_id"] == "A-3390"
    assert received["run_manager"] is manager
    assert received["config"] is graph_config


# ── A real ingest server is the instrument ──────────────────────────────────


class _IngestHandler(BaseHTTPRequestHandler):
    """Answers however the test told it to, and records what it received."""

    def log_message(self, *args):  # noqa: A003 - silence the default stderr log
        pass

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler's spelling
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        status, body = self.server.obsvr_response
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture
def ingest_server():
    server = HTTPServer(("127.0.0.1", 0), _IngestHandler)
    server.obsvr_response = (200, {"count": 1})
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


def _deliver_one(server, status, body):
    """Emit one event against the live server and return the delivery counters."""
    sender._reset_sender()
    obsvr.init(
        api_key="test-key",
        ingest_url=f"http://127.0.0.1:{server.server_address[1]}",
        environment="development",
        auto=False,
    )
    # Drain whatever init itself enqueued, THEN arm the response and zero the
    # counters — otherwise a policy event rides along and the assertion is about
    # a batch of two, which takes the batch path and answers a different
    # question than the one this test asks.
    server.obsvr_response = (200, {"count": 1})
    sender.flush(timeout=5)
    _quiesce_sender()
    server.obsvr_response = (status, body)

    from obsvr.config import get_config
    from obsvr.events import emit_event

    emit_event(
        get_config(),
        provider="test",
        model="m",
        operation="chat",
        source="test",
        prompt="p",
        response="r",
    )
    sender.flush(timeout=5)
    return sender.get_sender_stats()


def test_a_refused_event_is_never_counted_as_delivered(ingest_server):
    """403 on the single-event path. The server stored nothing; ``sent`` must
    not claim otherwise. This is the counter the reporter measured lying."""
    stats = _deliver_one(ingest_server, 403, {"error": "invalid_sdk_signature"})
    assert stats["sent"] == 0, "a refused event was counted as delivered"
    assert stats["dropped_rejected"] == 1


def test_a_2xx_that_enumerates_a_reject_is_not_a_delivery(ingest_server):
    """The single-event path never read the response body, so a 200 refusing
    the event inside it counted as a clean delivery of that same event."""
    stats = _deliver_one(
        ingest_server,
        200,
        {"count": 0, "rejected": [{"index": 0, "error": "policy_blocked"}]},
    )
    assert stats["sent"] == 0
    assert stats["dropped_rejected"] == 1


def test_a_short_accepted_count_is_reconciled(ingest_server):
    """The response says how many it took. Taking fewer than it was sent is a
    refusal whether or not the server enumerated it."""
    stats = _deliver_one(ingest_server, 200, {"count": 0})
    assert stats["sent"] == 0
    assert stats["dropped_rejected"] == 1


def test_an_accepted_event_still_counts_as_delivered(ingest_server):
    """The control. Without it every assertion above is satisfied by a sender
    that counts nothing at all."""
    stats = _deliver_one(ingest_server, 200, {"count": 1})
    assert stats["sent"] == 1
    assert stats["dropped_rejected"] == 0


def test_delivery_loss_is_reported_at_default_settings(ingest_server, caplog):
    """Nothing on this path used to speak unless debug=True, so a run that
    delivered nothing looked exactly like a run that delivered everything."""
    sender._loss_warned_at = 0.0
    with caplog.at_level("WARNING", logger="obsvr"):
        _deliver_one(ingest_server, 403, {"error": "invalid_sdk_signature"})
    assert any("were NOT recorded" in record.message for record in caplog.records), (
        "audit events were lost and the SDK said nothing at default settings"
    )
