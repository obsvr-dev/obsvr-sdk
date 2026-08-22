"""DNS snapshot and pinned-connection tests for strict receipt admission."""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import obsvr.external_backend as external_backend
from obsvr.ssrf import resolve_backend_url_allowed
from obsvr.strict_admission import (
    STRICT_RECEIPT_ADMISSION_SCHEMA,
    admit_strict_receipt,
)

RECEIPT_HASH = "a" * 64
RECEIPT = {
    "schema": "obsvr-strict-receipt-envelope-v1",
    "body": {"receipt_id": "session:1"},
    "receipt_hash": RECEIPT_HASH,
    "signature": {
        "algorithm": "Ed25519",
        "key_id": "sha256:" + "b" * 64,
        "value": "c" * 128,
    },
}


def response_body(status="accepted"):
    return json.dumps(
        {
            "schema": STRICT_RECEIPT_ADMISSION_SCHEMA,
            "ok": True,
            "status": status,
            "receipt_hash": RECEIPT_HASH,
            "accepted_at_ms": 1_700_000_000_000,
        }
    ).encode()


def options(resolver, transport, **overrides):
    state = {"now": 0.0}

    def sleep(delay):
        state["now"] += delay

    values = {
        "ingest_url": "https://ingest.example.test:8443/base",
        "api_key": "test-key",
        "resolver": resolver,
        "trusted_pinned_transport": transport,
        "clock_ms": lambda: state["now"],
        "sleep": sleep,
        "jitter": lambda: 0.0,
        "retry_base_ms": 2,
        "retry_deadline_ms": 100,
        "timeout_ms": 10,
    }
    values.update(overrides)
    return values


def test_default_is_the_pinned_production_transport():
    captured = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 - stdlib handler API
            length = int(self.headers["Content-Length"])
            captured.update(
                host=self.headers["Host"],
                connection=self.headers["Connection"],
                body=self.rfile.read(length),
            )
            payload = response_body()
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_args):
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever)
    worker.start()
    try:
        result = admit_strict_receipt(
            RECEIPT,
            ingest_url=f"http://localhost:{server.server_port}/base",
            api_key="test-key",
            resolver=lambda _host: ["127.0.0.1"],
            max_attempts=1,
        )
    finally:
        server.shutdown()
        worker.join(timeout=2)
        server.server_close()
    assert result["disposition"] == "accepted"
    assert captured["host"] == f"localhost:{server.server_port}"
    assert captured["connection"] == "close"
    assert (f'"receipt_hash":"{RECEIPT_HASH}"').encode() in captured["body"]


@pytest.mark.parametrize(
    "answers",
    (
        ["10.1.2.3"],
        ["8.8.8.8", "10.1.2.3"],
        ["169.254.169.254"],
    ),
    ids=("private", "mixed-public-private", "metadata"),
)
def test_unsafe_dns_snapshots_never_reach_transport(answers):
    calls = {"resolver": 0, "transport": 0}

    def resolver(_host):
        calls["resolver"] += 1
        return answers

    def transport(*_args):
        calls["transport"] += 1

    result = admit_strict_receipt(
        RECEIPT, **options(resolver, transport, max_attempts=2)
    )
    assert result == {
        "disposition": "uncertain",
        "receipt_hash": RECEIPT_HASH,
        "reason": "retry_exhausted",
        "attempts": 2,
    }
    assert calls == {"resolver": 2, "transport": 0}


def test_approved_ipv4_and_ipv6_answers_share_one_immutable_snapshot():
    calls = {"resolver": 0}
    snapshots = []

    def resolver(_host):
        calls["resolver"] += 1
        return ["8.8.8.8", "2606:4700:4700::1111"]

    def transport(target, _headers, _body, _timeout, _limit):
        snapshots.append(target)
        return 200, response_body()

    result = admit_strict_receipt(RECEIPT, **options(resolver, transport))
    assert result["disposition"] == "accepted"
    assert [(item.address, item.family) for item in snapshots[0].addresses] == [
        ("8.8.8.8", external_backend.socket.AF_INET),
        ("2606:4700:4700::1111", external_backend.socket.AF_INET6),
    ]
    assert calls["resolver"] == 1


def test_dns_cannot_change_between_guard_and_transport():
    answers = iter([["8.8.8.8"], ["127.0.0.1"]])
    resolver_calls = []
    seen = []

    def resolver(host):
        resolver_calls.append(host)
        return next(answers)

    def transport(target, _headers, _body, _timeout, _limit):
        seen.append([entry.address for entry in target.addresses])
        return 200, response_body()

    result = admit_strict_receipt(
        RECEIPT, **options(resolver, transport, max_attempts=1)
    )
    assert result["disposition"] == "accepted"
    assert seen == [["8.8.8.8"]]
    assert resolver_calls == ["ingest.example.test"]


def test_retry_resolves_a_fresh_snapshot_but_preserves_request_bytes():
    answers = iter([["8.8.8.8"], ["1.1.1.1"]])
    snapshots = []
    bodies = []
    keys = []

    def transport(target, headers, body, _timeout, _limit):
        snapshots.append([entry.address for entry in target.addresses])
        bodies.append(body)
        keys.append(headers["Idempotency-Key"])
        if len(snapshots) == 1:
            return 503, b"{}"
        return 200, response_body("already_accepted")

    result = admit_strict_receipt(
        RECEIPT,
        **options(lambda _host: next(answers), transport),
    )
    assert result["status"] == "already_accepted"
    assert result["attempts"] == 2
    assert snapshots == [["8.8.8.8"], ["1.1.1.1"]]
    assert bodies == [bodies[0], bodies[0]]
    assert keys == [RECEIPT_HASH, RECEIPT_HASH]


def test_resolver_failure_is_uncertain_and_never_reaches_transport():
    transport_calls = []

    def resolver(_host):
        raise OSError("resolver unavailable")

    def transport(*_args):
        transport_calls.append(True)

    result = admit_strict_receipt(
        RECEIPT, **options(resolver, transport, max_attempts=1)
    )
    assert result == {
        "disposition": "uncertain",
        "receipt_hash": RECEIPT_HASH,
        "reason": "retry_exhausted",
        "attempts": 1,
    }
    assert transport_calls == []


def test_slow_resolver_is_bounded_and_never_reaches_transport():
    transport_calls = []

    def resolver(_host):
        time.sleep(0.05)
        return ["8.8.8.8"]

    def transport(*_args):
        transport_calls.append(True)

    result = admit_strict_receipt(
        RECEIPT,
        **options(resolver, transport, timeout_ms=1, max_attempts=1),
    )
    assert result["disposition"] == "uncertain"
    assert result["reason"] == "retry_exhausted"
    assert transport_calls == []


def test_literal_loopback_http_skips_dns_but_localhost_metadata_is_refused():
    calls = []

    def transport(target, *_args):
        calls.append([entry.address for entry in target.addresses])
        return 200, response_body()

    result = admit_strict_receipt(
        RECEIPT,
        **options(
            lambda _host: (_ for _ in ()).throw(AssertionError("unexpected DNS")),
            transport,
            ingest_url="http://127.0.0.1:8787/base",
            max_attempts=1,
        ),
    )
    assert result["disposition"] == "accepted"
    assert calls == [["127.0.0.1"]]

    calls.clear()
    blocked = admit_strict_receipt(
        RECEIPT,
        **options(
            lambda _host: ["127.0.0.1", "169.254.169.254"],
            transport,
            ingest_url="http://localhost:8787/base",
            max_attempts=1,
        ),
    )
    assert blocked["disposition"] == "uncertain"
    assert calls == []


def test_pinned_https_preserves_host_header_sni_and_certificate_check(monkeypatch):
    target = resolve_backend_url_allowed(
        "https://ingest.example.test:8443/base",
        resolver=lambda _host: ["8.8.8.8"],
    )
    raw_socket = object()
    captured = {}

    class Context:
        check_hostname = True
        verify_mode = external_backend.ssl.CERT_REQUIRED

        @staticmethod
        def wrap_socket(sock, *, server_hostname):
            captured["server_hostname"] = server_hostname
            captured["raw_socket"] = sock
            return "tls-socket"

    connection = external_backend._PinnedHTTPSConnection(target, 1.0)
    assert connection._context.check_hostname is True
    assert connection._context.verify_mode == external_backend.ssl.CERT_REQUIRED
    monkeypatch.setattr(
        external_backend, "_connect_approved_socket", lambda *_args: raw_socket
    )
    connection._context = Context()
    connection.connect()
    assert captured == {
        "server_hostname": "ingest.example.test",
        "raw_socket": raw_socket,
    }

    request_capture = {}

    class FakeResponse:
        status = 200

        @staticmethod
        def getheader(_name):
            return None

        @staticmethod
        def read(_size):
            return response_body()

    class FakeConnection:
        def __init__(self, _target, _timeout):
            pass

        def request(self, method, path, body, headers):
            request_capture.update(method=method, path=path, body=body, headers=headers)

        @staticmethod
        def getresponse():
            return FakeResponse()

        @staticmethod
        def close():
            request_capture["closed"] = True

    monkeypatch.setattr(external_backend, "_PinnedHTTPSConnection", FakeConnection)
    status, raw = external_backend._pinned_request(
        target,
        {"Host": "169.254.169.254", "Connection": "keep-alive"},
        b"payload",
        1.0,
        1024,
    )
    assert status == 200 and raw == response_body()
    assert request_capture["headers"]["Host"] == "ingest.example.test:8443"
    assert request_capture["headers"]["Connection"] == "close"
    assert request_capture["closed"] is True
