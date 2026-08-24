import json

from obsvr.strict_admission_v2 import (
    STRICT_RECEIPT_V2_ADMISSION_SCHEMA,
    STRICT_RECEIPT_V2_ENDPOINT,
    STRICT_RECEIPT_V2_INGEST_SCHEMA,
    admit_strict_receipt_v2,
)

HASH = "a" * 64
RECEIPT = {
    "schema": "obsvr-strict-receipt-envelope-v2",
    "receipt_hash": HASH,
    "body": {
        "schema": "obsvr-strict-receipt-v2",
        "tenant_id": "tenant-1",
        "session_id": "session-1",
    },
}


def _accepted(status="accepted"):
    return json.dumps(
        {
            "schema": STRICT_RECEIPT_V2_ADMISSION_SCHEMA,
            "ok": True,
            "status": status,
            "receipt_hash": HASH,
            "accepted_at_ms": 10,
        }
    ).encode()


def test_exact_v2_endpoint_wrapper_and_approved_snapshot():
    captured = {}

    def transport(target, headers, body, timeout, limit):
        captured.update(target=target, headers=headers, body=body)
        return 200, _accepted()

    result = admit_strict_receipt_v2(
        RECEIPT,
        ingest_url="https://example.com/base/",
        api_key="key",
        resolver=lambda _host: ["8.8.8.8"],
        max_attempts=1,
        trusted_pinned_transport=transport,
    )
    assert captured["target"].parts.path == f"/base{STRICT_RECEIPT_V2_ENDPOINT}"
    assert [item.address for item in captured["target"].addresses] == ["8.8.8.8"]
    assert captured["headers"]["Idempotency-Key"] == HASH
    assert json.loads(captured["body"]) == {
        "schema": STRICT_RECEIPT_V2_INGEST_SCHEMA,
        "tenant_id": "tenant-1",
        "session_id": "session-1",
        "receipt": RECEIPT,
    }
    assert result["disposition"] == "accepted"
    assert result["tenant_id"] == "tenant-1"


def test_retry_refreshes_snapshot_but_preserves_bytes():
    bodies = []
    snapshots = []
    answers = iter((["8.8.8.8"], ["1.1.1.1"]))

    def transport(target, _headers, body, _timeout, _limit):
        bodies.append(body)
        snapshots.append([item.address for item in target.addresses])
        return (500, b"") if len(bodies) == 1 else (200, _accepted("already_accepted"))

    result = admit_strict_receipt_v2(
        RECEIPT,
        ingest_url="https://example.com",
        api_key="key",
        resolver=lambda _host: next(answers),
        max_attempts=2,
        trusted_pinned_transport=transport,
        sleep=lambda _delay: None,
        jitter=lambda: 0,
    )
    assert bodies[0] == bodies[1]
    assert snapshots == [["8.8.8.8"], ["1.1.1.1"]]
    assert result["status"] == "already_accepted"


def test_mixed_answers_never_reach_transport():
    called = False

    def transport(*_args):
        nonlocal called
        called = True
        return 200, _accepted()

    result = admit_strict_receipt_v2(
        RECEIPT,
        ingest_url="https://example.com",
        api_key="key",
        resolver=lambda _host: ["8.8.8.8", "127.0.0.1"],
        max_attempts=1,
        trusted_pinned_transport=transport,
    )
    assert called is False
    assert result["reason"] == "retry_exhausted"


def test_explicit_no_store_needs_no_tenant_echo():
    raw = json.dumps(
        {
            "schema": STRICT_RECEIPT_V2_ADMISSION_SCHEMA,
            "ok": False,
            "status": "rejected",
            "code": "invalid",
            "stored": False,
            "receipt_hash": HASH,
        }
    ).encode()
    result = admit_strict_receipt_v2(
        RECEIPT,
        ingest_url="http://127.0.0.1:8000",
        api_key="key",
        resolver=lambda _host: ["127.0.0.1"],
        max_attempts=1,
        trusted_pinned_transport=lambda *_args: (400, raw),
    )
    assert result["disposition"] == "definitive_no_store"
    assert result["tenant_id"] == "tenant-1"


def test_v1_response_is_uncertain():
    raw = json.dumps(
        {
            "schema": "obsvr-strict-receipt-admission-v1",
            "ok": True,
            "status": "accepted",
            "receipt_hash": HASH,
            "accepted_at_ms": 10,
        }
    ).encode()
    result = admit_strict_receipt_v2(
        RECEIPT,
        ingest_url="https://example.com",
        api_key="key",
        resolver=lambda _host: ["8.8.8.8"],
        max_attempts=1,
        trusted_pinned_transport=lambda *_args: (200, raw),
    )
    assert result["reason"] == "invalid_response"
