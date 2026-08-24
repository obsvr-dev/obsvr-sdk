import json

import pytest

from obsvr.strict_receipt_reconcile_v2 import (
    STRICT_RECONCILIATION_V2_ENDPOINT,
    reconcile_strict_receipt_v2,
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


def test_exact_wrapper_pinned_retry_and_stable_idempotency():
    bodies = []
    snapshots = []
    answers = iter((["8.8.8.8"], ["1.1.1.1"]))

    def transport(target, headers, body, _timeout, _limit):
        bodies.append(body)
        snapshots.append([item.address for item in target.addresses])
        assert target.parts.path == f"/base{STRICT_RECONCILIATION_V2_ENDPOINT}"
        assert headers["Idempotency-Key"] == HASH
        if len(bodies) == 1:
            return 500, b""
        return 200, json.dumps(
            {
                "schema": "obsvr-strict-receipt-reconciliation-v2",
                "ok": True,
                "status": "accepted",
                "session_id": "session-1",
                "receipt_hash": HASH,
                "accepted_at_ms": 10,
            }
        ).encode()

    result = reconcile_strict_receipt_v2(
        RECEIPT,
        ingest_url="https://example.com/base/",
        api_key="key",
        max_attempts=2,
        resolver=lambda _host: next(answers),
        sleep=lambda _: None,
        trusted_pinned_transport=transport,
    )
    assert bodies[0] == bodies[1]
    assert snapshots == [["8.8.8.8"], ["1.1.1.1"]]
    assert json.loads(bodies[0]) == {
        "schema": "obsvr-strict-receipt-ingest-v2",
        "tenant_id": "tenant-1",
        "session_id": "session-1",
        "receipt": RECEIPT,
    }
    assert result.value["status"] == "accepted"


def test_mixed_dns_and_wrong_echo_stay_unknown():
    called = False

    def transport(*_args):
        nonlocal called
        called = True
        raise AssertionError("must not connect")

    mixed = reconcile_strict_receipt_v2(
        RECEIPT,
        ingest_url="https://example.com",
        api_key="key",
        max_attempts=1,
        resolver=lambda _host: ["8.8.8.8", "127.0.0.1"],
        trusted_pinned_transport=transport,
    )
    assert called is False
    assert mixed.value["status"] == "unknown"
    wrong = reconcile_strict_receipt_v2(
        RECEIPT,
        ingest_url="https://example.com",
        api_key="key",
        max_attempts=1,
        resolver=lambda _host: ["8.8.8.8"],
        trusted_pinned_transport=lambda *_args: (
            200,
            json.dumps(
                {
                    "schema": "obsvr-strict-receipt-reconciliation-v2",
                    "ok": True,
                    "status": "accepted",
                    "session_id": "other",
                    "receipt_hash": HASH,
                    "accepted_at_ms": 10,
                }
            ).encode(),
        ),
    )
    assert wrong.value["status"] == "unknown"
    absent = reconcile_strict_receipt_v2(
        RECEIPT,
        ingest_url="https://example.com",
        api_key="key",
        max_attempts=1,
        resolver=lambda _host: ["8.8.8.8"],
        trusted_pinned_transport=lambda *_args: (
            404,
            json.dumps(
                {
                    "schema": "obsvr-strict-receipt-reconciliation-v2",
                    "ok": True,
                    "status": "absent",
                    "session_id": "session-1",
                    "receipt_hash": HASH,
                }
            ).encode(),
        ),
    )
    assert absent.value["status"] == "absent"


def test_invalid_transport_bounds_fail_before_lookup():
    with pytest.raises(ValueError, match="max_attempts"):
        reconcile_strict_receipt_v2(
            RECEIPT,
            ingest_url="https://example.com",
            api_key="key",
            max_attempts=0,
        )
