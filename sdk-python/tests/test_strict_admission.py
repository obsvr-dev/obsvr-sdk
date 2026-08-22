"""Focused tests for bounded, idempotent strict receipt admission."""

import json

import pytest

from obsvr.strict_admission import (
    STRICT_RECEIPT_ADMISSION_SCHEMA,
    STRICT_RECEIPT_INGEST_SCHEMA,
    StrictAdmissionValidationError,
    admit_strict_receipt,
)
from obsvr.tool_pinning import _canonical_json_for_hash

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


class Response:
    def __init__(self, status, value, headers=None):
        self.status = status
        self.headers = headers or {}
        self._body = value if isinstance(value, bytes) else json.dumps(value).encode()

    def read(self, size=-1):
        return self._body if size < 0 else self._body[:size]


def admission(status="accepted", receipt_hash=RECEIPT_HASH):
    return {
        "schema": STRICT_RECEIPT_ADMISSION_SCHEMA,
        "ok": True,
        "status": status,
        "receipt_hash": receipt_hash,
        "accepted_at_ms": 1_700_000_000_000,
    }


def rejection(receipt_hash=RECEIPT_HASH):
    return {
        "schema": STRICT_RECEIPT_ADMISSION_SCHEMA,
        "ok": False,
        "status": "rejected",
        "code": "not_authorized",
        "stored": False,
        "receipt_hash": receipt_hash,
    }


def deterministic(urlopen_fn, **overrides):
    state = {"now": 0.0}

    def sleep(delay):
        state["now"] += delay

    options = {
        "ingest_url": "https://ingest.example.test/base/",
        "api_key": "top-secret-test-key",
        "urlopen_fn": urlopen_fn,
        "clock_ms": lambda: state["now"],
        "sleep": sleep,
        "jitter": lambda: 0.0,
        "retry_base_ms": 2,
        "retry_deadline_ms": 100,
        "timeout_ms": 10,
    }
    options.update(overrides)
    return options


def headers(request):
    return {key.lower(): value for key, value in request.header_items()}


def test_retries_byte_identically_with_one_idempotency_key():
    calls = []

    def opener(request, timeout=None):
        calls.append((request, timeout))
        if len(calls) == 1:
            return Response(503, {"unavailable": True})
        return Response(200, admission())

    result = admit_strict_receipt(RECEIPT, **deterministic(opener))

    assert result == {
        "disposition": "accepted",
        "receipt_hash": RECEIPT_HASH,
        "status": "accepted",
        "attempts": 2,
    }
    assert [request.data for request, _ in calls] == [calls[0][0].data] * 2
    assert (
        calls[0][0].data
        == _canonical_json_for_hash(
            {"schema": STRICT_RECEIPT_INGEST_SCHEMA, "receipt": RECEIPT}
        ).encode()
    )
    assert [headers(request)["idempotency-key"] for request, _ in calls] == [
        RECEIPT_HASH,
        RECEIPT_HASH,
    ]
    assert calls[0][0].full_url == (
        "https://ingest.example.test/base/ingest/strict-receipts"
    )


def test_lost_ack_then_duplicate_is_accepted():
    calls = {"count": 0}

    def opener(_request, timeout=None):
        calls["count"] += 1
        if calls["count"] == 1:
            raise OSError("connection lost after write")
        return Response(200, admission("already_accepted"))

    assert admit_strict_receipt(RECEIPT, **deterministic(opener)) == {
        "disposition": "accepted",
        "receipt_hash": RECEIPT_HASH,
        "status": "already_accepted",
        "attempts": 2,
    }


def test_loopback_http_is_allowed_and_preserves_normalized_base_path():
    urls = []

    def opener(request, timeout=None):
        urls.append(request.full_url)
        return Response(200, admission())

    result = admit_strict_receipt(
        RECEIPT,
        **deterministic(opener, ingest_url="http://localhost:8787/base/"),
    )
    assert result["disposition"] == "accepted"
    assert urls == ["http://localhost:8787/base/ingest/strict-receipts"]


def test_plaintext_http_off_loopback_is_refused_without_exposing_url_material():
    sentinel = "sentinel-url-secret"
    calls = []

    def opener(*_args, **_kwargs):
        calls.append(True)

    with pytest.raises(StrictAdmissionValidationError) as caught:
        admit_strict_receipt(
            RECEIPT,
            **deterministic(
                opener,
                ingest_url=f"http://ingest.example.test/{sentinel}",
            ),
        )
    assert sentinel not in str(caught.value)
    assert calls == []


@pytest.mark.parametrize(
    "ingest_url",
    (
        "http://169.254.169.254/latest/meta-data",
        "https://169.254.1.2/collector",
        "https://10.0.0.5/collector",
    ),
)
def test_statically_unsafe_literal_target_is_refused(ingest_url):
    calls = []

    def opener(*_args, **_kwargs):
        calls.append(True)

    with pytest.raises(StrictAdmissionValidationError):
        admit_strict_receipt(
            RECEIPT,
            **deterministic(opener, ingest_url=ingest_url),
        )
    assert calls == []


def test_mismatched_success_hash_is_uncertain():
    result = admit_strict_receipt(
        RECEIPT,
        **deterministic(
            lambda *_args, **_kwargs: Response(200, admission(receipt_hash="d" * 64))
        ),
    )
    assert result == {
        "disposition": "uncertain",
        "receipt_hash": RECEIPT_HASH,
        "reason": "invalid_response",
        "attempts": 1,
    }


@pytest.mark.parametrize(
    "returned",
    [
        Response(200, b"{"),
        Response(200, admission(), {"Content-Length": "1000"}),
        Response(200, {**admission(), "extra": True}),
    ],
    ids=("malformed", "oversized", "additive-field"),
)
def test_malformed_or_oversized_success_is_uncertain(returned):
    result = admit_strict_receipt(
        RECEIPT,
        **deterministic(
            lambda *_args, **_kwargs: returned,
            max_response_bytes=100,
        ),
    )
    assert result["disposition"] == "uncertain"
    assert result["reason"] == "invalid_response"
    assert result["attempts"] == 1


def test_redirect_is_refused():
    result = admit_strict_receipt(
        RECEIPT,
        **deterministic(lambda *_args, **_kwargs: Response(302, b"")),
    )
    assert result == {
        "disposition": "uncertain",
        "receipt_hash": RECEIPT_HASH,
        "reason": "redirect",
        "attempts": 1,
    }


def test_only_explicit_matching_no_store_is_definitive():
    result = admit_strict_receipt(
        RECEIPT,
        **deterministic(lambda *_args, **_kwargs: Response(401, rejection())),
    )
    assert result == {
        "disposition": "definitive_no_store",
        "receipt_hash": RECEIPT_HASH,
        "http_status": 401,
        "attempts": 1,
    }
    mismatch = admit_strict_receipt(
        RECEIPT,
        **deterministic(lambda *_args, **_kwargs: Response(401, rejection("d" * 64))),
    )
    assert mismatch["disposition"] == "uncertain"
    assert mismatch["reason"] == "invalid_response"


def test_structured_conflict_is_uncertain():
    conflict = {
        "schema": STRICT_RECEIPT_ADMISSION_SCHEMA,
        "ok": False,
        "status": "conflict",
        "code": "idempotency_conflict",
        "receipt_hash": RECEIPT_HASH,
    }
    result = admit_strict_receipt(
        RECEIPT,
        **deterministic(lambda *_args, **_kwargs: Response(409, conflict)),
    )
    assert result == {
        "disposition": "uncertain",
        "receipt_hash": RECEIPT_HASH,
        "reason": "conflict",
        "attempts": 1,
    }


@pytest.mark.parametrize("kind", ("transport", "timeout", "http"))
def test_transport_and_http_retries_are_bounded_and_secret_free(kind):
    def opener(_request, timeout=None):
        if kind == "transport":
            raise OSError("top-secret-test-key")
        if kind == "timeout":
            raise TimeoutError("timed out")
        return Response(503, {"unavailable": True})

    result = admit_strict_receipt(RECEIPT, **deterministic(opener, max_attempts=3))
    assert result == {
        "disposition": "uncertain",
        "receipt_hash": RECEIPT_HASH,
        "reason": "retry_exhausted",
        "attempts": 3,
    }
    assert "top-secret-test-key" not in json.dumps(result)


def test_passes_a_bounded_timeout_to_urlopen():
    seen = []

    def opener(_request, timeout=None):
        seen.append(timeout)
        return Response(200, admission())

    result = admit_strict_receipt(
        RECEIPT, **deterministic(opener, timeout_ms=25, max_attempts=1)
    )
    assert result["disposition"] == "accepted"
    assert seen == [0.025]


def test_validation_errors_do_not_expose_api_key():
    with pytest.raises(StrictAdmissionValidationError) as caught:
        admit_strict_receipt(
            RECEIPT,
            **deterministic(
                lambda *_args, **_kwargs: None,
                ingest_url="not-a-url",
                api_key="top-secret-test-key",
            ),
        )
    assert "top-secret-test-key" not in str(caught.value)
