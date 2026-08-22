import copy
import hashlib
import json
from pathlib import Path

import pytest

from obsvr.strict_admission_v2_1 import (
    STRICT_RECEIPT_V2_1_ADMISSION_SCHEMA,
    STRICT_RECEIPT_V2_1_ENDPOINT,
    STRICT_RECEIPT_V2_1_INGEST_SCHEMA,
    STRICT_RECEIPT_V2_1_MAX_REQUEST_BYTES,
    StrictAdmissionV21ValidationError,
    _assert_request_bytes,
    admit_prepared_strict_receipt_v2_1,
)
from obsvr.strict_receipt_prepared_state import DEFINITIVE_NO_STORE

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = json.loads(
    (ROOT / "conformance/fixtures/strict_receipts_v2_1.json").read_text("utf-8")
)
RECEIPT = {
    "schema": "obsvr-strict-receipt-envelope-v2-1",
    "body": FIXTURE["vector"]["body"],
    "receipt_hash": FIXTURE["vector"]["receipt_hash"],
    "signature": {
        "algorithm": "Ed25519",
        "key_id": FIXTURE["public_test_key"]["key_id"],
        "value": FIXTURE["vector"]["signature"],
    },
    "public_key_b64": FIXTURE["public_test_key"]["public_key_b64"],
}
HASH = RECEIPT["receipt_hash"]
WRAPPER_SHA256 = "270dd3f997c5fb729e41d935dd840ebe4e6fbabd5a7af6fa4810352bc13aa83c"


def _prepared(**overrides):
    result = {
        "token": "token-21",
        "receipt_hash": HASH,
        "kind": "decision",
        "value": {
            "receipt": copy.deepcopy(RECEIPT),
            "action_context": {},
            "intent_evaluation": {},
            "evaluation_evidence": {},
        },
    }
    result.update(overrides)
    return result


class Coordinator:
    def __init__(self):
        self.current = {
            "token": "token-21",
            "receipt_hash": HASH,
            "kind": "decision",
        }
        self.frozen = False
        self.commits = 0
        self.aborts = 0
        self.freezes = []
        self.commit_failure = False

    def inspect_state(self):
        result = {
            "tenant_id": RECEIPT["body"]["tenant_id"],
            "session_id": RECEIPT["body"]["session_id"],
            "frozen": self.frozen,
        }
        if self.current is not None:
            result["prepared"] = self.current
        return result

    def commit_prepared(self, token, receipt_hash):
        self._match(token, receipt_hash)
        self.commits += 1
        if self.commit_failure:
            raise RuntimeError("commit failed")
        self.current = None

    def abort_prepared(self, token, receipt_hash, capability):
        self._match(token, receipt_hash)
        assert capability is DEFINITIVE_NO_STORE
        self.aborts += 1
        self.current = None

    def freeze_prepared(self, token, receipt_hash, reason="transport_ambiguous"):
        self._match(token, receipt_hash)
        self.frozen = True
        self.freezes.append(reason)

    def _match(self, token, receipt_hash):
        assert self.current is not None
        assert token == self.current["token"]
        assert receipt_hash == self.current["receipt_hash"]


def _accepted(status="accepted"):
    return json.dumps(
        {
            "schema": STRICT_RECEIPT_V2_1_ADMISSION_SCHEMA,
            "ok": True,
            "status": status,
            "receipt_hash": HASH,
            "accepted_at_ms": 10,
        }
    ).encode()


def _call(coordinator, prepared, transport, **overrides):
    return admit_prepared_strict_receipt_v2_1(
        coordinator,
        prepared,
        ingest_url="https://example.com/base/",
        api_key="key",
        resolver=lambda _host: ["8.8.8.8"],
        max_attempts=1,
        trusted_pinned_transport=transport,
        **overrides,
    )


def test_backend_request_cap_is_enforced_locally_before_transport():
    _assert_request_bytes(b"x" * STRICT_RECEIPT_V2_1_MAX_REQUEST_BYTES)
    with pytest.raises(StrictAdmissionV21ValidationError, match="supported size"):
        _assert_request_bytes(b"x" * (STRICT_RECEIPT_V2_1_MAX_REQUEST_BYTES + 1))


def test_exact_canonical_wrapper_pinned_snapshot_and_accepted_commit():
    coordinator = Coordinator()
    captured = {}

    def transport(target, headers, body, _timeout, _limit):
        captured.update(target=target, headers=headers, body=body)
        return 200, _accepted()

    result = _call(coordinator, _prepared(), transport)
    assert captured["target"].parts.path == f"/base{STRICT_RECEIPT_V2_1_ENDPOINT}"
    assert [item.address for item in captured["target"].addresses] == ["8.8.8.8"]
    assert captured["headers"]["Idempotency-Key"] == HASH
    assert json.loads(captured["body"]) == {
        "schema": STRICT_RECEIPT_V2_1_INGEST_SCHEMA,
        "tenant_id": RECEIPT["body"]["tenant_id"],
        "session_id": RECEIPT["body"]["session_id"],
        "receipt": RECEIPT,
    }
    assert hashlib.sha256(captured["body"]).hexdigest() == WRAPPER_SHA256
    assert result["disposition"] == "accepted"
    assert coordinator.commits == 1
    assert coordinator.freezes == []


def test_exact_already_accepted_commits():
    coordinator = Coordinator()
    result = _call(
        coordinator,
        _prepared(),
        lambda *_args: (200, _accepted("already_accepted")),
    )
    assert result["status"] == "already_accepted"
    assert coordinator.commits == 1


def test_exact_definitive_no_store_aborts_with_capability():
    coordinator = Coordinator()
    raw = json.dumps(
        {
            "schema": STRICT_RECEIPT_V2_1_ADMISSION_SCHEMA,
            "ok": False,
            "status": "rejected",
            "code": "invalid_receipt",
            "stored": False,
            "receipt_hash": HASH,
        }
    ).encode()
    result = _call(coordinator, _prepared(), lambda *_args: (400, raw))
    assert result["disposition"] == "definitive_no_store"
    assert coordinator.aborts == 1
    assert coordinator.freezes == []


def test_conflict_and_503_freeze():
    conflict_coordinator = Coordinator()
    raw = json.dumps(
        {
            "schema": STRICT_RECEIPT_V2_1_ADMISSION_SCHEMA,
            "ok": False,
            "status": "conflict",
            "code": "receipt_conflict",
            "receipt_hash": HASH,
        }
    ).encode()
    conflict = _call(conflict_coordinator, _prepared(), lambda *_args: (409, raw))
    assert conflict["reason"] == "conflict"
    assert conflict_coordinator.freezes == ["conflict"]

    retry_coordinator = Coordinator()
    retry = _call(retry_coordinator, _prepared(), lambda *_args: (503, b"{}"))
    assert retry["reason"] == "retry_exhausted"
    assert retry_coordinator.freezes == ["retry_exhausted"]


@pytest.mark.parametrize(
    "raw",
    [
        json.dumps({"nope": True}).encode(),
        json.dumps(
            {
                "schema": STRICT_RECEIPT_V2_1_ADMISSION_SCHEMA,
                "ok": True,
                "status": "accepted",
                "receipt_hash": "b" * 64,
                "accepted_at_ms": 10,
            }
        ).encode(),
        b'{"schema":',
        b" " * 65_537,
    ],
    ids=["malformed", "wrong-hash", "truncated", "oversized"],
)
def test_bad_success_response_freezes(raw):
    coordinator = Coordinator()
    result = _call(coordinator, _prepared(), lambda *_args: (200, raw))
    assert result["reason"] == "invalid_response"
    assert coordinator.freezes == ["invalid_response"]


def test_redirect_dns_rejection_and_pinned_transport_failure_freeze():
    redirect_coordinator = Coordinator()
    redirect = _call(redirect_coordinator, _prepared(), lambda *_args: (302, b""))
    assert redirect["reason"] == "redirect"

    dns_coordinator = Coordinator()
    calls = []
    dns = admit_prepared_strict_receipt_v2_1(
        dns_coordinator,
        _prepared(),
        ingest_url="https://example.com",
        api_key="key",
        resolver=lambda _host: ["8.8.8.8", "127.0.0.1"],
        max_attempts=1,
        trusted_pinned_transport=lambda *_args: calls.append(True),
    )
    assert calls == []
    assert dns["reason"] == "retry_exhausted"

    pin_coordinator = Coordinator()

    def failed(*_args):
        raise OSError("pinned socket failed")

    pin = _call(pin_coordinator, _prepared(), failed)
    assert pin["reason"] == "retry_exhausted"
    assert all(
        item.frozen for item in (redirect_coordinator, dns_coordinator, pin_coordinator)
    )


def test_nondecision_or_state_drift_is_rejected_before_transport():
    coordinator = Coordinator()
    coordinator.current["kind"] = "resolution"
    calls = []
    with pytest.raises(StrictAdmissionV21ValidationError, match="prepared decision"):
        _call(
            coordinator,
            _prepared(kind="resolution"),
            lambda *_args: calls.append(True),
        )
    assert calls == []
    assert coordinator.commits == 0


def test_accepted_but_local_commit_failure_freezes():
    coordinator = Coordinator()
    coordinator.commit_failure = True
    result = _call(coordinator, _prepared(), lambda *_args: (200, _accepted()))
    assert result["reason"] == "local_commit_failed"
    assert coordinator.freezes == ["accepted_but_local_commit_failed"]
