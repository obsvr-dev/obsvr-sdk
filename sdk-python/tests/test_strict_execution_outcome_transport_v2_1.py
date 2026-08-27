import copy
import json
from pathlib import Path

import pytest

from obsvr.device_identity import load_device_signer
from obsvr.strict_execution_outcome_transport_v2_1 import (
    STRICT_EXECUTION_OUTCOME_V2_1_ADMISSION_SCHEMA,
    STRICT_EXECUTION_OUTCOME_V2_1_ENDPOINT,
    STRICT_EXECUTION_OUTCOME_V2_1_INGEST_SCHEMA,
    StrictExecutionOutcomeV21TransportError,
    submit_strict_execution_outcome_v2_1,
    submit_strict_runtime_terminal_journal_v2_1,
)
from obsvr.strict_execution_outcome_v2_1 import sign_strict_execution_outcome_v2_1
from obsvr.strict_receipt_v2_1 import sign_strict_receipt_v2_1

ROOT = Path(__file__).resolve().parents[2]
DECISION = json.loads(
    (ROOT / "conformance/fixtures/strict_receipts_v2_1.json").read_text("utf-8")
)
OUTCOME = json.loads(
    (ROOT / "conformance/fixtures/strict_execution_outcomes_v2_1.json").read_text(
        "utf-8"
    )
)


def _subject(tmp_path):
    path = tmp_path / "outcome-transport-seed.key"
    path.write_text(DECISION["public_test_key"]["seed_hex"], encoding="ascii")
    signer = load_device_signer(str(path))
    body = copy.deepcopy(DECISION["vector"]["body"])
    body["evaluation"].update(copy.deepcopy(OUTCOME["decision_patch"]["evaluation"]))
    body["outcome"] = "ALLOW"
    body["execution_authorized"] = True
    for field in OUTCOME["decision_patch"]["remove"]:
        body.pop(field, None)
    decision = sign_strict_receipt_v2_1(body, signer)
    outcome = sign_strict_execution_outcome_v2_1(
        copy.deepcopy(OUTCOME["vector"]["body"]), signer, decision
    )
    trust = {
        "trusted_agent_keys": [
            {
                "tenant_id": "tenant-21",
                "agent_ref_hash": "b" * 64,
                "key_id": DECISION["public_test_key"]["key_id"],
                "public_key_b64": DECISION["public_test_key"]["public_key_b64"],
                "status": "active",
            }
        ],
        "allowed_evaluator_manifest_hashes": [DECISION["evaluator_manifest_hash"]],
    }
    return decision, outcome, trust


def _response(outcome_hash, status="accepted"):
    return json.dumps(
        {
            "schema": STRICT_EXECUTION_OUTCOME_V2_1_ADMISSION_SCHEMA,
            "ok": True,
            "status": status,
            "outcome_hash": outcome_hash,
            "accepted_at_ms": 10,
        }
    ).encode()


def _call(outcome, decision, trust, transport, **overrides):
    options = {
        "ingest_url": "https://example.com/base/",
        "api_key": "key",
        "max_attempts": 1,
        "resolver": lambda _host: ["8.8.8.8"],
        "trusted_pinned_transport": transport,
        **trust,
    }
    options.update(overrides)
    return submit_strict_execution_outcome_v2_1(
        outcome,
        decision,
        **options,
    )


def test_submits_exact_wrapper_through_dns_pinned_target(tmp_path):
    decision, outcome, trust = _subject(tmp_path)
    captured = {}

    def transport(target, headers, body, _timeout, _limit):
        captured.update(target=target, headers=headers, body=json.loads(body))
        return 201, _response(outcome["outcome_hash"])

    result = _call(outcome, decision, trust, transport)
    assert captured["target"].parts.path == (
        f"/base{STRICT_EXECUTION_OUTCOME_V2_1_ENDPOINT}"
    )
    assert [item.address for item in captured["target"].addresses] == ["8.8.8.8"]
    assert captured["headers"]["Idempotency-Key"] == outcome["outcome_hash"]
    assert captured["body"] == {
        "schema": STRICT_EXECUTION_OUTCOME_V2_1_INGEST_SCHEMA,
        "tenant_id": outcome["body"]["tenant_id"],
        "session_id": outcome["body"]["session_id"],
        "outcome": outcome,
    }
    assert result["disposition"] == "accepted"
    assert result["status"] == "accepted"


def test_accepts_exact_idempotent_replay_response(tmp_path):
    decision, outcome, trust = _subject(tmp_path)
    result = _call(
        outcome,
        decision,
        trust,
        lambda *_args: (200, _response(outcome["outcome_hash"], "already_accepted")),
    )
    assert result["status"] == "already_accepted"


@pytest.mark.parametrize("status", [400, 401, 403, 413])
def test_exact_rejection_is_definitive_no_store(tmp_path, status):
    decision, outcome, trust = _subject(tmp_path)
    raw = json.dumps(
        {
            "schema": STRICT_EXECUTION_OUTCOME_V2_1_ADMISSION_SCHEMA,
            "ok": False,
            "status": "rejected",
            "code": "rejected",
            "stored": False,
            "outcome_hash": outcome["outcome_hash"],
        }
    ).encode()
    result = _call(outcome, decision, trust, lambda *_args: (status, raw))
    assert result["disposition"] == "definitive_no_store"
    assert result["http_status"] == status


def test_ambiguous_transport_states_remain_uncertain(tmp_path):
    decision, outcome, trust = _subject(tmp_path)
    conflict_body = json.dumps(
        {
            "schema": STRICT_EXECUTION_OUTCOME_V2_1_ADMISSION_SCHEMA,
            "ok": False,
            "status": "conflict",
            "code": "decision_outcome_conflict",
            "outcome_hash": outcome["outcome_hash"],
        }
    ).encode()
    conflict = _call(
        outcome, decision, trust, lambda *_args: (409, conflict_body)
    )
    redirect = _call(outcome, decision, trust, lambda *_args: (302, b""))
    malformed = _call(outcome, decision, trust, lambda *_args: (200, b"{}"))

    def offline(*_args):
        raise OSError("offline")

    exhausted = _call(outcome, decision, trust, offline)
    assert conflict["reason"] == "conflict"
    assert redirect["reason"] == "redirect"
    assert malformed["reason"] == "invalid_response"
    assert exhausted["reason"] == "retry_exhausted"


def test_rejects_tampering_and_mixed_address_dns_before_connecting(tmp_path):
    decision, outcome, trust = _subject(tmp_path)
    tampered = copy.deepcopy(outcome)
    tampered["body"]["completed_at_ms"] += 1
    with pytest.raises(StrictExecutionOutcomeV21TransportError):
        _call(tampered, decision, trust, lambda *_args: (201, b"{}"))
    calls = []

    def transport(*_args):
        calls.append(True)
        raise AssertionError("must not connect")

    result = _call(
        outcome,
        decision,
        trust,
        transport,
        resolver=lambda _host: ["8.8.8.8", "127.0.0.1"],
    )
    assert calls == []
    assert result["reason"] == "retry_exhausted"


def test_terminal_journal_submits_and_unresolved_journal_is_refused(tmp_path):
    decision, outcome, trust = _subject(tmp_path)
    start = {
        "tenant_id": outcome["body"]["tenant_id"],
        "session_id": outcome["body"]["session_id"],
        "action_id": outcome["body"]["action_id"],
        "decision_receipt_hash": outcome["body"]["decision_receipt_hash"],
        "operation_fingerprint": outcome["body"]["operation_fingerprint"],
        "attempt": 1,
        "started_at_ms": outcome["body"]["started_at_ms"],
    }
    base = {
        "schema": "obsvr-strict-runtime-execution-journal-v2-1",
        "profile_version": "2.1",
        "tenant_id": decision["body"]["tenant_id"],
        "session_id": decision["body"]["session_id"],
        "runtime_action_id": decision["body"]["action"]["action_id"],
        "operation_fingerprint": outcome["body"]["operation_fingerprint"],
        "prepared_token": "prepared",
        "receipt_hash": decision["receipt_hash"],
        "committed_sequence": decision["body"]["sequence"],
        "committed_head_receipt_hash": decision["receipt_hash"],
        "receipt": decision,
        "execution_start": start,
        "execution_start_hash": outcome["body"]["execution_start_hash"],
    }
    options = {
        "ingest_url": "https://example.com/base/",
        "api_key": "key",
        "max_attempts": 1,
        "resolver": lambda _host: ["8.8.8.8"],
        "trusted_pinned_transport": lambda *_args: (
            201,
            _response(outcome["outcome_hash"]),
        ),
        **trust,
    }
    with pytest.raises(StrictExecutionOutcomeV21TransportError):
        submit_strict_runtime_terminal_journal_v2_1(
            {**base, "phase": "invocation_started"}, **options
        )
    result = submit_strict_runtime_terminal_journal_v2_1(
        {
            **base,
            "phase": "terminal",
            "terminal_status": "executed",
            "execution_outcome": outcome,
        },
        **options,
    )
    assert result["disposition"] == "accepted"
