import copy
import json
from pathlib import Path

import pytest

from obsvr.device_identity import load_device_signer
from obsvr.strict_execution_outcome_v2_1 import sign_strict_execution_outcome_v2_1
from obsvr.strict_receipt_v2_1 import sign_strict_receipt_v2_1
from obsvr.strict_receipt_runtime_v2_1_outcomes import (
    create_strict_runtime_execution_start_v2_1,
    create_strict_runtime_success_outcome_v2_1,
)
from obsvr.strict_runtime_recovery_v2_1 import (
    StrictRuntimeRecoveryV21Error,
    finalize_interrupted_strict_runtime_execution_v2_1,
    reconcile_strict_runtime_execution_v2_1,
)


ROOT = Path(__file__).resolve().parents[2]
DECISION = json.loads(
    (ROOT / "conformance/fixtures/strict_receipts_v2_1.json").read_text("utf-8")
)
OUTCOME = json.loads(
    (ROOT / "conformance/fixtures/strict_execution_outcomes_v2_1.json").read_text(
        "utf-8"
    )
)


def _signer(tmp_path):
    path = tmp_path / "runtime-recovery-public-seed.key"
    path.write_text(DECISION["public_test_key"]["seed_hex"], encoding="ascii")
    return load_device_signer(str(path))


def _receipt(signer):
    body = copy.deepcopy(DECISION["vector"]["body"])
    patch = OUTCOME["decision_patch"]
    body["evaluation"].update(copy.deepcopy(patch["evaluation"]))
    body["outcome"] = patch["outcome"]
    body["execution_authorized"] = patch["execution_authorized"]
    for field in patch["remove"]:
        body.pop(field, None)
    return sign_strict_receipt_v2_1(body, signer)


def _trust():
    return {
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


def _journal(tmp_path, phase="invocation_started"):
    signer = _signer(tmp_path)
    receipt = _receipt(signer)
    body = copy.deepcopy(OUTCOME["vector"]["body"])
    start = {
        "tenant_id": body["tenant_id"],
        "session_id": body["session_id"],
        "action_id": body["action_id"],
        "decision_receipt_hash": body["decision_receipt_hash"],
        "operation_fingerprint": body["operation_fingerprint"],
        "attempt": body["attempt"],
        "started_at_ms": body["started_at_ms"],
    }
    journal = {
        "schema": "obsvr-strict-runtime-execution-journal-v2-1",
        "profile_version": "2.1",
        "phase": phase,
        "tenant_id": receipt["body"]["tenant_id"],
        "session_id": receipt["body"]["session_id"],
        "runtime_action_id": receipt["body"]["action"]["action_id"],
        "operation_fingerprint": body["operation_fingerprint"],
        "prepared_token": "prepared-public",
        "receipt_hash": receipt["receipt_hash"],
        "committed_sequence": receipt["body"]["sequence"],
        "committed_head_receipt_hash": receipt["receipt_hash"],
        "receipt": receipt,
        **(
            {
                "execution_start": start,
                "execution_start_hash": body["execution_start_hash"],
            }
            if phase == "invocation_started"
            else {}
        ),
    }
    return signer, receipt, body, journal


def _resolution_journal(tmp_path):
    signer, decision, body, journal = _journal(tmp_path)
    resolution_body = copy.deepcopy(decision["body"])
    resolution_body["record_type"] = "resolution"
    resolution_body["receipt_id"] = (
        f"{resolution_body['session_id']}:resolution"
    )
    resolution_body["sequence"] += 1
    resolution_body["timestamp_ms"] += 1
    resolution_body["previous_receipt_hash"] = decision["receipt_hash"]
    resolution_body.pop("suspension", None)
    resolution_body["resolution"] = {
        "resolves_receipt_hash": decision["receipt_hash"],
        "suspension_id": "approval-public",
        "method": "approval_granted",
        "resolver_ref_hash": "c" * 64,
        "resolved_at_ms": resolution_body["timestamp_ms"],
        "approval_evidence_hash": "d" * 64,
    }
    resolution = sign_strict_receipt_v2_1(resolution_body, signer)
    start = create_strict_runtime_execution_start_v2_1(
        resolution,
        body["operation_fingerprint"],
        resolution_body["timestamp_ms"] + 1,
    )
    outcome_body = create_strict_runtime_success_outcome_v2_1(
        resolution,
        start,
        resolution_body["timestamp_ms"] + 2,
        {"schema": "obsvr-test-result-v1", "status": "ok"},
    )
    journal.update(
        {
            "tenant_id": resolution["body"]["tenant_id"],
            "session_id": resolution["body"]["session_id"],
            "runtime_action_id": resolution["body"]["action"]["action_id"],
            "receipt_hash": resolution["receipt_hash"],
            "committed_sequence": resolution["body"]["sequence"],
            "committed_head_receipt_hash": resolution["receipt_hash"],
            "receipt": resolution,
            "execution_start": {
                key: value for key, value in start.items()
                if key != "execution_start_hash"
            },
            "execution_start_hash": start["execution_start_hash"],
        }
    )
    return signer, resolution, outcome_body, journal


def test_started_action_without_terminal_outcome_is_never_retry_safe(tmp_path):
    _signer_value, _receipt_value, _body, journal = _journal(tmp_path)
    result = reconcile_strict_runtime_execution_v2_1(journal, **_trust())
    assert result["status"] == "outcome_unresolved"
    assert result["retry_safe"] is False
    assert result["decision_trusted"] is True
    assert result["journal"]["phase"] == "invocation_started"


def test_only_bound_signed_outcome_resolves_durable_start(tmp_path):
    signer, receipt, body, journal = _journal(tmp_path)
    outcome = sign_strict_execution_outcome_v2_1(body, signer, receipt)
    resolved = reconcile_strict_runtime_execution_v2_1(
        journal, outcome, **_trust()
    )
    assert resolved["status"] == "resolved"
    assert resolved["retry_safe"] is False
    assert resolved["terminal_status"] == "executed"
    assert resolved["decision_trusted"] is True
    assert resolved["outcome_integrity_valid"] is True
    assert resolved["outcome_trusted"] is True
    assert resolved["journal"]["execution_outcome"] == outcome
    again = reconcile_strict_runtime_execution_v2_1(
        resolved["journal"], **_trust()
    )
    assert again["status"] == "resolved"
    assert again["terminal_status"] == "executed"


def test_approval_resolution_can_authorize_recovered_terminal_evidence(tmp_path):
    signer, resolution, body, journal = _resolution_journal(tmp_path)
    outcome = sign_strict_execution_outcome_v2_1(body, signer, resolution)
    resolved = reconcile_strict_runtime_execution_v2_1(
        journal, outcome, **_trust()
    )
    assert resolved["status"] == "resolved"
    assert resolved["terminal_status"] == "executed"
    assert resolved["decision_trusted"] is True
    assert resolved["outcome_integrity_valid"] is True
    assert resolved["outcome_trusted"] is True
    assert resolved["journal"]["receipt"]["body"]["record_type"] == "resolution"


def test_pre_invocation_state_requires_receipt_reconciliation(tmp_path):
    _signer_value, receipt, _body, journal = _journal(tmp_path, "committed")
    result = reconcile_strict_runtime_execution_v2_1(journal, **_trust())
    assert result["status"] == "pre_invocation"
    assert result["retry_safe"] is False
    assert result["decision_trusted"] is True
    assert result["journal"]["receipt"] == receipt


@pytest.mark.parametrize("field", ["receipt", "start", "outcome"])
def test_tampered_evidence_never_resolves_execution(tmp_path, field):
    signer, receipt, body, journal = _journal(tmp_path)
    outcome = sign_strict_execution_outcome_v2_1(body, signer, receipt)
    changed = copy.deepcopy(journal)
    supplied = outcome
    if field == "receipt":
        changed["receipt"]["body"]["sequence"] += 1
    elif field == "start":
        changed["execution_start"]["started_at_ms"] += 1
    else:
        supplied = copy.deepcopy(outcome)
        supplied["body"]["result_hash"] = "7" * 64
    with pytest.raises(StrictRuntimeRecoveryV21Error):
        reconcile_strict_runtime_execution_v2_1(
            changed, supplied, **_trust()
        )


class _Store:
    def __init__(self, failure=None):
        self.saved = []
        self.failure = failure

    def save(self, checkpoint):
        if self.failure is not None:
            raise self.failure
        self.saved.append(copy.deepcopy(checkpoint))


def test_interrupted_process_persists_signed_uncertain_outcome(tmp_path):
    signer, _receipt_value, body, journal = _journal(tmp_path)
    store = _Store()
    resolved = finalize_interrupted_strict_runtime_execution_v2_1(
        journal,
        signer,
        store,
        completed_at_ms=body["started_at_ms"] + 500,
        **_trust(),
    )
    assert resolved["terminal_status"] == "invocation_uncertain"
    outcome = resolved["journal"]["execution_outcome"]
    assert outcome["body"]["status"] == "uncertain"
    assert outcome["body"]["error_code"] == "process_interrupted"
    assert outcome["body"]["completed_at_ms"] == body["started_at_ms"] + 500
    assert store.saved == [resolved["journal"]]


def test_persistence_failure_never_reports_interruption_finalized(tmp_path):
    signer, _receipt_value, body, journal = _journal(tmp_path)
    with pytest.raises(RuntimeError, match="disk full"):
        finalize_interrupted_strict_runtime_execution_v2_1(
            journal,
            signer,
            _Store(RuntimeError("disk full")),
            completed_at_ms=body["started_at_ms"] + 500,
            **_trust(),
        )
    unresolved = reconcile_strict_runtime_execution_v2_1(journal, **_trust())
    assert unresolved["status"] == "outcome_unresolved"


@pytest.mark.parametrize("phase", ["committed", "terminal"])
def test_only_unresolved_started_journal_can_be_finalized(tmp_path, phase):
    signer, receipt, body, journal = _journal(
        tmp_path, "committed" if phase == "committed" else "invocation_started"
    )
    if phase == "terminal":
        outcome = sign_strict_execution_outcome_v2_1(body, signer, receipt)
        journal = reconcile_strict_runtime_execution_v2_1(
            journal, outcome, **_trust()
        )["journal"]
    with pytest.raises(
        StrictRuntimeRecoveryV21Error,
        match="only an unresolved invocation_started journal",
    ):
        finalize_interrupted_strict_runtime_execution_v2_1(
            journal, signer, _Store(), **_trust()
        )
