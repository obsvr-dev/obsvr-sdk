"""Cross-language active-span correlation for durable strict evidence."""

import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from obsvr import otel_mirror
from obsvr.device_identity import load_device_signer
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
ATTRIBUTES = json.loads(
    (ROOT / "conformance/fixtures/strict_otel_attributes_v2_1.json").read_text(
        "utf-8"
    )
)


def _journal(tmp_path, phase):
    seed = tmp_path / "public-test-seed.key"
    seed.write_text(DECISION["public_test_key"]["seed_hex"], encoding="ascii")
    signer = load_device_signer(str(seed))
    body = copy.deepcopy(DECISION["vector"]["body"])
    patch = OUTCOME["decision_patch"]
    body["evaluation"].update(copy.deepcopy(patch["evaluation"]))
    body["outcome"] = patch["outcome"]
    body["execution_authorized"] = patch["execution_authorized"]
    for field in patch["remove"]:
        body.pop(field, None)
    receipt = sign_strict_receipt_v2_1(body, signer)
    outcome = sign_strict_execution_outcome_v2_1(
        copy.deepcopy(OUTCOME["vector"]["body"]), signer, receipt
    )
    checkpoint = {
        "schema": "obsvr-strict-runtime-execution-journal-v2-1",
        "profile_version": "2.1",
        "phase": phase,
        "tenant_id": body["tenant_id"],
        "session_id": body["session_id"],
        "runtime_action_id": body["action"]["action_id"],
        "operation_fingerprint": "f" * 64,
        "prepared_token": "prepared-token",
        "receipt_hash": receipt["receipt_hash"],
        "receipt": receipt,
        "committed_sequence": 0 if phase == "prepared" else 1,
        "committed_head_receipt_hash": (
            None if phase == "prepared" else receipt["receipt_hash"]
        ),
    }
    if phase == "terminal":
        checkpoint.update(terminal_status="executed", execution_outcome=outcome)
    return checkpoint


class _Span:
    def __init__(self, captured, recording=True, raises=False):
        self._captured = captured
        self._recording = recording
        self._raises = raises

    def is_recording(self):
        return self._recording

    def set_attributes(self, attributes):
        if self._raises:
            raise RuntimeError("telemetry unavailable")
        self._captured.append(attributes)


def _capture(recording=True, raises=False):
    captured = []
    span = _Span(captured, recording=recording, raises=raises)
    trace = SimpleNamespace(get_current_span=lambda: span)
    otel_mirror._otel = (trace, SimpleNamespace(OK=1, ERROR=2))
    return captured


@pytest.fixture(autouse=True)
def _reset_otel():
    otel_mirror._reset_otel_mirror()
    yield
    otel_mirror._reset_otel_mirror()


def test_committed_and_terminal_attributes_are_content_free_and_match(tmp_path):
    captured = _capture()
    assert not otel_mirror.correlate_strict_runtime_checkpoint_v2_1_to_otel(
        _journal(tmp_path, "prepared")
    )
    committed = _journal(tmp_path, "committed")
    assert otel_mirror.correlate_strict_runtime_checkpoint_v2_1_to_otel(committed)
    assert sorted(captured[0]) == ATTRIBUTES["committed_attribute_keys"]
    assert captured[0]["obsvr.strict.receipt_hash"] == committed["receipt_hash"]
    terminal = _journal(tmp_path, "terminal")
    assert otel_mirror.correlate_strict_runtime_checkpoint_v2_1_to_otel(terminal)
    assert sorted(captured[1]) == ATTRIBUTES["terminal_attribute_keys"]
    assert (
        captured[1]["obsvr.strict.execution_outcome_hash"]
        == terminal["execution_outcome"]["outcome_hash"]
    )
    assert not any(
        word in json.dumps(captured)
        for word in ("arguments", "target", "prompt", "content")
    )


def test_foreign_terminal_outcome_is_not_correlated(tmp_path):
    captured = _capture()
    terminal = _journal(tmp_path, "terminal")
    terminal["execution_outcome"]["body"]["decision_receipt_hash"] = "0" * 64
    assert otel_mirror.correlate_strict_runtime_checkpoint_v2_1_to_otel(terminal)
    assert "obsvr.strict.execution_outcome_hash" not in captured[0]
    assert "obsvr.strict.execution_status" not in captured[0]


def test_durable_save_precedes_nonfatal_telemetry(tmp_path):
    events = []
    _capture(raises=True)
    store = SimpleNamespace(save=lambda _checkpoint: events.append("saved"))
    wrapped = otel_mirror.with_strict_otel_correlation_v2_1(store)
    wrapped.save(_journal(tmp_path, "terminal"))
    assert events == ["saved"]
    failed = otel_mirror.with_strict_otel_correlation_v2_1(
        SimpleNamespace(save=lambda _checkpoint: (_ for _ in ()).throw(OSError("disk")))
    )
    with pytest.raises(OSError, match="disk"):
        failed.save(_journal(tmp_path, "terminal"))


def test_nonrecording_active_span_is_ignored(tmp_path):
    captured = _capture(recording=False)
    assert not otel_mirror.correlate_strict_runtime_checkpoint_v2_1_to_otel(
        _journal(tmp_path, "terminal")
    )
    assert captured == []
