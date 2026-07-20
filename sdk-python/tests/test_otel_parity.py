"""OTel attribute parity (E29), twin of sdk/tests/unit/otel-parity.test.ts:
the mirrored span's attribute KEY SET must match
conformance/fixtures/otel_attributes.json exactly in both SDKs."""

import json
import time
from pathlib import Path
from types import SimpleNamespace

from obsvr import otel_mirror

FIXTURE = json.loads(
    (Path(__file__).parent / "../../conformance/fixtures/otel_attributes.json")
    .resolve()
    .read_text()
)


class _FakeSpan:
    def set_status(self, *_args, **_kwargs):
        pass

    def end(self, **_kwargs):
        pass


class _FakeTracer:
    def __init__(self, captured):
        self._captured = captured

    def start_span(self, _name, start_time=None, attributes=None):
        self._captured.append(attributes or {})
        return _FakeSpan()


def test_mirrors_spans_with_exact_fixture_keys():
    captured = []
    fake_trace = SimpleNamespace(get_tracer=lambda _name: _FakeTracer(captured))
    fake_status = SimpleNamespace(OK=1, ERROR=2)
    otel_mirror._reset_otel_mirror()
    otel_mirror._otel = (fake_trace, fake_status)
    try:
        config = SimpleNamespace(otel={"enabled": True})
        event = {
            "operation": "chat.completions.create",
            "provider": "openai",
            "model": "gpt-4o",
            "input_tokens": 10,
            "output_tokens": 5,
            "event_type": "llm_call",
            "action_taken": "allowed",
            "action_reason": "none",
            "rule_id": "r1",
            "seq_no": 3,
            "sdk_session_id": "sess-1",
            "environment": "production",
            "timestamp_sdk": int(time.time() * 1000),
            "latency_ms": 12,
            "success": True,
        }
        otel_mirror.mirror_to_otel(config, event)
        assert len(captured) == 1
        assert sorted(captured[0].keys()) == FIXTURE["attribute_keys"]
    finally:
        otel_mirror._reset_otel_mirror()
