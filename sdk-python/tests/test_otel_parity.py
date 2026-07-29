"""OTel attribute parity (E29), twin of sdk-typescript/tests/unit/otel-parity.test.ts:
the mirrored span's attribute KEY SET must match
conformance/fixtures/otel_attributes.json exactly in both SDKs.

The token attributes are CONDITIONAL. An absent OTel attribute means "not
recorded"; an attribute set to 0 claims a measurement was taken and came out
zero. Emitting the second on evidence for the first is the same fabrication the
token extractors were fixed to stop making, so the mirror omits the key.
"""

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

CONDITIONAL = sorted(FIXTURE["conditional_keys"])
UNCONDITIONAL = sorted(k for k in FIXTURE["attribute_keys"] if k not in CONDITIONAL)

BASE_EVENT = {
    "operation": "chat.completions.create",
    "provider": "openai",
    "model": "gpt-4o",
    "event_type": "llm_call",
    "action_taken": "allowed",
    "action_reason": "none",
    "rule_id": "r1",
    "seq_no": 3,
    "sdk_session_id": "sess-1",
    "environment": "production",
    "latency_ms": 12,
    "success": True,
}


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


def _capture(**overrides):
    captured = []
    fake_trace = SimpleNamespace(get_tracer=lambda _name: _FakeTracer(captured))
    fake_status = SimpleNamespace(OK=1, ERROR=2)
    otel_mirror._reset_otel_mirror()
    otel_mirror._otel = (fake_trace, fake_status)
    try:
        config = SimpleNamespace(otel={"enabled": True})
        event = dict(BASE_EVENT, timestamp_sdk=int(time.time() * 1000), **overrides)
        otel_mirror.mirror_to_otel(config, event)
        assert len(captured) == 1
        return captured[0]
    finally:
        otel_mirror._reset_otel_mirror()


def test_mirrors_spans_with_exact_fixture_keys_when_tokens_are_known():
    attrs = _capture(input_tokens=10, output_tokens=5)
    assert sorted(attrs.keys()) == FIXTURE["attribute_keys"]
    assert attrs["gen_ai.usage.input_tokens"] == 10
    assert attrs["gen_ai.usage.output_tokens"] == 5


def test_omits_the_token_attributes_when_the_counts_were_never_read():
    attrs = _capture()
    assert sorted(attrs.keys()) == UNCONDITIONAL
    for key in CONDITIONAL:
        assert key not in attrs


def test_keeps_a_genuine_zero_which_is_a_different_fact():
    # `or 0` was doubly wrong: it fabricated a count for an unread value AND
    # rewrote a real zero as the same fabrication, so nothing downstream could
    # tell them apart even when the event itself had it right.
    attrs = _capture(input_tokens=0, output_tokens=0)
    assert sorted(attrs.keys()) == FIXTURE["attribute_keys"]
    assert attrs["gen_ai.usage.input_tokens"] == 0
    assert attrs["gen_ai.usage.output_tokens"] == 0


def test_reports_a_half_known_usage_as_half_known():
    attrs = _capture(output_tokens=5)
    assert "gen_ai.usage.input_tokens" not in attrs
    assert attrs["gen_ai.usage.output_tokens"] == 5
