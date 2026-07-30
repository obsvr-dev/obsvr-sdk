"""Raw PII must not come to rest in this integration's signed events.

This processor ran NO policy pipeline of any kind — not the PII scan, not rules,
not the floor — so at any sample rate it wrote whatever the agent said straight
into the chain, while its three observe-only siblings stored a redacted copy.
The canary half was already covered on this side (that net lives in
``events.build_audit_event`` and fires on every path); the PII half was the gap.

**This is not enforcement and these tests do not assert any.** A TracingProcessor
cannot refuse anything — the framework wraps every processor callback in its own
try/except and only logs — and a span ENDS after its call has completed. What is
asserted is what the record carries, which is the whole of what this surface can
affect.

The two controls carry the weight. ``detect_only`` must leave the record
READABLE, because that mode exists to baseline what actually flows and scrubbing
destroys its only output; and with no policy at all the raw value is stored.
Without them, a clean record would be indistinguishable from an SDK that always
redacts.

Live twin: driven through the real `openai-agents` SDK against a real provider
in the audit harness; these fakes duck-type the same span payloads the sibling
tests use.
"""
import sys

import obsvr
from obsvr import sender
from obsvr.config import _reset
from obsvr.integrations.openai_agents import ObsvrTracingProcessor

EVENTS_MODULE = sys.modules["obsvr.events"]

SSN = "123-45-6789"
PROMPT = f"the customer ssn is {SSN}, please summarise"
ANSWER = f"noted, ssn {SSN} recorded"


class _GenerationSpanData:
    type = "generation"

    def __init__(self, raw_input, raw_output):
        self.model = "gpt-4o"
        self.input = raw_input
        self.output = raw_output
        self.usage = None


class _FunctionSpanData:
    type = "function"

    def __init__(self, name, raw_input):
        self.name = name
        self.input = raw_input
        self.output = None


class _Span:
    def __init__(self, span_data, trace_id="trace_pii"):
        self.span_data = span_data
        self.trace_id = trace_id


def _init(**extra):
    _reset()
    sender._reset_sender()
    obsvr.init(api_key="test-key", ingest_url="http://localhost:9", sample_rate=1,
               disabled=False, **extra)


def _captured(monkeypatch):
    captured = []
    monkeypatch.setattr(
        EVENTS_MODULE.sender, "send_audit_async", lambda config, event: captured.append(event)
    )
    return captured


def _run_generation(monkeypatch, **cfg):
    _init(**cfg)
    captured = _captured(monkeypatch)
    ObsvrTracingProcessor().on_span_end(_Span(_GenerationSpanData(PROMPT, ANSWER)))
    return captured


class TestStoredContentIsScanned:
    def test_a_block_policy_keeps_the_raw_value_out_of_the_event(self, monkeypatch):
        captured = _run_generation(monkeypatch, pii_policy={"rules": {"ssn": "block"}})
        blob = str(captured)
        assert captured, "no event emitted — the assertion below would be vacuous"
        assert SSN not in blob
        assert "[REDACTED_SSN]" in blob

    def test_a_redact_policy_does_the_same(self, monkeypatch):
        captured = _run_generation(monkeypatch, pii_policy={"rules": {"ssn": "redact"}})
        assert SSN not in str(captured)

    def test_the_response_half_is_redacted_too(self, monkeypatch):
        captured = _run_generation(monkeypatch, pii_policy={"rules": {"ssn": "block"}})
        llm = [e for e in captured if e.get("operation") == "llm"]
        assert llm, "no llm event"
        assert SSN not in str(llm[0]["response"])

    def test_a_tool_span_input_is_redacted(self, monkeypatch):
        _init(pii_policy={"rules": {"ssn": "block"}})
        captured = _captured(monkeypatch)
        ObsvrTracingProcessor().on_span_end(_Span(_FunctionSpanData("lookup", PROMPT)))
        tool = [e for e in captured if e.get("operation") == "openai_agents.tool.call"]
        assert tool, "no tool event"
        assert SSN not in str(tool[0]["prompt"])

    def test_the_verdict_says_redacted_and_never_blocked(self, monkeypatch):
        # A TracingProcessor cannot refuse, so an event claiming it had would be
        # the exact false record this repository exists to remove.
        captured = _run_generation(monkeypatch, pii_policy={"rules": {"ssn": "block"}})
        llm = [e for e in captured if e.get("operation") == "llm"]
        assert llm[0]["action_taken"] == "redacted"
        assert llm[0]["action_reason"] == "pii_detected"


class TestTheControls:
    def test_detect_only_leaves_the_record_readable(self, monkeypatch):
        captured = _run_generation(monkeypatch, pii_policy={"rules": {"ssn": "detect_only"}})
        assert SSN in str(captured)

    def test_no_policy_stores_the_raw_value(self, monkeypatch):
        captured = _run_generation(monkeypatch)
        assert SSN in str(captured)
