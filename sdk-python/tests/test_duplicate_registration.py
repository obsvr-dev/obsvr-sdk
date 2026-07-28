"""One governed call produces one evidence record, however many times obsvr
got registered.

`obsvr.init()` auto-wires both of these frameworks whenever their package is
importable, and until now each integration's own docstring also told the reader
to register a handler. Following the documented setup therefore put TWO
handlers on the framework's registry and emitted every event twice, with
distinct request_ids that made the pair look like two real calls rather than
one call recorded twice.

That is the mechanism behind the double-emission observed against
llama-index-core: not double registration by the caller, and not a framework
firing its callback twice, but obsvr registering itself and then being
registered again by a caller following the instructions.

Duplicate evidence is a defect in its own right — it inflates any count taken
over the trail — and now that tokens are captured on these paths it would
double every cost and quota figure derived from them.
"""

import sys

import obsvr
from obsvr import sender
from obsvr.config import _reset
from obsvr.integrations.llamaindex import ObsvrLlamaIndexHandler
from obsvr.integrations.openai_agents import ObsvrTracingProcessor

EVENTS_MODULE = sys.modules["obsvr.events"]


def _init():
    _reset()
    sender._reset_sender()
    obsvr.init(api_key="k", ingest_url="http://localhost:9", sample_rate=1, disabled=False)


def _captured(monkeypatch):
    captured = []
    monkeypatch.setattr(
        EVENTS_MODULE.sender, "send_audit_async", lambda config, event: captured.append(event)
    )
    return captured


class _Span:
    """A completed Responses-path span."""

    def __init__(self):
        self.trace_id = "trace_1"
        self.span_data = self

    type = "response"
    input = [{"role": "user", "content": "2+2"}]
    usage = None
    response = {
        "id": "resp_1",
        "model": "gpt-4o-mini",
        "output": [{"content": [{"type": "output_text", "text": "four"}]}],
        "usage": {"input_tokens": 5, "output_tokens": 1},
    }


class TestOpenAIAgentsProcessor:
    def test_two_registered_processors_still_emit_one_record(self, monkeypatch):
        _init()
        captured = _captured(monkeypatch)

        # Exactly what the documented setup produces: init() built one, the
        # caller builds another, and the SDK's processor list is append-only.
        first = ObsvrTracingProcessor()
        second = ObsvrTracingProcessor()

        span = _Span()
        first.on_span_end(span)
        second.on_span_end(span)

        assert len(captured) == 1
        assert captured[0]["operation"] == "llm"

    def test_the_incumbent_is_the_one_that_emits(self, monkeypatch):
        _init()
        captured = _captured(monkeypatch)
        first = ObsvrTracingProcessor()
        second = ObsvrTracingProcessor()

        # The later arrival is inert on EVERY callback, not just span end.
        second.on_trace_start(type("T", (), {"trace_id": "t"})())
        second.on_trace_end(type("T", (), {"trace_id": "t"})())
        second.on_span_end(_Span())
        assert captured == []

        first.on_span_end(_Span())
        assert len(captured) == 1

    def test_a_reset_releases_the_slot(self, monkeypatch):
        # Otherwise the first handler any process ever built would hold the slot
        # forever and every later one would be silently dead.
        _init()
        ObsvrTracingProcessor()
        _init()
        captured = _captured(monkeypatch)
        ObsvrTracingProcessor().on_span_end(_Span())
        assert len(captured) == 1


class TestLlamaIndexHandler:
    def test_two_registered_handlers_still_emit_one_record(self, monkeypatch):
        _init()
        captured = _captured(monkeypatch)

        first = ObsvrLlamaIndexHandler()
        second = ObsvrLlamaIndexHandler()

        payload = {"messages": [{"role": "user", "content": "2+2"}]}
        for h in (first, second):
            h.on_event_start("llm", payload=payload, event_id="e1")
        for h in (first, second):
            h.on_event_end("llm", payload={"response": "four"}, event_id="e1")

        assert len(captured) == 1

    def test_the_later_handler_records_no_run_state_either(self, monkeypatch):
        # An inert handler must not accumulate per-event state; otherwise it
        # leaks a dict entry for every call it silently ignores.
        _init()
        _captured(monkeypatch)
        ObsvrLlamaIndexHandler()
        second = ObsvrLlamaIndexHandler()
        second.on_event_start("llm", payload={"messages": []}, event_id="e1")
        assert second._runs == {}
