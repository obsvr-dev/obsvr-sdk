"""One governed call produces one evidence record, however many times obsvr got
registered — and still produces one when a caller replaces the registry.

`obsvr.init()` auto-wires the frameworks that offer a clean global registration
point, and until now each integration's own docstring also told the reader to
register a handler. Following the documented setup therefore put TWO handlers on
the framework's registry and emitted every event twice, with distinct
request_ids that made the pair look like two real calls. That is the mechanism
behind the double-emission observed against llama-index-core: not double
registration by the caller, and not a framework firing its callback twice, but
obsvr registering itself and then being registered again by a caller following
the instructions.

WHY THE DEDUPE IS KEYED ON THE EVENT AND NOT ON THE HANDLER. The obvious fix is
to let the first-registered handler win and make later ones inert. That is
wrong in the dangerous direction, and the last test here is the reason: a caller
who does `Settings.callback_manager = CallbackManager([handler])` REPLACES the
manager obsvr auto-wired into, so the incumbent is detached and never fires
while the caller's handler is inert. Zero events, from a fix meant to prevent
two. The question is not which handler may speak but whether this particular
call has already been recorded.
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
    """A completed Responses-path span. Carries span_id, as the real one does —
    that id is what the two processors deduplicate on."""

    type = "response"
    input = [{"role": "user", "content": "2+2"}]
    usage = None
    response = {
        "id": "resp_1",
        "model": "gpt-4o-mini",
        "output": [{"content": [{"type": "output_text", "text": "four"}]}],
        "usage": {"input_tokens": 5, "output_tokens": 1},
    }

    def __init__(self, span_id="span_1"):
        self.trace_id = "trace_1"
        self.span_id = span_id
        self.span_data = self


class _Trace:
    def __init__(self, trace_id="trace_1"):
        self.trace_id = trace_id


class TestOpenAIAgentsProcessor:
    def test_two_registered_processors_record_the_span_once(self, monkeypatch):
        _init()
        captured = _captured(monkeypatch)

        # Exactly what the documented setup produced: init() built one, the
        # caller builds another, and the SDK's processor list is append-only so
        # both receive every callback.
        first, second = ObsvrTracingProcessor(), ObsvrTracingProcessor()
        span = _Span()
        first.on_span_end(span)
        second.on_span_end(span)

        assert len(captured) == 1
        assert captured[0]["operation"] == "llm"

    def test_run_lifecycle_events_are_recorded_once_too(self, monkeypatch):
        _init()
        captured = _captured(monkeypatch)
        first, second = ObsvrTracingProcessor(), ObsvrTracingProcessor()

        for p in (first, second):
            p.on_trace_start(_Trace())
        for p in (first, second):
            p.on_trace_end(_Trace())

        ops = [e["operation"] for e in captured]
        assert ops == [
            "openai_agents.agent.run.start",
            "openai_agents.agent.run.finish",
        ]

    def test_a_genuinely_different_span_is_still_recorded(self, monkeypatch):
        # Dedupe must not swallow real work: two distinct spans are two records.
        _init()
        captured = _captured(monkeypatch)
        proc = ObsvrTracingProcessor()
        proc.on_span_end(_Span("span_1"))
        proc.on_span_end(_Span("span_2"))
        assert len(captured) == 2

    def test_a_span_with_no_id_is_recorded_rather_than_dropped(self, monkeypatch):
        # With nothing stable to key on, emitting is the right default: a
        # duplicate record is a lesser fault than a dropped one.
        _init()
        captured = _captured(monkeypatch)
        span = _Span()
        del span.span_id
        ObsvrTracingProcessor().on_span_end(span)
        assert len(captured) == 1


class TestLlamaIndexHandler:
    def _fire(self, handler, event_id="e1"):
        handler.on_event_start(
            "llm", payload={"messages": [{"role": "user", "content": "2+2"}]}, event_id=event_id
        )
        handler.on_event_end("llm", payload={"response": "four"}, event_id=event_id)

    def test_two_registered_handlers_record_the_call_once(self, monkeypatch):
        _init()
        captured = _captured(monkeypatch)

        first, second = ObsvrLlamaIndexHandler(), ObsvrLlamaIndexHandler()
        payload = {"messages": [{"role": "user", "content": "2+2"}]}
        for h in (first, second):
            h.on_event_start("llm", payload=payload, event_id="e1")
        for h in (first, second):
            h.on_event_end("llm", payload={"response": "four"}, event_id="e1")

        assert len(captured) == 1

    def test_distinct_calls_are_still_recorded_separately(self, monkeypatch):
        _init()
        captured = _captured(monkeypatch)
        h = ObsvrLlamaIndexHandler()
        self._fire(h, "e1")
        self._fire(h, "e2")
        assert len(captured) == 2

    def test_a_handler_on_a_REPLACED_manager_still_records(self, monkeypatch):
        """The regression a handler-identity guard would have introduced.

        A caller who builds their own CallbackManager detaches the handler
        obsvr auto-wired. If the rule were "the first handler registered wins",
        the detached incumbent would hold the slot and the caller's handler —
        the only one actually receiving callbacks — would be silently inert.
        Nothing would be recorded at all, which is worse than the duplicate the
        rule was meant to prevent.
        """
        _init()
        captured = _captured(monkeypatch)

        detached = ObsvrLlamaIndexHandler()  # stands in for the auto-wired one
        attached = ObsvrLlamaIndexHandler()  # the one the caller actually uses
        assert detached is not attached

        self._fire(attached, "e1")

        assert len(captured) == 1
        assert captured[0]["operation"] == "llamaindex.llm"
