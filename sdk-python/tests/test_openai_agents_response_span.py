"""The Responses-path span, which is the DEFAULT path and was emitting nothing.

`agents.models._openai_shared.get_use_responses_by_default()` returns True, so
an ordinary agent run produces spans of type `response`. The processor handled
only `function` and `generation`, so on the default configuration every LLM call
was dropped: no prompt, no response, no model, no tokens. Run-start, run-finish
and tool-call events still arrived, which is what made it invisible — the trail
looked populated while the model calls, the thing actually being governed, were
absent.

The fakes below duck-type ResponseSpanData as the installed SDK defines it
(fields: response, input, usage) and the OpenAI Response body it carries.
"""

import sys

import obsvr
import obsvr.integrations.openai_agents  # noqa: F401
from obsvr import sender
from obsvr.config import _reset
from obsvr.integrations.openai_agents import ObsvrTracingProcessor

EVENTS_MODULE = sys.modules["obsvr.events"]


# ── Fakes shaped like the real span payloads ────────────────────────────────

class _ContentBlock:
    def __init__(self, text):
        self.type = "output_text"
        self.text = text


class _OutputItem:
    def __init__(self, text):
        self.type = "message"
        self.role = "assistant"
        self.content = [_ContentBlock(text)]


class _Usage:
    def __init__(self, i, o, t):
        self.input_tokens = i
        self.output_tokens = o
        self.total_tokens = t


class _Response:
    """Duck-types the openai Response body the Agents SDK stores on the span."""

    def __init__(self, model="gpt-4o-mini-2024-07-18", text="four", usage=None):
        self.id = "resp_abc123"
        self.model = model
        self.output = [_OutputItem(text)]
        self.usage = usage if usage is not None else _Usage(21, 2, 23)


class _ResponseSpanData:
    """agents.tracing.span_data.ResponseSpanData: (response, input, usage)."""

    type = "response"

    def __init__(self, response, raw_input):
        self.response = response
        self.input = raw_input
        self.usage = None


class _GenerationSpanData:
    type = "generation"

    def __init__(self, model, raw_input, raw_output, usage=None):
        self.model = model
        self.input = raw_input
        self.output = raw_output
        self.usage = usage


class _Span:
    def __init__(self, span_data, trace_id="trace_1"):
        self.span_data = span_data
        self.trace_id = trace_id


# ── Helpers ─────────────────────────────────────────────────────────────────

def _init(**extra):
    _reset()
    sender._reset_sender()
    extra.setdefault("disabled", False)
    obsvr.init(api_key="test-key", ingest_url="http://localhost:9", sample_rate=1, **extra)


def _captured(monkeypatch):
    captured = []
    monkeypatch.setattr(
        EVENTS_MODULE.sender, "send_audit_async", lambda config, event: captured.append(event)
    )
    return captured


# ── Tests ───────────────────────────────────────────────────────────────────

class TestResponseSpanIsAudited:
    def test_a_response_span_emits_a_complete_llm_event(self, monkeypatch):
        _init()
        captured = _captured(monkeypatch)
        proc = ObsvrTracingProcessor()

        proc.on_span_end(
            _Span(
                _ResponseSpanData(
                    _Response(),
                    [{"role": "user", "content": "what is 2+2"}],
                )
            )
        )

        assert len(captured) == 1
        ev = captured[0]
        assert ev["operation"] == "llm"
        assert ev["provider"] == "openai"
        assert ev["source"] == "openai_agents_py"
        assert ev["model"] == "gpt-4o-mini-2024-07-18"
        assert ev["prompt"] == "user: what is 2+2"
        assert ev["response"] == "four"
        assert ev["input_tokens"] == 21
        assert ev["output_tokens"] == 2
        assert ev["total_tokens"] == 23
        assert ev["metadata"]["agent_run_id"] == "trace_1"
        assert ev["metadata"]["response_id"] == "resp_abc123"

    def test_the_missing_alias_is_stated_not_left_to_be_inferred(self, monkeypatch):
        # On this path `model` necessarily holds the served snapshot: the span
        # carries only (response, input, usage), so the configured alias is not
        # observable anywhere in the trace. Saying so beats letting a reader
        # guess from model == model_resolved, which is also what a caller who
        # genuinely pinned a snapshot would produce.
        _init()
        captured = _captured(monkeypatch)
        ObsvrTracingProcessor().on_span_end(
            _Span(_ResponseSpanData(_Response(), [{"role": "user", "content": "hi"}]))
        )
        assert captured[0]["metadata"]["model_alias_unavailable"] is True

    def test_dict_shaped_span_payloads_are_read_too(self, monkeypatch):
        _init()
        captured = _captured(monkeypatch)

        class _DictSpanData:
            type = "response"
            response = {
                "id": "resp_1",
                "model": "gpt-4o-mini",
                "output": [
                    {"content": [{"type": "output_text", "text": "four"}]},
                ],
                "usage": {"input_tokens": 5, "output_tokens": 1},
            }
            input = [{"role": "user", "content": "2+2"}]
            usage = None

        ObsvrTracingProcessor().on_span_end(_Span(_DictSpanData()))
        ev = captured[0]
        assert ev["model"] == "gpt-4o-mini"
        assert ev["prompt"] == "user: 2+2"
        assert ev["response"] == "four"
        assert ev["input_tokens"] == 5
        assert ev["total_tokens"] == 6

    def test_absent_usage_leaves_counts_absent_never_zero(self, monkeypatch):
        _init()
        captured = _captured(monkeypatch)
        resp = _Response()
        resp.usage = None
        ObsvrTracingProcessor().on_span_end(
            _Span(_ResponseSpanData(resp, [{"role": "user", "content": "hi"}]))
        )
        ev = captured[0]
        # The builder drops an unknown count entirely rather than writing null,
        # which is the strongest form of "absent": there is no field for a
        # reader to mistake for a measurement.
        assert "input_tokens" not in ev
        assert "output_tokens" not in ev
        assert "total_tokens" not in ev


class TestGenerationSpanStillWorks:
    def test_the_chat_completions_path_is_unchanged_and_now_carries_tokens(self, monkeypatch):
        _init()
        captured = _captured(monkeypatch)

        ObsvrTracingProcessor().on_span_end(
            _Span(
                _GenerationSpanData(
                    model="gpt-4o-mini",
                    raw_input=[{"role": "user", "content": "2+2"}],
                    raw_output=[{"role": "assistant", "content": "four"}],
                    usage={"input_tokens": 7, "output_tokens": 1},
                )
            )
        )

        ev = captured[0]
        assert ev["operation"] == "llm"
        # The generation span carries the CONFIGURED alias, which is what the
        # schema wants — so no substitution marker belongs on this branch.
        assert ev["model"] == "gpt-4o-mini"
        assert "model_alias_unavailable" not in ev["metadata"]
        assert ev["input_tokens"] == 7
        assert ev["total_tokens"] == 8


class TestSpanTypesStayInTheirLanes:
    def test_an_unhandled_span_type_still_emits_nothing(self, monkeypatch):
        _init()
        captured = _captured(monkeypatch)

        class _GuardrailSpanData:
            type = "guardrail"
            triggered = False

        ObsvrTracingProcessor().on_span_end(_Span(_GuardrailSpanData()))
        assert captured == []
