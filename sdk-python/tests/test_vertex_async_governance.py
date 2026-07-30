"""`generate_content_async` was governed and never awaited.

It sits in `_GOVERNED_METHODS`, and the governed wrapper is a plain `def` — this
module contained ZERO awaits, which is how one function covered both a sync and
an async provider method. So the coroutine was handed straight to the response
extractor: empty response text, null token counts, a post-call policy that ran
over `""` and therefore never saw the answer, and an event claiming SUCCESS for
a call that had not happened yet. The caller then awaited the coroutine
themselves and got an ungoverned answer.

Pre-call enforcement always survived — the block is decided before the provider
is called at all — so this was never an enforcement hole. It is a record hole,
and that is the distinction these tests are shaped around: the assertions are
about what the EVENT says, plus one that the caller still receives the real
answer.

**NOT LIVE-VERIFIED, and that is a property of the host rather than of the fix.**
Vertex needs GCP service-account credentials, which do not exist on the machine
this was written on; a Gemini API key authenticates a different product and
would not exercise this path. Substituting the Gemini SDK to manufacture a live
run would have produced the first fabricated verification in this effort, so it
was not done. These fakes duck-type the response shape the module reads.
"""
import asyncio
import sys

import pytest

import obsvr
from obsvr import sender
from obsvr.config import _reset
from obsvr.integrations.vertex import wrap_vertex

EVENTS_MODULE = sys.modules["obsvr.events"]

SSN = "123-45-6789"


class _Part:
    def __init__(self, text):
        self.text = text


class _Content:
    def __init__(self, text):
        self.parts = [_Part(text)]


class _Candidate:
    def __init__(self, text):
        self.content = _Content(text)


class _Usage:
    prompt_token_count = 11
    candidates_token_count = 7
    total_token_count = 18


class _Response:
    """Duck-types the Vertex GenerationResponse the module reads."""

    def __init__(self, text):
        self.text = text
        self.candidates = [_Candidate(text)]
        self.usage_metadata = _Usage()


class _AsyncModel:
    """A model whose async method behaves like the real one: it returns a
    coroutine, and the answer exists only once that coroutine is awaited."""

    _model_name = "publishers/google/models/gemini-1.5-pro"

    def __init__(self, answer="the answer is four"):
        self.answer = answer
        self.calls = []

    def generate_content(self, contents, **kw):
        self.calls.append(contents)
        return _Response(self.answer)

    async def generate_content_async(self, contents, **kw):
        self.calls.append(contents)
        await asyncio.sleep(0)
        return _Response(self.answer)


def _init(**extra):
    _reset()
    sender._reset_sender()
    obsvr.init(api_key="k", ingest_url="http://localhost:9", sample_rate=1,
               policy_refresh_interval_s=0, **extra)


@pytest.fixture
def captured(monkeypatch):
    events = []
    monkeypatch.setattr(EVENTS_MODULE.sender, "send_audit_async",
                        lambda config, event: events.append(event))
    return events


class TestTheAsyncMethodIsAwaited:
    def test_the_event_carries_the_real_response(self, captured):
        _init()
        model = wrap_vertex(_AsyncModel())
        out = asyncio.run(model.generate_content_async("what is 2+2?"))

        assert out.text == "the answer is four"          # the caller still gets it
        assert len(captured) == 1
        assert captured[0]["response"] == "the answer is four"

    def test_the_event_carries_real_token_counts(self, captured):
        _init()
        model = wrap_vertex(_AsyncModel())
        asyncio.run(model.generate_content_async("what is 2+2?"))
        assert captured[0]["total_tokens"] == 18

    def test_response_side_policy_sees_the_answer(self, captured):
        # The load-bearing one. Post-call policy ran over "" before, so it never
        # saw the answer at all.
        #
        # `SSN not in response` alone is VACUOUS here and the non-vacuity run
        # caught it: pre-fix the recorded response was the empty string, which
        # contains no SSN, so the assertion passed for exactly the wrong reason.
        # What distinguishes the two states is that the response is PRESENT and
        # has been scrubbed.
        _init(pii_policy={"rules": {"ssn": "redact"}})
        model = wrap_vertex(_AsyncModel(answer=f"the ssn is {SSN}"))
        asyncio.run(model.generate_content_async("what is on file?"))

        recorded = str(captured[0]["response"])
        assert recorded != "", "the response never reached the record at all"
        assert "the ssn is" in recorded, "the answer is missing, not redacted"
        assert SSN not in recorded

    def test_a_failure_inside_the_coroutine_is_recorded(self, captured):
        # A coroutine raises when awaited, not when created, so the synchronous
        # try/except around the call could never see this.
        class _Boom(_AsyncModel):
            async def generate_content_async(self, contents, **kw):
                raise RuntimeError("upstream exploded")

        _init()
        model = wrap_vertex(_Boom())
        with pytest.raises(RuntimeError):
            asyncio.run(model.generate_content_async("hello"))

        assert len(captured) == 1
        assert captured[0]["success"] is False


class TestTheControls:
    def test_the_sync_method_is_unchanged(self, captured):
        # Same assertions against the path that always worked, so a regression
        # there cannot hide behind the async fix.
        _init()
        model = wrap_vertex(_AsyncModel())
        out = model.generate_content("what is 2+2?")
        assert out.text == "the answer is four"
        assert captured[0]["response"] == "the answer is four"
        assert captured[0]["total_tokens"] == 18

    def test_pre_call_enforcement_still_blocks_before_the_provider(self, captured):
        # This never broke, and the fix must not change it: the refusal happens
        # before the coroutine is created at all.
        _init(pii_policy={"rules": {"ssn": "block"}})
        raw = _AsyncModel()
        model = wrap_vertex(raw)
        with pytest.raises(Exception):
            asyncio.run(model.generate_content_async(f"the ssn is {SSN}"))
        assert raw.calls == []      # the provider was never reached
        assert captured[0]["action_taken"] == "blocked"
