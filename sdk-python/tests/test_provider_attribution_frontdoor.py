"""The front door must record where the call actually went.

Twin: sdk-typescript/tests/unit/provider-attribution-frontdoor.test.ts.

THE DEFECT. ``obsvr.wrap()`` labelled through ``_detect_provider()``, which
duck-types on the client's shape: anything exposing ``chat.completions`` is
"openai", whatever host it points at. Measured live against a local server
before this change, the event read ``provider: "openai"`` with
``model: "qwen2.5-coder:14b"`` - a model that endpoint does not serve, sitting
beside a vendor the request never reached, in the field a compliance reviewer
reads for data residency.

NON-VACUITY. ``test_records_the_vendor_when_the_call_really_goes_there`` is the
control: a fix that simply stopped saying "openai" would satisfy every other
assertion here and fail that one.
``test_keeps_duck_typed_label_when_no_base_url`` is the second control - it
fails if attribution is dropped rather than qualified.

The shape/destination split is asserted at the bottom, because collapsing those
two back into one field is the specific regression that would reintroduce this
defect while every label assertion above still passed.
"""

import sys

import pytest

import obsvr
import obsvr.wrap  # ensure module is loaded; package attr shadows it
from obsvr.config import _reset

WRAP_MODULE = sys.modules["obsvr.wrap"]


class _Usage:
    prompt_tokens = 7
    completion_tokens = 5
    total_tokens = 12


class _Message:
    content = "fake answer"


class _Choice:
    message = _Message()


class _Response:
    choices = [_Choice()]
    usage = _Usage()


class _Completions:
    def create(self, **kwargs):
        return _Response()


class _Chat:
    def __init__(self):
        self.completions = _Completions()


class OpenAIShapedClient:
    """Reports a base_url the way the real client does."""

    def __init__(self, base_url=None):
        self.chat = _Chat()
        self.api_key = "not-a-real-key"
        if base_url is not None:
            self.base_url = base_url


class _AnthropicMessages:
    def create(self, **kwargs):
        return type(
            "R",
            (),
            {
                "id": "msg_1",
                "model": "claude-x",
                "content": [type("B", (), {"type": "text", "text": "fake answer"})()],
                "usage": type("U", (), {"input_tokens": 11, "output_tokens": 3})(),
            },
        )()


class AnthropicShapedClient:
    def __init__(self, base_url=None):
        self.messages = _AnthropicMessages()
        self.api_key = "not-a-real-key"
        if base_url is not None:
            self.base_url = base_url


@pytest.fixture
def captured(monkeypatch):
    events = []
    monkeypatch.setattr(
        WRAP_MODULE, "send_audit_async", lambda config, event: events.append(event)
    )
    return events


def _init():
    _reset()
    obsvr.init(
        api_key="k",
        ingest_url="https://ingest.example",
        environment="development",
        sample_rate=1,
    )


def _call_openai_shaped(base_url=None):
    _init()
    client = obsvr.wrap(OpenAIShapedClient(base_url))
    client.chat.completions.create(
        model="qwen2.5-coder:14b", messages=[{"role": "user", "content": "hi"}]
    )


class TestFrontDoorDestination:
    def test_does_not_name_a_vendor_for_a_local_endpoint(self, captured):
        _call_openai_shaped("http://localhost:11434/v1")
        ev = captured[0]
        assert ev["provider"] != "openai"
        assert ev["provider"] == "unknown"
        assert ev["metadata"]["provider_detail"] == "local"
        assert ev["metadata"]["endpoint_host"] == "localhost:11434"
        assert ev["metadata"]["provider_attribution"] == "endpoint"

    def test_records_the_vendor_when_the_call_really_goes_there(self, captured):
        """CONTROL: stopping saying "openai" everywhere must not satisfy this."""
        _call_openai_shaped("https://api.openai.com/v1")
        ev = captured[0]
        assert ev["provider"] == "openai"
        assert ev["metadata"]["provider_detail"] == "openai"
        assert ev["metadata"]["endpoint_host"] == "api.openai.com"
        assert ev["metadata"]["provider_attribution"] == "endpoint"

    def test_keeps_duck_typed_label_when_no_base_url(self, captured):
        """CONTROL: attribution is qualified, not dropped."""
        _call_openai_shaped(None)
        ev = captured[0]
        assert ev["provider"] == "openai"
        assert ev["metadata"]["provider_attribution"] == "client_declared"
        assert "endpoint_host" not in ev["metadata"]

    def test_unknown_not_a_guess_for_a_host_it_cannot_name(self, captured):
        _call_openai_shaped("https://llm.internal.example.com/v1")
        ev = captured[0]
        assert ev["provider"] == "unknown"
        assert ev["metadata"]["provider_detail"] == "unrecognized_endpoint"
        assert ev["metadata"]["endpoint_host"] == "llm.internal.example.com"

    def test_names_a_vendor_the_canonical_enum_cannot_express(self, captured):
        _call_openai_shaped("https://api.groq.com/openai/v1")
        ev = captured[0]
        assert ev["provider"] == "unknown"
        assert ev["metadata"]["provider_detail"] == "groq"
        assert ev["metadata"]["endpoint_host"] == "api.groq.com"

    def test_no_base_url_credential_reaches_the_record(self, captured):
        import json

        _call_openai_shaped("https://user:sk-secret-token@api.openai.com/v1")
        blob = json.dumps(captured[0])
        assert "sk-secret-token" not in blob
        assert captured[0]["metadata"]["endpoint_host"] == "api.openai.com"

    def test_base_url_may_be_a_url_object_not_a_string(self, captured):
        """The modern client exposes base_url as a URL object, not a str."""

        class _URLish:
            def __str__(self):
                return "http://localhost:11434/v1"

        _init()
        client = obsvr.wrap(OpenAIShapedClient(_URLish()))
        client.chat.completions.create(
            model="qwen2.5-coder:14b", messages=[{"role": "user", "content": "hi"}]
        )
        assert captured[0]["metadata"]["endpoint_host"] == "localhost:11434"

    def test_a_raising_base_url_property_is_a_non_answer_not_a_crash(self, captured):
        class Hostile(OpenAIShapedClient):
            @property
            def base_url(self):
                raise RuntimeError("nope")

        _init()
        client = obsvr.wrap(Hostile())
        client.chat.completions.create(
            model="m", messages=[{"role": "user", "content": "hi"}]
        )
        # The call still happened and was still recorded; the label falls back.
        assert captured[0]["provider"] == "openai"
        assert captured[0]["metadata"]["provider_attribution"] == "client_declared"


class TestShapeAndDestinationStaySeparate:
    def test_anthropic_shaped_client_on_a_local_host_keeps_its_extractor(
        self, captured
    ):
        _init()
        client = obsvr.wrap(AnthropicShapedClient("http://localhost:8080/v1"))
        client.messages.create(
            model="claude-x", messages=[{"role": "user", "content": "hi there"}]
        )
        ev = captured[0]

        # The destination is recorded honestly...
        assert ev["provider"] == "unknown"
        assert ev["metadata"]["provider_detail"] == "local"

        # ...and the Anthropic extractor still ran, which is what proves the
        # shape was not overwritten by the destination. If one variable answered
        # both questions again, the token counts would be missing here.
        assert "hi there" in ev["prompt"]
        assert ev["input_tokens"] == 11
        assert ev["output_tokens"] == 3
