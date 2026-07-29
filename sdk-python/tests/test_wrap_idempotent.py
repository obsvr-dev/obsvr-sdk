"""wrap() is idempotent, because the documentation leads callers to wrap twice.

`register.py` patches the openai and anthropic client classes at init(), so
`Anthropic()` already returns a governed client. Both READMEs then document
`obsvr.wrap(...)`. A caller who follows both — which is what the docs invite —
was wrapping a wrapped client, and every call emitted TWO audit events.

Found live: one `messages.create` through
`obsvr.wrap(anthropic.Anthropic(...))` produced two `messages.create` events.
TypeScript has always been protected by its WRAPPED_MARKER check; this side was
not, which made it a cross-language divergence as well as a defect.
"""

import obsvr
from obsvr.wrap import _ObsvrProxy


class FakeAnthropic:
    class _Messages:
        def create(self, **kw):
            return {"id": "msg_1", "content": [{"type": "text", "text": "ok"}],
                    "usage": {"input_tokens": 1, "output_tokens": 1}}

    def __init__(self):
        self.messages = self._Messages()


def _init():
    obsvr.init(api_key="k", ingest_url="http://localhost:9",
               policy_refresh_interval_s=0)


def test_wrapping_a_wrapped_client_returns_the_same_object():
    _init()
    once = obsvr.wrap(FakeAnthropic())
    twice = obsvr.wrap(once)
    assert twice is once, "wrap() must not wrap an already-governed client"


def test_a_wrapped_client_is_still_a_proxy():
    """The guard must not make wrap() a no-op for genuinely raw clients."""
    _init()
    assert isinstance(obsvr.wrap(FakeAnthropic()), _ObsvrProxy)


def test_a_second_wrap_does_not_nest_a_proxy_inside_a_proxy():
    """The mechanism behind the duplicate events, asserted directly.

    Two events per call came from two proxy layers each auditing the same
    call. The event COUNT is pinned by a live probe against a real client
    rather than here, because the `sent` fixture does not intercept this
    particular send path — asserting on an empty list would have been a test
    that passes for the wrong reason.
    """
    _init()
    once = obsvr.wrap(FakeAnthropic())
    twice = obsvr.wrap(once)
    inner = object.__getattribute__(twice, "_obsvr_target")
    assert not isinstance(inner, _ObsvrProxy), "a proxy was nested inside a proxy"
    assert isinstance(inner, FakeAnthropic)
