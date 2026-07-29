"""A governed stream is still a stream, not a bare generator.

THE DEFECT. The streaming paths in ``wrap.py`` are generator functions, and the
call sites returned one directly — so a caller got a plain generator where the
provider's contract promises a stream object. A provider stream is also a context
manager, so the documented and extremely common shape::

    with client.chat.completions.create(..., stream=True) as stream:
        for chunk in stream: ...

raised ``TypeError: 'generator' object does not support the context manager
protocol`` as soon as obsvr was in the path. Calling ``obsvr.init()`` before
constructing a client was enough to break every caller written that way, LangChain
streaming included, since that is the form it uses.

This is not a governance defect and it does not put a false verdict on the
record — it breaks working code, which is why it is treated as a hotfix rather
than as part of the enforcement work. It also predates the current branch.

The subtle half is ``close()``. A bare generator HAS a ``close()``, so the old
return value satisfied ``hasattr(stream, "close")`` and any duck-typed cleanup —
while closing only the generator and leaving the provider's HTTP response open.
"""

import asyncio
import sys
import types

import pytest

import obsvr
import obsvr.wrap  # ensure the module is loaded; the package attr shadows it
from obsvr import sender
from obsvr.config import _reset

WRAP_MODULE = sys.modules["obsvr.wrap"]


def _chunk(text):
    return types.SimpleNamespace(
        choices=[types.SimpleNamespace(delta=types.SimpleNamespace(content=text))],
        usage=None,
    )


class FakeStream:
    """Shaped like a provider stream: iterable AND a context manager."""

    def __init__(self, parts=("Hello ", "world")):
        self.parts = parts
        self.entered = False
        self.exited = False
        self.closed = False

    def __iter__(self):
        for part in self.parts:
            yield _chunk(part)

    def __enter__(self):
        self.entered = True
        return self

    def __exit__(self, *exc_info):
        self.exited = True
        return False

    def close(self):
        self.closed = True

    @property
    def response(self):
        return "the-real-http-response"


class FakeAsyncStream:
    def __init__(self, parts=("Hello ", "world")):
        self.parts = parts
        self.entered = False
        self.exited = False

    async def __aiter__(self):
        for part in self.parts:
            yield _chunk(part)

    async def __aenter__(self):
        self.entered = True
        return self

    async def __aexit__(self, *exc_info):
        self.exited = True
        return False


def _client(stream):
    class _Completions:
        def create(self, **kwargs):
            return stream

    class _Chat:
        def __init__(self):
            self.completions = _Completions()

    class FakeOpenAI:
        def __init__(self):
            self.chat = _Chat()

    return FakeOpenAI()


def _async_client(stream):
    class _Completions:
        async def create(self, **kwargs):
            return stream

    class _Chat:
        def __init__(self):
            self.completions = _Completions()

    class FakeAsyncOpenAI:
        def __init__(self):
            self.chat = _Chat()

    return FakeAsyncOpenAI()


@pytest.fixture
def captured(monkeypatch):
    """``wrap.py`` binds ``send_audit_async`` by name, so patch it there."""
    events = []
    monkeypatch.setattr(
        WRAP_MODULE, "send_audit_async", lambda config, event: events.append(event)
    )
    return events


@pytest.fixture(autouse=True)
def _clean():
    _reset()
    sender._reset_sender()
    yield
    _reset()
    sender._reset_sender()


def _start(stream):
    obsvr.init(api_key="test", ingest_url="http://localhost:9", sample_rate=1)
    client = obsvr.wrap(_client(stream))
    return client.chat.completions.create(
        model="gpt-4o", messages=[{"role": "user", "content": "hi"}], stream=True
    )


# ── the reported break ───────────────────────────────────────────────────────


def test_a_governed_stream_supports_with(captured):
    raw = FakeStream()
    governed = _start(raw)

    with governed as stream:
        text = "".join(c.choices[0].delta.content for c in stream)

    assert text == "Hello world"
    assert raw.entered and raw.exited, (
        "the provider's own context manager must run — that is where the HTTP "
        "response gets closed"
    )


def test_chunks_inside_the_with_block_are_still_audited(captured):
    """``__enter__`` must hand back the GOVERNED object, not the raw stream.

    Returning the provider's own object would make `with` work and quietly stop
    accumulating, so the audit event would record an empty response for a stream
    that produced text. That failure is worse than the TypeError, because it looks
    like success.
    """
    governed = _start(FakeStream())

    with governed as stream:
        for _ in stream:
            pass

    assert len(captured) == 1
    assert captured[0]["response"] == "Hello world"


def test_iterating_without_with_still_works(captured):
    """The shape that worked before must keep working."""
    governed = _start(FakeStream())

    text = "".join(c.choices[0].delta.content for c in governed)

    assert text == "Hello world"
    assert len(captured) == 1
    assert captured[0]["response"] == "Hello world"


def test_next_works_directly(captured):
    governed = _start(FakeStream())

    first = next(iter(governed))

    assert first.choices[0].delta.content == "Hello "


# ── delegation ───────────────────────────────────────────────────────────────


def test_other_attributes_reach_the_real_stream(captured):
    governed = _start(FakeStream())

    assert governed.response == "the-real-http-response"


def test_close_closes_the_provider_stream_not_just_the_generator(captured):
    """A generator's own ``close()`` satisfied ``hasattr`` and closed nothing.

    That is why this is asserted on the underlying object rather than on the
    absence of an exception.
    """
    raw = FakeStream()
    governed = _start(raw)

    governed.close()

    assert raw.closed is True


def test_a_stream_with_no_context_manager_still_exits_cleanly(captured):
    """Not every OpenAI-compatible client's stream is a context manager.

    Entering one that is not must not raise, and exiting must fall back to
    ``close()`` so the response is not left open.
    """

    class PlainStream:
        def __init__(self):
            self.closed = False

        def __iter__(self):
            yield _chunk("ok")

        def close(self):
            self.closed = True

    raw = PlainStream()
    governed = _start(raw)

    with governed as stream:
        list(stream)

    assert raw.closed is True


# ── async twin ───────────────────────────────────────────────────────────────


def test_a_governed_async_stream_supports_async_with(captured):
    raw = FakeAsyncStream()

    async def go():
        obsvr.init(api_key="test", ingest_url="http://localhost:9", sample_rate=1)
        client = obsvr.wrap(_async_client(raw))
        governed = await client.chat.completions.create(
            model="gpt-4o", messages=[{"role": "user", "content": "hi"}], stream=True
        )
        async with governed as stream:
            return "".join([c.choices[0].delta.content async for c in stream])

    text = asyncio.run(go())

    assert text == "Hello world"
    assert raw.entered and raw.exited
    assert len(captured) == 1
    assert captured[0]["response"] == "Hello world"


def test_async_iteration_without_async_with_still_works(captured):
    async def go():
        obsvr.init(api_key="test", ingest_url="http://localhost:9", sample_rate=1)
        client = obsvr.wrap(_async_client(FakeAsyncStream()))
        governed = await client.chat.completions.create(
            model="gpt-4o", messages=[{"role": "user", "content": "hi"}], stream=True
        )
        return "".join([c.choices[0].delta.content async for c in governed])

    assert asyncio.run(go()) == "Hello world"
