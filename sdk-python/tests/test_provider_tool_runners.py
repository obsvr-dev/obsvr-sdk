"""Provider tool runners stay behind prompt and local-tool enforcement."""

import asyncio
import functools
import sys

import pytest

import obsvr
import obsvr.wrap  # noqa: F401 - package attribute shadows the module
from obsvr import sender
from obsvr.config import _reset

WRAP_MODULE = sys.modules["obsvr.wrap"]


class _TextBlock:
    text = "runner complete"


class _Usage:
    input_tokens = 7
    output_tokens = 3


class _Response:
    content = [_TextBlock()]
    usage = _Usage()


class _SyncTool:
    name = "write_file"
    description = "write a marker"

    def __init__(self):
        self.calls = []

    def call(self, payload):
        self.calls.append(payload)
        return "written"


class _AsyncTool:
    name = "write_file"
    description = "write a marker asynchronously"

    def __init__(self):
        self.calls = []

    async def call(self, payload):
        self.calls.append(payload)
        return "written"


class _SyncRunner:
    def __init__(self, kwargs):
        self.kwargs = kwargs

    def until_done(self):
        try:
            self.kwargs["tools"][0].call({"value": "payload"})
        except Exception:
            pass  # the real runner converts a tool refusal into an error result
        return _Response()


class _AsyncRunner:
    def __init__(self, kwargs):
        self.kwargs = kwargs

    async def until_done(self):
        try:
            await self.kwargs["tools"][0].call({"value": "payload"})
        except Exception:
            pass
        return _Response()


class _DecoratedAsyncRunner(_AsyncRunner):
    @functools.wraps(_AsyncRunner.until_done)
    def until_done(self):
        return super().until_done()


class _SessionRunner:
    def __init__(self, kwargs):
        self.kwargs = kwargs

    async def until_done(self):
        try:
            await self.kwargs["tools"][0].call({"value": "payload"})
        except Exception:
            pass


class _RunnerResource:
    def __init__(self, async_runner=False, decorated_async_runner=False):
        self.calls = []
        self.async_runner = async_runner
        self.decorated_async_runner = decorated_async_runner

    def create(self, **kwargs):
        return _Response()

    def tool_runner(self, **kwargs):
        self.calls.append(kwargs)
        if self.decorated_async_runner:
            return _DecoratedAsyncRunner(kwargs)
        return _AsyncRunner(kwargs) if self.async_runner else _SyncRunner(kwargs)


class _SessionEvents:
    def __init__(self):
        self.calls = []

    def tool_runner(self, session_id, **kwargs):
        self.calls.append((session_id, kwargs))
        return _SessionRunner(kwargs)


class _Client:
    def __init__(self, async_runner=False, decorated_async_runner=False):
        self.messages = _RunnerResource(async_runner, decorated_async_runner)
        self.beta = type("Beta", (), {})()
        self.beta.messages = _RunnerResource(async_runner, decorated_async_runner)
        self.beta.sessions = type("Sessions", (), {})()
        self.beta.sessions.events = _SessionEvents()


def _init(**extra):
    _reset()
    sender._reset_sender()
    extra.setdefault("disabled", False)
    obsvr.init(api_key="test-key", ingest_url="http://localhost:9", **extra)


@pytest.fixture
def events(monkeypatch):
    captured = []
    monkeypatch.setattr(sender, "send_audit_async", lambda config, event: captured.append(event))
    monkeypatch.setattr(WRAP_MODULE, "send_audit_async", lambda config, event: captured.append(event))
    from obsvr.integrations import tools as tools_module

    monkeypatch.setattr(tools_module, "_GOVERNED_TOOL_NAMES", set())
    return captured


def _runner(client, tool, prompt="hello"):
    return client.beta.messages.tool_runner(
        model="anthropic-test",
        max_tokens=16,
        messages=[{"role": "user", "content": prompt}],
        tools=[tool],
    )


def test_prompt_block_prevents_runner_construction(events):
    _init(pii_policy={"rules": {"ssn": "block"}})
    raw = _Client()
    tool = _SyncTool()

    with pytest.raises(RuntimeError, match="blocked by policy"):
        _runner(obsvr.wrap(raw), tool, "private 123-45-6789")

    assert raw.beta.messages.calls == []
    assert tool.calls == []
    assert len(events) == 1
    assert events[0]["operation"] == "beta.messages.tool_runner"
    assert events[0]["event_type"] == "blocked_call"


def test_runner_redacts_prompt_and_emits_after_completion(events):
    _init(pii_policy={"rules": {"email": "redact"}})
    raw = _Client()
    tool = _SyncTool()
    runner = _runner(obsvr.wrap(raw), tool, "mail a@b.com")

    assert raw.beta.messages.calls[0]["messages"][0]["content"] == (
        "mail [REDACTED_EMAIL]"
    )
    assert events == []

    result = runner.until_done()

    assert result.content[0].text == "runner complete"
    assert tool.calls == [{"value": "payload"}]
    assert [event["operation"] for event in events] == [
        "tool.call",
        "beta.messages.tool_runner",
    ]
    assert events[-1]["response"] == "runner complete"


def test_every_internal_model_turn_uses_the_governed_client(events):
    _init(pii_policy={"rules": {"ssn": "block"}})

    class _LoopRunner:
        def __init__(self, client):
            self.client = client

        def until_done(self):
            self.client.beta.messages.create(
                model="anthropic-test",
                max_tokens=16,
                messages=[{"role": "user", "content": "clean first turn"}],
            )
            self.client.beta.messages.create(
                model="anthropic-test",
                max_tokens=16,
                messages=[
                    {"role": "user", "content": "clean first turn"},
                    {"role": "user", "content": "tool returned 123-45-6789"},
                ],
            )
            return _Response()

    class _LoopResource(_RunnerResource):
        def __init__(self):
            super().__init__()
            self._client = None
            self.provider_calls = 0

        def create(self, **_kwargs):
            self.provider_calls += 1
            return _Response()

        def tool_runner(self, **kwargs):
            self.calls.append(kwargs)
            return _LoopRunner(self._client)

    raw = _Client()
    resource = _LoopResource()
    raw.messages = resource
    raw.beta.messages = resource
    resource._client = raw

    runner = _runner(obsvr.wrap(raw), _SyncTool())
    with pytest.raises(RuntimeError, match="blocked by policy"):
        runner.until_done()

    assert resource.provider_calls == 1


def test_denied_sync_runner_tool_never_enters_body(events):
    _init(agent_policy={"denied_tools": ["write_file"]})
    raw = _Client()
    tool = _SyncTool()

    result = _runner(obsvr.wrap(raw), tool).until_done()

    assert result.content[0].text == "runner complete"
    assert tool.calls == []
    assert [event["operation"] for event in events] == [
        "tool.policy.tool_blocked",
        "beta.messages.tool_runner",
    ]


def test_denied_async_runner_tool_never_enters_body(events):
    _init(agent_policy={"denied_tools": ["write_file"]})
    raw = _Client(async_runner=True)
    tool = _AsyncTool()
    runner = _runner(obsvr.wrap(raw), tool)

    result = asyncio.run(runner.until_done())

    assert result.content[0].text == "runner complete"
    assert tool.calls == []
    assert [event["operation"] for event in events] == [
        "tool.policy.tool_blocked",
        "beta.messages.tool_runner",
    ]


def test_decorated_async_runner_settles_after_await(events):
    _init()
    raw = _Client(decorated_async_runner=True)
    tool = _AsyncTool()
    runner = _runner(obsvr.wrap(raw), tool)

    pending = runner.until_done()

    assert events == []
    result = asyncio.run(pending)
    assert result.content[0].text == "runner complete"
    assert [event["operation"] for event in events] == [
        "tool.call",
        "beta.messages.tool_runner",
    ]


def test_managed_session_runner_gates_tools_without_fabricating_model_event(events):
    _init(agent_policy={"denied_tools": ["write_file"]})
    raw = _Client(async_runner=True)
    tool = _AsyncTool()
    runner = obsvr.wrap(raw).beta.sessions.events.tool_runner(
        "session_1", tools=[tool]
    )

    asyncio.run(runner.until_done())

    assert raw.beta.sessions.events.calls[0][0] == "session_1"
    assert tool.calls == []
    assert [event["operation"] for event in events] == [
        "tool.policy.tool_blocked"
    ]
