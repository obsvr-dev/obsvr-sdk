"""The wrap() coverage boundary, pinned. Parity with
sdk-typescript/tests/unit/coverage-boundary.test.ts.

Two things had no regression guard before this file existed: which method paths
are audited, and that a path outside the list stays outside it. ``beta`` was not
even in the traversal set here, so ``client.beta`` was handed back raw and every
path beneath it was unreachable — a stricter version of the same gap the
TypeScript proxy had. Nothing failed when that was true, and nothing would fail
if the list silently widened either.
"""
import sys

import pytest

import obsvr
import obsvr.wrap  # noqa: F401 - ensure module is loaded; package attr shadows it
from obsvr import sender
from obsvr.config import _reset

WRAP_MODULE = sys.modules["obsvr.wrap"]


# ── Fake provider clients ────────────────────────────────────────────────────

class FakeAnthropicUsage:
    input_tokens = 11
    output_tokens = 2


class FakeTextBlock:
    type = "text"
    text = "four"


class FakeAnthropicResponse:
    content = [FakeTextBlock()]
    usage = FakeAnthropicUsage()


class _RecordingMessages:
    """Duck-types anthropic's messages resource. ``create`` records the label it
    was reached through so a double-emit — the beta method re-entering the
    audited GA method underneath it — would show up as two entries."""

    def __init__(self, seen, label):
        self._seen = seen
        self._label = label

    def create(self, **kwargs):
        self._seen.append(self._label)
        return FakeAnthropicResponse()

    def count_tokens(self, **kwargs):
        self._seen.append(self._label + ".count_tokens")
        return {"input_tokens": 4}


class _Beta:
    def __init__(self, seen):
        self.messages = _RecordingMessages(seen, "beta.messages.create")


class FakeAnthropic:
    def __init__(self, seen):
        self.messages = _RecordingMessages(seen, "messages.create")
        self.beta = _Beta(seen)


class _Embeddings:
    def __init__(self, seen):
        self._seen = seen

    def create(self, **kwargs):
        self._seen.append("embeddings.create")
        return {"data": []}


class FakeClientWithExcludedSurfaces:
    def __init__(self, seen):
        self.messages = _RecordingMessages(seen, "messages.create")
        self.embeddings = _Embeddings(seen)
        self.beta = _Beta(seen)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _init(**extra):
    _reset()
    sender._reset_sender()
    extra.setdefault("disabled", False)
    obsvr.init(api_key="test-key", ingest_url="http://localhost:9", **extra)


def _captured_events(monkeypatch):
    captured = []

    def fake_send(config, event):
        captured.append(event)

    monkeypatch.setattr(WRAP_MODULE, "send_audit_async", fake_send)
    return captured


# ── Tests ────────────────────────────────────────────────────────────────────

class TestBetaNamespaceIsAudited:
    def test_beta_messages_create_emits_one_complete_event(self, monkeypatch):
        _init()
        captured = _captured_events(monkeypatch)
        seen = []
        client = obsvr.wrap(FakeAnthropic(seen))

        client.beta.messages.create(
            model="claude-sonnet-4-5",
            messages=[{"role": "user", "content": "what is 2+2"}],
        )

        assert seen == ["beta.messages.create"]
        # Exactly one: the beta path must not also trip the GA path underneath.
        assert len(captured) == 1
        ev = captured[0]
        assert ev["operation"] == "beta.messages.create"
        assert ev["provider"] == "anthropic"
        assert ev["model"] == "claude-sonnet-4-5"
        assert ev["prompt"] == "what is 2+2"
        assert ev["response"] == "four"
        assert ev["input_tokens"] == 11
        assert ev["output_tokens"] == 2

    def test_ga_path_unchanged_by_the_beta_entry(self, monkeypatch):
        _init()
        captured = _captured_events(monkeypatch)
        seen = []
        client = obsvr.wrap(FakeAnthropic(seen))

        client.messages.create(
            model="claude-sonnet-4-5",
            messages=[{"role": "user", "content": "what is 2+2"}],
        )

        assert seen == ["messages.create"]
        assert len(captured) == 1
        assert captured[0]["operation"] == "messages.create"
        assert captured[0]["response"] == "four"


class TestBoundaryHoldsInBothDirections:
    def test_excluded_surfaces_stay_ungoverned_including_under_beta(self, monkeypatch):
        _init()
        captured = _captured_events(monkeypatch)
        seen = []
        client = obsvr.wrap(FakeClientWithExcludedSurfaces(seen))

        client.embeddings.create(input="x")
        client.beta.messages.count_tokens(messages=[])

        assert seen == ["embeddings.create", "beta.messages.create.count_tokens"]
        assert captured == []

    @pytest.mark.parametrize(
        "path,expected_events",
        [
            (["chat", "completions", "create"], 1),
            (["chat", "completions", "parse"], 1),
            (["messages", "create"], 1),
            (["messages", "parse"], 1),
            (["responses", "create"], 1),
            (["responses", "parse"], 1),
            (["generate_content"], 1),
            (["beta", "messages", "create"], 1),
            (["beta", "responses", "create"], 1),
            (["beta", "chat", "completions", "create"], 1),
            (["beta", "chat", "completions", "parse"], 1),
            (["messages", "stream"], 0),
            (["messages", "count_tokens"], 0),
            (["messages", "batches", "create"], 0),
            (["chat", "completions", "stream"], 0),
            (["responses", "stream"], 0),
            (["generate_content_stream"], 0),
            (["start_chat"], 0),
            (["embeddings", "create"], 0),
            (["images", "generate"], 0),
            (["beta", "messages", "count_tokens"], 0),
            (["beta", "threads", "runs", "create"], 0),
        ],
    )
    def test_audited_set_is_pinned_exactly(self, monkeypatch, path, expected_events):
        """Probes the real gate by exposing one path at a time and checking
        whether an event appears, rather than re-reading the table the gate is
        built from."""
        _init()
        captured = _captured_events(monkeypatch)

        class _Leaf:
            def __call__(self, **kwargs):
                return FakeAnthropicResponse()

        node = _Leaf()
        for seg in reversed(path):
            holder = type("Node", (), {})()
            setattr(holder, seg, node)
            node = holder

        # The provider detector duck-types on messages.create; give it one
        # unless this path already supplies it.
        if path[0] != "messages":
            node.messages = _RecordingMessages([], "messages.create")

        client = obsvr.wrap(node)
        cursor = client
        for seg in path:
            cursor = getattr(cursor, seg)
        cursor(model="m", messages=[{"role": "user", "content": "hi"}])

        assert len(captured) == expected_events
