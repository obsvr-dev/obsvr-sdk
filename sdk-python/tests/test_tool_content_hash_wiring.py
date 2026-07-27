"""tool_content_hash at the real Python tool boundary. Twin of the MCP half of
sdk/tests/unit/tool-content-hash-wiring.test.ts.

The producer module is fixture-pinned elsewhere; this file pins that the
shipping path actually stamps it, on the right events, in the right place.
Three things have to hold together or the evidence is worthless: the value must
equal what an offline recomputation produces from the disclosed parts, caller
metadata must never be able to overwrite it, and a value neither language can
canonicalize must omit the field rather than seal a hash the TypeScript twin
cannot reproduce.

TypeScript additionally stamps a framework tool boundary (obsvrGovernTool),
which has no Python twin - Python's tool wrappers are per-framework. That half
of the TS suite therefore has no counterpart here.
"""

import asyncio

import pytest

import obsvr
from obsvr import sender
from obsvr.config import _reset
from obsvr.events import _RESERVED_META_KEYS
from obsvr.integrations import mcp as mcp_mod
from obsvr.integrations.mcp import McpToolBlockedError, govern_mcp
from obsvr.tool_content_hash import (
    TOOL_CONTENT_HASH_METADATA_KEY,
    compute_tool_content_hash,
)
from obsvr.tool_pinning import tool_descriptor_hash


class _StubSession:
    def __init__(self, tools=()):
        self._tools = list(tools)

    async def call_tool(self, name, arguments=None):
        return "ok"

    async def list_tools(self):
        class R:
            pass

        r = R()
        r.tools = list(self._tools)
        return r


def _init(**extra):
    _reset()
    sender._reset_sender()
    extra.setdefault("disabled", False)
    obsvr.init(api_key="test-key", ingest_url="http://localhost:9", **extra)


def _captured(monkeypatch):
    captured = []
    monkeypatch.setattr(mcp_mod, "send_audit_async", lambda cfg, ev: captured.append(ev))
    return captured


def _run(coro):
    return asyncio.run(coro)


def _hash_of(event):
    return (event.get("metadata") or {}).get(TOOL_CONTENT_HASH_METADATA_KEY)


def test_the_reserved_key_survives_metadata_trimming():
    """An oversized event trims metadata down to the reserved keys. The hash is
    sealed evidence, so it has to be one of them."""
    assert TOOL_CONTENT_HASH_METADATA_KEY in _RESERVED_META_KEYS


def test_stamps_a_hash_an_auditor_can_recompute_from_the_disclosed_parts(monkeypatch):
    _init()
    captured = _captured(monkeypatch)
    session = govern_mcp(_StubSession())
    _run(session.call_tool("readFile", {"path": "/tmp/a", "depth": 2}))

    ev = next(e for e in captured if e["operation"] == "mcp.tool.call")
    # call_tool carries no descriptor, so the document commits to the name and
    # arguments with the empty-descriptor digest - what this producer saw.
    assert _hash_of(ev) == compute_tool_content_hash(
        tool_name="readFile", args={"path": "/tmp/a", "depth": 2}
    )


def test_is_argument_sensitive(monkeypatch):
    _init()
    captured = _captured(monkeypatch)
    session = govern_mcp(_StubSession())
    _run(session.call_tool("readFile", {"path": "/tmp/a"}))
    _run(session.call_tool("readFile", {"path": "/etc/shadow"}))

    calls = [e for e in captured if e["operation"] == "mcp.tool.call"]
    assert len(calls) == 2
    assert _hash_of(calls[0]) != _hash_of(calls[1])


def test_stamps_blocked_tool_calls_too(monkeypatch):
    """What was refused is exactly the record an investigation wants."""
    _init(mcp_tool_policy={"denied_tools": ["dangerous"]})
    captured = _captured(monkeypatch)
    session = govern_mcp(_StubSession())
    with pytest.raises(McpToolBlockedError):
        _run(session.call_tool("dangerous", {"x": 1}))

    ev = next(e for e in captured if e.get("event_type") == "blocked_call")
    assert _hash_of(ev) == compute_tool_content_hash(tool_name="dangerous", args={"x": 1})


def test_caller_metadata_cannot_overwrite_the_sealed_value(monkeypatch):
    _init()
    captured = _captured(monkeypatch)
    session = govern_mcp(
        _StubSession(),
        options={"metadata": {TOOL_CONTENT_HASH_METADATA_KEY: "caller-spoof"}},
    )
    _run(session.call_tool("readFile", {"path": "/tmp/a"}))

    ev = next(e for e in captured if e["operation"] == "mcp.tool.call")
    assert _hash_of(ev) == compute_tool_content_hash(
        tool_name="readFile", args={"path": "/tmp/a"}
    )


def test_omits_the_field_rather_than_sealing_a_hash_typescript_cannot_reproduce(monkeypatch):
    _init()
    captured = _captured(monkeypatch)
    session = govern_mcp(_StubSession())
    # An integer past 2^53 canonicalizes differently in the two runtimes, so
    # the producer raises and the boundary drops the field - the call itself
    # must still go through.
    result = _run(session.call_tool("readFile", {"size": 9007199254740993}))
    assert result == "ok"

    ev = next(e for e in captured if e["operation"] == "mcp.tool.call")
    assert ev["metadata"]["tool_name"] == "readFile"
    assert _hash_of(ev) is None


def test_leaves_the_descriptor_pinning_hash_untouched(monkeypatch):
    descriptor = {
        "name": "readFile",
        "description": "reads a file",
        "inputSchema": {"type": "object"},
    }
    _init(mcp_tool_policy={"pinning": {"enabled": True, "mode": "warn"}})
    captured = _captured(monkeypatch)
    session = govern_mcp(_StubSession([descriptor]))
    _run(session.list_tools())
    _run(session.call_tool("readFile", {"path": "/tmp/a"}))

    ev = next(e for e in captured if e["operation"] == "mcp.tool.call")
    # Two different hashes on one event, both correct, neither substituted:
    # the pin identifies the descriptor, the content hash identifies the call.
    assert ev["metadata"]["tool_descriptor_hash"] == tool_descriptor_hash(descriptor)
    assert _hash_of(ev) == compute_tool_content_hash(
        tool_name="readFile", args={"path": "/tmp/a"}
    )
    assert ev["metadata"]["tool_descriptor_hash"] != _hash_of(ev)


def test_is_consumed_at_the_tool_boundary_and_nowhere_else():
    """The hash belongs at tool-call time and only there. Twin of the TS
    import-set gate, so a future change cannot quietly start stamping the field
    on, say, llm_call events - a different evidence claim than the one the
    ledger leaf seals."""
    import re
    from pathlib import Path

    pkg_dir = Path(__file__).parent.parent / "obsvr"
    pattern = re.compile(r"(?:from|import)\s+[.\w]*tool_content_hash")
    hits = sorted(
        str(p.relative_to(pkg_dir)).replace("\\", "/")
        for p in pkg_dir.rglob("*.py")
        if p.name != "tool_content_hash.py"
        # Imports only - a prose mention of the module is not wiring.
        and pattern.search(p.read_text(encoding="utf-8"))
    )
    assert hits == ["integrations/mcp.py"]
