"""End-to-end: a tool that declares itself destructive in its MCP descriptor
joins the destructive-capability set at discovery, with NO operator
configuration. Twin: sdk-typescript/tests/unit/capability-hints-wiring.test.ts.

The gap this closes is that the capability gate - the strongest control in the
SDK - used to require an operator to write a list of tool names, and a
deployment that wrote none got no gate at all and no warning about it. The
decision table itself is pinned in session_taint.json; what these tests pin is
that discovery actually feeds it, and that the hint stays one-way.
"""

import asyncio

import pytest

import obsvr
import obsvr.integrations.mcp as mcp_mod
from obsvr import sender
from obsvr.capability_hints import MAX_HINTED_TOOLS, create_capability_store
from obsvr.config import _reset
from obsvr.integrations.mcp import McpToolBlockedError, govern_mcp
from obsvr.session_taint import _reset_session_taint, mark_tainted


class _Annotations:
    def __init__(self, destructive_hint=None, read_only_hint=None):
        self.destructiveHint = destructive_hint
        self.readOnlyHint = read_only_hint


class _Tool:
    def __init__(self, name, description, annotations=None):
        self.name = name
        self.description = description
        self.annotations = annotations


class _Content:
    def __init__(self, text):
        self.text = text


class _CallResult:
    def __init__(self, text):
        self.content = [_Content(text)]


class _ListResult:
    def __init__(self, tools):
        self.tools = list(tools)


def _session_class(tools):
    class FakeClientSession:
        def __init__(self):
            self.calls = []

        async def call_tool(self, name, arguments=None):
            self.calls.append((name, arguments))
            return _CallResult(f"result of {name}")

        async def list_tools(self):
            return _ListResult(tools)

    return FakeClientSession


DESTRUCTIVE_TOOL = _Tool("delete_row", "Removes a row.", _Annotations(True, False))
SAFE_TOOL = _Tool("read_row", "Reads a row.", _Annotations(False, True))
UNANNOTATED_TOOL = _Tool("search", "Searches.")


def _init(**extra):
    _reset()
    sender._reset_sender()
    _reset_session_taint()
    extra.setdefault("disabled", False)
    obsvr.init(api_key="test-key", ingest_url="http://localhost:9", **extra)


def _captured(monkeypatch):
    captured = []
    monkeypatch.setattr(mcp_mod, "send_audit_async", lambda cfg, ev: captured.append(ev))
    return captured


def _run(coro):
    return asyncio.run(coro)


class TestDiscoveryFeedsTheTaintGate:
    def teardown_method(self):
        _reset()
        _reset_session_taint()

    def test_hinted_tool_is_blocked_with_no_operator_list(self, monkeypatch):
        _init(session_taint={"enabled": True})  # default flag action, no list
        captured = _captured(monkeypatch)
        raw = _session_class([DESTRUCTIVE_TOOL, SAFE_TOOL, UNANNOTATED_TOOL])()
        session = govern_mcp(raw)
        _run(session.list_tools())
        mark_tainted("global", "prompt_injection", 1.0)

        with pytest.raises(McpToolBlockedError):
            _run(session.call_tool("delete_row", {}))
        assert raw.calls == []  # the side effect never ran

        blocked = [e for e in captured if e.get("event_type") == "blocked_call"]
        assert blocked, "expected a blocked_call event"
        # The record says WHICH source put the tool in the set: an operator who
        # configured nothing needs to be able to tell where the block came from.
        assert "tool descriptor hint" in blocked[0]["policy_reason"]
        assert blocked[0]["rule_id"] == "sdk:session_tainted"

    def test_descriptor_claiming_safety_is_only_flagged(self, monkeypatch):
        _init(session_taint={"enabled": True})
        _captured(monkeypatch)
        raw = _session_class([DESTRUCTIVE_TOOL, SAFE_TOOL])()
        session = govern_mcp(raw)
        _run(session.list_tools())
        mark_tainted("global", "prompt_injection", 1.0)

        _run(session.call_tool("read_row", {}))
        assert len(raw.calls) == 1  # flag posture: ordinary egress still runs

    def test_unannotated_server_is_not_a_blanket_block(self, monkeypatch):
        _init(session_taint={"enabled": True})
        _captured(monkeypatch)
        raw = _session_class([UNANNOTATED_TOOL])()
        session = govern_mcp(raw)
        _run(session.list_tools())
        mark_tainted("global", "prompt_injection", 1.0)

        _run(session.call_tool("search", {"q": "x"}))
        assert len(raw.calls) == 1

    def test_inventory_event_records_the_hinted_names(self, monkeypatch):
        _init(session_taint={"enabled": True})
        captured = _captured(monkeypatch)
        session = govern_mcp(_session_class([DESTRUCTIVE_TOOL, SAFE_TOOL])())
        _run(session.list_tools())
        inventory = [e for e in captured if e.get("operation") == "mcp.tools.list"]
        assert inventory
        assert inventory[0]["metadata"]["destructive_hinted_tools"] == ["delete_row"]

    def test_a_later_listing_cannot_un_declare_the_tool(self, monkeypatch):
        _init(session_taint={"enabled": True})
        _captured(monkeypatch)
        tools = [DESTRUCTIVE_TOOL]
        raw = _session_class(tools)()
        session = govern_mcp(raw)
        _run(session.list_tools())
        # The server rug-pulls its own annotation: same name, now claiming safety.
        tools[0] = _Tool("delete_row", "Removes a row.", _Annotations(False, True))
        _run(session.list_tools())
        mark_tainted("global", "prompt_injection", 1.0)

        with pytest.raises(McpToolBlockedError):
            _run(session.call_tool("delete_row", {}))
        assert raw.calls == []

    def test_honor_flag_off_restricts_to_the_operator_list(self, monkeypatch):
        _init(session_taint={"enabled": True, "honor_destructive_hints": False})
        _captured(monkeypatch)
        raw = _session_class([DESTRUCTIVE_TOOL])()
        session = govern_mcp(raw)
        _run(session.list_tools())
        mark_tainted("global", "prompt_injection", 1.0)

        _run(session.call_tool("delete_row", {}))
        assert len(raw.calls) == 1

    def test_untainted_session_reaches_a_hinted_tool(self, monkeypatch):
        _init(session_taint={"enabled": True})
        _captured(monkeypatch)
        raw = _session_class([DESTRUCTIVE_TOOL])()
        session = govern_mcp(raw)
        _run(session.list_tools())
        _run(session.call_tool("delete_row", {}))
        assert len(raw.calls) == 1

    def test_two_sessions_do_not_share_hints_for_one_name(self, monkeypatch):
        _init(session_taint={"enabled": True})
        _captured(monkeypatch)
        raw_a = _session_class([DESTRUCTIVE_TOOL])()
        raw_b = _session_class([_Tool("delete_row", "Different server.")])()
        hinting = govern_mcp(raw_a)
        benign = govern_mcp(raw_b)
        _run(hinting.list_tools())
        _run(benign.list_tools())
        mark_tainted("global", "prompt_injection", 1.0)

        with pytest.raises(McpToolBlockedError):
            _run(hinting.call_tool("delete_row", {}))
        _run(benign.call_tool("delete_row", {}))
        assert raw_a.calls == []
        assert len(raw_b.calls) == 1


class TestCapabilityStoreInvariants:
    def test_a_false_hint_records_nothing(self):
        store = create_capability_store()
        store.record("read_row", False)
        assert store.is_destructive("read_row") is False
        assert store.size() == 0

    def test_recording_is_add_only_and_idempotent(self):
        store = create_capability_store()
        store.record("delete_row", True)
        store.record("delete_row", False)  # cannot be talked out of it
        assert store.is_destructive("delete_row") is True
        assert store.names() == ["delete_row"]

    def test_refuses_past_the_cap_rather_than_evicting(self):
        store = create_capability_store()
        for i in range(MAX_HINTED_TOOLS):
            store.record(f"t{i}", True)
        assert store.saturated() is False
        store.record("one_too_many", True)
        assert store.saturated() is True
        assert store.is_destructive("one_too_many") is False
        assert store.is_destructive("t0") is True  # the earlier one survived
