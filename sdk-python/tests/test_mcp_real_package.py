"""The MCP tool gate, driven against the REAL ``mcp`` package.

Every other integration in this suite is tested against hand-written fakes, and
until this file existed so was this one — on the surface ``SECURITY.md`` names
as the place to put a destructive capability behind. A gate whose only evidence
is a restatement of itself is graded by its own copy, so this drives a real
``FastMCP`` server and a real ``ClientSession`` over the package's own in-memory
transport.

The grading is not "the caller raised". It is whether the SERVER executed the
tool body: each tool appends to ``executed``, so a refusal is asserted from the
far side of a real session rather than from the caller's exception. A gate that
raised after delegating would satisfy an exception-only assertion and fail this
one.
"""

import asyncio

import pytest

import obsvr
import obsvr.integrations.mcp as mcp_mod
from obsvr.config import _reset
from obsvr.integrations.mcp import govern_mcp

mcp_pkg = pytest.importorskip("mcp", reason="the `mcp` dev dependency is not installed")
from mcp.server.fastmcp import FastMCP  # noqa: E402
from mcp.shared.memory import create_connected_server_and_client_session  # noqa: E402


def _init(**extra):
    _reset()
    extra.setdefault("sample_rate", 1.0)
    extra.setdefault("disabled", False)
    obsvr.init(api_key="test-key", ingest_url="http://localhost:9", **extra)


def _captured(monkeypatch):
    captured = []
    monkeypatch.setattr(mcp_mod, "send_audit_async", lambda cfg, ev: captured.append(ev))
    return captured


def _build_real_server(executed):
    """A real FastMCP server: one destructive-shaped tool, one benign one."""
    server = FastMCP("obsvr-test-server")

    @server.tool(description="Transfer funds. Stands in for a destructive capability.")
    def send_money(amount: int) -> str:
        executed.append("send_money")
        return f"sent {amount}"

    @server.tool(description="Read a file. Stands in for a benign capability.")
    def read_file(path: str) -> str:
        executed.append("read_file")
        return f"contents of {path}"

    return server


async def _call(tool_name, arguments, executed):
    """Drive one real session end to end and return (result, raised)."""
    server = _build_real_server(executed)
    async with create_connected_server_and_client_session(server) as session:
        governed = govern_mcp(session)
        try:
            return await governed.call_tool(tool_name, arguments), None
        except Exception as exc:  # noqa: BLE001 - the raise IS the observation
            return None, exc


def _run(coro):
    return asyncio.run(coro)


class TestMcpGateAgainstRealPackage:
    def test_control_no_policy_the_real_server_executes_the_tool(self, monkeypatch):
        # Without this row, "the tool did not run" below would also be satisfied
        # by a session that never worked at all.
        _init()
        _captured(monkeypatch)
        executed = []
        result, raised = _run(_call("send_money", {"amount": 100}, executed))
        assert raised is None
        assert executed == ["send_money"]
        assert result is not None

    def test_denied_tool_is_refused_and_the_server_never_runs_its_body(self, monkeypatch):
        _init(mcp_tool_policy={"denied_tools": ["send_money"]})
        _captured(monkeypatch)
        executed = []
        _result, raised = _run(_call("send_money", {"amount": 100}, executed))
        assert raised is not None
        # The assertion that matters: the far side of a real session reports
        # that the tool body was never entered.
        assert executed == []

    def test_control_under_the_same_policy_an_undenied_tool_still_runs(self, monkeypatch):
        # Without this, "send_money did not run" would also be satisfied by a
        # gate that had stopped letting anything through.
        _init(mcp_tool_policy={"denied_tools": ["send_money"]})
        _captured(monkeypatch)
        executed = []
        _result, raised = _run(_call("read_file", {"path": "/tmp/x"}, executed))
        assert raised is None
        assert executed == ["read_file"]

    def test_the_refusal_is_recorded_as_blocked_on_a_signed_event(self, monkeypatch):
        _init(mcp_tool_policy={"denied_tools": ["send_money"]})
        captured = _captured(monkeypatch)
        executed = []
        _result, raised = _run(_call("send_money", {"amount": 100}, executed))
        assert raised is not None

        blocked = [e for e in captured if e.get("action_taken") == "blocked"]
        # Both halves, because either alone has already shipped as a defect
        # somewhere in this tree: the tool did not run, AND the record says so.
        assert executed == []
        assert len(blocked) == 1
        assert blocked[0]["operation"] == "mcp.tool.call"
        assert blocked[0]["reason_code"] == "MCP_TOOL_DENIED"
        assert blocked[0]["event_type"] == "blocked_call"
        assert blocked[0]["success"] is False
        # Deliberately NOT asserted here: `sdk_sig` and `seq_no`. This capture
        # point is `send_audit_async`, and signing happens downstream of it at
        # sender.py:296 — so asserting a signature here could only ever fail,
        # which is a vacuous check pointing the other way. The chain is pinned
        # by test_signing.py and the conformance vectors; what this row grades
        # is the verdict the gate decided.

    def test_the_allowlist_form_refuses_a_tool_that_is_not_on_it(self, monkeypatch):
        _init(mcp_tool_policy={"allowed_tools": ["read_file"]})
        _captured(monkeypatch)

        executed = []
        _result, raised = _run(_call("send_money", {"amount": 100}, executed))
        assert raised is not None
        assert executed == []

        allowed_executed = []
        _result2, raised2 = _run(_call("read_file", {"path": "/tmp/x"}, allowed_executed))
        assert raised2 is None
        assert allowed_executed == ["read_file"]

    def test_list_tools_reaches_the_gate_on_a_real_session(self, monkeypatch):
        """Discovery is the other half of this surface, and it is a real call."""
        _init()
        _captured(monkeypatch)

        async def _list():
            executed = []
            server = _build_real_server(executed)
            async with create_connected_server_and_client_session(server) as session:
                governed = govern_mcp(session)
                return await governed.list_tools()

        listing = _run(_list())
        names = sorted(t.name for t in listing.tools)
        assert names == ["read_file", "send_money"]
