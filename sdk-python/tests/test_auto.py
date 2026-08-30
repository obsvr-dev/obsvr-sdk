"""WS2B — auto-instrumentation. enable_auto_instrumentation() is best-effort,
idempotent, and non-throwing; init(auto=...) drives it; a framework exposing a
clean global hook (openai-agents) gets wired; per-call frameworks are reported
as manual."""

import sys
import types

import obsvr
from obsvr import auto


def test_enable_returns_report_and_never_throws():
    auto._reset_auto()
    report = auto.enable_auto_instrumentation()
    assert isinstance(report, dict)
    assert "wired" in report and "manual" in report
    assert isinstance(report["wired"], list) and isinstance(report["manual"], list)


def test_init_default_runs_auto_without_error():
    # No frameworks installed in the test env -> a clean no-op, must not raise.
    obsvr.init(api_key="test")
    assert obsvr.is_initialized()


def test_init_auto_false_is_respected():
    auto._reset_auto()
    obsvr.init(api_key="test", auto=False)
    assert obsvr.is_initialized()


def test_openai_agents_is_wired_when_available(monkeypatch):
    auto._reset_auto()
    calls = []

    fake_agents = types.ModuleType("agents")
    fake_agents.add_trace_processor = lambda proc: calls.append(proc)
    monkeypatch.setitem(sys.modules, "agents", fake_agents)
    # find_spec on a synthetic module is unreliable; force availability.
    monkeypatch.setattr(auto, "_module_available", lambda name: name == "agents")

    report = auto.enable_auto_instrumentation()
    assert "openai-agents" in report["wired"]
    assert len(calls) == 1  # exactly one processor registered

    # Idempotency: a second call does not re-register.
    report2 = auto.enable_auto_instrumentation()
    assert "openai-agents" not in report2["wired"]
    assert len(calls) == 1


def test_safe_global_tool_gates_are_wired_once(monkeypatch):
    auto._reset_auto()
    calls = []
    monkeypatch.setattr(
        auto,
        "_module_available",
        lambda name: name in {"crewai", "autogen"},
    )
    monkeypatch.setattr(
        auto,
        "_wire_crewai_tool_gate",
        lambda: calls.append("crewai") or True,
    )
    monkeypatch.setattr(
        auto,
        "_wire_autogen_tool_gate",
        lambda: calls.append("autogen") or True,
    )
    report = auto.enable_auto_instrumentation()
    assert "crewai:tool-gate" in report["wired"]
    assert "autogen:tool-gate" in report["wired"]
    assert calls == ["crewai", "autogen"]
    assert any("CrewAI run/step audit" in hint for hint in report["manual"])
    assert any("AutoGen message policy" in hint for hint in report["manual"])

    report2 = auto.enable_auto_instrumentation()
    assert "crewai:tool-gate" not in report2["wired"]
    assert "autogen:tool-gate" not in report2["wired"]
    assert calls == ["crewai", "autogen"]


def test_reset_uninstalls_global_tool_gates(monkeypatch):
    auto._reset_auto()
    removed = []
    auto._uninstallers.extend(
        [lambda: removed.append("first"), lambda: removed.append("second")]
    )
    auto._wired.extend(["crewai_tool_gate", "autogen_tool_gate"])
    auto._reset_auto()
    assert removed == ["second", "first"]
    assert auto._wired == []
    assert auto._uninstallers == []


def test_status_distinguishes_bound_and_explicit_surfaces(monkeypatch):
    auto._reset_auto()
    from obsvr import binding_report

    saved = {name: dict(symbols) for name, symbols in binding_report._BINDINGS.items()}
    binding_report._BINDINGS.clear()
    try:
        monkeypatch.setattr(
            auto,
            "_module_available",
            lambda name: name in {"mcp", "langchain_core"},
        )

        armed = auto.auto_governance_status()
        assert armed["enabled"] is False
        assert armed["bindings"]["mcp.client"] == {"state": "armed"}
        assert armed["bindings"]["langchain.models"]["state"] == "not-applicable"

        binding_report.record_binding("mcp.client", "mcp.ClientSession")
        bound = auto.auto_governance_status()
        assert bound["bindings"]["mcp.client"] == {"state": "bound"}
        assert obsvr.auto_governance_status is auto.auto_governance_status
    finally:
        binding_report._BINDINGS.clear()
        binding_report._BINDINGS.update(saved)
