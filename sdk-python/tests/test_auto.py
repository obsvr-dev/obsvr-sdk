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


def test_manual_frameworks_reported(monkeypatch):
    auto._reset_auto()
    monkeypatch.setattr(auto, "_module_available", lambda name: name == "crewai")
    report = auto.enable_auto_instrumentation()
    assert any("CrewAI" in hint for hint in report["manual"])
