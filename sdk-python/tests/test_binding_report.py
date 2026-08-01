"""An optional integration that fails to bind must say WHY, not just that it did.

Every framework integration binds upstream symbols behind try/except so the SDK
never hard-depends on a framework the caller has not installed. The except used
to discard the exception, and three different situations then produced one
identical silent False:

  * the package is not installed (normal),
  * a symbol was RENAMED upstream (an obsvr defect — the integration is inert
    while the manifest advertises support),
  * a transitive dependency is broken (upstream's problem, belongs in the
    manifest).

Only the middle one is obsvr's to fix. Two real defects needed a manual
reproduction to diagnose for exactly this reason, and both looked like "not
installed" from the outside.
"""

import pytest

import obsvr
from obsvr import binding_report
from obsvr.binding_report import (
    integration_bindings,
    record_binding,
    unbound_symbols,
)


@pytest.fixture
def isolated_registry():
    """The registry is populated at IMPORT time, so clearing it outright would
    destroy what the real-integration tests below assert on — the modules are
    already imported and re-importing records nothing. Snapshot and restore."""
    saved = {k: dict(v) for k, v in binding_report._BINDINGS.items()}
    binding_report._BINDINGS.clear()
    try:
        yield
    finally:
        binding_report._BINDINGS.clear()
        binding_report._BINDINGS.update(saved)


class TestRecording:
    def test_a_successful_bind_records_no_reason(self, isolated_registry):
        record_binding("demo", "pkg.Symbol")
        assert integration_bindings() == {"demo": {"pkg.Symbol": {"bound": True}}}
        assert unbound_symbols() == []

    def test_a_failed_bind_keeps_the_exception_type_and_message(self, isolated_registry):
        record_binding("demo", "pkg.Symbol", ImportError("cannot import name 'Gone'"))
        entry = integration_bindings()["demo"]["pkg.Symbol"]
        assert entry["bound"] is False
        assert entry["error_type"] == "ImportError"
        assert "cannot import name 'Gone'" in entry["error"]

    def test_the_three_causes_are_distinguishable(self, isolated_registry):
        """The whole point: these used to be one indistinguishable False."""
        record_binding("a", "s", ModuleNotFoundError("No module named 'a'"))
        record_binding("b", "s", ImportError("cannot import name 'Renamed' from 'b'"))
        record_binding("c", "s", ModuleNotFoundError("No module named 'transitive_dep'"))
        by_integration = {u["integration"]: u for u in unbound_symbols()}
        assert by_integration["a"]["error_type"] == "ModuleNotFoundError"
        assert "No module named 'a'" in by_integration["a"]["error"]
        assert by_integration["b"]["error_type"] == "ImportError"
        assert "Renamed" in by_integration["b"]["error"]
        # Same exception TYPE as (a), different module named — which is exactly
        # the distinction a bare flag destroyed.
        assert "transitive_dep" in by_integration["c"]["error"]

    def test_recording_never_raises(self, isolated_registry):

        class Hostile(Exception):
            def __str__(self):
                raise RuntimeError("boom")

        record_binding("demo", "pkg.Symbol", Hostile())  # must not propagate
        entry = integration_bindings()["demo"]["pkg.Symbol"]
        # Recorded as a failure even though the message was unrenderable — a
        # bind that failed must never leave no trace.
        assert entry["bound"] is False
        assert entry["error_type"] == "Hostile"


class TestRealIntegrationsReport:
    def test_every_guarded_integration_reports_its_binds(self):
        # Importing the modules is what records; assert each names itself.
        import obsvr.integrations.haystack  # noqa: F401
        import obsvr.integrations.langchain  # noqa: F401
        import obsvr.integrations.pydantic_ai  # noqa: F401

        reported = integration_bindings()
        for name in (
            "haystack",
            "langchain",
            "pydantic_ai",
        ):
            assert name in reported, f"{name} records no binding at all"
            assert reported[name], f"{name} reports an empty symbol set"

    def test_a_reason_is_present_for_every_unbound_symbol(self):
        """The assertion that converts this failure class from silent to loud:
        no symbol may be reported as unbound without saying why."""
        for entry in unbound_symbols():
            assert entry["error_type"], entry
            assert entry["error"], entry

    def test_exposed_on_the_package_surface(self):
        assert obsvr.integration_bindings() == integration_bindings()
        assert obsvr.unbound_symbols() == unbound_symbols()
