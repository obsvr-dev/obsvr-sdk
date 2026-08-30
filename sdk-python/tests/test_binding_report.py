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

import ast
import contextlib
import importlib
import pathlib
import sys

import pytest

import obsvr
from obsvr import binding_report
from obsvr.binding_report import (
    RequiredBindingsError,
    assert_required_bindings,
    integration_bindings,
    record_binding,
    required_binding_failures,
    unbound_symbols,
)


@contextlib.contextmanager
def _blocked(package):
    """Make every import of ``package`` (and its submodules) raise ImportError,
    whether or not it is installed, and restore the real state afterwards.

    ``None`` in sys.modules halts the import machinery with ImportError, which
    is exactly the failure an absent install produces - so these tests run the
    same way on a machine that has the framework and one that does not."""
    prefix = package + "."
    saved = {
        name: sys.modules[name]
        for name in list(sys.modules)
        if name == package or name.startswith(prefix)
    }
    for name in saved:
        del sys.modules[name]
    sys.modules[package] = None
    try:
        yield
    finally:
        if sys.modules.get(package) is None:
            del sys.modules[package]
        sys.modules.update(saved)


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
        assert integration_bindings() == {
            "demo": {
                "pkg.Symbol": {"bound": True, "enforcement_depth": "unknown"}
            }
        }
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


class TestRequiredBindings:
    def test_passes_only_after_every_required_integration_reports_bound(
        self, isolated_registry
    ):
        record_binding("openai", "openai.OpenAI")
        record_binding("langchain", "langchain_core.callbacks.BaseCallbackHandler")

        assert required_binding_failures(["openai", "langchain"]) == []
        assert_required_bindings(["openai", "langchain"])

    def test_distinguishes_missing_from_unbound(self, isolated_registry):
        record_binding(
            "langchain",
            "langchain_core.callbacks.BaseCallbackHandler",
            TypeError("symbol moved"),
        )

        assert required_binding_failures(["openai", "langchain"]) == [
            {"integration": "openai", "symbol": "", "reason": "missing"},
            {
                "integration": "langchain",
                "symbol": "langchain_core.callbacks.BaseCallbackHandler",
                "reason": "unbound",
                "error_type": "TypeError",
                "error": "symbol moved",
            },
        ]

    def test_typed_error_carries_a_copy_of_failures(self, isolated_registry):
        with pytest.raises(RequiredBindingsError) as exc_info:
            assert_required_bindings(["openai"])
        assert exc_info.value.failures == [
            {"integration": "openai", "symbol": "", "reason": "missing"}
        ]
        exc_info.value.failures[0]["integration"] = "mutated"
        assert required_binding_failures(["openai"])[0]["integration"] == "openai"

    def test_deduplicates_and_rejects_blank_names(self, isolated_registry):
        assert len(required_binding_failures(["openai", "openai"])) == 1
        with pytest.raises(TypeError):
            required_binding_failures([" "])


class TestRealIntegrationsReport:
    def test_every_guarded_integration_reports_its_binds(self):
        # Importing the modules is what records; assert each names itself.
        import obsvr.integrations.bedrock  # noqa: F401
        import obsvr.integrations.haystack  # noqa: F401
        import obsvr.integrations.langchain  # noqa: F401
        import obsvr.integrations.llamaindex  # noqa: F401
        import obsvr.integrations.pydantic_ai  # noqa: F401
        import obsvr.integrations.vertex  # noqa: F401

        reported = integration_bindings()
        for name in (
            "bedrock",
            "haystack",
            "langchain",
            "llamaindex",
            "pydantic_ai",
            "vertex",
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
        assert obsvr.required_binding_failures is required_binding_failures
        assert obsvr.assert_required_bindings is assert_required_bindings


class TestEveryIntegrationRecordsItsBindFailures:
    """Each integration's guarded upstream import, driven through its absent
    path: the symbol must land in ``unbound_symbols()`` with the exception
    type, and the paths that refuse loudly must STILL refuse loudly - the
    report is in addition to the refusal, never instead of it."""

    def _unbound_for(self, integration):
        return {
            u["symbol"]: u for u in unbound_symbols() if u["integration"] == integration
        }

    def test_llamaindex_records_why_its_base_class_did_not_bind(self, isolated_registry):
        import obsvr.integrations.llamaindex as llamaindex_module

        try:
            with _blocked("llama_index"):
                importlib.reload(llamaindex_module)
            entry = self._unbound_for("llamaindex")[
                "llama_index.core.callbacks.base_handler.BaseCallbackHandler"
            ]
        finally:
            # Re-import against the real environment so later tests see the
            # module as it actually is on this machine.
            importlib.reload(llamaindex_module)
        assert entry["error_type"] in ("ImportError", "ModuleNotFoundError")
        assert entry["error"]

    def test_crewai_records_why_the_sanitizer_did_not_bind(
        self, isolated_registry, monkeypatch
    ):
        from obsvr.integrations import crewai as crewai_module

        # The sanitizer is cached in a cell on first use; start uncached.
        monkeypatch.setattr(crewai_module, "_sanitizer_cell", [])
        with _blocked("crewai"):
            # The mirror fallback still normalizes - the report adds why the
            # authoritative helper was not the one doing it.
            assert crewai_module._sanitize_tool_name("MyTool") == "my_tool"
        entry = self._unbound_for("crewai")[
            "crewai.utilities.string_utils.sanitize_tool_name"
        ]
        assert entry["error_type"] in ("ImportError", "ModuleNotFoundError")

    def test_crewai_records_why_the_hook_system_did_not_bind(self, isolated_registry):
        from obsvr.integrations import crewai as crewai_module

        with _blocked("crewai"):
            with pytest.raises(ImportError):  # the loud path stays loud
                crewai_module.install_tool_gate_hook()
        entry = self._unbound_for("crewai")[
            "crewai.hooks.tool_hooks.register_before_tool_call_hook"
        ]
        assert entry["error_type"] in ("ImportError", "ModuleNotFoundError")

    def test_bedrock_records_why_the_exception_types_did_not_bind(
        self, isolated_registry
    ):
        import obsvr.integrations.bedrock as bedrock_module

        try:
            with _blocked("botocore"):
                importlib.reload(bedrock_module)
        finally:
            importlib.reload(bedrock_module)
        entry = self._unbound_for("bedrock")["botocore.exceptions"]
        assert entry["error_type"] in ("ImportError", "ModuleNotFoundError")
        assert entry["error"]

    def test_vertex_records_why_the_model_class_did_not_bind(self, isolated_registry):
        import obsvr.integrations.vertex as vertex_module

        try:
            with _blocked("vertexai"):
                importlib.reload(vertex_module)
        finally:
            importlib.reload(vertex_module)
        entry = self._unbound_for("vertex")[
            "vertexai.generative_models.GenerativeModel"
        ]
        assert entry["error_type"] in ("ImportError", "ModuleNotFoundError")
        assert entry["error"]

    def test_haystack_records_why_the_hook_dispatch_probe_did_not_bind(
        self, isolated_registry
    ):
        from obsvr.integrations import haystack as haystack_module

        with _blocked("haystack"):
            # The probe's verdict still reaches the caller directly - the
            # report adds why, it does not replace the returned False.
            assert haystack_module._hook_dispatch_present() is False
        entry = self._unbound_for("haystack")["haystack.hooks.protocol"]
        assert entry["error_type"] in ("ImportError", "ModuleNotFoundError")

    def test_autogen_records_why_the_agent_class_did_not_bind(self, isolated_registry):
        from obsvr.integrations import autogen as autogen_module

        with _blocked("autogen"):
            with pytest.raises(ImportError):  # the loud path stays loud
                autogen_module.install_tool_gate()
        entry = self._unbound_for("autogen")["autogen.ConversableAgent"]
        assert entry["error_type"] in ("ImportError", "ModuleNotFoundError")

    def test_openai_agents_records_why_guardrail_types_did_not_bind(
        self, isolated_registry
    ):
        from obsvr.integrations import openai_agents as agents_module

        with _blocked("agents"):
            with pytest.raises(ImportError):  # the loud path stays loud
                agents_module.make_tool_gate_guardrail()
        entry = self._unbound_for("openai_agents")[
            "agents.tool_guardrails.ToolInputGuardrail"
        ]
        assert entry["error_type"] in ("ImportError", "ModuleNotFoundError")

    def test_openai_agents_records_both_probe_homes_when_dispatch_is_absent(
        self, isolated_registry
    ):
        from obsvr.integrations import openai_agents as agents_module

        with _blocked("agents"):
            assert agents_module._guardrail_dispatch_present() is False
        symbols = set(self._unbound_for("openai_agents"))
        assert "agents.run_internal.tool_execution._execute_tool_input_guardrails" in symbols
        assert "agents._run_impl.RunImpl._execute_input_guardrails" in symbols


class TestCompleteness:
    """Every guarded third-party import block under obsvr/integrations must
    record a binding, so a NEW integration (or a new guarded import in an old
    one) cannot ship silently inert. Modelled on the tree-scanning idiom the
    enforcement-reporting invariant uses: scan the source, don't trust a
    hand-maintained list of call sites.

    A block is identified by (file, first third-party module it imports).
    The allowlist below names the blocks that record nothing today and are
    outside this surface's scope; the assertion is EQUALITY, so the test
    fails both when a new unrecorded block appears and when an allowlisted
    one starts recording (a stale allowlist is itself a finding)."""

    #: Every guarded third-party import under obsvr/integrations records a
    #: binding as of the bedrock/haystack-probe/vertex wiring; an entry here
    #: names a block that records nothing and says why it may.
    KNOWN_UNRECORDED: set = set()

    @staticmethod
    def _third_party_imports(try_node):
        """Dotted names of non-stdlib, non-obsvr imports inside a Try."""
        found = []
        for node in ast.walk(try_node):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if root not in sys.stdlib_module_names and root != "obsvr":
                        found.append(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                root = node.module.split(".")[0]
                if root not in sys.stdlib_module_names and root != "obsvr":
                    found.append(node.module)
        return found

    @staticmethod
    def _records_binding(try_node):
        return any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "record_binding"
            for node in ast.walk(try_node)
        )

    def test_every_optional_import_block_records_a_binding(self):
        integrations_dir = (
            pathlib.Path(obsvr.integrations.__file__).resolve().parent
        )
        unrecorded = set()
        scanned_blocks = 0
        for source_file in sorted(integrations_dir.glob("*.py")):
            tree = ast.parse(source_file.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Try):
                    continue
                imports = self._third_party_imports(node)
                if not imports:
                    continue
                scanned_blocks += 1
                if not self._records_binding(node):
                    unrecorded.add((source_file.name, imports[0]))
        # The scan must be finding real blocks, or a refactor that moved the
        # directory would turn this into a vacuous pass.
        assert scanned_blocks >= 10, f"only {scanned_blocks} guarded blocks found"
        assert unrecorded == self.KNOWN_UNRECORDED, (
            "guarded third-party imports out of step with the allowlist.\n"
            f"  unrecorded now: {sorted(unrecorded)}\n"
            f"  allowlisted:    {sorted(self.KNOWN_UNRECORDED)}\n"
            "A NEW entry here is an optional-import block that records no "
            "binding - wire record_binding through it. A MISSING entry means "
            "an allowlisted block now records - delete it from the allowlist."
        )
