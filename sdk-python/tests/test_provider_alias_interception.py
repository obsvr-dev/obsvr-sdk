"""Construct interception reaches EVERY public name a client class is bound to.

A provider package binds one class object to more than one module attribute:
``anthropic.Client is anthropic.Anthropic`` and ``openai.Client is
openai.OpenAI`` are both True. Interception used to enumerate names and replace
the ones it listed, so construction through any other name reached the ORIGINAL
class — ungoverned, with ``init(auto=True)`` reporting success. That is how
``langchain_anthropic``, which constructs via ``anthropic.Client(**params)``,
escaped governance entirely: a PII policy was loaded, looked active, and blocked
nothing.

Two kinds of test here, and both are needed:

* the SYNTHETIC module proves the MECHANISM is alias-agnostic — it never names
  ``Client``, so a fix that special-cased that one name would fail it;
* the REAL packages prove the mechanism against what upstream actually ships,
  and are the half that fails when a provider adds a client class. They skip
  when the optional provider is not installed, because a silent pass on an
  absent package is the same false all-clear the defect was.
"""

import sys
import types

import pytest

import obsvr
from obsvr.register import install, uninstall
from obsvr.binding_report import integration_bindings


@pytest.fixture(autouse=True)
def _clean_interception(monkeypatch):
    # Depend on monkeypatch so uninstall() runs before synthetic provider
    # modules are restored to their real package objects during teardown.
    uninstall()
    yield
    uninstall()


def _init():
    obsvr.init(
        api_key="test-key",
        ingest_url="http://127.0.0.1:1",
        environment="development",
        auto=False,
    )


def _synthetic_provider(monkeypatch, module_name, primary, aliases, extra_clients=()):
    """A provider module shaped like the real ones: one class, several names."""
    module = types.ModuleType(module_name)

    class BaseClient:
        def __init__(self, **kwargs):
            self.options = kwargs

    # Shaped like the real packages, where the base client is defined INSIDE the
    # provider package: that is what lets the sweep derive it from a seed's
    # ancestry instead of being told its name.
    BaseClient.__module__ = module_name
    primary_cls = types.new_class(primary, (BaseClient,))
    primary_cls.__module__ = module_name
    setattr(module, primary, primary_cls)
    for alias in aliases:
        setattr(module, alias, primary_cls)  # SAME object, second name
    for name in extra_clients:
        cls = types.new_class(name, (BaseClient,))
        cls.__module__ = module_name
        setattr(module, name, cls)
    module.BaseClient = BaseClient
    module.NotAClient = object()
    monkeypatch.setitem(sys.modules, module_name, module)
    return module


def test_every_alias_of_a_client_class_is_intercepted(monkeypatch):
    """The mechanism is identity-based: no name in this test appears in the SDK."""
    module = _synthetic_provider(
        monkeypatch, "anthropic", "Anthropic", ["Client", "LegacyHandle"]
    )
    _init()
    install(providers=["anthropic"])

    for name in ("Anthropic", "Client", "LegacyHandle"):
        client = getattr(module, name)(api_key="x")
        assert type(client).__name__ == "_ObsvrProxy", (
            f"anthropic.{name}() escaped construct interception"
        )
    report = integration_bindings()["anthropic"]
    for name in ("Anthropic", "Client", "LegacyHandle"):
        assert report[f"anthropic.{name}"]["bound"] is True


def test_aliases_still_point_at_one_class_after_interception(monkeypatch):
    """Interception must not BREAK the package's own aliasing.

    Replacing one name and leaving the other made ``Client is Anthropic`` False,
    which is itself a behaviour change callers can trip over. Every name for one
    class is rebound to one governed subclass.
    """
    module = _synthetic_provider(monkeypatch, "anthropic", "Anthropic", ["Client"])
    _init()
    install(providers=["anthropic"])
    assert module.Client is module.Anthropic


def test_sibling_client_classes_are_intercepted_too(monkeypatch):
    """Gateway flavours descend from the package's base client, not from the
    primary client, so an identity-only sweep would miss them."""
    module = _synthetic_provider(
        monkeypatch,
        "anthropic",
        "Anthropic",
        ["Client"],
        extra_clients=("AnthropicVertex", "AnthropicBedrock"),
    )
    _init()
    install(providers=["anthropic"])
    for name in ("AnthropicVertex", "AnthropicBedrock"):
        assert type(getattr(module, name)()).__name__ == "_ObsvrProxy", (
            f"anthropic.{name}() escaped construct interception"
        )


def test_private_names_are_left_alone(monkeypatch):
    """A package's private client is built by its own lazy machinery, not by a
    caller; substituting one puts a proxy inside the package's internals."""
    module = _synthetic_provider(monkeypatch, "anthropic", "Anthropic", ["Client"])

    class _ModuleClient(module.Anthropic):
        pass

    module._ModuleClient = _ModuleClient
    _init()
    install(providers=["anthropic"])
    assert module._ModuleClient is _ModuleClient


def test_uninstall_restores_every_name(monkeypatch):
    module = _synthetic_provider(monkeypatch, "anthropic", "Anthropic", ["Client"])
    original = module.Anthropic
    _init()
    install(providers=["anthropic"])
    assert module.Anthropic is not original
    uninstall()
    assert module.Anthropic is original
    assert module.Client is original


def test_install_is_idempotent(monkeypatch):
    module = _synthetic_provider(monkeypatch, "anthropic", "Anthropic", ["Client"])
    _init()
    first = install(providers=["anthropic"])
    governed = module.Anthropic
    second = install(providers=["anthropic"])
    assert sorted(first) == ["anthropic.Anthropic", "anthropic.Client"]
    assert second == []
    assert module.Anthropic is governed  # not re-wrapped


# ── The same invariant against what upstream actually ships ─────────────────


def _real_client_names(module, module_name):
    """Public exported classes descending from the package's own base client."""
    seed = getattr(module, "Anthropic", None) or getattr(module, "OpenAI", None)
    base = None
    for cls in seed.__mro__[1:]:
        if cls.__module__.split(".")[0] == module_name:
            base = cls
    names = []
    for name, value in list(vars(module).items()):
        if name.startswith("_") or not isinstance(value, type):
            continue
        try:
            if base is not None and issubclass(value, base):
                names.append(name)
        except TypeError:
            continue
    return sorted(names)


@pytest.mark.parametrize("module_name", ["openai", "anthropic"])
def test_real_package_has_no_ungoverned_client_class(module_name):
    """Every public client class the installed package exports is intercepted.

    This is the half that fails when upstream adds a client class or a new
    alias, which is the whole point: the previous behaviour was that such an
    addition reached a customer silently.
    """
    module = pytest.importorskip(
        module_name, reason=f"{module_name} is an optional provider extra"
    )
    _init()
    install(providers=[module_name])
    ungoverned = [
        name
        for name in _real_client_names(module, module_name)
        if not getattr(getattr(module, name), "_obsvr_governed_client_class", False)
    ]
    assert ungoverned == [], (
        f"{module_name} exports client classes construct interception does not "
        f"reach: {ungoverned}"
    )


@pytest.mark.parametrize(
    "module_name,names",
    [("openai", ("OpenAI", "Client")), ("anthropic", ("Anthropic", "Client"))],
)
def test_real_package_constructs_governed_through_every_alias(module_name, names):
    module = pytest.importorskip(
        module_name, reason=f"{module_name} is an optional provider extra"
    )
    _init()
    install(providers=[module_name])
    for name in names:
        client = getattr(module, name)(api_key="sk-fake")
        assert type(client).__name__ == "_ObsvrProxy", (
            f"{module_name}.{name}() escaped construct interception"
        )


# ── The same defect one scope out: a name held by ANOTHER module ────────────


def test_a_framework_that_already_imported_the_class_is_reached(monkeypatch):
    """``from openai import OpenAI`` binds the CLASS OBJECT into the importing
    module, so rebinding ``openai.OpenAI`` afterwards cannot reach it.

    A framework imported before ``init(auto=True)`` therefore kept constructing
    the ungoverned class while the report named every provider alias as
    intercepted and nothing warned — each write on the provider module
    genuinely took. Measured on crewai, ag2, LlamaIndex, Haystack and
    openai-agents: all five hold such a binding, three of them from the bare
    top-level import.
    """
    _synthetic_provider(monkeypatch, "anthropic", "Anthropic", ["Client"])
    provider = sys.modules["anthropic"]

    framework = types.ModuleType("pretend_framework")
    # Exactly what `from anthropic import Anthropic` leaves behind.
    framework.Anthropic = provider.Anthropic
    framework.SomethingElse = object()
    monkeypatch.setitem(sys.modules, "pretend_framework", framework)

    _init()
    labels = install(providers=["anthropic"])

    assert getattr(framework.Anthropic, "_obsvr_governed_client_class", False), (
        "the framework's own binding still points at the ungoverned class"
    )
    assert "pretend_framework.Anthropic" in labels, (
        "the report did not name the binding it reached"
    )
    assert type(framework.Anthropic(api_key="sk-fake")).__name__ == "_ObsvrProxy"


def test_an_unrelated_class_of_the_same_name_is_left_alone(monkeypatch):
    """Resolved by IDENTITY, never by name. LlamaIndex exports its own
    ``OpenAI`` LLM class alongside the provider client it holds; rebinding that
    one would replace a framework's public API with a provider proxy."""
    _synthetic_provider(monkeypatch, "anthropic", "Anthropic", ["Client"])

    class Anthropic:  # same name, unrelated object
        pass

    framework = types.ModuleType("pretend_framework")
    framework.Anthropic = Anthropic
    monkeypatch.setitem(sys.modules, "pretend_framework", framework)

    _init()
    install(providers=["anthropic"])

    assert framework.Anthropic is Anthropic, (
        "an unrelated class was rebound because it shared a name"
    )
