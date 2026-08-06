"""Zero-code interception (Python twin of node --import @obsvr/sdk/register).

    import obsvr.register  # before importing openai / anthropic clients

or explicitly:

    from obsvr.register import install
    install(providers=["openai"])

Design parity with the TS interceptor's no-monkey-patching rule: provider
class METHODS and PROTOTYPES are never touched. Interception happens at
construction only - the module's client class attribute is replaced with a
thin subclass whose constructor returns an obsvr-wrapped instance (the same
proxy wrap() produces). The returned object is a transparent proxy for
attribute access and calls, but note it is NOT the original client type:
`isinstance(client, OpenAI)` is False after interception, so code that
type-checks its client should wrap() explicitly instead of relying on
register.

Configuration comes from the environment when init() has not run yet:
OBSVR_API_KEY (required), OBSVR_INGEST_URL, OBSVR_ENVIRONMENT.
"""

import logging
import os
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .config import is_initialized, try_get_config
from .wrap import wrap

_installed: List[str] = []

#: Where the search for a provider's client classes STARTS. These are seeds,
#: not the set of names that gets replaced: the names below are resolved to
#: class OBJECTS and the module is then swept for every attribute bound to one
#: of those objects (or to a subclass of one). Read
#: :func:`_client_classes_by_name` for why a name list cannot be the patch set.
_PROVIDER_SEEDS: Dict[str, Tuple[str, ...]] = {
    "openai": ("OpenAI", "AsyncOpenAI", "AzureOpenAI", "AsyncAzureOpenAI"),
    "anthropic": ("Anthropic", "AsyncAnthropic"),
}


def _ensure_init() -> bool:
    if is_initialized():
        return try_get_config() is not None
    api_key = os.environ.get("OBSVR_API_KEY")
    if not api_key:
        logging.getLogger("obsvr").warning("register: OBSVR_API_KEY not set and init() not called - interception disabled")
        return False
    from .config import init
    init(
        api_key=api_key,
        ingest_url=os.environ.get("OBSVR_INGEST_URL"),
        environment=os.environ.get("OBSVR_ENVIRONMENT"),
    )
    return True


def _governed_subclass(cls: type, label: str) -> type:
    """A subclass whose constructor hands back a wrapped instance.

    __new__ builds the real client via the ORIGINAL class, then returns the
    obsvr proxy around it. No method or attribute of the original class is
    modified; unwrapped construction stays available via the original class
    object, which callers can still reach as obsvr.register.originals[label].
    """

    class Governed(cls):  # type: ignore[misc,valid-type]
        def __new__(_gcls, *args: Any, **kwargs: Any):  # noqa: N804
            real = cls(*args, **kwargs)
            return wrap(real)

    Governed.__name__ = cls.__name__
    Governed.__qualname__ = cls.__qualname__
    Governed.__module__ = cls.__module__
    setattr(Governed, _GOVERNED_CLASS_MARKER, True)
    return Governed


originals: dict = {}


#: Set on every subclass this module builds, so a second install() can tell a
#: governed class from a client class and never gates a gate.
_GOVERNED_CLASS_MARKER = "_obsvr_governed_client_class"


def _client_base(module_name: str, roots: List[type]) -> Optional[type]:
    """The provider's own base client class, derived from a seed's ancestry.

    Walking a seed's MRO and keeping the DEEPEST ancestor still defined inside
    the provider's package lands on the class every one of that package's
    clients descends from (``openai._base_client.BaseClient``,
    ``anthropic._base_client.BaseClient``). Deriving it means the gateway
    flavours a provider ships — Azure, Bedrock, Vertex, Foundry, and whatever it
    adds next — are found by ANCESTRY rather than by being named here. Several
    of them are not subclasses of the primary client at all, so a sweep rooted
    only at the seeds would miss them, and a list naming them would be the same
    defect one level up.
    """
    base: Optional[type] = None
    for root in roots:
        for cls in root.__mro__[1:]:
            if cls.__module__.split(".")[0] == module_name:
                base = cls
    return base


def _client_classes_by_name(
    module: Any, module_name: str, seeds: Iterable[str]
) -> List[Tuple[type, List[str]]]:
    """Group this module's client classes by the class object each name binds.

    A NAME LIST CANNOT BE THE PATCH SET, because a provider package binds one
    class object to more than one attribute. ``anthropic.Client is
    anthropic.Anthropic`` and ``openai.Client is openai.OpenAI`` are both True:
    two module attributes, one class. Replacing the attribute this SDK happened
    to enumerate leaves every other name pointing at the ORIGINAL class, so a
    caller constructing through the other one is not governed — and nothing says
    so, because interception reported the name it did replace. That is how
    ``langchain_anthropic`` (which constructs via ``anthropic.Client(**params)``)
    escaped ``auto=True`` entirely while ``init()`` reported success.

    So the seeds are resolved to class OBJECTS, their shared in-package base is
    derived (:func:`_client_base`), and the module is then swept for every
    PUBLIC attribute that is a client class. Every name in one group is rebound
    to the SAME governed subclass, so the package's own aliasing survives
    interception — ``anthropic.Client is anthropic.Anthropic`` is still True
    afterwards, which is a property callers already rely on.

    Underscore-prefixed names are left alone. A provider's private client
    classes are built by the package's own lazy module machinery rather than by
    a caller, and substituting one puts an obsvr proxy inside the package's
    internals rather than in front of a construction a user wrote.

    The sweep reads a SNAPSHOT of ``vars(module)`` rather than ``dir()``: the
    module __dict__ holds what the package has actually bound, asking for a name
    a lazy module __getattr__ would materialize could import a submodule this
    process never needed — and the openai module mutates its own __dict__ during
    attribute access, so an unsnapshotted iteration raises.
    """
    roots: List[type] = []
    for name in seeds:
        cls = getattr(module, name, None)
        if isinstance(cls, type) and not any(cls is seen for seen in roots):
            roots.append(cls)
    if not roots:
        return []

    targets = list(roots)
    base = _client_base(module_name, roots)
    if base is not None:
        targets.append(base)

    groups: List[Tuple[type, List[str]]] = []
    for name, value in list(vars(module).items()):
        if name.startswith("_") or not isinstance(value, type):
            continue
        if getattr(value, _GOVERNED_CLASS_MARKER, False):
            continue  # already a gate; gating it again would nest proxies
        if base is not None and value is base:
            # The derived base is the thing SUBCLASSES are recognized by, not a
            # client anyone constructs. Governing it would wrap an abstract
            # class whose instances are never the ones making calls.
            continue
        try:
            if not any(value is t or issubclass(value, t) for t in targets):
                continue
        except TypeError:  # noqa: PERF203 - an exotic metaclass is not a client
            continue
        for cls, names in groups:
            if cls is value:
                names.append(name)
                break
        else:
            groups.append((value, [name]))
    return groups


def _install_provider(module_name: str, seeds: Iterable[str]) -> List[str]:
    """Govern construction of every client class this module exposes.

    One governed subclass per class OBJECT, installed on every attribute bound
    to it, and each write is READ BACK: a module that resents the assignment
    (a lazy loader that re-materializes, a __getattr__ shim) must not be
    reported as intercepted. Only labels whose write verifiably took are
    returned, so the report ``init(auto=True)`` prints names what is actually
    governed rather than what was attempted.
    """
    try:
        module = __import__(module_name)
    except ImportError:
        return []
    except Exception as exc:  # noqa: BLE001 - a provider that fails to import
        logging.getLogger("obsvr").debug(
            "register: %s could not be imported: %s", module_name, exc
        )
        return []

    done: List[str] = []
    for cls, names in _client_classes_by_name(module, module_name, seeds):
        pending = [n for n in names if f"{module_name}.{n}" not in _installed]
        if not pending:
            continue
        governed = _governed_subclass(cls, f"{module_name}.{pending[0]}")
        for name in pending:
            label = f"{module_name}.{name}"
            try:
                setattr(module, name, governed)
                took = getattr(module, name, None) is governed
            except Exception:  # noqa: BLE001 - a module that vetoes the write
                took = False
            if not took:
                logging.getLogger("obsvr").warning(
                    "register: could not intercept %s - construction through that "
                    "name is NOT governed; use obsvr.wrap() on the client",
                    label,
                )
                continue
            originals[label] = cls
            _installed.append(label)
            done.append(label)
    return done


def install(providers: Optional[Iterable[str]] = None) -> List[str]:
    """Intercept provider client construction for installed SDKs.

    providers narrows which SDKs are governed (default: all installed).
    Returns the list of intercepted class labels — every ALIAS included, not
    one label per provider. Idempotent.
    """
    if not _ensure_init():
        return []
    wanted = set(providers) if providers else set(_PROVIDER_SEEDS)
    done: List[str] = []
    for module_name, seeds in _PROVIDER_SEEDS.items():
        if module_name in wanted:
            done.extend(_install_provider(module_name, seeds))
    return done


def uninstall() -> None:
    """Restore the original client classes (tests / explicit opt-out)."""
    for label, cls in originals.items():
        mod_name, cls_name = label.split(".", 1)
        try:
            mod = __import__(mod_name)
            setattr(mod, cls_name, cls)
        except Exception:
            pass
    originals.clear()
    _installed.clear()


# Importing the module installs interception (parity with --import register).
install()
