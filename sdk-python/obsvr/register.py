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
from typing import Any, Iterable, List, Optional

from .config import is_initialized, try_get_config
from .wrap import wrap

_installed: List[str] = []


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
    return Governed


originals: dict = {}


def install(providers: Optional[Iterable[str]] = None) -> List[str]:
    """Intercept provider client construction for installed SDKs.

    providers narrows which SDKs are governed (default: all installed).
    Returns the list of intercepted class labels. Idempotent.
    """
    if not _ensure_init():
        return []
    wanted = set(providers) if providers else {"openai", "anthropic"}
    done: List[str] = []

    if "openai" in wanted:
        try:
            import openai  # type: ignore
            for name in ("OpenAI", "AsyncOpenAI", "AzureOpenAI", "AsyncAzureOpenAI"):
                cls = getattr(openai, name, None)
                label = f"openai.{name}"
                if cls is not None and label not in _installed:
                    originals[label] = cls
                    setattr(openai, name, _governed_subclass(cls, label))
                    _installed.append(label)
                    done.append(label)
        except ImportError:
            pass

    if "anthropic" in wanted:
        try:
            import anthropic  # type: ignore
            for name in ("Anthropic", "AsyncAnthropic"):
                cls = getattr(anthropic, name, None)
                label = f"anthropic.{name}"
                if cls is not None and label not in _installed:
                    originals[label] = cls
                    setattr(anthropic, name, _governed_subclass(cls, label))
                    _installed.append(label)
                    done.append(label)
        except ImportError:
            pass

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
