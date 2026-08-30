"""Why an optional integration failed to bind, instead of only that it did.

Every framework integration binds its upstream symbols behind ``try/except`` and
falls back to a shim, so the module always imports and the SDK never hard-depends
on a framework the caller has not installed. That part is deliberate. What was
not deliberate is that the ``except`` discarded the exception, leaving a bare
``False`` flag — and three completely different situations produce the identical
bare ``False``:

  * the package is not installed at all (normal; nothing to fix),
  * the package is installed but a symbol was RENAMED upstream (an obsvr defect;
    the integration is silently inert while the manifest advertises support),
  * the package is installed and importable but a transitive dependency is
    broken (upstream's problem; the manifest should say so).

Only the middle one is obsvr's to fix, and the flag could not tell them apart.
That is why two real defects needed a manual reproduction to diagnose: an agent
framework renaming two symbols at its 1.0 GA, and a tool package that could not
import against a current transformers. Both looked exactly like "not installed".

The report is a plain dict of stdlib types — no dependency, no new transport, and
nothing is emitted anywhere. It is read on demand through
``obsvr.integration_bindings()``.
"""

from typing import Any, Dict, Iterable, List, Optional

#: integration name -> {symbol -> {"bound": bool, "error_type": str|None,
#:                                 "error": str|None}}
_BINDINGS: Dict[str, Dict[str, Dict[str, Any]]] = {}


class RequiredBindingsError(RuntimeError):
    """Raised when a deployment-declared integration is not completely bound."""

    def __init__(self, failures: List[Dict[str, Any]]) -> None:
        self.failures = [dict(failure) for failure in failures]
        summary = ", ".join(
            (
                f"{failure['integration']} was never bound"
                if failure["reason"] == "missing"
                else f"{failure['integration']}:{failure['symbol']} is unbound"
            )
            for failure in failures
        )
        super().__init__(f"Required obsvr bindings are not active: {summary}")


def record_binding(
    integration: str,
    symbol: str,
    error: Optional[BaseException] = None,
) -> None:
    """Record that ``symbol`` bound for ``integration``, or why it did not.

    Never raises: a diagnostic that can break an import is worse than no
    diagnostic. The message is truncated because an import error can carry a
    full path list and this is a summary, not a log.
    """
    entry: Dict[str, Any] = {"bound": error is None}
    if error is not None:
        # Each field is captured separately: an exception whose __str__ raises
        # must still be RECORDED as a failure. Losing the whole entry because
        # the message could not be rendered would put us back where we started,
        # with a bind that failed and left no trace.
        try:
            entry["error_type"] = type(error).__name__
        except Exception:  # pragma: no cover - defensive
            entry["error_type"] = "Unknown"
        try:
            entry["error"] = str(error)[:300]
        except Exception:  # pragma: no cover - defensive
            entry["error"] = "<exception message could not be rendered>"
    try:
        _BINDINGS.setdefault(integration, {})[symbol] = entry
    except Exception:  # pragma: no cover - defensive
        pass


def integration_bindings() -> Dict[str, Dict[str, Dict[str, Any]]]:
    """Every recorded bind, keyed by integration then symbol.

    Only integrations whose bind path has actually run appear — module-level
    binds record at import time, and call-time binds (a gate install probing
    its framework) record when that call runs. An integration nobody touched
    has nothing to report and saying otherwise would be a guess.
    """
    return {name: dict(symbols) for name, symbols in _BINDINGS.items()}


def unbound_symbols() -> List[Dict[str, Any]]:
    """The failures only, flattened — the list worth looking at when an
    integration is registered and quietly doing nothing."""
    out: List[Dict[str, Any]] = []
    for integration, symbols in _BINDINGS.items():
        for symbol, entry in symbols.items():
            if not entry.get("bound"):
                out.append(
                    {
                        "integration": integration,
                        "symbol": symbol,
                        "error_type": entry.get("error_type"),
                        "error": entry.get("error"),
                    }
                )
    return out


def required_binding_failures(required: Iterable[str]) -> List[Dict[str, Any]]:
    """Resolve requirements against binding paths that have actually run.

    Call this after the application's client/tool factory installs its
    integrations. A missing integration and a failed upstream symbol remain
    distinguishable, while both fail a deployment requirement.
    """
    failures: List[Dict[str, Any]] = []
    seen = set()
    for integration in required:
        if not isinstance(integration, str) or not integration.strip():
            raise TypeError("required bindings must be non-empty integration names")
        name = integration.strip()
        if name in seen:
            continue
        seen.add(name)
        symbols = _BINDINGS.get(name)
        if not symbols:
            failures.append(
                {"integration": name, "symbol": "", "reason": "missing"}
            )
            continue
        for symbol, entry in symbols.items():
            if not entry.get("bound"):
                failures.append(
                    {
                        "integration": name,
                        "symbol": symbol,
                        "reason": "unbound",
                        "error_type": entry.get("error_type"),
                        "error": entry.get("error"),
                    }
                )
    return failures


def assert_required_bindings(required: Iterable[str]) -> None:
    """Refuse startup when a deployment-declared integration is not bound."""
    failures = required_binding_failures(required)
    if failures:
        raise RequiredBindingsError(failures)


def _reset_bindings() -> None:
    """Test seam."""
    _BINDINGS.clear()
