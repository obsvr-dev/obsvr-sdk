"""Process-level duplicate-instance guard (twin of sdk-typescript/src/proxy/instance-guard.ts).

The SDK can end up in a process twice: installed directly by the application
and again as a transitive dependency of something else, at two versions, in two
site-packages trees or under a vendored path. Both copies are real modules with
their own config, their own sender thread, and their own polling loop. Neither
knows about the other, so a call governed by both is emitted twice - duplicate
audit events for one call, two quota decrements, two policy polls per interval.

The fix has to survive module duplication, so a module-level variable is not
enough: two copies of this file have two of those. What every copy does share
is ``sys.modules``, so the slot lives there under a name no package would
otherwise use. That is the Python analogue of the TypeScript side's
``Symbol.for`` global slot.

**What yielding means, stated plainly:** the yielded copy does not start a
second polling loop and does not wrap clients. A client wrapped only through
the yielded copy is therefore NOT governed. That is deliberate - the
alternative is two engines governing the same call, which produces
contradictory evidence about what happened - but it means the warning is not
cosmetic, and it names the fix: deduplicate the dependency so one copy remains.

Version stance matches the TypeScript side: the incumbent keeps the slot, and
an older incumbent is called out explicitly, because "the copy governing your
traffic is older than the one you installed" is exactly the surprise an
operator needs told.
"""

import sys
import types
from typing import Any, Dict, Optional

__all__ = [
    "claim_governing_instance",
    "governing_instance",
    "is_governing_instance",
    "duplicate_instance_message",
    "_reset_instance_guard",
]

#: A key in sys.modules, shared by every copy of the package in this process.
_SLOT_NAME = "_obsvr_governing_instance"


def _slot() -> types.ModuleType:
    holder = sys.modules.get(_SLOT_NAME)
    if holder is None:
        holder = types.ModuleType(_SLOT_NAME)
        holder.instance = None  # type: ignore[attr-defined]
        sys.modules[_SLOT_NAME] = holder
    return holder


def _is_older(a: str, b: str) -> bool:
    """Numeric version compare; unparseable versions compare equal."""
    try:
        pa = [int(p) for p in a.split(".")[:3]]
        pb = [int(p) for p in b.split(".")[:3]]
    except (ValueError, AttributeError):
        return False
    if len(pa) < 3 or len(pb) < 3:
        return False
    return pa < pb


def claim_governing_instance(version: str, instance_id: str) -> Dict[str, Any]:
    """Claim the governing slot for this copy, or yield to whoever holds it.

    Idempotent for the same ``instance_id``: re-initializing the governing copy
    (a re-init with new config) keeps it governing and is not a duplicate.

    Returns a dict with ``governing`` plus, when yielding, ``incumbent`` and
    ``incumbent_is_older``.
    """
    holder = _slot()
    incumbent: Optional[Dict[str, str]] = getattr(holder, "instance", None)

    if incumbent is None or incumbent.get("instance_id") == instance_id:
        holder.instance = {"version": version, "instance_id": instance_id}  # type: ignore[attr-defined]
        return {"governing": True}

    return {
        "governing": False,
        "incumbent": dict(incumbent),
        "incumbent_is_older": _is_older(incumbent.get("version", ""), version),
    }


def governing_instance() -> Optional[Dict[str, str]]:
    """The copy currently holding the slot, if any."""
    return getattr(_slot(), "instance", None)


def is_governing_instance(instance_id: str) -> bool:
    """Whether the given copy holds the slot."""
    current = governing_instance()
    return bool(current and current.get("instance_id") == instance_id)


def duplicate_instance_message(result: Dict[str, Any]) -> str:
    """The message a yielding copy logs.

    Exactly one line, once per yielding copy: a duplicate install is one
    problem, not one problem per call.
    """
    incumbent = result.get("incumbent") or {}
    older_note = (
        " The governing copy is an OLDER version than this one."
        if result.get("incumbent_is_older")
        else ""
    )
    return (
        f"Another copy of the SDK (version {incumbent.get('version', 'unknown')}) is already "
        "governing this process, so this copy will not govern: it will not poll for policy and "
        f"clients wrapped through it are NOT governed.{older_note} "
        "Deduplicate obsvr-sdk in your dependency tree so exactly one copy is installed."
    )


def _reset_instance_guard() -> None:
    """Release the slot (tests, and any deliberate teardown)."""
    sys.modules.pop(_SLOT_NAME, None)
