"""Destructive-capability hints read off tool descriptors.

Twin of ``sdk/src/policy/capability-hints.ts``; the decision table is pinned
cross-language in ``conformance/fixtures/session_taint.json``.

The session-taint latch's strongest control is the destructive-capability set:
a tainted session loses the tools that could do damage while ordinary egress is
only flagged, so one detection never bricks the session. That control was
operator-supplied only - an exact list of tool names in
``session_taint.destructive_tools``. An operator who configured nothing got no
capability gate at all, silently, which made the strongest thing in the SDK the
one most likely to be switched off by omission.

MCP tool descriptors already declare ``annotations.destructiveHint``, and the
SDK already hashes it as part of descriptor pinning. This module reads it, so a
discovered tool that declares itself destructive joins the set without anyone
having to write its name down.

The hint comes from the untrusted party
---------------------------------------

The descriptor is authored by the tool server, which is exactly the party the
taint latch exists to defend against. So the hint is admitted in ONE direction
only: it can ADD a tool to the destructive set, never remove one.

* ``destructiveHint: True`` adds the tool. An affirmative claim of danger from
  any source is worth acting on; the worst case is over-restriction of an
  already-compromised session.
* ``destructiveHint: False`` does nothing. It is a safety claim from an
  untrusted author, and honoring it would be letting a hostile server talk its
  way out of the gate by writing one word in its own descriptor.
* An ABSENT hint likewise does nothing: the tool is treated as non-destructive
  unless the operator listed it. This is the compatible default and it is
  deliberate - most deployed MCP servers publish no annotations at all, and
  treating silence as destructive would turn the ``flag`` posture into a
  blanket block for those servers, which is precisely what ``flag`` avoids.

That last point is a knowing departure from how the field is specified for MCP
itself, where an unspecified ``destructiveHint`` is read as true. That reading
makes sense for a client deciding how loudly to prompt a user. It does not
survive here, because a default of "destructive unless told otherwise" only
works if ``destructiveHint: False`` is honored - and the whole point of this
module is that it must not be. Given the choice between honoring a hostile
server's denial and treating silence as an accusation, the SDK does neither:
only an affirmative claim moves anything, and the operator's own list is always
available for the tools that matter.

Reading is strict (``is True``, not truthiness) so the decision is exactly
expressible in a fixture and identical in both languages. A server wanting to
escape the set can simply omit the field, so strictness costs nothing.

All of this runs at DISCOVERY, never on the call path: the store is written
during ``tools/list`` and read with one set-membership test at the gate.
"""

from __future__ import annotations

import threading
from typing import Any, List, Optional

__all__ = [
    "declares_destructive",
    "CapabilityStore",
    "create_capability_store",
    "MAX_HINTED_TOOLS",
]

# Bounded like the pin store, and for the same reason.
MAX_HINTED_TOOLS = 10_000


def _annotations_of(tool: Any) -> Optional[dict]:
    """The descriptor's ``annotations`` mapping, or None.

    Accepts both a plain dict descriptor and an object carrying the attribute,
    because the MCP Python SDK hands back models rather than dicts.
    """
    if tool is None:
        return None
    if isinstance(tool, dict):
        value = tool.get("annotations")
    else:
        value = getattr(tool, "annotations", None)
    if isinstance(value, dict):
        return value
    if value is None or isinstance(value, (str, bytes, int, float, bool, list, tuple)):
        return None
    # A model object: read the one field this module cares about off it.
    hint = getattr(value, "destructiveHint", None)
    return {"destructiveHint": hint}


def declares_destructive(tool: Any) -> bool:
    """Does this descriptor affirmatively declare itself destructive?

    True only for ``annotations.destructiveHint`` being exactly ``True``.
    Everything else - absent annotations, absent hint, ``False``, a string, a
    number - is False. See the module docstring for why this is
    one-directional.

    FAILS TOWARD DESTRUCTIVE. Reading an attribute off an attacker-supplied
    object can raise (a property, a ``__getattr__``), and a descriptor the SDK
    cannot read is precisely the case where it does not know. Treating that as
    "not destructive" would let a server escape the set by making the field
    unreadable rather than by lying in it, which is the same escape with an
    extra step. The cost of the other direction is bounded: over-adding only
    restricts a session that is ALREADY tainted.
    """
    try:
        annotations = _annotations_of(tool)
        if annotations is None:
            return False
        return annotations.get("destructiveHint") is True
    except Exception:  # noqa: BLE001 - deliberate: unreadable means unknown
        return True


class CapabilityStore:
    """Bounded per-client record of which discovered tools declared themselves
    destructive.

    Monotonic by name: once recorded, a later listing claiming the tool is now
    harmless does NOT clear it, for the same reason the hint cannot remove -
    that would be the rug-pull the descriptor pin already defends against,
    arriving through the capability gate instead.
    """

    def __init__(self) -> None:
        self._destructive: set = set()
        self._saturated = False
        self._lock = threading.Lock()

    def record(self, name: str, destructive: bool) -> None:
        """Record one discovered descriptor. Only a True hint has any effect."""
        if not destructive:
            return  # silence and denial are the same: no effect
        with self._lock:
            if name in self._destructive:
                return
            if len(self._destructive) >= MAX_HINTED_TOOLS:
                # Refuse rather than evict. Evicting would silently drop a
                # capability restriction, and an attacker who can flood a
                # listing would choose exactly which one to drop.
                self._saturated = True
                return
            self._destructive.add(name)

    def is_destructive(self, name: str) -> bool:
        """Was this tool name recorded destructive by a descriptor hint?"""
        with self._lock:
            return name in self._destructive

    def size(self) -> int:
        with self._lock:
            return len(self._destructive)

    def saturated(self) -> bool:
        """True once the store refused a recording because it was full."""
        with self._lock:
            return self._saturated

    def names(self) -> List[str]:
        """Every hinted-destructive name, sorted (event evidence)."""
        with self._lock:
            return sorted(self._destructive)


def create_capability_store() -> CapabilityStore:
    return CapabilityStore()
