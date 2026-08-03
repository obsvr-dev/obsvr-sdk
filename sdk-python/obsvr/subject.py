"""Per-request ambient subject attribution.

``use_subject(subject)`` binds an ambient end-user identity for the duration
of the ``with`` block via a :class:`contextvars.ContextVar`. Governed calls
made inside attribute to that subject WITHOUT threading ``user_id`` through
every call — the SDK fills ``user_id`` / ``service_name`` from the ambient
subject when the call doesn't specify them (explicit options always win).
This feeds both channels the same way: the signed event principal
(``events.build_audit_event``) and the enforcing identity metadata the
per-user quota and session-taint scoping read.

Python twin of the TypeScript SDK's ``useSubject()``
(``sdk-typescript/src/proxy/subject.ts``): same string forms, same
nested-scope merge, same explicit-wins precedence. The scoping idiom is the
one this SDK already uses for spans (``span.py``) and agent runs
(``agent_run.py``): set the ContextVar on entry, ``reset(token)`` in a
``finally`` so the previous subject is restored on success, exception and
generator close alike.

::

    with obsvr.use_subject("user:alice;tenant:acme"):
        agent.run(...)   # events attributed to alice / acme

CONTEXT-PROPAGATION BOUNDARIES — measured on the stdlib, not assumed. A
``ContextVar`` follows the *context*, and not every way of moving work copies
the context:

    survives                          silently lost
    ------------------------------    ------------------------------
    plain ``await``                   ``loop.run_in_executor``
    ``asyncio.create_task``           ``concurrent.futures.ThreadPoolExecutor.submit``
    ``asyncio.to_thread``             ``threading.Thread``

Work handed across a losing boundary resolves NO ambient subject: the call
attributes exactly as it would outside any ``use_subject`` scope (the
wrap-time identity, or none), with nothing recorded about the loss. A tool
that hops to a worker thread through one of those APIs must carry the
identity explicitly (``user_id=`` / ``metadata=``) or wrap the callable with
``contextvars.copy_context()``. The boundary matrix is pinned by
``tests/test_subject.py`` so a runtime change surfaces as a test failure
rather than a silent misattribution.

There are exactly two establishment sources: an explicit option on the call
or wrapper, and this ambient scope. No environment-variable or
device-identity fallback exists, deliberately — every recorded principal is
one an application stated in code.
"""

import re
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Dict, Iterator, Optional, Union

__all__ = ["parse_subject", "use_subject", "get_current_subject"]

#: The ambient subject for the current context, or None outside any scope.
#: Keys: ``user_id`` / ``tenant_id`` / ``service_name`` (same shape as the
#: TypeScript ``Subject``).
_current_subject: "ContextVar[Optional[Dict[str, str]]]" = ContextVar(
    "obsvr_subject", default=None
)

_KEYED_PART = re.compile(r"^([a-z_]+)\s*[:=]\s*(.+)$", re.IGNORECASE)

#: Accepted spellings per subject field (twin of subject.ts parseSubject).
_KEY_ALIASES = {
    "user": "user_id",
    "user_id": "user_id",
    "tenant": "tenant_id",
    "tenant_id": "tenant_id",
    "service": "service_name",
    "service_name": "service_name",
}


def parse_subject(subject: Union[str, Dict[str, Any]]) -> Dict[str, str]:
    """Parse a subject: a dict, or a string like ``"user:alice"``,
    ``"user:alice;tenant:acme"``, ``"user=alice,service=api"``, or a bare
    ``"alice"`` (treated as ``user_id``). A dict is copied, never aliased."""
    if not isinstance(subject, str):
        return dict(subject)
    out: Dict[str, str] = {}
    for part in re.split(r"[;,]", subject):
        trimmed = part.strip()
        if not trimmed:
            continue
        match = _KEYED_PART.match(trimmed)
        if not match:
            # bare token -> user_id
            out["user_id"] = trimmed
            continue
        key = _KEY_ALIASES.get(match.group(1).lower())
        if key:
            out[key] = match.group(2).strip()
    return out


@contextmanager
def use_subject(subject: Union[str, Dict[str, Any]]) -> Iterator[Dict[str, str]]:
    """Run a block with ``subject`` bound as the ambient subject.

    Nested scopes merge over the enclosing subject (inner values win).
    Survives plain ``await`` — and see the module docstring for the
    boundaries it does NOT survive. The previous subject is restored in a
    ``finally``, so an exception inside the block cannot leak this scope's
    identity into later, unrelated calls.
    """
    parsed = parse_subject(subject)
    current = _current_subject.get() or {}
    token = _current_subject.set({**current, **parsed})
    try:
        yield _current_subject.get() or {}
    finally:
        _current_subject.reset(token)


def get_current_subject() -> Optional[Dict[str, str]]:
    """The ambient subject, if a :func:`use_subject` scope is active."""
    return _current_subject.get()
