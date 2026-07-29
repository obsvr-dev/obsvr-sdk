"""One governed call, one evidence record — however many times obsvr got
registered with a framework.

``obsvr.init()`` auto-wires the frameworks that offer a clean global
registration point, and a caller may also register a handler themselves. Both
handlers then receive the same callbacks and each emits, so a single LLM call
lands in the audit trail twice with distinct request ids, reading as two real
calls. Duplicate evidence is a defect on its own — it inflates any count taken
over the trail — and it doubles every cost and quota figure derived from the
token counts.

WHY THIS IS KEYED ON THE EVENT AND NOT ON THE HANDLER. The obvious fix is to
let the first-registered handler win and make later ones inert. That is wrong,
and wrong in the dangerous direction: a caller who does
``Settings.callback_manager = CallbackManager([handler])`` REPLACES the manager
obsvr auto-wired into, so the incumbent is detached and never fires while the
caller's handler is inert — zero events, from a fix meant to prevent two. The
question is not "which handler is allowed to speak" but "has this particular
call already been recorded", and only the second one is safe to answer.

The set is bounded and ordered so a long-running process cannot grow it without
limit; entries age out by insertion order, and the cap is far above any
plausible number of in-flight calls.
"""

from collections import OrderedDict
from threading import Lock
from typing import Optional

#: Far above any plausible in-flight call count, small enough to be free.
_MAX_REMEMBERED = 1024

_seen: "OrderedDict[str, None]" = OrderedDict()
_lock = Lock()


def claim_emission(key: Optional[str]) -> bool:
    """Whether the caller should emit for ``key``, or someone already has.

    A falsy key means the framework gave us nothing stable to deduplicate on.
    Emitting is the right answer there: a duplicate record is a lesser fault
    than a dropped one, and silently dropping evidence is the failure this
    whole exercise exists to find.
    """
    if not key:
        return True
    with _lock:
        if key in _seen:
            return False
        _seen[key] = None
        while len(_seen) > _MAX_REMEMBERED:
            _seen.popitem(last=False)
        return True


def _reset_dedupe() -> None:
    """Test seam: forget every claim so each test starts clean."""
    with _lock:
        _seen.clear()
