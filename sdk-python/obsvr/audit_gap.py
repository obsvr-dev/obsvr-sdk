"""Audit gap markers - the signed record of events that never reached the chain.

The bounded sender queue drops events when it is full. Those drops happen
BEFORE a sequence number is assigned (this SDK even rolls the chain head back
on a losing race), so the surviving chain is contiguous and verifies clean: the
record says nothing happened, when in a saturated burst most of what happened
is missing. Counters in ``get_sender_stats()`` see it, but counters live in the
process that lost the events and are not evidence - they are gone the moment it
exits.

A gap marker closes that: one real, signed, chain-linked event that states how
many events were lost immediately before it. It is emitted at the first moment
the queue has room again, so it occupies the chain position between the last
event that survived and the first event after the loss.

WHY THE COUNT LIVES IN ``prompt``: the HMAC preimage covers a content hash of
``prompt`` and ``response`` (in every chain format - see chain_format.py), and
metadata is deliberately NOT in it, so a count carried only in metadata could
be edited from 10,000 to 1 without breaking a single signature - a
tamper-evident record whose one load-bearing number is not tamper-evident.
Putting the canonical statement in the signed content preimage costs no
chain-format change and no verifier special case: the marker verifies exactly
like any other event, and its claim is covered by the same HMAC. The structured copy in
``metadata.obsvr_audit_gap`` exists for querying; when the two disagree, the
signed ``prompt`` is the one that means anything.

Twin of sdk/src/proxy/audit-gap.ts, and dependency-free for the same reason:
the verifier must not import the sender's module-level state to read a string.
The preimage is byte-identical across both SDKs, pinned by
conformance/fixtures/audit_gap.json.
"""

import re
from typing import Any, Dict, Optional

__all__ = [
    "AUDIT_GAP_FORMAT",
    "AUDIT_GAP_REASON_QUEUE_OVERFLOW",
    "AUDIT_GAP_METADATA_KEY",
    "AUDIT_GAP_GOVERNANCE_EVENT",
    "AUDIT_GAP_OPERATION",
    "format_audit_gap_prompt",
    "parse_audit_gap_prompt",
]

#: Preimage format version. Bumping it changes the signed bytes, so a reader can
#: tell a marker it fully understands from one written by a newer SDK.
AUDIT_GAP_FORMAT = "obsvr:audit-gap/1"

#: Events dropped because the bounded sender queue was full.
AUDIT_GAP_REASON_QUEUE_OVERFLOW = "queue_overflow"

#: Reserved metadata key carrying the structured (unsigned) copy of the claim.
AUDIT_GAP_METADATA_KEY = "obsvr_audit_gap"

#: ``metadata.governance_event`` value, matching the ``governance_disabled`` precedent.
AUDIT_GAP_GOVERNANCE_EVENT = "audit_gap"

#: ``operation`` stamped on a marker event.
AUDIT_GAP_OPERATION = "audit.gap"

_AUDIT_GAP_PROMPT_RE = re.compile(
    r"^" + re.escape(AUDIT_GAP_FORMAT) + r" dropped=(\d+) reason=([a-z0-9_]+)$"
)


def format_audit_gap_prompt(
    dropped: int, reason: str = AUDIT_GAP_REASON_QUEUE_OVERFLOW
) -> str:
    """The canonical signed statement of a gap.

    Byte-identical to the TypeScript ``formatAuditGapPrompt`` - it goes through
    SHA-256 into an HMAC, so a single character of drift makes the two
    languages sign different markers.
    """
    return f"{AUDIT_GAP_FORMAT} dropped={dropped} reason={reason}"


def parse_audit_gap_prompt(prompt: Any) -> Optional[Dict[str, Any]]:
    """Read a marker's claim back out of its signed content.

    Returns ``{"dropped": int, "reason": str}``, or ``None`` if this is not a
    marker. Deliberately strict: a near-miss is treated as an ordinary event
    rather than guessed at, because the alternative is inventing a loss count
    from a string that was never a marker.
    """
    if not isinstance(prompt, str):
        return None
    match = _AUDIT_GAP_PROMPT_RE.match(prompt)
    if not match:
        return None
    return {"dropped": int(match.group(1)), "reason": match.group(2)}
