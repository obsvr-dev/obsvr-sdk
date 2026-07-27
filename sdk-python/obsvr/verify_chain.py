"""Audit chain integrity verifier.

Recomputes every event's HMAC-SHA256 signature and validates the chain
linking, so evidence can be checked offline by whoever holds the API key -
without trusting obsvr, and without a Node toolchain. Twin of the TypeScript
``verifyAuditChain`` (sdk/src/governance/verify-chain.ts): same checks, same
order, same verdicts, same reason strings, so a mixed-language shop gets one
answer rather than two.

The checks, in the order a break is reported:

1. ``sdk_session_id`` is consistent across all events
2. every event declares the same signing format as the first (see
   chain_format.py; the result reports which format the chain used)
3. ``seq_no`` is present, starts at >= 1, and increases by exactly one
4. ``timestamp_sdk`` never decreases
5. ``prev_sig`` links to the prior event's ``sdk_sig``
6. the recomputed HMAC matches ``sdk_sig``, under the declared format

Verification is offline and off the hot path, so it does the thorough thing:
every event is re-signed from scratch rather than trusting any stored digest.

It also TALLIES what the chain admits it is missing: gap markers the sender
signed to record events the bounded queue dropped before they could be chained.
Those events left no hole to detect - they never got a sequence number - so the
marker is the only evidence they existed, and a verifier that returns valid
without surfacing it reports a lossy run as a complete one.

Cross-language determinism: nothing here sorts or collates text, so there is
no locale surface. Where ordering matters it is the numeric ``seq_no``, which
cannot diverge between languages the way locale-aware string collation can.

Parity is pinned by conformance/fixtures/signing_vectors.json, which both
suites consume (tests/test_verify_chain.py here,
sdk/tests/unit/signing-vectors.test.ts and the TS verifier there).

One documented edge: an event carrying an explicit ``null`` timestamp_sdk
mid-chain is rejected by both languages at the same index, but the reason
string can differ (JavaScript's null-to-zero coercion trips its
timestamp-monotonicity check first, while this implementation skips the
absent timestamp and trips on the signature). The verdict and the break
index - what a verification decision rests on - are identical either way.
"""

import hashlib
import hmac as hmac_mod
from dataclasses import dataclass
from typing import Any, Dict, Optional, Sequence

from .audit_gap import parse_audit_gap_prompt
from .chain_format import (
    CHAIN_FORMAT_CURRENT,
    CHAIN_FORMAT_LEGACY,
    signature_payload,
)
from .sender import derive_signing_key

__all__ = ["ChainVerificationResult", "verify_chain"]


@dataclass
class ChainVerificationResult:
    """Outcome of verifying one chain.

    Field names are Python-idiomatic; the values are the cross-language
    contract (twin: ``ChainVerificationResult`` in TypeScript, whose fields
    are ``valid`` / ``brokenAt`` / ``reason`` / ``eventsVerified``). Parity is
    asserted on values, never on layout.
    """

    valid: bool
    events_verified: int
    broken_at: Optional[int] = None
    reason: Optional[str] = None
    #: Gap markers found in the verified prefix - events the SDK signed to say
    #: it had dropped events before them (see audit_gap.py).
    gap_markers: int = 0
    #: Total events those markers declare lost. A chain can be perfectly valid
    #: and still be missing this many events: ``valid`` means what is here is
    #: genuine and in order, NOT that it is everything. Reporting them
    #: separately is the point - a caller that ignores this reads a saturated
    #: burst as a clean run.
    events_declared_lost: int = 0
    #: Signing format the chain was checked under (see chain_format.py): 2 for
    #: current chains, 1 for chains signed before length-prefixed content
    #: framing existed. Reported so a legacy chain never passes as silently
    #: equivalent to a current one - format 1 does not bind the
    #: prompt/response boundary, and a consumer weighing the evidence is
    #: entitled to know that. ``None`` when verification broke before the
    #: format could be established (empty chain, missing session id,
    #: unrecognized format value).
    chain_format: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """JSON-friendly view using the cross-language field names."""
        out: Dict[str, Any] = {"valid": self.valid, "eventsVerified": self.events_verified}
        if self.broken_at is not None:
            out["brokenAt"] = self.broken_at
        if self.reason is not None:
            out["reason"] = self.reason
        out["gapMarkers"] = self.gap_markers
        out["eventsDeclaredLost"] = self.events_declared_lost
        if self.chain_format is not None:
            out["chainFormat"] = self.chain_format
        return out


def _declared_format(event: Dict[str, Any]) -> Optional[int]:
    """The event's declared signing format.

    Absent means 1: legacy chains were signed before the field existed.
    Anything but 1 or 2 returns ``None`` - an unrecognized format fails
    closed rather than being guessed at. ``bool`` is excluded explicitly
    because it is an ``int`` subclass and ``True`` would read as format 1.
    """
    raw = event.get("chain_format")
    if raw is None:
        return CHAIN_FORMAT_LEGACY
    # A JSON number is a number: JavaScript parses 2.0 and 2 to the same
    # value, so an integral float counts as its integer here or the two
    # verifiers would return different verdicts on the same export.
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return None
    if raw == CHAIN_FORMAT_LEGACY:
        return CHAIN_FORMAT_LEGACY
    if raw == CHAIN_FORMAT_CURRENT:
        return CHAIN_FORMAT_CURRENT
    return None


def _compute_signature(
    signing_key: bytes,
    fmt: int,
    session_id: str,
    seq_no: int,
    timestamp_sdk: int,
    prompt: str,
    response: str,
    prev_sig: Optional[str],
) -> str:
    payload = signature_payload(
        fmt, session_id, seq_no, timestamp_sdk, prompt, response, prev_sig
    )
    return hmac_mod.new(signing_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_chain(events: Sequence[Dict[str, Any]], api_key: str) -> ChainVerificationResult:
    """Verify the integrity of an audit event chain.

    Args:
        events: the exported events, in emission order, as dicts with the
            wire field names (``sdk_session_id``, ``seq_no``,
            ``timestamp_sdk``, ``prompt``, ``response``, ``prev_sig``,
            ``sdk_sig``).
        api_key: the API key the events were signed under. The signing key is
            derived from it exactly as the sender derives it.

    Returns:
        A result whose ``valid`` says whether the whole chain verifies, and
        whose ``broken_at`` / ``reason`` locate and explain the first break.
        ``events_verified`` counts the events that verified before the break
        (all of them when valid).

    An empty chain is vacuously valid: there is nothing to contradict.
    """
    gap_markers = 0
    events_declared_lost = 0
    chain_format: Optional[int] = None

    def broken(index: int, reason: str) -> ChainVerificationResult:
        """A break: the gap tally covers only the prefix that verified."""
        return ChainVerificationResult(
            valid=False,
            broken_at=index,
            reason=reason,
            events_verified=index,
            gap_markers=gap_markers,
            events_declared_lost=events_declared_lost,
            chain_format=chain_format,
        )

    if not events:
        return ChainVerificationResult(valid=True, events_verified=0)

    signing_key = derive_signing_key(api_key)
    session_id = events[0].get("sdk_session_id")

    if not session_id:
        return broken(0, "First event missing sdk_session_id")

    # The first event fixes the chain's signing format. A chain is one
    # session, one process, one SDK build - no legitimate producer changes
    # format mid-chain, so a later event declaring a different format is a
    # break, not a negotiation. An unrecognized value fails closed: a newer
    # format is not guessed at by an older verifier.
    first_format = _declared_format(events[0])
    if first_format is None:
        return broken(
            0, f"Unsupported chain_format at event 0: {events[0].get('chain_format')}"
        )
    chain_format = first_format

    last_sig: Optional[str] = None
    last_seq = 0
    last_timestamp = 0

    for i, event in enumerate(events):
        if event.get("sdk_session_id") != session_id:
            return broken(
                i,
                f"Session ID mismatch at event {i}: expected {session_id}, "
                f"got {event.get('sdk_session_id')}",
            )

        fmt = _declared_format(event)
        if fmt is None:
            return broken(
                i, f"Unsupported chain_format at event {i}: {event.get('chain_format')}"
            )
        if fmt != chain_format:
            return broken(
                i,
                f"Chain format mismatch at event {i}: expected {chain_format}, got {fmt}",
            )

        seq_no = event.get("seq_no")
        if seq_no is None:
            return broken(i, f"Missing seq_no at event {i}")
        if i == 0:
            if seq_no < 1:
                return broken(i, f"Invalid initial seq_no: {seq_no}")
        elif seq_no != last_seq + 1:
            return broken(
                i, f"seq_no gap at event {i}: expected {last_seq + 1}, got {seq_no}"
            )
        last_seq = seq_no

        timestamp_sdk = event.get("timestamp_sdk")
        if timestamp_sdk is not None:
            if timestamp_sdk < last_timestamp:
                return broken(
                    i, f"Timestamp decreased at event {i}: {timestamp_sdk} < {last_timestamp}"
                )
            last_timestamp = timestamp_sdk

        if i > 0:
            # An absent prev_sig and an empty one are the same claim ("no
            # predecessor"), which is a break anywhere but the first event.
            if (event.get("prev_sig") or None) != last_sig:
                return broken(
                    i,
                    f"Chain break at event {i}: prev_sig does not match "
                    "prior event's sdk_sig",
                )

        expected_sig = _compute_signature(
            signing_key,
            chain_format,
            session_id,
            seq_no,
            timestamp_sdk if timestamp_sdk is not None else 0,
            event.get("prompt") or "",
            event.get("response") or "",
            event.get("prev_sig") or None,
        )

        # Constant-time compare: verification runs against attacker-supplied
        # signatures, and a timing oracle on the comparison is free to give
        # away otherwise.
        if not hmac_mod.compare_digest(str(event.get("sdk_sig") or ""), expected_sig):
            return broken(i, f"Signature mismatch at event {i}")

        last_sig = event.get("sdk_sig")

        # Counted only after the event's own signature verified: an unverified
        # marker's count is an unverified claim.
        gap = parse_audit_gap_prompt(event.get("prompt"))
        if gap:
            gap_markers += 1
            events_declared_lost += gap["dropped"]

    return ChainVerificationResult(
        valid=True,
        events_verified=len(events),
        gap_markers=gap_markers,
        events_declared_lost=events_declared_lost,
        chain_format=chain_format,
    )
