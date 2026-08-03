"""Audit chain integrity verifier.

Recomputes every event's HMAC-SHA256 signature and validates the chain
linking, so evidence can be checked offline by whoever holds the API key -
without trusting obsvr, and without a Node toolchain. Twin of the TypeScript
``verifyAuditChain`` (sdk-typescript/src/governance/verify-chain.ts): same checks, same
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
One pass reports EVERY break (``breaks``), re-anchoring on each breaking
event's own claims so independent tampers surface as independent breaks;
``broken_at`` / ``reason`` remain the first of them.

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
sdk-typescript/tests/unit/signing-vectors.test.ts and the TS verifier there).

One documented edge: an event carrying an explicit ``null`` timestamp_sdk
mid-chain is rejected by both languages at the same index, but the reason
string can differ (JavaScript's null-to-zero coercion trips its
timestamp-monotonicity check first, while this implementation skips the
absent timestamp and trips on the signature). The verdict and the break
index - what a verification decision rests on - are identical either way.
"""

import hashlib
import hmac as hmac_mod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from .audit_gap import read_audit_gap_claim
from .chain_format import (
    CHAIN_FORMATS_SUPPORTED,
    CHAIN_FORMAT_LEGACY,
    decision_fields_of,
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
    #: Every break found in one pass, in event order, each as
    #: ``{"index": int, "reason": str}``. ``broken_at`` / ``reason`` remain the
    #: FIRST entry, so existing readers keep working; this list is the full
    #: damage report - an auditor investigating a tampered export gets every
    #: independent break in one run instead of one index per run. After a
    #: break the verifier re-anchors on the breaking event's own claims
    #: (seq_no, timestamp, stored sdk_sig), so one tampered event yields one
    #: break rather than failing everything downstream of it.
    breaks: List[Dict[str, Any]] = field(default_factory=list)
    #: Signing format the chain was checked under (see chain_format.py): 3 for
    #: current chains, 2 for content-framed chains signed before the verdict
    #: entered the preimage, and 1 for chains signed before length-prefixed
    #: content framing existed. This list said "2 for current" and stopped
    #: there, so a current chain reported a value the documented vocabulary did
    #: not contain. Reported so a legacy chain never passes as silently
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
        # Always present, even empty: a consumer that never sees the key could
        # not tell "no breaks" from "a verifier too old to report them".
        out["breaks"] = list(self.breaks)
        if self.chain_format is not None:
            out["chainFormat"] = self.chain_format
        return out


def _declared_format(event: Dict[str, Any]) -> Optional[int]:
    """The event's declared signing format.

    Absent means 1: legacy chains were signed before the field existed.
    Anything outside ``CHAIN_FORMATS_SUPPORTED`` returns ``None`` - an
    unrecognized format fails closed rather than being guessed at, which is
    also what makes a chain from a NEWER SDK report unsupported rather than
    silently mis-verifying under an older rule. ``bool`` is excluded explicitly
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
    for supported in CHAIN_FORMATS_SUPPORTED:
        if raw == supported:
            return supported
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
    decision: Optional[Dict[str, Any]] = None,
) -> str:
    payload = signature_payload(
        fmt, session_id, seq_no, timestamp_sdk, prompt, response, prev_sig, decision
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
        A result whose ``valid`` says whether the whole chain verifies, whose
        ``breaks`` lists EVERY break found in one pass, and whose
        ``broken_at`` / ``reason`` locate and explain the first of them.
        ``events_verified`` counts the events that verified before the first
        break (all of them when valid).

    An empty chain is vacuously valid: there is nothing to contradict.
    """
    gap_markers = 0
    events_declared_lost = 0
    chain_format: Optional[int] = None
    breaks: List[Dict[str, Any]] = []

    def broken(index: int, reason: str) -> ChainVerificationResult:
        """A terminal break, before per-event scanning could even start: the
        gap tally covers only the prefix that verified."""
        breaks.append({"index": index, "reason": reason})
        return ChainVerificationResult(
            valid=False,
            broken_at=index,
            reason=reason,
            events_verified=index,
            gap_markers=gap_markers,
            events_declared_lost=events_declared_lost,
            chain_format=chain_format,
            breaks=breaks,
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
    #: ``None`` means "unknown": after an event with no usable seq_no, the next
    #: event's sequence is adopted as the new anchor rather than compared
    #: against a stale value, so one missing field is one break, not two.
    last_seq: Optional[int] = 0
    last_timestamp = 0

    def record_break(index: int, reason: str, event: Dict[str, Any]) -> None:
        """One break per event, then RE-ANCHOR on the event's own claims so
        scanning continues: an auditor gets every independent break in one
        run, and a single tampered event does not fail everything downstream
        of it. The stored sdk_sig anchors the linkage check even when it did
        not verify - the next event's prev_sig was minted against the stored
        value, so a mismatch there is a further, real inconsistency."""
        nonlocal last_seq, last_timestamp, last_sig
        breaks.append({"index": index, "reason": reason})
        seq = event.get("seq_no")
        last_seq = seq if isinstance(seq, int) and not isinstance(seq, bool) else None
        ts = event.get("timestamp_sdk")
        if isinstance(ts, (int, float)) and not isinstance(ts, bool):
            last_timestamp = ts
        sig = event.get("sdk_sig")
        last_sig = sig if isinstance(sig, str) else None

    for i, event in enumerate(events):
        if event.get("sdk_session_id") != session_id:
            # A foreign event is not part of this chain: it is reported and
            # SKIPPED, neither anchoring nor advancing the state the rest of
            # the session verifies against.
            breaks.append(
                {
                    "index": i,
                    "reason": f"Session ID mismatch at event {i}: expected "
                    f"{session_id}, got {event.get('sdk_session_id')}",
                }
            )
            continue

        fmt = _declared_format(event)
        if fmt is None:
            record_break(
                i, f"Unsupported chain_format at event {i}: {event.get('chain_format')}", event
            )
            continue
        if fmt != chain_format:
            record_break(
                i,
                f"Chain format mismatch at event {i}: expected {chain_format}, got {fmt}",
                event,
            )
            continue

        seq_no = event.get("seq_no")
        if seq_no is None:
            record_break(i, f"Missing seq_no at event {i}", event)
            continue
        if i == 0:
            if seq_no < 1:
                record_break(i, f"Invalid initial seq_no: {seq_no}", event)
                continue
        elif last_seq is not None and seq_no != last_seq + 1:
            record_break(
                i, f"seq_no gap at event {i}: expected {last_seq + 1}, got {seq_no}", event
            )
            continue
        last_seq = seq_no

        timestamp_sdk = event.get("timestamp_sdk")
        if timestamp_sdk is not None:
            if timestamp_sdk < last_timestamp:
                record_break(
                    i,
                    f"Timestamp decreased at event {i}: {timestamp_sdk} < {last_timestamp}",
                    event,
                )
                continue
            last_timestamp = timestamp_sdk

        if i > 0:
            # An absent prev_sig and an empty one are the same claim ("no
            # predecessor"), which is a break anywhere but the first event.
            if (event.get("prev_sig") or None) != last_sig:
                record_break(
                    i,
                    f"Chain break at event {i}: prev_sig does not match "
                    "prior event's sdk_sig",
                    event,
                )
                continue

        expected_sig = _compute_signature(
            signing_key,
            chain_format,
            session_id,
            seq_no,
            timestamp_sdk if timestamp_sdk is not None else 0,
            event.get("prompt") or "",
            event.get("response") or "",
            event.get("prev_sig") or None,
            # Format 3 folds these into the preimage; formats 1 and 2 ignore the
            # argument entirely, so one call site verifies every format. Read
            # through the SAME reader the signer used - two readers that
            # disagree about an absent field would make every event look
            # tampered with.
            decision_fields_of(event),
        )

        # Constant-time compare: verification runs against attacker-supplied
        # signatures, and a timing oracle on the comparison is free to give
        # away otherwise.
        if not hmac_mod.compare_digest(str(event.get("sdk_sig") or ""), expected_sig):
            record_break(i, f"Signature mismatch at event {i}", event)
            continue

        last_sig = event.get("sdk_sig")

        # Counted only after the event's own signature verified, and only in
        # the prefix before the first break - the tally a caller acts on must
        # not change because scanning now continues past a break.
        # Must require the event to BE a marker, not merely to contain the
        # string: parsing every prompt let a user forge a loss declaration.
        if not breaks:
            gap = read_audit_gap_claim(event)
            if gap:
                gap_markers += 1
                events_declared_lost += gap["dropped"]

    if breaks:
        return ChainVerificationResult(
            valid=False,
            broken_at=breaks[0]["index"],
            reason=breaks[0]["reason"],
            events_verified=breaks[0]["index"],
            gap_markers=gap_markers,
            events_declared_lost=events_declared_lost,
            chain_format=chain_format,
            breaks=breaks,
        )

    return ChainVerificationResult(
        valid=True,
        events_verified=len(events),
        gap_markers=gap_markers,
        events_declared_lost=events_declared_lost,
        chain_format=chain_format,
    )
