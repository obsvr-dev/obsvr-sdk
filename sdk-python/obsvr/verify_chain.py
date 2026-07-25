"""Audit chain integrity verifier.

Recomputes every event's HMAC-SHA256 signature and validates the chain
linking, so evidence can be checked offline by whoever holds the API key -
without trusting obsvr, and without a Node toolchain. Twin of the TypeScript
``verifyAuditChain`` (sdk/src/governance/verify-chain.ts): same checks, same
order, same verdicts, same reason strings, so a mixed-language shop gets one
answer rather than two.

The checks, in the order a break is reported:

1. ``sdk_session_id`` is consistent across all events
2. ``seq_no`` is present, starts at >= 1, and increases by exactly one
3. ``timestamp_sdk`` never decreases
4. ``prev_sig`` links to the prior event's ``sdk_sig``
5. the recomputed HMAC matches ``sdk_sig``

Verification is offline and off the hot path, so it does the thorough thing:
every event is re-signed from scratch rather than trusting any stored digest.

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

    def to_dict(self) -> Dict[str, Any]:
        """JSON-friendly view using the cross-language field names."""
        out: Dict[str, Any] = {"valid": self.valid, "eventsVerified": self.events_verified}
        if self.broken_at is not None:
            out["brokenAt"] = self.broken_at
        if self.reason is not None:
            out["reason"] = self.reason
        return out


def _content_hash(prompt: str, response: str) -> str:
    return hashlib.sha256(((prompt or "") + (response or "")).encode("utf-8")).hexdigest()


def _compute_signature(
    signing_key: bytes,
    session_id: str,
    seq_no: int,
    timestamp_sdk: int,
    prompt: str,
    response: str,
    prev_sig: Optional[str],
) -> str:
    payload = "|".join(
        [
            session_id,
            str(seq_no),
            str(timestamp_sdk),
            _content_hash(prompt, response),
            prev_sig or "",
        ]
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
    if not events:
        return ChainVerificationResult(valid=True, events_verified=0)

    signing_key = derive_signing_key(api_key)
    session_id = events[0].get("sdk_session_id")

    if not session_id:
        return ChainVerificationResult(
            valid=False,
            broken_at=0,
            reason="First event missing sdk_session_id",
            events_verified=0,
        )

    last_sig: Optional[str] = None
    last_seq = 0
    last_timestamp = 0

    for i, event in enumerate(events):
        if event.get("sdk_session_id") != session_id:
            return ChainVerificationResult(
                valid=False,
                broken_at=i,
                reason=(
                    f"Session ID mismatch at event {i}: expected {session_id}, "
                    f"got {event.get('sdk_session_id')}"
                ),
                events_verified=i,
            )

        seq_no = event.get("seq_no")
        if seq_no is None:
            return ChainVerificationResult(
                valid=False, broken_at=i, reason=f"Missing seq_no at event {i}", events_verified=i
            )
        if i == 0:
            if seq_no < 1:
                return ChainVerificationResult(
                    valid=False,
                    broken_at=i,
                    reason=f"Invalid initial seq_no: {seq_no}",
                    events_verified=i,
                )
        elif seq_no != last_seq + 1:
            return ChainVerificationResult(
                valid=False,
                broken_at=i,
                reason=f"seq_no gap at event {i}: expected {last_seq + 1}, got {seq_no}",
                events_verified=i,
            )
        last_seq = seq_no

        timestamp_sdk = event.get("timestamp_sdk")
        if timestamp_sdk is not None:
            if timestamp_sdk < last_timestamp:
                return ChainVerificationResult(
                    valid=False,
                    broken_at=i,
                    reason=(
                        f"Timestamp decreased at event {i}: {timestamp_sdk} < {last_timestamp}"
                    ),
                    events_verified=i,
                )
            last_timestamp = timestamp_sdk

        if i > 0:
            # An absent prev_sig and an empty one are the same claim ("no
            # predecessor"), which is a break anywhere but the first event.
            if (event.get("prev_sig") or None) != last_sig:
                return ChainVerificationResult(
                    valid=False,
                    broken_at=i,
                    reason=(
                        f"Chain break at event {i}: prev_sig does not match "
                        "prior event's sdk_sig"
                    ),
                    events_verified=i,
                )

        expected_sig = _compute_signature(
            signing_key,
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
            return ChainVerificationResult(
                valid=False,
                broken_at=i,
                reason=f"Signature mismatch at event {i}",
                events_verified=i,
            )

        last_sig = event.get("sdk_sig")

    return ChainVerificationResult(valid=True, events_verified=len(events))
