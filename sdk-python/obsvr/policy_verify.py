"""SDK-side verification of the Ed25519-signed policy payload.

Behavioral twin of ``sdk-typescript/src/proxy/policy-verify.ts``: same checks, same
order, same verdicts, and reason strings carrying the same substrings the
shared fixture pins (``conformance/fixtures/policy_signature.json``).

When ``obsvr.init`` is given a pinned ``policy_public_key``, the SDK REQUIRES a
valid signature on every /policies response before applying it. A tamperer on
the delivery path cannot modify the rules (the signed hash breaks) or forge a
signature (no private key), and cannot roll the policy back to an older signed
version (issued_at monotonicity). On any verification failure the SDK fails
closed: it does NOT apply the fetched rules and keeps its last-good policy.

Crypto backend
--------------
Python has no Ed25519 in the standard library (TypeScript gets it free from
``node:crypto``), and this package ships zero mandatory runtime dependencies.
So the backend is resolved lazily and optionally: ``cryptography`` first, then
PyNaCl. Install one with ``pip install "obsvr-sdk[crypto]"``.

With a key pinned and NO backend importable, verification does not silently
pass. It returns a distinct UNAVAILABLE verdict: the fetched policy is still
refused (fail-closed, last-good stays in force) AND every subsequently emitted
event carries ``policy_verification_unavailable`` so the degraded posture is on
the audit record rather than inferred from its absence. A missing backend is a
different audit story from a failed signature, and the flag is what keeps them
distinguishable.
"""

import base64
import hashlib
from typing import Any, Callable, Dict, List, Optional

from .rules import _canonical_json

#: Reserved-metadata key carrying per-event integrity flags. New evidence
#: fields start in reserved ``obsvr_*`` metadata (the existing
#: ``obsvr_external_backend`` precedent) and are promoted to a top-level ingest
#: column once the wire schema accepts them; see the promotion plan below.
INTEGRITY_FLAGS_METADATA_KEY = "obsvr_integrity_flags"

#: Emitted when a policy public key is pinned but no Ed25519 backend could be
#: imported, so signature verification could not run.
POLICY_VERIFICATION_UNAVAILABLE = "policy_verification_unavailable"

# Promotion plan for obsvr_integrity_flags:
#   1. (now) SDK emits the array under metadata.obsvr_integrity_flags. The
#      metadata trimmer preserves reserved obsvr_* keys, so it survives.
#   2. Ingest adds an integrity_flags column and accepts the reserved key as
#      its source, backfilling from metadata.
#   3. The SDK emits the top-level field and keeps mirroring into metadata for
#      one minor release, then stops.
# Until step 2 lands, consumers read metadata.obsvr_integrity_flags.


class PolicyVerifyResult:
    """Verdict of one policy-signature verification.

    ``ok`` is the only accepting state. ``unavailable`` marks the specific
    not-ok cause "no crypto backend", which callers surface as an integrity
    flag rather than a signature failure.
    """

    __slots__ = ("ok", "reason", "unavailable")

    def __init__(self, ok: bool, reason: Optional[str] = None, unavailable: bool = False):
        self.ok = ok
        self.reason = reason
        self.unavailable = unavailable

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"PolicyVerifyResult(ok={self.ok!r}, reason={self.reason!r}, unavailable={self.unavailable!r})"


# --- process-wide degraded-posture latch -----------------------------------
# Set when a pinned key could not be checked for want of a backend; read by the
# sender when stamping reserved metadata. Module state (not config state)
# because the condition is a property of the interpreter, not of one config.
_verification_unavailable = False


def mark_verification_unavailable() -> None:
    """Latch the degraded posture so every subsequent event carries the flag."""
    global _verification_unavailable
    _verification_unavailable = True


def is_verification_unavailable() -> bool:
    return _verification_unavailable


def _reset_policy_verify() -> None:
    """Reset module state (tests only)."""
    global _verification_unavailable, _backend
    _verification_unavailable = False
    _backend = _UNRESOLVED


def integrity_flags() -> List[str]:
    """The integrity flags that apply to events emitted right now."""
    return [POLICY_VERIFICATION_UNAVAILABLE] if _verification_unavailable else []


# --- optional Ed25519 backend ----------------------------------------------

_UNRESOLVED = object()
#: None once resolution has been attempted and failed; a verify callable once
#: it has succeeded. Resolved at most once per process.
_backend: Any = _UNRESOLVED


def _resolve_backend() -> Optional[Callable[[bytes, bytes, bytes], bool]]:
    """Return ``verify(public_key_32, message, signature) -> bool`` or None.

    Tries ``cryptography`` then PyNaCl. Both are optional; neither is imported
    unless a policy key is actually pinned.
    """
    global _backend
    if _backend is not _UNRESOLVED:
        return _backend  # type: ignore[return-value]

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )

        def _verify_cryptography(pub: bytes, message: bytes, signature: bytes) -> bool:
            try:
                Ed25519PublicKey.from_public_bytes(pub).verify(signature, message)
                return True
            except InvalidSignature:
                return False

        _backend = _verify_cryptography
        return _backend
    except Exception:
        pass

    try:
        from nacl.exceptions import BadSignatureError
        from nacl.signing import VerifyKey

        def _verify_nacl(pub: bytes, message: bytes, signature: bytes) -> bool:
            try:
                VerifyKey(pub).verify(message, signature)
                return True
            except BadSignatureError:
                return False

        _backend = _verify_nacl
        return _backend
    except Exception:
        pass

    _backend = None
    return None


# --- canonical forms (byte-identical to the TS twin) -----------------------


def _payload_hash(value: Any) -> str:
    """sha256 hex over the canonical JSON of a received array. Uses the SAME
    canonicalizer the rules hash uses, so the hash recomputed here matches the
    one ingest signed byte-for-byte."""
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _canonical_policy_message(signature: Dict[str, Any]) -> bytes:
    return (
        "obsvr-policy-v1|"
        f"{signature.get('issued_at')}|"
        f"{signature.get('rules_sha256')}|"
        f"{signature.get('approvals_sha256')}"
    ).encode("utf-8")


def _key_id_of(raw_b64: str) -> str:
    return hashlib.sha256(base64.b64decode(raw_b64)).hexdigest()[:16]


def verify_policy_signature(
    rules: List[Any],
    approvals: List[Any],
    signature: Optional[Dict[str, Any]],
    pinned_public_key_b64: str,
    last_applied_issued_at: Optional[str] = None,
) -> PolicyVerifyResult:
    """Verify a signed policy payload against the pinned public key.

    :param rules: the raw rules array as received (pre-validation)
    :param approvals: the raw approvals array as received
    :param signature: the response's signature block, or None if unsigned
    :param pinned_public_key_b64: base64 raw 32-byte Ed25519 key from init()
    :param last_applied_issued_at: issued_at of the last applied signed policy
        (anti-rollback), or None
    """
    if not signature:
        return PolicyVerifyResult(
            False,
            "policy signature required (policy_public_key pinned) but response was unsigned",
        )
    alg = signature.get("alg")
    if alg != "ed25519":
        return PolicyVerifyResult(False, f"unsupported signature alg: {alg}")

    # The inline key must be the pinned key (defends against a swapped key_id).
    if signature.get("public_key") != pinned_public_key_b64:
        return PolicyVerifyResult(
            False, "signature public_key does not match the pinned policy_public_key"
        )
    if signature.get("key_id") != _key_id_of(pinned_public_key_b64):
        return PolicyVerifyResult(
            False, "signature key_id does not match its public key"
        )

    # The signed hashes must match the rules/approvals actually received.
    if _payload_hash(rules) != signature.get("rules_sha256"):
        return PolicyVerifyResult(
            False,
            "rules hash does not match the signed rules_sha256 (rules were altered in transit)",
        )
    if _payload_hash(approvals) != signature.get("approvals_sha256"):
        return PolicyVerifyResult(
            False, "approvals hash does not match the signed approvals_sha256"
        )

    # Anti-rollback: never accept a signed policy older than the last applied one.
    issued_at = str(signature.get("issued_at") or "")
    if last_applied_issued_at and issued_at < last_applied_issued_at:
        return PolicyVerifyResult(
            False,
            f"signed policy issued_at {issued_at} is older than the last applied "
            f"{last_applied_issued_at} (rollback)",
        )

    # Ed25519 verification over the canonical message.
    try:
        raw = base64.b64decode(pinned_public_key_b64)
    except Exception:
        raw = b""
    if len(raw) != 32:
        return PolicyVerifyResult(
            False, "pinned policy_public_key is not a 32-byte Ed25519 key"
        )

    verify = _resolve_backend()
    if verify is None:
        # NOT a pass. The policy is refused like any other failure; the flag
        # records WHY it could not be checked so the gap is auditable.
        mark_verification_unavailable()
        return PolicyVerifyResult(
            False,
            "policy signature could not be verified: no Ed25519 backend is installed "
            '(pip install "obsvr-sdk[crypto]"); the fetched policy was NOT applied',
            unavailable=True,
        )

    try:
        ok = verify(raw, _canonical_policy_message(signature), base64.b64decode(signature.get("value") or ""))
    except Exception as err:
        return PolicyVerifyResult(False, f"signature verification error: {err}")
    if not ok:
        return PolicyVerifyResult(False, "Ed25519 signature verification failed")
    return PolicyVerifyResult(True)
