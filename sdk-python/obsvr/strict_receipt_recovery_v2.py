"""Authenticated durable checkpoints for strict v2 coordinator recovery."""

from __future__ import annotations

import copy
import hashlib
from typing import Any, Dict

from .strict_receipt_v2 import strict_receipt_v2_key_id
from .tool_pinning import _canonical_json_for_hash

STRICT_RECOVERY_V2_SCHEMA = "obsvr-strict-receipt-recovery-v2"
STRICT_RECOVERY_V2_ENVELOPE_SCHEMA = "obsvr-strict-receipt-recovery-envelope-v2"
_DOMAIN = b"obsvr-strict-receipt-recovery/2\x00"
_HEX = frozenset("0123456789abcdef")
_MAX_SAFE = 9_007_199_254_740_991


class StrictRecoveryV2Error(ValueError):
    """A recovery checkpoint is malformed, untrusted, or inconsistent."""


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise StrictRecoveryV2Error(f"{field} must be nonblank")
    return value


def _integer(value: Any, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > _MAX_SAFE
    ):
        raise StrictRecoveryV2Error(f"{field} must be a nonnegative safe integer")
    return value


def _hash(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in _HEX for char in value)
    ):
        raise StrictRecoveryV2Error(f"{field} must be 64 lowercase hex characters")
    return value


def _checkpoint_hash(document: Dict[str, Any]) -> str:
    return hashlib.sha256(
        _canonical_json_for_hash(document).encode("utf-8")
    ).hexdigest()


def _preimage(checkpoint_hash: str) -> bytes:
    return _DOMAIN + bytes.fromhex(checkpoint_hash)


def _verify(raw_public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        Ed25519PublicKey.from_public_bytes(raw_public_key).verify(signature, message)
        return True
    except Exception:
        try:
            from nacl.signing import VerifyKey

            VerifyKey(raw_public_key).verify(message, signature)
            return True
        except Exception:
            return False


def validate_strict_recovery_v2_document(document: Dict[str, Any]) -> None:
    if (
        not isinstance(document, dict)
        or document.get("schema") != STRICT_RECOVERY_V2_SCHEMA
        or document.get("profile_version") != "2.0"
        or document.get("sdk_language") != "python"
        or not isinstance(document.get("committed"), dict)
    ):
        raise StrictRecoveryV2Error("invalid checkpoint document")
    _text(document.get("tenant_id"), "tenant_id")
    _text(document.get("session_id"), "session_id")
    _text(document.get("sdk_version"), "sdk_version")
    _integer(document.get("origin_pid"), "origin_pid")
    committed = document["committed"]
    sequence = _integer(committed.get("sequence"), "committed.sequence")
    head = committed.get("head_receipt_hash")
    if (head is None) != (sequence == 0):
        raise StrictRecoveryV2Error("checkpoint head/sequence mismatch")
    if head is not None:
        _hash(head, "head_receipt_hash")
    timestamp = committed.get("last_timestamp_ms")
    if timestamp is not None:
        _integer(timestamp, "last_timestamp_ms")
    for field in (
        "prior_actions",
        "suspended",
        "resolved_receipt_hashes",
        "action_ids",
        "approval_requests",
    ):
        if not isinstance(committed.get(field), list):
            raise StrictRecoveryV2Error("checkpoint collections must be arrays")
    prior = committed["prior_actions"]
    if sequence and (
        not prior
        or prior[-1].get("sequence") != sequence
        or prior[-1].get("receipt_hash") != head
    ):
        raise StrictRecoveryV2Error("checkpoint head does not match prior actions")
    prepared = document.get("prepared")
    if prepared is not None:
        if not isinstance(prepared, dict) or prepared.get("kind") not in (
            "decision",
            "resolution",
            "timeout",
        ):
            raise StrictRecoveryV2Error("invalid prepared checkpoint")
        receipt = prepared.get("receipt", {})
        body = receipt.get("body", {}) if isinstance(receipt, dict) else {}
        if (
            body.get("tenant_id") != document["tenant_id"]
            or body.get("session_id") != document["session_id"]
            or body.get("profile_version") != "2.0"
            or body.get("sequence") != sequence + 1
            or body.get("previous_receipt_hash") != head
        ):
            raise StrictRecoveryV2Error(
                "prepared receipt does not continue checkpoint head"
            )


def sign_strict_recovery_v2(document: Dict[str, Any], signer: Any) -> Dict[str, Any]:
    validate_strict_recovery_v2_document(document)
    checkpoint_hash = _checkpoint_hash(document)
    key_id = strict_receipt_v2_key_id(signer.raw_public_key)
    value = signer.sign_bytes(_preimage(checkpoint_hash))
    if len(value) != 128 or any(char not in _HEX for char in value):
        raise StrictRecoveryV2Error("checkpoint signer returned an invalid signature")
    if not _verify(
        signer.raw_public_key, _preimage(checkpoint_hash), bytes.fromhex(value)
    ):
        raise StrictRecoveryV2Error("checkpoint signature failed self-verification")
    return {
        "schema": STRICT_RECOVERY_V2_ENVELOPE_SCHEMA,
        "document": copy.deepcopy(document),
        "checkpoint_hash": checkpoint_hash,
        "signature": {"algorithm": "Ed25519", "key_id": key_id, "value": value},
    }


def verify_strict_recovery_v2(value: Any, signer: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise StrictRecoveryV2Error("checkpoint must be an object")
    signature = value.get("signature")
    if (
        value.get("schema") != STRICT_RECOVERY_V2_ENVELOPE_SCHEMA
        or not isinstance(signature, dict)
        or signature.get("algorithm") != "Ed25519"
        or signature.get("key_id") != strict_receipt_v2_key_id(signer.raw_public_key)
    ):
        raise StrictRecoveryV2Error("invalid checkpoint envelope")
    checkpoint_hash = _hash(value.get("checkpoint_hash"), "checkpoint_hash")
    signature_hex = signature.get("value")
    if (
        not isinstance(signature_hex, str)
        or len(signature_hex) != 128
        or any(char not in _HEX for char in signature_hex)
    ):
        raise StrictRecoveryV2Error("invalid checkpoint envelope")
    document = value.get("document")
    validate_strict_recovery_v2_document(document)
    if _checkpoint_hash(document) != checkpoint_hash:
        raise StrictRecoveryV2Error("checkpoint hash mismatch")
    if not _verify(
        signer.raw_public_key,
        _preimage(checkpoint_hash),
        bytes.fromhex(signature_hex),
    ):
        raise StrictRecoveryV2Error("checkpoint signature invalid")
    return copy.deepcopy(document)
