"""Offline verification for strict receipts and receipt chains."""

from __future__ import annotations

import base64
import binascii
import hashlib
from typing import Any, Dict, List, Literal, Optional

from .strict_receipt import (
    STRICT_RECEIPT_BODY_DOMAIN,
    STRICT_RECEIPT_ENVELOPE_SCHEMA,
    StrictReceiptValidationError,
    _canonical_json_for_hash,
    _u64,
    build_strict_receipt_body,
    strict_receipt_key_id,
    strict_receipt_signature_preimage,
)

_HEX = frozenset("0123456789abcdef")
StrictKeyTrust = Literal[
    "pinned", "registered", "revoked", "self_asserted", "unknown"
]


def _record(value: Any) -> Optional[Dict[str, Any]]:
    return value if isinstance(value, dict) else None


def _exact(value: Dict[str, Any], allowed: set[str]) -> bool:
    return set(value).issubset(allowed)


def _lower_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(char in _HEX for char in value)
    )


def _key_id(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("sha256:") and _lower_hex(
        value[7:], 64
    )


def _decode_public_key(value: Any) -> Optional[bytes]:
    if not isinstance(value, str):
        return None
    try:
        raw = base64.b64decode(value, validate=True)
        return raw if len(raw) == 32 and base64.b64encode(raw).decode() == value else None
    except (binascii.Error, ValueError):
        return None


def verify_strict_receipt(
    value: Any, *, pinned_public_key_b64: Optional[str] = None
) -> Dict[str, Any]:
    envelope = _record(value)
    body = _record(envelope.get("body")) if envelope else None
    signature = _record(envelope.get("signature")) if envelope else None
    schema_valid = bool(
        envelope is not None
        and _exact(
            envelope,
            {"schema", "body", "receipt_hash", "signature", "public_key_b64"},
        )
        and envelope.get("schema") == STRICT_RECEIPT_ENVELOPE_SCHEMA
        and body is not None
        and _lower_hex(envelope.get("receipt_hash"), 64)
        and signature is not None
        and _exact(signature, {"algorithm", "key_id", "value"})
        and signature.get("algorithm") == "Ed25519"
        and _key_id(signature.get("key_id"))
        and _lower_hex(signature.get("value"), 128)
        and (
            "public_key_b64" not in envelope
            or isinstance(envelope["public_key_b64"], str)
        )
    )

    semantic_valid = False
    if body is not None:
        try:
            build_strict_receipt_body(body)
            semantic_valid = True
        except StrictReceiptValidationError:
            pass

    hash_valid = False
    if body is not None and envelope is not None and isinstance(
        envelope.get("receipt_hash"), str
    ):
        try:
            canonical = _canonical_json_for_hash(body).encode("utf-8")
            actual = hashlib.sha256(
                STRICT_RECEIPT_BODY_DOMAIN
                + b"\x00"
                + _u64(len(canonical))
                + canonical
            ).hexdigest()
            hash_valid = actual == envelope["receipt_hash"]
        except Exception:
            pass

    pin_supplied = pinned_public_key_b64 is not None
    pinned = _decode_public_key(pinned_public_key_b64)
    embedded = _decode_public_key(envelope.get("public_key_b64") if envelope else None)
    raw_key = pinned if pin_supplied else embedded
    key_trust: StrictKeyTrust = (
        "pinned" if pin_supplied else "self_asserted" if embedded else "unknown"
    )
    initiator = _record(body.get("initiator")) if body else None
    body_key_id = initiator.get("key_id") if initiator else None
    signature_key_id = signature.get("key_id") if signature else None
    fingerprint = strict_receipt_key_id(raw_key) if raw_key is not None else None
    identity_valid = bool(
        isinstance(body_key_id, str)
        and isinstance(signature_key_id, str)
        and fingerprint is not None
        and body_key_id == signature_key_id == fingerprint
    )

    signature_valid = False
    if (
        raw_key is not None
        and isinstance(signature_key_id, str)
        and envelope is not None
        and isinstance(envelope.get("receipt_hash"), str)
        and signature is not None
        and isinstance(signature.get("value"), str)
    ):
        try:
            from .policy_verify import _resolve_backend

            backend = _resolve_backend()
            if backend is not None:
                signature_valid = bool(
                    backend(
                        raw_key,
                        strict_receipt_signature_preimage(
                            signature_key_id, envelope["receipt_hash"]
                        ),
                        bytes.fromhex(signature["value"]),
                    )
                )
        except Exception:
            pass

    return {
        "schema_valid": schema_valid,
        "hash_valid": hash_valid,
        "signature_valid": signature_valid,
        "semantic_valid": semantic_valid,
        "identity_binding_valid": identity_valid,
        "key_trust": key_trust,
    }


def _same_action(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    return all(
        left.get(field) == right.get(field)
        for field in ("action_id", "kind", "name", "arguments_hash", "target")
    )


def _compatible_resolution(suspension: Dict[str, Any], method: str) -> bool:
    if suspension.get("type") == "approval":
        return method in (
            "approval_granted",
            "approval_denied",
            "expired",
            "cancelled",
        )
    return method in ("context_supplied", "expired", "cancelled")


def verify_strict_receipt_chain(
    envelopes: List[Any], *, pinned_public_key_b64: Optional[str] = None
) -> Dict[str, Any]:
    if not envelopes:
        return {"valid": False, "errors": ["empty_chain"]}
    errors: List[str] = []
    by_hash: Dict[str, Dict[str, Any]] = {}
    resolved: set[str] = set()
    session = None
    previous = None
    for index, candidate in enumerate(envelopes):
        current = _record(candidate)
        body = _record(current.get("body")) if current else None
        receipt_id = body.get("receipt_id", f"index-{index}") if body else f"index-{index}"
        axes = verify_strict_receipt(
            candidate, pinned_public_key_b64=pinned_public_key_b64
        )
        for axis, label in (
            ("schema_valid", "receipt_schema_invalid"),
            ("semantic_valid", "receipt_semantic_invalid"),
            ("hash_valid", "receipt_hash_invalid"),
            ("signature_valid", "receipt_signature_invalid"),
            ("identity_binding_valid", "receipt_identity_invalid"),
        ):
            if not axes[axis]:
                errors.append(f"{label}:{receipt_id}")
        if current is None or body is None or not all(
            axes[key]
            for key in (
                "schema_valid",
                "semantic_valid",
                "hash_valid",
                "signature_valid",
                "identity_binding_valid",
            )
        ):
            continue
        body = build_strict_receipt_body(body)
        if session is None:
            session = body["session_id"]

        if body["sequence"] != index + 1:
            errors.append(f"sequence_order_invalid:{receipt_id}")
        if body["session_id"] != session:
            errors.append(f"session_mismatch:{receipt_id}")
        if previous is not None:
            previous_body = previous["body"]
            if body["previous_receipt_hash"] != previous["receipt_hash"]:
                errors.append(f"previous_hash_mismatch:{receipt_id}")
            if body["timestamp_ms"] < previous_body["timestamp_ms"]:
                errors.append(f"timestamp_regression:{receipt_id}")

        resolution = body.get("resolution")
        if body["record_type"] == "resolution" and resolution:
            if resolution["resolves_receipt_hash"] in resolved:
                errors.append(f"duplicate_resolution:{receipt_id}")
            else:
                resolved.add(resolution["resolves_receipt_hash"])
            prior = by_hash.get(resolution["resolves_receipt_hash"])
            if prior is None:
                errors.append(f"resolution_reference_invalid:{receipt_id}")
            else:
                prior_body = prior["body"]
                suspension = prior_body.get("suspension")
                if prior_body["record_type"] != "decision" or suspension is None:
                    errors.append(f"resolution_prior_not_suspended:{receipt_id}")
                else:
                    if suspension["suspension_id"] != resolution["suspension_id"]:
                        errors.append(f"resolution_suspension_mismatch:{receipt_id}")
                    if not _compatible_resolution(suspension, resolution["method"]):
                        errors.append(f"resolution_method_mismatch:{receipt_id}")
                    if resolution["resolved_at_ms"] < prior_body["timestamp_ms"]:
                        errors.append(f"resolution_time_invalid:{receipt_id}")
                    if (
                        resolution["method"]
                        in ("approval_granted", "context_supplied")
                        and resolution["resolved_at_ms"]
                        > suspension["expires_at_ms"]
                    ):
                        errors.append(f"resolution_after_expiry:{receipt_id}")
                if not _same_action(prior_body["action"], body["action"]):
                    errors.append(f"resolution_action_mismatch:{receipt_id}")
                if prior_body["initiator"] != body["initiator"]:
                    errors.append(f"resolution_initiator_mismatch:{receipt_id}")
        by_hash[current["receipt_hash"]] = current
        previous = current
    return {"valid": not errors, "errors": errors}
