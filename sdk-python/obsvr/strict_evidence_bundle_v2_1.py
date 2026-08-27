"""Portable, signed evidence bundles for strict receipt profile 2.1."""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
from typing import Any, Dict, List, Optional, Sequence

from .policy_verify import _resolve_backend
from .strict_execution_outcome_v2_1 import (
    verify_strict_execution_outcome_v2_1,
)
from .strict_policy_continuity_v2_1 import (
    reconstruct_strict_policy_continuity_v2_1,
)
from .strict_receipt_v2_1 import strict_receipt_v2_1_key_id
from .strict_receipt_v2_1_verify import verify_strict_receipt_v2_1_chain
from .tool_pinning import _canonical_json_for_hash

STRICT_EVIDENCE_BUNDLE_V2_1_SCHEMA = "obsvr-strict-evidence-bundle-v2-1"
STRICT_EVIDENCE_BUNDLE_V2_1_ENVELOPE_SCHEMA = (
    "obsvr-strict-evidence-bundle-envelope-v2-1"
)
STRICT_EVIDENCE_BUNDLE_V2_1_BODY_DOMAIN = b"obsvr-strict-evidence-bundle/body/2.1"
STRICT_EVIDENCE_BUNDLE_V2_1_SIGNATURE_DOMAIN = (
    b"obsvr-strict-evidence-bundle/signature/2.1"
)

_HEX = frozenset("0123456789abcdef")
_MAX_ITEMS = 4096


class StrictEvidenceBundleV21Error(ValueError):
    """Strict evidence cannot be represented by a trusted portable bundle."""


def _fail(message: str) -> None:
    raise StrictEvidenceBundleV21Error(message)


def _lower_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in _HEX for character in value)
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
        return (
            raw
            if len(raw) == 32 and base64.b64encode(raw).decode("ascii") == value
            else None
        )
    except (binascii.Error, ValueError):
        return None


def _trust_arguments(
    trusted_agent_keys: Sequence[Dict[str, Any]],
    allowed_evaluator_manifest_hashes: Sequence[str],
) -> Dict[str, Sequence[Any]]:
    return {
        "trusted_agent_keys": trusted_agent_keys,
        "allowed_evaluator_manifest_hashes": allowed_evaluator_manifest_hashes,
    }


def _domain_hash(domain: bytes, value: Any) -> str:
    canonical = _canonical_json_for_hash(value).encode("utf-8")
    return hashlib.sha256(
        domain + b"\x00" + len(canonical).to_bytes(8, "big") + canonical
    ).hexdigest()


def strict_evidence_bundle_v2_1_hash(body: Dict[str, Any]) -> str:
    """Hash a normalized strict evidence bundle body."""
    return _domain_hash(STRICT_EVIDENCE_BUNDLE_V2_1_BODY_DOMAIN, body)


def strict_evidence_bundle_v2_1_signature_preimage(
    key_id: str, bundle_hash: str
) -> bytes:
    """Return the domain-separated bytes signed by a bundle envelope."""
    if not _key_id(key_id) or not _lower_hex(bundle_hash, 64):
        _fail("invalid evidence bundle signature binding")
    key = key_id.encode("utf-8")
    return (
        STRICT_EVIDENCE_BUNDLE_V2_1_SIGNATURE_DOMAIN
        + b"\x00"
        + len(key).to_bytes(8, "big")
        + key
        + bytes.fromhex(bundle_hash)
    )


def build_strict_evidence_bundle_v2_1_body(
    receipts: Sequence[Dict[str, Any]],
    execution_outcomes: Sequence[Dict[str, Any]],
    *,
    trusted_agent_keys: Sequence[Dict[str, Any]],
    allowed_evaluator_manifest_hashes: Sequence[str],
) -> Dict[str, Any]:
    """Normalize trusted receipts and outcomes into a portable bundle body."""
    if (
        not isinstance(receipts, (list, tuple))
        or not receipts
        or len(receipts) > _MAX_ITEMS
    ):
        _fail("receipt chain size is unsupported")
    if not isinstance(execution_outcomes, (list, tuple)) or len(
        execution_outcomes
    ) > _MAX_ITEMS:
        _fail("outcome set size is unsupported")
    trust = _trust_arguments(
        trusted_agent_keys, allowed_evaluator_manifest_hashes
    )
    normalized_receipts = copy.deepcopy(list(receipts))
    chain = verify_strict_receipt_v2_1_chain(normalized_receipts, **trust)
    if not chain["valid"]:
        _fail("receipt chain is not trusted: " + ", ".join(chain["errors"]))
    by_hash = {
        receipt["receipt_hash"]: receipt for receipt in normalized_receipts
    }
    outcomes = copy.deepcopy(list(execution_outcomes))
    try:
        outcomes.sort(key=lambda item: item["body"]["decision_sequence"])
    except (KeyError, TypeError):
        _fail("execution outcome is malformed")
    outcome_by_receipt: Dict[str, Dict[str, Any]] = {}
    for outcome in outcomes:
        try:
            receipt_hash = outcome["body"]["decision_receipt_hash"]
        except (KeyError, TypeError):
            _fail("execution outcome is malformed")
        receipt = by_hash.get(receipt_hash)
        if receipt is None:
            _fail("execution outcome references a receipt outside the bundle")
        if receipt_hash in outcome_by_receipt:
            _fail("receipt has duplicate execution outcomes")
        if not verify_strict_execution_outcome_v2_1(
            outcome, receipt, **trust
        )["trusted"]:
            _fail("execution outcome is not trusted")
        outcome_by_receipt[receipt_hash] = outcome
    coverage: List[Dict[str, Any]] = []
    for receipt in normalized_receipts:
        outcome = outcome_by_receipt.get(receipt["receipt_hash"])
        authorized = receipt["body"]["execution_authorized"]
        item = {
            "sequence": receipt["body"]["sequence"],
            "receipt_hash": receipt["receipt_hash"],
            "record_type": receipt["body"]["record_type"],
            "execution_authorized": authorized,
            "execution_status": (
                outcome["body"]["status"]
                if authorized and outcome
                else "missing" if authorized else "not_authorized"
            ),
        }
        if outcome:
            item["outcome_hash"] = outcome["outcome_hash"]
        coverage.append(item)
    return {
        "schema": STRICT_EVIDENCE_BUNDLE_V2_1_SCHEMA,
        "profile_version": "2.1",
        "tenant_id": normalized_receipts[0]["body"]["tenant_id"],
        "session_id": normalized_receipts[0]["body"]["session_id"],
        "first_sequence": normalized_receipts[0]["body"]["sequence"],
        "last_sequence": normalized_receipts[-1]["body"]["sequence"],
        "head_receipt_hash": normalized_receipts[-1]["receipt_hash"],
        "complete": all(item["execution_status"] != "missing" for item in coverage),
        "receipts": normalized_receipts,
        "execution_outcomes": outcomes,
        "coverage": coverage,
        "policy_continuity": reconstruct_strict_policy_continuity_v2_1(
            normalized_receipts, **trust
        ),
    }


def create_strict_evidence_bundle_v2_1(
    receipts: Sequence[Dict[str, Any]],
    execution_outcomes: Sequence[Dict[str, Any]],
    signer: Any,
    *,
    trusted_agent_keys: Sequence[Dict[str, Any]],
    allowed_evaluator_manifest_hashes: Sequence[str],
) -> Dict[str, Any]:
    """Build and sign a strict evidence bundle with the head receipt key."""
    body = build_strict_evidence_bundle_v2_1_body(
        receipts,
        execution_outcomes,
        trusted_agent_keys=trusted_agent_keys,
        allowed_evaluator_manifest_hashes=allowed_evaluator_manifest_hashes,
    )
    head = body["receipts"][-1]
    key_id = strict_receipt_v2_1_key_id(signer.raw_public_key)
    public_key_b64 = base64.b64encode(signer.raw_public_key).decode("ascii")
    if (
        key_id != head["signature"]["key_id"]
        or public_key_b64 != head["public_key_b64"]
        or signer.public_key_b64 != public_key_b64
    ):
        _fail("evidence bundle signer must match the head receipt signer")
    bundle_hash = strict_evidence_bundle_v2_1_hash(body)
    preimage = strict_evidence_bundle_v2_1_signature_preimage(key_id, bundle_hash)
    signature = signer.sign_bytes(preimage)
    if not _lower_hex(signature, 128):
        _fail("signer returned an invalid Ed25519 signature")
    backend = _resolve_backend()
    if backend is None or not backend(
        signer.raw_public_key, preimage, bytes.fromhex(signature)
    ):
        _fail("signer signature failed self-verification")
    return {
        "schema": STRICT_EVIDENCE_BUNDLE_V2_1_ENVELOPE_SCHEMA,
        "body": body,
        "bundle_hash": bundle_hash,
        "signature": {
            "algorithm": "Ed25519",
            "key_id": key_id,
            "value": signature,
        },
        "public_key_b64": public_key_b64,
    }


def verify_strict_evidence_bundle_v2_1(
    value: Any,
    *,
    trusted_agent_keys: Sequence[Dict[str, Any]],
    allowed_evaluator_manifest_hashes: Sequence[str],
) -> Dict[str, Any]:
    """Verify bundle components, semantics, head signer, and bundle signature."""
    errors: List[str] = []
    envelope = value if isinstance(value, dict) else None
    body = envelope.get("body") if envelope and isinstance(envelope.get("body"), dict) else None
    signature = envelope.get("signature") if envelope and isinstance(envelope.get("signature"), dict) else None
    schema_valid = bool(
        envelope
        and set(envelope) == {"schema", "body", "bundle_hash", "signature", "public_key_b64"}
        and envelope.get("schema") == STRICT_EVIDENCE_BUNDLE_V2_1_ENVELOPE_SCHEMA
        and body
        and _lower_hex(envelope.get("bundle_hash"), 64)
        and signature
        and set(signature) == {"algorithm", "key_id", "value"}
        and signature.get("algorithm") == "Ed25519"
        and _key_id(signature.get("key_id"))
        and _lower_hex(signature.get("value"), 128)
        and _decode_public_key(envelope.get("public_key_b64")) is not None
    )
    if not schema_valid:
        errors.append("bundle_schema_invalid")
    rebuilt = None
    try:
        rebuilt = build_strict_evidence_bundle_v2_1_body(
            body.get("receipts") if body else None,
            body.get("execution_outcomes") if body else None,
            trusted_agent_keys=trusted_agent_keys,
            allowed_evaluator_manifest_hashes=allowed_evaluator_manifest_hashes,
        )
    except (StrictEvidenceBundleV21Error, TypeError):
        errors.append("bundle_components_untrusted")
    semantic_valid = bool(
        rebuilt
        and _canonical_json_for_hash(rebuilt) == _canonical_json_for_hash(body)
    )
    if not semantic_valid:
        errors.append("bundle_semantic_invalid")
    hash_valid = bool(
        rebuilt
        and envelope
        and strict_evidence_bundle_v2_1_hash(rebuilt) == envelope.get("bundle_hash")
    )
    if not hash_valid:
        errors.append("bundle_hash_invalid")
    raw_key = _decode_public_key(envelope.get("public_key_b64")) if envelope else None
    signature_valid = False
    try:
        backend = _resolve_backend()
        signature_valid = bool(
            backend
            and raw_key
            and signature
            and envelope
            and backend(
                raw_key,
                strict_evidence_bundle_v2_1_signature_preimage(
                    signature["key_id"], envelope["bundle_hash"]
                ),
                bytes.fromhex(signature["value"]),
            )
        )
    except Exception:
        signature_valid = False
    if not signature_valid:
        errors.append("bundle_signature_invalid")
    head = rebuilt["receipts"][-1] if rebuilt else None
    signer_binding_valid = bool(
        raw_key
        and head
        and signature
        and strict_receipt_v2_1_key_id(raw_key) == signature.get("key_id")
        and signature.get("key_id") == head["signature"]["key_id"]
        and envelope.get("public_key_b64") == head["public_key_b64"]
    )
    if not signer_binding_valid:
        errors.append("bundle_signer_mismatch")
    trusted = bool(
        schema_valid
        and semantic_valid
        and hash_valid
        and signature_valid
        and signer_binding_valid
    )
    return {
        "schema_valid": schema_valid,
        "semantic_valid": semantic_valid,
        "hash_valid": hash_valid,
        "signature_valid": signature_valid,
        "signer_binding_valid": signer_binding_valid,
        "trusted": trusted,
        "complete": bool(trusted and rebuilt["complete"]),
        "errors": errors,
    }


__all__ = [
    "STRICT_EVIDENCE_BUNDLE_V2_1_SCHEMA",
    "STRICT_EVIDENCE_BUNDLE_V2_1_ENVELOPE_SCHEMA",
    "StrictEvidenceBundleV21Error",
    "build_strict_evidence_bundle_v2_1_body",
    "create_strict_evidence_bundle_v2_1",
    "strict_evidence_bundle_v2_1_hash",
    "strict_evidence_bundle_v2_1_signature_preimage",
    "verify_strict_evidence_bundle_v2_1",
]
