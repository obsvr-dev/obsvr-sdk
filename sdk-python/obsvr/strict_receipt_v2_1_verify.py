"""Offline integrity and trust verification for strict receipt profile 2.1."""

from __future__ import annotations

import base64
import binascii
import hashlib
from typing import Any, Dict, List, Optional, Sequence

from .strict_receipt_v2_1 import (
    STRICT_RECEIPT_V2_1_BODY_DOMAIN,
    STRICT_RECEIPT_V2_1_ENVELOPE_SCHEMA,
    StrictReceiptV21ValidationError,
    build_strict_receipt_v2_1_body,
    strict_receipt_v2_1_key_id,
    strict_receipt_v2_1_signature_preimage,
)
from .tool_pinning import _canonical_json_for_hash

_HEX = frozenset("0123456789abcdef")


def _record(value: Any) -> Optional[Dict[str, Any]]:
    return value if isinstance(value, dict) else None


def _exact(value: Dict[str, Any], keys: set[str]) -> bool:
    return set(value) == keys


def _lower_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(char in _HEX for char in value)
    )


def _key_id(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("sha256:")
        and _lower_hex(value[7:], 64)
    )


def _decode_key(value: Any) -> Optional[bytes]:
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


def _key_trust(
    body: Optional[Dict[str, Any]],
    raw_key: Optional[bytes],
    trusted_agent_keys: Sequence[Dict[str, Any]],
) -> str:
    identity = _record(body.get("identity")) if body else None
    initiator = _record(identity.get("initiator")) if identity else None
    tenant = body.get("tenant_id") if body else None
    agent = initiator.get("agent_ref_hash") if initiator else None
    key_id = initiator.get("key_id") if initiator else None
    if (
        not all(isinstance(value, str) for value in (tenant, agent, key_id))
        or raw_key is None
    ):
        return "malformed"
    matches = [
        entry
        for entry in trusted_agent_keys
        if isinstance(entry, dict)
        and entry.get("tenant_id") == tenant
        and entry.get("agent_ref_hash") == agent
        and entry.get("key_id") == key_id
    ]
    if not matches:
        return "unknown"
    if len(matches) != 1:
        return "malformed"
    entry = matches[0]
    if set(entry) != {
        "tenant_id",
        "agent_ref_hash",
        "key_id",
        "public_key_b64",
        "status",
    }:
        return "malformed"
    trusted_key = _decode_key(entry.get("public_key_b64"))
    try:
        if (
            trusted_key is None
            or strict_receipt_v2_1_key_id(trusted_key) != entry["key_id"]
        ):
            return "malformed"
    except StrictReceiptV21ValidationError:
        return "malformed"
    if trusted_key != raw_key:
        return "mismatch"
    if entry.get("status") not in ("active", "revoked"):
        return "malformed"
    return "trusted" if entry["status"] == "active" else "revoked"


def _evaluator_trust(
    body: Optional[Dict[str, Any]], allowed_evaluator_manifest_hashes: Sequence[str]
) -> str:
    evaluation = _record(body.get("evaluation")) if body else None
    manifest = evaluation.get("evaluator_manifest_hash") if evaluation else None
    if not _lower_hex(manifest, 64):
        return "malformed"
    if not all(_lower_hex(value, 64) for value in allowed_evaluator_manifest_hashes):
        return "malformed"
    return "allowlisted" if manifest in allowed_evaluator_manifest_hashes else "unknown"


def verify_strict_receipt_v2_1(
    value: Any,
    *,
    trusted_agent_keys: Sequence[Dict[str, Any]],
    allowed_evaluator_manifest_hashes: Sequence[str],
) -> Dict[str, Any]:
    envelope = _record(value)
    body = _record(envelope.get("body")) if envelope else None
    signature = _record(envelope.get("signature")) if envelope else None
    schema_valid = bool(
        envelope
        and _exact(
            envelope, {"schema", "body", "receipt_hash", "signature", "public_key_b64"}
        )
        and envelope.get("schema") == STRICT_RECEIPT_V2_1_ENVELOPE_SCHEMA
        and body
        and _lower_hex(envelope.get("receipt_hash"), 64)
        and signature
        and _exact(signature, {"algorithm", "key_id", "value"})
        and signature.get("algorithm") == "Ed25519"
        and _key_id(signature.get("key_id"))
        and _lower_hex(signature.get("value"), 128)
        and isinstance(envelope.get("public_key_b64"), str)
    )
    semantic_valid = False
    if body:
        try:
            semantic_valid = _canonical_json_for_hash(
                build_strict_receipt_v2_1_body(body)
            ) == _canonical_json_for_hash(body)
        except StrictReceiptV21ValidationError:
            pass
    hash_valid = False
    if body and envelope and isinstance(envelope.get("receipt_hash"), str):
        try:
            canonical = _canonical_json_for_hash(body).encode("utf-8")
            actual = hashlib.sha256(
                STRICT_RECEIPT_V2_1_BODY_DOMAIN
                + b"\x00"
                + len(canonical).to_bytes(8, "big")
                + canonical
            ).hexdigest()
            hash_valid = actual == envelope["receipt_hash"]
        except Exception:
            pass
    raw_key = _decode_key(envelope.get("public_key_b64")) if envelope else None
    identity = _record(body.get("identity")) if body else None
    initiator = _record(identity.get("initiator")) if identity else None
    body_key_id = initiator.get("key_id") if initiator else None
    signature_key_id = signature.get("key_id") if signature else None
    try:
        fingerprint = strict_receipt_v2_1_key_id(raw_key) if raw_key else None
    except StrictReceiptV21ValidationError:
        fingerprint = None
    identity_binding_valid = bool(
        body_key_id == signature_key_id == fingerprint and fingerprint
    )
    signature_valid = False
    if (
        raw_key
        and isinstance(signature_key_id, str)
        and envelope
        and isinstance(envelope.get("receipt_hash"), str)
        and signature
        and isinstance(signature.get("value"), str)
    ):
        try:
            from .policy_verify import _resolve_backend

            backend = _resolve_backend()
            signature_valid = bool(
                backend
                and backend(
                    raw_key,
                    strict_receipt_v2_1_signature_preimage(
                        signature_key_id, envelope["receipt_hash"]
                    ),
                    bytes.fromhex(signature["value"]),
                )
            )
        except Exception:
            pass
    key_trust = _key_trust(body, raw_key, trusted_agent_keys)
    evaluator_trust = _evaluator_trust(body, allowed_evaluator_manifest_hashes)
    integrity_valid = all(
        (
            schema_valid,
            semantic_valid,
            hash_valid,
            signature_valid,
            identity_binding_valid,
        )
    )
    return {
        "schema_valid": schema_valid,
        "semantic_valid": semantic_valid,
        "hash_valid": hash_valid,
        "signature_valid": signature_valid,
        "identity_binding_valid": identity_binding_valid,
        "integrity_valid": integrity_valid,
        "key_trust": key_trust,
        "evaluator_trust": evaluator_trust,
        "trusted": integrity_valid
        and key_trust == "trusted"
        and evaluator_trust == "allowlisted",
    }


def _resolution_method_matches(suspension_type: str, method: str) -> bool:
    return method in (
        ("approval_granted", "approval_denied", "expired", "cancelled")
        if suspension_type == "approval"
        else ("context_supplied", "expired", "cancelled")
    )


def verify_strict_receipt_v2_1_chain(
    values: List[Any],
    *,
    trusted_agent_keys: Sequence[Dict[str, Any]],
    allowed_evaluator_manifest_hashes: Sequence[str],
) -> Dict[str, Any]:
    if not values:
        return {"valid": False, "errors": ["empty_chain"]}
    errors: List[str] = []
    by_hash: Dict[str, Dict[str, Any]] = {}
    resolved: set[str] = set()
    tenant = session = None
    previous = None
    for index, candidate in enumerate(values):
        envelope = _record(candidate)
        raw_body = _record(envelope.get("body")) if envelope else None
        receipt_id = (
            raw_body.get("receipt_id", f"index-{index}")
            if raw_body
            else f"index-{index}"
        )
        result = verify_strict_receipt_v2_1(
            candidate,
            trusted_agent_keys=trusted_agent_keys,
            allowed_evaluator_manifest_hashes=allowed_evaluator_manifest_hashes,
        )
        for field, code in (
            ("schema_valid", "receipt_schema_invalid"),
            ("semantic_valid", "receipt_semantic_invalid"),
            ("hash_valid", "receipt_hash_invalid"),
            ("signature_valid", "receipt_signature_invalid"),
            ("identity_binding_valid", "receipt_identity_invalid"),
        ):
            if not result[field]:
                errors.append(f"{code}:{receipt_id}")
        if result["key_trust"] != "trusted":
            errors.append(f"receipt_key_untrusted:{receipt_id}")
        if result["evaluator_trust"] != "allowlisted":
            errors.append(f"receipt_evaluator_untrusted:{receipt_id}")
        if not result["integrity_valid"] or not envelope or not raw_body:
            continue
        body = build_strict_receipt_v2_1_body(raw_body)
        tenant = body["tenant_id"] if tenant is None else tenant
        session = body["session_id"] if session is None else session
        if body["tenant_id"] != tenant:
            errors.append(f"tenant_mismatch:{receipt_id}")
        if body["session_id"] != session:
            errors.append(f"session_mismatch:{receipt_id}")
        if body["sequence"] != index + 1:
            errors.append(f"sequence_order_invalid:{receipt_id}")
        if (previous["receipt_hash"] if previous else None) != body[
            "previous_receipt_hash"
        ]:
            errors.append(f"previous_hash_mismatch:{receipt_id}")
        if previous and body["timestamp_ms"] < previous["body"]["timestamp_ms"]:
            errors.append(f"timestamp_regression:{receipt_id}")
        receipt_hash = envelope["receipt_hash"]
        if receipt_hash in by_hash:
            errors.append(f"duplicate_receipt:{receipt_id}")
        if body["record_type"] == "resolution":
            resolution = body["resolution"]
            target_hash = resolution["resolves_receipt_hash"]
            target = by_hash.get(target_hash)
            if (
                not target
                or target["body"]["record_type"] != "decision"
                or "suspension" not in target["body"]
            ):
                errors.append(f"resolution_target_invalid:{receipt_id}")
            else:
                if target_hash in resolved:
                    errors.append(f"duplicate_resolution:{receipt_id}")
                else:
                    resolved.add(target_hash)
                target_body = target["body"]
                if _canonical_json_for_hash(
                    body["identity"]
                ) != _canonical_json_for_hash(target_body["identity"]):
                    errors.append(f"resolution_identity_mismatch:{receipt_id}")
                action_fields = (
                    "action_id",
                    "kind",
                    "name",
                    "arguments_hash",
                    "target_hash",
                )
                if (
                    any(
                        body["action"].get(field) != target_body["action"].get(field)
                        for field in action_fields
                    )
                    or body["context_hash"] != target_body["context_hash"]
                ):
                    errors.append(f"resolution_action_mismatch:{receipt_id}")
                suspension = target_body["suspension"]
                if resolution["suspension_id"] != suspension["suspension_id"]:
                    errors.append(f"resolution_suspension_mismatch:{receipt_id}")
                if not _resolution_method_matches(
                    suspension["type"], resolution["method"]
                ):
                    errors.append(f"resolution_method_mismatch:{receipt_id}")
                if body["timestamp_ms"] < target_body["timestamp_ms"]:
                    errors.append(f"resolution_before_decision:{receipt_id}")
                if (
                    resolution["method"] in ("approval_granted", "context_supplied")
                    and body["timestamp_ms"] >= suspension["expires_at_ms"]
                ):
                    errors.append(f"resolution_after_expiry:{receipt_id}")
        current = {**envelope, "body": body}
        by_hash[receipt_hash] = current
        previous = current
    return {"valid": not errors, "errors": errors}
