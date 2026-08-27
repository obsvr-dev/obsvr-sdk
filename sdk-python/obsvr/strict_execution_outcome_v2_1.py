"""Signed terminal execution outcomes bound to strict receipt profile 2.1."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from typing import Any, Dict, Optional, Sequence

from .strict_canonical import STRICT_IDENTIFIER_MAX_BYTES, bounded_canonical_text
from .strict_receipt_v2_1 import strict_receipt_v2_1_key_id
from .strict_receipt_v2_1_verify import verify_strict_receipt_v2_1
from .tool_pinning import _canonical_json_for_hash

STRICT_EXECUTION_OUTCOME_V2_1_SCHEMA = "obsvr-strict-execution-outcome-v2-1"
STRICT_EXECUTION_OUTCOME_V2_1_ENVELOPE_SCHEMA = (
    "obsvr-strict-execution-outcome-envelope-v2-1"
)
STRICT_EXECUTION_OUTCOME_V2_1_BODY_DOMAIN = b"obsvr-strict-execution-outcome/body/2.1"
STRICT_EXECUTION_OUTCOME_V2_1_SIGNATURE_DOMAIN = (
    b"obsvr-strict-execution-outcome/signature/2.1"
)
STRICT_EXECUTION_START_V2_1_DOMAIN = b"obsvr-strict-execution-start/2.1"
STRICT_EXECUTION_RESULT_V2_1_DOMAIN = b"obsvr-strict-execution-result/2.1"

_HEX = frozenset("0123456789abcdef")
_ERROR_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_MAX_CANONICAL_BYTES = 262_144


class StrictExecutionOutcomeV21ValidationError(ValueError):
    """The value cannot be represented by the terminal outcome contract."""


def _fail(message: str) -> None:
    raise StrictExecutionOutcomeV21ValidationError(message)


def _record(value: Any, field: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{field} must be an object")
    return value


def _exact(
    value: Dict[str, Any],
    required: set[str],
    field: str,
    optional: Optional[set[str]] = None,
) -> None:
    optional = optional or set()
    unknown = sorted(
        set(value) - required - optional, key=lambda item: tuple(map(ord, item))
    )
    if unknown:
        _fail(f"{field} contains unsupported field: {unknown[0]}")
    missing = sorted(required - set(value), key=lambda item: tuple(map(ord, item)))
    if missing:
        _fail(f"{field} is missing required field: {missing[0]}")


def _text(value: Any, field: str) -> str:
    return bounded_canonical_text(value, field, STRICT_IDENTIFIER_MAX_BYTES, _fail)


def _lower_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in _HEX for character in value)
    )


def _hash(value: Any, field: str) -> str:
    if not _lower_hex(value, 64):
        _fail(f"{field} must be 64 lowercase hex characters")
    return value


def _key_id(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("sha256:")
        and _lower_hex(value[7:], 64)
    )


def _integer(value: Any, field: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        _fail(f"{field} must be a safe integer >= {minimum}")
    if value > 9_007_199_254_740_991:
        _fail(f"{field} must be a safe integer >= {minimum}")
    return value


def _domain_hash(domain: bytes, canonical: str) -> str:
    body = canonical.encode("utf-8")
    return hashlib.sha256(
        domain + b"\x00" + len(body).to_bytes(8, "big") + body
    ).hexdigest()


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


def strict_execution_start_v2_1_hash(input_value: Any) -> str:
    root = _record(input_value, "execution start")
    _exact(
        root,
        {
            "tenant_id",
            "session_id",
            "action_id",
            "decision_receipt_hash",
            "operation_fingerprint",
            "attempt",
            "started_at_ms",
        },
        "execution start",
    )
    _text(root["tenant_id"], "tenant_id")
    _text(root["session_id"], "session_id")
    _text(root["action_id"], "action_id")
    _hash(root["decision_receipt_hash"], "decision_receipt_hash")
    _hash(root["operation_fingerprint"], "operation_fingerprint")
    if root["attempt"] != 1:
        _fail("attempt must be 1")
    _integer(root["started_at_ms"], "started_at_ms")
    return _domain_hash(
        STRICT_EXECUTION_START_V2_1_DOMAIN, _canonical_json_for_hash(root)
    )


def strict_execution_result_v2_1_hash(value: Any) -> str:
    canonical = _canonical_json_for_hash(value)
    if len(canonical.encode("utf-8")) > _MAX_CANONICAL_BYTES:
        _fail(f"canonical result exceeds {_MAX_CANONICAL_BYTES} UTF-8 bytes")
    return _domain_hash(STRICT_EXECUTION_RESULT_V2_1_DOMAIN, canonical)


def build_strict_execution_outcome_v2_1_body(input_value: Any) -> Dict[str, Any]:
    root = _record(input_value, "execution outcome")
    _exact(
        root,
        {
            "schema",
            "profile_version",
            "record_type",
            "outcome_id",
            "tenant_id",
            "session_id",
            "action_id",
            "decision_receipt_hash",
            "decision_sequence",
            "operation_fingerprint",
            "attempt",
            "started_at_ms",
            "execution_start_hash",
            "completed_at_ms",
            "status",
        },
        "execution outcome",
        {"result_hash", "error_code"},
    )
    if (
        root["schema"] != STRICT_EXECUTION_OUTCOME_V2_1_SCHEMA
        or root["profile_version"] != "2.1"
    ):
        _fail("invalid execution outcome profile")
    if root["record_type"] != "execution_outcome":
        _fail("invalid record_type")
    _text(root["outcome_id"], "outcome_id")
    _text(root["tenant_id"], "tenant_id")
    _text(root["session_id"], "session_id")
    _text(root["action_id"], "action_id")
    _hash(root["decision_receipt_hash"], "decision_receipt_hash")
    _integer(root["decision_sequence"], "decision_sequence", 1)
    _hash(root["operation_fingerprint"], "operation_fingerprint")
    if root["attempt"] != 1:
        _fail("attempt must be 1")
    started_at = _integer(root["started_at_ms"], "started_at_ms")
    completed_at = _integer(root["completed_at_ms"], "completed_at_ms")
    if completed_at < started_at:
        _fail("completed_at_ms cannot precede started_at_ms")
    expected_start_hash = strict_execution_start_v2_1_hash(
        {
            "tenant_id": root["tenant_id"],
            "session_id": root["session_id"],
            "action_id": root["action_id"],
            "decision_receipt_hash": root["decision_receipt_hash"],
            "operation_fingerprint": root["operation_fingerprint"],
            "attempt": 1,
            "started_at_ms": started_at,
        }
    )
    if (
        _hash(root["execution_start_hash"], "execution_start_hash")
        != expected_start_hash
    ):
        _fail("execution_start_hash does not match the execution start")
    if root["status"] not in ("succeeded", "failed", "uncertain"):
        _fail("invalid execution outcome status")
    if root["status"] == "succeeded":
        _hash(root.get("result_hash"), "result_hash")
        if "error_code" in root:
            _fail("succeeded outcome cannot contain error_code")
    else:
        if not isinstance(root.get("error_code"), str) or not _ERROR_CODE.fullmatch(
            root["error_code"]
        ):
            _fail("invalid error_code")
        if "result_hash" in root:
            _fail("failed or uncertain outcome cannot contain result_hash")
    canonical = _canonical_json_for_hash(root)
    if len(canonical.encode("utf-8")) > _MAX_CANONICAL_BYTES:
        _fail(f"canonical execution outcome exceeds {_MAX_CANONICAL_BYTES} UTF-8 bytes")
    return json.loads(canonical)


def canonicalize_strict_execution_outcome_v2_1_body(input_value: Any) -> str:
    return _canonical_json_for_hash(
        build_strict_execution_outcome_v2_1_body(input_value)
    )


def strict_execution_outcome_v2_1_hash(input_value: Any) -> str:
    return _domain_hash(
        STRICT_EXECUTION_OUTCOME_V2_1_BODY_DOMAIN,
        canonicalize_strict_execution_outcome_v2_1_body(input_value),
    )


def strict_execution_outcome_v2_1_signature_preimage(
    key_id: str, outcome_hash: str
) -> bytes:
    if not _key_id(key_id):
        _fail("invalid strict key id")
    key = key_id.encode("utf-8")
    return (
        STRICT_EXECUTION_OUTCOME_V2_1_SIGNATURE_DOMAIN
        + b"\x00"
        + len(key).to_bytes(8, "big")
        + key
        + bytes.fromhex(_hash(outcome_hash, "outcome_hash"))
    )


def _decision_integrity(decision: Dict[str, Any]) -> bool:
    try:
        body = decision["body"]
        initiator = body["identity"]["initiator"]
        result = verify_strict_receipt_v2_1(
            decision,
            trusted_agent_keys=[
                {
                    "tenant_id": body["tenant_id"],
                    "agent_ref_hash": initiator["agent_ref_hash"],
                    "key_id": initiator["key_id"],
                    "public_key_b64": decision["public_key_b64"],
                    "status": "active",
                }
            ],
            allowed_evaluator_manifest_hashes=[
                body["evaluation"]["evaluator_manifest_hash"]
            ],
        )
        return bool(result["integrity_valid"])
    except Exception:
        return False


def _binds_decision(body: Dict[str, Any], decision: Dict[str, Any]) -> bool:
    try:
        decision_body = decision["body"]
        return bool(
            _decision_integrity(decision)
            and decision_body["execution_authorized"]
            and body["decision_receipt_hash"] == decision["receipt_hash"]
            and body["decision_sequence"] == decision_body["sequence"]
            and body["tenant_id"] == decision_body["tenant_id"]
            and body["session_id"] == decision_body["session_id"]
            and body["action_id"] == decision_body["action"]["action_id"]
            and body["started_at_ms"] >= decision_body["timestamp_ms"]
        )
    except Exception:
        return False


def sign_strict_execution_outcome_v2_1(
    input_value: Any, signer: Any, decision: Dict[str, Any]
) -> Dict[str, Any]:
    body = build_strict_execution_outcome_v2_1_body(input_value)
    if not _binds_decision(body, decision):
        _fail("execution outcome does not bind an authorized decision receipt")
    key_id = strict_receipt_v2_1_key_id(signer.raw_public_key)
    if (
        key_id != decision["signature"]["key_id"]
        or key_id != decision["body"]["identity"]["initiator"]["key_id"]
    ):
        _fail("outcome signer does not match the decision signer")
    outcome_hash = strict_execution_outcome_v2_1_hash(body)
    preimage = strict_execution_outcome_v2_1_signature_preimage(key_id, outcome_hash)
    signature = signer.sign_bytes(preimage)
    if not _lower_hex(signature, 128):
        _fail("signer returned an invalid Ed25519 signature")
    public_key_b64 = base64.b64encode(signer.raw_public_key).decode("ascii")
    if signer.public_key_b64 != public_key_b64:
        _fail("signer public_key_b64 does not match raw_public_key")
    from .policy_verify import _resolve_backend

    backend = _resolve_backend()
    if backend is None or not backend(
        signer.raw_public_key, preimage, bytes.fromhex(signature)
    ):
        _fail("signer signature failed self-verification")
    return {
        "schema": STRICT_EXECUTION_OUTCOME_V2_1_ENVELOPE_SCHEMA,
        "body": body,
        "outcome_hash": outcome_hash,
        "signature": {"algorithm": "Ed25519", "key_id": key_id, "value": signature},
        "public_key_b64": public_key_b64,
    }


def verify_strict_execution_outcome_v2_1(
    value: Any,
    decision: Dict[str, Any],
    *,
    trusted_agent_keys: Sequence[Dict[str, Any]],
    allowed_evaluator_manifest_hashes: Sequence[str],
) -> Dict[str, bool]:
    envelope = value if isinstance(value, dict) else None
    body = (
        envelope.get("body")
        if envelope and isinstance(envelope.get("body"), dict)
        else None
    )
    signature = (
        envelope.get("signature")
        if envelope and isinstance(envelope.get("signature"), dict)
        else None
    )
    schema_valid = bool(
        envelope
        and set(envelope)
        == {"schema", "body", "outcome_hash", "signature", "public_key_b64"}
        and envelope.get("schema") == STRICT_EXECUTION_OUTCOME_V2_1_ENVELOPE_SCHEMA
        and body
        and _lower_hex(envelope.get("outcome_hash"), 64)
        and signature
        and set(signature) == {"algorithm", "key_id", "value"}
        and signature.get("algorithm") == "Ed25519"
        and _key_id(signature.get("key_id"))
        and _lower_hex(signature.get("value"), 128)
        and isinstance(envelope.get("public_key_b64"), str)
    )
    normalized: Optional[Dict[str, Any]] = None
    semantic_valid = False
    if body:
        try:
            normalized = build_strict_execution_outcome_v2_1_body(body)
            semantic_valid = _canonical_json_for_hash(
                normalized
            ) == _canonical_json_for_hash(body)
        except StrictExecutionOutcomeV21ValidationError:
            pass
    hash_valid = False
    if normalized and envelope and isinstance(envelope.get("outcome_hash"), str):
        try:
            hash_valid = (
                strict_execution_outcome_v2_1_hash(normalized)
                == envelope["outcome_hash"]
            )
        except StrictExecutionOutcomeV21ValidationError:
            pass
    raw_key = _decode_public_key(envelope.get("public_key_b64")) if envelope else None
    signature_valid = False
    if raw_key and signature and envelope:
        try:
            from .policy_verify import _resolve_backend

            backend = _resolve_backend()
            signature_valid = bool(
                backend
                and backend(
                    raw_key,
                    strict_execution_outcome_v2_1_signature_preimage(
                        signature["key_id"], envelope["outcome_hash"]
                    ),
                    bytes.fromhex(signature["value"]),
                )
            )
        except Exception:
            pass
    decision_verification = verify_strict_receipt_v2_1(
        decision,
        trusted_agent_keys=trusted_agent_keys,
        allowed_evaluator_manifest_hashes=allowed_evaluator_manifest_hashes,
    )
    decision_binding_valid = bool(normalized and _binds_decision(normalized, decision))
    try:
        raw_key_id = strict_receipt_v2_1_key_id(raw_key) if raw_key else None
    except Exception:
        raw_key_id = None
    signer_binding_valid = bool(
        raw_key_id
        and signature
        and signature.get("key_id") == raw_key_id
        and raw_key_id == decision.get("signature", {}).get("key_id")
        and envelope
        and envelope.get("public_key_b64") == decision.get("public_key_b64")
    )
    integrity_valid = bool(
        schema_valid
        and semantic_valid
        and hash_valid
        and signature_valid
        and decision_verification["integrity_valid"]
        and decision_binding_valid
        and signer_binding_valid
    )
    return {
        "schema_valid": schema_valid,
        "semantic_valid": semantic_valid,
        "hash_valid": hash_valid,
        "signature_valid": signature_valid,
        "decision_integrity_valid": decision_verification["integrity_valid"],
        "decision_binding_valid": decision_binding_valid,
        "signer_binding_valid": signer_binding_valid,
        "integrity_valid": integrity_valid,
        "decision_trusted": decision_verification["trusted"],
        "trusted": integrity_valid and decision_verification["trusted"],
    }
