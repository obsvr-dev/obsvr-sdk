"""Versioned strict receipts with signed tenant and target-hash binding."""

from __future__ import annotations

import base64
import binascii
import hashlib
from typing import Any, Dict, List, Optional

from .intent_alignment_v2 import INTENT_V2_ENGINE_VERSION
from .strict_canonical import (
    STRICT_IDENTIFIER_MAX_BYTES,
    STRICT_SET_MAX_ITEMS,
    bounded_canonical_text,
)
from .strict_receipt import (
    STRICT_RECEIPT_PROFILE_VERSION,
    STRICT_RECEIPT_SCHEMA,
    build_strict_receipt_body,
)
from .tool_pinning import _canonical_json_for_hash

STRICT_RECEIPT_V2_SCHEMA = "obsvr-strict-receipt-v2"
STRICT_RECEIPT_V2_PROFILE_VERSION = "2.0"
STRICT_RECEIPT_V2_ENVELOPE_SCHEMA = "obsvr-strict-receipt-envelope-v2"
STRICT_RECEIPT_V2_BODY_DOMAIN = b"obsvr-strict-receipt/body/2"
STRICT_RECEIPT_V2_SIGNATURE_DOMAIN = b"obsvr-strict-receipt/signature/2"

_HEX = frozenset("0123456789abcdef")


class StrictReceiptV2ValidationError(ValueError):
    """The value cannot be represented as one strict v2 receipt."""


def _fail(message: str) -> None:
    raise StrictReceiptV2ValidationError(message)


def _record(value: Any, field: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{field} must be an object")
    return value


def _exact(value: Dict[str, Any], allowed: set[str], field: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        _fail(f"{field} contains unsupported field: {unknown[0]}")


def _text(value: Any, field: str) -> str:
    return bounded_canonical_text(value, field, STRICT_IDENTIFIER_MAX_BYTES, _fail)


def _hash(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _HEX for character in value)
    ):
        _fail(f"{field} must be 64 lowercase hex characters")
    return value


def _optional_hash(source: Dict[str, Any], key: str, field: str) -> Optional[str]:
    return _hash(source[key], field) if key in source else None


def _bounded_texts(values: Optional[List[str]], field: str) -> None:
    if values is None:
        return
    if len(values) > STRICT_SET_MAX_ITEMS:
        _fail(f"{field} exceeds {STRICT_SET_MAX_ITEMS} items")
    for index, value in enumerate(values):
        _text(value, f"{field}[{index}]")


def _bounded_input_texts(value: Any, field: str) -> None:
    if not isinstance(value, list):
        _fail(f"{field} must be an array")
    if len(value) > STRICT_SET_MAX_ITEMS:
        _fail(f"{field} exceeds {STRICT_SET_MAX_ITEMS} items")
    for index, item in enumerate(value):
        _text(item, f"{field}[{index}]")


def _u64(value: int) -> bytes:
    return value.to_bytes(8, "big", signed=False)


def strict_receipt_v2_key_id(raw_public_key: bytes) -> str:
    if not isinstance(raw_public_key, bytes) or len(raw_public_key) != 32:
        _fail("public key must be 32 raw bytes")
    return "sha256:" + hashlib.sha256(raw_public_key).hexdigest()


def _validate_text_bounds(body: Dict[str, Any]) -> None:
    for value, field in (
        (body["receipt_id"], "receipt_id"),
        (body["session_id"], "session_id"),
        (body["sdk"]["version"], "sdk.version"),
        (body["initiator"]["agent_id"], "initiator.agent_id"),
        (body["action"]["action_id"], "action.action_id"),
        (body["action"]["kind"], "action.kind"),
        (body["action"]["name"], "action.name"),
        (body["context"]["run_id"], "context.run_id"),
        (body["evaluation"]["engine_version"], "evaluation.engine_version"),
        (body["evaluation"]["policy_version"], "evaluation.policy_version"),
        (body["evaluation"]["reason_code"], "evaluation.reason_code"),
    ):
        _text(value, field)
    if "thread_id" in body["context"]:
        _text(body["context"]["thread_id"], "context.thread_id")
    _bounded_texts(body["evaluation"]["rule_ids"], "evaluation.rule_ids")
    suspension = body.get("suspension")
    if suspension:
        _text(suspension["suspension_id"], "suspension.suspension_id")
        _bounded_texts(suspension["required_fields"], "suspension.required_fields")
        if "approval_request_id" in suspension:
            _text(suspension["approval_request_id"], "suspension.approval_request_id")
    resolution = body.get("resolution")
    if resolution:
        _text(resolution["suspension_id"], "resolution.suspension_id")
        _text(resolution["resolver_principal_id"], "resolution.resolver_principal_id")


def build_strict_receipt_v2_body(input_value: Any) -> Dict[str, Any]:
    root = _record(input_value, "receipt body")
    _exact(
        root,
        {
            "schema",
            "profile_version",
            "record_type",
            "receipt_id",
            "tenant_id",
            "session_id",
            "sequence",
            "timestamp_ms",
            "clock_regression_clamped",
            "previous_receipt_hash",
            "sdk",
            "initiator",
            "action",
            "context",
            "evaluation",
            "execution_authorized",
            "suspension",
            "resolution",
        },
        "receipt body",
    )
    if root.get("schema") != STRICT_RECEIPT_V2_SCHEMA:
        _fail("invalid receipt schema")
    if root.get("profile_version") != STRICT_RECEIPT_V2_PROFILE_VERSION:
        _fail("invalid receipt profile_version")
    tenant_id = _text(root.get("tenant_id"), "tenant_id")
    raw_action = _record(root.get("action"), "action")
    _exact(
        raw_action,
        {
            "action_id",
            "kind",
            "name",
            "arguments_hash",
            "target_hash",
            "effective_arguments_hash",
        },
        "action",
    )
    target_hash = _optional_hash(raw_action, "target_hash", "action.target_hash")
    raw_context = _record(root.get("context"), "context")
    _exact(raw_context, {"schema", "context_hash", "run_id", "thread_id"}, "context")
    if raw_context.get("schema") != "obsvr-action-context-v2":
        _fail("invalid context.schema")
    raw_evaluation = _record(root.get("evaluation"), "evaluation")
    _bounded_input_texts(raw_evaluation.get("rule_ids"), "evaluation.rule_ids")
    if "suspension" in root:
        raw_suspension = _record(root["suspension"], "suspension")
        _bounded_input_texts(
            raw_suspension.get("required_fields"), "suspension.required_fields"
        )

    legacy_action = dict(raw_action)
    legacy_action.pop("target_hash", None)
    if target_hash is not None:
        legacy_action["target"] = target_hash
    legacy_input = {
        **root,
        "schema": STRICT_RECEIPT_SCHEMA,
        "profile_version": STRICT_RECEIPT_PROFILE_VERSION,
        "action": legacy_action,
        "context": {**raw_context, "schema": "obsvr-action-context-v1"},
    }
    legacy_input.pop("tenant_id")
    try:
        legacy = build_strict_receipt_body(legacy_input)
    except ValueError as error:
        raise StrictReceiptV2ValidationError(str(error)) from None
    normalized_action = dict(legacy["action"])
    normalized_target = normalized_action.pop("target", None)
    if normalized_target is not None:
        normalized_action["target_hash"] = normalized_target
    body = {
        **legacy,
        "schema": STRICT_RECEIPT_V2_SCHEMA,
        "profile_version": STRICT_RECEIPT_V2_PROFILE_VERSION,
        "tenant_id": tenant_id,
        "action": normalized_action,
        "context": {**legacy["context"], "schema": "obsvr-action-context-v2"},
    }
    _validate_text_bounds(body)
    if body["evaluation"]["engine_version"] != INTENT_V2_ENGINE_VERSION:
        _fail(f"evaluation.engine_version must be {INTENT_V2_ENGINE_VERSION}")
    return body


def canonicalize_strict_receipt_v2_body(input_value: Any) -> str:
    return _canonical_json_for_hash(build_strict_receipt_v2_body(input_value))


def strict_receipt_v2_hash(input_value: Any) -> str:
    body = canonicalize_strict_receipt_v2_body(input_value).encode("utf-8")
    preimage = STRICT_RECEIPT_V2_BODY_DOMAIN + b"\x00" + _u64(len(body)) + body
    return hashlib.sha256(preimage).hexdigest()


def strict_receipt_v2_signature_preimage(key_id: str, receipt_hash: str) -> bytes:
    if (
        not isinstance(key_id, str)
        or not key_id.startswith("sha256:")
        or len(key_id) != 71
        or any(character not in _HEX for character in key_id[7:])
    ):
        _fail("invalid strict key id")
    key = key_id.encode("utf-8")
    digest = bytes.fromhex(_hash(receipt_hash, "receipt_hash"))
    return STRICT_RECEIPT_V2_SIGNATURE_DOMAIN + b"\x00" + _u64(len(key)) + key + digest


def sign_strict_receipt_v2(
    input_value: Any, signer: Any, include_public_key: bool = False
) -> Dict[str, Any]:
    body = build_strict_receipt_v2_body(input_value)
    key_id = strict_receipt_v2_key_id(signer.raw_public_key)
    if body["initiator"]["key_id"] != key_id:
        _fail("signer does not match initiator.key_id")
    receipt_hash = strict_receipt_v2_hash(body)
    preimage = strict_receipt_v2_signature_preimage(key_id, receipt_hash)
    signature = signer.sign_bytes(preimage)
    if (
        not isinstance(signature, str)
        or len(signature) != 128
        or any(character not in _HEX for character in signature)
    ):
        _fail("signer returned an invalid Ed25519 signature")
    public_key_b64 = base64.b64encode(signer.raw_public_key).decode("ascii")
    if signer.public_key_b64 != public_key_b64:
        _fail("signer public_key_b64 does not match raw_public_key")
    from .policy_verify import _resolve_backend

    backend = _resolve_backend()
    try:
        signature_bytes = binascii.unhexlify(signature)
    except (binascii.Error, ValueError) as error:
        raise StrictReceiptV2ValidationError(
            "signer returned an invalid Ed25519 signature"
        ) from error
    if backend is None or not backend(signer.raw_public_key, preimage, signature_bytes):
        _fail("signer signature failed self-verification")
    envelope = {
        "schema": STRICT_RECEIPT_V2_ENVELOPE_SCHEMA,
        "body": body,
        "receipt_hash": receipt_hash,
        "signature": {"algorithm": "Ed25519", "key_id": key_id, "value": signature},
    }
    if include_public_key:
        envelope["public_key_b64"] = public_key_b64
    return envelope
