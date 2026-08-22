"""Pure canonical strict receipts and offline verification."""

from __future__ import annotations

import base64
import binascii
import hashlib
from typing import Any, Dict, List, Optional

from .aarm_outcome import AARM_OUTCOMES
from .tool_pinning import _canonical_json_for_hash

STRICT_RECEIPT_SCHEMA = "obsvr-strict-receipt-v1"
STRICT_RECEIPT_PROFILE_VERSION = "1.0"
STRICT_RECEIPT_ENVELOPE_SCHEMA = "obsvr-strict-receipt-envelope-v1"
STRICT_RECEIPT_BODY_DOMAIN = b"obsvr-strict-receipt/body/1"
STRICT_RECEIPT_SIGNATURE_DOMAIN = b"obsvr-strict-receipt/signature/1"

_OUTCOMES = frozenset(AARM_OUTCOMES)
_HEX = frozenset("0123456789abcdef")
_MAX_SAFE_INTEGER = 9_007_199_254_740_991


class StrictReceiptValidationError(ValueError):
    """The value cannot be represented as one strict receipt."""


def _record(value: Any, field: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise StrictReceiptValidationError(f"{field} must be an object")
    return value


def _exact(value: Dict[str, Any], allowed: set[str], field: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise StrictReceiptValidationError(
            f"{field} contains unsupported field: {unknown[0]}"
        )


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise StrictReceiptValidationError(f"{field} must be a nonblank string")
    return value


def _hash(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in _HEX for char in value)
    ):
        raise StrictReceiptValidationError(
            f"{field} must be 64 lowercase hex characters"
        )
    return value


def _safe_integer(value: Any, field: str, *, positive: bool = False) -> int:
    floor = 1 if positive else 0
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < floor
        or value > _MAX_SAFE_INTEGER
    ):
        label = "positive" if positive else "nonnegative"
        raise StrictReceiptValidationError(f"{field} must be a {label} safe integer")
    return value


def _optional_text(source: Dict[str, Any], key: str, field: str) -> Optional[str]:
    if key not in source:
        return None
    return _text(source[key], field)


def _string_set(value: Any, field: str) -> List[str]:
    if not isinstance(value, list):
        raise StrictReceiptValidationError(f"{field} must be an array")
    values = [_text(item, f"{field}[{index}]") for index, item in enumerate(value)]
    return sorted(set(values), key=lambda item: tuple(ord(char) for char in item))


def _u64(value: int) -> bytes:
    return value.to_bytes(8, "big", signed=False)


def strict_receipt_key_id(raw_public_key: bytes) -> str:
    if len(raw_public_key) != 32:
        raise StrictReceiptValidationError("public key must be 32 raw bytes")
    return "sha256:" + hashlib.sha256(raw_public_key).hexdigest()


def build_strict_receipt_body(input_value: Any) -> Dict[str, Any]:
    root = _record(input_value, "receipt body")
    _exact(
        root,
        {
            "schema",
            "profile_version",
            "record_type",
            "receipt_id",
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
    if root.get("schema") != STRICT_RECEIPT_SCHEMA:
        raise StrictReceiptValidationError("invalid receipt schema")
    if root.get("profile_version") != STRICT_RECEIPT_PROFILE_VERSION:
        raise StrictReceiptValidationError("invalid receipt profile_version")
    record_type = root.get("record_type")
    if record_type not in ("decision", "resolution"):
        raise StrictReceiptValidationError("invalid record_type")
    session_id = _text(root.get("session_id"), "session_id")
    sequence = _safe_integer(root.get("sequence"), "sequence", positive=True)
    if root.get("receipt_id") != f"{session_id}:{sequence}":
        raise StrictReceiptValidationError("receipt_id must equal session_id:sequence")
    timestamp = _safe_integer(root.get("timestamp_ms"), "timestamp_ms")
    if not isinstance(root.get("clock_regression_clamped"), bool):
        raise StrictReceiptValidationError(
            "clock_regression_clamped must be a boolean"
        )
    if sequence == 1:
        if root.get("previous_receipt_hash") is not None:
            raise StrictReceiptValidationError(
                "genesis previous_receipt_hash must be null"
            )
        previous = None
    else:
        previous = _hash(root.get("previous_receipt_hash"), "previous_receipt_hash")

    sdk = _record(root.get("sdk"), "sdk")
    _exact(sdk, {"language", "version"}, "sdk")
    if sdk.get("language") not in ("typescript", "python"):
        raise StrictReceiptValidationError("invalid sdk.language")
    initiator = _record(root.get("initiator"), "initiator")
    _exact(initiator, {"agent_id", "key_id"}, "initiator")
    key_id = _text(initiator.get("key_id"), "initiator.key_id")
    if (
        not key_id.startswith("sha256:")
        or len(key_id) != 71
        or any(char not in _HEX for char in key_id[7:])
    ):
        raise StrictReceiptValidationError(
            "initiator.key_id must be sha256:<64 lowercase hex>"
        )

    action = _record(root.get("action"), "action")
    _exact(
        action,
        {
            "action_id",
            "kind",
            "name",
            "arguments_hash",
            "target",
            "effective_arguments_hash",
        },
        "action",
    )
    normalized_action: Dict[str, Any] = {
        "action_id": _text(action.get("action_id"), "action.action_id"),
        "kind": _text(action.get("kind"), "action.kind"),
        "name": _text(action.get("name"), "action.name"),
        "arguments_hash": _hash(action.get("arguments_hash"), "action.arguments_hash"),
    }
    target = _optional_text(action, "target", "action.target")
    if target is not None:
        normalized_action["target"] = target

    context = _record(root.get("context"), "context")
    _exact(context, {"schema", "context_hash", "run_id", "thread_id"}, "context")
    if context.get("schema") != "obsvr-action-context-v1":
        raise StrictReceiptValidationError("invalid context.schema")
    normalized_context: Dict[str, Any] = {
        "schema": "obsvr-action-context-v1",
        "context_hash": _hash(context.get("context_hash"), "context.context_hash"),
        "run_id": _text(context.get("run_id"), "context.run_id"),
    }
    thread_id = _optional_text(context, "thread_id", "context.thread_id")
    if thread_id is not None:
        normalized_context["thread_id"] = thread_id

    evaluation = _record(root.get("evaluation"), "evaluation")
    _exact(
        evaluation,
        {
            "input_hash",
            "policy_hash",
            "evaluator_hash",
            "engine_version",
            "policy_version",
            "outcome",
            "reason_code",
            "rule_ids",
        },
        "evaluation",
    )
    outcome = evaluation.get("outcome")
    if not isinstance(outcome, str) or outcome not in _OUTCOMES:
        raise StrictReceiptValidationError("invalid evaluation.outcome")
    normalized_evaluation = {
        "input_hash": _hash(evaluation.get("input_hash"), "evaluation.input_hash"),
        "policy_hash": _hash(evaluation.get("policy_hash"), "evaluation.policy_hash"),
        "evaluator_hash": _hash(
            evaluation.get("evaluator_hash"), "evaluation.evaluator_hash"
        ),
        "engine_version": _text(
            evaluation.get("engine_version"), "evaluation.engine_version"
        ),
        "policy_version": _text(
            evaluation.get("policy_version"), "evaluation.policy_version"
        ),
        "outcome": outcome,
        "reason_code": _text(evaluation.get("reason_code"), "evaluation.reason_code"),
        "rule_ids": _string_set(evaluation.get("rule_ids"), "evaluation.rule_ids"),
    }
    authorized = outcome in ("ALLOW", "MODIFY")
    if root.get("execution_authorized") is not authorized:
        raise StrictReceiptValidationError("execution_authorized disagrees with outcome")
    if outcome == "MODIFY":
        effective = _hash(
            action.get("effective_arguments_hash"), "action.effective_arguments_hash"
        )
        if effective == normalized_action["arguments_hash"]:
            raise StrictReceiptValidationError("MODIFY effective hash must differ")
        normalized_action["effective_arguments_hash"] = effective
    elif "effective_arguments_hash" in action:
        raise StrictReceiptValidationError("effective_arguments_hash requires MODIFY")

    suspension = None
    if record_type == "decision" and outcome in ("STEP_UP", "DEFER"):
        raw = _record(root.get("suspension"), "suspension")
        _exact(
            raw,
            {
                "suspension_id",
                "type",
                "status",
                "required_fields",
                "expires_at_ms",
                "approval_request_id",
                "approval_action_hash",
            },
            "suspension",
        )
        expected = "approval" if outcome == "STEP_UP" else "context"
        if raw.get("type") != expected:
            raise StrictReceiptValidationError(
                f"suspension.type must be {expected}"
            )
        if raw.get("status") != "pending":
            raise StrictReceiptValidationError("suspension.status must be pending")
        required_fields = _string_set(
            raw.get("required_fields"), "suspension.required_fields"
        )
        expires_at = _safe_integer(
            raw.get("expires_at_ms"), "suspension.expires_at_ms"
        )
        if expires_at < timestamp:
            raise StrictReceiptValidationError(
                "suspension.expires_at_ms precedes timestamp_ms"
            )
        suspension = {
            "suspension_id": _text(
                raw.get("suspension_id"), "suspension.suspension_id"
            ),
            "type": expected,
            "status": "pending",
            "required_fields": required_fields,
            "expires_at_ms": expires_at,
        }
        if outcome == "STEP_UP":
            if required_fields:
                raise StrictReceiptValidationError(
                    "STEP_UP required_fields must be empty"
                )
            suspension["approval_request_id"] = _text(
                raw.get("approval_request_id"),
                "suspension.approval_request_id",
            )
            suspension["approval_action_hash"] = _hash(
                raw.get("approval_action_hash"),
                "suspension.approval_action_hash",
            )
        else:
            if not required_fields:
                raise StrictReceiptValidationError(
                    "DEFER required_fields must be nonempty"
                )
            if "approval_request_id" in raw or "approval_action_hash" in raw:
                raise StrictReceiptValidationError(
                    "DEFER cannot carry approval fields"
                )
    elif "suspension" in root:
        raise StrictReceiptValidationError(
            "suspension requires a STEP_UP or DEFER decision"
        )

    resolution = None
    if record_type == "resolution":
        if outcome not in ("ALLOW", "DENY", "MODIFY"):
            raise StrictReceiptValidationError("resolution outcome must be final")
        raw = _record(root.get("resolution"), "resolution")
        _exact(
            raw,
            {
                "resolves_receipt_hash",
                "suspension_id",
                "method",
                "resolver_principal_id",
                "resolution_source_hash",
                "resolved_at_ms",
            },
            "resolution",
        )
        method = raw.get("method")
        if method not in (
            "approval_granted",
            "approval_denied",
            "context_supplied",
            "expired",
            "cancelled",
        ):
            raise StrictReceiptValidationError("invalid resolution.method")
        if method in ("approval_denied", "expired", "cancelled") and outcome != "DENY":
            raise StrictReceiptValidationError("resolution method requires DENY")
        resolved_at = _safe_integer(
            raw.get("resolved_at_ms"), "resolution.resolved_at_ms"
        )
        if resolved_at > timestamp:
            raise StrictReceiptValidationError(
                "resolution.resolved_at_ms exceeds timestamp_ms"
            )
        resolution = {
            "resolves_receipt_hash": _hash(
                raw.get("resolves_receipt_hash"),
                "resolution.resolves_receipt_hash",
            ),
            "suspension_id": _text(
                raw.get("suspension_id"), "resolution.suspension_id"
            ),
            "method": method,
            "resolver_principal_id": _text(
                raw.get("resolver_principal_id"),
                "resolution.resolver_principal_id",
            ),
            "resolution_source_hash": _hash(
                raw.get("resolution_source_hash"),
                "resolution.resolution_source_hash",
            ),
            "resolved_at_ms": resolved_at,
        }
    elif "resolution" in root:
        raise StrictReceiptValidationError("decision cannot carry resolution")

    body = {
        "schema": STRICT_RECEIPT_SCHEMA,
        "profile_version": STRICT_RECEIPT_PROFILE_VERSION,
        "record_type": record_type,
        "receipt_id": f"{session_id}:{sequence}",
        "session_id": session_id,
        "sequence": sequence,
        "timestamp_ms": timestamp,
        "clock_regression_clamped": root["clock_regression_clamped"],
        "previous_receipt_hash": previous,
        "sdk": {"language": sdk["language"], "version": _text(sdk.get("version"), "sdk.version")},
        "initiator": {
            "agent_id": _text(initiator.get("agent_id"), "initiator.agent_id"),
            "key_id": key_id,
        },
        "action": normalized_action,
        "context": normalized_context,
        "evaluation": normalized_evaluation,
        "execution_authorized": authorized,
    }
    if suspension is not None:
        body["suspension"] = suspension
    if resolution is not None:
        body["resolution"] = resolution
    return body


def canonicalize_strict_receipt_body(input_value: Any) -> str:
    return _canonical_json_for_hash(build_strict_receipt_body(input_value))


def strict_receipt_hash(input_value: Any) -> str:
    body = canonicalize_strict_receipt_body(input_value).encode("utf-8")
    preimage = STRICT_RECEIPT_BODY_DOMAIN + b"\x00" + _u64(len(body)) + body
    return hashlib.sha256(preimage).hexdigest()


def strict_receipt_signature_preimage(key_id: str, receipt_hash: str) -> bytes:
    if (
        not isinstance(key_id, str)
        or not key_id.startswith("sha256:")
        or len(key_id) != 71
        or any(char not in _HEX for char in key_id[7:])
    ):
        raise StrictReceiptValidationError("invalid strict key id")
    key = key_id.encode("utf-8")
    digest = bytes.fromhex(_hash(receipt_hash, "receipt_hash"))
    return STRICT_RECEIPT_SIGNATURE_DOMAIN + b"\x00" + _u64(len(key)) + key + digest


def sign_strict_receipt(
    input_value: Any, signer: Any, include_public_key: bool = False
) -> Dict[str, Any]:
    body = build_strict_receipt_body(input_value)
    key_id = strict_receipt_key_id(signer.raw_public_key)
    if body["initiator"]["key_id"] != key_id:
        raise StrictReceiptValidationError("signer does not match initiator.key_id")
    receipt_hash = strict_receipt_hash(body)
    preimage = strict_receipt_signature_preimage(key_id, receipt_hash)
    signature = signer.sign_bytes(preimage)
    if (
        not isinstance(signature, str)
        or len(signature) != 128
        or any(char not in _HEX for char in signature)
    ):
        raise StrictReceiptValidationError(
            "signer returned an invalid Ed25519 signature"
        )
    public_key_b64 = base64.b64encode(signer.raw_public_key).decode("ascii")
    if signer.public_key_b64 != public_key_b64:
        raise StrictReceiptValidationError(
            "signer public_key_b64 does not match raw_public_key"
        )
    from .policy_verify import _resolve_backend

    backend = _resolve_backend()
    try:
        signature_bytes = binascii.unhexlify(signature)
    except (binascii.Error, ValueError) as exc:
        raise StrictReceiptValidationError(
            "signer returned an invalid Ed25519 signature"
        ) from exc
    if backend is None or not backend(signer.raw_public_key, preimage, signature_bytes):
        raise StrictReceiptValidationError(
            "signer signature failed self-verification"
        )
    envelope = {
        "schema": STRICT_RECEIPT_ENVELOPE_SCHEMA,
        "body": body,
        "receipt_hash": receipt_hash,
        "signature": {
            "algorithm": "Ed25519",
            "key_id": key_id,
            "value": signature,
        },
    }
    if include_public_key:
        envelope["public_key_b64"] = public_key_b64
    return envelope
