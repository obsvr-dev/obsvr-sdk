"""Authenticated profile-2.1 coordinator recovery checkpoints."""

from __future__ import annotations

import copy
import hashlib
from typing import Any, Dict

from .strict_receipt_coordinator_v2_1_support import normalize_decision_action_v2_1
from .strict_receipt_v2_1 import strict_receipt_v2_1_key_id
from .strict_receipt_v2_1_verify import verify_strict_receipt_v2_1
from .tool_pinning import _canonical_json_for_hash

STRICT_RECOVERY_V2_1_SCHEMA = "obsvr-strict-receipt-recovery-v2-1"
STRICT_RECOVERY_V2_1_ENVELOPE_SCHEMA = "obsvr-strict-receipt-recovery-envelope-v2-1"
_DOMAIN = b"obsvr-strict-receipt-recovery/2.1\x00"
_HEX = frozenset("0123456789abcdef")
_MAX_SAFE = 9_007_199_254_740_991


class StrictRecoveryV21Error(ValueError):
    """A profile-2.1 recovery checkpoint is malformed or untrusted."""


def _exact(value: Any, required: set[str], optional: set[str] = frozenset()) -> None:
    if (
        not isinstance(value, dict)
        or set(value) - required - optional
        or required - set(value)
    ):
        raise StrictRecoveryV21Error(
            "checkpoint contains missing or unsupported fields"
        )


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise StrictRecoveryV21Error(f"{field} must be nonblank")
    return value


def _integer(value: Any, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= _MAX_SAFE
    ):
        raise StrictRecoveryV21Error(f"{field} must be a nonnegative safe integer")
    return value


def _hash(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in _HEX for char in value)
    ):
        raise StrictRecoveryV21Error(f"{field} must be 64 lowercase hex characters")
    return value


def _sorted_unique(value: Any, field: str) -> None:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise StrictRecoveryV21Error(f"{field} must be a string array")
    if value != sorted(set(value)):
        raise StrictRecoveryV21Error(f"{field} must be sorted and unique")


def _checkpoint_hash(document: Dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json_for_hash(document).encode()).hexdigest()


def _preimage(checkpoint_hash: str) -> bytes:
    return _DOMAIN + bytes.fromhex(checkpoint_hash)


def _verify(key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        Ed25519PublicKey.from_public_bytes(key).verify(signature, message)
        return True
    except Exception:
        try:
            from nacl.signing import VerifyKey

            VerifyKey(key).verify(message, signature)
            return True
        except Exception:
            return False


def validate_strict_recovery_v2_1_document(document: Dict[str, Any]) -> None:
    _exact(
        document,
        {
            "schema",
            "profile_version",
            "tenant_id",
            "session_id",
            "sdk_language",
            "sdk_version",
            "origin_pid",
            "committed",
        },
        {"prepared"},
    )
    if (
        document["schema"] != STRICT_RECOVERY_V2_1_SCHEMA
        or document["profile_version"] != "2.1"
        or document["sdk_language"] != "python"
    ):
        raise StrictRecoveryV21Error("invalid checkpoint document")
    _text(document["tenant_id"], "tenant_id")
    _text(document["session_id"], "session_id")
    _text(document["sdk_version"], "sdk_version")
    _integer(document["origin_pid"], "origin_pid")
    committed = document["committed"]
    _exact(
        committed,
        {
            "sequence",
            "head_receipt_hash",
            "last_timestamp_ms",
            "prior_actions",
            "action_ids",
            "pending_approval_ids",
        },
    )
    sequence = _integer(committed["sequence"], "committed.sequence")
    head = committed["head_receipt_hash"]
    if (head is None) != (sequence == 0):
        raise StrictRecoveryV21Error("checkpoint head/sequence mismatch")
    if head is not None:
        _hash(head, "head_receipt_hash")
    if (committed["last_timestamp_ms"] is None) != (sequence == 0):
        raise StrictRecoveryV21Error("checkpoint timestamp/sequence mismatch")
    if committed["last_timestamp_ms"] is not None:
        _integer(committed["last_timestamp_ms"], "last_timestamp_ms")
    if not isinstance(committed["prior_actions"], list):
        raise StrictRecoveryV21Error("prior_actions must be an array")
    _sorted_unique(committed["action_ids"], "action_ids")
    _sorted_unique(committed["pending_approval_ids"], "pending_approval_ids")
    prior = committed["prior_actions"]
    if len(prior) != sequence or (
        prior
        and (
            prior[-1].get("sequence") != sequence
            or prior[-1].get("receipt_hash") != head
        )
    ):
        raise StrictRecoveryV21Error("committed history does not match checkpoint head")
    prepared = document.get("prepared")
    if prepared is None:
        return
    _exact(prepared, {"kind", "input", "result"})
    if prepared["kind"] != "decision":
        raise StrictRecoveryV21Error("profile 2.1 recovery accepts decisions only")
    _exact(
        prepared["result"],
        {"action_context", "intent_evaluation", "evaluation_evidence", "receipt"},
    )
    _exact(
        prepared["result"]["intent_evaluation"],
        {"outcome", "reason_code", "context_hash", "policy_hash"},
    )
    context = prepared["result"]["action_context"]
    _exact(
        context,
        {"schema", "agent", "action", "run_id", "prior_actions"},
        {"session_id", "thread_id"},
    )
    _exact(
        context["agent"], {"agent_id", "active_intents"}, {"role", "privilege_scope"}
    )
    _exact(
        context["action"],
        {"kind", "name", "arguments_hash", "data_classifications", "requested_scopes"},
        {"target_hash"},
    )
    try:
        if _canonical_json_for_hash(
            normalize_decision_action_v2_1(prepared["input"])
        ) != _canonical_json_for_hash(prepared["input"]):
            raise StrictRecoveryV21Error("prepared state is not canonical")
    except Exception as error:
        if isinstance(error, StrictRecoveryV21Error):
            raise
        raise StrictRecoveryV21Error("prepared state is not canonical") from error
    receipt = prepared.get("result", {}).get("receipt")
    verified = verify_strict_receipt_v2_1(
        receipt, trusted_agent_keys=[], allowed_evaluator_manifest_hashes=[]
    )
    body = receipt.get("body", {}) if isinstance(receipt, dict) else {}
    input_value = prepared.get("input", {})
    action = (
        input_value.get("current_action", {}) if isinstance(input_value, dict) else {}
    )
    result = prepared.get("result", {})
    context = result.get("action_context", {})
    intent = result.get("intent_evaluation", {})
    evidence = result.get("evaluation_evidence", {})
    context_hash = hashlib.sha256(
        _canonical_json_for_hash(context).encode()
    ).hexdigest()
    if (
        not verified["integrity_valid"]
        or body.get("record_type") != "decision"
        or body.get("profile_version") != "2.1"
        or body.get("tenant_id") != document["tenant_id"]
        or body.get("session_id") != document["session_id"]
        or body.get("sequence") != sequence + 1
        or body.get("previous_receipt_hash") != head
        or body.get("action", {}).get("action_id") != input_value.get("action_id")
        or body.get("action", {}).get("arguments_hash") != action.get("arguments_hash")
        or body.get("action", {}).get("target_hash") != action.get("target_hash")
        or context_hash != body.get("context_hash")
        or _canonical_json_for_hash(context.get("action"))
        != _canonical_json_for_hash(action)
        or _canonical_json_for_hash(context.get("prior_actions"))
        != _canonical_json_for_hash(committed["prior_actions"])
        or intent.get("context_hash") != body.get("context_hash")
        or intent.get("outcome") != body.get("outcome")
        or intent.get("policy_hash")
        != body.get("evaluation", {}).get("effective_policy", {}).get("artifact_hash")
        or _canonical_json_for_hash([intent.get("reason_code")])
        != _canonical_json_for_hash(
            body.get("evaluation", {}).get("decision_reason_codes")
        )
        or _canonical_json_for_hash(evidence)
        != _canonical_json_for_hash(body.get("evaluation"))
    ):
        raise StrictRecoveryV21Error(
            "prepared decision does not continue the exact checkpoint head"
        )


def sign_strict_recovery_v2_1(document: Dict[str, Any], signer: Any) -> Dict[str, Any]:
    validate_strict_recovery_v2_1_document(document)
    checkpoint_hash = _checkpoint_hash(document)
    key_id = strict_receipt_v2_1_key_id(signer.raw_public_key)
    value = signer.sign_bytes(_preimage(checkpoint_hash))
    if (
        len(value) != 128
        or any(char not in _HEX for char in value)
        or not _verify(
            signer.raw_public_key, _preimage(checkpoint_hash), bytes.fromhex(value)
        )
    ):
        raise StrictRecoveryV21Error("checkpoint signer returned an invalid signature")
    return {
        "schema": STRICT_RECOVERY_V2_1_ENVELOPE_SCHEMA,
        "document": copy.deepcopy(document),
        "checkpoint_hash": checkpoint_hash,
        "signature": {"algorithm": "Ed25519", "key_id": key_id, "value": value},
    }


def verify_strict_recovery_v2_1(value: Any, signer: Any) -> Dict[str, Any]:
    _exact(value, {"schema", "document", "checkpoint_hash", "signature"})
    _exact(value["signature"], {"algorithm", "key_id", "value"})
    signature = value["signature"]
    if (
        value["schema"] != STRICT_RECOVERY_V2_1_ENVELOPE_SCHEMA
        or signature["algorithm"] != "Ed25519"
        or signature["key_id"] != strict_receipt_v2_1_key_id(signer.raw_public_key)
    ):
        raise StrictRecoveryV21Error("invalid checkpoint envelope")
    checkpoint_hash = _hash(value["checkpoint_hash"], "checkpoint_hash")
    signature_hex = signature["value"]
    if (
        not isinstance(signature_hex, str)
        or len(signature_hex) != 128
        or any(char not in _HEX for char in signature_hex)
    ):
        raise StrictRecoveryV21Error("invalid checkpoint envelope")
    validate_strict_recovery_v2_1_document(value["document"])
    if _checkpoint_hash(value["document"]) != checkpoint_hash:
        raise StrictRecoveryV21Error("checkpoint hash mismatch")
    if not _verify(
        signer.raw_public_key, _preimage(checkpoint_hash), bytes.fromhex(signature_hex)
    ):
        raise StrictRecoveryV21Error("checkpoint signature invalid")
    return copy.deepcopy(value["document"])
