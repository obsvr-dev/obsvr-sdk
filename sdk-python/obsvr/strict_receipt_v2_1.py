"""Signed strict receipt profile 2.1 with identity and evaluation evidence."""

from __future__ import annotations

import base64
import hashlib
import re
from typing import Any, Dict, List

from .strict_identity_evidence_v2_1 import (
    build_strict_identity_evidence_v2_1,
)
from .strict_canonical import STRICT_IDENTIFIER_MAX_BYTES, STRICT_SET_MAX_ITEMS
from .tool_pinning import _canonical_json_for_hash

STRICT_RECEIPT_V2_1_SCHEMA = "obsvr-strict-receipt-v2-1"
STRICT_RECEIPT_V2_1_PROFILE_VERSION = "2.1"
STRICT_RECEIPT_V2_1_ENVELOPE_SCHEMA = "obsvr-strict-receipt-envelope-v2-1"
STRICT_RECEIPT_V2_1_BODY_DOMAIN = b"obsvr-strict-receipt/body/2.1"
STRICT_RECEIPT_V2_1_SIGNATURE_DOMAIN = b"obsvr-strict-receipt/signature/2.1"
STRICT_EVALUATION_EVIDENCE_V2_1_SCHEMA = "obsvr-strict-evaluation-evidence-v2-1"

_HEX = frozenset("0123456789abcdef")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
_FAILURE_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_MAX_CANONICAL_BYTES = 262_144
_DETECTOR_SET_DOMAIN = b"obsvr-strict-detector-set/2.1"
_OUTCOMES = frozenset(("ALLOW", "DENY", "MODIFY", "STEP_UP", "DEFER"))
_EVALUATION_REASONS = frozenset(
    (
        "evaluation_complete",
        "required_detector_uncertain",
        "required_transform_unavailable",
    )
)


class StrictReceiptV21ValidationError(ValueError):
    """The value cannot be represented by strict receipt profile 2.1."""


def _fail(message: str) -> None:
    raise StrictReceiptV21ValidationError(message)


def _record(value: Any, field: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{field} must be an object")
    return value


def _exact(
    value: Dict[str, Any],
    required: set[str],
    field: str,
    optional: set[str] | None = None,
) -> None:
    optional = optional or set()
    unknown = sorted(set(value) - required - optional)
    if unknown:
        _fail(f"{field} contains unsupported field: {unknown[0]}")
    missing = sorted(required - set(value))
    if missing:
        _fail(f"{field} is missing required field: {missing[0]}")


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or value.isspace():
        _fail(f"{field} must be a nonblank string")
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        _fail(f"{field} contains an unpaired surrogate")
    if len(value.encode("utf-8")) > STRICT_IDENTIFIER_MAX_BYTES:
        _fail(f"{field} exceeds {STRICT_IDENTIFIER_MAX_BYTES} UTF-8 bytes")
    return value


def _hash(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _HEX for character in value)
    ):
        _fail(f"{field} must be 64 lowercase hex characters")
    return value


def _key_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        _fail(f"invalid {field}")
    _hash(value[7:], field)
    return value


def _integer(value: Any, field: str, minimum: int = 0) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > 9_007_199_254_740_991
    ):
        _fail(f"{field} must be a safe integer >= {minimum}")
    return value


def _canonical_set(value: Any, field: str) -> List[str]:
    if not isinstance(value, list) or len(value) > STRICT_SET_MAX_ITEMS:
        _fail(f"{field} must contain at most {STRICT_SET_MAX_ITEMS} items")
    items = [_text(item, f"{field}[{index}]") for index, item in enumerate(value)]
    if items != sorted(set(items), key=lambda item: tuple(ord(char) for char in item)):
        _fail(f"{field} must be sorted and unique")
    return items


def _safe_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None:
        _fail(f"{field} must be a bounded ASCII identifier")
    return value


def _domain_hash(domain: bytes, canonical: str) -> str:
    body = canonical.encode("utf-8")
    return hashlib.sha256(
        domain + b"\x00" + len(body).to_bytes(8, "big") + body
    ).hexdigest()


def _evaluation(value: Any) -> Dict[str, Any]:
    evaluation = _record(value, "evaluation")
    _exact(
        evaluation,
        {
            "schema",
            "profile_version",
            "effective_policy",
            "evaluator_manifest_hash",
            "detectors",
            "detector_set_hash",
            "requested_outcome",
            "outcome",
            "decision_reason_codes",
            "reason_code",
        },
        "evaluation",
    )
    if evaluation["schema"] != STRICT_EVALUATION_EVIDENCE_V2_1_SCHEMA:
        _fail("invalid evaluation.schema")
    if evaluation["profile_version"] != STRICT_RECEIPT_V2_1_PROFILE_VERSION:
        _fail("invalid evaluation.profile_version")
    policy = _record(evaluation["effective_policy"], "evaluation.effective_policy")
    _exact(
        policy,
        {"version", "artifact_hash", "matched_rule_ids"},
        "evaluation.effective_policy",
    )
    _safe_id(policy["version"], "evaluation.effective_policy.version")
    _hash(policy["artifact_hash"], "evaluation.effective_policy.artifact_hash")
    rules = _canonical_set(
        policy["matched_rule_ids"], "evaluation.effective_policy.matched_rule_ids"
    )
    for index, rule in enumerate(rules):
        _safe_id(rule, f"evaluation.effective_policy.matched_rule_ids[{index}]")
    _hash(evaluation["evaluator_manifest_hash"], "evaluation.evaluator_manifest_hash")
    _hash(evaluation["detector_set_hash"], "evaluation.detector_set_hash")
    detectors = evaluation["detectors"]
    if not isinstance(detectors, list) or len(detectors) > STRICT_SET_MAX_ITEMS:
        _fail(f"evaluation.detectors must contain at most {STRICT_SET_MAX_ITEMS} items")
    previous = None
    for index, candidate in enumerate(detectors):
        detector = _record(candidate, f"evaluation.detectors[{index}]")
        status = detector.get("status")
        required = {
            "detector_id",
            "detector_manifest_hash",
            "required",
            "purpose",
            "status",
            "result_hash" if status == "ok" else "failure_code",
        }
        _exact(detector, required, f"evaluation.detectors[{index}]")
        detector_id = _safe_id(
            detector["detector_id"], f"evaluation.detectors[{index}].detector_id"
        )
        if previous is not None and previous >= detector_id:
            _fail("evaluation.detectors must be sorted by unique detector_id")
        previous = detector_id
        _hash(detector["detector_manifest_hash"], "detector_manifest_hash")
        if type(detector["required"]) is not bool or detector["purpose"] not in (
            "evaluation",
            "transform",
        ):
            _fail("invalid detector requirement")
        if status not in ("ok", "unavailable", "degraded"):
            _fail("invalid detector status")
        if status == "ok":
            _hash(detector["result_hash"], "detector.result_hash")
        else:
            if (
                not isinstance(detector["failure_code"], str)
                or _FAILURE_CODE.fullmatch(detector["failure_code"]) is None
            ):
                _fail("invalid detector failure_code")
    if (
        evaluation["requested_outcome"] not in _OUTCOMES
        or evaluation["outcome"] not in _OUTCOMES
    ):
        _fail("invalid evaluation outcome")
    reasons = evaluation["decision_reason_codes"]
    if not isinstance(reasons, list) or not reasons or len(reasons) > 32:
        _fail("evaluation.decision_reason_codes must contain 1 to 32 items")
    _canonical_set(reasons, "evaluation.decision_reason_codes")
    for index, reason in enumerate(reasons):
        _safe_id(reason, f"evaluation.decision_reason_codes[{index}]")
    if evaluation["reason_code"] not in _EVALUATION_REASONS:
        _fail("invalid evaluation.reason_code")
    unhealthy = [
        detector
        for detector in detectors
        if detector["required"] and detector["status"] != "ok"
    ]
    expected_outcome = evaluation["requested_outcome"]
    expected_reason = "evaluation_complete"
    if evaluation["requested_outcome"] in ("ALLOW", "MODIFY") and any(
        detector["purpose"] == "transform" for detector in unhealthy
    ):
        expected_outcome, expected_reason = "DENY", "required_transform_unavailable"
    elif evaluation["requested_outcome"] in ("ALLOW", "MODIFY") and unhealthy:
        expected_outcome, expected_reason = "DEFER", "required_detector_uncertain"
    if (
        evaluation["outcome"] != expected_outcome
        or evaluation["reason_code"] != expected_reason
    ):
        _fail("evaluation outcome and reason are inconsistent with detector evidence")
    expected_set_hash = _domain_hash(
        _DETECTOR_SET_DOMAIN,
        _canonical_json_for_hash(
            {"schema": "obsvr-strict-detector-set-v2-1", "detectors": detectors}
        ),
    )
    if evaluation["detector_set_hash"] != expected_set_hash:
        _fail("evaluation.detector_set_hash does not match detectors")
    return evaluation


def build_strict_receipt_v2_1_body(input_value: Any) -> Dict[str, Any]:
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
            "previous_receipt_hash",
            "action",
            "context_hash",
            "identity",
            "evaluation",
            "outcome",
            "reason_code",
            "execution_authorized",
        },
        "receipt body",
        {"suspension", "resolution"},
    )
    if root["schema"] != STRICT_RECEIPT_V2_1_SCHEMA or root["profile_version"] != "2.1":
        _fail("invalid receipt profile")
    if root["record_type"] not in ("decision", "resolution"):
        _fail("invalid record_type")
    for field in ("receipt_id", "tenant_id", "session_id"):
        _text(root[field], field)
    sequence = _integer(root["sequence"], "sequence", 1)
    timestamp = _integer(root["timestamp_ms"], "timestamp_ms")
    if root["previous_receipt_hash"] is not None:
        _hash(root["previous_receipt_hash"], "previous_receipt_hash")
    if (sequence == 1) != (root["previous_receipt_hash"] is None):
        _fail("genesis and previous_receipt_hash are inconsistent")
    action = _record(root["action"], "action")
    _exact(
        action,
        {"action_id", "kind", "name", "arguments_hash", "target_hash"},
        "action",
        {"effective_arguments_hash"},
    )
    for field in ("action_id", "kind", "name"):
        _text(action[field], f"action.{field}")
    _hash(action["arguments_hash"], "action.arguments_hash")
    _hash(action["target_hash"], "action.target_hash")
    _hash(root["context_hash"], "context_hash")
    try:
        identity = build_strict_identity_evidence_v2_1(root["identity"])
    except ValueError as error:
        raise StrictReceiptV21ValidationError(str(error)) from None
    evaluation = _evaluation(root["evaluation"])
    if root["record_type"] == "decision" and identity["receipt_time_ms"] != timestamp:
        _fail("decision identity.receipt_time_ms must equal timestamp_ms")
    if root["record_type"] == "resolution" and identity["receipt_time_ms"] > timestamp:
        _fail("resolution identity.receipt_time_ms cannot follow timestamp_ms")
    if (
        root["outcome"] != evaluation["outcome"]
        or root["reason_code"] != evaluation["reason_code"]
    ):
        _fail("receipt outcome and reason must match evaluation evidence")
    if root["outcome"] not in _OUTCOMES:
        _fail("invalid outcome")
    if root["outcome"] == "MODIFY":
        effective = _hash(
            action.get("effective_arguments_hash"), "action.effective_arguments_hash"
        )
        if effective == action["arguments_hash"]:
            _fail("MODIFY effective_arguments_hash must differ from arguments_hash")
    elif "effective_arguments_hash" in action:
        _fail("effective_arguments_hash is valid only for MODIFY")
    if type(root["execution_authorized"]) is not bool:
        _fail("execution_authorized must be boolean")
    if root["execution_authorized"] != (root["outcome"] in ("ALLOW", "MODIFY")):
        _fail("execution_authorized is inconsistent with outcome")
    if "suspension" in root:
        suspension = _record(root["suspension"], "suspension")
        _exact(
            suspension,
            {"suspension_id", "type", "expires_at_ms"},
            "suspension",
            {"approval_action_hash"},
        )
        _text(suspension["suspension_id"], "suspension.suspension_id")
        if suspension["type"] not in ("approval", "context"):
            _fail("invalid suspension.type")
        if (
            _integer(suspension["expires_at_ms"], "suspension.expires_at_ms")
            <= timestamp
        ):
            _fail("suspension expiry must follow receipt timestamp")
        if "approval_action_hash" in suspension:
            if suspension["type"] != "approval":
                _fail("approval_action_hash requires an approval suspension")
            _hash(
                suspension["approval_action_hash"],
                "suspension.approval_action_hash",
            )
    if "resolution" in root:
        resolution = _record(root["resolution"], "resolution")
        _exact(
            resolution,
            {
                "resolves_receipt_hash",
                "suspension_id",
                "method",
                "resolver_ref_hash",
                "resolved_at_ms",
            },
            "resolution",
            {"approval_evidence_hash"},
        )
        _hash(resolution["resolves_receipt_hash"], "resolution.resolves_receipt_hash")
        _text(resolution["suspension_id"], "resolution.suspension_id")
        if resolution["method"] not in (
            "approval_granted",
            "approval_denied",
            "context_supplied",
            "expired",
            "cancelled",
        ):
            _fail("invalid resolution.method")
        _hash(resolution["resolver_ref_hash"], "resolution.resolver_ref_hash")
        if "approval_evidence_hash" in resolution:
            if resolution["method"] not in ("approval_granted", "approval_denied"):
                _fail("approval_evidence_hash requires an approval resolution")
            _hash(
                resolution["approval_evidence_hash"],
                "resolution.approval_evidence_hash",
            )
        if (
            _integer(resolution["resolved_at_ms"], "resolution.resolved_at_ms")
            != timestamp
        ):
            _fail("resolution time must equal receipt timestamp")
    if root["record_type"] == "decision" and "resolution" in root:
        _fail("decision cannot contain resolution")
    if root["record_type"] == "resolution" and (
        "resolution" not in root or "suspension" in root
    ):
        _fail("resolution record has invalid suspension fields")
    if (root["outcome"] in ("STEP_UP", "DEFER")) != ("suspension" in root):
        _fail("suspension is inconsistent with outcome")
    normalized = {**root, "identity": identity, "evaluation": evaluation}
    canonical = _canonical_json_for_hash(normalized)
    if len(canonical.encode("utf-8")) > _MAX_CANONICAL_BYTES:
        _fail(f"canonical receipt exceeds {_MAX_CANONICAL_BYTES} UTF-8 bytes")
    return __import__("json").loads(canonical)


def canonicalize_strict_receipt_v2_1_body(input_value: Any) -> str:
    return _canonical_json_for_hash(build_strict_receipt_v2_1_body(input_value))


def strict_receipt_v2_1_hash(input_value: Any) -> str:
    canonical = canonicalize_strict_receipt_v2_1_body(input_value).encode("utf-8")
    preimage = (
        STRICT_RECEIPT_V2_1_BODY_DOMAIN
        + b"\x00"
        + len(canonical).to_bytes(8, "big")
        + canonical
    )
    return hashlib.sha256(preimage).hexdigest()


def strict_receipt_v2_1_key_id(raw_public_key: bytes) -> str:
    if not isinstance(raw_public_key, bytes) or len(raw_public_key) != 32:
        _fail("public key must be 32 raw bytes")
    return "sha256:" + hashlib.sha256(raw_public_key).hexdigest()


def strict_receipt_v2_1_signature_preimage(key_id: str, receipt_hash: str) -> bytes:
    _key_id(key_id, "strict key id")
    key = key_id.encode("utf-8")
    return (
        STRICT_RECEIPT_V2_1_SIGNATURE_DOMAIN
        + b"\x00"
        + len(key).to_bytes(8, "big")
        + key
        + bytes.fromhex(_hash(receipt_hash, "receipt_hash"))
    )


def sign_strict_receipt_v2_1(input_value: Any, signer: Any) -> Dict[str, Any]:
    body = build_strict_receipt_v2_1_body(input_value)
    key_id = strict_receipt_v2_1_key_id(signer.raw_public_key)
    if body["identity"]["initiator"]["key_id"] != key_id:
        _fail("signer does not match identity.initiator.key_id")
    receipt_hash = strict_receipt_v2_1_hash(body)
    preimage = strict_receipt_v2_1_signature_preimage(key_id, receipt_hash)
    signature = signer.sign_bytes(preimage)
    if (
        not isinstance(signature, str)
        or len(signature) != 128
        or any(c not in _HEX for c in signature)
    ):
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
        "schema": STRICT_RECEIPT_V2_1_ENVELOPE_SCHEMA,
        "body": body,
        "receipt_hash": receipt_hash,
        "signature": {"algorithm": "Ed25519", "key_id": key_id, "value": signature},
        "public_key_b64": public_key_b64,
    }
