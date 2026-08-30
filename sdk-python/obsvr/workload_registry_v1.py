"""Signed runtime workload and capability registrations, not a general CMDB."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from .device_identity import DeviceSigner, derive_device_key_id, verify_device_sig
from .strict_canonical import code_point_key
from .tool_pinning import _canonical_json_for_hash

WORKLOAD_REGISTRATION_V1_SCHEMA = "obsvr-workload-registration-v1"
WORKLOAD_REGISTRATION_ENVELOPE_V1_SCHEMA = "obsvr-workload-registration-envelope-v1"
_HEX = frozenset("0123456789abcdef")


class WorkloadRegistryV1ValidationError(ValueError):
    pass


def _fail(message: str) -> None:
    raise WorkloadRegistryV1ValidationError(message)


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip().encode()) > 256:
        _fail(f"{field} must be nonblank and at most 256 UTF-8 bytes")
    return value.strip()


def _hash(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in _HEX for c in value):
        _fail(f"{field} must be a lowercase SHA-256 hash")
    return value


def _texts(value: Any, field: str) -> List[str]:
    if not isinstance(value, list) or len(value) > 256:
        _fail(f"{field} must contain at most 256 items")
    return sorted({_text(item, f"{field}[{i}]") for i, item in enumerate(value)}, key=code_point_key)


def build_workload_registration_v1(input_value: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(input_value, dict):
        _fail("registration must be an object")
    allowed = {"schema", "workload_id", "owner_ref_hash", "environment", "deployment_id", "autonomy", "entry_points", "capabilities", "providers", "models", "tools", "mcp_servers", "data_zones", "external_side_effects", "required_approvals", "policy_pack_hashes", "coverage_attestation_hash", "registered_at_ms"}
    unknown = sorted(set(input_value) - allowed, key=code_point_key)
    if unknown:
        _fail(f"registration contains unsupported field: {unknown[0]}")
    if "schema" in input_value and input_value["schema"] != WORKLOAD_REGISTRATION_V1_SCHEMA:
        _fail("registration schema is invalid")
    if input_value.get("autonomy") not in {"assistive", "supervised", "autonomous"}:
        _fail("autonomy is invalid")
    registered = input_value.get("registered_at_ms")
    if isinstance(registered, bool) or not isinstance(registered, int) or not 0 <= registered <= 9_007_199_254_740_991:
        _fail("registered_at_ms must be a nonnegative safe integer")
    result = {"schema": WORKLOAD_REGISTRATION_V1_SCHEMA, "workload_id": _text(input_value.get("workload_id"), "workload_id"), "owner_ref_hash": _hash(input_value.get("owner_ref_hash"), "owner_ref_hash"), "environment": _text(input_value.get("environment"), "environment"), "deployment_id": _text(input_value.get("deployment_id"), "deployment_id"), "autonomy": input_value["autonomy"], "registered_at_ms": registered, "coverage_attestation_hash": _hash(input_value.get("coverage_attestation_hash"), "coverage_attestation_hash")}
    for field in ("entry_points", "capabilities", "providers", "models", "tools", "mcp_servers", "data_zones", "external_side_effects", "required_approvals"):
        result[field] = _texts(input_value.get(field), field)
    result["policy_pack_hashes"] = [_hash(item, "policy_pack_hashes") for item in _texts(input_value.get("policy_pack_hashes"), "policy_pack_hashes")]
    if not result["entry_points"] or not result["capabilities"] or not result["policy_pack_hashes"]:
        _fail("entry_points, capabilities, and policy_pack_hashes must be nonempty")
    return result


def workload_registration_v1_hash(input_value: Dict[str, Any]) -> str:
    body = _canonical_json_for_hash(build_workload_registration_v1(input_value))
    return hashlib.sha256(f"obsvr-workload-registration/1\0{body}".encode()).hexdigest()


def sign_workload_registration_v1(input_value: Dict[str, Any], signer: DeviceSigner) -> Dict[str, Any]:
    body = build_workload_registration_v1(input_value)
    body_hash = workload_registration_v1_hash(body)
    payload = f"obsvr-workload-registration-signature/1\0{body_hash}"
    return {"schema": WORKLOAD_REGISTRATION_ENVELOPE_V1_SCHEMA, "body": body, "body_hash": body_hash, "key_id": signer.key_id, "signature": signer.sign_payload(payload)}


def verify_workload_registration_v1(envelope: Any, raw_public_key: bytes) -> bool:
    try:
        if not isinstance(envelope, dict) or envelope.get("schema") != WORKLOAD_REGISTRATION_ENVELOPE_V1_SCHEMA or envelope.get("key_id") != derive_device_key_id(raw_public_key) or not isinstance(envelope.get("signature"), str):
            return False
        body = build_workload_registration_v1(envelope.get("body"))
        body_hash = workload_registration_v1_hash(body)
        payload = f"obsvr-workload-registration-signature/1\0{body_hash}"
        return envelope.get("body_hash") == body_hash and verify_device_sig(raw_public_key, envelope["key_id"], payload, envelope["signature"]) is True
    except (ValueError, TypeError):
        return False


class WorkloadRegistryV1:
    def __init__(self) -> None:
        self._entries: Dict[str, Dict[str, Any]] = {}

    def register(self, envelope: Dict[str, Any], raw_public_key: bytes) -> None:
        if not verify_workload_registration_v1(envelope, raw_public_key):
            _fail("registration signature is invalid")
        body = envelope["body"]
        self._entries[f"{body['workload_id']}\0{body['environment']}\0{body['deployment_id']}"] = envelope

    def snapshot(self) -> List[Dict[str, Any]]:
        return sorted(self._entries.values(), key=lambda item: code_point_key(item["body_hash"]))
