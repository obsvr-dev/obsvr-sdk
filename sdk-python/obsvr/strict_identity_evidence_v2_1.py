"""Bounded, pseudonymous identity evidence for strict receipt profile 2.1."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import weakref
from typing import Any, Dict, List

from .tool_pinning import _canonical_json_for_hash

STRICT_IDENTITY_EVIDENCE_V2_1_SCHEMA = "obsvr-strict-identity-evidence-v2-1"
STRICT_IDENTITY_EVIDENCE_V2_1_PROFILE = "2.1"
STRICT_IDENTITY_EVIDENCE_V2_1_HASH_DOMAIN = "obsvr-strict-identity-evidence/2.1"

_HASH = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_PRINCIPAL_TYPES = frozenset({"human", "service", "agent", "workload", "unknown"})
_MAX_SET_ITEMS = 64
_MAX_DELEGATION_HOPS = 16
_MAX_CANONICAL_BYTES = 65_536
_MAX_SAFE_INTEGER = 9_007_199_254_740_991


class StrictIdentityEvidenceV21ValidationError(ValueError):
    """Raised when strict identity evidence cannot be canonicalized safely."""


def _fail(message: str) -> None:
    raise StrictIdentityEvidenceV21ValidationError(message)


def _record(value: Any, field: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{field} must be an object")
    return value


def _exact(value: Dict[str, Any], allowed: set[str], field: str) -> None:
    unknown = sorted(set(value) - allowed, key=lambda item: tuple(ord(c) for c in item))
    if unknown:
        _fail(f"{field} contains unsupported field: {unknown[0]}")


def _hex(value: Any, field: str) -> str:
    if not isinstance(value, str) or _HASH.fullmatch(value) is None:
        _fail(f"{field} must be 64 lowercase hex characters")
    return value


def _safe_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None:
        _fail(f"{field} must be a 1-128 byte safe ASCII identifier")
    return value


def _safe_set(value: Any, field: str) -> List[str]:
    if not isinstance(value, list):
        _fail(f"{field} must be an array")
    if len(value) > _MAX_SET_ITEMS:
        _fail(f"{field} exceeds {_MAX_SET_ITEMS} items")
    values = [_safe_id(item, f"{field}[{index}]") for index, item in enumerate(value)]
    return sorted(set(values), key=lambda item: tuple(ord(char) for char in item))


def _integer(value: Any, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > _MAX_SAFE_INTEGER
    ):
        _fail(f"{field} must be a nonnegative safe integer")
    return value


def _subset(child: List[str], parent: List[str]) -> bool:
    return set(child).issubset(parent)


def _delegation_hop(value: Any, index: int, receipt_time: int) -> Dict[str, Any]:
    field = f"delegation_chain[{index}]"
    hop = _record(value, field)
    _exact(
        hop,
        {
            "hop",
            "delegation_id_hash",
            "delegator_ref_hash",
            "delegatee_ref_hash",
            "granted_scopes",
            "issued_at_ms",
            "expires_at_ms",
        },
        field,
    )
    normalized = {
        "hop": _integer(hop.get("hop"), f"{field}.hop"),
        "delegation_id_hash": _hex(
            hop.get("delegation_id_hash"), f"{field}.delegation_id_hash"
        ),
        "delegator_ref_hash": _hex(
            hop.get("delegator_ref_hash"), f"{field}.delegator_ref_hash"
        ),
        "delegatee_ref_hash": _hex(
            hop.get("delegatee_ref_hash"), f"{field}.delegatee_ref_hash"
        ),
        "granted_scopes": _safe_set(
            hop.get("granted_scopes"), f"{field}.granted_scopes"
        ),
        "issued_at_ms": _integer(hop.get("issued_at_ms"), f"{field}.issued_at_ms"),
        "expires_at_ms": _integer(hop.get("expires_at_ms"), f"{field}.expires_at_ms"),
    }
    if normalized["hop"] != index:
        _fail(f"{field}.hop must equal {index}")
    if not (normalized["issued_at_ms"] <= receipt_time < normalized["expires_at_ms"]):
        _fail(f"{field} is not valid at receipt_time_ms")
    return normalized


def build_strict_identity_evidence_v2_1(input_value: Any) -> Dict[str, Any]:
    """Normalize exact profile-2.1 identity fields without accepting raw identity."""

    root = _record(input_value, "identity evidence")
    _exact(
        root,
        {
            "schema",
            "profile_version",
            "relationship",
            "receipt_time_ms",
            "requester",
            "initiator",
            "delegation_chain",
        },
        "identity evidence",
    )
    if root.get("schema") != STRICT_IDENTITY_EVIDENCE_V2_1_SCHEMA:
        _fail(f"schema must be {STRICT_IDENTITY_EVIDENCE_V2_1_SCHEMA}")
    if root.get("profile_version") != STRICT_IDENTITY_EVIDENCE_V2_1_PROFILE:
        _fail(f"profile_version must be {STRICT_IDENTITY_EVIDENCE_V2_1_PROFILE}")
    if root.get("relationship") not in {"direct", "delegated"}:
        _fail("relationship must be direct or delegated")
    receipt_time = _integer(root.get("receipt_time_ms"), "receipt_time_ms")

    requester = _record(root.get("requester"), "requester")
    _exact(
        requester,
        {"requester_ref_hash", "principal_type", "role_ids", "privilege_scopes"},
        "requester",
    )
    if requester.get("principal_type") not in _PRINCIPAL_TYPES:
        _fail("requester.principal_type is unsupported")
    normalized_requester = {
        "requester_ref_hash": _hex(
            requester.get("requester_ref_hash"), "requester.requester_ref_hash"
        ),
        "principal_type": requester["principal_type"],
        "role_ids": _safe_set(requester.get("role_ids"), "requester.role_ids"),
        "privilege_scopes": _safe_set(
            requester.get("privilege_scopes"), "requester.privilege_scopes"
        ),
    }

    initiator = _record(root.get("initiator"), "initiator")
    _exact(
        initiator,
        {"agent_ref_hash", "key_id", "role_ids", "privilege_scopes"},
        "initiator",
    )
    key_id = initiator.get("key_id")
    if not isinstance(key_id, str) or _KEY_ID.fullmatch(key_id) is None:
        _fail("initiator.key_id must be sha256 followed by 64 lowercase hex characters")
    normalized_initiator = {
        "agent_ref_hash": _hex(
            initiator.get("agent_ref_hash"), "initiator.agent_ref_hash"
        ),
        "key_id": key_id,
        "role_ids": _safe_set(initiator.get("role_ids"), "initiator.role_ids"),
        "privilege_scopes": _safe_set(
            initiator.get("privilege_scopes"), "initiator.privilege_scopes"
        ),
    }

    raw_chain = root.get("delegation_chain")
    if not isinstance(raw_chain, list):
        _fail("delegation_chain must be an array")
    if len(raw_chain) > _MAX_DELEGATION_HOPS:
        _fail(f"delegation_chain exceeds {_MAX_DELEGATION_HOPS} items")
    chain = [
        _delegation_hop(hop, index, receipt_time) for index, hop in enumerate(raw_chain)
    ]
    delegation_ids: set[str] = set()
    for hop in chain:
        if hop["delegation_id_hash"] in delegation_ids:
            _fail("delegation_chain contains duplicate delegation_id_hash")
        delegation_ids.add(hop["delegation_id_hash"])

    if root["relationship"] == "direct":
        if chain:
            _fail("direct relationship requires an empty delegation_chain")
        if (
            normalized_requester["requester_ref_hash"]
            != normalized_initiator["agent_ref_hash"]
        ):
            _fail("direct relationship requires requester and initiator to match")
        if not _subset(
            normalized_initiator["privilege_scopes"],
            normalized_requester["privilege_scopes"],
        ):
            _fail("initiator privilege_scopes exceed requester privilege_scopes")
    else:
        if not chain:
            _fail("delegated relationship requires delegation_chain")
        if chain[0]["delegator_ref_hash"] != normalized_requester["requester_ref_hash"]:
            _fail("delegation_chain must start at requester")
        if chain[-1]["delegatee_ref_hash"] != normalized_initiator["agent_ref_hash"]:
            _fail("delegation_chain must end at initiator")
        if not _subset(
            chain[0]["granted_scopes"], normalized_requester["privilege_scopes"]
        ):
            _fail("first delegation grants scopes outside requester privilege_scopes")
        for index in range(1, len(chain)):
            if (
                chain[index - 1]["delegatee_ref_hash"]
                != chain[index]["delegator_ref_hash"]
            ):
                _fail(f"delegation_chain[{index}] does not continue the prior hop")
            if not _subset(
                chain[index]["granted_scopes"],
                chain[index - 1]["granted_scopes"],
            ):
                _fail(f"delegation_chain[{index}] expands granted_scopes")
        if not _subset(
            normalized_initiator["privilege_scopes"], chain[-1]["granted_scopes"]
        ):
            _fail("initiator privilege_scopes exceed delegated scopes")

    document = {
        "schema": STRICT_IDENTITY_EVIDENCE_V2_1_SCHEMA,
        "profile_version": STRICT_IDENTITY_EVIDENCE_V2_1_PROFILE,
        "relationship": root["relationship"],
        "receipt_time_ms": receipt_time,
        "requester": normalized_requester,
        "initiator": normalized_initiator,
        "delegation_chain": chain,
    }
    canonical = _canonical_json_for_hash(document)
    if len(canonical.encode("utf-8")) > _MAX_CANONICAL_BYTES:
        _fail(f"canonical identity evidence exceeds {_MAX_CANONICAL_BYTES} UTF-8 bytes")
    return document


def canonicalize_strict_identity_evidence_v2_1(input_value: Any) -> str:
    return _canonical_json_for_hash(build_strict_identity_evidence_v2_1(input_value))


def strict_identity_evidence_v2_1_hash(input_value: Any) -> str:
    canonical = canonicalize_strict_identity_evidence_v2_1(input_value)
    preimage = f"{STRICT_IDENTITY_EVIDENCE_V2_1_HASH_DOMAIN}\0{canonical}"
    return hashlib.sha256(preimage.encode("utf-8")).hexdigest()


class _TrustedStrictIdentityEvidenceV21:
    __slots__ = ("schema", "profile_version", "_canonical", "__weakref__")

    def __init__(self, canonical: str) -> None:
        self.schema = STRICT_IDENTITY_EVIDENCE_V2_1_SCHEMA
        self.profile_version = STRICT_IDENTITY_EVIDENCE_V2_1_PROFILE
        self._canonical = canonical


_TRUSTED: weakref.WeakSet[_TrustedStrictIdentityEvidenceV21] = weakref.WeakSet()


class StrictIdentityEvidenceV21Authority:
    """Issue process-local evidence objects that plain dictionaries cannot forge."""

    __slots__ = ()

    def issue(self, input_value: Any) -> _TrustedStrictIdentityEvidenceV21:
        evidence = _TrustedStrictIdentityEvidenceV21(
            canonicalize_strict_identity_evidence_v2_1(input_value)
        )
        _TRUSTED.add(evidence)
        return evidence


def create_strict_identity_evidence_v2_1_authority() -> (
    StrictIdentityEvidenceV21Authority
):
    return StrictIdentityEvidenceV21Authority()


def trusted_strict_identity_evidence_v2_1_document(
    evidence: Any,
) -> Dict[str, Any]:
    if (
        not isinstance(evidence, _TrustedStrictIdentityEvidenceV21)
        or evidence not in _TRUSTED
    ):
        _fail("identity evidence was not issued by a trusted authority")
    parsed = json.loads(evidence._canonical)
    return copy.deepcopy(build_strict_identity_evidence_v2_1(parsed))
