"""Explicit source-lineage context for document ancestry and taint.

The caller identifies a source at the trust boundary. Context propagation then
stamps the same validated envelope on every governed event in the async/task
scope. Queue and process boundaries must export and re-bind the envelope.
"""

from __future__ import annotations

import contextvars
import hashlib
import time
import uuid
from contextlib import contextmanager
from typing import Any, Dict, Iterator, Optional

from .strict_canonical import code_point_key
from .tool_pinning import _canonical_json_for_hash

SOURCE_LINEAGE_SCHEMA_V1 = "obsvr-source-lineage/1"
SOURCE_LINEAGE_METADATA_KEY = "obsvr_source_lineage"
SOURCE_LINEAGE_HASH_DOMAIN = b"obsvr-source-lineage/1"

_MAX_SOURCES = 16
_MAX_PARENTS = 32
_MAX_TAINTS = 16
_MAX_ID_BYTES = 256
_MAX_REASON_BYTES = 512
_MAX_ENVELOPE_BYTES = 6000
_SOURCE_KINDS = {"document", "retrieval", "tool_result", "memory", "user_input", "other"}
_DERIVATIONS = {"direct", "retrieved", "generated", "summarized", "tool_result", "handoff", "merged", "unknown"}
_TAINT_KINDS = {"prompt_injection", "canary_leak", "policy_violation", "custom"}

_current_lineage: contextvars.ContextVar[Optional[Dict[str, Any]]] = contextvars.ContextVar(
    "obsvr_current_source_lineage", default=None
)


def _fail(message: str) -> None:
    raise TypeError(f"Invalid source lineage: {message}")


def _bounded_string(value: Any, field: str, max_bytes: int = _MAX_ID_BYTES) -> str:
    if not isinstance(value, str) or not value or all(
        ord(character) == 0x20 or 0x09 <= ord(character) <= 0x0D
        for character in value
    ):
        _fail(f"{field} must be a non-empty string")
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        _fail(f"{field} contains an unpaired surrogate")
    if len(value.encode("utf-8")) > max_bytes:
        _fail(f"{field} exceeds {max_bytes} UTF-8 bytes")
    return value


def _optional_string(value: Any, field: str) -> Optional[str]:
    if value is None:
        return None
    return _bounded_string(value, field)


def _unique_sorted(values: Any, field: str, maximum: int) -> list[str]:
    if not isinstance(values, list):
        _fail(f"{field} must be an array")
    if len(values) > maximum:
        _fail(f"{field} exceeds {maximum} entries")
    normalized = [_bounded_string(value, f"{field}[{index}]") for index, value in enumerate(values)]
    if len(set(normalized)) != len(normalized):
        _fail(f"{field} contains duplicates")
    return sorted(normalized, key=code_point_key)


def _normalize_source(value: Any, index: int) -> Dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"sources[{index}] must be an object")
    kind = value.get("source_kind")
    if kind not in _SOURCE_KINDS:
        _fail(f"sources[{index}].source_kind is unsupported")
    source_hash = _optional_string(value.get("source_hash"), f"sources[{index}].source_hash")
    if source_hash is not None and (
        len(source_hash) != 64 or any(ch not in "0123456789abcdef" for ch in source_hash)
    ):
        _fail(f"sources[{index}].source_hash must be lowercase SHA-256 hex")
    out: Dict[str, Any] = {
        "source_id": _bounded_string(value.get("source_id"), f"sources[{index}].source_id"),
        "source_kind": kind,
    }
    for key in ("source_version", "chunk_id", "retrieval_id"):
        normalized = _optional_string(value.get(key), f"sources[{index}].{key}")
        if normalized is not None:
            out[key] = normalized
    if source_hash is not None:
        out["source_hash"] = source_hash
    return out


def _normalize_taint(value: Any, index: int) -> Dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"taints[{index}] must be an object")
    kind = value.get("kind")
    if kind not in _TAINT_KINDS:
        _fail(f"taints[{index}].kind is unsupported")
    detected_at_ms = value.get("detected_at_ms")
    if isinstance(detected_at_ms, bool) or not isinstance(detected_at_ms, int) or detected_at_ms < 0:
        _fail(f"taints[{index}].detected_at_ms must be a non-negative safe integer")
    if detected_at_ms > 9_007_199_254_740_991:
        _fail(f"taints[{index}].detected_at_ms must be a non-negative safe integer")
    out: Dict[str, Any] = {
        "taint_id": _bounded_string(value.get("taint_id"), f"taints[{index}].taint_id"),
        "kind": kind,
        "reason": _bounded_string(value.get("reason"), f"taints[{index}].reason", _MAX_REASON_BYTES),
        "detected_at_ms": detected_at_ms,
    }
    for key in ("source_id", "detector", "trigger_event_id"):
        normalized = _optional_string(value.get(key), f"taints[{index}].{key}")
        if normalized is not None:
            out[key] = normalized
    return out


def _body_of(envelope: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema": SOURCE_LINEAGE_SCHEMA_V1,
        "lineage_id": envelope["lineage_id"],
        "derivation": envelope["derivation"],
        "sources": envelope["sources"],
        "parent_lineage_ids": envelope["parent_lineage_ids"],
        "taints": envelope["taints"],
    }


def source_lineage_hash(envelope: Dict[str, Any]) -> str:
    canonical = _canonical_json_for_hash(_body_of(envelope)).encode("utf-8")
    return hashlib.sha256(SOURCE_LINEAGE_HASH_DOMAIN + b"\0" + canonical).hexdigest()


def create_source_lineage(input_value: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(input_value, dict):
        _fail("input must be an object")
    raw_sources = input_value.get("sources")
    if not isinstance(raw_sources, list) or not raw_sources:
        _fail("sources must contain at least one source")
    if len(raw_sources) > _MAX_SOURCES:
        _fail(f"sources exceeds {_MAX_SOURCES} entries")
    derivation = input_value.get("derivation", "direct")
    if derivation not in _DERIVATIONS:
        _fail("derivation is unsupported")
    sources = sorted(
        (_normalize_source(value, index) for index, value in enumerate(raw_sources)),
        key=lambda value: code_point_key(_canonical_json_for_hash(value)),
    )
    if len({_canonical_json_for_hash(value) for value in sources}) != len(sources):
        _fail("sources contains duplicates")
    raw_taints = input_value.get("taints", [])
    if not isinstance(raw_taints, list):
        _fail("taints must be an array")
    if len(raw_taints) > _MAX_TAINTS:
        _fail(f"taints exceeds {_MAX_TAINTS} entries")
    taints = sorted(
        (_normalize_taint(value, index) for index, value in enumerate(raw_taints)),
        key=lambda value: code_point_key(value["taint_id"]),
    )
    if len({value["taint_id"] for value in taints}) != len(taints):
        _fail("taints contains duplicate taint_id values")
    body = {
        "schema": SOURCE_LINEAGE_SCHEMA_V1,
        "lineage_id": _bounded_string(input_value.get("lineage_id", str(uuid.uuid4())), "lineage_id"),
        "derivation": derivation,
        "sources": sources,
        "parent_lineage_ids": _unique_sorted(
            input_value.get("parent_lineage_ids", []), "parent_lineage_ids", _MAX_PARENTS
        ),
        "taints": taints,
    }
    if len(_canonical_json_for_hash(body).encode("utf-8")) > _MAX_ENVELOPE_BYTES:
        _fail(f"canonical envelope exceeds {_MAX_ENVELOPE_BYTES} UTF-8 bytes")
    return {**body, "lineage_hash": source_lineage_hash(body)}


def validate_source_lineage(value: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != SOURCE_LINEAGE_SCHEMA_V1:
        _fail("schema is unsupported")
    rebuilt = create_source_lineage(value)
    if value.get("lineage_hash") != rebuilt["lineage_hash"]:
        _fail("lineage_hash does not match the canonical envelope")
    return rebuilt


def _clone(value: Dict[str, Any]) -> Dict[str, Any]:
    return {
        **value,
        "sources": [dict(source) for source in value["sources"]],
        "parent_lineage_ids": list(value["parent_lineage_ids"]),
        "taints": [dict(taint) for taint in value["taints"]],
    }


def current_source_lineage() -> Optional[Dict[str, Any]]:
    value = _current_lineage.get()
    if value is None:
        return None
    value["lineage_hash"] = source_lineage_hash(value)
    return _clone(value)


@contextmanager
def source_lineage(value: Dict[str, Any]) -> Iterator[Dict[str, Any]]:
    envelope = validate_source_lineage(value) if "lineage_hash" in value else create_source_lineage(value)
    mutable = _clone(envelope)
    token = _current_lineage.set(mutable)
    try:
        yield _clone(mutable)
    finally:
        _current_lineage.reset(token)


def derive_source_lineage(
    *, derivation: str = "handoff", lineage_id: Optional[str] = None
) -> Dict[str, Any]:
    parent = current_source_lineage()
    if parent is None:
        _fail("derive_source_lineage requires an active source-lineage scope")
    return create_source_lineage({
        "lineage_id": lineage_id or str(uuid.uuid4()),
        "derivation": derivation,
        "sources": parent["sources"],
        "parent_lineage_ids": [parent["lineage_id"]],
        "taints": parent["taints"],
    })


def mark_current_lineage_tainted(
    *,
    kind: str,
    reason: str,
    taint_id: Optional[str] = None,
    detected_at_ms: Optional[int] = None,
    source_id: Optional[str] = None,
    detector: Optional[str] = None,
    trigger_event_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    value = _current_lineage.get()
    if value is None:
        return None
    effective_source_id = (
        source_id
        if source_id is not None
        else value["sources"][0]["source_id"] if len(value["sources"]) == 1 else None
    )
    for existing in value["taints"]:
        if (
            existing["kind"] == kind
            and existing["reason"] == reason
            and existing.get("source_id") == effective_source_id
        ):
            return dict(existing)
    if len(value["taints"]) >= _MAX_TAINTS:
        _fail(f"taints exceeds {_MAX_TAINTS} entries")
    candidate = {
        "taint_id": taint_id or str(uuid.uuid4()),
        "kind": kind,
        "reason": reason,
        "detected_at_ms": int(time.time() * 1000) if detected_at_ms is None else detected_at_ms,
        **(
            {"source_id": effective_source_id}
            if effective_source_id is not None
            else {}
        ),
        **({"detector": detector} if detector is not None else {}),
        **({"trigger_event_id": trigger_event_id} if trigger_event_id is not None else {}),
    }
    taint = _normalize_taint(candidate, len(value["taints"]))
    value["taints"].append(taint)
    value["taints"].sort(key=lambda item: code_point_key(item["taint_id"]))
    value["lineage_hash"] = source_lineage_hash(value)
    return dict(taint)


def with_source_lineage_metadata(
    metadata: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    lineage = current_source_lineage()
    if lineage is None:
        return metadata
    return {**(metadata or {}), SOURCE_LINEAGE_METADATA_KEY: lineage}


def source_lineage_hash_from_metadata(metadata: Optional[Dict[str, Any]]) -> Optional[str]:
    """Validate a carried envelope and return the hash format 5 must seal."""
    if not metadata or SOURCE_LINEAGE_METADATA_KEY not in metadata:
        return None
    return validate_source_lineage(metadata[SOURCE_LINEAGE_METADATA_KEY])["lineage_hash"]
