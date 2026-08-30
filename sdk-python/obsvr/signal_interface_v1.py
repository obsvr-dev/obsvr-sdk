"""Bounded evaluator signals; the deterministic local kernel retains authority."""

from __future__ import annotations

import hashlib
from typing import Any, Dict

from .strict_canonical import code_point_key
from .tool_pinning import _canonical_json_for_hash

SIGNAL_DECLARATION_V1_SCHEMA = "obsvr-signal-declaration-v1"
SIGNAL_OBSERVATION_V1_SCHEMA = "obsvr-signal-observation-v1"
SIGNAL_RESOLUTION_V1_SCHEMA = "obsvr-signal-resolution-v1"
_HEX = frozenset("0123456789abcdef")


class SignalInterfaceV1ValidationError(ValueError):
    pass


def _fail(message: str) -> None:
    raise SignalInterfaceV1ValidationError(message)


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip().encode()) > 256:
        _fail(f"{field} must be nonblank and at most 256 UTF-8 bytes")
    return value.strip()


def _hash(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in _HEX for c in value):
        _fail(f"{field} must be a lowercase SHA-256 hash")
    return value


def _integer(value: Any, field: str, maximum: int = 9_007_199_254_740_991) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        _fail(f"{field} must be a nonnegative safe integer no greater than {maximum}")
    return value


def build_signal_declaration_v1(input_value: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(input_value, dict):
        _fail("declaration must be an object")
    unknown = sorted(set(input_value) - {"schema", "signal_id", "version", "determinism", "locality", "timeout_ms", "cache_ttl_ms", "failure_disposition"}, key=code_point_key)
    if unknown:
        _fail(f"declaration contains unsupported field: {unknown[0]}")
    if "schema" in input_value and input_value["schema"] != SIGNAL_DECLARATION_V1_SCHEMA:
        _fail("declaration schema is invalid")
    if input_value.get("determinism") not in {"deterministic", "probabilistic"} or input_value.get("locality") not in {"local", "remote"} or input_value.get("failure_disposition") not in {"deny", "defer", "ignore"}:
        _fail("declaration enum is invalid")
    timeout = _integer(input_value.get("timeout_ms"), "timeout_ms", 300_000)
    if timeout == 0:
        _fail("timeout_ms must be greater than zero")
    return {"schema": SIGNAL_DECLARATION_V1_SCHEMA, "signal_id": _text(input_value.get("signal_id"), "signal_id"), "version": _text(input_value.get("version"), "version"), "determinism": input_value["determinism"], "locality": input_value["locality"], "timeout_ms": timeout, "cache_ttl_ms": _integer(input_value.get("cache_ttl_ms"), "cache_ttl_ms", 86_400_000), "failure_disposition": input_value["failure_disposition"], "authoritative_allow": False}


def build_signal_observation_v1(input_value: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(input_value, dict):
        _fail("observation must be an object")
    unknown = sorted(set(input_value) - {"schema", "signal_id", "version", "input_hash", "status", "labels", "score_bps", "provenance_hash", "evaluated_at_ms", "latency_ms", "cache_state"}, key=code_point_key)
    if unknown:
        _fail(f"observation contains unsupported field: {unknown[0]}")
    if "schema" in input_value and input_value["schema"] != SIGNAL_OBSERVATION_V1_SCHEMA:
        _fail("observation schema is invalid")
    if input_value.get("status") not in {"matched", "not_matched", "error", "timeout"} or input_value.get("cache_state") not in {"hit", "miss", "not_cacheable"}:
        _fail("observation enum is invalid")
    raw_labels = input_value.get("labels")
    if not isinstance(raw_labels, list) or len(raw_labels) > 128:
        _fail("labels must contain at most 128 items")
    result = {"schema": SIGNAL_OBSERVATION_V1_SCHEMA, "signal_id": _text(input_value.get("signal_id"), "signal_id"), "version": _text(input_value.get("version"), "version"), "input_hash": _hash(input_value.get("input_hash"), "input_hash"), "status": input_value["status"], "labels": sorted({_text(item, f"labels[{i}]") for i, item in enumerate(raw_labels)}, key=code_point_key), "provenance_hash": _hash(input_value.get("provenance_hash"), "provenance_hash"), "evaluated_at_ms": _integer(input_value.get("evaluated_at_ms"), "evaluated_at_ms"), "latency_ms": _integer(input_value.get("latency_ms"), "latency_ms"), "cache_state": input_value["cache_state"]}
    if "score_bps" in input_value:
        result["score_bps"] = _integer(input_value["score_bps"], "score_bps", 10_000)
    return result


def resolve_signal_v1(declaration_input: Dict[str, Any], observation_input: Dict[str, Any]) -> Dict[str, Any]:
    declaration = build_signal_declaration_v1(declaration_input)
    observation = build_signal_observation_v1(observation_input)
    if declaration["signal_id"] != observation["signal_id"] or declaration["version"] != observation["version"]:
        _fail("observation does not match declaration")
    failure = observation["status"] in {"error", "timeout"}
    required = declaration["failure_disposition"].upper() if failure and declaration["failure_disposition"] != "ignore" else None
    fact = {"matched": observation["status"] == "matched", "labels": observation["labels"]}
    if "score_bps" in observation:
        fact["score_bps"] = observation["score_bps"]
    body = {"schema": SIGNAL_RESOLUTION_V1_SCHEMA, "declaration": declaration, "observation": observation, "fact": fact, "required_outcome": required, "authoritative_allow": False}
    body["resolution_hash"] = hashlib.sha256(f"obsvr-signal-resolution/1\0{_canonical_json_for_hash(body)}".encode()).hexdigest()
    return body


def signal_resolution_to_otel_attributes_v1(resolution: Dict[str, Any]) -> Dict[str, Any]:
    return {"obsvr.signal.schema": resolution["schema"], "obsvr.signal.id": resolution["declaration"]["signal_id"], "obsvr.signal.version": resolution["declaration"]["version"], "obsvr.signal.determinism": resolution["declaration"]["determinism"], "obsvr.signal.locality": resolution["declaration"]["locality"], "obsvr.signal.status": resolution["observation"]["status"], "obsvr.signal.provenance_hash": resolution["observation"]["provenance_hash"], "obsvr.signal.resolution_hash": resolution["resolution_hash"], "obsvr.signal.latency_ms": resolution["observation"]["latency_ms"], "obsvr.signal.authoritative_allow": False}


def signal_resolution_to_opa_input_v1(resolution: Dict[str, Any]) -> Dict[str, Any]:
    return {"obsvr_signal": {"id": resolution["declaration"]["signal_id"], "version": resolution["declaration"]["version"], "matched": resolution["fact"]["matched"], "labels": resolution["fact"]["labels"], "score_bps": resolution["fact"].get("score_bps"), "provenance_hash": resolution["observation"]["provenance_hash"], "required_outcome": resolution["required_outcome"], "authoritative_allow": False, "resolution_hash": resolution["resolution_hash"]}}


def signal_resolution_to_cedar_context_v1(resolution: Dict[str, Any]) -> Dict[str, Any]:
    return {"obsvrSignalId": resolution["declaration"]["signal_id"], "obsvrSignalVersion": resolution["declaration"]["version"], "obsvrSignalMatched": resolution["fact"]["matched"], "obsvrSignalLabels": resolution["fact"]["labels"], "obsvrSignalScoreBps": resolution["fact"].get("score_bps", 0), "obsvrSignalProvenanceHash": resolution["observation"]["provenance_hash"], "obsvrSignalRequiredOutcome": resolution["required_outcome"] or "", "obsvrSignalAuthoritativeAllow": False, "obsvrSignalResolutionHash": resolution["resolution_hash"]}
