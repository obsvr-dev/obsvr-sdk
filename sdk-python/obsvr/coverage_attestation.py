"""Signed, bounded deployment coverage statements.

The attestation proves what the process reported as bound. It never claims to
discover calls outside the process or handles that bypassed every obsvr hook.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Iterable, List, Optional

from .binding_report import integration_bindings
from .device_identity import (
    DeviceSigner,
    derive_device_key_id,
    verify_device_sig,
)
from .tool_pinning import _canonical_json_for_hash

COVERAGE_ATTESTATION_SCHEMA = "obsvr-coverage-attestation-v1"
COVERAGE_ATTESTATION_ENVELOPE_SCHEMA = "obsvr-coverage-attestation-envelope-v1"
COVERAGE_ATTESTATION_DOMAIN = "obsvr-coverage-attestation/1"

_MAX_ITEMS = 256
_MAX_TEXT_BYTES = 256
_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_HEX = frozenset("0123456789abcdef")
_DEPTH_RANK = {"unknown": 0, "observe": 1, "enforce": 2}
_BODY_FIELDS = {
    "schema",
    "attestation_id",
    "workload_id",
    "environment",
    "sdk_language",
    "sdk_version",
    "generated_at_ms",
    "valid_until_ms",
    "required",
    "bindings",
    "policy_pack_hashes",
    "coverage_complete",
    "failures",
}


class CoverageAttestationValidationError(ValueError):
    """The value cannot produce one canonical coverage attestation."""


class CoverageRequirementsError(RuntimeError):
    """The current process does not meet its exact coverage contract."""

    def __init__(self, failures: List[Dict[str, Any]]) -> None:
        self.failures = [dict(failure) for failure in failures]
        summary = ", ".join(
            f"{failure['integration']}:{failure['symbol'] or '*'} "
            f"{failure['reason']} (required {failure['required_depth']}, "
            f"actual {failure['actual_depth']})"
            for failure in failures
        )
        super().__init__(f"Required obsvr coverage is not active: {summary}")


def _fail(message: str) -> None:
    raise CoverageAttestationValidationError(message)


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _fail(f"{field} must be nonblank")
    normalized = value.strip()
    if len(normalized.encode("utf-8")) > _MAX_TEXT_BYTES:
        _fail(f"{field} exceeds {_MAX_TEXT_BYTES} UTF-8 bytes")
    return normalized


def _integer(value: Any, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > _MAX_SAFE_INTEGER
    ):
        _fail(f"{field} must be a nonnegative safe integer")
    return value


def _unique_texts(values: Any, field: str) -> List[str]:
    if not isinstance(values, list) or len(values) > _MAX_ITEMS:
        _fail(f"{field} must be an array with at most {_MAX_ITEMS} items")
    return sorted(
        {_text(value, f"{field}[{index}]") for index, value in enumerate(values)},
        key=lambda value: tuple(ord(char) for char in value),
    )


def _hashes(values: Any, field: str) -> List[str]:
    items = _unique_texts(values, field)
    if any(len(item) != 64 or any(char not in _HEX for char in item) for item in items):
        _fail(f"{field} contains an invalid hash")
    return items


def _requirements(values: Any) -> List[Dict[str, Any]]:
    if not isinstance(values, list) or len(values) > _MAX_ITEMS:
        _fail(f"required must be an array with at most {_MAX_ITEMS} items")
    requirements = []
    for index, candidate in enumerate(values):
        if not isinstance(candidate, dict):
            _fail(f"required[{index}] must be an object")
        unknown = sorted(set(candidate) - {"integration", "minimum_depth", "symbols"})
        if unknown:
            _fail(f"required[{index}] contains unsupported field: {unknown[0]}")
        depth = candidate.get("minimum_depth")
        if depth not in {"observe", "enforce"}:
            _fail(f"required[{index}].minimum_depth is invalid")
        requirements.append(
            {
                "integration": _text(
                    candidate.get("integration"), f"required[{index}].integration"
                ),
                "minimum_depth": depth,
                "symbols": _unique_texts(
                    candidate.get("symbols", []), f"required[{index}].symbols"
                ),
            }
        )
    requirements.sort(
        key=lambda item: tuple(
            ord(char)
            for char in (
                f"{item['integration']}\x00{item['minimum_depth']}\x00"
                + "\x00".join(item["symbols"])
            )
        )
    )
    keys = [_canonical_json_for_hash(item) for item in requirements]
    if len(keys) != len(set(keys)):
        _fail("required contains duplicate requirements")
    return requirements


def _binding(integration: str, symbol: str, entry: Dict[str, Any]) -> Dict[str, Any]:
    depth = entry.get("enforcement_depth", "unknown")
    if depth not in _DEPTH_RANK:
        depth = "unknown"
    binding = {
        "integration": _text(integration, "binding.integration"),
        "symbol": _text(symbol, "binding.symbol"),
        "bound": entry.get("bound") is True,
        "enforcement_depth": depth,
        "exclusions": _unique_texts(entry.get("exclusions", []), "binding.exclusions"),
    }
    if "integration_version" in entry:
        binding["integration_version"] = _text(
            entry["integration_version"], "binding.integration_version"
        )
    if "initialized_at_ms" in entry:
        binding["initialized_at_ms"] = _integer(
            entry["initialized_at_ms"], "binding.initialized_at_ms"
        )
    if "error_type" in entry:
        binding["error_type"] = _text(entry["error_type"], "binding.error_type")
    if "error" in entry:
        binding["error"] = _text(entry["error"], "binding.error")
    return binding


def _flatten_bindings(snapshot: Dict[str, Dict[str, Dict[str, Any]]]) -> List[Dict[str, Any]]:
    flattened = [
        _binding(integration, symbol, entry)
        for integration, symbols in snapshot.items()
        for symbol, entry in symbols.items()
    ]
    if len(flattened) > _MAX_ITEMS:
        _fail(f"bindings exceeds {_MAX_ITEMS} items")
    return sorted(
        flattened,
        key=lambda item: tuple(
            ord(char) for char in f"{item['integration']}\x00{item['symbol']}"
        ),
    )


def _coverage_failures(
    required: Iterable[Dict[str, Any]], bindings: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    failures = []
    for requirement in required:
        candidates = [
            binding
            for binding in bindings
            if binding["integration"] == requirement["integration"]
            and (
                not requirement["symbols"]
                or binding["symbol"] in requirement["symbols"]
            )
        ]
        symbols = requirement["symbols"] or sorted(
            {binding["symbol"] for binding in candidates}
        ) or [""]
        for symbol in symbols:
            binding = next(
                (candidate for candidate in candidates if candidate["symbol"] == symbol),
                None,
            )
            if binding is None:
                reason, actual = "missing", "missing"
            elif not binding["bound"]:
                reason, actual = "unbound", binding["enforcement_depth"]
            elif _DEPTH_RANK[binding["enforcement_depth"]] < _DEPTH_RANK[
                requirement["minimum_depth"]
            ]:
                reason, actual = "insufficient_depth", binding["enforcement_depth"]
            else:
                continue
            failures.append(
                {
                    "integration": requirement["integration"],
                    "symbol": symbol,
                    "reason": reason,
                    "required_depth": requirement["minimum_depth"],
                    "actual_depth": actual,
                }
            )
    return sorted(
        failures,
        key=lambda item: tuple(
            ord(char)
            for char in f"{item['integration']}\x00{item['symbol']}\x00{item['reason']}"
        ),
    )


def coverage_requirement_failures(
    required: List[Dict[str, Any]],
    snapshot: Optional[Dict[str, Dict[str, Dict[str, Any]]]] = None,
) -> List[Dict[str, Any]]:
    """Resolve exact symbol/depth requirements against current bindings."""
    normalized = _requirements(required)
    bindings = _flatten_bindings(
        snapshot if snapshot is not None else integration_bindings()
    )
    return _coverage_failures(normalized, bindings)


def assert_coverage_requirements(
    required: List[Dict[str, Any]],
    snapshot: Optional[Dict[str, Dict[str, Dict[str, Any]]]] = None,
) -> None:
    """Refuse startup when a path is absent, unbound, or too shallow."""
    failures = coverage_requirement_failures(required, snapshot)
    if failures:
        raise CoverageRequirementsError(failures)


def build_coverage_attestation_body(
    input_value: Dict[str, Any],
    snapshot: Optional[Dict[str, Dict[str, Dict[str, Any]]]] = None,
) -> Dict[str, Any]:
    generated_at = _integer(input_value.get("generated_at_ms"), "generated_at_ms")
    valid_until = _integer(input_value.get("valid_until_ms"), "valid_until_ms")
    if valid_until <= generated_at:
        _fail("valid_until_ms must be after generated_at_ms")
    language = input_value.get("sdk_language")
    if language not in {"typescript", "python"}:
        _fail("sdk_language is invalid")
    required = _requirements(input_value.get("required"))
    bindings = _flatten_bindings(snapshot if snapshot is not None else integration_bindings())
    failures = _coverage_failures(required, bindings)
    return {
        "schema": COVERAGE_ATTESTATION_SCHEMA,
        "attestation_id": _text(input_value.get("attestation_id"), "attestation_id"),
        "workload_id": _text(input_value.get("workload_id"), "workload_id"),
        "environment": _text(input_value.get("environment"), "environment"),
        "sdk_language": language,
        "sdk_version": _text(input_value.get("sdk_version"), "sdk_version"),
        "generated_at_ms": generated_at,
        "valid_until_ms": valid_until,
        "required": required,
        "bindings": bindings,
        "policy_pack_hashes": _hashes(
            input_value.get("policy_pack_hashes"), "policy_pack_hashes"
        ),
        "coverage_complete": not failures,
        "failures": failures,
    }


def canonicalize_coverage_attestation_body(body: Dict[str, Any]) -> str:
    if not isinstance(body, dict):
        _fail("body must be an object")
    if set(body) != _BODY_FIELDS:
        _fail("body fields do not match the coverage attestation schema")
    if body.get("schema") != COVERAGE_ATTESTATION_SCHEMA:
        _fail("body schema is invalid")
    snapshot: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for binding in body.get("bindings", []):
        entry = {
            "bound": binding.get("bound") is True,
            "enforcement_depth": binding.get("enforcement_depth", "unknown"),
            "exclusions": binding.get("exclusions", []),
        }
        for source, destination in (
            ("integration_version", "integration_version"),
            ("initialized_at_ms", "initialized_at_ms"),
            ("error_type", "error_type"),
            ("error", "error"),
        ):
            if source in binding:
                entry[destination] = binding[source]
        snapshot.setdefault(binding.get("integration"), {})[
            binding.get("symbol")
        ] = entry
    rebuilt = build_coverage_attestation_body(body, snapshot)
    if _canonical_json_for_hash(body) != _canonical_json_for_hash(rebuilt):
        _fail("body contains noncanonical or inconsistent derived fields")
    return _canonical_json_for_hash(rebuilt)


def coverage_attestation_body_hash(body: Dict[str, Any]) -> str:
    return hashlib.sha256(
        canonicalize_coverage_attestation_body(body).encode("utf-8")
    ).hexdigest()


def _signature_payload(body: Dict[str, Any]) -> str:
    return (
        COVERAGE_ATTESTATION_DOMAIN
        + "\x00"
        + canonicalize_coverage_attestation_body(body)
    )


def sign_coverage_attestation(
    input_value: Dict[str, Any],
    signer: DeviceSigner,
    snapshot: Optional[Dict[str, Dict[str, Dict[str, Any]]]] = None,
) -> Dict[str, Any]:
    body = build_coverage_attestation_body(input_value, snapshot)
    return {
        "schema": COVERAGE_ATTESTATION_ENVELOPE_SCHEMA,
        "body": body,
        "body_hash": coverage_attestation_body_hash(body),
        "key_id": signer.key_id,
        "signature": signer.sign_payload(_signature_payload(body)),
    }


def verify_coverage_attestation(
    envelope: Dict[str, Any], raw_public_key: bytes
) -> Dict[str, Any]:
    try:
        if envelope.get("schema") != COVERAGE_ATTESTATION_ENVELOPE_SCHEMA:
            raise ValueError
        body_hash = coverage_attestation_body_hash(envelope["body"])
    except Exception:
        return {"valid": False, "reason": "invalid_body"}
    if body_hash != envelope.get("body_hash"):
        return {
            "valid": False,
            "reason": "body_hash_mismatch",
            "body_hash": body_hash,
        }
    if derive_device_key_id(raw_public_key) != envelope.get("key_id"):
        return {"valid": False, "reason": "foreign_key", "body_hash": body_hash}
    verified = verify_device_sig(
        raw_public_key,
        envelope["key_id"],
        _signature_payload(envelope["body"]),
        envelope.get("signature"),
    )
    if verified is not True:
        return {
            "valid": False,
            "reason": "verification_unavailable" if verified is None else "invalid_signature",
            "body_hash": body_hash,
        }
    return {"valid": True, "reason": "valid", "body_hash": body_hash}


__all__ = [
    "COVERAGE_ATTESTATION_SCHEMA",
    "COVERAGE_ATTESTATION_ENVELOPE_SCHEMA",
    "CoverageAttestationValidationError",
    "build_coverage_attestation_body",
    "canonicalize_coverage_attestation_body",
    "coverage_attestation_body_hash",
    "sign_coverage_attestation",
    "verify_coverage_attestation",
]
