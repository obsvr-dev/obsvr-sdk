"""Deterministic trusted evaluation evidence for strict profile 2.1."""

import hashlib
import struct
import weakref
from typing import Any, Callable, Dict

from .tool_pinning import _canonical_json_for_hash

STRICT_EVALUATION_EVIDENCE_V2_1_SCHEMA = "obsvr-strict-evaluation-evidence-v2-1"
_DETECTOR_SET_SCHEMA = "obsvr-strict-detector-set-v2-1"
_OUTCOMES = frozenset(("ALLOW", "DENY", "MODIFY", "STEP_UP", "DEFER"))
_MAX_DETECTORS = 64
_MAX_RULES = 128
_PROVIDERS: weakref.WeakSet[Any] = weakref.WeakSet()
_MANIFEST = {
    "schema": "obsvr-strict-evaluator-manifest-v2-1",
    "profile_version": "2.1",
    "engine": "obsvr-strict-evaluation",
    "semantics_version": "1",
}


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _domain_hash(domain: str, canonical: str) -> str:
    body = canonical.encode("utf-8")
    preimage = domain.encode("ascii") + b"\x00" + struct.pack(">Q", len(body)) + body
    return hashlib.sha256(preimage).hexdigest()


STRICT_EVALUATOR_MANIFEST_HASH_V2_1 = _sha(_canonical_json_for_hash(_MANIFEST))


class StrictEvaluationEvidenceV21Error(ValueError):
    """Trusted evaluation evidence is malformed or incomplete."""


class _TrustedProvider:
    def __init__(self, capture: Callable[[], Dict[str, Any]]) -> None:
        self.capture = capture


def _exact(value: Any, keys, field: str) -> Dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(keys):
        raise StrictEvaluationEvidenceV21Error(f"{field} has unknown or missing keys")
    return value


def _identifier(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 64
        or not value[0].isalnum()
        or not value.isascii()
        or any(not (char.isalnum() or char in "._:-") for char in value)
    ):
        raise StrictEvaluationEvidenceV21Error(
            f"{field} must be a bounded ASCII identifier"
        )
    return value


def _hash(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise StrictEvaluationEvidenceV21Error(f"{field} must be lowercase SHA-256")
    return value


def _failure(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 64
        or not value[0].islower()
        or not value.isascii()
        or any(not (char.islower() or char.isdigit() or char == "_") for char in value)
    ):
        raise StrictEvaluationEvidenceV21Error("invalid detector failure_code")
    return value


def _policy(value: Any) -> Dict[str, Any]:
    item = _exact(value, ("version", "artifact_hash", "matched_rule_ids"), "policy")
    rules = item["matched_rule_ids"]
    if not isinstance(rules, list) or len(rules) > _MAX_RULES:
        raise StrictEvaluationEvidenceV21Error("matched_rule_ids must be bounded")
    return {
        "version": _identifier(item["version"], "policy.version"),
        "artifact_hash": _hash(item["artifact_hash"], "policy.artifact_hash"),
        "matched_rule_ids": sorted(
            set(_identifier(rule, "matched_rule_ids") for rule in rules)
        ),
    }


def _requirements(value: Any):
    if not isinstance(value, list) or len(value) > _MAX_DETECTORS:
        raise StrictEvaluationEvidenceV21Error("detector_requirements must be bounded")
    found = set()
    output = []
    for raw in value:
        item = _exact(
            raw,
            ("detector_id", "detector_manifest_hash", "required", "purpose"),
            "requirement",
        )
        detector_id = _identifier(item["detector_id"], "detector_id")
        if detector_id in found:
            raise StrictEvaluationEvidenceV21Error("duplicate detector requirement")
        found.add(detector_id)
        if type(item["required"]) is not bool or item["purpose"] not in (
            "evaluation",
            "transform",
        ):
            raise StrictEvaluationEvidenceV21Error("invalid detector requirement")
        output.append(
            {
                "detector_id": detector_id,
                "detector_manifest_hash": _hash(
                    item["detector_manifest_hash"], "detector_manifest_hash"
                ),
                "required": item["required"],
                "purpose": item["purpose"],
            }
        )
    return sorted(output, key=lambda item: item["detector_id"])


def _results(value: Any, declared):
    if not isinstance(value, list) or len(value) > _MAX_DETECTORS:
        raise StrictEvaluationEvidenceV21Error("detector_results must be bounded")
    allowed = {item["detector_id"] for item in declared}
    output = {}
    for raw in value:
        if not isinstance(raw, dict):
            raise StrictEvaluationEvidenceV21Error("detector result must be an object")
        status = raw.get("status")
        keys = (
            ("detector_id", "status", "result_hash")
            if status == "ok"
            else ("detector_id", "status", "failure_code")
        )
        item = _exact(raw, keys, "detector_result")
        detector_id = _identifier(item["detector_id"], "detector_id")
        if detector_id not in allowed or detector_id in output:
            raise StrictEvaluationEvidenceV21Error(
                "unknown or duplicate detector result"
            )
        if status not in ("ok", "unavailable", "degraded"):
            raise StrictEvaluationEvidenceV21Error("invalid detector status")
        output[detector_id] = {
            "detector_id": detector_id,
            "status": status,
            **(
                {"result_hash": _hash(item["result_hash"], "result_hash")}
                if status == "ok"
                else {"failure_code": _failure(item["failure_code"])}
            ),
        }
    return output


def create_trusted_evaluation_evidence_provider_v2_1(capture):
    if not callable(capture):
        raise StrictEvaluationEvidenceV21Error("trusted provider must be callable")
    provider = _TrustedProvider(capture)
    _PROVIDERS.add(provider)
    return provider


def build_strict_evaluation_evidence_v2_1(provider, requested_outcome: str):
    if not isinstance(provider, _TrustedProvider) or provider not in _PROVIDERS:
        raise StrictEvaluationEvidenceV21Error("trusted evidence provider is required")
    if requested_outcome not in _OUTCOMES:
        raise StrictEvaluationEvidenceV21Error("unsupported requested outcome")
    try:
        captured = provider.capture()
    except Exception:
        raise StrictEvaluationEvidenceV21Error(
            "trusted evidence capture failed"
        ) from None
    snapshot = _exact(
        captured,
        ("effective_policy", "detector_requirements", "detector_results"),
        "snapshot",
    )
    policy = _policy(snapshot["effective_policy"])
    declared = _requirements(snapshot["detector_requirements"])
    actual = _results(snapshot["detector_results"], declared)
    detectors = []
    for requirement in declared:
        record = actual.get(
            requirement["detector_id"],
            {
                "detector_id": requirement["detector_id"],
                "status": "unavailable",
                "failure_code": "detector_missing",
            },
        )
        detectors.append(
            {
                **requirement,
                "status": record["status"],
                **(
                    {"result_hash": record["result_hash"]}
                    if record["status"] == "ok"
                    else {"failure_code": record["failure_code"]}
                ),
            }
        )
    unhealthy = [
        item for item in detectors if item["required"] and item["status"] != "ok"
    ]
    outcome = requested_outcome
    reason_code = "evaluation_complete"
    if requested_outcome in ("ALLOW", "MODIFY") and any(
        item["purpose"] == "transform" for item in unhealthy
    ):
        outcome, reason_code = "DENY", "required_transform_unavailable"
    elif requested_outcome in ("ALLOW", "MODIFY") and unhealthy:
        outcome, reason_code = "DEFER", "required_detector_uncertain"
    detector_set_hash = _domain_hash(
        "obsvr-strict-detector-set/2.1",
        _canonical_json_for_hash(
            {"schema": _DETECTOR_SET_SCHEMA, "detectors": detectors}
        ),
    )
    evidence = {
        "schema": STRICT_EVALUATION_EVIDENCE_V2_1_SCHEMA,
        "profile_version": "2.1",
        "effective_policy": policy,
        "evaluator_manifest_hash": STRICT_EVALUATOR_MANIFEST_HASH_V2_1,
        "detectors": detectors,
        "detector_set_hash": detector_set_hash,
        "requested_outcome": requested_outcome,
        "outcome": outcome,
        "reason_code": reason_code,
    }
    return {
        "evidence": evidence,
        "evidence_hash": _domain_hash(
            "obsvr-strict-evaluation-evidence/2.1",
            _canonical_json_for_hash(evidence),
        ),
    }
