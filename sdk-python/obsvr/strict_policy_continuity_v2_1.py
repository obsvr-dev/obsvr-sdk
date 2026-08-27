"""Reconstruct trusted policy snapshots across a strict 2.1 receipt chain."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Sequence

from .strict_receipt_v2_1_verify import verify_strict_receipt_v2_1_chain
from .tool_pinning import _canonical_json_for_hash

STRICT_POLICY_CONTINUITY_V2_1_SCHEMA = "obsvr-strict-policy-continuity-v2-1"


class StrictPolicyContinuityV21Error(ValueError):
    """Policy continuity cannot be derived from an invalid or untrusted chain."""

    def __init__(self, errors: List[str]) -> None:
        self.errors = errors
        super().__init__(
            "strict policy continuity requires a valid trusted chain: "
            + ", ".join(errors)
        )


def _snapshot(receipt: Dict[str, Any]) -> Dict[str, Any]:
    body = receipt["body"]
    evaluation = body["evaluation"]
    policy = evaluation["effective_policy"]
    return {
        "sequence": body["sequence"],
        "receipt_hash": receipt["receipt_hash"],
        "record_type": body["record_type"],
        "policy_version": policy["version"],
        "policy_artifact_hash": policy["artifact_hash"],
        "evaluator_manifest_hash": evaluation["evaluator_manifest_hash"],
        "matched_rule_ids": list(policy["matched_rule_ids"]),
    }


def _changed(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    return any(
        left[field] != right[field]
        for field in (
            "policy_version",
            "policy_artifact_hash",
            "evaluator_manifest_hash",
        )
    )


def reconstruct_strict_policy_continuity_v2_1(
    receipts: List[Dict[str, Any]],
    *,
    trusted_agent_keys: Sequence[Dict[str, Any]],
    allowed_evaluator_manifest_hashes: Sequence[str],
) -> Dict[str, Any]:
    verification = verify_strict_receipt_v2_1_chain(
        receipts,
        trusted_agent_keys=trusted_agent_keys,
        allowed_evaluator_manifest_hashes=allowed_evaluator_manifest_hashes,
    )
    if not verification["valid"]:
        raise StrictPolicyContinuityV21Error(verification["errors"])
    snapshots = [_snapshot(receipt) for receipt in receipts]
    transitions = []
    for before, after in zip(snapshots, snapshots[1:]):
        if not _changed(before, after):
            continue
        transitions.append(
            {
                "at_sequence": after["sequence"],
                "receipt_hash": after["receipt_hash"],
                "from_policy_version": before["policy_version"],
                "from_policy_artifact_hash": before["policy_artifact_hash"],
                "from_evaluator_manifest_hash": before["evaluator_manifest_hash"],
                "to_policy_version": after["policy_version"],
                "to_policy_artifact_hash": after["policy_artifact_hash"],
                "to_evaluator_manifest_hash": after["evaluator_manifest_hash"],
            }
        )
    document = {
        "schema": STRICT_POLICY_CONTINUITY_V2_1_SCHEMA,
        "profile_version": "2.1",
        "tenant_id": receipts[0]["body"]["tenant_id"],
        "session_id": receipts[0]["body"]["session_id"],
        "first_sequence": snapshots[0]["sequence"],
        "last_sequence": snapshots[-1]["sequence"],
        "receipt_count": len(snapshots),
        "snapshots": snapshots,
        "transitions": transitions,
    }
    return {
        **document,
        "timeline_hash": hashlib.sha256(
            _canonical_json_for_hash(document).encode("utf-8")
        ).hexdigest(),
    }


__all__ = [
    "STRICT_POLICY_CONTINUITY_V2_1_SCHEMA",
    "StrictPolicyContinuityV21Error",
    "reconstruct_strict_policy_continuity_v2_1",
]
