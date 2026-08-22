import copy

import pytest

from obsvr.strict_evaluation_evidence_v2_1 import (
    STRICT_EVALUATOR_MANIFEST_HASH_V2_1,
    build_strict_evaluation_evidence_v2_1,
    create_trusted_evaluation_evidence_provider_v2_1,
)

A, B, C, D, E, F = (char * 64 for char in "abcdef")


def snapshot():
    return {
        "effective_policy": {
            "version": "policy-7",
            "artifact_hash": A,
            "matched_rule_ids": ["rule-z", "rule-a", "rule-a"],
        },
        "detector_requirements": [
            {
                "detector_id": "redactor",
                "detector_manifest_hash": C,
                "required": True,
                "purpose": "transform",
            },
            {
                "detector_id": "telemetry",
                "detector_manifest_hash": D,
                "required": False,
                "purpose": "evaluation",
            },
            {
                "detector_id": "pii",
                "detector_manifest_hash": B,
                "required": True,
                "purpose": "evaluation",
            },
        ],
        "detector_results": [
            {
                "detector_id": "telemetry",
                "status": "degraded",
                "failure_code": "optional_timeout",
            },
            {"detector_id": "redactor", "status": "ok", "result_hash": F},
            {"detector_id": "pii", "status": "ok", "result_hash": E},
        ],
    }


def build(value, outcome="ALLOW"):
    provider = create_trusted_evaluation_evidence_provider_v2_1(lambda: value)
    return build_strict_evaluation_evidence_v2_1(provider, outcome)


def test_exact_normalization_and_cross_language_hashes():
    result = build(snapshot())
    assert STRICT_EVALUATOR_MANIFEST_HASH_V2_1 == (
        "5e70e3fb6281921e614504b9dbcb41c8ca077698c525cd40b42d7bdb952689f7"
    )
    assert result["evidence_hash"] == (
        "ac433f5ae1d44147070d99b3f0ec3dda5aa113c5637e2248b750e9d3755f66f4"
    )
    evidence = result["evidence"]
    assert evidence["effective_policy"] == {
        "version": "policy-7",
        "artifact_hash": A,
        "matched_rule_ids": ["rule-a", "rule-z"],
    }
    assert evidence["detector_set_hash"] == (
        "74af29dbdae32a036e61000187726dc546520f795aebece4aedc0de22716be0c"
    )
    assert [item["detector_id"] for item in evidence["detectors"]] == [
        "pii",
        "redactor",
        "telemetry",
    ]
    assert evidence["outcome"] == "ALLOW"


def test_evaluator_manifest_is_invariant_across_policy_changes():
    first = build(snapshot())
    changed = snapshot()
    changed["effective_policy"] = {
        "version": "policy-8",
        "artifact_hash": B,
        "matched_rule_ids": ["rule-b"],
    }
    second = build(changed)
    assert (
        second["evidence"]["evaluator_manifest_hash"]
        == first["evidence"]["evaluator_manifest_hash"]
    )
    assert second["evidence"]["effective_policy"] == changed["effective_policy"]
    assert second["evidence_hash"] != first["evidence_hash"]
    forged = snapshot()
    forged["effective_policy"]["matched_rule_ids"] = ["rule@forged"]
    with pytest.raises(ValueError, match="ASCII identifier"):
        build(forged)


def test_required_detector_outages_fail_closed():
    evaluation = snapshot()
    evaluation["detector_results"][2] = {
        "detector_id": "pii",
        "status": "unavailable",
        "failure_code": "detector_timeout",
    }
    assert build(evaluation)["evidence"]["outcome"] == "DEFER"
    missing = snapshot()
    missing["detector_results"] = [
        item for item in missing["detector_results"] if item["detector_id"] != "pii"
    ]
    deferred = build(missing)["evidence"]
    assert (deferred["outcome"], deferred["reason_code"]) == (
        "DEFER",
        "required_detector_uncertain",
    )
    assert deferred["detectors"][0]["failure_code"] == "detector_missing"
    transform = snapshot()
    transform["detector_results"][1] = {
        "detector_id": "redactor",
        "status": "degraded",
        "failure_code": "transform_failed",
    }
    denied = build(transform, "MODIFY")["evidence"]
    assert (denied["outcome"], denied["reason_code"]) == (
        "DENY",
        "required_transform_unavailable",
    )


def test_capability_exact_keys_duplicates_errors_and_caps():
    class Forged:
        capture = staticmethod(snapshot)

    with pytest.raises(ValueError, match="trusted evidence provider"):
        build_strict_evaluation_evidence_v2_1(Forged(), "ALLOW")
    provider = create_trusted_evaluation_evidence_provider_v2_1(
        lambda: (_ for _ in ()).throw(RuntimeError("secret"))
    )
    with pytest.raises(ValueError, match="trusted evidence capture failed"):
        build_strict_evaluation_evidence_v2_1(provider, "ALLOW")
    duplicate = snapshot()
    duplicate["detector_results"].append(
        copy.deepcopy(duplicate["detector_results"][0])
    )
    with pytest.raises(ValueError, match="duplicate detector result"):
        build(duplicate)
    duplicate_requirement = snapshot()
    duplicate_requirement["detector_requirements"].append(
        copy.deepcopy(duplicate_requirement["detector_requirements"][0])
    )
    with pytest.raises(ValueError, match="duplicate detector requirement"):
        build(duplicate_requirement)
    raw = snapshot()
    raw["detector_results"][0]["raw_error"] = "secret"
    with pytest.raises(ValueError, match="unknown or missing keys"):
        build(raw)
    over = snapshot()
    over["effective_policy"]["matched_rule_ids"] = [f"r{index}" for index in range(129)]
    with pytest.raises(ValueError, match="bounded"):
        build(over)
    detector_cap = snapshot()
    detector_cap["detector_requirements"] = [
        {
            "detector_id": f"d{index}",
            "detector_manifest_hash": B,
            "required": False,
            "purpose": "evaluation",
        }
        for index in range(65)
    ]
    with pytest.raises(ValueError, match="detector_requirements must be bounded"):
        build(detector_cap)
    bad = snapshot()
    bad["detector_requirements"][0]["detector_id"] = "bad@id"
    with pytest.raises(ValueError, match="ASCII identifier"):
        build(bad)
