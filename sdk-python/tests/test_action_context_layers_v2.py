import copy
import json
from pathlib import Path

import pytest

from obsvr.action_context_v2 import (
    ActionContextV2ValidationError,
    action_context_v2_hash,
    build_action_context_v2,
    canonicalize_action_context_v2,
)


FIXTURE = json.loads(
    (
        Path(__file__).parents[2]
        / "conformance"
        / "fixtures"
        / "action_context_layers_v2.json"
    ).read_text()
)


def test_pins_bounded_identity_execution_and_governance_layers():
    assert FIXTURE["claimable"] is False
    assert build_action_context_v2(FIXTURE["input"]) == FIXTURE["expect"]["document"]
    assert canonicalize_action_context_v2(FIXTURE["input"]) == FIXTURE["expect"][
        "canonical"
    ]
    assert action_context_v2_hash(FIXTURE["input"]) == FIXTURE["expect"]["hash"]


def test_raw_targets_and_arbitrary_payload_fields_stay_out():
    assert "tenant/acme/contract/42" not in canonicalize_action_context_v2(
        FIXTURE["input"]
    )
    unknown = copy.deepcopy(FIXTURE["input"])
    unknown["governance"]["raw_prompt"] = "do not store this"
    with pytest.raises(ActionContextV2ValidationError):
        build_action_context_v2(unknown)


def test_rejects_unknown_enums_and_malformed_evidence_hashes():
    enum_value = copy.deepcopy(FIXTURE["input"])
    enum_value["execution"]["autonomy_level"] = "unbounded"
    with pytest.raises(
        ActionContextV2ValidationError,
        match="execution.autonomy_level is unsupported",
    ):
        build_action_context_v2(enum_value)

    malformed = copy.deepcopy(FIXTURE["input"])
    malformed["governance"]["coverage_claim_hash"] = "not-a-hash"
    with pytest.raises(
        ActionContextV2ValidationError,
        match="governance.coverage_claim_hash",
    ):
        build_action_context_v2(malformed)
