"""Twin tests for bounded v2 action contexts."""

import json
from pathlib import Path

import pytest

from obsvr.action_context_v2 import (
    ActionContextV2ValidationError,
    action_context_v2_hash,
    action_target_hash,
    build_action_context_v2,
    canonicalize_action_context_v2,
)

FIXTURE = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "conformance"
        / "fixtures"
        / "action_context_v2.json"
    ).read_text(encoding="utf-8")
)


def _base():
    return {
        "agent_id": "agent",
        "active_intents": ["intent"],
        "current_action": {
            "kind": "tool",
            "name": "send",
            "arguments_hash": "a" * 64,
            "target": "workspace",
            "data_classifications": [],
            "requested_scopes": [],
        },
        "run_id": "run",
        "prior_actions": [],
    }


def test_fixture_pins_canonical_bytes_and_target_hashes():
    assert FIXTURE["claimable"] is False
    for vector in FIXTURE["target_hash_vectors"]:
        assert action_target_hash(vector["target"]) == vector["target_hash"]
    case = FIXTURE["valid_case"]
    assert build_action_context_v2(case["input"]) == case["expect"]["document"]
    assert canonicalize_action_context_v2(case["input"]) == case["expect"]["canonical"]
    assert action_context_v2_hash(case["input"]) == case["expect"]["hash"]


def test_raw_target_is_absent_from_canonical_document():
    canonical = canonicalize_action_context_v2(_base())
    assert "workspace" not in canonical
    assert f'"target_hash":"{action_target_hash("workspace")}"' in canonical


def test_target_1024_byte_boundary():
    accepted = _base()
    accepted["current_action"]["target"] = "x" * 1_024
    assert build_action_context_v2(accepted)["action"][
        "target_hash"
    ] == action_target_hash("x" * 1_024)
    rejected = _base()
    rejected["current_action"]["target"] = "x" * 1_025
    with pytest.raises(ActionContextV2ValidationError):
        build_action_context_v2(rejected)


def test_astral_utf8_bytes_and_unpaired_surrogates():
    accepted = _base()
    accepted["current_action"]["target"] = "🚀" * 256
    build_action_context_v2(accepted)
    rejected = _base()
    rejected["current_action"]["target"] = "🚀" * 257
    with pytest.raises(ActionContextV2ValidationError):
        build_action_context_v2(rejected)
    surrogate = _base()
    surrogate["current_action"]["target"] = "\ud800"
    with pytest.raises(ActionContextV2ValidationError):
        build_action_context_v2(surrogate)


def test_ascii_blankness_and_code_point_sorting():
    input_value = _base()
    input_value["active_intents"] = ["😀", "\ue000", "\u00a0"]
    assert build_action_context_v2(input_value)["agent"]["active_intents"] == [
        "\u00a0",
        "\ue000",
        "😀",
    ]


def test_identifier_set_prior_and_context_caps():
    identifier = _base()
    identifier["agent_id"] = "x" * 257
    with pytest.raises(ActionContextV2ValidationError):
        build_action_context_v2(identifier)
    set_overflow = _base()
    set_overflow["active_intents"] = [f"i{index}" for index in range(65)]
    with pytest.raises(ActionContextV2ValidationError):
        build_action_context_v2(set_overflow)
    prior_overflow = _base()
    prior_overflow["prior_actions"] = [
        {
            "sequence": sequence,
            "kind": "tool",
            "name": "prior",
            "outcome": "ALLOW",
            "receipt_hash": "b" * 64,
            "data_classifications": [],
        }
        for sequence in range(257)
    ]
    with pytest.raises(ActionContextV2ValidationError):
        build_action_context_v2(prior_overflow)
    classifications = [f"{index:02d}" + "x" * 240 for index in range(64)]
    large = _base()
    large["prior_actions"] = [
        {
            "sequence": sequence,
            "kind": "tool",
            "name": "prior",
            "outcome": "ALLOW",
            "receipt_hash": "b" * 64,
            "data_classifications": classifications,
        }
        for sequence in range(256)
    ]
    with pytest.raises(
        ActionContextV2ValidationError,
        match="canonical action context exceeds 65536 UTF-8 bytes",
    ):
        build_action_context_v2(large)
