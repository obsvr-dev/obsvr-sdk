import copy
import json
from pathlib import Path

import pytest

from obsvr.action_context_v2 import build_action_context_v2
from obsvr.remediation_v1 import (
    RemediationV1ValidationError,
    build_remediation_plan_v1,
    build_remediation_retry_v1,
    canonicalize_remediation_plan_v1,
    remediation_plan_v1_hash,
    remediation_retry_v1_hash,
)


FIXTURE = json.loads(
    (
        Path(__file__).parents[2]
        / "conformance"
        / "fixtures"
        / "remediation_v1.json"
    ).read_text()
)


def _retry():
    return {**FIXTURE["retry"], "plan": FIXTURE["plan"]}


def test_pins_deterministic_plan_and_retry_hashes_across_languages():
    assert FIXTURE["claimable"] is False
    assert build_remediation_plan_v1(FIXTURE["plan"]) == FIXTURE["expect"][
        "plan_document"
    ]
    assert canonicalize_remediation_plan_v1(FIXTURE["plan"]) == FIXTURE["expect"][
        "plan_canonical"
    ]
    assert remediation_plan_v1_hash(FIXTURE["plan"]) == FIXTURE["expect"][
        "plan_hash"
    ]
    assert build_remediation_retry_v1(_retry()) == FIXTURE["expect"][
        "retry_document"
    ]
    assert remediation_retry_v1_hash(_retry()) == FIXTURE["expect"]["retry_hash"]


def test_requires_new_attempt_and_evidence_for_every_requirement():
    same = _retry()
    same["retry_attempt_id"] = FIXTURE["plan"]["attempt_id"]
    with pytest.raises(RemediationV1ValidationError, match="new attempt"):
        build_remediation_retry_v1(same)
    incomplete = _retry()
    incomplete["satisfied_requirements"] = incomplete["satisfied_requirements"][:1]
    with pytest.raises(RemediationV1ValidationError, match="every plan requirement"):
        build_remediation_retry_v1(incomplete)


@pytest.mark.parametrize("outcome", ["MODIFY", "STEP_UP", "DEFER"])
def test_maps_existing_remediation_outcomes(outcome):
    plan = {**FIXTURE["plan"], "outcome": outcome}
    assert build_remediation_plan_v1(plan)["outcome"] == outcome


def test_does_not_turn_terminal_deny_into_implicit_retry():
    plan = {**FIXTURE["plan"], "outcome": "DENY"}
    with pytest.raises(RemediationV1ValidationError, match="MODIFY, STEP_UP, or DEFER"):
        build_remediation_plan_v1(plan)


def test_rejects_raw_fields_and_links_retry_into_next_action_context():
    raw = copy.deepcopy(FIXTURE["plan"])
    raw["rewritten_input"] = "raw"
    with pytest.raises(RemediationV1ValidationError):
        build_remediation_plan_v1(raw)
    retry = build_remediation_retry_v1(_retry())
    context = build_action_context_v2(
        {
            "agent_id": "agent",
            "active_intents": ["send"],
            "run_id": "run",
            "prior_actions": [],
            "current_action": {
                "kind": "action",
                "name": "contract.send",
                "arguments_hash": "e" * 64,
                "target": "contract/42",
                "data_classifications": [],
                "requested_scopes": ["contracts:send"],
                "attempt_id": retry["retry_attempt_id"],
                "parent_attempt_id": retry["parent_attempt_id"],
                "remediation_retry_hash": FIXTURE["expect"]["retry_hash"],
            },
        }
    )
    assert context["action"] | {"target_hash": "ignored"} == {
        "kind": "action",
        "name": "contract.send",
        "arguments_hash": "e" * 64,
        "target_hash": "ignored",
        "data_classifications": [],
        "requested_scopes": ["contracts:send"],
        "attempt_id": "attempt-2",
        "parent_attempt_id": "attempt-1",
        "remediation_retry_hash": FIXTURE["expect"]["retry_hash"],
    }
