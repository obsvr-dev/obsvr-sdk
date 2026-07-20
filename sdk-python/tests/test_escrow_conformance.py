"""Cross-SDK conformance harness (Python side) for fleet-quota escrow (ADR-7).
Twin: sdk/tests/unit/escrow-conformance.test.ts. Both drive every
(grant, spend, report) sequence in conformance/fixtures/quota_escrow.json and
must reach identical allow/block decisions and consumption reports. A
divergence is a release blocker."""

import json
from pathlib import Path

import pytest

from obsvr.escrow import (
    _reset_escrow,
    apply_escrow_grant,
    apply_escrow_response,
    has_escrow,
    peek_escrow_share,
    snapshot_consumption,
    spend_escrow_share,
)
from obsvr.rules import PolicyRule, evaluate_policy_rules
from obsvr.rules import _reset_quota

FIXTURE = json.loads(
    (Path(__file__).parent / "../../conformance/fixtures/quota_escrow.json")
    .resolve()
    .read_text()
)


@pytest.fixture(autouse=True)
def _clean():
    _reset_escrow()
    _reset_quota()
    yield
    _reset_escrow()
    _reset_quota()


@pytest.mark.parametrize("case", FIXTURE["cases"], ids=[c["id"] for c in FIXTURE["cases"]])
def test_escrow_conformance_case(case):
    _reset_escrow()
    for i, step in enumerate(case["steps"]):
        op = step["op"]
        where = f"{case['id']} step {i} ({op})"
        if op == "grant":
            apply_escrow_grant(step["rule_id"], step["share"], step["epoch"])
        elif op == "poll_response":
            apply_escrow_response(step.get("escrow"))
        elif op == "spend":
            result = spend_escrow_share(step["rule_id"])
            assert result == step["expect"], where
        elif op == "peek":
            result = peek_escrow_share(step["rule_id"])
            assert result == step["expect"], where
        elif op == "has_escrow":
            assert has_escrow(step["rule_id"]) is step["expect"], where
        elif op == "report":
            assert snapshot_consumption() == step["expect"], where
        else:
            raise AssertionError(f"{where}: unknown op")


# ── Wiring: the rules engine must route a quota rule through the escrow share
# when a grant is in effect, and fall back to the per-process meter otherwise.

def _quota_rule():
    return PolicyRule(
        id="q1",
        name="request quota",
        enabled=True,
        action="block",
        type="quota",
        conditions={"quota_limit": 100, "quota_window_ms": 60000, "quota_scope": "project"},
    )


def test_rules_engine_spends_escrow_share_when_in_effect():
    # Escrow grants only 1, even though the rule limit is 100: the fleet
    # allocator, not the local limit, bounds this instance.
    apply_escrow_grant("q1", 1, 1)
    assert evaluate_policy_rules([_quota_rule()], "hello")["decision"] == "allow"
    blocked = evaluate_policy_rules([_quota_rule()], "hello")
    assert blocked["decision"] == "block"
    assert blocked["rule_id"] == "q1"
    assert snapshot_consumption() == {"q1": {"consumed": 1, "epoch": 1}}


def test_rules_engine_falls_back_to_per_process_without_escrow():
    # No grant for q1 -> uses the local limit of 100, so the first call allows
    # and nothing is tracked as escrow consumption.
    assert evaluate_policy_rules([_quota_rule()], "hello")["decision"] == "allow"
    assert has_escrow("q1") is False
    assert snapshot_consumption() == {}


def test_rules_engine_check_only_peeks_escrow_without_consuming():
    apply_escrow_grant("q1", 1, 4)
    # Shadow/explain path (check_only) must not burn the share.
    evaluate_policy_rules([_quota_rule()], "hello", "prompt", None, check_only=True)
    assert snapshot_consumption() == {"q1": {"consumed": 0, "epoch": 4}}
    # A real (consuming) call then still has its full share.
    assert evaluate_policy_rules([_quota_rule()], "hello")["decision"] == "allow"
    assert snapshot_consumption() == {"q1": {"consumed": 1, "epoch": 4}}
