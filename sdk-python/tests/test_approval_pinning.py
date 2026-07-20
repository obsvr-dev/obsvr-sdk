"""Approval pinning (twin of sdk/tests/unit/approvals-pinning.test.ts):
a grant minted under one rule definition must not satisfy the rule after
it is edited; legacy grants without a hash stay honored."""

import time

import pytest

from obsvr import remote
from obsvr.rules import PolicyRule, derive_rule_hash, evaluate_policy_rules

FUTURE = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() + 3600)) + "Z"

RULE = PolicyRule(
    id="r-gate",
    name="Dangerous op gate",
    enabled=True,
    action="block",
    type="action_gate",
    conditions={"require_approval": True, "action_types": ["delete"]},
)


@pytest.fixture(autouse=True)
def _clean_grants():
    with remote._grants_lock:
        remote._grants.clear()
    yield
    with remote._grants_lock:
        remote._grants.clear()


def _set_grants(grants):
    with remote._grants_lock:
        remote._grants.clear()
        remote._grants.extend(grants)


def test_matching_hash_grant_is_honored():
    h = derive_rule_hash(RULE)
    _set_grants([{"id": "g1", "rule_id": "r-gate", "expires_at": FUTURE, "rule_hash": h}])
    assert remote.has_approval("r-gate", None, h) is True


def test_stale_hash_grant_is_void():
    old = derive_rule_hash(PolicyRule(
        id="r-gate", name="Old name", enabled=True, action="block",
        type="action_gate", conditions={"require_approval": True, "action_types": ["delete"]},
    ))
    current = derive_rule_hash(RULE)
    assert old != current
    _set_grants([{"id": "g1", "rule_id": "r-gate", "expires_at": FUTURE, "rule_hash": old}])
    assert remote.has_approval("r-gate", None, current) is False


def test_legacy_grant_without_hash_is_honored():
    _set_grants([{"id": "g1", "rule_id": "r-gate", "expires_at": FUTURE}])
    assert remote.has_approval("r-gate", None, derive_rule_hash(RULE)) is True


def test_evaluate_blocks_with_rule_hash_when_no_grant():
    result = evaluate_policy_rules(
        [RULE], "please delete everything",
        context={"action_name": "delete"},
    )
    assert result["decision"] == "block"
    assert result["approval_required"] is True
    assert result["rule_hash"] == derive_rule_hash(RULE)


def test_grant_stops_binding_after_rule_edit():
    _set_grants([{
        "id": "g1", "rule_id": "r-gate", "expires_at": FUTURE,
        "rule_hash": derive_rule_hash(RULE),
    }])
    allowed = evaluate_policy_rules(
        [RULE], "please delete everything", context={"action_name": "delete"},
    )
    assert allowed["decision"] == "allow"

    edited = PolicyRule(
        id="r-gate", name="Dangerous op gate", enabled=True, action="block",
        type="action_gate",
        conditions={"require_approval": True, "action_types": ["delete", "drop"]},
    )
    blocked = evaluate_policy_rules(
        [edited], "please delete everything", context={"action_name": "delete"},
    )
    assert blocked["decision"] == "block"
    assert blocked["approval_required"] is True
