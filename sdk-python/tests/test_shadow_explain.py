"""Shadow mode (EV-20/21) and check-only explain (EV-22) tests, twin of
sdk/tests/unit/shadow-explain.test.ts."""

import json

import pytest

import obsvr
from obsvr.rules import (
    PolicyRule,
    _reset_quota,
    derive_policy_version,
    evaluate_policy_rules,
    evaluate_shadow_rules,
    increment_quota,
)

BLOCK_RULE = PolicyRule(
    id="r-active", name="Active block", enabled=True, action="block",
    type="keyword", conditions={"keywords": ["forbidden"]},
)

SHADOW_RULE = PolicyRule(
    id="r-shadow", name="Shadow block candidate", enabled=True, action="block",
    type="keyword", conditions={"keywords": ["candidate"]}, mode="shadow",
)


@pytest.fixture(autouse=True)
def _clean_quota():
    _reset_quota()
    yield
    _reset_quota()


def test_ev20_active_decision_byte_identical_with_shadow():
    for text in [
        "a perfectly fine prompt",
        "this mentions candidate territory",
        "this is forbidden content",
        "both forbidden and candidate",
    ]:
        without = evaluate_policy_rules([BLOCK_RULE], text)
        with_shadow = evaluate_policy_rules([BLOCK_RULE, SHADOW_RULE], text)
        assert json.dumps(with_shadow, sort_keys=True) == json.dumps(without, sort_keys=True)


def test_ev20_shadow_only_never_blocks():
    result = evaluate_policy_rules([SHADOW_RULE], "candidate text")
    assert result["decision"] == "allow"
    assert result.get("rule_id") is None


def test_ev21_shadow_outcome_recorded():
    outcome = evaluate_shadow_rules([BLOCK_RULE, SHADOW_RULE], "candidate text")
    assert outcome == {
        "rule_id": "r-shadow",
        "would": "block",
        "reason_code": "SHADOW_WOULD_BLOCK",
        "reason": "Shadow block candidate",
    }


def test_ev21_null_when_nothing_matches():
    assert evaluate_shadow_rules([BLOCK_RULE, SHADOW_RULE], "harmless") is None
    assert evaluate_shadow_rules([BLOCK_RULE], "candidate text") is None


def test_ev16_shadow_flag_changes_hash():
    import dataclasses
    enforcing = dataclasses.replace(SHADOW_RULE, mode="enforce")
    assert derive_policy_version([SHADOW_RULE]) != derive_policy_version([enforcing])
    # mode "enforce" hashes identically to mode omitted (back-compat)
    with_mode = dataclasses.replace(BLOCK_RULE, mode="enforce")
    assert derive_policy_version([with_mode]) == derive_policy_version([BLOCK_RULE])


def test_ev22_check_only_consumes_no_quota():
    quota_rule = PolicyRule(
        id="r-quota", name="Two per user", enabled=True, action="block",
        type="quota",
        conditions={"quota_limit": 2, "quota_window_ms": 60000, "quota_scope": "user_id"},
    )
    ctx = {"metadata": {"user_id": "u1"}}
    for _ in range(5):
        r = evaluate_policy_rules([quota_rule], "hi", context=ctx, check_only=True)
        assert r["decision"] == "allow"
    # Real quota untouched: both slots still available
    probe = increment_quota("user_id", "u1", 2, 60000, record=False)
    assert probe["remaining"] == 2


def test_explain_is_pure_and_reports(sent=None):
    obsvr.init(api_key="k", policy_refresh_interval_s=0, policy_rules=[
        BLOCK_RULE, SHADOW_RULE,
        PolicyRule(
            id="r-quota", name="Two per user", enabled=True, action="block",
            type="quota",
            conditions={"quota_limit": 2, "quota_window_ms": 60000, "quota_scope": "user_id"},
        ),
    ])
    result = obsvr.explain("candidate text", metadata={"user_id": "u9"})
    assert result["decision"] == "allow"
    assert result["shadow_outcome"]["rule_id"] == "r-shadow"
    assert result["rules_hash"] == derive_policy_version(obsvr.get_config().policy_rules)
    assert "customer_hook" in result["not_evaluated"]

    blocked = obsvr.explain("this is forbidden content")
    assert blocked["decision"] == "block"
    assert blocked["rule_id"] == "r-active"

    # Purity: repeated explains never consume the quota
    for _ in range(5):
        obsvr.explain("hi", metadata={"user_id": "u9"})
    probe = increment_quota("user_id", "u9", 2, 60000, record=False)
    assert probe["remaining"] == 2
