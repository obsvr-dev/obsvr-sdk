"""Cross-SDK canonical rules-hash fixture tests (twin of
sdk/tests/unit/rules-hash.test.ts). A divergence from the fixture is a
release blocker: the hash is the policy_version on every audit event
and the pin for approvals."""

import json
from pathlib import Path

from obsvr.rules import PolicyRule, derive_policy_version, derive_rule_hash

FIXTURE = json.loads(
    (Path(__file__).parent / "../../conformance/fixtures/rules_hash.json")
    .resolve()
    .read_text()
)


def _rules():
    return [
        PolicyRule(
            id=r["id"], name=r["name"], enabled=r["enabled"],
            action=r["action"], type=r["type"],
            conditions=r.get("conditions", {}),
            applies_to=r.get("applies_to"),
        )
        for r in FIXTURE["rules"]
    ]


def test_set_hash_matches_fixture():
    assert derive_policy_version(_rules()) == FIXTURE["expected"]["set_hash"]


def test_order_insensitive():
    assert derive_policy_version(list(reversed(_rules()))) == FIXTURE["expected"]["set_hash"]


def test_disabled_rules_excluded():
    enabled_only = [r for r in _rules() if r.enabled]
    assert derive_policy_version(enabled_only) == FIXTURE["expected"]["set_hash"]


def test_empty_and_all_disabled_are_none():
    assert derive_policy_version([]) == FIXTURE["expected"]["empty_set_hash"]
    disabled_only = [r for r in _rules() if not r.enabled]
    assert derive_policy_version(disabled_only) == FIXTURE["expected"]["all_disabled_hash"]


def test_rule_hashes_match_fixture():
    by_id = {r.id: r for r in _rules()}
    for rule_id, expected in FIXTURE["expected"]["rule_hashes"].items():
        assert derive_rule_hash(by_id[rule_id]) == expected


def test_rule_hash_changes_on_edit():
    rule = next(r for r in _rules() if r.id == "r-block-ssn")
    original = derive_rule_hash(rule)
    rule.conditions = dict(rule.conditions, min_confidence=0.9)
    assert derive_rule_hash(rule) != original
