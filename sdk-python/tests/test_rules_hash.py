"""Cross-SDK canonical rules-hash fixture tests (twin of
sdk-typescript/tests/unit/rules-hash.test.ts). A divergence from the fixture is a
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


# --- A-4: the two rule-id sort sites -----------------------------------------
#
# Both languages sort ids before hashing, and they sorted DIFFERENTLY -- this
# side by code point, TypeScript by UTF-16 code unit. Every id in the fixture
# above is ASCII, so both orders agree on all of them and the divergence
# survived the whole corpus.
#
# The case that catches it needs an ASTRAL id beside a BMP id in
# U+E000..U+FFFF. That is the only region where the orders differ, so a pair
# chosen anywhere else would pass whatever the sort key is -- a fixture that
# cannot fail.

_ORDERING = FIXTURE["ordering"]


def _ordering_rules():
    return [
        PolicyRule(
            id=r["id"], name=r["name"], enabled=r["enabled"], action=r["action"],
            type=r["type"], conditions=r["conditions"],
        )
        for r in _ORDERING["rules"]
    ]


def test_the_two_orders_genuinely_differ_on_this_pair():
    """Non-vacuity: if these two orders agreed, every assertion below would
    hold with either sort key and the fixture would prove nothing."""
    from obsvr.rules import _utf16_order

    ids = [r["id"] for r in _ORDERING["rules"]]
    assert sorted(ids, key=_utf16_order) == _ORDERING["expected"]["utf16_order"]
    assert sorted(ids) == _ORDERING["expected"]["codepoint_order_do_not_use"]
    assert sorted(ids, key=_utf16_order) != sorted(ids)


def test_derive_policy_version_stamps_the_pinned_hash():
    assert derive_policy_version(_ordering_rules()) == _ORDERING["expected"]["set_hash"]


def test_derive_floor_version_stamps_the_pinned_hash():
    from obsvr.rules import derive_floor_version

    assert derive_floor_version(_ORDERING["rules"]) == _ORDERING["expected"]["floor_hash"]
