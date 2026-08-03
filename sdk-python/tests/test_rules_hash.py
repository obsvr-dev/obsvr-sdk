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


# --- Resolution binding ------------------------------------------------------
#
# A ruleset that DECLARES its conflict-resolution mode gets the mode committed
# into policy_version, and the hash then commits to exactly what can change a
# decision under that mode: evaluation order under first_match, the sorted set
# under deny_wins. Undeclared rulesets keep the historical bytes, so nothing
# already deployed restamps. Pinned cross-language by the fixture's
# resolution_binding section.

_BINDING = FIXTURE["resolution_binding"]


def _binding_rules():
    return [
        PolicyRule(
            id=r["id"], name=r["name"], enabled=r["enabled"], action=r["action"],
            type=r["type"], conditions=r["conditions"],
        )
        for r in _BINDING["rules"]
    ]


def test_undeclared_hash_is_order_insensitive_and_pinned():
    expected = _BINDING["expected"]["undeclared_hash"]
    assert derive_policy_version(_binding_rules()) == expected
    assert derive_policy_version(list(reversed(_binding_rules()))) == expected


def test_first_match_hash_commits_to_evaluation_order():
    listed = derive_policy_version(_binding_rules(), "first_match")
    reversed_ = derive_policy_version(list(reversed(_binding_rules())), "first_match")
    assert listed == _BINDING["expected"]["first_match_listed_order"]
    assert reversed_ == _BINDING["expected"]["first_match_reversed_order"]
    assert listed != reversed_


def test_deny_wins_hash_is_order_insensitive_and_pinned():
    expected = _BINDING["expected"]["deny_wins_hash"]
    assert derive_policy_version(_binding_rules(), "deny_wins") == expected
    assert derive_policy_version(list(reversed(_binding_rules())), "deny_wins") == expected


def test_a_declared_mode_never_shares_a_version_with_the_undeclared_set():
    hashes = {
        derive_policy_version(_binding_rules()),
        derive_policy_version(_binding_rules(), "first_match"),
        derive_policy_version(_binding_rules(), "deny_wins"),
    }
    assert len(hashes) == 3


def test_unknown_resolution_derives_unknown_never_a_hash():
    # Provenance stays open: a typo'd declaration must not stamp a hash that
    # LOOKS like a committed version, and must not raise out of a live path.
    assert derive_policy_version(_binding_rules(), "deny-wins") == "unknown"


def test_order_commitment_disarmed_is_caught(monkeypatch):
    """Sibling non-vacuity probe: disarm the order-commitment (hash the
    first_match projections sorted by id, the way the undeclared path does)
    and the orderings-differ assertion above must go red."""
    import obsvr.rules as rules_mod

    def sorted_regardless(enabled, resolution):
        ordered = sorted(enabled, key=lambda r: rules_mod._utf16_order(r.id))
        return {
            "resolution": resolution,
            "rules": [rules_mod._canonical_rule(r) for r in ordered],
        }

    monkeypatch.setattr(rules_mod, "_version_document", sorted_regardless)
    listed = derive_policy_version(_binding_rules(), "first_match")
    reversed_ = derive_policy_version(list(reversed(_binding_rules())), "first_match")
    import pytest

    with pytest.raises(AssertionError):
        assert listed != reversed_
