"""Conflict-resolution precedence (twin: sdk-typescript/tests/unit/rule-precedence.test.ts).

Two contracts, both pinned:

- first_match (the default, and what an undeclared ruleset gets): rules
  evaluate in document order and the first rule that renders an outcome
  decides, so a matched topic_allow pre-empts every rule after it. List
  position is load-bearing, which is exactly what the tests here pin.
- deny_wins (the declared opt-in): every enforcing rule is evaluated and the
  strongest action prevails -- refusal over redaction over flag over permit --
  with the smallest rule id (UTF-16 code-unit order) breaking ties. The
  verdict and the recorded rule_id are identical for every permutation of the
  same rule list.

The two modes stamp different policy_version values (the declared mode is
committed into the hash -- see test_rules_hash.py), and deny_wins evaluation
carries its own engine_version marker, so the audit record alone says which
resolution produced a verdict.
"""
from itertools import permutations

import pytest

import obsvr.rules as rules_mod
from obsvr.rules import (
    RULE_RESOLUTION_MODES,
    PolicyRule,
    _reset_quota,
    derive_policy_version,
    ensure_rule_resolution,
    evaluate_policy_rules,
)


def _rule(**kw):
    defaults = dict(id="r1", name="rule", enabled=True, action="block", type="keyword")
    defaults.update(kw)
    return PolicyRule(**defaults)


def _allow_rule():
    return _rule(
        id="r-allow", name="Allow billing topics", action="flag",
        type="topic_allow", conditions={"topics": ["billing"]},
    )


def _block_rule():
    return _rule(
        id="r-block", name="Block billing", action="block",
        conditions={"keywords": ["billing"]},
    )


TEXT = "a billing question"


class TestFirstMatchPinsTodaysBehavior:
    """The default contract, unchanged: list position decides."""

    def test_allow_listed_first_preempts_the_block(self):
        result = evaluate_policy_rules([_allow_rule(), _block_rule()], TEXT)
        assert result["decision"] == "allow"
        assert result["rule_id"] == "r-allow"

    def test_block_listed_first_blocks(self):
        result = evaluate_policy_rules([_block_rule(), _allow_rule()], TEXT)
        assert result["decision"] == "block"
        assert result["rule_id"] == "r-block"

    def test_the_two_orderings_decide_differently(self):
        a = evaluate_policy_rules([_allow_rule(), _block_rule()], TEXT)
        b = evaluate_policy_rules([_block_rule(), _allow_rule()], TEXT)
        assert a["decision"] != b["decision"]

    def test_declared_first_match_agrees_with_undeclared(self):
        for rules in ([_allow_rule(), _block_rule()], [_block_rule(), _allow_rule()]):
            undeclared = evaluate_policy_rules(rules, TEXT)
            declared = evaluate_policy_rules(rules, TEXT, resolution="first_match")
            assert declared == undeclared


class TestDenyWins:
    def test_both_orderings_block_identically(self):
        a = evaluate_policy_rules(
            [_allow_rule(), _block_rule()], TEXT, resolution="deny_wins"
        )
        b = evaluate_policy_rules(
            [_block_rule(), _allow_rule()], TEXT, resolution="deny_wins"
        )
        assert a == b
        assert a["decision"] == "block"
        assert a["rule_id"] == "r-block"

    def test_redact_prevails_over_flag(self):
        flag = _rule(id="r-flag", action="flag", conditions={"keywords": ["billing"]})
        redact = _rule(id="r-redact", action="redact", conditions={"keywords": ["billing"]})
        for rules in ([flag, redact], [redact, flag]):
            result = evaluate_policy_rules(rules, TEXT, resolution="deny_wins")
            assert result["decision"] == "redact"
            assert result["rule_id"] == "r-redact"

    def test_flag_prevails_over_a_permit(self):
        # A flag carries a classification worth surfacing; a matched
        # topic_allow carries none. Nothing blocks either way.
        flag = _rule(id="r-flag", action="flag", conditions={"keywords": ["billing"]})
        for rules in ([_allow_rule(), flag], [flag, _allow_rule()]):
            result = evaluate_policy_rules(rules, TEXT, resolution="deny_wins")
            assert result["decision"] == "allow"
            assert result["rule_id"] == "r-flag"

    def test_a_lone_permit_still_allows_with_its_rule_id(self):
        result = evaluate_policy_rules([_allow_rule()], TEXT, resolution="deny_wins")
        assert result["decision"] == "allow"
        assert result["rule_id"] == "r-allow"

    def test_ties_break_to_the_smallest_rule_id(self):
        b1 = _rule(id="r-block-b", action="block", conditions={"keywords": ["billing"]})
        b2 = _rule(id="r-block-a", action="block", conditions={"keywords": ["billing"]})
        for rules in ([b1, b2], [b2, b1]):
            result = evaluate_policy_rules(rules, TEXT, resolution="deny_wins")
            assert result["decision"] == "block"
            assert result["rule_id"] == "r-block-a"

    def test_an_unrecognized_action_on_a_matched_rule_refuses(self):
        # The parse boundary rejects unknown actions (EV-12); for a rule
        # constructed in-process, deny_wins resolves the unrankable action to
        # the strongest outcome. first_match keeps its historical shape (the
        # flag fallthrough), pinned here so the difference is deliberate.
        odd = _rule(id="r-odd", action="quarantine", conditions={"keywords": ["billing"]})
        legacy = evaluate_policy_rules([odd], TEXT)
        assert legacy["decision"] == "allow"
        strict = evaluate_policy_rules([odd], TEXT, resolution="deny_wins")
        assert strict["decision"] == "block"
        assert strict["rule_id"] == "r-odd"

    def test_an_approval_grant_on_one_rule_does_not_shield_another(self, monkeypatch):
        import obsvr.remote as remote_mod

        monkeypatch.setattr(remote_mod, "has_approval", lambda *a, **k: True)
        gated = _rule(
            id="r-gated", action="block",
            conditions={"keywords": ["billing"], "require_approval": True},
        )
        # The grant satisfies r-gated (a permit); the plain block still wins.
        result = evaluate_policy_rules(
            [gated, _block_rule()], TEXT, resolution="deny_wins"
        )
        assert result["decision"] == "block"
        assert result["rule_id"] == "r-block"
        # Alone, the granted rule allows.
        alone = evaluate_policy_rules([gated], TEXT, resolution="deny_wins")
        assert alone["decision"] == "allow"
        assert alone.get("approval_granted") is not None

    def test_a_quota_block_prevails_over_an_earlier_permit(self):
        _reset_quota()
        try:
            quota = _rule(
                id="r-quota", action="block", type="quota",
                conditions={
                    "quota_limit": 1, "quota_window_ms": 60_000,
                    "quota_scope": "project",
                },
            )
            rules = [_allow_rule(), quota]
            first = evaluate_policy_rules(rules, TEXT, resolution="deny_wins")
            assert first["decision"] == "allow"
            second = evaluate_policy_rules(rules, TEXT, resolution="deny_wins")
            assert second["decision"] == "block"
            assert second["rule_id"] == "r-quota"
        finally:
            _reset_quota()

    def test_first_match_never_reaches_a_quota_behind_a_permit(self):
        # The pinned contrast: under first_match the same list allows forever,
        # because the matched topic_allow returns before the quota rule runs.
        _reset_quota()
        try:
            quota = _rule(
                id="r-quota", action="block", type="quota",
                conditions={
                    "quota_limit": 1, "quota_window_ms": 60_000,
                    "quota_scope": "project",
                },
            )
            rules = [_allow_rule(), quota]
            for _ in range(3):
                assert evaluate_policy_rules(rules, TEXT)["decision"] == "allow"
        finally:
            _reset_quota()


class TestResolutionValidation:
    def test_known_modes_and_none_pass(self):
        assert ensure_rule_resolution(None) is None
        for mode in RULE_RESOLUTION_MODES:
            assert ensure_rule_resolution(mode) == mode

    def test_an_unknown_resolution_raises_instead_of_evaluating(self):
        # House posture: a typo'd mode invalidates loudly, never silently
        # evaluates under semantics the author did not choose.
        with pytest.raises(ValueError):
            evaluate_policy_rules([_block_rule()], TEXT, resolution="deny-wins")
        with pytest.raises(ValueError):
            evaluate_policy_rules([_block_rule()], TEXT, resolution="denywins")


class TestPolicyVersionTiesToTheOrderingHazard:
    def test_orderings_that_decide_differently_stamp_different_versions(self):
        listed = [_allow_rule(), _block_rule()]
        reordered = [_block_rule(), _allow_rule()]
        # The two orderings decide differently under first_match...
        assert (
            evaluate_policy_rules(listed, TEXT)["decision"]
            != evaluate_policy_rules(reordered, TEXT)["decision"]
        )
        # ...and a declared first_match ruleset commits order into the hash,
        # so the record distinguishes them.
        assert derive_policy_version(listed, "first_match") != derive_policy_version(
            reordered, "first_match"
        )

    def test_deny_wins_orderings_that_decide_identically_share_a_version(self):
        listed = [_allow_rule(), _block_rule()]
        reordered = [_block_rule(), _allow_rule()]
        assert evaluate_policy_rules(
            listed, TEXT, resolution="deny_wins"
        ) == evaluate_policy_rules(reordered, TEXT, resolution="deny_wins")
        assert derive_policy_version(listed, "deny_wins") == derive_policy_version(
            reordered, "deny_wins"
        )


def _four_matching_rules():
    return [
        _allow_rule(),
        _rule(id="r-flag", action="flag", conditions={"keywords": ["billing"]}),
        _block_rule(),
        _rule(id="r-redact", action="redact", conditions={"keywords": ["billing"]}),
    ]


def _assert_one_verdict_across_all_permutations():
    """Evaluate every permutation of four matching rules under deny_wins and
    require a single (decision, rule_id) across all 24."""
    outcomes = {
        (result["decision"], result.get("rule_id"))
        for perm in permutations(_four_matching_rules())
        for result in [evaluate_policy_rules(list(perm), TEXT, resolution="deny_wins")]
    }
    assert outcomes == {("block", "r-block")}, outcomes


class TestOrderInsensitivityIsNotVacuous:
    def test_deny_wins_resolves_every_permutation_identically(self):
        _assert_one_verdict_across_all_permutations()

    def test_a_reintroduced_first_match_return_is_caught(self, monkeypatch):
        """Sibling non-vacuity probe: disarm the resolver (take the first
        collected outcome, which is the first-match shape) and the
        permutation invariant above must go red."""
        monkeypatch.setattr(
            rules_mod, "_resolve_matched", lambda collected: collected[0][1]
        )
        with pytest.raises(AssertionError):
            _assert_one_verdict_across_all_permutations()


class TestEngineVersionMarker:
    def test_deny_wins_evaluation_carries_its_own_marker(self):
        from obsvr.decision_record import (
            DENY_WINS_SEMANTICS_VERSION,
            ENGINE_VERSION,
            engine_version_for,
        )

        assert ENGINE_VERSION == "obsvr-rules/1"
        assert engine_version_for(None) == ENGINE_VERSION
        assert engine_version_for("first_match") == ENGINE_VERSION
        assert engine_version_for("deny_wins") == "obsvr-rules/%d" % (
            DENY_WINS_SEMANTICS_VERSION
        )
        assert engine_version_for("deny_wins") != ENGINE_VERSION

    def test_the_marker_reaches_the_decision_input_document(self):
        from obsvr.decision_record import build_decision_input, engine_version_for

        doc = build_decision_input(
            rules_hash="abc", degraded=False, target="request",
            evaluated_text="x", hook="not_configured",
            engine_version=engine_version_for("deny_wins"),
        )
        assert doc["engine_version"] == "obsvr-rules/2"
        default = build_decision_input(
            rules_hash="abc", degraded=False, target="request",
            evaluated_text="x", hook="not_configured",
        )
        assert default["engine_version"] == "obsvr-rules/1"
