"""Rule-type parity tests: the 8 context-dependent rule types ported from TS.

Parity targets: sdk/tests/unit/fintech-rules.test.ts, saas-rules.test.ts,
healthcare-rules.test.ts, devops-rules.test.ts, legal-rules.test.ts,
governance-quota.test.ts.
"""
import pytest

from obsvr.rules import (
    PolicyRule,
    compute_grounding_score,
    evaluate_policy_rules,
    increment_quota,
    _reset_quota,
)


def rule(**kw):
    defaults = dict(id="r1", name="test rule", enabled=True, action="block")
    defaults.update(kw)
    return PolicyRule(**defaults)


class TestActionGate:
    def test_blocks_matching_action_over_threshold(self):
        r = rule(type="action_gate", conditions={
            "action_types": ["wire_transfer"],
            "threshold": {"field": "amount", "operator": ">", "value": 10000},
        })
        result = evaluate_policy_rules(
            [r], "initiate transfer", context={"action_name": "wire_transfer", "amount": 50000}
        )
        assert result["decision"] == "block"
        assert result["rule_id"] == "r1"

    def test_allows_under_threshold(self):
        r = rule(type="action_gate", conditions={
            "action_types": ["wire_transfer"],
            "threshold": {"field": "amount", "operator": ">", "value": 10000},
        })
        result = evaluate_policy_rules(
            [r], "transfer", context={"action_name": "wire_transfer", "amount": 500}
        )
        assert result["decision"] == "allow"

    def test_no_context_never_matches(self):
        r = rule(type="action_gate", conditions={
            "action_types": ["wire_transfer"],
            "threshold": {"field": "amount", "operator": ">", "value": 10000},
        })
        assert evaluate_policy_rules([r], "wire_transfer text")["decision"] == "allow"

    def test_metadata_threshold_field(self):
        r = rule(type="action_gate", conditions={
            "threshold": {"field": "risk_score", "operator": ">=", "value": 0.8},
        })
        result = evaluate_policy_rules(
            [r], "x", context={"metadata": {"risk_score": 0.95}}
        )
        assert result["decision"] == "block"


class TestNamespaceIsolation:
    def test_cross_namespace_blocked(self):
        r = rule(type="namespace_isolation", conditions={})
        result = evaluate_policy_rules(
            [r], "read patient record",
            context={"caller_namespace": "clinic-a", "target_namespace": "clinic-b"},
        )
        assert result["decision"] == "block"

    def test_same_namespace_allowed(self):
        r = rule(type="namespace_isolation", conditions={})
        result = evaluate_policy_rules(
            [r], "read patient record",
            context={"caller_namespace": "clinic-a", "target_namespace": "clinic-a"},
        )
        assert result["decision"] == "allow"

    def test_cross_tenant_block_same_semantics(self):
        r = rule(type="cross_tenant_block", conditions={})
        result = evaluate_policy_rules(
            [r], "query", context={"caller_namespace": "t1", "target_namespace": "t2"}
        )
        assert result["decision"] == "block"


class TestDestructiveOpGate:
    def test_blocks_destructive_text(self):
        r = rule(type="destructive_op_gate", conditions={
            "destructive_operations": ["DROP TABLE", "rm -rf"],
        })
        result = evaluate_policy_rules([r], "please run DROP TABLE users;")
        assert result["decision"] == "block"

    def test_blocks_destructive_action_name(self):
        r = rule(type="destructive_op_gate", conditions={
            "destructive_operations": ["delete_all"],
        })
        result = evaluate_policy_rules(
            [r], "benign text", context={"action_name": "delete_all_records"}
        )
        assert result["decision"] == "block"

    def test_benign_passes(self):
        r = rule(type="destructive_op_gate", conditions={
            "destructive_operations": ["DROP TABLE"],
        })
        assert evaluate_policy_rules([r], "SELECT * FROM users")["decision"] == "allow"


class TestSourceGrounding:
    def test_ungrounded_output_flagged(self):
        r = rule(type="source_grounding", action="flag", conditions={
            "min_grounding_ratio": 0.5,
        })
        result = evaluate_policy_rules(
            [r], "completely fabricated hallucinated nonsense claims",
            target="response",
            context={"source_documents": ["the contract term is twelve months"]},
        )
        assert result["rule_id"] == "r1"  # fired (flag keeps decision allow)

    def test_grounded_output_passes(self):
        r = rule(type="source_grounding", action="block", conditions={
            "min_grounding_ratio": 0.5,
        })
        result = evaluate_policy_rules(
            [r], "contract term twelve months",
            target="response",
            context={"source_documents": ["the contract term is twelve months"]},
        )
        assert result["decision"] == "allow"
        assert result.get("rule_id") is None

    def test_no_sources_counts_as_ungrounded(self):
        r = rule(type="source_grounding", conditions={"min_grounding_ratio": 0.5})
        result = evaluate_policy_rules([r], "any output", context={})
        assert result["decision"] == "block"

    def test_grounding_score_math(self):
        assert compute_grounding_score("", ["src"]) == 1.0
        score = compute_grounding_score(
            "alpha beta gamma", ["alpha beta something else"]
        )
        assert 0.6 < score < 0.7  # 2 of 3 words grounded


class TestEnvironmentGate:
    def test_blocks_in_restricted_environment(self):
        r = rule(type="environment_gate", conditions={
            "target_environments": ["production"],
        })
        result = evaluate_policy_rules(
            [r], "deploy", context={"current_environment": "production"}
        )
        assert result["decision"] == "block"

    def test_allows_elsewhere(self):
        r = rule(type="environment_gate", conditions={
            "target_environments": ["production"],
        })
        result = evaluate_policy_rules(
            [r], "deploy", context={"current_environment": "staging"}
        )
        assert result["decision"] == "allow"


class TestQuota:
    def setup_method(self):
        _reset_quota()

    def test_quota_blocks_after_limit(self):
        r = rule(type="quota", conditions={
            "quota_limit": 2, "quota_window_ms": 60000, "quota_scope": "user_id",
        })
        ctx = {"metadata": {"user_id": "u1"}}
        assert evaluate_policy_rules([r], "x", context=ctx)["decision"] == "allow"
        assert evaluate_policy_rules([r], "x", context=ctx)["decision"] == "allow"
        third = evaluate_policy_rules([r], "x", context=ctx)
        assert third["decision"] == "block"
        assert "Quota exceeded" in third["reason"]

    def test_quota_scopes_are_independent(self):
        r = rule(type="quota", conditions={
            "quota_limit": 1, "quota_window_ms": 60000, "quota_scope": "user_id",
        })
        assert evaluate_policy_rules([r], "x", context={"metadata": {"user_id": "a"}})["decision"] == "allow"
        assert evaluate_policy_rules([r], "x", context={"metadata": {"user_id": "b"}})["decision"] == "allow"
        assert evaluate_policy_rules([r], "x", context={"metadata": {"user_id": "a"}})["decision"] == "block"

    def test_increment_quota_window_reset(self):
        _reset_quota()
        first = increment_quota("user_id", "u1", 1, 1)  # 1ms window
        assert first["allowed"] is True
        import time
        time.sleep(0.005)
        again = increment_quota("user_id", "u1", 1, 1)
        assert again["allowed"] is True  # new window


class TestBackwardCompatibility:
    def test_text_only_call_signature_still_works(self):
        r = rule(type="keyword", conditions={"keywords": ["forbidden"]})
        assert evaluate_policy_rules([r], "this is forbidden")["decision"] == "block"
        assert evaluate_policy_rules([r], "fine", "response")["decision"] == "allow"

    def test_disabled_rules_skipped(self):
        r = rule(type="keyword", enabled=False, conditions={"keywords": ["forbidden"]})
        assert evaluate_policy_rules([r], "forbidden")["decision"] == "allow"
