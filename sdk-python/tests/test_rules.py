"""Tests for structured policy rules engine."""
import pytest
from obsvr.rules import PolicyRule, evaluate_policy_rules, derive_policy_version


def make_rule(**kwargs):
    defaults = {"id": "r1", "name": "test", "enabled": True, "action": "block", "type": "keyword", "conditions": {}}
    defaults.update(kwargs)
    return PolicyRule(**defaults)


def test_allow_when_no_match():
    rules = [make_rule(conditions={"keywords": ["badword"]})]
    assert evaluate_policy_rules(rules, "hello world")["decision"] == "allow"


def test_block_on_keyword():
    rules = [make_rule(conditions={"keywords": ["badword"]})]
    result = evaluate_policy_rules(rules, "this is badword")
    assert result["decision"] == "block"
    assert result["rule_id"] == "r1"


def test_skip_disabled_rule():
    rules = [make_rule(enabled=False, conditions={"keywords": ["badword"]})]
    assert evaluate_policy_rules(rules, "badword")["decision"] == "allow"


def test_topic_allow_short_circuits():
    rules = [make_rule(type="topic_allow", action="flag", conditions={"topics": ["science"]})]
    result = evaluate_policy_rules(rules, "discussing science")
    assert result["decision"] == "allow"
    assert result["rule_id"] == "r1"


def test_regex_rule():
    rules = [make_rule(type="regex", action="block", conditions={"pattern": r"\d{4}-\d{4}"})]
    assert evaluate_policy_rules(rules, "code 1234-5678")["decision"] == "block"


# ── model_gate (parity with TS sdk/tests/unit/model-gate-token-budget.test.ts) ──

def test_model_gate_blocks_model_not_on_allowlist():
    rules = [make_rule(type="model_gate", conditions={"allowed_models": ["gpt-4o", "claude-sonnet-5"]})]
    result = evaluate_policy_rules(rules, "hi", context={"model": "gpt-3.5-turbo"})
    assert result["decision"] == "block"
    assert result["rule_id"] == "r1"


def test_model_gate_allows_model_on_allowlist():
    rules = [make_rule(type="model_gate", conditions={"allowed_models": ["gpt-4o"]})]
    assert evaluate_policy_rules(rules, "hi", context={"model": "gpt-4o"})["decision"] == "allow"


def test_model_gate_allowlist_prefix_match():
    rules = [make_rule(type="model_gate", conditions={"allowed_models": ["gpt-4"]})]
    assert evaluate_policy_rules(rules, "hi", context={"model": "gpt-4o"})["decision"] == "allow"


def test_model_gate_blocks_denied_model():
    rules = [make_rule(type="model_gate", conditions={"denied_models": ["gpt-3.5"]})]
    assert evaluate_policy_rules(rules, "hi", context={"model": "gpt-3.5-turbo"})["decision"] == "block"


def test_model_gate_provider_allowlist():
    rules = [make_rule(type="model_gate", conditions={"allowed_providers": ["anthropic"]})]
    assert evaluate_policy_rules(rules, "hi", context={"provider": "openai"})["decision"] == "block"
    assert evaluate_policy_rules(rules, "hi", context={"provider": "anthropic"})["decision"] == "allow"


def test_model_gate_no_model_context_is_inert():
    # With no model in context, a model-only allowlist cannot decide -> no match.
    rules = [make_rule(type="model_gate", conditions={"allowed_models": ["gpt-4o"]})]
    assert evaluate_policy_rules(rules, "hi")["decision"] == "allow"


def test_derive_version_empty():
    assert derive_policy_version([]) == "none"


def test_derive_version_consistent():
    rules = [make_rule()]
    assert derive_policy_version(rules) == derive_policy_version(rules)


def test_derive_version_changes():
    r1 = [make_rule(name="a", conditions={"keywords": ["a"]})]
    r2 = [make_rule(name="b", conditions={"keywords": ["b"]})]
    assert derive_policy_version(r1) != derive_policy_version(r2)


# ── token-unit quotas (KD-2: parity with TS checkTokenBudget/recordTokenUsage) ──

def test_token_quota_allows_until_budget_consumed_then_blocks():
    from obsvr.rules import record_token_usage, _reset_quota
    _reset_quota()
    rule = make_rule(
        type="quota", action="block",
        conditions={"quota_unit": "tokens", "quota_limit": 100,
                    "quota_window_ms": 60000, "quota_scope": "user_id"},
    )
    ctx = {"metadata": {"user_id": "u1"}}
    # Pre-call check does not consume; with no prior usage it allows.
    assert evaluate_policy_rules([rule], "hi", context=ctx)["decision"] == "allow"
    # Record 120 tokens consumed by a completed call for u1.
    record_token_usage("user_id", "u1", 120, 60000)
    # Now the budget is exceeded -> next pre-call blocks.
    assert evaluate_policy_rules([rule], "hi", context=ctx)["decision"] == "block"
    # A different user is unaffected (separate bucket).
    assert evaluate_policy_rules([rule], "hi", context={"metadata": {"user_id": "u2"}})["decision"] == "allow"


def test_quota_scope_falls_back_to_top_level_context_key():
    # Parity with TS rules.ts: metadata[scope] ?? context[scope] ?? 'default'.
    # Callers (e.g. the proxy wrapper) may spread identity at the TOP level of
    # the context rather than under metadata; a tenant-scoped rule must meter
    # that bucket, never silently 'default'.
    from obsvr.rules import _reset_quota
    _reset_quota()
    rule = make_rule(
        type="quota", action="block",
        conditions={"quota_limit": 1, "quota_window_ms": 60000,
                    "quota_scope": "tenant_id"},
    )
    # tenant_id only at top level (not under metadata).
    ctx_a = {"tenant_id": "acme"}
    assert evaluate_policy_rules([rule], "hi", context=ctx_a)["decision"] == "allow"
    assert evaluate_policy_rules([rule], "hi", context=ctx_a)["decision"] == "block"
    # A different top-level tenant is a separate bucket.
    assert evaluate_policy_rules([rule], "hi", context={"tenant_id": "globex"})["decision"] == "allow"
    # metadata still wins over top level when both are present.
    from obsvr.rules import quota_scope_value
    assert quota_scope_value("tenant_id", {"tenant_id": "meta"}, None, {"tenant_id": "top"}) == "meta"


# ── request-unit quota phase accounting (1 call = 1 unit, never 2) ──────────
# The post-call pipeline re-runs the rules with target="response"; a
# both/unset-scoped quota must NOT be consumed a second time there.

def _quota_rule(**kwargs):
    conditions = {"quota_limit": 2, "quota_window_ms": 60000, "quota_scope": "project"}
    conditions.update(kwargs.pop("conditions", {}))
    return make_rule(type="quota", action="block", conditions=conditions, **kwargs)


@pytest.mark.parametrize("applies_to", [None, "both"])
def test_quota_consumed_once_per_call_not_per_phase(applies_to):
    from obsvr.rules import _reset_quota
    _reset_quota()
    rules = [_quota_rule(applies_to=applies_to)]
    ctx = {"metadata": {}}
    # Call 1: request phase consumes unit 1; response phase only re-checks.
    assert evaluate_policy_rules(rules, "hi", "prompt", ctx)["decision"] == "allow"
    assert evaluate_policy_rules(rules, "resp", "response", ctx)["decision"] == "allow"
    # Call 2 request phase consumes unit 2 of 2 — this would already be
    # blocked if the response phase had double-counted call 1.
    assert evaluate_policy_rules(rules, "hi", "prompt", ctx)["decision"] == "allow"
    # Call 3: limit genuinely reached.
    assert evaluate_policy_rules(rules, "hi", "prompt", ctx)["decision"] == "block"


def test_quota_response_scoped_rule_consumes_in_response_phase():
    from obsvr.rules import _reset_quota
    _reset_quota()
    rules = [_quota_rule(applies_to="response", conditions={"quota_limit": 1})]
    ctx = {"metadata": {}}
    # The request phase never evaluates a response-only rule.
    assert evaluate_policy_rules(rules, "hi", "prompt", ctx)["decision"] == "allow"
    assert evaluate_policy_rules(rules, "resp", "response", ctx)["decision"] == "allow"
    assert evaluate_policy_rules(rules, "resp", "response", ctx)["decision"] == "block"


def test_quota_check_only_never_consumes():
    from obsvr.rules import _reset_quota
    _reset_quota()
    rules = [_quota_rule(conditions={"quota_limit": 1})]
    ctx = {"metadata": {}}
    for _ in range(3):
        assert evaluate_policy_rules(
            rules, "hi", "prompt", ctx, check_only=True
        )["decision"] == "allow"


def test_token_quota_is_separate_from_request_quota():
    from obsvr.rules import increment_quota, _reset_quota
    _reset_quota()
    # A requests-unit rule and a tokens-unit rule with the same scope must not
    # share a counter.
    tok = make_rule(type="quota", action="block", conditions={
        "quota_unit": "tokens", "quota_limit": 10, "quota_window_ms": 60000, "quota_scope": "project"})
    # Consuming request-quota does not touch the token budget.
    increment_quota("project", "project", 1, 60000)
    assert evaluate_policy_rules([tok], "hi", context={"metadata": {}})["decision"] == "allow"
