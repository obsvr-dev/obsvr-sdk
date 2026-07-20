"""Reserved-reason-registry staleness check (Python side). Twin:
sdk/tests/unit/reason-codes.test.ts.

Mirrors the repo's shared-fixture contract-test pattern: the closed
reason-code registry is pinned in conformance/fixtures/reason_codes.json,
and this suite fails if
  - the Python registry drifts from the fixture (which also guarantees
    TS/Python parity, since the TS twin pins to the same fixture),
  - a PolicyRule type gains no explicit reason-code mapping, or
  - the rules engine can emit a reason_code outside the registry.
"""
import json
from pathlib import Path

import pytest

from obsvr.reason_codes import (
    REASON_CODES,
    RULE_TYPE_TO_REASON_CODE,
    ReasonCode,
    rule_type_to_reason_code,
)
from obsvr.remote import _VALID_TYPES
from obsvr.rules import (
    PolicyRule,
    _reset_quota,
    evaluate_policy_rules,
    evaluate_shadow_rules,
)

FIXTURE = json.loads(
    (Path(__file__).parent / "../../conformance/fixtures/reason_codes.json")
    .resolve()
    .read_text()
)

_REGISTRY = set(REASON_CODES)


def test_registry_matches_fixture():
    enum_values = sorted(rc.value for rc in ReasonCode)
    assert list(REASON_CODES) == enum_values
    # Fixture is the cross-language pin; equality here + in the TS twin
    # guarantees TS and Python never diverge.
    assert list(REASON_CODES) == sorted(FIXTURE["codes"])
    assert sorted(FIXTURE["codes"]) == FIXTURE["codes"]


def test_rule_type_mapping_matches_fixture():
    assert RULE_TYPE_TO_REASON_CODE == FIXTURE["rule_type_to_reason_code"]


def test_every_rule_type_has_explicit_in_registry_mapping():
    for rule_type in _VALID_TYPES:
        code = rule_type_to_reason_code(rule_type)
        assert code != ReasonCode.UNKNOWN_BLOCKED.value
        assert code in _REGISTRY
        assert FIXTURE["rule_type_to_reason_code"][rule_type] == code


def test_fixture_mapping_covers_exactly_enforceable_types():
    assert sorted(FIXTURE["rule_type_to_reason_code"].keys()) == sorted(_VALID_TYPES)


# Matrix firing each verdict path. Every emitted reason_code must be present
# and drawn from the registry; a new engine path emitting an unregistered
# code fails here.
_CASES = [
    ("no match -> permitted", [], "hello", None),
    ("keyword block", [{"id": "k", "name": "k", "enabled": True, "action": "block", "type": "keyword", "conditions": {"keywords": ["trigger"]}}], "a trigger word", None),
    ("regex redact", [{"id": "r", "name": "r", "enabled": True, "action": "redact", "type": "regex", "conditions": {"pattern": "trig+er"}}], "trigger", None),
    ("keyword flag", [{"id": "f", "name": "f", "enabled": True, "action": "flag", "type": "keyword", "conditions": {"keywords": ["trigger"]}}], "trigger", None),
    ("topic_deny block", [{"id": "td", "name": "td", "enabled": True, "action": "block", "type": "topic_deny", "conditions": {"topics": ["trigger"]}}], "trigger", None),
    ("topic_allow allow", [{"id": "ta", "name": "ta", "enabled": True, "action": "flag", "type": "topic_allow", "conditions": {"topics": ["trigger"]}}], "trigger", None),
    ("action_gate block", [{"id": "ag", "name": "ag", "enabled": True, "action": "block", "type": "action_gate", "conditions": {"action_types": ["wire"]}}], "wire", {"action_name": "wire"}),
    ("namespace_isolation block", [{"id": "ns", "name": "ns", "enabled": True, "action": "block", "type": "namespace_isolation", "conditions": {}}], "x", {"caller_namespace": "a", "target_namespace": "b"}),
    ("cross_tenant_block block", [{"id": "ct", "name": "ct", "enabled": True, "action": "block", "type": "cross_tenant_block", "conditions": {}}], "x", {"caller_namespace": "a", "target_namespace": "b"}),
    ("destructive_op_gate block", [{"id": "do", "name": "do", "enabled": True, "action": "block", "type": "destructive_op_gate", "conditions": {"destructive_operations": ["drop table"]}}], "drop table users", None),
    ("source_grounding flag", [{"id": "sg", "name": "sg", "enabled": True, "action": "flag", "type": "source_grounding", "conditions": {"min_grounding_ratio": 0.9}}], "ungrounded claim about the moon", None),
    ("environment_gate block", [{"id": "eg", "name": "eg", "enabled": True, "action": "block", "type": "environment_gate", "conditions": {"target_environments": ["prod"]}}], "x", {"current_environment": "prod"}),
    ("model_gate block", [{"id": "mg", "name": "mg", "enabled": True, "action": "block", "type": "model_gate", "conditions": {"denied_models": ["gpt-4"]}}], "x", {"model": "gpt-4"}),
    ("approval_required block", [{"id": "ap", "name": "ap", "enabled": True, "action": "block", "type": "keyword", "conditions": {"keywords": ["trigger"], "require_approval": True}}], "trigger", None),
]


def _to_rule(r):
    return PolicyRule(
        id=r["id"], name=r["name"], enabled=r["enabled"],
        action=r["action"], type=r["type"],
        conditions=r.get("conditions", {}),
        applies_to=r.get("applies_to"), mode=r.get("mode"),
    )


@pytest.mark.parametrize("label,rules,text,context", _CASES, ids=[c[0] for c in _CASES])
def test_engine_emits_only_registry_codes(label, rules, text, context):
    result = evaluate_policy_rules([_to_rule(r) for r in rules], text, "prompt", context)
    assert result.get("reason_code") is not None
    assert result["reason_code"] in _REGISTRY


def test_quota_exhaustion_emits_quota_exceeded():
    _reset_quota()
    rule = _to_rule({
        "id": "q", "name": "q", "enabled": True, "action": "block", "type": "quota",
        "conditions": {"quota_limit": 1, "quota_window_ms": 60000, "quota_scope": "project"},
    })
    evaluate_policy_rules([rule], "x")  # consume the single unit
    blocked = evaluate_policy_rules([rule], "x")
    assert blocked["decision"] == "block"
    assert blocked["reason_code"] == ReasonCode.QUOTA_EXCEEDED.value
    assert blocked["reason_code"] in _REGISTRY


def test_shadow_outcome_emits_shadow_would_block():
    shadow = evaluate_shadow_rules(
        [_to_rule({"id": "s", "name": "s", "enabled": True, "mode": "shadow", "action": "block", "type": "keyword", "conditions": {"keywords": ["trigger"]}})],
        "trigger",
        "prompt",
    )
    assert shadow["reason_code"] == ReasonCode.SHADOW_WOULD_BLOCK.value
    assert shadow["reason_code"] in _REGISTRY
