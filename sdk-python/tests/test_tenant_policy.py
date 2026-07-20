"""Tests for per-tenant policy isolation."""
import pytest
from obsvr.config import ResolvedConfig, set_tenant_policy, get_tenant_config
from obsvr.policy import apply_pre_call_policy
from obsvr.rules import PolicyRule
import obsvr


def setup_function():
    obsvr._reset()


def test_tenant_sees_own_rules():
    obsvr.init(api_key="test")
    rules_a = [PolicyRule(id="r1", name="block-a", enabled=True, action="block", type="keyword", conditions={"keywords": ["tenantA-secret"]})]
    rules_b = [PolicyRule(id="r2", name="block-b", enabled=True, action="block", type="keyword", conditions={"keywords": ["tenantB-secret"]})]
    set_tenant_policy("tenantA", rules_a)
    set_tenant_policy("tenantB", rules_b)

    from obsvr.config import get_config
    result_a = apply_pre_call_policy("tenantA-secret text", get_config(), tenant_id="tenantA")
    assert result_a["decision"] == "block"

    result_b = apply_pre_call_policy("tenantA-secret text", get_config(), tenant_id="tenantB")
    assert result_b["decision"] == "allow"


def test_global_config_unchanged():
    obsvr.init(api_key="test")
    set_tenant_policy("t1", [PolicyRule(id="r1", name="x", enabled=True, action="block", type="keyword", conditions={"keywords": ["x"]})])
    from obsvr.config import get_config
    assert get_config().policy_rules is None
