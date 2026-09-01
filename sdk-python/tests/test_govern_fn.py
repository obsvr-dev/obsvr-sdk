import asyncio

import pytest

import obsvr
from obsvr import sender
from obsvr.binding_report import _reset_bindings, integration_bindings
from obsvr.errors import ObsvrPolicyError


@pytest.fixture(autouse=True)
def _fresh_state(monkeypatch):
    obsvr._reset()
    _reset_bindings()
    monkeypatch.setattr(sender, "send_audit_async", lambda _config, _event: None)


def test_govern_decorator_denies_before_entering_the_function():
    obsvr.init(
        api_key="test",
        sample_rate=1,
        agent_policy={"denied_tools": ["contract.send"]},
    )
    calls = []

    @obsvr.govern(name="contract.send", consequence="external_write")
    def send(contract):
        calls.append(contract)
        return contract

    with pytest.raises(ObsvrPolicyError):
        send("nda")
    assert calls == []


def test_govern_fn_applies_redaction_to_the_received_arguments():
    obsvr.init(
        api_key="test",
        sample_rate=1,
        pii_policy={"rules": {"ssn": "redact"}},
    )
    received = []

    def store(value):
        received.append(value)
        return value

    governed = obsvr.govern_fn(store, name="customer.store")
    result = governed("SSN 078-05-1120")
    assert "078-05-1120" not in received[0]
    assert result == received[0]


def test_govern_fn_steers_before_entering_the_application_function():
    obsvr.init(
        api_key="test",
        sample_rate=1,
        policy_rules=[{
            "id": "control:external-write",
            "name": "External writes require review",
            "enabled": True,
            "type": "control",
            "action": "steer",
            "conditions": {
                "expression": {"predicate": {
                    "path": "context.metadata.obsvr_action.name",
                    "operator": "equals",
                    "value": "contract.send",
                }},
                "steering_context": "Route the contract to Legal, then retry.",
            },
        }],
    )
    calls = []
    governed = obsvr.govern_fn(lambda: calls.append("sent"), name="contract.send")

    with pytest.raises(ObsvrPolicyError) as caught:
        governed()
    assert caught.value.steering == {
        "outcome": "MODIFY",
        "guidance": "Route the contract to Legal, then retry.",
    }
    assert caught.value.to_dict()["steering"] == caught.value.steering
    assert calls == []


def test_async_function_and_honest_coverage_binding():
    obsvr.init(api_key="test", sample_rate=1)

    @obsvr.govern(name="record.lookup", surface="workflow")
    async def lookup(value):
        return value + 1

    assert asyncio.run(lookup(3)) == 4
    assert integration_bindings()["govern_fn"]["record.lookup"] | {
        "initialized_at_ms": 0
    } == {
        "bound": True,
        "enforcement_depth": "enforce",
        "initialized_at_ms": 0,
        "exclusions": ["calls through retained raw function aliases"],
    }


def test_direct_decorator_form_is_idempotent_and_validates_names():
    def calculate():
        return 1

    governed = obsvr.govern(calculate)
    assert obsvr.govern(governed) is governed
    with pytest.raises(TypeError, match="name must be a nonblank string"):
        obsvr.govern_fn(lambda: 1, name=" ")
