"""Tests for policy change audit log."""
from datetime import datetime, timezone, timedelta
import pytest
from obsvr.rules import PolicyRule
from obsvr.policy_log import (
    snapshot_policy, get_policy_at_time,
    emit_policy_changed_event, _reset_policy_log
)
import obsvr


def setup_function():
    obsvr._reset()
    _reset_policy_log()


def test_snapshot_and_retrieve():
    rules = [PolicyRule(id="r1", name="test", enabled=True, action="block", type="keyword", conditions={"keywords": ["bad"]})]
    snapshot_policy(rules)
    future = datetime.now(timezone.utc) + timedelta(seconds=1)
    snap = get_policy_at_time(future)
    assert snap is not None
    assert '"r1"' in snap.rules_snapshot


def test_policy_changed_event_structure():
    rules = [PolicyRule(id="r1", name="block-bad", enabled=True, action="block", type="keyword", conditions={"keywords": ["bad"]})]
    event = emit_policy_changed_event([], rules, "tenant1", "admin")
    assert event.event_type == "policy_changed"
    assert event.tenant_id == "tenant1"
    assert "r1" in event.diff["added"]
    assert event.previous_version == "none"
    assert event.new_version != "none"


def test_get_policy_at_time_before_snapshot():
    past = datetime.now(timezone.utc) - timedelta(days=1)
    assert get_policy_at_time(past) is None


def test_emit_policy_changed_event_is_well_formed():
    # the event carries the ingest wire fields so it is ACCEPTED, not 400'd.
    from dataclasses import asdict
    rules = [PolicyRule(id="r1", name="t", enabled=True, action="block", type="keyword", conditions={"keywords": ["x"]})]
    ev = emit_policy_changed_event([], rules, "tenant1", "admin")
    d = asdict(ev)
    assert d["event_type"] == "policy_changed"
    assert d["request_id"]              # present (uuid)
    assert d["model"] == ""             # required by ingest schema
    assert d["policy_version"] == d["new_version"]
    assert d["metadata"]["policy_change"]["changed_by"] == "admin"


def test_set_tenant_policy_sends_policy_changed_event(monkeypatch):
    # the event is actually delivered (was built and dropped).
    import obsvr.config as cfgmod
    from obsvr import policy_log
    obsvr.init(api_key="k", ingest_url="https://ingest.example")
    sent = []
    monkeypatch.setattr(policy_log, "send_policy_event", lambda ev, url, key: sent.append((ev, url, key)))
    rules = [PolicyRule(id="r1", name="t", enabled=True, action="block", type="keyword", conditions={"keywords": ["x"]})]
    cfgmod.set_tenant_policy("tenant1", rules, "admin")
    assert len(sent) == 1
    assert sent[0][1] == "https://ingest.example"
