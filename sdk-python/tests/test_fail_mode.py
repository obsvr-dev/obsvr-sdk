"""fail_mode ('open' | 'closed') parity tests for the Python SDK.

Mirrors sdk/tests/unit/fail-mode.test.ts. Default is 'open' (hook
timeout/error -> allow); 'closed' blocks on hook failure.
"""
import time

import obsvr
from obsvr.config import get_config
from obsvr.policy import apply_pre_call_policy


def _reset():
    obsvr._reset() if hasattr(obsvr, "_reset") else None
    from obsvr.config import _reset as cfg_reset
    cfg_reset()


class TestFailModeDefaultOpen:
    def test_defaults_to_open(self):
        _reset()
        obsvr.init(api_key="test")
        assert get_config().fail_mode == "open"

    def test_allows_on_hook_timeout(self):
        _reset()

        def slow_hook(_event):
            time.sleep(1.0)
            return "allow"

        obsvr.init(api_key="test", hook_timeout_ms=50, on_pre_call=slow_hook)
        result = apply_pre_call_policy("hello", get_config(), provider="openai", operation="chat")
        assert result["decision"] == "allow"

    def test_allows_on_hook_error(self):
        _reset()

        def bad_hook(_event):
            raise RuntimeError("hook exploded")

        obsvr.init(api_key="test", on_pre_call=bad_hook)
        result = apply_pre_call_policy("hello", get_config(), provider="openai", operation="chat")
        assert result["decision"] == "allow"
        assert result["compliance"]["action_taken"] == "hook_error"

    def test_hook_error_does_not_unblock_builtin_pii_block(self):
        # a broken hook must NOT downgrade a builtin PII block in fail-open.
        _reset()

        def bad_hook(_event):
            raise RuntimeError("hook exploded")

        obsvr.init(api_key="test", pii_policy={}, on_pre_call=bad_hook)  # ssn defaults to block
        result = apply_pre_call_policy(
            "my ssn is 123-45-6789", get_config(), provider="openai", operation="chat"
        )
        assert result["decision"] == "block"
        assert result["compliance"]["action_taken"] == "blocked"


class TestFailModeClosed:
    def test_carried_through_config(self):
        _reset()
        obsvr.init(api_key="test", fail_mode="closed")
        assert get_config().fail_mode == "closed"

    def test_blocks_on_hook_timeout(self):
        _reset()

        def slow_hook(_event):
            time.sleep(1.0)
            return "allow"

        obsvr.init(api_key="test", fail_mode="closed", hook_timeout_ms=50, on_pre_call=slow_hook)
        result = apply_pre_call_policy("hello", get_config(), provider="openai", operation="chat")
        assert result["decision"] == "block"

    def test_blocks_on_hook_error(self):
        _reset()

        def bad_hook(_event):
            raise RuntimeError("boom")

        obsvr.init(api_key="test", fail_mode="closed", on_pre_call=bad_hook)
        result = apply_pre_call_policy("hello", get_config(), provider="openai", operation="chat")
        assert result["decision"] == "block"

    def test_normal_verdict_unaffected(self):
        _reset()
        obsvr.init(api_key="test", fail_mode="closed", on_pre_call=lambda _e: "allow")
        result = apply_pre_call_policy("hello", get_config(), provider="openai", operation="chat")
        assert result["decision"] == "allow"


class TestKillSwitchNotHookOverridable:
    """EV-3: an enforcement-integrity gate block (paused project / revoked key /
    fail-closed staleness) must NOT be overridable by the customer hook. Mirrors
    the TS wrapper's `!degraded.degraded` guard. Regression test for the P0."""

    def test_allow_hook_cannot_override_kill_switch(self):
        from unittest.mock import patch

        _reset()
        obsvr.init(api_key="test", on_pre_call=lambda _e: "allow")
        with patch(
            "obsvr.remote.is_enforcement_degraded",
            return_value={"degraded": True, "reason": "project_paused_or_key_revoked"},
        ):
            result = apply_pre_call_policy(
                "hello", get_config(), provider="openai", operation="chat"
            )
        assert result["decision"] == "block"
        assert result["compliance"]["action_taken"] == "blocked"
        assert result["compliance"]["action_reason"] != "customer_override"
        # Gate blocks are labeled policy_rules (parity with both TS paths).
        assert result["compliance"]["action_source"] == "policy_rules"
        assert result["compliance"]["rule_id"] == "sdk:project_paused_or_key_revoked"

    def test_hook_still_runs_when_not_degraded(self):
        from unittest.mock import patch

        _reset()
        obsvr.init(api_key="test", on_pre_call=lambda _e: "block")
        with patch(
            "obsvr.remote.is_enforcement_degraded",
            return_value={"degraded": False, "reason": None},
        ):
            result = apply_pre_call_policy(
                "hello", get_config(), provider="openai", operation="chat"
            )
        assert result["decision"] == "block"
        assert result["compliance"]["action_source"] == "customer_hook"


# ── Central failure-disposition registry ─────────────────────────────────────
#
# The registry declares what every governance layer does when it cannot render
# a verdict. These tests assert three things: the Python registry matches the
# shared fixture (which the TypeScript twin also pins to, so this is the parity
# check), every detector module has a declaration (so a new detector cannot land
# without stating its posture), and the declarations match what the code
# actually does for every state a unit test can drive.

import json
from pathlib import Path

from obsvr.failure_dispositions import (
    DECLARED_LAYER_IDS,
    FAILURE_DISPOSITIONS,
    disposition_for,
    get_failure_disposition,
    unguarded_layer_ids,
)

FIXTURE_PATH = (
    Path(__file__).parent / "../../conformance/fixtures/fail_mode.json"
).resolve()


def _fixture():
    with open(FIXTURE_PATH) as f:
        return json.load(f)


class TestRegistryPinnedToFixture:
    def test_declares_exactly_the_pinned_layers_in_order(self):
        assert DECLARED_LAYER_IDS == [layer["id"] for layer in _fixture()["layers"]]

    def test_matches_the_fixture_on_every_field(self):
        for expected in _fixture()["layers"]:
            entry = get_failure_disposition(expected["id"])
            assert entry is not None, expected["id"]
            assert entry["module"] == expected["module_py"], expected["id"]
            assert entry["hook_overridable"] == expected["hook_overridable"], expected["id"]
            assert entry["notes"] == expected["notes"], expected["id"]
            for state in _fixture()["vocabulary"]["states"]:
                assert entry[state] == expected[state], f"{expected['id']}.{state}"

    def test_every_layer_declares_all_states_with_pinned_vocabulary(self):
        vocab = _fixture()["vocabulary"]
        for entry in FAILURE_DISPOSITIONS:
            for state in vocab["states"]:
                declared = entry[state]
                assert declared["disposition"] in vocab["dispositions"]
                if declared.get("qualifier"):
                    assert declared["qualifier"] in vocab["qualifiers"]

    def test_no_duplicate_layer_ids(self):
        assert len(set(DECLARED_LAYER_IDS)) == len(DECLARED_LAYER_IDS)


class TestRegistryGate:
    """Modules that are NOT governance layers and need no declaration. Adding a
    name here is a deliberate statement that it decides nothing; adding a
    detector without a declaration fails this gate."""

    NON_DETECTOR_MODULES = {
        "__init__.py",
        "_version.py",
        "agent_run.py",
        "auto.py",
        "cli_verify.py",
        "config.py",
        "decision_record.py",
        "errors.py",
        "escrow.py",
        "events.py",
        "failure_dispositions.py",
        "instance_guard.py",
        "normalize.py",
        "otel_mirror.py",
        "pii_types.py",
        "policy_log.py",
        "reason_codes.py",
        "register.py",
        "safe_regex.py",
        "sender.py",
        "span.py",
        "span_attributes.py",
        "ssrf.py",
        "verify_chain.py",
        "wrap.py",
    }

    def test_every_detector_module_is_declared(self):
        pkg_dir = Path(__file__).parent.parent / "obsvr"
        declared = {Path(str(e["module"])).name for e in FAILURE_DISPOSITIONS}
        undeclared = sorted(
            p.name
            for p in pkg_dir.glob("*.py")
            if p.name not in self.NON_DETECTOR_MODULES and p.name not in declared
        )
        assert undeclared == [], (
            f"detector modules with no failure disposition declared: {undeclared}"
        )

    def test_no_layer_lets_its_failure_escape_to_the_host(self):
        """This list was the eight in-process layers with no error channel at
        all. Every one is now guarded, so the correct assertion is that the
        list is EMPTY - and it stays a tripwire in the other direction: a new
        detector that ships without an error channel, or a guard someone
        removes, turns this red rather than passing unnoticed."""
        assert unguarded_layer_ids() == []


class TestDeclarationsMatchObservedBehavior:
    def test_customer_hook_is_fail_mode_and_behaves_that_way(self):
        assert disposition_for("customer_hook", "timeout") == {"disposition": "fail_mode"}
        assert disposition_for("customer_hook", "error") == {"disposition": "fail_mode"}

        def boom(_event):
            raise RuntimeError("hook exploded")

        _reset()
        obsvr.init(api_key="test", on_pre_call=boom)
        assert apply_pre_call_policy(
            "hello", get_config(), provider="openai", operation="chat"
        )["decision"] == "allow"

        _reset()
        obsvr.init(api_key="test", fail_mode="closed", on_pre_call=boom)
        assert apply_pre_call_policy(
            "hello", get_config(), provider="openai", operation="chat"
        )["decision"] == "block"

    def test_external_backend_is_closed_with_a_shadow_exemption(self, monkeypatch):
        assert disposition_for("external_backend", "error") == {
            "disposition": "closed",
            "qualifier": "shadow_exempt",
        }
        from obsvr import external_backend as eb

        def boom(*_a):
            raise RuntimeError("ECONNREFUSED")

        backend = {"type": "opa", "url": "https://8.8.8.8/v1/data/obsvr/allow"}

        _reset()
        monkeypatch.setattr(eb, "_urllib_transport", boom)
        obsvr.init(api_key="t", external_policy_backend=dict(backend))
        assert apply_pre_call_policy(
            "hello world", get_config(), provider="openai", operation="chat.completions.create"
        )["decision"] == "block"

        _reset()
        obsvr.init(api_key="t", external_policy_backend={**backend, "shadow": True})
        assert apply_pre_call_policy(
            "hello world", get_config(), provider="openai", operation="chat.completions.create"
        )["decision"] == "allow"

    def test_integrity_gate_is_closed_when_degraded(self):
        from unittest.mock import patch

        assert disposition_for("enforcement_integrity_gate", "degraded") == {
            "disposition": "closed"
        }
        _reset()
        obsvr.init(api_key="test")
        with patch(
            "obsvr.remote.is_enforcement_degraded",
            return_value={"degraded": True, "reason": "project_paused_or_key_revoked"},
        ):
            assert apply_pre_call_policy(
                "hello", get_config(), provider="openai", operation="chat"
            )["decision"] == "block"

    def test_a_detector_defect_resolves_instead_of_reaching_the_caller(self, monkeypatch):
        """This test used to assert the opposite. The declaration said an
        exception escaped to the host, and its docstring said that the day
        someone added a guard, this test would tell them to update the table.
        That is what happened, so the assertion is inverted rather than
        deleted: the same injected defect must now resolve."""
        from obsvr import policy as policy_mod
        from obsvr.policy import get_detector_error_count

        assert disposition_for("builtin_pii_scan", "error") == {
            "disposition": "fail_mode",
            "qualifier": "redaction_application_closed",
        }

        def boom(*_a, **_k):
            raise RuntimeError("detector bug")

        _reset()
        obsvr.init(api_key="test", pii_policy={"action": "block", "types": ["email"]})
        monkeypatch.setattr(policy_mod, "run_builtin_pii_scan", boom)
        res = apply_pre_call_policy(
            "hello a@b.com", get_config(), provider="openai", operation="chat"
        )
        assert res["decision"] == "allow"
        assert res["compliance"]["rule_id"] == "sdk:detector_error"
        assert get_detector_error_count() == 1

        # And closed when the operator opted in.
        _reset()
        obsvr.init(api_key="test", fail_mode="closed",
                   pii_policy={"action": "block", "types": ["email"]})
        monkeypatch.setattr(policy_mod, "run_builtin_pii_scan", boom)
        assert apply_pre_call_policy(
            "hello a@b.com", get_config(), provider="openai", operation="chat"
        )["decision"] == "block"
