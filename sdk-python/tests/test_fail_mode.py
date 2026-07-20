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
