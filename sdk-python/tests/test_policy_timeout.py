"""Tests for hook timeout and hook error handling."""
import time
import pytest
from obsvr.config import ResolvedConfig
from obsvr.policy import apply_post_call_policy, apply_pre_call_policy

# NB: hung-hook threads are abandoned (shutdown(wait=False)) and joined only
# at interpreter exit, so keep sleeps short enough not to outlive the suite.
HOOK_SLEEP_S = 1.0
# Generous wall-clock ceiling for a 50ms timeout: proves the timeout bounds
# the call (the pre-fix context manager joined the hook for its full runtime).
WALL_CLOCK_CEILING_S = 0.5


def never_resolving_hook(event):
    time.sleep(HOOK_SLEEP_S)  # much longer than timeout
    return "allow"


def throwing_hook(event):
    raise RuntimeError("hook failed")


def test_hook_timeout():
    config = ResolvedConfig(api_key="test", on_pre_call=never_resolving_hook, hook_timeout_ms=50)
    result = apply_pre_call_policy("hello world", config)
    assert result["compliance"]["action_taken"] == "hook_timeout"
    assert result["decision"] == "allow"


def test_hook_error():
    config = ResolvedConfig(api_key="test", on_pre_call=throwing_hook)
    result = apply_pre_call_policy("hello world", config)
    assert result["compliance"]["action_taken"] == "hook_error"
    assert result["decision"] == "allow"


def test_pre_call_hook_timeout_bounds_wall_clock_fail_open():
    config = ResolvedConfig(api_key="test", on_pre_call=never_resolving_hook, hook_timeout_ms=50)
    start = time.monotonic()
    result = apply_pre_call_policy("hello world", config)
    elapsed = time.monotonic() - start
    assert elapsed < WALL_CLOCK_CEILING_S
    assert result["compliance"]["action_taken"] == "hook_timeout"
    assert result["decision"] == "allow"


def test_pre_call_hook_timeout_bounds_wall_clock_fail_closed():
    config = ResolvedConfig(
        api_key="test", on_pre_call=never_resolving_hook,
        hook_timeout_ms=50, fail_mode="closed",
    )
    start = time.monotonic()
    result = apply_pre_call_policy("hello world", config)
    elapsed = time.monotonic() - start
    assert elapsed < WALL_CLOCK_CEILING_S
    assert result["decision"] == "block"
    assert result["compliance"]["action_taken"] == "blocked"
    assert result["compliance"]["policy_reason"] == "hook_timeout (fail_closed)"


def test_post_call_hook_timeout_bounds_wall_clock():
    def slow_post_hook(resp, event):
        time.sleep(HOOK_SLEEP_S)
        return {"decision": "redact_response"}

    config = ResolvedConfig(api_key="test", on_post_call=slow_post_hook, hook_timeout_ms=50)
    start = time.monotonic()
    result = apply_post_call_policy("response text", {}, config)
    elapsed = time.monotonic() - start
    assert elapsed < WALL_CLOCK_CEILING_S
    assert result["decision"] == "pass"  # timeout keeps the existing decision
