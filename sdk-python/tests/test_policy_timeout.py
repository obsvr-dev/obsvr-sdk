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

    config = ResolvedConfig(
        api_key="test", on_post_call=slow_post_hook, post_call_timeout_ms=50
    )
    start = time.monotonic()
    result = apply_post_call_policy("response text", {}, config)
    elapsed = time.monotonic() - start
    assert elapsed < WALL_CLOCK_CEILING_S
    assert result["decision"] == "pass"  # timeout keeps the existing decision


def test_post_call_hook_budget_comes_from_its_own_key():
    """The post-call budget is post_call_timeout_ms, not hook_timeout_ms.

    A tiny pre-call budget beside a generous post-call one: the hook's verdict
    must land. Under the wrong key (hook_timeout_ms) the 1ms budget would time
    the hook out and the decision would stay "pass", so this test fails if the
    post-call path ever reads the pre-call key again.
    """

    def flagging_post_hook(resp, event):
        time.sleep(0.15)
        return {"decision": "flag"}

    config = ResolvedConfig(
        api_key="test",
        on_post_call=flagging_post_hook,
        hook_timeout_ms=1,
        post_call_timeout_ms=2000,
    )
    result = apply_post_call_policy("response text", {}, config)
    assert result["decision"] == "flag"


def test_post_call_hook_budget_is_not_the_larger_of_the_two():
    """The inverse direction: a generous pre-call budget must not rescue a
    post-call hook from its own small budget. Kills the max(a, b) mutant the
    test above cannot see."""

    def slow_post_hook(resp, event):
        time.sleep(HOOK_SLEEP_S)
        return {"decision": "redact_response"}

    config = ResolvedConfig(
        api_key="test",
        on_post_call=slow_post_hook,
        hook_timeout_ms=60000,
        post_call_timeout_ms=50,
    )
    start = time.monotonic()
    result = apply_post_call_policy("response text", {}, config)
    elapsed = time.monotonic() - start
    assert elapsed < WALL_CLOCK_CEILING_S
    assert result["decision"] == "pass"
