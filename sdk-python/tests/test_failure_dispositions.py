"""The two customer-hook rows of the failure-disposition registry.

The request-phase hook resolves timeout and error by the configured fail_mode.
The response-phase hook cannot: the provider has already answered when it
runs, so a hook that times out or throws leaves standing whatever decision the
response layers already rendered, and only the hook's own verdict is lost for
the call. The registry declares the two phases as separate rows because they
answer the failure question differently; these tests hold each row to the
behavior it declares. Registry-vs-fixture equality is asserted by
test_fail_mode.py; the TS twin rows live in
sdk-typescript/src/policy/failure-dispositions.ts.
"""
import time

from obsvr.config import ResolvedConfig
from obsvr.failure_dispositions import disposition_for
from obsvr.policy import apply_post_call_policy
from obsvr.rules import PolicyRule


def _response_block_rule():
    return PolicyRule(
        id="r-resp-block", name="Block leaked codenames", enabled=True,
        action="block", type="keyword",
        conditions={"keywords": ["aurora"]}, applies_to="response",
    )


def _config(hook, fail_mode="open"):
    # Both timeout keys are set so the budget is 50ms whichever key the
    # post-call path reads.
    return ResolvedConfig(
        api_key="test",
        policy_rules=[_response_block_rule()],
        on_post_call=hook,
        fail_mode=fail_mode,
        hook_timeout_ms=50,
        post_call_timeout_ms=50,
    )


class TestPostCallHookRow:
    def test_the_row_declares_open_in_both_failure_states(self):
        assert disposition_for("customer_hook_post_call", "timeout") == {
            "disposition": "open"
        }
        assert disposition_for("customer_hook_post_call", "error") == {
            "disposition": "open"
        }

    def test_the_request_phase_row_still_declares_fail_mode(self):
        assert disposition_for("customer_hook", "timeout") == {"disposition": "fail_mode"}
        assert disposition_for("customer_hook", "error") == {"disposition": "fail_mode"}

    def test_a_hook_error_keeps_the_rendered_decision(self):
        def boom(_resp, _event):
            raise RuntimeError("hook exploded")

        result = apply_post_call_policy("the codename is aurora", {}, _config(boom))
        assert result["decision"] == "redact_response"

    def test_a_hook_timeout_keeps_the_rendered_decision(self):
        def slow(_resp, _event):
            time.sleep(1.0)
            return {"decision": "flag"}

        result = apply_post_call_policy("the codename is aurora", {}, _config(slow))
        assert result["decision"] == "redact_response"

    def test_fail_mode_closed_is_not_consulted_on_this_path(self):
        # The declared point of the row: unlike the request phase, closing the
        # fail mode does not turn a response-phase hook failure into a block.
        # The already-rendered decision stands either way.
        def boom(_resp, _event):
            raise RuntimeError("hook exploded")

        result = apply_post_call_policy(
            "the codename is aurora", {}, _config(boom, fail_mode="closed")
        )
        assert result["decision"] == "redact_response"

    def test_a_clean_response_with_a_failing_hook_passes_open(self):
        def boom(_resp, _event):
            raise RuntimeError("hook exploded")

        result = apply_post_call_policy("a clean answer", {}, _config(boom))
        assert result["decision"] == "pass"
        # ...even when the operator opted into fail-closed: the hook's own
        # verdict is the only thing lost.
        result = apply_post_call_policy(
            "a clean answer", {}, _config(boom, fail_mode="closed")
        )
        assert result["decision"] == "pass"
