"""Cost and token-quota metering on the framework-integration path, opt-in.

Twin of sdk-typescript/tests/unit/meter-integration-events.test.ts.

The wrap() client-proxy path has always metered. This one never has — the
integration event builder called neither half — so every framework integration
(LangChain, LlamaIndex, the agent frameworks) has been invisible to cost
reporting and to token budgets since it shipped.

That is deliberately NOT fixed unconditionally. A ``quota_unit: "tokens"``
budget that has never bound on framework traffic would begin binding, and calls
that previously succeeded would start being blocked once the budget was reached.
For someone already running a token quota that is an outage, not a fix. So the
default is off, and these tests pin BOTH halves: that off changes nothing, and
that on produces real figures.
"""

import obsvr
from obsvr import sender
from obsvr.config import _reset, get_config
from obsvr.cost import COST_METADATA_KEY
from obsvr.events import build_audit_event
from obsvr.rules import PolicyRule, _reset_quota, check_token_budget

COST_POLICY = {
    "rates": {"gpt-4o-mini": {"input_micros_per_1k": 150, "output_micros_per_1k": 600}}
}

# A real PolicyRule, not a dict: the metering reader inspects rule attributes,
# and a dict here would be silently skipped rather than exercising the path.
TOKEN_QUOTA_RULE = PolicyRule(
    id="tokens-per-user",
    name="token budget",
    enabled=True,
    action="block",
    type="quota",
    conditions={
        "quota_unit": "tokens",
        "quota_limit": 1000,
        "quota_window_ms": 60_000,
        "quota_scope": "user_id",
    },
)


def _init(**extra):
    _reset()
    sender._reset_sender()
    _reset_quota()
    obsvr.init(api_key="k", ingest_url="http://localhost:9", sample_rate=1, **extra)


def _build_event(success=True):
    return build_audit_event(
        get_config(),
        provider="openai",
        model="gpt-4o-mini",
        operation="llm",
        source="langchain",
        prompt="what is 2+2",
        response="four",
        input_tokens=1000,
        output_tokens=500,
        total_tokens=1500,
        success=success,
        options={"user_id": "alice"},
    )


def _cost_fragment(event):
    """The cost fragment rides one reserved metadata key."""
    return (event.get("metadata") or {}).get(COST_METADATA_KEY)


class TestDefaultIsUnmetered:
    def test_no_cost_fragment_even_with_a_cost_policy(self):
        _init(cost_policy=COST_POLICY)
        assert get_config().meter_integration_events is False
        assert _cost_fragment(_build_event()) is None

    def test_no_quota_increment_so_a_budget_never_binds(self):
        _init(policy_rules=[TOKEN_QUOTA_RULE])
        # Four events at 1500 tokens each: four times the 1000-token budget.
        for _ in range(4):
            _build_event()
        verdict = check_token_budget("user_id", "alice", 1000, 60_000)
        assert verdict["allowed"] is True
        assert verdict["remaining"] == 1000


class TestFlagOnMetersLikeTheProxyPath:
    def test_stamps_a_metered_cost_from_the_reported_counts(self):
        _init(cost_policy=COST_POLICY, meter_integration_events=True)
        fragment = _cost_fragment(_build_event())
        assert fragment is not None
        # 1000 input @150/1k + 500 output @600/1k = 150 + 300 = 450 micros.
        assert fragment["metered_micros"] == 450

    def test_increments_the_token_quota_so_the_budget_starts_binding(self):
        _init(policy_rules=[TOKEN_QUOTA_RULE], meter_integration_events=True)
        assert check_token_budget("user_id", "alice", 1000, 60_000)["remaining"] == 1000
        _build_event()  # 1500 tokens, over the 1000 budget
        after = check_token_budget("user_id", "alice", 1000, 60_000)
        assert after["remaining"] == 0
        assert after["allowed"] is False  # the budget now binds

    def test_meters_nothing_when_neither_half_is_configured(self):
        # The flag only removes the path-level block; the two halves stay
        # independently configured, so enabling it alone changes no event.
        _init(meter_integration_events=True)
        assert _cost_fragment(_build_event()) is None

    def test_a_failed_call_is_not_counted_against_the_budget(self):
        _init(policy_rules=[TOKEN_QUOTA_RULE], meter_integration_events=True)
        _build_event(success=False)
        assert check_token_budget("user_id", "alice", 1000, 60_000)["remaining"] == 1000
