"""Cross-SDK layered-cost conformance (Python side). Twin:
sdk-typescript/tests/unit/cost-conformance.test.ts.

The amounts are integer micro-units and the rounding rule is written out in
both languages rather than delegated to a built-in, so these cases are exact: a
difference of one micro-unit between the SDKs fails here.
"""

import json
from pathlib import Path

import pytest

from obsvr.cost import (
    cost_metadata,
    longest_prefix_key,
    price_tokens,
    resolve_call_cost,
)

FIXTURE = json.loads(
    (Path(__file__).parent / "../../conformance/fixtures/cost.json")
    .resolve()
    .read_text(encoding="utf-8")
)

RESOLVE_CASES = FIXTURE["resolve_cases"]
PRICE_CASES = FIXTURE["price_cases"]
METADATA_CASES = FIXTURE["metadata_cases"]


@pytest.mark.parametrize("case", RESOLVE_CASES, ids=[c["id"] for c in RESOLVE_CASES])
def test_layered_cost_resolution(case):
    assert resolve_call_cost(**case["inputs"]) == case["expect"]


@pytest.mark.parametrize("case", PRICE_CASES, ids=[c["id"] for c in PRICE_CASES])
def test_rate_arithmetic(case):
    assert price_tokens(case["tokens"], case["micros_per_1k"]) == case["expect"]


@pytest.mark.parametrize("case", METADATA_CASES, ids=[c["id"] for c in METADATA_CASES])
def test_what_reaches_the_event(case):
    assert cost_metadata(case["cost"]) == case["expect"]


class TestPropertiesTheCasesRestOn:
    def test_longest_matching_prefix_is_chosen_and_unique(self):
        table = {"gpt": 1, "gpt-4": 2, "gpt-4o": 3}
        assert longest_prefix_key(table, "gpt-4o-mini") == "gpt-4o"
        assert longest_prefix_key(table, "gpt-4-turbo") == "gpt-4"
        assert longest_prefix_key(table, "gpt-3.5") == "gpt"
        assert longest_prefix_key(table, "claude-3") is None
        assert longest_prefix_key(None, "gpt-4") is None
        assert longest_prefix_key(table, "") is None

    def test_an_empty_key_never_matches(self):
        # It would match everything.
        assert longest_prefix_key({"": 1, "gpt": 2}, "gpt-4") == "gpt"
        assert longest_prefix_key({"": 1}, "anything") is None

    def test_delta_present_only_when_both_halves_are(self):
        policy = {"currency": "USD", "rates": {"m": {"input_micros_per_1k": 1000}}}
        assert "delta_micros" not in resolve_call_cost(
            policy=policy, model="m", input_tokens=1000
        )
        assert "delta_micros" not in resolve_call_cost(caller_estimate_micros=5)
        assert (
            resolve_call_cost(
                policy=policy, model="m", input_tokens=1000, caller_estimate_micros=5
            )["delta_micros"]
            == 995
        )

    def test_keeps_the_estimate_alongside_the_correction(self):
        # The whole argument for this living in an evidence product: the gap is
        # only auditable if both numbers survive to the record.
        result = resolve_call_cost(
            policy={"currency": "USD", "rates": {"m": {"input_micros_per_1k": 1000}}},
            model="m",
            input_tokens=10_000,
            caller_estimate_micros=100,
        )
        assert result["estimate_micros"] == 100
        assert result["metered_micros"] == 10_000
        assert result["delta_micros"] == 9_900

    def test_is_pure(self):
        kwargs = dict(
            policy={"currency": "USD", "rates": {"m": {"input_micros_per_1k": 7}}},
            model="m",
            input_tokens=123,
            caller_estimate_micros=1,
        )
        assert resolve_call_cost(**kwargs) == resolve_call_cost(**kwargs)
