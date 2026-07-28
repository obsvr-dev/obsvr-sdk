"""The layered cost reaches the record. Twin:
sdk/tests/unit/cost-wiring.test.ts.

The resolution itself is pinned in cost.json; what these pin is that a real
call resolves it from real usage, that all three layers survive to the event
rather than being collapsed to the best one, and that an unconfigured
deployment's events are unchanged.
"""

from typing import Any, Dict, Optional

import obsvr
import sys
from obsvr import sender
from obsvr.config import _reset

WRAP_MODULE = sys.modules["obsvr.wrap"]

# Python's per-call metadata channel is the `obsvr_metadata` kwarg (stripped
# before the request reaches the provider, which would reject an unknown
# parameter); the TypeScript twin reads the same values from the request's
# `metadata` field. Pre-existing and deliberate on both sides - the cost
# estimate simply rides whichever channel each SDK already has.

RATES = {
    "currency": "USD",
    "rates": {"gpt-4": {"input_micros_per_1k": 30_000, "output_micros_per_1k": 60_000}},
}


class _Usage:
    def __init__(self, prompt, completion):
        self.prompt_tokens = prompt
        self.completion_tokens = completion
        self.total_tokens = prompt + completion


class _Message:
    content = "ok"


class _Choice:
    message = _Message()


class _Response:
    def __init__(self, prompt, completion, model="gpt-4"):
        self.choices = [_Choice()]
        self.model = model
        self.usage = _Usage(prompt, completion)


class _Completions:
    def __init__(self, prompt, completion, model="gpt-4"):
        self._args = (prompt, completion, model)
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return _Response(*self._args)


class _Chat:
    def __init__(self, completions):
        self.completions = completions


class _Client:
    def __init__(self, prompt, completion, model="gpt-4"):
        self.chat = _Chat(_Completions(prompt, completion, model))


def _init(monkeypatch, **extra):
    _reset()
    sender._reset_sender()
    captured = []
    extra.setdefault("disabled", False)
    obsvr.init(api_key="k", ingest_url="http://localhost:9", **extra)
    monkeypatch.setattr(WRAP_MODULE, "send_audit_async", lambda cfg, ev: captured.append(ev))
    return captured


def _cost_of(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    return (event.get("metadata") or {}).get("obsvr_cost")


class TestLayeredCostWiring:
    def teardown_method(self):
        _reset()

    def test_meters_real_usage_at_operator_rates(self, monkeypatch):
        captured = _init(monkeypatch, cost_policy=RATES)
        client = obsvr.wrap(_Client(1000, 500))
        client.chat.completions.create(model="gpt-4", messages=[{"role": "user", "content": "hi"}])
        assert _cost_of(captured[0]) == {
            "currency": "USD",
            "metered_micros": 30_000 + 30_000,  # 1000@30k/1k + 500@60k/1k
        }

    def test_keeps_the_caller_estimate_alongside_the_correction(self, monkeypatch):
        captured = _init(monkeypatch, cost_policy=RATES)
        client = obsvr.wrap(_Client(1000, 0))
        client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "hi"}],
            obsvr_metadata={"cost_estimate_micros": 1_000},
        )
        # The estimate was thirty times under. That is exactly the finding the
        # record has to preserve, so both numbers and their difference survive.
        assert _cost_of(captured[0]) == {
            "currency": "USD",
            "estimate_micros": 1_000,
            "estimate_source": "caller",
            "metered_micros": 30_000,
            "delta_micros": 29_000,
        }

    def test_operator_declared_cost_overrides_the_caller(self, monkeypatch):
        policy = dict(RATES)
        policy["declared"] = {"gpt-4": 50_000}
        captured = _init(monkeypatch, cost_policy=policy)
        client = obsvr.wrap(_Client(1000, 0))
        client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "hi"}],
            obsvr_metadata={"cost_estimate_micros": 1_000},
        )
        cost = _cost_of(captured[0])
        assert cost["estimate_micros"] == 50_000
        assert cost["estimate_source"] == "policy"
        assert cost["delta_micros"] == -20_000

    def test_a_caller_cannot_overwrite_the_sealed_cost(self, monkeypatch):
        captured = _init(monkeypatch, cost_policy=RATES)
        client = obsvr.wrap(_Client(1000, 0))
        client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "hi"}],
            obsvr_metadata={"obsvr_cost": {"metered_micros": 1}},
        )
        assert _cost_of(captured[0])["metered_micros"] == 30_000

    def test_no_cost_policy_leaves_events_unchanged(self, monkeypatch):
        captured = _init(monkeypatch)
        client = obsvr.wrap(_Client(1000, 500))
        client.chat.completions.create(model="gpt-4", messages=[{"role": "user", "content": "hi"}])
        assert _cost_of(captured[0]) is None

    def test_an_unpriced_model_gets_no_guess(self, monkeypatch):
        captured = _init(monkeypatch, cost_policy=RATES)
        client = obsvr.wrap(_Client(1000, 0, model="some-unpriced-model"))
        client.chat.completions.create(
            model="some-unpriced-model", messages=[{"role": "user", "content": "hi"}]
        )
        assert _cost_of(captured[0]) is None
