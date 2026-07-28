"""Layered call cost (twin of sdk-typescript/src/governance/cost.ts).

Three layers, each overriding the one before it, and ALL of them retained:

1. **Caller/tool estimate** - what the caller said the call would cost.
2. **Policy mapping** - what the operator declares it costs, which overrides
   layer 1. A tool's own claim about its cost is a claim by the party being
   governed, so an operator who has written a number wins.
3. **Runtime metering** - actual provider-reported usage priced at the
   operator's own rates, available only after the call answers.

The reason to keep all three rather than collapse to the best one is the whole
reason this belongs in an evidence product: **the gap between what was expected
and what was spent is itself a finding.** A tool that consistently estimates an
order of magnitude under its metered cost is either broken or lying, and a
record that kept only the corrected figure cannot tell you which. So the event
carries the estimate, the metered value, and their signed difference.

No price list ships here
------------------------

There is no vendored table of provider prices, and there will not be. Prices
change on the vendor's schedule, not this package's, and a stale rate baked
into a released SDK produces a *sealed* wrong number - worse than no number at
all, because sealed evidence cannot be reissued. Rates are declared by the
operator, in their own configuration.

Integer micro-units, not floating point
---------------------------------------

Every amount here is an INTEGER count of millionths of a currency unit. Money
computed in binary floating point does not agree between two runtimes at the
edges, and "the two SDKs seal amounts that differ in the last place" is not a
defect an evidence product can carry. Integer arithmetic with a stated rounding
rule (half-up on the final division, applied once) is identical in both
languages and is fixture-pinnable to the unit.
"""

from __future__ import annotations

import math
from typing import Any, Dict, Optional

__all__ = [
    "COST_METADATA_KEY",
    "longest_prefix_key",
    "price_tokens",
    "resolve_call_cost",
    "cost_metadata",
    "resolve_cost_policy",
]

#: Reserved-metadata key the resolved cost rides on.
COST_METADATA_KEY = "obsvr_cost"

_MAX_SAFE_INT = 2**53 - 1


def _as_micros(value: Any) -> Optional[int]:
    """A finite, non-negative integer, or None. Everything else is rejected."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer():
            return None
        value = int(value)
    if value < 0 or abs(value) > _MAX_SAFE_INT:
        return None
    return int(value)


_as_tokens = _as_micros


def longest_prefix_key(table: Optional[Dict[str, Any]], subject: str) -> Optional[str]:
    """The longest key of ``table`` that ``subject`` starts with, or None.

    Deterministic: the longest prefix of a given string is unique among
    distinct keys, so no tie-break is needed and none is invented.
    """
    if not table or not subject:
        return None
    best: Optional[str] = None
    for key in table:
        if not key or not subject.startswith(key):
            continue
        if best is None or len(key) > len(best):
            best = key
    return best


def price_tokens(tokens: int, micros_per_1k: int) -> int:
    """Price a token count at a per-1,000 rate, in integer micro-units.

    Rounding is HALF-UP on the single final division, applied once, so the two
    languages cannot drift: ``(tokens * rate + 500) // 1000`` over non-negative
    integers. Python's ``round()`` is banker's rounding and JavaScript's
    ``Math.round`` is half-up-toward-positive-infinity, so neither built-in is
    used on either side.
    """
    return (tokens * micros_per_1k + 500) // 1000


def resolve_call_cost(
    policy: Optional[Dict[str, Any]] = None,
    model: Optional[str] = None,
    action_name: Optional[str] = None,
    caller_estimate_micros: Any = None,
    input_tokens: Any = None,
    output_tokens: Any = None,
) -> Dict[str, Any]:
    """Resolve the layered cost of one call.

    Pure: no clock, no I/O, no per-process state, so the same inputs always
    yield the same result. Pinned by conformance/fixtures/cost.json.

    An absent layer is absent from the result rather than defaulted to zero: a
    cost of zero and an unknown cost are different facts, and an evidence
    product that renders the second as the first is lying quietly.
    """
    policy = policy or {}
    out: Dict[str, Any] = {}
    currency = policy.get("currency")
    if isinstance(currency, str) and currency:
        out["currency"] = currency

    # Layers 1 and 2. Later overrides earlier: the operator's declared number
    # beats whatever the caller claimed, because the caller is the party being
    # governed and its own cost claim is not evidence about itself.
    caller_estimate = _as_micros(caller_estimate_micros)
    if caller_estimate is not None:
        out["estimate_micros"] = caller_estimate
        out["estimate_source"] = "caller"
    declared_table = policy.get("declared")
    declared_key = longest_prefix_key(declared_table, action_name or "") or (
        longest_prefix_key(declared_table, model or "")
    )
    if declared_key is not None:
        declared = _as_micros((declared_table or {}).get(declared_key))
        if declared is not None:
            out["estimate_micros"] = declared
            out["estimate_source"] = "policy"

    # Layer 3: what it actually cost, at the operator's own rates.
    rates = policy.get("rates")
    rate_key = longest_prefix_key(rates, model or "")
    rate = (rates or {}).get(rate_key) if rate_key is not None else None
    if isinstance(rate, dict):
        in_tokens = _as_tokens(input_tokens)
        out_tokens = _as_tokens(output_tokens)
        in_rate = _as_micros(rate.get("input_micros_per_1k"))
        out_rate = _as_micros(rate.get("output_micros_per_1k"))
        metered: Optional[int] = None
        if in_tokens is not None and in_rate is not None:
            metered = price_tokens(in_tokens, in_rate)
        if out_tokens is not None and out_rate is not None:
            metered = (metered or 0) + price_tokens(out_tokens, out_rate)
        if metered is not None:
            out["metered_micros"] = metered

    if "estimate_micros" in out and "metered_micros" in out:
        out["delta_micros"] = out["metered_micros"] - out["estimate_micros"]
    return out


def cost_metadata(cost: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """The metadata fragment carrying the resolved cost, empty when nothing
    resolved.

    Spread it LAST at every emission site, after caller-supplied metadata, so a
    key collision cannot overwrite it - the same precedence the tool-content and
    pin stamps already use. It rides reserved ``obsvr_*`` metadata rather than a
    top-level field for the reason the tool-content hash does: the ingest wire
    schema has no column for it yet, and an unknown top-level field is stripped.
    """
    if not cost:
        return {}
    keys = list(cost.keys())
    # A currency alone says nothing about this call; it is a unit with no value.
    if keys == ["currency"]:
        return {}
    return {COST_METADATA_KEY: cost}


def resolve_cost_policy(config: Any) -> Optional[Dict[str, Any]]:
    """Resolve the cost sub-config (absent/empty => None)."""
    c = getattr(config, "cost_policy", None)
    if not isinstance(c, dict):
        return None
    has_rates = bool(c.get("rates"))
    has_declared = bool(c.get("declared"))
    if not has_rates and not has_declared:
        return None
    return c
