"""Post-call metering: what a governed call cost, and what it consumed against
a token budget. Twin of sdk-typescript/src/governance/metering.ts.

These two run together or not at all. Metering the cost of a call without
counting it against its token budget produces an audit record that disagrees
with itself — a cost figure the budget it belongs to has never heard of — and a
governance record that contradicts itself is worse than one that is silent.
That is why they live in one module behind one call, and why the config flag
gating them for the framework-integration path is a single boolean rather than
a pair.

Both are best-effort and additive: with no cost policy configured nothing is
stamped, and with no token-unit quota rule nothing is recorded, so an
unconfigured deployment produces byte-identical events.
"""

from typing import Any, Dict


def stamp_cost(config: Any, event: Dict[str, Any]) -> None:
    """Resolve and stamp this call's layered cost onto the event's reserved
    telemetry metadata. No-op unless a cost policy is configured.

    The caller's own estimate is read from ``metadata.cost_estimate_micros`` -
    the channel a tool or framework already has - and is the WEAKEST layer: an
    operator-declared cost for the same action or model replaces it, because a
    cost claimed by the party being governed is not evidence about that party.
    Twin: stampCost in proxy/wrapper.ts.
    """
    from .cost import cost_metadata, resolve_call_cost, resolve_cost_policy
    policy = resolve_cost_policy(config)
    if not policy:
        return
    metadata = event.get("metadata") or {}
    cost = resolve_call_cost(
        policy=policy,
        model=event.get("model_resolved") or event.get("model"),
        action_name=event.get("action_name"),
        caller_estimate_micros=metadata.get("cost_estimate_micros"),
        input_tokens=event.get("input_tokens"),
        output_tokens=event.get("output_tokens"),
    )
    fragment = cost_metadata(cost)
    if not fragment:
        return
    # Stamped LAST so a caller metadata key collision cannot overwrite it.
    event["metadata"] = {**metadata, **fragment}


def record_token_usage_for_rules(config: Any, event: Dict[str, Any]) -> None:
    """Post-call: record consumed tokens against any token-unit quota rules, so
    the next pre-call check enforces the budget. Parity with the TS wrapper's
    recordTokenUsageForRules. No-op unless the call succeeded with token usage."""
    rules = getattr(config, "policy_rules", None)
    if not rules or not event.get("total_tokens"):
        return
    from .rules import quota_scope_value, record_token_usage
    meta = event.get("metadata") or {}
    for rule in rules:
        if not getattr(rule, "enabled", True) or getattr(rule, "type", None) != "quota":
            continue
        c = getattr(rule, "conditions", None) or {}
        if (
            c.get("quota_unit") != "tokens"
            or not c.get("quota_limit")
            or not c.get("quota_window_ms")
            or not c.get("quota_scope")
        ):
            continue
        scope = c["quota_scope"]
        scope_value = quota_scope_value(scope, meta, event.get("user_id"))
        record_token_usage(
            scope, scope_value, int(event.get("total_tokens") or 0), int(c["quota_window_ms"])
        )


def meter_event(config: Any, event: Dict[str, Any]) -> None:
    """Meter a completed event: quota first, then cost.

    The order matters only in that cost is stamped last, so a caller-supplied
    metadata key cannot overwrite the cost fragment.
    """
    if event.get("success") is not False and event.get("total_tokens"):
        record_token_usage_for_rules(config, event)
    stamp_cost(config, event)
