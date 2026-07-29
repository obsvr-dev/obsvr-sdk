/**
 * Post-call metering: what a governed call cost, and what it consumed against a
 * token budget.
 *
 * These two run together or not at all. Metering the cost of a call without
 * counting it against its token budget produces an audit record that disagrees
 * with itself — a cost figure the budget it belongs to has never heard of — and
 * a governance record that contradicts itself is worse than one that is silent.
 * That is why the two live in one module behind one call, and why the config
 * flag that gates them for the framework-integration path is a single boolean
 * rather than a pair.
 *
 * Both are best-effort and additive: with no cost policy configured `stampCost`
 * writes nothing, and with no token-unit quota rule `recordTokenUsageForRules`
 * does nothing, so an unconfigured deployment produces byte-identical events.
 *
 * @packageDocumentation
 */
import type { AuditEvent, ResolvedConfig } from "../proxy/types.js";
import { costMetadata, resolveCallCost, resolveCostPolicy } from "./cost.js";
import { recordTokenUsage } from "./quota.js";

/**
 * Record this call's token usage against any token-unit quota rules, so their
 * pre-call budget checks reflect consumption. Tokens are only known post-call,
 * so budgets are approximate by design.
 */
export function recordTokenUsageForRules(config: ResolvedConfig, event: AuditEvent): void {
  const rules = config.policyRules;
  if (!rules?.length) return;
  for (const rule of rules) {
    if (!rule.enabled || rule.type !== "quota") continue;
    const c = rule.conditions;
    if (c.quota_unit !== "tokens" || !c.quota_limit || !c.quota_window_ms || !c.quota_scope)
      continue;
    const meta = (event.metadata ?? {}) as Record<string, unknown>;
    const scopeValue =
      c.quota_scope === "project"
        ? "project"
        : String(
            meta[c.quota_scope] ??
              (c.quota_scope === "user_id" ? event.user_id : undefined) ??
              "default",
          );
    recordTokenUsage(c.quota_scope, scopeValue, event.total_tokens ?? 0, c.quota_window_ms);
  }
}

/**
 * Layered cost: the caller's estimate, the operator's declared override, and
 * the metered figure from real usage at the operator's own rates — all three
 * kept, because the gap between the estimate and the correction is the part an
 * auditor can act on. Stamped LAST so a caller metadata key collision cannot
 * overwrite it, and only when a cost policy is configured.
 */
export function stampCost(config: ResolvedConfig, event: AuditEvent): void {
  const policy = resolveCostPolicy(config);
  if (!policy) return;
  const metadata = (event.metadata ?? {}) as Record<string, unknown>;
  const cost = resolveCallCost({
    policy,
    model: event.model_resolved ?? event.model,
    actionName: event.action_name,
    callerEstimateMicros: metadata.cost_estimate_micros,
    inputTokens: event.input_tokens,
    outputTokens: event.output_tokens,
  });
  const fragment = costMetadata(cost);
  if (Object.keys(fragment).length === 0) return;
  event.metadata = { ...metadata, ...fragment };
}

/**
 * Meter a completed event: quota first, then cost.
 *
 * The order matters only in that cost is stamped last, so a caller-supplied
 * metadata key cannot overwrite the cost fragment.
 */
export function meterEvent(config: ResolvedConfig, event: AuditEvent): void {
  if (event.success !== false && event.total_tokens) {
    recordTokenUsageForRules(config, event);
  }
  stampCost(config, event);
}
