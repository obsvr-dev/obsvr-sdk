/**
 * FinTech industry policy module.
 *
 * Provides action-gate matching with threshold evaluation and time-of-day
 * restrictions with timezone support.
 *
 * @packageDocumentation
 */

import type { PolicyRule, PolicyEvalContext } from '../rules.js';

/**
 * Evaluate action gate conditions for FinTech rules.
 * Checks action type matching, numeric thresholds, and time windows.
 */
export function evaluateActionGate(
  rule: PolicyRule,
  text: string,
  context?: PolicyEvalContext,
): boolean {
  const { conditions } = rule;

  // Action type matching
  if (conditions.action_types && conditions.action_types.length > 0) {
    const actionName = context?.actionName ?? text;
    const lower = actionName.toLowerCase();
    const actionMatch = conditions.action_types.some(
      (at) => lower.includes(at.toLowerCase()),
    );
    if (!actionMatch) return false;
  }

  // Threshold evaluation
  if (conditions.threshold) {
    const { field, operator, value } = conditions.threshold;
    const actual = resolveThresholdField(field, context);
    if (actual === undefined) return false;
    if (!compareThreshold(actual, operator, value)) return false;
  }

  // Time window evaluation
  if (conditions.time_window) {
    const { allow_hours, timezone } = conditions.time_window;
    const now = getCurrentHour(timezone);
    const [start, end] = allow_hours;
    // If outside the allowed window, the gate fires (blocks)
    if (start <= end) {
      if (now >= start && now < end) return false; // within window = allowed
    } else {
      // Wraps midnight, e.g. [22, 6]
      if (now >= start || now < end) return false;
    }
    return true;
  }

  return true;
}

/**
 * Resolve a threshold field from context.
 */
export function resolveThresholdField(
  field: string,
  context?: PolicyEvalContext,
): number | undefined {
  if (!context) return undefined;
  if (field === 'amount') return context.amount;
  const meta = context.metadata;
  if (meta && field in meta) {
    const v = meta[field];
    return typeof v === 'number' ? v : undefined;
  }
  return undefined;
}

/**
 * Compare a numeric value against a threshold.
 */
export function compareThreshold(
  actual: number,
  operator: '>' | '<' | '>=' | '<=' | '==',
  value: number,
): boolean {
  switch (operator) {
    case '>': return actual > value;
    case '<': return actual < value;
    case '>=': return actual >= value;
    case '<=': return actual <= value;
    case '==': return actual === value;
    default: return false;
  }
}

/**
 * Get the current hour in a given timezone (24h format).
 */
export function getCurrentHour(timezone?: string): number {
  if (timezone) {
    try {
      const fmt = new Intl.DateTimeFormat('en-US', {
        hour: 'numeric',
        hour12: false,
        timeZone: timezone,
      });
      return parseInt(fmt.format(new Date()), 10);
    } catch {
      // Invalid timezone - fall back to local
    }
  }
  return new Date().getHours();
}

/**
 * Classify the risk level of a financial action based on amount and type.
 */
export function classifyFintechRisk(
  actionName: string,
  amount?: number,
): 'low' | 'medium' | 'high' | 'critical' {
  const lower = actionName.toLowerCase();
  const isHighRiskAction =
    lower.includes('wire_transfer') ||
    lower.includes('ach_transfer') ||
    lower.includes('international');

  if (!amount) return isHighRiskAction ? 'medium' : 'low';
  if (amount >= 100_000) return 'critical';
  if (amount >= 10_000) return isHighRiskAction ? 'critical' : 'high';
  if (amount >= 1_000) return isHighRiskAction ? 'high' : 'medium';
  return isHighRiskAction ? 'medium' : 'low';
}
