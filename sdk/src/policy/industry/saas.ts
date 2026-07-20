/**
 * SaaS industry policy module.
 *
 * Provides cross-tenant access detection and destructive operation
 * classification with approval gating.
 *
 * @packageDocumentation
 */

import type { PolicyRule, PolicyEvalContext } from '../rules.js';

/**
 * Default list of operations classified as destructive.
 */
export const DEFAULT_DESTRUCTIVE_OPS = [
  'drop table', 'truncate', 'delete all', 'rm -rf',
  'destroy', 'purge', 'wipe', 'format',
];

/**
 * Cross-tenant access: detects when caller and target belong to different
 * tenants/namespaces.
 *
 * Re-exported from the rules engine — single implementation, fail-closed on
 * asymmetric contexts (see the note in healthcare.ts; this module's previous
 * local copy failed open on one-side-missing namespaces).
 */
export { evaluateCrossTenantBlock } from '../rules.js';

/**
 * Evaluate destructive operation gate: detects destructive operations
 * in text or action name.
 */
export function evaluateDestructiveOpGate(
  rule: PolicyRule,
  text: string,
  context?: PolicyEvalContext,
): boolean {
  const ops = rule.conditions.destructive_operations;
  if (!ops || ops.length === 0) return false;
  const lower = text.toLowerCase();
  const actionName = (context?.actionName ?? '').toLowerCase();
  return ops.some(
    (op) => lower.includes(op.toLowerCase()) || actionName.includes(op.toLowerCase()),
  );
}

/**
 * Classify whether an operation is destructive.
 */
export function isDestructiveOperation(
  text: string,
  customOps?: string[],
): boolean {
  const ops = customOps ?? DEFAULT_DESTRUCTIVE_OPS;
  const lower = text.toLowerCase();
  return ops.some((op) => lower.includes(op.toLowerCase()));
}

/**
 * Check if approval is required for a destructive operation.
 */
export function requiresApproval(rule: PolicyRule): boolean {
  return rule.conditions.require_approval === true;
}

/**
 * Detect cross-tenant access from caller/target namespace strings.
 */
export function detectCrossTenantAccess(
  callerNamespace: string,
  targetNamespace: string,
): { isCrossTenant: boolean; callerTenant: string; targetTenant: string } {
  return {
    isCrossTenant: callerNamespace !== targetNamespace,
    callerTenant: callerNamespace,
    targetTenant: targetNamespace,
  };
}
