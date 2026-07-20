/**
 * Healthcare industry policy module.
 *
 * Provides namespace isolation for PHI data silos and hard-deletion
 * support for HIPAA right-to-delete compliance.
 *
 * @packageDocumentation
 */

import type { AuditEvent, ResolvedConfig } from '../../proxy/types.js';
import { generateUUID } from '../../client.js';

/**
 * Namespace isolation: blocks when caller and target namespaces differ.
 *
 * Re-exported from the rules engine so the industry barrel and the live
 * decision path share ONE implementation. A previous local copy here
 * returned false (allow) on an asymmetric context — exactly the input an
 * attacker crafts by nulling one namespace — while the engine's evaluator
 * fails closed; identical names with opposite verdicts is how that kind of
 * drift survives review, so the duplicate was removed rather than patched.
 */
export { evaluateNamespaceIsolation } from '../rules.js';

/**
 * Request hard deletion of audit events matching the given filter criteria.
 * Sends a DELETE request to the ingest endpoint and emits a hard_delete audit
 * event for the deletion action itself (audit trail of the deletion).
 */
export async function hardDeleteEvents(
  config: ResolvedConfig,
  filter: {
    eventIds?: string[];
    userId?: string;
    before?: Date;
    tenantId?: string;
  },
): Promise<{ success: boolean; deletedCount?: number; error?: string }> {
  if (!config.hardDeletion?.enabled) {
    return { success: false, error: 'Hard deletion is not enabled in config' };
  }
  // Do NOT default to ingest_url: the ingest service exposes no deletion route,
  // so the old fallback made every call 404 silently (a non-functional HIPAA
  // right-to-delete that still emitted a hard_delete event claiming success).
  // Require an explicit erasure endpoint and fail loudly if it is unset.
  const endpoint = config.hardDeletion?.endpoint;
  if (!endpoint) {
    return {
      success: false,
      error:
        'Hard deletion requires an explicit hardDeletion.endpoint (the ingest ' +
        'service has no deletion route); configure your erasure/retention endpoint.',
    };
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), config.timeout);
    if (typeof timeoutId === 'object' && (timeoutId as any).unref) {
      (timeoutId as any).unref();
    }

    const resp = await fetch(`${endpoint}/events/delete`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': config.api_key,
      },
      body: JSON.stringify({
        event_ids: filter.eventIds,
        user_id: filter.userId,
        before: filter.before?.toISOString(),
        tenant_id: filter.tenantId,
      }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!resp.ok) {
      return { success: false, error: `Delete request failed: ${resp.status}` };
    }

    const data = (await resp.json()) as { deleted_count?: number };
    return { success: true, deletedCount: data.deleted_count };
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Build a hard_delete audit event to record the deletion action.
 */
export function buildHardDeleteAuditEvent(
  config: ResolvedConfig,
  filter: Record<string, unknown>,
  deletedCount: number,
): AuditEvent {
  return {
    request_id: generateUUID(),
    environment: config.environment,
    region: config.default_region ?? 'unknown',
    provider: 'unknown',
    model: 'n/a',
    operation: 'hard_delete',
    source: 'healthcare_compliance',
    prompt: '',
    response: '',
    success: true,
    status_code: 200,
    error_type: null,
    event_type: 'hard_delete',
    policy_version: 'v1',
    action_taken: 'allowed',
    action_reason: 'none',
    action_source: 'policy_rules',
    redacted_types: [],
    metadata: {
      filter,
      deleted_count: deletedCount,
    },
  };
}

/**
 * Check if a data access request is within the caller's allowed namespace.
 */
export function isWithinNamespace(
  callerNamespace: string,
  targetNamespace: string,
): boolean {
  return callerNamespace === targetNamespace;
}
