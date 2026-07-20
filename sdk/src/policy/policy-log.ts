/**
 * Policy change audit log.
 * Tracks policy version snapshots and emits change events.
 * @packageDocumentation
 */

import type { PolicyRule } from './rules.js';
import { derivePolicyVersion } from './rules.js';
import { generateUUID } from '../client.js';

export interface PolicySnapshot {
  version: string;
  timestamp: string;
  rules_snapshot: string;
}

/** One field of a modified rule that changed, with its before/after values. */
export interface RuleFieldChange {
  field: string;
  from: unknown;
  to: unknown;
}

/** Body-level change for a single modified rule (the "what actually changed"). */
export interface RuleBodyChange {
  id: string;
  fields: RuleFieldChange[];
}

export interface PolicyDiff {
  added: string[];
  removed: string[];
  modified: string[];
  /**
   * Field-level before/after for each modified rule. `added`/`removed`/
   * `modified` remain rule-id lists for backward compatibility; this carries
   * the actual body change so "what changed" survives beyond the id.
   */
  rule_changes: RuleBodyChange[];
}

export interface PolicyChangedEvent {
  event_type: 'policy_changed';
  timestamp: string;
  tenant_id?: string;
  previous_version: string;
  new_version: string;
  changed_by?: string;
  diff: PolicyDiff;
  // ── Wire fields so the event validates AND persists at ingest ──────────────
  // RawEventSchema requires request_id + model, and strips unknown top-level
  // keys — so the structured change detail rides in `metadata.policy_change`,
  // the only channel canonical preserves. `policy_version` = new_version keeps
  // the marker consistent with the llm events that follow under it.
  request_id: string;
  model: string;
  policy_version: string;
  metadata: {
    policy_change: {
      previous_version: string;
      new_version: string;
      changed_by?: string;
      diff: PolicyDiff;
    };
  };
}

// Ring buffer: last 100 snapshots per key (global + per-tenant)
const MAX_SNAPSHOTS = 100;
const snapshotBuffers = new Map<string, PolicySnapshot[]>();

function getBuffer(key: string): PolicySnapshot[] {
  if (!snapshotBuffers.has(key)) snapshotBuffers.set(key, []);
  return snapshotBuffers.get(key)!;
}

export function snapshotPolicy(
  rules: PolicyRule[],
  tenantId?: string,
): PolicySnapshot {
  const snapshot: PolicySnapshot = {
    version: derivePolicyVersion(rules),
    timestamp: new Date().toISOString(),
    rules_snapshot: JSON.stringify(rules),
  };
  const key = tenantId ?? '__global__';
  const buf = getBuffer(key);
  buf.push(snapshot);
  if (buf.length > MAX_SNAPSHOTS) buf.shift();
  return snapshot;
}

export function getPolicyAtTime(
  timestamp: Date,
  tenantId?: string,
): PolicySnapshot | null {
  const key = tenantId ?? '__global__';
  const buf = getBuffer(key);
  if (buf.length === 0) return null;

  const ts = timestamp.getTime();
  // Binary search: find last snapshot with timestamp <= ts
  let lo = 0, hi = buf.length - 1, result: PolicySnapshot | null = null;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    const midTs = new Date(buf[mid].timestamp).getTime();
    if (midTs <= ts) {
      result = buf[mid];
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  return result;
}

/**
 * Field-level diff of one rule: every top-level key whose value changed, with
 * before/after. Deterministic (keys sorted) so two emitters agree byte-for-byte.
 */
export function diffRuleBodies(
  prev: PolicyRule,
  next: PolicyRule,
): RuleFieldChange[] {
  const keys = Array.from(
    new Set([...Object.keys(prev), ...Object.keys(next)]),
  ).sort();
  const changes: RuleFieldChange[] = [];
  const p = prev as unknown as Record<string, unknown>;
  const n = next as unknown as Record<string, unknown>;
  for (const field of keys) {
    const from = p[field];
    const to = n[field];
    if (JSON.stringify(from) !== JSON.stringify(to)) {
      changes.push({ field, from, to });
    }
  }
  return changes;
}

function computeDiff(prev: PolicyRule[], next: PolicyRule[]): PolicyDiff {
  const prevMap = new Map(prev.map((r) => [r.id, r]));
  const nextMap = new Map(next.map((r) => [r.id, r]));
  const added = next.filter((r) => !prevMap.has(r.id)).map((r) => r.id);
  const removed = prev.filter((r) => !nextMap.has(r.id)).map((r) => r.id);
  const modifiedRules = next.filter(
    (r) => prevMap.has(r.id) && JSON.stringify(prevMap.get(r.id)) !== JSON.stringify(r),
  );
  const modified = modifiedRules.map((r) => r.id);
  const rule_changes: RuleBodyChange[] = modifiedRules.map((r) => ({
    id: r.id,
    fields: diffRuleBodies(prevMap.get(r.id)!, r),
  }));
  return { added, removed, modified, rule_changes };
}

/**
 * Emit a policy_changed event. This is a best-effort fire-and-forget;
 * failures are swallowed since policy logging must not break the call path.
 */
export function emitPolicyChangedEvent(
  prevRules: PolicyRule[],
  nextRules: PolicyRule[],
  tenantId?: string,
  changedBy?: string,
): PolicyChangedEvent {
  const previous_version = derivePolicyVersion(prevRules);
  const new_version = derivePolicyVersion(nextRules);
  const diff = computeDiff(prevRules, nextRules);
  const event: PolicyChangedEvent = {
    event_type: 'policy_changed',
    timestamp: new Date().toISOString(),
    tenant_id: tenantId,
    previous_version,
    new_version,
    changed_by: changedBy,
    diff,
    request_id: generateUUID(),
    model: '',
    policy_version: new_version,
    metadata: {
      policy_change: { previous_version, new_version, changed_by: changedBy, diff },
    },
  };
  return event;
}

/** POST a PolicyChangedEvent to the ingest endpoint. Fire-and-forget. */
export async function sendPolicyEvent(
  event: PolicyChangedEvent,
  ingestUrl: string,
  apiKey: string,
): Promise<void> {
  try {
    await fetch(`${ingestUrl}/ingest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey },
      body: JSON.stringify(event),
    });
  } catch {
    // swallow - must never break caller
  }
}

/** Reset snapshot buffers (for testing only) */
export function _resetPolicyLog(): void {
  snapshotBuffers.clear();
}
