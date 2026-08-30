import { createHash } from 'node:crypto';
import { canonicalJsonForHash } from '../policy/tool-pinning.js';

export const CONTROL_ANALYTICS_REPORT_V1_SCHEMA = 'obsvr-control-analytics-report-v1' as const;
const HASH_RE = /^[0-9a-f]{64}$/;
const OUTCOMES = ['ALLOW', 'DENY', 'MODIFY', 'STEP_UP', 'DEFER', 'ERROR'] as const;
type Outcome = typeof OUTCOMES[number];
type Approval = 'none' | 'requested' | 'approved' | 'denied' | 'expired' | 'overridden';
export interface ControlAnalyticsEventV1 { event_id: string; workload_id: string; policy_hash: string; outcome: Outcome; shadow_outcome?: Outcome; approval: Approval; latency_ms: number; coverage_complete: boolean; evidence_complete: boolean; occurred_at_ms: number; }

export class ControlAnalyticsV1ValidationError extends Error { constructor(message: string) { super(message); this.name = 'ControlAnalyticsV1ValidationError'; } }
function fail(message: string): never { throw new ControlAnalyticsV1ValidationError(message); }
function text(value: unknown, field: string): string { if (typeof value !== 'string' || !value.trim() || Buffer.byteLength(value.trim(), 'utf8') > 256) fail(`${field} must be nonblank and at most 256 UTF-8 bytes`); return value.trim(); }
function integer(value: unknown, field: string): number { if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) fail(`${field} must be a nonnegative safe integer`); return value; }
function bps(count: number, total: number): number { return total === 0 ? 0 : Math.floor(count * 10_000 / total); }
function percentile(values: number[], percentage: number): number { if (!values.length) return 0; const sorted = [...values].sort((a, b) => a - b); return sorted[Math.ceil(percentage * sorted.length) - 1]; }

export function buildControlAnalyticsReportV1(eventsInput: ControlAnalyticsEventV1[]) {
  if (!Array.isArray(eventsInput) || eventsInput.length === 0 || eventsInput.length > 100_000) fail('events must contain between 1 and 100000 items');
  const outcomeSet = new Set<string>(OUTCOMES); const approvalSet = new Set(['none', 'requested', 'approved', 'denied', 'expired', 'overridden']);
  const events = eventsInput.map((item, index) => {
    if (!item || typeof item !== 'object' || Array.isArray(item)) fail(`events[${index}] must be an object`);
    const unknown = Object.keys(item).filter((key) => !['event_id', 'workload_id', 'policy_hash', 'outcome', 'shadow_outcome', 'approval', 'latency_ms', 'coverage_complete', 'evidence_complete', 'occurred_at_ms'].includes(key)); if (unknown.length) fail(`events[${index}] contains unsupported field: ${unknown[0]}`);
    if (!outcomeSet.has(item.outcome) || (item.shadow_outcome !== undefined && !outcomeSet.has(item.shadow_outcome))) fail(`events[${index}] outcome is invalid`);
    if (!approvalSet.has(item.approval)) fail(`events[${index}].approval is invalid`);
    if (typeof item.coverage_complete !== 'boolean' || typeof item.evidence_complete !== 'boolean') fail(`events[${index}] completeness fields must be boolean`);
    if (typeof item.policy_hash !== 'string' || !HASH_RE.test(item.policy_hash)) fail(`events[${index}].policy_hash is invalid`);
    return { ...item, event_id: text(item.event_id, `events[${index}].event_id`), workload_id: text(item.workload_id, `events[${index}].workload_id`), latency_ms: integer(item.latency_ms, 'latency_ms'), occurred_at_ms: integer(item.occurred_at_ms, 'occurred_at_ms') };
  });
  if (new Set(events.map((item) => item.event_id)).size !== events.length) fail('event_id values must be unique');
  const outcomes = Object.fromEntries(OUTCOMES.map((outcome) => [outcome, events.filter((event) => event.outcome === outcome).length])) as Record<Outcome, number>;
  const shadow = events.filter((event) => event.shadow_outcome !== undefined); const shadowChanged = shadow.filter((event) => event.shadow_outcome !== event.outcome).length;
  const approvals = { requested: events.filter((e) => e.approval === 'requested').length, approved: events.filter((e) => e.approval === 'approved').length, denied: events.filter((e) => e.approval === 'denied').length, expired: events.filter((e) => e.approval === 'expired').length, overridden: events.filter((e) => e.approval === 'overridden').length };
  const total = events.length; const report = {
    schema: CONTROL_ANALYTICS_REPORT_V1_SCHEMA, window_start_ms: Math.min(...events.map((e) => e.occurred_at_ms)), window_end_ms: Math.max(...events.map((e) => e.occurred_at_ms)), input_event_count: total,
    workload_ids: [...new Set(events.map((e) => e.workload_id))].sort(), policy_hashes: [...new Set(events.map((e) => e.policy_hash))].sort(), outcome_counts: outcomes,
    control_action_bps: bps(outcomes.DENY + outcomes.MODIFY + outcomes.STEP_UP + outcomes.DEFER, total),
    coverage_gap_count: events.filter((e) => !e.coverage_complete).length, evidence_gap_count: events.filter((e) => !e.evidence_complete).length,
    shadow: { evaluated_count: shadow.length, changed_count: shadowChanged, changed_bps: bps(shadowChanged, shadow.length) },
    approvals: { ...approvals, request_bps: bps(approvals.requested + approvals.approved + approvals.denied + approvals.expired + approvals.overridden, total), override_bps: bps(approvals.overridden, approvals.approved + approvals.denied + approvals.expired + approvals.overridden) },
    latency_ms: { p50: percentile(events.map((e) => e.latency_ms), .5), p95: percentile(events.map((e) => e.latency_ms), .95), max: Math.max(...events.map((e) => e.latency_ms)) },
  };
  return { ...report, report_hash: createHash('sha256').update(`obsvr-control-analytics/1\0${canonicalJsonForHash(report)}`, 'utf8').digest('hex') };
}
