import { buildControlAnalyticsReportV1 } from '../../src/governance/control-analytics-v1.js';

const events = [
  { event_id: '1', workload_id: 'contract-ai', policy_hash: 'a'.repeat(64), outcome: 'ALLOW' as const, shadow_outcome: 'DENY' as const, approval: 'none' as const, latency_ms: 2, coverage_complete: true, evidence_complete: true, occurred_at_ms: 100 },
  { event_id: '2', workload_id: 'contract-ai', policy_hash: 'a'.repeat(64), outcome: 'STEP_UP' as const, shadow_outcome: 'STEP_UP' as const, approval: 'requested' as const, latency_ms: 7, coverage_complete: false, evidence_complete: true, occurred_at_ms: 200 },
  { event_id: '3', workload_id: 'contract-ai', policy_hash: 'a'.repeat(64), outcome: 'ALLOW' as const, approval: 'overridden' as const, latency_ms: 20, coverage_complete: true, evidence_complete: false, occurred_at_ms: 300 },
];

describe('control analytics v1', () => {
  test('reports bounded effectiveness indicators without hiding gaps', () => {
    expect(buildControlAnalyticsReportV1(events)).toMatchObject({ input_event_count: 3, outcome_counts: { ALLOW: 2, STEP_UP: 1 }, control_action_bps: 3333, coverage_gap_count: 1, evidence_gap_count: 1, shadow: { evaluated_count: 2, changed_count: 1, changed_bps: 5000 }, latency_ms: { p50: 7, p95: 20, max: 20 } });
  });
  test('is deterministic across input order', () => {
    expect(buildControlAnalyticsReportV1([...events].reverse()).report_hash).toBe(buildControlAnalyticsReportV1(events).report_hash);
    expect(buildControlAnalyticsReportV1(events).report_hash).toBe('7bdad8cb33d6e675c38584f4ee120db8a1324fd48b93c082cc1f067ba5db5a93');
  });
  test('rejects duplicate ids and unbounded raw fields', () => {
    expect(() => buildControlAnalyticsReportV1([...events, events[0]])).toThrow('unique');
    expect(() => buildControlAnalyticsReportV1([{ ...events[0], prompt: 'secret' } as never])).toThrow('unsupported field');
  });
});
