import {
  buildPolicyCandidateV1, decidePolicyPromotionV1, policyCandidateV1Hash,
  replayPolicyCandidateV1,
} from '../../src/governance/policy-lifecycle-v1.js';

const candidate = {
  policy_id: 'contracts', version: '7', artifact_hash: 'a'.repeat(64),
  previous_active_hash: 'b'.repeat(64), stage: 'shadow' as const, rollout_bps: 0,
  explanation_codes: ['contract.external_send', 'contract.pii'],
};
const cases = [
  { case_id: 'a', baseline_outcome: 'ALLOW' as const, candidate_outcome: 'DENY' as const, evidence_complete: true },
  { case_id: 'b', baseline_outcome: 'ALLOW' as const, candidate_outcome: 'ALLOW' as const, evidence_complete: true },
];

describe('policy lifecycle v1', () => {
  test('builds one deterministic candidate and replay report', () => {
    expect(policyCandidateV1Hash(candidate)).toBe('b761b5bdbf23d80ad49f9499ad5b58f772051c7389f279a57033f2128ee0226f');
    expect(replayPolicyCandidateV1(candidate, cases)).toMatchObject({ total_cases: 2, changed_cases: 1, changed_bps: 5000 });
  });
  test('promotes only inside replay thresholds and carries rollback', () => {
    const report = replayPolicyCandidateV1(candidate, cases);
    expect(decidePolicyPromotionV1(candidate, report, 'canary', 500, { max_error_count: 0, max_evidence_gap_count: 0, max_changed_bps: 5000 }))
      .toMatchObject({ approved: true, effective_stage: 'canary', rollback_artifact_hash: 'b'.repeat(64), reason_codes: ['policy.promotion.ready'] });
    expect(decidePolicyPromotionV1(candidate, report, 'active', 10_000, { max_error_count: 0, max_evidence_gap_count: 0, max_changed_bps: 100 }))
      .toMatchObject({ approved: false, effective_stage: 'shadow', reason_codes: ['policy.replay.change_budget_exceeded'] });
  });
  test('lints invalid lifecycle metadata before use', () => {
    expect(() => buildPolicyCandidateV1({ ...candidate, stage: 'active', rollout_bps: 50 } as never)).toThrow('inconsistent');
    expect(() => replayPolicyCandidateV1(candidate, [...cases, cases[0]])).toThrow('case_id values must be unique');
  });
});
