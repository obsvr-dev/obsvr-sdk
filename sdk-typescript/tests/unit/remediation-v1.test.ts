import { readFileSync } from 'node:fs';
import {
  buildRemediationPlanV1,
  buildRemediationRetryV1,
  canonicalizeRemediationPlanV1,
  remediationPlanV1Hash,
  remediationRetryV1Hash,
  RemediationV1ValidationError,
  type RemediationPlanV1Input,
} from '../../src/governance/remediation-v1.js';
import { buildActionContextV2 } from '../../src/governance/action-context-v2.js';

const fixture = JSON.parse(readFileSync(
  new URL('../../../conformance/fixtures/remediation_v1.json', import.meta.url),
  'utf8',
)) as {
  claimable: boolean;
  plan: RemediationPlanV1Input;
  retry: { retry_attempt_id: string; satisfied_requirements: Array<{ code: string; evidence_hash: string }> };
  expect: { plan_document: object; plan_canonical: string; plan_hash: string; retry_document: object; retry_hash: string };
};

function retryInput() {
  return { ...fixture.retry, plan: fixture.plan };
}

describe('structured remediation v1', () => {
  test('pins deterministic plan and retry hashes across languages', () => {
    expect(fixture.claimable).toBe(false);
    expect(buildRemediationPlanV1(fixture.plan)).toEqual(fixture.expect.plan_document);
    expect(canonicalizeRemediationPlanV1(fixture.plan)).toBe(fixture.expect.plan_canonical);
    expect(remediationPlanV1Hash(fixture.plan)).toBe(fixture.expect.plan_hash);
    expect(buildRemediationRetryV1(retryInput())).toEqual(fixture.expect.retry_document);
    expect(remediationRetryV1Hash(retryInput())).toBe(fixture.expect.retry_hash);
  });

  test('requires a new attempt and evidence for every requirement', () => {
    expect(() => buildRemediationRetryV1({
      ...retryInput(), retry_attempt_id: fixture.plan.attempt_id,
    })).toThrow('retry_attempt_id must identify a new attempt');
    expect(() => buildRemediationRetryV1({
      ...retryInput(), satisfied_requirements: fixture.retry.satisfied_requirements.slice(0, 1),
    })).toThrow('evidence for every plan requirement');
  });

  test.each(['MODIFY', 'STEP_UP', 'DEFER'] as const)(
    'maps the existing %s outcome to one structured plan',
    (outcome) => {
      expect(buildRemediationPlanV1({ ...fixture.plan, outcome }).outcome).toBe(outcome);
    },
  );

  test('does not turn a terminal deny into an implicit retry', () => {
    expect(() => buildRemediationPlanV1({ ...fixture.plan, outcome: 'DENY' } as never))
      .toThrow('outcome must be MODIFY, STEP_UP, or DEFER');
  });

  test('rejects raw fields and links a retry into the next action context', () => {
    expect(() => buildRemediationPlanV1({ ...fixture.plan, rewritten_input: 'raw' } as never))
      .toThrow(RemediationV1ValidationError);
    const retry = buildRemediationRetryV1(retryInput());
    const context = buildActionContextV2({
      agent_id: 'agent', active_intents: ['send'], run_id: 'run', prior_actions: [],
      current_action: {
        kind: 'action', name: 'contract.send', arguments_hash: 'e'.repeat(64),
        target: 'contract/42', data_classifications: [], requested_scopes: ['contracts:send'],
        attempt_id: retry.retry_attempt_id,
        parent_attempt_id: retry.parent_attempt_id,
        remediation_retry_hash: fixture.expect.retry_hash,
      },
    });
    expect(context.action).toMatchObject({
      attempt_id: 'attempt-2',
      parent_attempt_id: 'attempt-1',
      remediation_retry_hash: fixture.expect.retry_hash,
    });
  });
});
