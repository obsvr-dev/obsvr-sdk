import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { actionTargetHash } from '../../src/governance/action-context-v2.js';
import { STRICT_RECEIPT_V21_ADMISSION_SCHEMA } from '../../src/governance/strict-admission-v2-1.js';
import {
  createStrictActionBoundaryV21,
  executeStrictActionV21,
  ObsvrStrictActionBoundaryV21Error,
  type StrictActionV21,
} from '../../src/governance/strict-action-boundary-v2-1.js';
import {
  createTrustedEvaluationEvidenceProviderV21,
} from '../../src/governance/strict-evaluation-evidence-v2-1.js';
import {
  createStrictIdentityEvidenceV21Authority,
} from '../../src/governance/strict-identity-evidence-v2-1.js';
import {
  StrictReceiptCoordinatorV21,
  createTrustedIntentDecisionProviderV21,
} from '../../src/governance/strict-receipt-coordinator-v2-1.js';
import {
  StrictReceiptRuntimeV21,
  type StrictRuntimeExecutionJournalV21,
} from '../../src/governance/strict-receipt-runtime-v2-1.js';
import { strictExecutionResultV21Hash } from '../../src/governance/strict-execution-outcome-v2-1.js';
import { strictReceiptV21KeyId } from '../../src/governance/strict-receipt-v2-1.js';
import { intentPolicyV2Hash, type IntentV2BaseResult } from '../../src/policy/intent-alignment-v2.js';
import { loadDeviceSigner } from '../../src/proxy/device-identity.js';

const B = 'b'.repeat(64);
const TARGET = 'contracts://agreement/send';
const ACTION: StrictActionV21 = {
  kind: 'tool', name: 'send', target: TARGET,
  data_classifications: ['confidential'], requested_scopes: ['write'],
};
const POLICY = {
  schema: 'obsvr-intent-policy-v2' as const,
  profile_version: '2.0' as const,
  intent_scopes: [{
    intent_id: 'deploy',
    allowed_actions: [{ kind: 'tool' as const, name: 'send' }],
    allowed_targets: [TARGET],
    allowed_requested_scopes: ['write'],
    allowed_data_classifications: ['confidential'],
  }],
};
const NONEXECUTING_CASES: Array<[IntentV2BaseResult, string, boolean]> = [
  [{ action_taken: 'blocked' }, 'not_authorized', true],
  [{ action_taken: 'redacted', modified_arguments_hash: '0'.repeat(64) },
    'admission_not_confirmed', false],
];

function setup(base: IntentV2BaseResult = { action_taken: 'allowed' }) {
  const path = join(mkdtempSync(join(tmpdir(), 'obsvr-action-v21-')), 'seed.key');
  writeFileSync(path, '00'.repeat(32), 'ascii');
  const signer = loadDeviceSigner(path);
  let now = 1_000; let token = 0;
  const contexts: unknown[] = [];
  const checkpoints: StrictRuntimeExecutionJournalV21[] = [];
  const events: string[] = [];
  const coordinator = new StrictReceiptCoordinatorV21({
    signer, policy: POLICY, tenant_id: 'tenant-1', session_id: 'session-1',
    sdk_language: 'typescript', clock: () => now++, defer_ttl_ms: 500,
    identity_authority: createStrictIdentityEvidenceV21Authority(),
    identity_snapshot: (timestamp) => ({
      schema: 'obsvr-strict-identity-evidence-v2-1', profile_version: '2.1',
      relationship: 'direct', receipt_time_ms: timestamp,
      requester: { requester_ref_hash: B, principal_type: 'agent', role_ids: ['worker'],
        privilege_scopes: ['write'] },
      initiator: { agent_ref_hash: B, key_id: strictReceiptV21KeyId(signer.rawPublicKey),
        role_ids: ['worker'], privilege_scopes: ['write'] }, delegation_chain: [],
    }),
    intent_decision_provider: createTrustedIntentDecisionProviderV21((context) => {
      contexts.push(structuredClone(context)); return structuredClone(base);
    }),
    evaluation_evidence_provider: createTrustedEvaluationEvidenceProviderV21(() => ({
      effective_policy: { version: 'policy-1', artifact_hash: intentPolicyV2Hash(POLICY),
        matched_rule_ids: ['deploy'] }, detector_requirements: [], detector_results: [],
    })),
    pid: () => 7, prepared_token_factory: () => `prepared-${++token}`,
  });
  const runtime = new StrictReceiptRuntimeV21(coordinator, {
    ingest_url: 'https://example.com', api_key: 'key', max_attempts: 1,
    resolver: async () => ['8.8.8.8'],
    trusted_pinned_transport: async (_target, _body, headers) => ({
      status: 200,
      body: Buffer.from(JSON.stringify({
        schema: STRICT_RECEIPT_V21_ADMISSION_SCHEMA, ok: true, status: 'accepted',
        receipt_hash: headers['Idempotency-Key'], accepted_at_ms: 10,
      })),
    }),
  }, { save: (checkpoint) => {
    checkpoints.push(structuredClone(checkpoint)); events.push(checkpoint.phase);
  } });
  return {
    contexts, checkpoints, events,
    boundary: createStrictActionBoundaryV21({
      runtime,
      context: () => ({ active_intents: ['deploy'], run_id: 'run-1', thread_id: 'thread-1' }),
    }),
  };
}

describe('strict action boundary v2.1', () => {
  test('admits exact arguments before an arbitrary side effect and signs its result', async () => {
    const subject = setup(); let calls = 0;
    const value = await executeStrictActionV21(
      subject.boundary, ACTION, { agreement_id: 'a-1' },
      (input) => { calls += 1; subject.events.push('invoke'); return { id: input.agreement_id }; },
      { result_projection: (result) => ({ id: result.id }) },
    );
    expect(value).toEqual({ id: 'a-1' }); expect(calls).toBe(1);
    expect(subject.events).toEqual([
      'prepared', 'remote_accepted', 'committed', 'invocation_started', 'invoke', 'terminal',
    ]);
    expect(subject.contexts[0]).toMatchObject({ action: {
      kind: 'tool', name: 'send', target_hash: actionTargetHash(TARGET),
      data_classifications: ['confidential'], requested_scopes: ['write'],
    } });
    expect(subject.checkpoints.at(-1)).toMatchObject({
      terminal_status: 'executed',
      execution_outcome: { body: {
        status: 'succeeded', result_hash: strictExecutionResultV21Hash({ id: 'a-1' }),
      } },
    });
  });

  test.each(NONEXECUTING_CASES)(
    'does not invoke a side effect without execution authorization',
    async (base, code, admitted) => {
      const subject = setup(base); let calls = 0;
      await expect(executeStrictActionV21(subject.boundary, ACTION, { id: 1 }, () => {
        calls += 1;
      })).rejects.toMatchObject({ code });
      expect(calls).toBe(0);
      if (admitted) {
        expect(subject.checkpoints.at(-1)).toMatchObject({ terminal_status: 'nonexecuted' });
      } else {
        expect(subject.checkpoints).toHaveLength(0);
      }
    },
  );

  test('marks an unclassified side-effect error uncertain', async () => {
    const subject = setup();
    await expect(executeStrictActionV21(subject.boundary, ACTION, { id: 1 }, () => {
      throw new Error('connection ended after send');
    })).rejects.toMatchObject({ code: 'admission_not_confirmed' });
    expect(subject.checkpoints.at(-1)).toMatchObject({
      terminal_status: 'invocation_uncertain',
      execution_outcome: { body: {
        status: 'uncertain', error_code: 'action_error_unclassified',
      } },
    });
  });

  test('preserves a definitively classified local failure', async () => {
    const subject = setup(); const failure = new Error('validation rejected');
    await expect(executeStrictActionV21(
      subject.boundary, ACTION, { id: 1 }, () => { throw failure; },
      { classify_error: () => ({ status: 'failed', error_code: 'local_validation_failed' }) },
    )).rejects.toBe(failure);
    expect(subject.checkpoints.at(-1)).toMatchObject({
      terminal_status: 'invocation_failed',
      execution_outcome: { body: {
        status: 'failed', error_code: 'local_validation_failed',
      } },
    });
  });

  test('rejects forged capabilities and non-JSON arguments before invocation', async () => {
    let calls = 0;
    await expect(executeStrictActionV21(
      { profile_version: '2.1' } as any, ACTION, { id: 1 }, () => { calls += 1; },
    )).rejects.toBeInstanceOf(ObsvrStrictActionBoundaryV21Error);
    const subject = setup(); const circular: any = {}; circular.self = circular;
    await expect(executeStrictActionV21(subject.boundary, ACTION, circular, () => {
      calls += 1;
    })).rejects.toMatchObject({ code: 'context_unavailable' });
    expect(calls).toBe(0); expect(subject.checkpoints).toHaveLength(0);
  });
});
