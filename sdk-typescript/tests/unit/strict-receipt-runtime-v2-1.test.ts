import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonicalJsonForHash } from '../../src/policy/tool-pinning.js';
import { actionTargetHash } from '../../src/governance/action-context-v2.js';
import { STRICT_RECEIPT_V21_ADMISSION_SCHEMA } from '../../src/governance/strict-admission-v2-1.js';
import {
  createTrustedEvaluationEvidenceProviderV21,
} from '../../src/governance/strict-evaluation-evidence-v2-1.js';
import {
  createStrictIdentityEvidenceV21Authority,
} from '../../src/governance/strict-identity-evidence-v2-1.js';
import {
  StrictReceiptCoordinatorV21, createTrustedIntentDecisionProviderV21,
  type StrictDecisionActionV21Input,
} from '../../src/governance/strict-receipt-coordinator-v2-1.js';
import {
  bindStrictV21JsonArguments, StrictReceiptRuntimeV21,
  type StrictRuntimeExecutionJournalV21,
} from '../../src/governance/strict-receipt-runtime-v2-1.js';
import { strictReceiptV21KeyId } from '../../src/governance/strict-receipt-v2-1.js';
import { intentPolicyV2Hash, type IntentV2BaseResult } from '../../src/policy/intent-alignment-v2.js';
import { loadDeviceSigner } from '../../src/proxy/device-identity.js';

const B = 'b'.repeat(64); const C = 'c'.repeat(64);
const TARGET = actionTargetHash('prod');
const CHECKPOINT_SHA256 = 'e005d13ddfe1e349bcf13fbda8f6c05305d61b3af192e8488d9c05c4f086197e';
const POLICY = { schema: 'obsvr-intent-policy-v2' as const, profile_version: '2.0' as const,
  intent_scopes: [{ intent_id: 'deploy', allowed_actions: [{ kind: 'tool', name: 'send' }],
    allowed_targets: ['prod'], allowed_requested_scopes: ['write'],
    allowed_data_classifications: ['confidential'] }] };

function signer() {
  const path = join(mkdtempSync(join(tmpdir(), 'obsvr-runtime-v21-')), 'seed.key');
  writeFileSync(path, '00'.repeat(32), 'ascii'); return loadDeviceSigner(path);
}
function decision(actionId: string, argumentsHash: string, active = ['deploy']): StrictDecisionActionV21Input {
  return { action_id: actionId, active_intents: active, current_action: {
    kind: 'tool', name: 'send', arguments_hash: argumentsHash, target_hash: TARGET,
    data_classifications: ['confidential'], requested_scopes: ['write'],
  }, run_id: 'run-1', thread_id: 'thread-1' };
}
function coordinator(base: IntentV2BaseResult = { action_taken: 'allowed' }) {
  const device = signer();
  return new StrictReceiptCoordinatorV21({
    signer: device, policy: POLICY, tenant_id: 'tenant-1', session_id: 'session-1',
    sdk_language: 'typescript', clock: () => 1_000, defer_ttl_ms: 500,
    identity_authority: createStrictIdentityEvidenceV21Authority(),
    identity_snapshot: (timestamp) => ({ schema: 'obsvr-strict-identity-evidence-v2-1',
      profile_version: '2.1', relationship: 'direct', receipt_time_ms: timestamp,
      requester: { requester_ref_hash: B, principal_type: 'agent', role_ids: ['worker'],
        privilege_scopes: ['write'] }, initiator: { agent_ref_hash: B,
        key_id: strictReceiptV21KeyId(device.rawPublicKey), role_ids: ['worker'],
        privilege_scopes: ['write'] }, delegation_chain: [] }),
    intent_decision_provider: createTrustedIntentDecisionProviderV21(() => structuredClone(base)),
    evaluation_evidence_provider: createTrustedEvaluationEvidenceProviderV21(() => ({
      effective_policy: { version: 'policy-1', artifact_hash: intentPolicyV2Hash(POLICY),
        matched_rule_ids: ['deploy'] }, detector_requirements: [], detector_results: [],
    })), pid: () => 7, prepared_token_factory: () => 'prepared-token',
  });
}
function accepted(hash: string, status = 'accepted') {
  return Buffer.from(JSON.stringify({ schema: STRICT_RECEIPT_V21_ADMISSION_SCHEMA,
    ok: true, status, receipt_hash: hash, accepted_at_ms: 10 }));
}
function setup(base: IntentV2BaseResult = { action_taken: 'allowed' },
  response: (hash: string) => { status: number; body: Uint8Array } = (hash) => ({ status: 200, body: accepted(hash) }),
  failCommit = false) {
  const events: string[] = []; const checkpoints: StrictRuntimeExecutionJournalV21[] = [];
  const subject = coordinator(base); const originalCommit = subject.commitPrepared.bind(subject);
  subject.commitPrepared = (token, hash) => {
    events.push('commit');
    if (failCommit) throw new Error('commit failed');
    return originalCommit(token, hash);
  };
  const runtime = new StrictReceiptRuntimeV21(subject, {
    ingest_url: 'https://example.com', api_key: 'key', max_attempts: 1,
    resolver: async () => ['8.8.8.8'], trusted_pinned_transport: async (_target, _body, headers) => {
      events.push('admit'); return response(headers['Idempotency-Key']);
    },
  }, { save: (checkpoint) => { checkpoints.push(structuredClone(checkpoint));
    events.push(`persist:${checkpoint.phase}`); } });
  return { subject, runtime, events, checkpoints };
}

describe('strict profile 2.1 runtime', () => {
  test('persists prepared, admits, commits, persists committed, then invokes', async () => {
    const bound = bindStrictV21JsonArguments({ message: 'hello' });
    const { runtime, events, checkpoints } = setup();
    const result = await runtime.runDecision({ decision: decision('action-1', bound.arguments_hash),
      action: { runtime_action_id: 'action-1', original_arguments: bound,
        invoke: (value) => { events.push('invoke'); return value.message; } } });
    expect(result).toMatchObject({ status: 'executed', value: 'hello' });
    expect(events).toEqual(['persist:prepared', 'admit', 'persist:remote_accepted', 'commit',
      'persist:committed', 'persist:invocation_started', 'invoke', 'persist:terminal']);
    expect(checkpoints[0]).toMatchObject({ schema: 'obsvr-strict-runtime-execution-journal-v2-1',
      profile_version: '2.1', phase: 'prepared', tenant_id: 'tenant-1', session_id: 'session-1',
      runtime_action_id: 'action-1', prepared_token: 'prepared-token' });
    expect(JSON.stringify(checkpoints[0])).not.toContain('hello');
    expect(checkpoints[0]).not.toHaveProperty('api_key');
    expect(checkpoints[0]).not.toHaveProperty('provider_response');
    expect(checkpoints[0]).not.toHaveProperty('error');
    expect(createHash('sha256').update(canonicalJsonForHash(checkpoints[0])).digest('hex'))
      .toBe(CHECKPOINT_SHA256);
  });

  test('MODIFY invokes only the bound effective arguments', async () => {
    const original = bindStrictV21JsonArguments({ message: 'unsafe' });
    const effective = bindStrictV21JsonArguments({ message: 'redacted' });
    const { runtime, events } = setup({ action_taken: 'redacted',
      modified_arguments_hash: effective.arguments_hash });
    const result = await runtime.runDecision({ decision: decision('modify', original.arguments_hash),
      action: { runtime_action_id: 'modify', original_arguments: original,
        effective_arguments: effective, invoke: (value) => { events.push(`value:${value.message}`); return value; } } });
    expect(result.status).toBe('executed'); expect(events).toContain('value:redacted');
  });

  test.each([
    ['DENY', { action_taken: 'blocked' } as IntentV2BaseResult, ['deploy']],
    ['STEP_UP', { action_taken: 'blocked', approval_required: true,
      approval_request_id: 'approval-1', approval_action_hash: '',
      approval_expires_at_ms: 1_500 } as IntentV2BaseResult, ['deploy']],
    ['DEFER', { action_taken: 'allowed' } as IntentV2BaseResult, ['deploy', 'other']],
  ])('admits but never invokes %s', async (_outcome, rawBase, active) => {
    const bound = bindStrictV21JsonArguments({ message: 'hello' });
    const base = { ...rawBase } as IntentV2BaseResult;
    if ('approval_action_hash' in base) base.approval_action_hash = bound.arguments_hash;
    const { runtime, events } = setup(base); let invokes = 0;
    const result = await runtime.runDecision({ decision: decision(`action-${_outcome}`, bound.arguments_hash, active),
      action: { runtime_action_id: `action-${_outcome}`, original_arguments: bound,
        invoke: () => { invokes += 1; } } });
    expect(result).toMatchObject({ status: 'nonexecuted', reason: 'not_authorized' });
    expect(events).toEqual(['persist:prepared', 'admit', 'persist:remote_accepted', 'commit',
      'persist:committed', 'persist:terminal']);
    expect(invokes).toBe(0);
  });

  test('binding failure aborts locally before persistence or admission', async () => {
    const signed = bindStrictV21JsonArguments({ message: 'signed' });
    const wrong = bindStrictV21JsonArguments({ message: 'wrong' });
    const { runtime, events, subject } = setup(); let invokes = 0;
    const result = await runtime.runDecision({ decision: decision('binding', signed.arguments_hash),
      action: { runtime_action_id: 'binding', original_arguments: wrong,
        invoke: () => { invokes += 1; } } });
    expect(result).toMatchObject({ status: 'nonexecuted', reason: 'binding_unavailable' });
    expect(events).toEqual([]); expect(invokes).toBe(0);
    expect(subject.inspectState()).not.toHaveProperty('prepared');
  });

  test('admission uncertainty and commit failure freeze without invoking', async () => {
    const bound = bindStrictV21JsonArguments({ message: 'hello' });
    const uncertain = setup(undefined, () => ({ status: 503, body: new Uint8Array() }));
    let invokes = 0;
    const first = await uncertain.runtime.runDecision({ decision: decision('uncertain', bound.arguments_hash),
      action: { runtime_action_id: 'uncertain', original_arguments: bound,
        invoke: () => { invokes += 1; } } });
    expect(first).toMatchObject({ status: 'nonexecuted', reason: 'admission_uncertain' });
    expect(uncertain.subject.inspectState()).toMatchObject({ frozen: true });

    const failed = setup(undefined, undefined, true);
    const second = await failed.runtime.runDecision({ decision: decision('commit-fail', bound.arguments_hash),
      action: { runtime_action_id: 'commit-fail', original_arguments: bound,
        invoke: () => { invokes += 1; } } });
    expect(second).toMatchObject({ status: 'nonexecuted', reason: 'admission_uncertain' });
    expect(failed.subject.inspectState()).toMatchObject({ frozen: true }); expect(invokes).toBe(0);
  });

  test('checkpoint failures fail closed on both sides of admission', async () => {
    const bound = bindStrictV21JsonArguments({ message: 'hello' }); let invokes = 0;
    const before = setup();
    const beforeRuntime = new StrictReceiptRuntimeV21(before.subject, {
      ingest_url: 'https://example.com', api_key: 'key', max_attempts: 1,
      resolver: async () => ['8.8.8.8'], trusted_pinned_transport: async () => {
        before.events.push('admit'); return { status: 200, body: new Uint8Array() };
      },
    }, { save: () => { throw new Error('disk failed'); } });
    const first = await beforeRuntime.runDecision({ decision: decision('before', bound.arguments_hash),
      action: { runtime_action_id: 'before', original_arguments: bound, invoke: () => { invokes += 1; } } });
    expect(first).toMatchObject({ reason: 'checkpoint_persist_failed' }); expect(before.events).toEqual([]);

    const after = setup(); let saves = 0;
    const afterRuntime = new StrictReceiptRuntimeV21(after.subject, {
      ingest_url: 'https://example.com', api_key: 'key', max_attempts: 1,
      resolver: async () => ['8.8.8.8'], trusted_pinned_transport: async (_t, _b, h) => {
        after.events.push('admit'); return { status: 200, body: accepted(h['Idempotency-Key']) };
      },
    }, { save: () => { saves += 1; if (saves === 4) throw new Error('disk failed'); } });
    const second = await afterRuntime.runDecision({ decision: decision('after', bound.arguments_hash),
      action: { runtime_action_id: 'after', original_arguments: bound, invoke: () => { invokes += 1; } } });
    expect(second).toMatchObject({ reason: 'checkpoint_persist_failed' }); expect(invokes).toBe(0);
    expect(() => afterRuntime.runDecision({ decision: decision('next', bound.arguments_hash),
      action: { runtime_action_id: 'next', original_arguments: bound, invoke: () => undefined } }))
      .toThrow('runtime is frozen');
  });

  test.each([2, 3])('journal failure at pre-invocation phase %i freezes without invoking', async (failOn) => {
    const bound = bindStrictV21JsonArguments({ message: 'hello' }); const subject = coordinator();
    let saves = 0; let invokes = 0;
    const runtime = new StrictReceiptRuntimeV21(subject, {
      ingest_url: 'https://example.com', api_key: 'key', max_attempts: 1,
      resolver: async () => ['8.8.8.8'], trusted_pinned_transport: async (_t, _b, h) => (
        { status: 200, body: accepted(h['Idempotency-Key']) }
      ),
    }, { save: () => { saves += 1; if (saves === failOn) throw new Error('disk failed'); } });
    const result = await runtime.runDecision({ decision: decision(`fail-${failOn}`, bound.arguments_hash),
      action: { runtime_action_id: `fail-${failOn}`, original_arguments: bound,
        invoke: () => { invokes += 1; } } });
    expect(result).toMatchObject({ status: 'nonexecuted', reason: 'checkpoint_persist_failed' });
    expect(invokes).toBe(0);
    expect(() => runtime.runDecision({ decision: decision('next', bound.arguments_hash),
      action: { runtime_action_id: 'next', original_arguments: bound, invoke: () => undefined } }))
      .toThrow('runtime is frozen');
  });
});
