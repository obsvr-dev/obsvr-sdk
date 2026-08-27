import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  actionTargetHash,
} from '../../src/governance/action-context-v2';
import {
  createStrictIdentityEvidenceV21Authority,
  type StrictIdentityEvidenceV21Input,
} from '../../src/governance/strict-identity-evidence-v2-1';
import {
  createTrustedEvaluationEvidenceProviderV21,
  type TrustedEvaluationSnapshotV21,
} from '../../src/governance/strict-evaluation-evidence-v2-1';
import {
  StrictReceiptCoordinatorV21,
  createTrustedIntentDecisionProviderV21,
  type StrictDecisionActionV21Input,
} from '../../src/governance/strict-receipt-coordinator-v2-1';
import type { StrictApprovalVerifier } from '../../src/governance/strict-receipt-coordinator-support';
import { DEFINITIVE_NO_STORE } from '../../src/governance/strict-receipt-prepared-state';
import { strictReceiptV21KeyId } from '../../src/governance/strict-receipt-v2-1';
import {
  intentPolicyV2Hash,
  type IntentPolicyV2Input,
  type IntentV2BaseResult,
} from '../../src/policy/intent-alignment-v2';
import { loadDeviceSigner, type DeviceSigner } from '../../src/proxy/device-identity';

const A = 'a'.repeat(64); const B = 'b'.repeat(64); const C = 'c'.repeat(64);
const D = 'd'.repeat(64); const TARGET = actionTargetHash('prod');
const PARITY_HASH = '2f22fc808f9ddb6f49f3c853bec7c57c32bc26a1a325089bb2044cfc5556ff1c';
const PARITY_SIGNATURE = '9be900fe817f00b5ac06c319a5591a1b91272950630d2bfed21540c75655352b1f8ffd47f13c46fd3a7ce9da4277bf55cdce926a9513fd488b95c4caf37f750f';
const POLICY: IntentPolicyV2Input = {
  schema: 'obsvr-intent-policy-v2', profile_version: '2.0', intent_scopes: [{
    intent_id: 'deploy', allowed_actions: [{ kind: 'tool', name: 'send' }],
    allowed_targets: ['prod'], allowed_requested_scopes: ['write'],
    allowed_data_classifications: ['confidential'],
  }],
};

function signer(seed = '00'): DeviceSigner {
  const path = join(mkdtempSync(join(tmpdir(), 'obsvr-v21-coordinator-')), 'seed.key');
  writeFileSync(path, seed.repeat(32), 'ascii');
  return loadDeviceSigner(path);
}

function identity(timestamp: number, deviceSigner: DeviceSigner): StrictIdentityEvidenceV21Input {
  return {
    schema: 'obsvr-strict-identity-evidence-v2-1', profile_version: '2.1',
    relationship: 'direct', receipt_time_ms: timestamp,
    requester: { requester_ref_hash: B, principal_type: 'agent',
      role_ids: ['worker'], privilege_scopes: ['write'] },
    initiator: { agent_ref_hash: B, key_id: strictReceiptV21KeyId(deviceSigner.rawPublicKey),
      role_ids: ['worker'], privilege_scopes: ['write'] },
    delegation_chain: [],
  };
}

function action(actionId = 'action-1', activeIntents = ['deploy']): StrictDecisionActionV21Input {
  return { action_id: actionId, active_intents: activeIntents,
    current_action: { kind: 'tool', name: 'send', arguments_hash: A, target_hash: TARGET,
      data_classifications: ['confidential'], requested_scopes: ['write'] },
    run_id: 'run-1', thread_id: 'thread-1' };
}

function evaluationSnapshot(overrides: Partial<TrustedEvaluationSnapshotV21> = {}): TrustedEvaluationSnapshotV21 {
  return { effective_policy: { version: 'policy-1', artifact_hash: intentPolicyV2Hash(POLICY),
    matched_rule_ids: ['deploy'] }, detector_requirements: [], detector_results: [], ...overrides };
}

function coordinator(params: {
  clock?: () => number;
  base?: IntentV2BaseResult;
  snapshot?: TrustedEvaluationSnapshotV21;
  deviceSigner?: DeviceSigner;
  identitySnapshot?: (timestamp: number, signer: DeviceSigner) => StrictIdentityEvidenceV21Input;
  tenantId?: string;
  pid?: () => number;
  approvalVerifier?: StrictApprovalVerifier;
} = {}): StrictReceiptCoordinatorV21 {
  const deviceSigner = params.deviceSigner ?? signer();
  const base = params.base ?? { action_taken: 'allowed' };
  return new StrictReceiptCoordinatorV21({
    signer: deviceSigner, policy: POLICY, tenant_id: params.tenantId ?? 'tenant-1',
    session_id: 'session-1', sdk_language: 'typescript', clock: params.clock ?? (() => 1_000),
    defer_ttl_ms: 500, identity_authority: createStrictIdentityEvidenceV21Authority(),
    identity_snapshot: (timestamp) => (params.identitySnapshot ?? identity)(timestamp, deviceSigner),
    intent_decision_provider: createTrustedIntentDecisionProviderV21(() => structuredClone(base)),
    evaluation_evidence_provider: createTrustedEvaluationEvidenceProviderV21(
      () => structuredClone(params.snapshot ?? evaluationSnapshot()),
    ),
    approval_verifier: params.approvalVerifier,
    pid: params.pid ?? (() => 7), prepared_token_factory: () => 'prepared-token',
  });
}

describe('strict receipt profile 2.1 coordinator', () => {
  test('derives identity and policy evidence while rejecting caller-forged authority fields', () => {
    const subject = coordinator();
    for (const field of ['agent_id', 'requester', 'roles', 'delegation', 'session_id',
      'prior_actions', 'base_result', 'policy_version', 'rule_ids', 'evaluator', 'detectors']) {
      expect(() => subject.prepareDecision({ ...action(), [field]: 'forged' } as never))
        .toThrow(`unsupported field: ${field}`);
    }
    const prepared = subject.prepareDecision(action());
    expect(prepared.value.action_context.agent).toMatchObject({ agent_id: B,
      role: 'worker', privilege_scope: ['write'] });
    expect(prepared.value.receipt.body.identity.initiator.agent_ref_hash).toBe(B);
    expect(JSON.stringify(prepared)).not.toContain('"target":"prod"');
  });

  test('binds the actual policy, active rule IDs, signer identity, and evaluator reason', () => {
    expect(() => coordinator({ snapshot: evaluationSnapshot({ effective_policy: {
      version: 'policy-1', artifact_hash: C, matched_rule_ids: ['deploy'],
    } }) }).prepareDecision(action())).toThrow('artifact_hash does not match');
    expect(() => coordinator({ snapshot: evaluationSnapshot({ effective_policy: {
      version: 'policy-1', artifact_hash: intentPolicyV2Hash(POLICY), matched_rule_ids: [],
    } }) }).prepareDecision(action())).toThrow('matched_rule_ids do not match');
    const wrong = signer('01');
    expect(() => coordinator({ identitySnapshot: (timestamp) => identity(timestamp, wrong) })
      .prepareDecision(action())).toThrow('signer does not match');
    const prepared = coordinator().prepareDecision(action());
    expect(prepared.value.intent_evaluation.reason_code).toBe('intent_aligned');
    expect(prepared.value.evaluation_evidence.decision_reason_codes).toEqual(['intent_aligned']);
    expect(prepared.value.receipt.body.evaluation.decision_reason_codes).toEqual(['intent_aligned']);
  });

  test('lets detector fail-close results control authorization', () => {
    const evaluationOutage = evaluationSnapshot({ detector_requirements: [{ detector_id: 'pii',
      detector_manifest_hash: C, required: true, purpose: 'evaluation' }], detector_results: [] });
    const deferred = coordinator({ snapshot: evaluationOutage }).prepareDecision(action()).value.receipt.body;
    expect(deferred).toMatchObject({ outcome: 'DEFER', execution_authorized: false,
      evaluation: { requested_outcome: 'ALLOW', outcome: 'DEFER',
        reason_code: 'required_detector_uncertain' }, suspension: { type: 'context' } });
    const transformOutage = evaluationSnapshot({ detector_requirements: [{ detector_id: 'redactor',
      detector_manifest_hash: C, required: true, purpose: 'transform' }], detector_results: [] });
    const denied = coordinator({ base: { action_taken: 'redacted', modified_arguments_hash: D },
      snapshot: transformOutage }).prepareDecision(action()).value.receipt.body;
    expect(denied).toMatchObject({ outcome: 'DENY', execution_authorized: false,
      evaluation: { requested_outcome: 'MODIFY', outcome: 'DENY',
        reason_code: 'required_transform_unavailable' } });
    expect(denied.action).not.toHaveProperty('effective_arguments_hash');
  });

  test('signs MODIFY output and supports approval and context suspension decisions', () => {
    const modified = coordinator({ base: { action_taken: 'redacted', modified_arguments_hash: D } })
      .prepareDecision(action()).value.receipt.body;
    expect(modified).toMatchObject({ outcome: 'MODIFY', execution_authorized: true,
      action: { effective_arguments_hash: D } });
    const approval = coordinator({ base: { action_taken: 'blocked', approval_required: true,
      approval_request_id: 'approval-1', approval_action_hash: A,
      approval_expires_at_ms: 1_500 } }).prepareDecision(action()).value.receipt.body;
    expect(approval).toMatchObject({ outcome: 'STEP_UP', execution_authorized: false,
      suspension: { suspension_id: 'approval-1', type: 'approval', expires_at_ms: 1_500,
        approval_action_hash: A } });
    const context = coordinator().prepareDecision(action('defer', ['deploy', 'other'])).value.receipt.body;
    expect(context).toMatchObject({ outcome: 'DEFER', execution_authorized: false,
      suspension: { type: 'context', expires_at_ms: 1_500 } });
  });

  test('resolves a trusted approval once and binds it to the original action', () => {
    const times = [1_000, 1_100];
    const approvalVerifier: StrictApprovalVerifier = (evidence, expected) => {
      if ((evidence as { token?: string }).token !== 'trusted') throw new Error('untrusted approval');
      return { request_id: expected.request_id, action_hash: expected.action_hash,
        principal_id: 'reviewer-1', decision: expected.decision,
        source_hash: D, expires_at_ms: 1_400 };
    };
    const subject = coordinator({ clock: () => times.shift()!, approvalVerifier,
      base: { action_taken: 'blocked', approval_required: true,
        approval_request_id: 'approval-1', approval_action_hash: A,
        approval_expires_at_ms: 1_500 } });
    const pending = subject.prepareDecision(action('approval-action'));
    const decision = subject.commitPrepared(pending.token, pending.receipt_hash);
    expect('receipt' in decision ? decision.receipt.body.outcome : '').toBe('STEP_UP');
    const prepared = subject.prepareApprovalResolution({
      suspended_receipt_hash: pending.receipt_hash,
      method: 'approval_granted', approval_evidence: { token: 'trusted' },
    });
    expect(subject.prepareApprovalResolution({
      suspended_receipt_hash: pending.receipt_hash,
      method: 'approval_granted', approval_evidence: { token: 'trusted' },
    })).toEqual(prepared);
    expect(prepared.value.body).toMatchObject({ record_type: 'resolution', sequence: 2,
      previous_receipt_hash: pending.receipt_hash, outcome: 'ALLOW',
      execution_authorized: true, action: { action_id: 'approval-action' },
      resolution: { resolves_receipt_hash: pending.receipt_hash,
        suspension_id: 'approval-1', method: 'approval_granted',
        approval_evidence_hash: D } });
    subject.commitPrepared(prepared.token, prepared.receipt_hash);
    expect(() => subject.prepareApprovalResolution({
      suspended_receipt_hash: pending.receipt_hash,
      method: 'approval_granted', approval_evidence: { token: 'trusted' },
    })).toThrow('already resolved');
  });

  test('rejects expired, mismatched, and delegated approval authority', () => {
    const base = { action_taken: 'blocked', approval_required: true,
      approval_request_id: 'approval-1', approval_action_hash: A,
      approval_expires_at_ms: 1_500 } as const;
    const expired = coordinator({ clock: (() => {
      const times = [1_000, 1_500]; return () => times.shift()!;
    })(), base, approvalVerifier: (_evidence, expected) => ({
      request_id: expected.request_id, action_hash: expected.action_hash,
      principal_id: 'reviewer-1', decision: expected.decision,
      source_hash: D, expires_at_ms: 1_500,
    }) });
    const pending = expired.prepareDecision(action());
    expired.commitPrepared(pending.token, pending.receipt_hash);
    expect(() => expired.prepareApprovalResolution({
      suspended_receipt_hash: pending.receipt_hash,
      method: 'approval_granted', approval_evidence: {},
    })).toThrow('expiry');

    const mismatched = coordinator({ clock: (() => {
      const times = [1_000, 1_100]; return () => times.shift()!;
    })(), base, approvalVerifier: (_evidence, expected) => ({
      request_id: expected.request_id, action_hash: C,
      principal_id: 'reviewer-1', decision: expected.decision,
      source_hash: D, expires_at_ms: 1_400,
    }) });
    const wrong = mismatched.prepareDecision(action());
    mismatched.commitPrepared(wrong.token, wrong.receipt_hash);
    expect(() => mismatched.prepareApprovalResolution({
      suspended_receipt_hash: wrong.receipt_hash,
      method: 'approval_granted', approval_evidence: {},
    })).toThrow('expected binding');

    const delegated = coordinator({ clock: (() => {
      const times = [1_000, 1_100]; return () => times.shift()!;
    })(), base, approvalVerifier: (_evidence, expected) => ({
      request_id: expected.request_id, action_hash: expected.action_hash,
      principal_id: 'reviewer-1', decision: expected.decision,
      source_hash: D, expires_at_ms: 1_400,
    }), identitySnapshot: (timestamp, deviceSigner) => ({
      ...identity(timestamp, deviceSigner), relationship: 'delegated',
      requester: { requester_ref_hash: C, principal_type: 'human',
        role_ids: ['owner'], privilege_scopes: ['write'] },
      delegation_chain: [{ hop: 0, delegation_id_hash: D,
        delegator_ref_hash: C, delegatee_ref_hash: B, granted_scopes: ['write'],
        issued_at_ms: 900, expires_at_ms: 1_050 }],
    }) });
    const delegatedPending = delegated.prepareDecision(action());
    delegated.commitPrepared(delegatedPending.token, delegatedPending.receipt_hash);
    expect(() => delegated.prepareApprovalResolution({
      suspended_receipt_hash: delegatedPending.receipt_hash,
      method: 'approval_granted', approval_evidence: {},
    })).toThrow('delegated authority');
  });

  test('advances only after commit, preserves exact retries, and rejects approval reuse', () => {
    const base = { action_taken: 'blocked', approval_required: true,
      approval_request_id: 'approval-1', approval_action_hash: A,
      approval_expires_at_ms: 1_500 } as const;
    const subject = coordinator({ base });
    const first = subject.prepareDecision(action('one'));
    expect(subject.prepareDecision(action('one'))).toEqual(first);
    expect(subject.inspectState()).toMatchObject({ sequence: 0, head_receipt_hash: null });
    expect(() => subject.commitPrepared('wrong', first.receipt_hash)).toThrow('token mismatch');
    expect(() => subject.commitPrepared(first.token, C)).toThrow('hash mismatch');
    subject.commitPrepared(first.token, first.receipt_hash);
    expect(subject.inspectState()).toMatchObject({ sequence: 1, head_receipt_hash: first.receipt_hash });
    expect(() => subject.prepareDecision(action('one'))).toThrow('already committed');
    expect(() => subject.prepareDecision(action('two'))).toThrow('already pending');
  });

  test('keeps sequence/linking monotonic and freezes ambiguous admission', () => {
    const times = [1_000, 1_001]; const subject = coordinator({ clock: () => times.shift()! });
    const first = subject.prepareDecision(action('one'));
    subject.commitPrepared(first.token, first.receipt_hash);
    const second = subject.prepareDecision(action('two'));
    expect(second.value.receipt.body).toMatchObject({ sequence: 2, timestamp_ms: 1_001,
      previous_receipt_hash: first.receipt_hash });
    subject.freezePrepared(second.token, second.receipt_hash, 'lost_ack');
    expect(() => subject.prepareDecision(action('two'))).toThrow('frozen');
  });

  test('aborts only with definitive no-store and tenant-binds deterministic receipts', () => {
    const subject = coordinator(); const prepared = subject.prepareDecision(action());
    expect(() => subject.abortPrepared(prepared.token, prepared.receipt_hash, {} as never))
      .toThrow('definitive_no_store');
    subject.abortPrepared(prepared.token, prepared.receipt_hash, DEFINITIVE_NO_STORE);
    expect(subject.inspectState()).not.toHaveProperty('prepared');
    const left = coordinator({ tenantId: 'tenant-1' }).prepareDecision(action()).value.receipt;
    const right = coordinator({ tenantId: 'tenant-2' }).prepareDecision(action()).value.receipt;
    expect(left.receipt_hash).toBe(PARITY_HASH);
    expect(left.signature.value).toBe(PARITY_SIGNATURE);
    expect(left.receipt_hash).not.toBe(right.receipt_hash);
  });

  test('preserves committed state on clock, signer, and process-boundary failures', () => {
    const times = [1_000, 999]; const subject = coordinator({ clock: () => times.shift()! });
    const first = subject.prepareDecision(action('one'));
    subject.commitPrepared(first.token, first.receipt_hash);
    expect(() => subject.prepareDecision(action('two'))).toThrow('clock regressed');
    expect(subject.inspectState()).toMatchObject({ sequence: 1, head_receipt_hash: first.receipt_hash });
    expect(subject.inspectState()).not.toHaveProperty('prepared');

    const valid = signer('02');
    const broken: DeviceSigner = { ...valid, signBytes: () => '0'.repeat(128) };
    const unsigned = coordinator({ deviceSigner: broken });
    expect(() => unsigned.prepareDecision(action())).toThrow('self-verification');
    expect(unsigned.inspectState()).toMatchObject({ sequence: 0, head_receipt_hash: null });
    expect(unsigned.inspectState()).not.toHaveProperty('prepared');

    let pid = 7; const forked = coordinator({ pid: () => pid }); pid = 8;
    expect(() => forked.prepareDecision(action())).toThrow('process boundary');
  });
});
