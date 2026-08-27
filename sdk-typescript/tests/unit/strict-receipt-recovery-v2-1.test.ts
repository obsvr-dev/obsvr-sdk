import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { actionTargetHash } from '../../src/governance/action-context-v2';
import { createStrictIdentityEvidenceV21Authority } from '../../src/governance/strict-identity-evidence-v2-1';
import { createTrustedEvaluationEvidenceProviderV21 } from '../../src/governance/strict-evaluation-evidence-v2-1';
import {
  RecoverableStrictReceiptCoordinatorV21,
} from '../../src/governance/strict-receipt-coordinator-v2-1-recovery';
import { createTrustedIntentDecisionProviderV21 } from '../../src/governance/strict-receipt-coordinator-v2-1';
import type { StrictDecisionActionV21Input } from '../../src/governance/strict-receipt-coordinator-v2-1-types';
import {
  reconcileStrictReceiptV21,
} from '../../src/governance/strict-receipt-reconcile-v2-1';
import { strictReceiptV21KeyId } from '../../src/governance/strict-receipt-v2-1';
import { intentPolicyV2Hash, type IntentPolicyV2Input } from '../../src/policy/intent-alignment-v2';
import { loadDeviceSigner, type DeviceSigner } from '../../src/proxy/device-identity';

const A = 'a'.repeat(64); const B = 'b'.repeat(64); const TARGET = actionTargetHash('prod');
const PARITY_RECEIPT_HASH = '2f22fc808f9ddb6f49f3c853bec7c57c32bc26a1a325089bb2044cfc5556ff1c';
const POLICY: IntentPolicyV2Input = { schema: 'obsvr-intent-policy-v2', profile_version: '2.0',
  intent_scopes: [{ intent_id: 'deploy', allowed_actions: [{ kind: 'tool', name: 'send' }],
    allowed_targets: ['prod'], allowed_requested_scopes: ['write'],
    allowed_data_classifications: ['confidential'] }] };

function signer(seed = '00'): DeviceSigner {
  const path = join(mkdtempSync(join(tmpdir(), 'obsvr-v21-recovery-')), 'seed.key');
  writeFileSync(path, seed.repeat(32), 'ascii'); return loadDeviceSigner(path);
}
function action(id = 'action-1'): StrictDecisionActionV21Input {
  return { action_id: id, active_intents: ['deploy'], current_action: { kind: 'tool', name: 'send',
    arguments_hash: A, target_hash: TARGET, data_classifications: ['confidential'],
    requested_scopes: ['write'] }, run_id: 'run-1', thread_id: 'thread-1' };
}
function options(deviceSigner: DeviceSigner, pid = 7) {
  return { signer: deviceSigner, policy: POLICY, tenant_id: 'tenant-1', session_id: 'session-1',
    sdk_language: 'typescript' as const, sdk_version: '0.11.2', clock: () => 1_000,
    defer_ttl_ms: 500, identity_authority: createStrictIdentityEvidenceV21Authority(),
    identity_snapshot: (timestamp: number) => ({ schema: 'obsvr-strict-identity-evidence-v2-1' as const,
      profile_version: '2.1' as const, relationship: 'direct' as const, receipt_time_ms: timestamp,
      requester: { requester_ref_hash: B, principal_type: 'agent' as const,
        role_ids: ['worker'], privilege_scopes: ['write'] },
      initiator: { agent_ref_hash: B, key_id: strictReceiptV21KeyId(deviceSigner.rawPublicKey),
        role_ids: ['worker'], privilege_scopes: ['write'] }, delegation_chain: [] }),
    intent_decision_provider: createTrustedIntentDecisionProviderV21(() => ({ action_taken: 'allowed' })),
    evaluation_evidence_provider: createTrustedEvaluationEvidenceProviderV21(() => ({
      effective_policy: { version: 'policy-1', artifact_hash: intentPolicyV2Hash(POLICY),
        matched_rule_ids: ['deploy'] }, detector_requirements: [], detector_results: [],
    })), pid: () => pid, prepared_token_factory: () => 'prepared-token' };
}
function response(value: unknown, status = 200) {
  return Promise.resolve({ status, headers: {}, body: Buffer.from(JSON.stringify(value)) });
}

describe('strict profile 2.1 authenticated recovery', () => {
  test('restores exact prepared state, blocks work, and commits only trusted accepted proof', async () => {
    const deviceSigner = signer(); const original = new RecoverableStrictReceiptCoordinatorV21(options(deviceSigner));
    const committed = original.prepareDecision(action());
    expect(committed.receipt_hash).toBe(PARITY_RECEIPT_HASH);
    original.commitPrepared(committed.token, committed.receipt_hash);
    const prepared = original.prepareDecision(action('pending'));
    const checkpoint = original.exportRecoveryCheckpoint();
    expect({ hash: checkpoint.checkpoint_hash, signature: checkpoint.signature.value }).toEqual({
      hash: '61a5df39cf47929f07d064e5d26f8d8572c7071d3c704aac360ef49dbea9e14a',
      signature: 'df8b6864f51cc1a8680c983acb771ea5aa065cf3959eddf372157a0dd7432748bb5ad102566ee8d335ae633e1627ccf8aa11ce238c9a3890bb3936643fc19b00',
    });
    expect(checkpoint.document.prepared?.kind).toBe('decision');
    const recoveredDecision = checkpoint.document.prepared;
    if (!recoveredDecision || recoveredDecision.kind !== 'decision') throw new Error('decision missing');
    expect(recoveredDecision.result.receipt.receipt_hash).toBe(prepared.receipt_hash);
    const restored = new RecoverableStrictReceiptCoordinatorV21(options(deviceSigner), {
      checkpoint, expected_origin_pid: 7,
    });
    expect(restored.inspectState()).toMatchObject({ sequence: 1, head_receipt_hash: committed.receipt_hash, frozen: true,
      freeze_reason: 'restart_reconciliation_required' });
    expect(() => restored.prepareDecision(action('other'))).toThrow('requires accepted reconciliation');
    const receipt = recoveredDecision.result.receipt;
    const absent = await reconcileStrictReceiptV21(receipt, { ingest_url: 'http://127.0.0.1:8080',
      api_key: 'test', max_attempts: 1, resolver: async () => ['127.0.0.1'],
      trusted_pinned_transport: () => response({ schema: 'obsvr-strict-receipt-reconciliation-v2-1',
        ok: true, status: 'absent', session_id: 'session-1', receipt_hash: receipt.receipt_hash }, 404) });
    expect(absent.status).toBe('absent');
    expect(() => restored.reconcileRecoveredAccepted(absent)).toThrow('trusted accepted');
    const accepted = await reconcileStrictReceiptV21(receipt, { ingest_url: 'http://127.0.0.1:8080',
      api_key: 'test', max_attempts: 1, resolver: async () => ['127.0.0.1'],
      trusted_pinned_transport: (target, body, headers) => {
        expect(target.url.pathname).toBe('/ingest/strict-receipts/v2-1/reconcile');
        expect(headers['Idempotency-Key']).toBe(receipt.receipt_hash);
        expect(JSON.parse(body)).toEqual({ schema: 'obsvr-strict-receipt-ingest-v2-1',
          tenant_id: 'tenant-1', session_id: 'session-1', receipt });
        return response({ schema: 'obsvr-strict-receipt-reconciliation-v2-1', ok: true,
          status: 'accepted', session_id: 'session-1', receipt_hash: receipt.receipt_hash,
          accepted_at_ms: 2_000 });
      } });
    expect(restored.reconcileRecoveredAccepted(accepted)).toEqual(receipt);
    expect(restored.inspectState()).toMatchObject({ sequence: 2, head_receipt_hash: receipt.receipt_hash,
      frozen: false });
    expect(restored.prepareDecision(action('next')).value.receipt.body).toMatchObject({
      sequence: 3, previous_receipt_hash: receipt.receipt_hash,
    });
  });

  test('rejects tamper, key, tenant, sdk, profile, and PID drift', () => {
    const deviceSigner = signer(); const subject = new RecoverableStrictReceiptCoordinatorV21(options(deviceSigner));
    subject.prepareDecision(action()); const checkpoint = subject.exportRecoveryCheckpoint();
    const changed = structuredClone(checkpoint); changed.document.tenant_id = 'evil';
    expect(() => new RecoverableStrictReceiptCoordinatorV21(options(deviceSigner), {
      checkpoint: changed, expected_origin_pid: 7,
    })).toThrow();
    expect(() => new RecoverableStrictReceiptCoordinatorV21(options(signer('01')), {
      checkpoint, expected_origin_pid: 7,
    })).toThrow('invalid checkpoint envelope');
    expect(() => new RecoverableStrictReceiptCoordinatorV21({ ...options(deviceSigner), tenant_id: 'other' }, {
      checkpoint, expected_origin_pid: 7,
    })).toThrow('tenant/session/sdk/profile');
    expect(() => new RecoverableStrictReceiptCoordinatorV21({ ...options(deviceSigner), session_id: 'other' }, {
      checkpoint, expected_origin_pid: 7,
    })).toThrow('tenant/session/sdk/profile');
    expect(() => new RecoverableStrictReceiptCoordinatorV21({ ...options(deviceSigner), sdk_version: 'other' }, {
      checkpoint, expected_origin_pid: 7,
    })).toThrow('tenant/session/sdk/profile');
    expect(() => new RecoverableStrictReceiptCoordinatorV21(options(deviceSigner), {
      checkpoint, expected_origin_pid: 8,
    })).toThrow('origin PID');
    const forged = structuredClone(checkpoint); forged.document.profile_version = '2.0' as '2.1';
    expect(() => new RecoverableStrictReceiptCoordinatorV21(options(deviceSigner), {
      checkpoint: forged, expected_origin_pid: 7,
    })).toThrow();
  });

  test('conflict, retry, and malformed responses remain frozen', async () => {
    const deviceSigner = signer(); const original = new RecoverableStrictReceiptCoordinatorV21(options(deviceSigner));
    original.prepareDecision(action()); const checkpoint = original.exportRecoveryCheckpoint();
    for (const [status, value] of [[409, {}], [200, { schema: 'wrong' }], [503, {}]] as const) {
      const restored = new RecoverableStrictReceiptCoordinatorV21(options(deviceSigner), {
        checkpoint, expected_origin_pid: 7,
      });
      const recovered = checkpoint.document.prepared;
      if (!recovered || recovered.kind !== 'decision') throw new Error('decision missing');
      const receipt = recovered.result.receipt;
      const result = await reconcileStrictReceiptV21(receipt, { ingest_url: 'http://127.0.0.1:8080',
        api_key: 'test', max_attempts: 1, resolver: async () => ['127.0.0.1'],
        trusted_pinned_transport: () => response(value, status) });
      expect(result.status).not.toBe('accepted');
      expect(() => restored.reconcileRecoveredAccepted(result)).toThrow('trusted accepted');
      expect(restored.inspectState()).toMatchObject({ sequence: 0, frozen: true });
    }
  });

  test('restores a prepared approval without persisting raw approval evidence', async () => {
    const deviceSigner = signer(); const times = [1_000, 1_100];
    const recoveryOptions = { ...options(deviceSigner), clock: () => times.shift()!,
      intent_decision_provider: createTrustedIntentDecisionProviderV21(() => ({
        action_taken: 'blocked', approval_required: true, approval_request_id: 'approval-1',
        approval_action_hash: A, approval_expires_at_ms: 1_500,
      })), approval_verifier: (_evidence: unknown, expected: {
        request_id: string; action_hash: string; decision: 'granted' | 'denied';
      }) => ({ request_id: expected.request_id, action_hash: expected.action_hash,
        principal_id: 'reviewer-1', decision: expected.decision,
        source_hash: B, expires_at_ms: 1_400 }) };
    const original = new RecoverableStrictReceiptCoordinatorV21(recoveryOptions);
    const pending = original.prepareDecision(action('approval-action'));
    original.commitPrepared(pending.token, pending.receipt_hash);
    const prepared = original.prepareApprovalResolution({
      suspended_receipt_hash: pending.receipt_hash, method: 'approval_granted',
      approval_evidence: { token: 'must-not-persist' },
    });
    const checkpoint = original.exportRecoveryCheckpoint();
    expect(checkpoint.document.prepared?.kind).toBe('resolution');
    expect(JSON.stringify(checkpoint)).not.toContain('must-not-persist');
    const restored = new RecoverableStrictReceiptCoordinatorV21(recoveryOptions, {
      checkpoint, expected_origin_pid: 7,
    });
    const accepted = await reconcileStrictReceiptV21(prepared.value, {
      ingest_url: 'http://127.0.0.1:8080', api_key: 'test', max_attempts: 1,
      resolver: async () => ['127.0.0.1'], trusted_pinned_transport: () => response({
        schema: 'obsvr-strict-receipt-reconciliation-v2-1', ok: true,
        status: 'accepted', session_id: 'session-1', receipt_hash: prepared.receipt_hash,
        accepted_at_ms: 2_000,
      }),
    });
    expect(restored.reconcileRecoveredAccepted(accepted)).toEqual(prepared.value);
    expect(restored.inspectState()).toMatchObject({ sequence: 2,
      head_receipt_hash: prepared.receipt_hash, frozen: false });
    expect(() => restored.prepareApprovalResolution({
      suspended_receipt_hash: pending.receipt_hash, method: 'approval_granted',
      approval_evidence: {},
    })).toThrow('already resolved');
  });
});
