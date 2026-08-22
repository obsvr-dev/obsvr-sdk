import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { IntentPolicyV2Input } from '../../src/policy/intent-alignment-v2';
import { RecoverableStrictReceiptCoordinatorV2 } from '../../src/governance/strict-receipt-coordinator-v2-recovery';
import { reconcileStrictReceiptV2 } from '../../src/governance/strict-receipt-reconcile-v2';
import { verifyStrictRecoveryV2 } from '../../src/governance/strict-receipt-recovery-v2';
import { bindStrictV2JsonArguments, createTrustedStrictV2Admission,
  StrictReceiptRuntimeV2 } from '../../src/governance/strict-receipt-runtime-v2';
import { loadDeviceSigner } from '../../src/proxy/device-identity';

const A = 'a'.repeat(64);
const POLICY: IntentPolicyV2Input = { schema: 'obsvr-intent-policy-v2', profile_version: '2.0',
  intent_scopes: [{ intent_id: 'deploy', allowed_actions: [{ kind: 'tool', name: 'send' }],
    allowed_targets: ['prod'], allowed_requested_scopes: ['write'],
    allowed_data_classifications: ['confidential'] }] };
function signer() {
  const path = join(mkdtempSync(join(tmpdir(), 'obsvr-v2-recovery-')), 'seed.key');
  writeFileSync(path, '00'.repeat(32)); return loadDeviceSigner(path);
}
function options(deviceSigner: ReturnType<typeof signer>, pid: number, tenant = 'tenant-1') {
  return { signer: deviceSigner, policy: POLICY, sdk_language: 'typescript' as const,
    sdk_version: '0.test', tenant_id: tenant, session_id: 'session-1', clock: () => 1000,
    defer_ttl_ms: 500, approval_verifier: () => { throw new Error('unused'); }, pid: () => pid };
}
function decision(hash = A) {
  return { context: { agent_id: 'agent-1', active_intents: ['deploy'], privilege_scope: ['write'],
    current_action: { kind: 'tool', name: 'send', arguments_hash: hash, target: 'prod',
      requested_scopes: ['write'], data_classifications: ['confidential'] }, run_id: 'run-1' },
    base_result: { action_taken: 'allowed' as const }, policy_version: 'policy-1',
    rule_ids: ['rule-1'], action_id: 'action-1' };
}

describe('strict receipt v2 restart recovery', () => {
  test('authenticates exact prepared state and reconciles accept without invocation', async () => {
    const deviceSigner = signer();
    const original = new RecoverableStrictReceiptCoordinatorV2(options(deviceSigner, 41));
    const prepared = original.prepareDecision(decision());
    const checkpoint = original.exportRecoveryCheckpoint();
    const serialized = JSON.stringify(checkpoint);
    expect(serialized).not.toContain('"target":"prod"');
    expect(serialized).not.toContain('raw-arguments');

    const restored = new RecoverableStrictReceiptCoordinatorV2(
      options(deviceSigner, 42), { checkpoint, expected_origin_pid: 41 });
    expect(restored.inspectState()).toMatchObject({ sequence: 0, frozen: true,
      freeze_reason: 'restart_reconciliation_required' });
    expect(() => restored.prepareDecision(decision())).toThrow('requires reconciliation');
    const proof = await reconcileStrictReceiptV2(prepared.value.receipt, {
      ingest_url: 'https://example.com', api_key: 'key', max_attempts: 1,
      resolver: async () => ['8.8.8.8'], trusted_pinned_transport: async () => ({ status: 200,
        body: Buffer.from(JSON.stringify({ schema: 'obsvr-strict-receipt-reconciliation-v2',
          ok: true, status: 'accepted', session_id: 'session-1', receipt_hash: prepared.receipt_hash,
          accepted_at_ms: 1010 })) }),
    });
    expect(restored.reconcileRecoveredAccepted(proof).receipt_hash).toBe(prepared.receipt_hash);
    expect(restored.inspectState()).toMatchObject({ sequence: 1,
      head_receipt_hash: prepared.receipt_hash });
    const committed = verifyStrictRecoveryV2(restored.exportRecoveryCheckpoint(), deviceSigner);
    expect(committed).not.toHaveProperty('prepared');
    expect(committed.origin_pid).toBe(42);
  });

  test('refuses checkpoint tamper, identity drift, and absent reconciliation', async () => {
    const deviceSigner = signer(); const original = new RecoverableStrictReceiptCoordinatorV2(options(deviceSigner, 7));
    const prepared = original.prepareDecision(decision()); const checkpoint = original.exportRecoveryCheckpoint();
    const tampered = structuredClone(checkpoint); tampered.document.session_id = 'other';
    expect(() => verifyStrictRecoveryV2(tampered, deviceSigner)).toThrow();
    expect(() => new RecoverableStrictReceiptCoordinatorV2(
      options(deviceSigner, 8), { checkpoint, expected_origin_pid: 9 })).toThrow('origin PID');
    expect(() => new RecoverableStrictReceiptCoordinatorV2(
      options(deviceSigner, 8, 'other'), { checkpoint, expected_origin_pid: 7 })).toThrow('tenant/session/sdk');
    const restored = new RecoverableStrictReceiptCoordinatorV2(
      options(deviceSigner, 8), { checkpoint, expected_origin_pid: 7 });
    const absent = await reconcileStrictReceiptV2(prepared.value.receipt, {
      ingest_url: 'https://example.com', api_key: 'key', max_attempts: 1,
      resolver: async () => ['8.8.8.8'], trusted_pinned_transport: async () => ({ status: 404,
        body: Buffer.from(JSON.stringify({ schema: 'obsvr-strict-receipt-reconciliation-v2',
          ok: true, status: 'absent', session_id: 'session-1',
          receipt_hash: prepared.receipt_hash })) }),
    });
    expect(() => restored.reconcileRecoveredAccepted(absent)).toThrow('trusted accepted');
    expect(restored.inspectState()).toMatchObject({ sequence: 0, frozen: true });
  });

  test('persists prepared and committed checkpoints before admission and invocation', async () => {
    const deviceSigner = signer(); const subject = new RecoverableStrictReceiptCoordinatorV2(options(deviceSigner, 1));
    const bound = bindStrictV2JsonArguments({ message: 'safe' }); const events: string[] = [];
    const runtime = new StrictReceiptRuntimeV2(subject, { ingest_url: 'https://unused', api_key: 'key' },
      createTrustedStrictV2Admission(async (receipt) => { events.push('admit'); return {
        schema: 'obsvr-strict-receipt-admission-v2', tenant_id: 'tenant-1', session_id: 'session-1',
        disposition: 'accepted', status: 'accepted', receipt_hash: receipt.receipt_hash,
        accepted_at_ms: 1001, attempts: 1 }; }),
      { save: (checkpoint) => { const document = verifyStrictRecoveryV2(checkpoint, deviceSigner);
        events.push(document.prepared ? 'save-prepared' : 'save-committed'); } });
    const result = await runtime.runDecision({ decision: decision(bound.arguments_hash), action: {
      runtime_action_id: 'action-1', original_arguments: bound,
      invoke: () => { events.push('invoke'); return 'done'; } } });
    expect(result.status).toBe('executed');
    expect(events).toEqual(['save-prepared', 'admit', 'save-committed', 'invoke']);
  });

  test('checkpoint failure aborts locally before admission', async () => {
    const deviceSigner = signer(); const subject = new RecoverableStrictReceiptCoordinatorV2(options(deviceSigner, 1));
    const bound = bindStrictV2JsonArguments({ message: 'safe' }); let admits = 0; let invokes = 0;
    const runtime = new StrictReceiptRuntimeV2(subject, { ingest_url: 'https://unused', api_key: 'key' },
      createTrustedStrictV2Admission(async () => { admits += 1; throw new Error('must not admit'); }),
      { save: () => { throw new Error('disk unavailable'); } });
    const result = await runtime.runDecision({ decision: decision(bound.arguments_hash), action: {
      runtime_action_id: 'action-1', original_arguments: bound,
      invoke: () => { invokes += 1; } } });
    expect(result).toMatchObject({ status: 'nonexecuted', reason: 'recovery_persist_failed' });
    expect({ admits, invokes }).toEqual({ admits: 0, invokes: 0 });
    expect(subject.inspectState()).toMatchObject({ sequence: 0 });
    expect(subject.inspectState()).not.toHaveProperty('prepared');
  });
});
