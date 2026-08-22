import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { IntentPolicyV2Input, IntentV2BaseResult } from '../../src/policy/intent-alignment-v2';
import { StrictReceiptCoordinatorV2 } from '../../src/governance/strict-receipt-coordinator-v2';
import {
  decisionV2Fingerprint, resolutionV2Fingerprint, timeoutV2Fingerprint,
} from '../../src/governance/strict-receipt-coordinator-v2-support';
import { DEFINITIVE_NO_STORE } from '../../src/governance/strict-receipt-prepared-state';
import { verifyStrictReceiptV2, verifyStrictReceiptV2Chain } from '../../src/governance/strict-receipt-v2-verify';
import { loadDeviceSigner, type DeviceSigner } from '../../src/proxy/device-identity';

const A = 'a'.repeat(64); const B = 'b'.repeat(64); const D = 'd'.repeat(64);
const POLICY: IntentPolicyV2Input = {
  schema: 'obsvr-intent-policy-v2', profile_version: '2.0', intent_scopes: [{
    intent_id: 'deploy', allowed_actions: [{ kind: 'tool', name: 'send' }],
    allowed_targets: ['prod'], allowed_requested_scopes: ['write'],
    allowed_data_classifications: ['confidential'],
  }],
};
function signer(seed = '00'): DeviceSigner {
  const path = join(mkdtempSync(join(tmpdir(), 'obsvr-v2-coordinator-')), 'seed.key');
  writeFileSync(path, seed.repeat(32)); return loadDeviceSigner(path);
}
function context(argumentsHash = A) {
  return { agent_id: 'agent-1', active_intents: ['deploy'], privilege_scope: ['write'],
    current_action: { kind: 'tool', name: 'send', arguments_hash: argumentsHash,
      target: 'prod', requested_scopes: ['write'], data_classifications: ['confidential'] },
    run_id: 'run-1', thread_id: 'thread-1' };
}
function coordinator(clock: () => number, deviceSigner = signer(), extras = {}) {
  return new StrictReceiptCoordinatorV2({
    signer: deviceSigner, policy: POLICY, sdk_language: 'typescript', sdk_version: '0.test',
    tenant_id: 'tenant-1', session_id: 'session-1', clock, defer_ttl_ms: 500,
    approval_verifier: (evidence, expected) => {
      const raw = evidence as { token?: string; expires_at_ms?: number };
      if (raw?.token !== 'trusted' || typeof raw.expires_at_ms !== 'number') throw new Error('untrusted approval evidence');
      return { request_id: expected.request_id, action_hash: expected.action_hash,
        principal_id: 'reviewer-1', decision: expected.decision,
        source_hash: D, expires_at_ms: raw.expires_at_ms };
    }, ...extras,
  });
}
function prepare(subject: StrictReceiptCoordinatorV2, actionId: string, base: IntentV2BaseResult, hash = A) {
  return subject.prepareDecision({ context: context(hash), base_result: base,
    policy_version: 'policy-1', rule_ids: ['rule-b', 'rule-a'], action_id: actionId });
}

describe('strict receipt v2 coordinator', () => {
  it('emits only tenant-bound v2 data and advances only after commit', () => {
    const deviceSigner = signer(); const subject = coordinator(() => 1000, deviceSigner);
    const first = prepare(subject, 'action-1', { action_taken: 'allowed' });
    expect(subject.inspectState()).toMatchObject({ tenant_id: 'tenant-1', session_id: 'session-1', sequence: 0 });
    expect(first.value.receipt.body).toMatchObject({ schema: 'obsvr-strict-receipt-v2',
      profile_version: '2.0', tenant_id: 'tenant-1', sequence: 1,
      action: { target_hash: expect.stringMatching(/^[0-9a-f]{64}$/) },
      evaluation: { engine_version: 'obsvr-intent/2' } });
    expect(JSON.stringify(first)).not.toContain('"target":"prod"');
    expect(verifyStrictReceiptV2(first.value.receipt,
      { pinned_public_key_b64: deviceSigner.publicKeyB64 })).toMatchObject({
      schema_valid: true, hash_valid: true, signature_valid: true,
      semantic_valid: true, identity_binding_valid: true, key_trust: 'pinned',
    });
    expect(prepare(subject, 'action-1', { action_taken: 'allowed' })).toEqual(first);
    subject.commitPrepared(first.token, first.receipt_hash);
    expect(subject.inspectState()).toMatchObject({ sequence: 1, head_receipt_hash: first.receipt_hash });
    expect(() => prepare(subject, 'action-1', { action_taken: 'allowed' })).toThrow('already committed');
  });

  it('keeps exact links and monotonic time across committed decisions', () => {
    const deviceSigner = signer(); const times = [1000, 900];
    const subject = coordinator(() => times.shift()!, deviceSigner);
    const first = prepare(subject, 'one', { action_taken: 'allowed' });
    const one = subject.commitPrepared(first.token, first.receipt_hash);
    const second = prepare(subject, 'two', { action_taken: 'blocked' }, B);
    const two = subject.commitPrepared(second.token, second.receipt_hash);
    expect(two).toMatchObject({ receipt: { body: { sequence: 2, timestamp_ms: 1000,
      clock_regression_clamped: true, previous_receipt_hash: first.receipt_hash } } });
    expect(verifyStrictReceiptV2Chain(
      [(one as { receipt: unknown }).receipt, (two as { receipt: unknown }).receipt],
      { pinned_public_key_b64: deviceSigner.publicKeyB64 },
    )).toEqual({ valid: true, errors: [] });
  });

  it('binds trusted approval and refuses caller-shaped evidence', () => {
    const deviceSigner = signer(); const times = [1000, 1100, 1100];
    const subject = coordinator(() => times.shift()!, deviceSigner);
    const pending = prepare(subject, 'approval', { action_taken: 'blocked', approval_required: true,
      approval_request_id: 'request-1', approval_action_hash: A, approval_expires_at_ms: 1500 });
    const decision = subject.commitPrepared(pending.token, pending.receipt_hash) as { receipt: typeof pending.value.receipt };
    expect(() => subject.prepareResolution({ suspended_receipt_hash: pending.receipt_hash,
      method: 'approval_granted', context: context(), base_result: { action_taken: 'allowed' },
      policy_version: 'policy-1', rule_ids: [], approval_evidence: { principal_id: 'attacker' } }))
      .toThrow('untrusted approval evidence');
    const resolution = subject.prepareResolution({ suspended_receipt_hash: pending.receipt_hash,
      method: 'approval_granted', context: context(), base_result: { action_taken: 'allowed' },
      policy_version: 'policy-1', rule_ids: [],
      approval_evidence: { token: 'trusted', expires_at_ms: 1500 } });
    expect(subject.prepareResolution({ suspended_receipt_hash: pending.receipt_hash,
      method: 'approval_granted', context: context(), base_result: { action_taken: 'allowed' },
      policy_version: 'policy-1', rule_ids: [],
      approval_evidence: { token: 'trusted', expires_at_ms: 1500 } })).toEqual(resolution);
    const resolved = subject.commitPrepared(resolution.token, resolution.receipt_hash);
    expect(verifyStrictReceiptV2Chain([decision.receipt, resolved],
      { pinned_public_key_b64: deviceSigner.publicKeyB64 })).toEqual({ valid: true, errors: [] });
  });

  it('times out only at expiry and preserves abort/freeze ambiguity semantics', () => {
    const times = [1000, 1499, 1500, 1500]; const subject = coordinator(() => times.shift()!);
    const pending = prepare(subject, 'approval', { action_taken: 'blocked', approval_required: true,
      approval_request_id: 'request-1', approval_action_hash: A, approval_expires_at_ms: 1500 });
    subject.commitPrepared(pending.token, pending.receipt_hash);
    expect(() => subject.prepareResolution({ suspended_receipt_hash: pending.receipt_hash,
      method: 'expired' as never, context: context(), base_result: { action_taken: 'blocked' },
      policy_version: 'p', rule_ids: [] })).toThrow('prepareTimeout');
    expect(() => subject.prepareTimeout({ suspended_receipt_hash: pending.receipt_hash,
      policy_version: 'policy-1', rule_ids: [] })).toThrow('not expired');
    const timeout = subject.prepareTimeout({ suspended_receipt_hash: pending.receipt_hash,
      policy_version: 'policy-1', rule_ids: [] });
    expect(timeout.value.body).toMatchObject({ evaluation: { outcome: 'DENY' },
      resolution: { method: 'expired', resolved_at_ms: 1500 } });
    subject.abortPrepared(timeout.token, timeout.receipt_hash, DEFINITIVE_NO_STORE);
    const retry = subject.prepareTimeout({ suspended_receipt_hash: pending.receipt_hash,
      policy_version: 'policy-1', rule_ids: [] });
    subject.freezePrepared(retry.token, retry.receipt_hash);
    expect(() => subject.prepareTimeout({ suspended_receipt_hash: pending.receipt_hash,
      policy_version: 'policy-1', rule_ids: [] })).toThrow('frozen');
  });

  it('refuses approval at the exact expiry boundary without advancing', () => {
    const times = [1000, 1500]; const subject = coordinator(() => times.shift()!);
    const pending = prepare(subject, 'approval', { action_taken: 'blocked', approval_required: true,
      approval_request_id: 'request-1', approval_action_hash: A, approval_expires_at_ms: 1500 });
    subject.commitPrepared(pending.token, pending.receipt_hash);
    expect(() => subject.prepareResolution({ suspended_receipt_hash: pending.receipt_hash,
      method: 'approval_granted', context: context(), base_result: { action_taken: 'allowed' },
      policy_version: 'policy-1', rule_ids: [],
      approval_evidence: { token: 'trusted', expires_at_ms: 1500 } })).toThrow('expired');
    expect(subject.inspectState()).toMatchObject({ sequence: 1 });
    expect(subject.inspectState()).not.toHaveProperty('prepared');
  });

  it('rejects caller-owned history, duplicate approval IDs, and prepared-state drift', () => {
    const subject = coordinator(() => 1000);
    expect(() => subject.prepareDecision({ context: { ...context(), session_id: 'caller' } as never,
      base_result: { action_taken: 'allowed' }, policy_version: 'p', rule_ids: [], action_id: 'bad' }))
      .toThrow('caller session_id');
    expect(() => subject.prepareDecision({ context: { ...context(), prior_actions: [] } as never,
      base_result: { action_taken: 'allowed' }, policy_version: 'p', rule_ids: [], action_id: 'bad' }))
      .toThrow('caller prior_actions');
    const first = prepare(subject, 'one', { action_taken: 'blocked', approval_required: true,
      approval_request_id: 'request-1', approval_action_hash: A, approval_expires_at_ms: 1500 });
    expect(() => subject.commitPrepared('wrong', first.receipt_hash)).toThrow('token mismatch');
    expect(() => subject.commitPrepared(first.token, B)).toThrow('hash mismatch');
    expect(() => prepare(subject, 'two', { action_taken: 'allowed' })).toThrow('different receipt');
    subject.commitPrepared(first.token, first.receipt_hash);
    expect(() => prepare(subject, 'two', { action_taken: 'blocked', approval_required: true,
      approval_request_id: 'request-1', approval_action_hash: A, approval_expires_at_ms: 1500 }))
      .toThrow('already pending');
  });

  it('validates DEFER resolution fields and never serializes a raw target', () => {
    const times = [1000, 1100, 1100, 1100]; const subject = coordinator(() => times.shift()!);
    const pending = prepare(subject, 'defer', { action_taken: 'hook_error' });
    subject.commitPrepared(pending.token, pending.receipt_hash);
    expect(() => subject.prepareResolution({ suspended_receipt_hash: pending.receipt_hash,
      method: 'context_supplied', context: { ...context(), thread_id: 'changed' },
      base_result: { action_taken: 'allowed' },
      policy_version: 'p', rule_ids: [], resolver_principal_id: 'reviewer',
      resolution_source_hash: D })).toThrow('outside required_fields');
    const resolved = subject.prepareResolution({ suspended_receipt_hash: pending.receipt_hash,
      method: 'context_supplied', context: context(), base_result: { action_taken: 'allowed' },
      policy_version: 'p', rule_ids: [], resolver_principal_id: 'reviewer',
      resolution_source_hash: D });
    expect(resolved.value.body.evaluation.outcome).toBe('ALLOW');
    expect(JSON.stringify(resolved)).not.toContain('"target":"prod"');
  });

  it('rejects resolution identity, target, outcome, and resolver-source drift', () => {
    const subject = coordinator(() => 1100);
    const pending = prepare(subject, 'approval', { action_taken: 'blocked', approval_required: true,
      approval_request_id: 'request-1', approval_action_hash: A, approval_expires_at_ms: 1500 });
    subject.commitPrepared(pending.token, pending.receipt_hash);
    const approval = (overrides = {}) => ({ suspended_receipt_hash: pending.receipt_hash,
      method: 'approval_granted' as const, context: context(), base_result: { action_taken: 'allowed' as const },
      policy_version: 'p', rule_ids: [], approval_evidence: { token: 'trusted', expires_at_ms: 1500 },
      ...overrides });
    expect(() => subject.prepareResolution(approval({ context: { ...context(), agent_id: 'other' } })))
      .toThrow('does not match');
    expect(() => subject.prepareResolution(approval({ context: { ...context(), current_action: {
      ...context().current_action, target: 'other' } } }))).toThrow('does not match');
    expect(() => subject.prepareResolution(approval({ resolver_principal_id: 'caller' })))
      .toThrow('approval source');
    expect(() => subject.prepareResolution(approval({ method: 'approval_denied',
      base_result: { action_taken: 'allowed' } }))).toThrow('requires DENY');
    expect(() => subject.prepareResolution(approval({ method: 'cancelled',
      base_result: { action_taken: 'allowed' }, approval_evidence: undefined,
      resolver_principal_id: 'reviewer', resolution_source_hash: D }))).toThrow('requires DENY');
  });

  it('binds every request fingerprint to tenant and refuses process reuse', () => {
    const decision = { context: context(), base_result: { action_taken: 'allowed' as const },
      policy_version: 'policy-1', rule_ids: [], action_id: 'one' };
    expect(decisionV2Fingerprint(decision, 'tenant-a', 'session-1'))
      .not.toBe(decisionV2Fingerprint(decision, 'tenant-b', 'session-1'));
    const resolution = { suspended_receipt_hash: A, method: 'cancelled' as const,
      context: context(), base_result: { action_taken: 'blocked' as const }, policy_version: 'p',
      rule_ids: [], resolver_principal_id: 'reviewer', resolution_source_hash: D };
    expect(resolutionV2Fingerprint(resolution, 'tenant-a', 'session-1'))
      .not.toBe(resolutionV2Fingerprint(resolution, 'tenant-b', 'session-1'));
    expect(timeoutV2Fingerprint({ suspended_receipt_hash: A, policy_version: 'p', rule_ids: [] },
      'tenant-a', 'session-1')).not.toBe(timeoutV2Fingerprint(
      { suspended_receipt_hash: A, policy_version: 'p', rule_ids: [] }, 'tenant-b', 'session-1'));
    let pid = 1; const subject = coordinator(() => 1000, signer(), { pid: () => pid });
    pid = 2; expect(() => subject.inspectState()).toThrow('process boundary');
  });

  it('does not reserve sequence or chain state when signer self-verification fails', () => {
    const valid = signer(); const broken: DeviceSigner = { ...valid, signBytes: () => '0'.repeat(128) };
    const subject = coordinator(() => 1000, broken);
    expect(() => prepare(subject, 'one', { action_taken: 'allowed' })).toThrow('self-verification');
    expect(subject.inspectState()).toMatchObject({ sequence: 0, head_receipt_hash: null });
    expect(subject.inspectState()).not.toHaveProperty('prepared');
  });
});
