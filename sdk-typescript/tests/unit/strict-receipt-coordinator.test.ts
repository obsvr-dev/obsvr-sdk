import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { IntentBaseResult, IntentPolicyInput } from '../../src/policy/intent-alignment';
import { StrictReceiptCoordinator } from '../../src/governance/strict-receipt-coordinator';
import {
  DEFINITIVE_NO_STORE,
  PreparedReceiptState,
} from '../../src/governance/strict-receipt-prepared-state';
import { verifyStrictReceiptChain } from '../../src/governance/strict-receipt-verify';
import { loadDeviceSigner, type DeviceSigner } from '../../src/proxy/device-identity';

const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);
const HASH_C = 'c'.repeat(64);
const HASH_D = 'd'.repeat(64);

const POLICY: IntentPolicyInput = {
  schema: 'obsvr-intent-policy-v1',
  profile_version: '1.0',
  intent_scopes: [{
    intent_id: 'deploy',
    allowed_actions: [{ kind: 'tool', name: 'send' }],
    allowed_targets: ['prod'],
    allowed_requested_scopes: ['write'],
    allowed_data_classifications: ['confidential'],
  }],
};

function signer(seed = '00'): DeviceSigner {
  const path = join(mkdtempSync(join(tmpdir(), 'obsvr-coordinator-')), 'seed.key');
  writeFileSync(path, seed.repeat(32));
  return loadDeviceSigner(path);
}

function context(argumentsHash = HASH_A) {
  return {
    agent_id: 'agent-1', active_intents: ['deploy'], privilege_scope: ['write'],
    current_action: {
      kind: 'tool', name: 'send', arguments_hash: argumentsHash, target: 'prod',
      requested_scopes: ['write'], data_classifications: ['confidential'],
    },
    run_id: 'run-1', thread_id: 'thread-1',
  };
}

function coordinator(
  clock: () => number, deviceSigner = signer(),
  extras: Partial<ConstructorParameters<typeof StrictReceiptCoordinator>[0]> = {},
) {
  return new StrictReceiptCoordinator({
    signer: deviceSigner, policy: POLICY, sdk_language: 'typescript',
    sdk_version: '0.test', session_id: 'session-1', clock, defer_ttl_ms: 500,
    approval_verifier: (evidence, expected) => {
      const raw = evidence as { token?: string; expires_at_ms?: number } | undefined;
      if (raw?.token !== 'trusted' || typeof raw.expires_at_ms !== 'number') {
        throw new Error('untrusted approval evidence');
      }
      return {
        request_id: expected.request_id, action_hash: expected.action_hash,
        principal_id: 'reviewer-1', decision: expected.decision,
        source_hash: HASH_D, expires_at_ms: raw.expires_at_ms,
      };
    },
    ...extras,
  });
}

function decide(
  subject: StrictReceiptCoordinator, actionId: string,
  baseResult: IntentBaseResult, argumentsHash = HASH_A,
) {
  return subject.decide({
    context: context(argumentsHash), base_result: baseResult,
    policy_version: 'policy-1', rule_ids: ['rule-b', 'rule-a'], action_id: actionId,
  });
}

describe('strict receipt coordinator', () => {
  it('serializes every outcome, clamps time, and keeps authorization fail-closed', () => {
    const times = [1000, 900, 1100, 1200, 1300];
    const subject = coordinator(() => times.shift() as number);
    const results = [
      decide(subject, 'allow', { action_taken: 'allowed' }),
      decide(subject, 'deny', { action_taken: 'blocked' }, HASH_B),
      decide(subject, 'modify', {
        action_taken: 'redacted', modified_arguments_hash: HASH_D,
      }, HASH_C),
      decide(subject, 'step', {
        action_taken: 'blocked', approval_required: true,
        approval_request_id: 'approval-1', approval_action_hash: HASH_A,
        approval_expires_at_ms: 1600,
      }),
      decide(subject, 'defer', { action_taken: 'hook_error' }, HASH_B),
    ];
    expect(results.map((item) => item.evaluation.outcome))
      .toEqual(['ALLOW', 'DENY', 'MODIFY', 'STEP_UP', 'DEFER']);
    expect(results.map((item) => item.receipt.body.execution_authorized))
      .toEqual([true, false, true, false, false]);
    expect(results[1].receipt.body).toMatchObject({
      timestamp_ms: 1000, clock_regression_clamped: true,
      previous_receipt_hash: results[0].receipt.receipt_hash,
    });
    expect(verifyStrictReceiptChain(results.map((item) => item.receipt)))
      .toEqual({ valid: true, errors: [] });
  });

  it('returns an exact idempotent receipt and rejects action-id drift', () => {
    const subject = coordinator(() => 1000);
    const first = decide(subject, 'same', { action_taken: 'allowed' });
    const retry = decide(subject, 'same', { action_taken: 'allowed' });
    expect(retry).toEqual(first);
    retry.receipt.body.action.name = 'caller-mutation';
    expect(decide(subject, 'same', { action_taken: 'allowed' })).toEqual(first);
    expect(() => decide(subject, 'same', { action_taken: 'blocked' }))
      .toThrow('action_id was reused with different input');
    expect(decide(subject, 'next', { action_taken: 'allowed' }, HASH_B).receipt.body.sequence)
      .toBe(2);
  });

  it('re-evaluates and binds approval resolution, then refuses replay', () => {
    const times = [1000, 1100, 1200];
    const subject = coordinator(() => times.shift() as number);
    const pending = decide(subject, 'step', {
      action_taken: 'blocked', approval_required: true,
      approval_request_id: 'approval-1', approval_action_hash: HASH_A,
      approval_expires_at_ms: 1500,
    });
    expect(() => subject.resolve({
      suspended_receipt_hash: pending.receipt.receipt_hash,
      method: 'approval_granted', context: context(),
      base_result: { action_taken: 'allowed' }, policy_version: 'policy-1',
      rule_ids: [],
    })).toThrow('untrusted approval evidence');
    const resolved = subject.resolve({
      suspended_receipt_hash: pending.receipt.receipt_hash,
      method: 'approval_granted', context: context(),
      base_result: { action_taken: 'allowed' }, policy_version: 'policy-1',
      rule_ids: [], approval_evidence: { token: 'trusted', expires_at_ms: 1500 },
    });
    expect(resolved.body).toMatchObject({
      record_type: 'resolution', execution_authorized: true,
      evaluation: { outcome: 'ALLOW' },
      resolution: { method: 'approval_granted', resolved_at_ms: 1200 },
    });
    expect(verifyStrictReceiptChain([pending.receipt, resolved]))
      .toEqual({ valid: true, errors: [] });
    expect(() => subject.resolve({
      suspended_receipt_hash: pending.receipt.receipt_hash,
      method: 'approval_granted', context: context(),
      base_result: { action_taken: 'allowed' }, policy_version: 'policy-1',
      rule_ids: [], approval_evidence: { token: 'trusted', expires_at_ms: 1500 },
    })).toThrow('already resolved');
  });

  it('does not treat caller-shaped approval data as trusted evidence', () => {
    const times = [1000, 1100];
    const subject = coordinator(() => times.shift() as number);
    const pending = decide(subject, 'step', {
      action_taken: 'blocked', approval_required: true,
      approval_request_id: 'approval-1', approval_action_hash: HASH_A,
      approval_expires_at_ms: 1500,
    });
    expect(() => subject.resolve({
      suspended_receipt_hash: pending.receipt.receipt_hash,
      method: 'approval_granted', context: context(),
      base_result: { action_taken: 'allowed' }, policy_version: 'policy-1',
      rule_ids: [], approval_evidence: {
        approval_request_id: 'approval-1', approval_action_hash: HASH_A,
        resolver_principal_id: 'attacker', decision: 'granted',
      },
    })).toThrow('untrusted approval evidence');
  });

  it.each(['request', 'action', 'decision', 'expiry', 'source'] as const)(
    'rejects a trusted approval result with wrong %s binding', (field) => {
      const times = [1000, 1100];
      const subject = coordinator(() => times.shift() as number, signer(), {
        approval_verifier: (_evidence, expected) => ({
          request_id: field === 'request' ? 'wrong' : expected.request_id,
          action_hash: field === 'action' ? HASH_B : expected.action_hash,
          principal_id: 'reviewer-1',
          decision: field === 'decision' ? 'denied' : expected.decision,
          source_hash: field === 'source' ? 'bad' : HASH_D,
          expires_at_ms: field === 'expiry' ? 1600 : 1500,
        }),
      });
      const pending = decide(subject, 'step', {
        action_taken: 'blocked', approval_required: true,
        approval_request_id: 'approval-1', approval_action_hash: HASH_A,
        approval_expires_at_ms: 1500,
      });
      expect(() => subject.resolve({
        suspended_receipt_hash: pending.receipt.receipt_hash,
        method: 'approval_granted', context: context(),
        base_result: { action_taken: 'allowed' }, policy_version: 'policy-1',
        rule_ids: [], approval_evidence: { token: 'anything' },
      })).toThrow();
    },
  );

  it('refuses authorization at exact expiry and a regressed clock cannot reopen it', () => {
    const times = [1000, 1500, 1400];
    const subject = coordinator(() => times.shift() as number);
    const pending = decide(subject, 'step', {
      action_taken: 'blocked', approval_required: true,
      approval_request_id: 'approval-1', approval_action_hash: HASH_A,
      approval_expires_at_ms: 1500,
    });
    decide(subject, 'head-at-expiry', { action_taken: 'allowed' }, HASH_B);
    expect(() => subject.resolve({
      suspended_receipt_hash: pending.receipt.receipt_hash,
      method: 'approval_granted', context: context(),
      base_result: { action_taken: 'allowed' }, policy_version: 'policy-1',
      rule_ids: [], approval_evidence: { token: 'trusted', expires_at_ms: 1500 },
    })).toThrow('expired');
  });

  it('does not advance state when the approval verifier throws', () => {
    const times = [1000, 1100, 1200];
    let fail = true;
    const subject = coordinator(() => times.shift() as number, signer(), {
      approval_verifier: (_evidence, expected) => {
        if (fail) { fail = false; throw new Error('verification unavailable'); }
        return {
          request_id: expected.request_id, action_hash: expected.action_hash,
          principal_id: 'reviewer-1', decision: expected.decision,
          source_hash: HASH_D, expires_at_ms: 1500,
        };
      },
    });
    const pending = decide(subject, 'step', {
      action_taken: 'blocked', approval_required: true,
      approval_request_id: 'approval-1', approval_action_hash: HASH_A,
      approval_expires_at_ms: 1500,
    });
    const request = {
      suspended_receipt_hash: pending.receipt.receipt_hash,
      method: 'approval_granted' as const, context: context(),
      base_result: { action_taken: 'allowed' as const }, policy_version: 'policy-1',
      rule_ids: [], approval_evidence: { token: 'trusted' },
    };
    expect(() => subject.resolve(request)).toThrow('verification unavailable');
    expect(subject.resolve(request).body.sequence).toBe(2);
  });

  it('only resolves DEFER through named fields and updates one prior summary', () => {
    const times = [1000, 1100, 1200];
    const onePriorPolicy: IntentPolicyInput = {
      ...POLICY,
      intent_scopes: [{ ...POLICY.intent_scopes[0], max_prior_actions: 1 }],
    };
    const subject = coordinator(
      () => times.shift() as number, signer(), { policy: onePriorPolicy },
    );
    const pending = decide(subject, 'defer', { action_taken: 'hook_error' });
    const resolved = subject.resolve({
      suspended_receipt_hash: pending.receipt.receipt_hash,
      method: 'context_supplied', context: context(),
      base_result: { action_taken: 'allowed' }, policy_version: 'policy-1',
      rule_ids: [], resolver_principal_id: 'worker-1', resolution_source_hash: HASH_D,
    });
    expect(resolved.body.evaluation.outcome).toBe('ALLOW');
    expect(decide(subject, 'after', { action_taken: 'allowed' }, HASH_B).evaluation.outcome)
      .toBe('ALLOW');
  });

  it('times out once at expiry and never authorizes the original action', () => {
    const times = [1000, 1499, 1500];
    const subject = coordinator(() => times.shift() as number);
    const pending = decide(subject, 'defer', { action_taken: 'hook_timeout' });
    expect(() => subject.timeout({
      suspended_receipt_hash: pending.receipt.receipt_hash,
      policy_version: 'policy-1', rule_ids: [],
    })).toThrow('has not expired');
    const timeout = subject.timeout({
      suspended_receipt_hash: pending.receipt.receipt_hash,
      policy_version: 'policy-1', rule_ids: [],
    });
    expect(timeout.body).toMatchObject({
      execution_authorized: false, evaluation: { outcome: 'DENY' },
      resolution: { method: 'expired', resolved_at_ms: 1500 },
    });
    expect(() => subject.timeout({
      suspended_receipt_hash: pending.receipt.receipt_hash,
      policy_version: 'policy-1', rule_ids: [],
    })).toThrow('already resolved');
  });

  it.each(['throw', 'malformed', 'wrong-key', 'mismatched-public'] as const)(
    'does not advance state after %s signer failure', (mode) => {
      const real = signer();
      const other = signer('11');
      let first = true;
      const adversarial: DeviceSigner = {
        keyId: real.keyId, rawPublicKey: real.rawPublicKey,
        get publicKeyB64() {
          if (mode === 'mismatched-public' && first) {
            first = false;
            return other.publicKeyB64;
          }
          return real.publicKeyB64;
        },
        signPayload: real.signPayload,
        signBytes(message) {
          if (!first) return real.signBytes(message);
          if (mode === 'mismatched-public') return real.signBytes(message);
          first = false;
          if (mode === 'throw') throw new Error('sign failed');
          if (mode === 'malformed') return 'bad';
          if (mode === 'wrong-key') return other.signBytes(message);
          return real.signBytes(message);
        },
      };
      const subject = coordinator(() => 1000, adversarial);
      expect(() => decide(subject, 'first', { action_taken: 'allowed' })).toThrow();
      const success = decide(subject, 'second', { action_taken: 'allowed' });
      expect(success.receipt.body).toMatchObject({
        sequence: 1, previous_receipt_hash: null, receipt_id: 'session-1:1',
      });
    },
  );

  it('starts a new genesis session after a PID change', () => {
    let pid = 10;
    const subject = coordinator(() => 1000, signer(), {
      pid: () => pid, session_factory: () => 'session-child',
    });
    decide(subject, 'parent', { action_taken: 'allowed' });
    pid = 11;
    const child = decide(subject, 'child', { action_taken: 'allowed' });
    expect(child.receipt.body).toMatchObject({
      session_id: 'session-child', sequence: 1, previous_receipt_hash: null,
    });
  });

  it('prepares idempotently without advancing committed state', () => {
    const subject = coordinator(() => 1000, signer(), {
      prepared_token_factory: () => 'opaque-token',
    });
    const input = {
      context: context(), base_result: { action_taken: 'allowed' as const },
      policy_version: 'policy-1', rule_ids: ['rule-a'], action_id: 'prepared',
    };
    const first = subject.prepareDecision(input);
    expect(subject.inspectState()).toMatchObject({
      sequence: 0, head_receipt_hash: null,
      prepared: { token: 'opaque-token', receipt_hash: first.receipt_hash },
    });
    expect(subject.prepareDecision(input)).toEqual(first);
    expect(() => subject.prepareDecision({ ...input, action_id: 'other' }))
      .toThrow('different receipt is already prepared');
    expect(() => subject.commitPrepared('wrong', first.receipt_hash))
      .toThrow('prepared token mismatch');
    expect(() => subject.commitPrepared(first.token, HASH_A))
      .toThrow('prepared receipt hash mismatch');
    const committed = subject.commitPrepared(first.token, first.receipt_hash);
    expect(committed).toEqual(first.value);
    expect(subject.inspectState()).toMatchObject({
      sequence: 1, head_receipt_hash: first.receipt_hash, frozen: false,
    });
  });

  it('requires the no-store capability and freezes ambiguous preparation', () => {
    const state = new PreparedReceiptState(() => 'opaque-token');
    let commits = 0;
    const prepared = state.prepare({
      fingerprint: HASH_A, receipt_hash: HASH_B, kind: 'decision', value: 'value',
      commit: () => { commits += 1; },
    });
    expect(() => state.abort(
      prepared.token, prepared.receipt_hash,
      { status: 'definitive_no_store' } as typeof DEFINITIVE_NO_STORE,
    )).toThrow('definitive_no_store capability');
    state.freeze(prepared.token, prepared.receipt_hash, 'delivery_unknown');
    expect(() => state.retry(HASH_A, 'decision')).toThrow('session is frozen');
    expect(state.reconcile({
      status: 'stored', token: prepared.token, receipt_hash: prepared.receipt_hash,
    })).toBe('value');
    expect(commits).toBe(1);

    const aborted = state.prepare({
      fingerprint: HASH_C, receipt_hash: HASH_D, kind: 'decision', value: 'unused',
      commit: () => { commits += 1; },
    });
    state.abort(aborted.token, aborted.receipt_hash, DEFINITIVE_NO_STORE);
    expect(state.inspect()).toEqual({ frozen: false });
    expect(commits).toBe(1);
  });

  it('freezes when an accepted receipt cannot be committed locally', () => {
    const state = new PreparedReceiptState(() => 'opaque-token');
    const prepared = state.prepare({
      fingerprint: HASH_A, receipt_hash: HASH_B, kind: 'decision', value: 'value',
      commit: () => { throw new Error('local commit failed'); },
    });
    expect(() => state.commit(prepared.token, prepared.receipt_hash))
      .toThrow('local commit failed');
    expect(state.inspect()).toMatchObject({
      frozen: true, freeze_reason: 'accepted_but_local_commit_failed',
    });
    expect(() => state.prepare({
      fingerprint: HASH_C, receipt_hash: HASH_D, kind: 'decision', value: 'other',
      commit: () => undefined,
    })).toThrow('session is frozen');
  });

  it('prepares resolution and timeout without advancing their chains', () => {
    const approvalTimes = [1000, 1100];
    const approval = coordinator(() => approvalTimes.shift() as number);
    const pending = decide(approval, 'step', {
      action_taken: 'blocked', approval_required: true,
      approval_request_id: 'approval-1', approval_action_hash: HASH_A,
      approval_expires_at_ms: 1500,
    });
    const preparedResolution = approval.prepareResolution({
      suspended_receipt_hash: pending.receipt.receipt_hash,
      method: 'approval_granted', context: context(),
      base_result: { action_taken: 'allowed' }, policy_version: 'policy-1',
      rule_ids: [], approval_evidence: { token: 'trusted', expires_at_ms: 1500 },
    });
    expect(approval.inspectState().sequence).toBe(1);
    expect((approval.commitPrepared(
      preparedResolution.token, preparedResolution.receipt_hash,
    ) as { body: { sequence: number } }).body.sequence).toBe(2);

    const timeoutTimes = [1000, 1500];
    const timeout = coordinator(() => timeoutTimes.shift() as number);
    const deferred = decide(timeout, 'defer', { action_taken: 'hook_timeout' });
    const preparedTimeout = timeout.prepareTimeout({
      suspended_receipt_hash: deferred.receipt.receipt_hash,
      policy_version: 'policy-1', rule_ids: [],
    });
    expect(timeout.inspectState().sequence).toBe(1);
    expect((timeout.commitPrepared(
      preparedTimeout.token, preparedTimeout.receipt_hash,
    ) as { body: { sequence: number } }).body.sequence).toBe(2);
  });

  it('drops inherited prepared and frozen state after a PID change', () => {
    let pid = 10;
    const subject = coordinator(() => 1000, signer(), {
      pid: () => pid, session_factory: () => 'session-child',
    });
    const parent = subject.prepareDecision({
      context: context(), base_result: { action_taken: 'allowed' },
      policy_version: 'policy-1', rule_ids: [], action_id: 'parent',
    });
    subject.freezePrepared(parent.token, parent.receipt_hash, 'delivery_unknown');
    pid = 11;
    const child = subject.prepareDecision({
      context: context(), base_result: { action_taken: 'allowed' },
      policy_version: 'policy-1', rule_ids: [], action_id: 'child',
    });
    expect(child.value.receipt.body).toMatchObject({
      session_id: 'session-child', sequence: 1, previous_receipt_hash: null,
    });
    expect(subject.inspectState().frozen).toBe(false);
  });
});
