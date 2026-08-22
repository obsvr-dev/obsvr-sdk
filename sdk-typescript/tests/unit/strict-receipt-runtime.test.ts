import { jest } from '@jest/globals';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { IntentBaseResult, IntentPolicyInput } from '../../src/policy/intent-alignment';
import type { StrictAdmissionResult } from '../../src/governance/strict-admission';
import type { StrictReceiptEnvelope } from '../../src/governance/strict-receipt';
import { StrictReceiptCoordinator } from '../../src/governance/strict-receipt-coordinator';
import {
  STRICT_BOUND_ARGUMENTS,
  StrictReceiptRuntime,
} from '../../src/governance/strict-receipt-runtime';
import { loadDeviceSigner } from '../../src/proxy/device-identity';

const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);
const HASH_D = 'd'.repeat(64);
const POLICY: IntentPolicyInput = {
  schema: 'obsvr-intent-policy-v1', profile_version: '1.0',
  intent_scopes: [{
    intent_id: 'deploy', allowed_actions: [{ kind: 'tool', name: 'send' }],
    allowed_targets: ['prod'], allowed_requested_scopes: ['write'],
    allowed_data_classifications: ['confidential'],
  }],
};

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

function coordinator(clock: () => number) {
  const path = join(mkdtempSync(join(tmpdir(), 'obsvr-runtime-')), 'seed.key');
  writeFileSync(path, '00'.repeat(32));
  return new StrictReceiptCoordinator({
    signer: loadDeviceSigner(path), policy: POLICY, sdk_language: 'typescript',
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
  });
}

function decision(actionId: string, baseResult: IntentBaseResult) {
  return {
    context: context(), base_result: baseResult,
    policy_version: 'policy-1', rule_ids: ['rule-a'], action_id: actionId,
  };
}

function accepted(receiptHash: string) {
  return {
    disposition: 'accepted' as const, receipt_hash: receiptHash,
    status: 'accepted' as const, attempts: 1,
  };
}

function action(
  actionId: string,
  invoke: (value: { value: string }) => unknown,
  original = { value: 'original' },
) {
  return {
    runtime_action_id: actionId,
    original_arguments: {
      capability: STRICT_BOUND_ARGUMENTS, arguments_hash: HASH_A, value: original,
    },
    invoke,
  };
}

describe('strict receipt runtime', () => {
  it('admits and commits the exact signed receipt before invoking', async () => {
    const events: string[] = [];
    const state = coordinator(() => 1000);
    const runtime = new StrictReceiptRuntime(
      state,
      async (receipt, config: { marker: string }) => {
        events.push(`admit:${config.marker}:${state.inspectState().sequence}`);
        return accepted(receipt.receipt_hash);
      },
      { marker: 'configured' },
    );
    const invoke = jest.fn((value: { value: string }) => {
      events.push(`invoke:${state.inspectState().sequence}`);
      return value.value;
    });
    const result = await runtime.runDecision({
      decision: decision('allow', { action_taken: 'allowed' }),
      action: action('allow', invoke),
    });
    expect(result).toMatchObject({ status: 'executed', value: 'original' });
    expect(events).toEqual(['admit:configured:0', 'invoke:1']);
    expect(invoke).toHaveBeenCalledTimes(1);
  });

  it.each<[string, IntentBaseResult]>([
    ['deny', { action_taken: 'blocked' }],
    ['defer', { action_taken: 'hook_error' }],
    ['step', {
      action_taken: 'blocked', approval_required: true,
      approval_request_id: 'approval-1', approval_action_hash: HASH_A,
      approval_expires_at_ms: 1500,
    }],
  ])('admits %s receipts without invoking', async (actionId, baseResult) => {
    const state = coordinator(() => 1000);
    const admissions = jest.fn(async (receipt: StrictReceiptEnvelope) => (
      accepted(receipt.receipt_hash)
    ));
    const runtime = new StrictReceiptRuntime(state, admissions, undefined);
    const invoke = jest.fn();
    const result = await runtime.runDecision({
      decision: decision(actionId, baseResult), action: action(actionId, invoke),
    });
    expect(result).toMatchObject({ status: 'nonexecuted', reason: 'not_authorized' });
    expect(admissions).toHaveBeenCalledTimes(1);
    expect(invoke).not.toHaveBeenCalled();
    expect(state.inspectState().sequence).toBe(1);
  });

  it.each(['definitive_no_store', 'uncertain', 'throw', 'wrong_hash'] as const)(
    'fails closed for %s admission', async (mode) => {
      const state = coordinator(() => 1000);
      const invoke = jest.fn();
      const admission = jest.fn(async (
        receipt: StrictReceiptEnvelope,
      ): Promise<StrictAdmissionResult> => {
        if (mode === 'throw') throw new Error('lost acknowledgement');
        if (mode === 'wrong_hash') return accepted(HASH_B);
        if (mode === 'definitive_no_store') return {
          disposition: 'definitive_no_store', receipt_hash: receipt.receipt_hash,
          http_status: 401, attempts: 1,
        };
        return {
          disposition: 'uncertain', receipt_hash: receipt.receipt_hash,
          reason: 'retry_exhausted', attempts: 3,
        };
      });
      const runtime = new StrictReceiptRuntime(state, admission, undefined);
      const result = await runtime.runDecision({
        decision: decision('blocked', { action_taken: 'allowed' }),
        action: action('blocked', invoke),
      });
      expect(result.status).toBe('nonexecuted');
      expect(invoke).not.toHaveBeenCalled();
      expect(state.inspectState().sequence).toBe(0);
      expect(state.inspectState().frozen).toBe(mode !== 'definitive_no_store');
    },
  );

  it('reports accepted admission and freezes when local commit fails', async () => {
    const state = coordinator(() => 1000);
    const runtime = new StrictReceiptRuntime(
      state,
      async (receipt) => {
        (state as unknown as { commitDecision: () => void }).commitDecision = () => {
          throw new Error('commit storage failed');
        };
        return accepted(receipt.receipt_hash);
      },
      undefined,
    );
    const invoke = jest.fn();
    const result = await runtime.runDecision({
      decision: decision('commit-fail', { action_taken: 'allowed' }),
      action: action('commit-fail', invoke),
    });
    expect(result).toMatchObject({ status: 'admitted', reason: 'local_commit_failed' });
    expect(state.inspectState()).toMatchObject({
      sequence: 0, frozen: true, freeze_reason: 'accepted_but_local_commit_failed',
    });
    expect(invoke).not.toHaveBeenCalled();
  });

  it('uses trusted effective arguments for MODIFY and never falls back', async () => {
    const missingState = coordinator(() => 1000);
    const missingAdmission = jest.fn(async (receipt: StrictReceiptEnvelope) => (
      accepted(receipt.receipt_hash)
    ));
    const missing = new StrictReceiptRuntime(
      missingState, missingAdmission, undefined,
    );
    const missingInvoke = jest.fn();
    const missingResult = await missing.runDecision({
      decision: decision('modify-missing', {
        action_taken: 'redacted', modified_arguments_hash: HASH_D,
      }),
      action: {
        ...action('modify-missing', missingInvoke),
        effective_arguments: {
          capability: STRICT_BOUND_ARGUMENTS,
          arguments_hash: HASH_B,
          value: { value: 'wrong-binding' },
        },
      },
    });
    expect(missingResult).toMatchObject({
      status: 'nonexecuted', reason: 'effective_arguments_unavailable',
    });
    expect(missingAdmission).not.toHaveBeenCalled();
    expect(missingState.inspectState().sequence).toBe(0);
    expect(missingInvoke).not.toHaveBeenCalled();

    const trustedState = coordinator(() => 1000);
    const trusted = new StrictReceiptRuntime(
      trustedState, async (receipt) => accepted(receipt.receipt_hash), undefined,
    );
    const trustedInvoke = jest.fn((value: { value: string }) => value.value);
    const trustedResult = await trusted.runDecision({
      decision: decision('modify-trusted', {
        action_taken: 'redacted', modified_arguments_hash: HASH_D,
      }),
      action: {
        ...action('modify-trusted', trustedInvoke),
        effective_arguments: {
          capability: STRICT_BOUND_ARGUMENTS,
          arguments_hash: HASH_D,
          value: { value: 'redacted' },
        },
      },
    });
    expect(trustedResult).toMatchObject({ status: 'executed', value: 'redacted' });
    expect(trustedInvoke).toHaveBeenCalledWith({ value: 'redacted' });
  });

  it.each(['missing', 'untrusted', 'mismatch'] as const)(
    'does not invoke ALLOW with %s original argument binding', async (mode) => {
      const state = coordinator(() => 1000);
      const admission = jest.fn(async (receipt: StrictReceiptEnvelope) => (
        accepted(receipt.receipt_hash)
      ));
      const runtime = new StrictReceiptRuntime(
        state, admission, undefined,
      );
      const invoke = jest.fn();
      const actionValue = action('original-binding', invoke) as unknown as {
        runtime_action_id: string;
        original_arguments?: { capability: unknown; arguments_hash: string; value: unknown };
        invoke: typeof invoke;
      };
      if (mode === 'missing') delete actionValue.original_arguments;
      if (mode === 'untrusted' && actionValue.original_arguments) {
        actionValue.original_arguments.capability = { status: 'trusted_bound_arguments' };
      }
      if (mode === 'mismatch' && actionValue.original_arguments) {
        actionValue.original_arguments.arguments_hash = HASH_B;
      }
      const result = await runtime.runDecision({
        decision: decision('original-binding', { action_taken: 'allowed' }),
        action: actionValue as never,
      });
      expect(result).toMatchObject({
        status: 'nonexecuted', reason: 'original_arguments_unavailable',
      });
      expect(admission).not.toHaveBeenCalled();
      expect(state.inspectState().sequence).toBe(0);
      expect(invoke).not.toHaveBeenCalled();
    },
  );

  it('does not invoke an authorized resolution with mismatched original binding', async () => {
    const times = [1000, 1100];
    const state = coordinator(() => times.shift() as number);
    const admission = jest.fn(async (receipt: StrictReceiptEnvelope) => (
      accepted(receipt.receipt_hash)
    ));
    const runtime = new StrictReceiptRuntime(
      state, admission, undefined,
    );
    const pending = await runtime.runDecision({
      decision: decision('resolution-binding', {
        action_taken: 'blocked', approval_required: true,
        approval_request_id: 'approval-1', approval_action_hash: HASH_A,
        approval_expires_at_ms: 1500,
      }),
      action: action('resolution-binding', jest.fn()),
    });
    const invoke = jest.fn();
    const wrong = action('resolution-binding', invoke);
    wrong.original_arguments.arguments_hash = HASH_B;
    const result = await runtime.runResolution({
      resolution: {
        suspended_receipt_hash: pending.receipt_hash,
        method: 'approval_granted', context: context(),
        base_result: { action_taken: 'allowed' }, policy_version: 'policy-1',
        rule_ids: [], approval_evidence: { token: 'trusted', expires_at_ms: 1500 },
      },
      action: wrong,
    });
    expect(result).toMatchObject({
      status: 'nonexecuted', reason: 'original_arguments_unavailable',
    });
    expect(admission).toHaveBeenCalledTimes(1);
    expect(state.inspectState().sequence).toBe(1);
    expect(invoke).not.toHaveBeenCalled();
  });

  it('uses the preflight argument snapshot when admission replaces the wrapper', async () => {
    const state = coordinator(() => 1000);
    const original = { value: 'original' };
    const invoke = jest.fn((value: { value: string }) => value.value);
    const actionValue = action('snapshot', invoke, original);
    const runtime = new StrictReceiptRuntime(
      state,
      async (receipt) => {
        actionValue.original_arguments.value = { value: 'swapped-field' };
        actionValue.original_arguments = {
          capability: STRICT_BOUND_ARGUMENTS,
          arguments_hash: HASH_B,
          value: { value: 'replacement' },
        };
        return accepted(receipt.receipt_hash);
      },
      undefined,
    );
    const result = await runtime.runDecision({
      decision: decision('snapshot', { action_taken: 'allowed' }),
      action: actionValue,
    });
    expect(result).toMatchObject({ status: 'executed', value: 'original' });
    expect(invoke).toHaveBeenCalledWith(original);
  });

});
