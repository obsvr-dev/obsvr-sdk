import { jest } from '@jest/globals';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { IntentBaseResult, IntentPolicyInput } from '../../src/policy/intent-alignment';
import type { StrictReceiptEnvelope } from '../../src/governance/strict-receipt';
import { StrictReceiptCoordinator } from '../../src/governance/strict-receipt-coordinator';
import {
  STRICT_BOUND_ARGUMENTS,
  StrictReceiptRuntime,
} from '../../src/governance/strict-receipt-runtime';
import { loadDeviceSigner } from '../../src/proxy/device-identity';

const HASH_A = 'a'.repeat(64);
const HASH_D = 'd'.repeat(64);
const POLICY: IntentPolicyInput = {
  schema: 'obsvr-intent-policy-v1', profile_version: '1.0',
  intent_scopes: [{
    intent_id: 'deploy', allowed_actions: [{ kind: 'tool', name: 'send' }],
    allowed_targets: ['prod'], allowed_requested_scopes: ['write'],
    allowed_data_classifications: ['confidential'],
  }],
};

function context() {
  return {
    agent_id: 'agent-1', active_intents: ['deploy'], privilege_scope: ['write'],
    current_action: {
      kind: 'tool', name: 'send', arguments_hash: HASH_A, target: 'prod',
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

describe('strict receipt runtime idempotency and lifecycle', () => {
  it('never invokes an action id twice after the provider starts', async () => {
    const state = coordinator(() => 1000);
    const admission = jest.fn(async (receipt: StrictReceiptEnvelope) => (
      accepted(receipt.receipt_hash)
    ));
    const runtime = new StrictReceiptRuntime(state, admission, undefined);
    const invoke = jest.fn(() => { throw new Error('provider failed after start'); });
    const request = {
      decision: decision('once', { action_taken: 'allowed' }),
      action: action('once', invoke),
    };
    const first = await runtime.runDecision(request);
    const retry = await runtime.runDecision(request);
    expect(first.status).toBe('invocation_failed');
    expect(retry).toEqual(first);
    expect((retry as { error: unknown }).error).toBe((first as { error: unknown }).error);
    expect(invoke).toHaveBeenCalledTimes(1);
    expect(admission).toHaveBeenCalledTimes(1);
  });

  it('rejects a changed decision fingerprint before preparation', async () => {
    const state = coordinator(() => 1000);
    const admission = jest.fn(async (receipt: StrictReceiptEnvelope) => (
      accepted(receipt.receipt_hash)
    ));
    const invoke = jest.fn(() => 'done');
    const runtime = new StrictReceiptRuntime(state, admission, undefined);
    await runtime.runDecision({
      decision: decision('fingerprint', { action_taken: 'allowed' }),
      action: action('fingerprint', invoke),
    });
    await expect(runtime.runDecision({
      decision: decision('fingerprint', { action_taken: 'blocked' }),
      action: action('fingerprint', invoke),
    })).rejects.toThrow('reused with different input');
    expect(state.inspectState().sequence).toBe(1);
    expect(admission).toHaveBeenCalledTimes(1);
    expect(invoke).toHaveBeenCalledTimes(1);
  });

  it('rejects a changed resolution fingerprint before preparation', async () => {
    const times = [1000, 1100];
    const state = coordinator(() => times.shift() as number);
    const admission = jest.fn(async (receipt: StrictReceiptEnvelope) => (
      accepted(receipt.receipt_hash)
    ));
    const runtime = new StrictReceiptRuntime(state, admission, undefined);
    const pending = await runtime.runDecision({
      decision: decision('resolution-fingerprint', {
        action_taken: 'blocked', approval_required: true,
        approval_request_id: 'approval-1', approval_action_hash: HASH_A,
        approval_expires_at_ms: 1500,
      }),
      action: action('resolution-fingerprint', jest.fn()),
    });
    const invoke = jest.fn(() => 'resolved');
    const request = {
      suspended_receipt_hash: pending.receipt_hash,
      method: 'approval_granted' as const, context: context(),
      base_result: { action_taken: 'allowed' as const }, policy_version: 'policy-1',
      rule_ids: [], approval_evidence: { token: 'trusted', expires_at_ms: 1500 },
    };
    await runtime.runResolution({
      resolution: request, action: action('resolution-fingerprint', invoke),
    });
    await expect(runtime.runResolution({
      resolution: { ...request, rule_ids: ['different'] },
      action: action('resolution-fingerprint', invoke),
    })).rejects.toThrow('reused with different input');
    expect(state.inspectState().sequence).toBe(2);
    expect(admission).toHaveBeenCalledTimes(2);
    expect(invoke).toHaveBeenCalledTimes(1);
  });

  it('defends cached receipt and status from caller mutation', async () => {
    const state = coordinator(() => 1000);
    const providerValue = { provider: 'value' };
    const invoke = jest.fn(() => providerValue);
    const runtime = new StrictReceiptRuntime(
      state, async (receipt) => accepted(receipt.receipt_hash), undefined,
    );
    const request = {
      decision: decision('mutation', { action_taken: 'allowed' }),
      action: action('mutation', invoke),
    };
    const first = await runtime.runDecision(request);
    first.receipt.body.action.name = 'caller-mutation';
    (first as { status: string }).status = 'nonexecuted';
    const retry = await runtime.runDecision(request);
    expect(retry.status).toBe('executed');
    expect(retry.receipt.body.action.name).toBe('send');
    expect((retry as { value: unknown }).value).toBe(providerValue);
    expect(invoke).toHaveBeenCalledTimes(1);
  });

  it('fails closed under concurrency and after a lost acknowledgement', async () => {
    const state = coordinator(() => 1000);
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const admission = jest.fn(async (receipt: StrictReceiptEnvelope) => {
      await gate;
      return {
        disposition: 'uncertain' as const, receipt_hash: receipt.receipt_hash,
        reason: 'retry_exhausted' as const, attempts: 1,
      };
    });
    const runtime = new StrictReceiptRuntime(state, admission, undefined);
    const invoke = jest.fn();
    const request = {
      decision: decision('lost-ack', { action_taken: 'allowed' }),
      action: action('lost-ack', invoke),
    };
    const first = runtime.runDecision(request);
    await expect(runtime.runDecision(request)).rejects.toThrow('runtime is busy');
    release?.();
    await expect(first).resolves.toMatchObject({
      status: 'nonexecuted', reason: 'admission_uncertain',
    });
    await expect(runtime.runDecision(request)).rejects.toThrow('session is frozen');
    expect(admission).toHaveBeenCalledTimes(1);
    expect(invoke).not.toHaveBeenCalled();
  });

  it('orchestrates resolution and timeout through admission', async () => {
    const times = [1000, 1100];
    const approvalState = coordinator(() => times.shift() as number);
    const approval = new StrictReceiptRuntime(
      approvalState, async (receipt) => accepted(receipt.receipt_hash), undefined,
    );
    const noInvoke = jest.fn();
    const pending = await approval.runDecision({
      decision: decision('approval', {
        action_taken: 'blocked', approval_required: true,
        approval_request_id: 'approval-1', approval_action_hash: HASH_A,
        approval_expires_at_ms: 1500,
      }),
      action: action('approval', noInvoke),
    });
    const invoke = jest.fn(() => 'resolved');
    const resolved = await approval.runResolution({
      resolution: {
        suspended_receipt_hash: pending.receipt_hash,
        method: 'approval_granted', context: context(),
        base_result: { action_taken: 'allowed' }, policy_version: 'policy-1',
        rule_ids: [], approval_evidence: { token: 'trusted', expires_at_ms: 1500 },
      },
      action: action('approval', invoke),
    });
    expect(resolved).toMatchObject({ status: 'executed', value: 'resolved' });

    const timeoutTimes = [1000, 1500];
    const timeoutState = coordinator(() => timeoutTimes.shift() as number);
    const timeout = new StrictReceiptRuntime(
      timeoutState, async (receipt) => accepted(receipt.receipt_hash), undefined,
    );
    const deferred = await timeout.runDecision({
      decision: decision('timeout', { action_taken: 'hook_timeout' }),
      action: action('timeout', noInvoke),
    });
    const timedOut = await timeout.runTimeout({
      suspended_receipt_hash: deferred.receipt_hash,
      policy_version: 'policy-1', rule_ids: [],
    });
    expect(timedOut).toMatchObject({ status: 'nonexecuted', reason: 'not_authorized' });
    expect(timeoutState.inspectState().sequence).toBe(2);
    expect(noInvoke).not.toHaveBeenCalled();
  });
});
