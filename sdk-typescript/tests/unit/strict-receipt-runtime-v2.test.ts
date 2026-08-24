import {
  bindStrictV2JsonArguments, createTrustedStrictV2Admission,
  StrictReceiptRuntimeV2, StrictReceiptRuntimeV2Error,
} from '../../src/governance/strict-receipt-runtime-v2.js';
import type { StrictReceiptV2Envelope } from '../../src/governance/strict-receipt-v2.js';

const HASH = 'c'.repeat(64);
const TENANT = 'tenant-1';
const SESSION = 'session-1';

function receipt(actionId: string, argsHash: string, outcome = 'ALLOW', effective?: string): StrictReceiptV2Envelope {
  return {
    schema: 'obsvr-strict-receipt-envelope-v2', receipt_hash: HASH,
    body: {
      schema: 'obsvr-strict-receipt-v2', tenant_id: TENANT, session_id: SESSION,
      action: { action_id: actionId, arguments_hash: argsHash,
        ...(effective ? { effective_arguments_hash: effective } : {}) },
      evaluation: { outcome }, execution_authorized: ['ALLOW', 'MODIFY'].includes(outcome),
    },
  } as unknown as StrictReceiptV2Envelope;
}

class FakeCoordinator {
  committed = 0; aborted = 0; frozen = 0; failCommit = false;
  current?: StrictReceiptV2Envelope;
  inspectState(): { tenant_id: string; session_id: string } { return { tenant_id: TENANT, session_id: SESSION }; }
  prepareDecision(input: any): any {
    const outcome = input.base_result.action_taken === 'blocked' ? 'DENY'
      : input.base_result.action_taken === 'redacted' ? 'MODIFY' : 'ALLOW';
    this.current = receipt(input.action_id, input.context.current_action.arguments_hash,
      outcome, input.base_result.modified_arguments_hash);
    return { token: 'tok', receipt_hash: HASH, kind: 'decision',
      value: { evaluation: this.current.body.evaluation, receipt: this.current } };
  }
  prepareResolution(input: any): any {
    this.current = receipt(input.context.current_action.action_id ?? 'action-1',
      input.context.current_action.arguments_hash, 'ALLOW');
    return { token: 'tok', receipt_hash: HASH, kind: 'resolution', value: this.current };
  }
  prepareTimeout(): any {
    this.current = receipt('timeout-action', 'a'.repeat(64), 'DENY');
    return { token: 'tok', receipt_hash: HASH, kind: 'timeout', value: this.current };
  }
  commitPrepared(): any {
    if (this.failCommit) throw new Error('commit failed');
    this.committed += 1;
    return this.current;
  }
  abortPrepared(): void { this.aborted += 1; }
  freezePrepared(): void { this.frozen += 1; }
}

function decision(id: string, hash: string, actionTaken = 'allowed'): any {
  return { action_id: id, context: { current_action: { arguments_hash: hash } },
    base_result: { action_taken: actionTaken }, policy_version: 'v1', rule_ids: [] };
}
function config(): any { return { ingest_url: 'https://example.com', api_key: 'test' }; }
function response(hash = HASH, overrides: Record<string, unknown> = {}): any {
  return { schema: 'obsvr-strict-receipt-admission-v2', tenant_id: TENANT,
    session_id: SESSION, receipt_hash: hash, attempts: 1,
    disposition: 'accepted', status: 'accepted', ...overrides };
}
function runtime(fake: FakeCoordinator, admit: (receipt: StrictReceiptV2Envelope) => Promise<any>): StrictReceiptRuntimeV2 {
  return new StrictReceiptRuntimeV2(fake as never, config(), createTrustedStrictV2Admission(admit));
}

describe('StrictReceiptRuntimeV2', () => {
  test('production default uses the concrete pinned v2 admission transport', async () => {
    const fake = new FakeCoordinator(); const bound = bindStrictV2JsonArguments({ ok: true }); let transports = 0;
    const subject = new StrictReceiptRuntimeV2(fake as never, {
      ingest_url: 'https://example.com', api_key: 'key', max_attempts: 1,
      resolver: async () => ['8.8.8.8'],
      trusted_pinned_transport: async (_target, body) => {
        transports += 1; expect(JSON.parse(body).schema).toBe('obsvr-strict-receipt-ingest-v2');
        return { status: 200, body: Buffer.from(JSON.stringify({
          schema: 'obsvr-strict-receipt-admission-v2', ok: true,
          status: 'accepted', receipt_hash: HASH, accepted_at_ms: 1,
        })) };
      },
    });
    const result = await subject.runDecision({ decision: decision('action-1', bound.arguments_hash),
      action: { runtime_action_id: 'action-1', original_arguments: bound, invoke: () => 'ok' } });
    expect(result.status).toBe('executed'); expect(transports).toBe(1);
  });

  test('admits, commits, then invokes and caches an exact retry', async () => {
    const fake = new FakeCoordinator(); const order: string[] = [];
    const bound = bindStrictV2JsonArguments({ prompt: 'hello' });
    const subject = runtime(fake, async (item) => {
      order.push(`admit:${fake.committed}`);
      expect(item.body.tenant_id).toBe(TENANT);
      return response(item.receipt_hash);
    });
    const action = { runtime_action_id: 'action-1', original_arguments: bound,
      invoke: (value: any) => { order.push(`invoke:${fake.committed}`); return value.prompt; } };
    const input = { decision: decision('action-1', bound.arguments_hash), action };
    const first = await subject.runDecision(input);
    (first.receipt.body as any).tenant_id = 'mutated';
    const second = await subject.runDecision(input);
    expect(first.status).toBe('executed'); expect(second.status).toBe('executed');
    expect(second.receipt.body.tenant_id).toBe(TENANT);
    expect(order).toEqual(['admit:0', 'invoke:1']); expect(fake.committed).toBe(1);
  });

  test('snapshots canonical JSON arguments before asynchronous admission', async () => {
    const fake = new FakeCoordinator(); const source = { value: 1 };
    const bound = bindStrictV2JsonArguments(source); let seen: unknown;
    const subject = runtime(fake, async () => { source.value = 99; return response(); });
    const result = await subject.runDecision({ decision: decision('action-1', bound.arguments_hash),
      action: { runtime_action_id: 'action-1', original_arguments: bound,
        invoke: (value) => { seen = value; return 'ok'; } } });
    expect(result.status).toBe('executed'); expect(seen).toEqual({ value: 1 });
    expect(Object.isFrozen(bound.value)).toBe(true);
  });

  test('fails local argument binding before admission and does not freeze', async () => {
    const fake = new FakeCoordinator(); let admissions = 0; let invokes = 0;
    const signed = bindStrictV2JsonArguments({ a: 1 });
    const other = bindStrictV2JsonArguments({ a: 2 });
    const subject = runtime(fake, async () => { admissions += 1; return response(); });
    const result = await subject.runDecision({ decision: decision('action-1', signed.arguments_hash),
      action: { runtime_action_id: 'action-1', original_arguments: other,
        invoke: () => { invokes += 1; } } });
    expect(result).toMatchObject({ status: 'nonexecuted', reason: 'original_arguments_unavailable' });
    expect({ admissions, invokes, aborted: fake.aborted, frozen: fake.frozen }).toEqual({ admissions: 0, invokes: 0, aborted: 1, frozen: 0 });
  });

  test('uses only the signed effective arguments for MODIFY', async () => {
    const fake = new FakeCoordinator(); const original = bindStrictV2JsonArguments({ value: 1 });
    const effective = bindStrictV2JsonArguments({ value: 2 }); let seen = 0;
    const subject = runtime(fake, async () => response());
    const result = await subject.runDecision({
      decision: { ...decision('action-1', original.arguments_hash, 'redacted'),
        base_result: { action_taken: 'redacted', modified_arguments_hash: effective.arguments_hash } },
      action: { runtime_action_id: 'action-1', original_arguments: original,
        effective_arguments: effective, invoke: (value) => { seen = value.value; } },
    });
    expect(result.status).toBe('executed'); expect(seen).toBe(2);
  });

  test('admitted DENY and timeout never invoke', async () => {
    const fake = new FakeCoordinator(); const bound = bindStrictV2JsonArguments({ ok: true }); let invokes = 0;
    const subject = runtime(fake, async () => response());
    const denied = await subject.runDecision({ decision: decision('action-1', bound.arguments_hash, 'blocked'),
      action: { runtime_action_id: 'action-1', original_arguments: bound, invoke: () => { invokes += 1; } } });
    const timeout = await subject.runTimeout({} as any);
    expect(denied).toMatchObject({ status: 'nonexecuted', reason: 'not_authorized' });
    expect(timeout).toMatchObject({ status: 'nonexecuted', reason: 'not_authorized' });
    expect(invokes).toBe(0);
  });

  test('resolution binds the same action and invokes only after admission', async () => {
    const fake = new FakeCoordinator(); const bound = bindStrictV2JsonArguments({ ok: true }); let invokes = 0;
    const result = await runtime(fake, async () => response()).runResolution({
      resolution: { context: { current_action: { action_id: 'action-1',
        arguments_hash: bound.arguments_hash } } } as any,
      action: { runtime_action_id: 'action-1', original_arguments: bound,
        invoke: () => { invokes += 1; return 'done'; } },
    });
    expect(result.status).toBe('executed'); expect(invokes).toBe(1); expect(fake.committed).toBe(1);
  });

  test('definitive no-store aborts while uncertainty and identity drift freeze', async () => {
    const cases = [
      [response(HASH, { disposition: 'definitive_no_store', http_status: 400, status: undefined }), 1, 0, 'definitive_no_store'],
      [response(HASH, { disposition: 'uncertain', reason: 'retry_exhausted', status: undefined }), 0, 1, 'admission_uncertain'],
      [response('d'.repeat(64)), 0, 1, 'receipt_hash_mismatch'],
      [response(HASH, { tenant_id: 'other' }), 0, 1, 'tenant_mismatch'],
      [response(HASH, { schema: 'wrong' }), 0, 1, 'admission_schema_mismatch'],
    ] as const;
    for (const [reply, aborted, frozen, reason] of cases) {
      const fake = new FakeCoordinator(); const bound = bindStrictV2JsonArguments({ ok: true });
      const result = await runtime(fake, async () => reply as any).runDecision({
        decision: decision('action-1', bound.arguments_hash),
        action: { runtime_action_id: 'action-1', original_arguments: bound, invoke: () => fail('invoked') },
      });
      expect(result).toMatchObject({ status: 'nonexecuted', reason });
      expect([fake.aborted, fake.frozen]).toEqual([aborted, frozen]);
    }
  });

  test('accepted local commit failure never invokes', async () => {
    const fake = new FakeCoordinator(); fake.failCommit = true; let invokes = 0;
    const bound = bindStrictV2JsonArguments({ ok: true });
    const result = await runtime(fake, async () => response()).runDecision({
      decision: decision('action-1', bound.arguments_hash),
      action: { runtime_action_id: 'action-1', original_arguments: bound, invoke: () => { invokes += 1; } },
    });
    expect(result.status).toBe('admitted'); expect(invokes).toBe(0);
  });

  test('provider failure starts once and action id drift fails closed', async () => {
    const fake = new FakeCoordinator(); const bound = bindStrictV2JsonArguments({ ok: true }); let invokes = 0;
    const subject = runtime(fake, async () => response());
    const action = { runtime_action_id: 'action-1', original_arguments: bound,
      invoke: () => { invokes += 1; throw new Error('provider failed'); } };
    const input = { decision: decision('action-1', bound.arguments_hash), action };
    expect((await subject.runDecision(input)).status).toBe('invocation_failed');
    expect((await subject.runDecision(input)).status).toBe('invocation_failed');
    expect(() => subject.runDecision({ ...input,
      decision: { ...input.decision, policy_version: 'v2' } })).toThrow(StrictReceiptRuntimeV2Error);
    expect(invokes).toBe(1);
  });

  test('concurrent operations fail closed while admission is pending', async () => {
    const fake = new FakeCoordinator(); const bound = bindStrictV2JsonArguments({ ok: true });
    let release!: () => void; const gate = new Promise<void>((resolve) => { release = resolve; });
    const subject = runtime(fake, async () => { await gate; return response(); });
    const action = { runtime_action_id: 'action-1', original_arguments: bound, invoke: () => 'ok' };
    const first = subject.runDecision({ decision: decision('action-1', bound.arguments_hash), action });
    await Promise.resolve();
    await expect(subject.runDecision({ decision: decision('action-2', bound.arguments_hash),
      action: { ...action, runtime_action_id: 'action-2' } })).rejects.toBeInstanceOf(StrictReceiptRuntimeV2Error);
    release(); expect((await first).status).toBe('executed');
  });
});
