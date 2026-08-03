import { evaluate, explain } from '../../src/governance/evaluate';
import { ReasonCode } from '../../src/governance/reason-codes';
import { init, _reset, getConfig, _getPolicySyncState } from '../../src/proxy/config';
import { _resetSender, flushQueue } from '../../src/proxy/sender/fire-and-forget';
import type { PolicyRule } from '../../src/policy/rules';
import type { AuditEvent } from '../../src/proxy/types';

/**
 * Global monitor mode: evaluate everything, block nothing, keep the
 * evidence. Twin: sdk-python/tests/test_monitor_mode.py. The governance
 * evaluate() surface carries the TS conversion point; the proxy wrapper and
 * integrations pipelines are wired separately.
 */

const RULE: PolicyRule = {
  id: 'r-key',
  name: 'no forbidden topics',
  enabled: true,
  action: 'block',
  type: 'keyword',
  conditions: { keywords: ['forbidden'] },
};

const BASE = {
  apiKey: 'test-key-monitor',
  ingestUrl: 'https://localhost:19999',
  policyRules: [RULE],
};

const originalFetch = global.fetch;
let sentEvents: AuditEvent[] = [];

/** Capture everything the sender posts, single or batch shape. */
function captureFetch(): void {
  global.fetch = (async (_url: unknown, opts?: { body?: string }) => {
    try {
      const body = JSON.parse(opts?.body ?? 'null') as AuditEvent | AuditEvent[];
      if (Array.isArray(body)) sentEvents.push(...body);
      else if (body) sentEvents.push(body);
    } catch {
      /* not an event body */
    }
    return { ok: true, status: 200, json: async () => ({}) } as Response;
  }) as unknown as typeof fetch;
}

beforeEach(() => {
  _reset();
  _resetSender();
  sentEvents = [];
  captureFetch();
});

afterEach(() => {
  _getPolicySyncState().remoteDisabled = false;
  global.fetch = originalFetch;
  _reset();
  _resetSender();
});

describe('monitor mode conversion', () => {
  it('converts a final block to PERMITTED and keeps the would-be verdict', async () => {
    // Control: the enforcing verdict for this exact call.
    init({ ...BASE });
    const control = await evaluate({ action_type: 'test', payload: { data: 'a forbidden request' } });
    expect(control.decision).toBe('BLOCKED');
    expect(control.reason_code).toBe(ReasonCode.KEYWORD_BLOCKED);
    expect(control.rule_id).toBe('r-key');

    _reset();
    _resetSender();
    init({ ...BASE, enforcementMode: 'monitor' });
    const result = await evaluate({ action_type: 'test', payload: { data: 'a forbidden request' } });

    // The call proceeds, with the enforcing run's classification intact.
    expect(result.decision).toBe('PERMITTED');
    expect(result.reason_code).toBe(control.reason_code);
    expect(result.rule_id).toBe(control.rule_id);
    expect(result.execution_token).toBeTruthy();
  });

  it('emits exactly one event whose shadow_outcome carries the enforcing verdict', async () => {
    init({ ...BASE, enforcementMode: 'monitor' });
    await evaluate({ action_type: 'test', payload: { data: 'a forbidden request' } });
    await flushQueue(getConfig());

    const events = sentEvents.filter((e) => e.source === 'governance-evaluate');
    expect(events).toHaveLength(1);
    expect(events[0].action_taken).toBe('allowed');
    const shadow = (events[0] as { shadow_outcome?: { would: string; rule_id: string; reason_code?: string } }).shadow_outcome;
    expect(shadow).toBeDefined();
    expect(shadow!.would).toBe('block');
    expect(shadow!.rule_id).toBe('r-key');
    expect(shadow!.reason_code).toBe(ReasonCode.KEYWORD_BLOCKED);
  });

  it('defaults to enforce: without the opt-in the block stands', async () => {
    init({ ...BASE });
    expect(getConfig().enforcementMode).toBe('enforce');
    const result = await evaluate({ action_type: 'test', payload: { data: 'a forbidden request' } });
    expect(result.decision).toBe('BLOCKED');
  });

  it('refuses a typo mode at init rather than silently monitoring', () => {
    expect(() => init({ api_key: 'k', enforcement_mode: 'monitr' as never })).toThrow(
      /enforcementMode/,
    );
  });
});

describe('monitor mode carve-outs', () => {
  it('the kill switch still blocks in monitor mode', async () => {
    init({ ...BASE, enforcementMode: 'monitor' });
    _getPolicySyncState().remoteDisabled = true;

    const result = await evaluate({ action_type: 'test', payload: { data: 'anything at all' } });

    expect(result.decision).toBe('BLOCKED');
    expect(result.rule_id).toBe('sdk:project_paused_or_key_revoked');
    expect(result.execution_token).toBeUndefined();
  });

  it('explain() keeps predicting enforce-mode behaviour', () => {
    init({ ...BASE, enforcementMode: 'monitor' });
    const prediction = explain('a forbidden request');
    expect(prediction.decision).toBe('block');
    expect(prediction.rule_id).toBe('r-key');
  });
});
