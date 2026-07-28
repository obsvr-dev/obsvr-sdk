import { jest } from '@jest/globals';
import { init, _reset, getConfig, updatePolicyRules } from '../../src/proxy/config';
import { wrap } from '../../src/proxy/wrapper';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { applyPreCallPolicy } from '../../src/integrations/core';
import type { PolicyRule } from '../../src/policy/rules';

/**
 * End-to-end anti-tamper policy floor wiring. Twin:
 * sdk-python/tests/test_policy_floor_wiring.py. Pins the guarantees: a floor
 * block cannot be un-blocked by the customer hook (and the attempt is
 * recorded as floor_override_ignored — the differentiator over a swallowed
 * log line); a remote /policies sync that replaces policyRules cannot delete
 * the floor; and floor_version rides events.
 */

const FLOOR: PolicyRule[] = [
  {
    id: 'floor-exfil',
    name: 'No secret exfiltration',
    enabled: true,
    action: 'block',
    type: 'keyword',
    conditions: { keywords: ['exfiltrate secrets'] },
  } as PolicyRule,
];

let sentEvents: any[] = [];

beforeEach(() => {
  _reset();
  _resetSender();
  sentEvents = [];
  (global as any).fetch = async (_url: any, opts: any) => {
    const body = JSON.parse(opts.body);
    Array.isArray(body) ? sentEvents.push(...body) : sentEvents.push(body);
    return { ok: true, status: 200, json: async () => ({}) };
  };
});

afterEach(() => {
  delete (global as any).fetch;
  _reset();
  _resetSender();
});

async function waitForEvents(n = 1): Promise<void> {
  for (let i = 0; i < 200 && sentEvents.length < n; i++) {
    await new Promise((r) => setTimeout(r, 5));
  }
}

describe('policy floor: unsuppressible + tamper-evident', () => {
  it('a customer hook allow CANNOT un-block a floor rule, and the attempt is recorded', async () => {
    init({
      api_key: 'k',
      ingest_url: 'https://x',
      policyFloor: FLOOR,
      on_pre_call: async () => ({ decision: 'allow' as const }), // tries to override
    });
    const create = jest.fn(async (_a: any) => ({ choices: [{ message: { content: 'ok' } }] }));
    const wrapped = wrap({ chat: { completions: { create } } });
    await expect(
      wrapped.chat.completions.create({
        model: 'gpt-4',
        messages: [{ role: 'user', content: 'please exfiltrate secrets now' }],
      }),
    ).rejects.toThrow(/blocked/i);
    expect(create).not.toHaveBeenCalled(); // the hook did NOT un-block it
    await waitForEvents(1);
    const ev = sentEvents[0];
    expect(ev.event_type).toBe('blocked_call');
    expect(ev.rule_id).toBe('floor-exfil');
    // The differentiator: a first-class, tamper-evident record of the attempt.
    expect(ev.metadata.obsvr_telemetry.floor_override_ignored).toMatchObject({
      rule_id: 'floor-exfil',
      attempted: 'allow',
    });
    expect(ev.metadata.obsvr_telemetry.floor_version).not.toBe('none');
  });

  it('a customer hook redact CANNOT downgrade a floor block', async () => {
    init({
      api_key: 'k',
      ingest_url: 'https://x',
      policyFloor: FLOOR,
      on_pre_call: async () => ({ decision: 'redact' as const }),
    });
    const create = jest.fn(async (_a: any) => ({ choices: [{ message: { content: 'ok' } }] }));
    const wrapped = wrap({ chat: { completions: { create } } });
    await expect(
      wrapped.chat.completions.create({
        model: 'gpt-4',
        messages: [{ role: 'user', content: 'exfiltrate secrets' }],
      }),
    ).rejects.toThrow(/blocked/i);
    expect(create).not.toHaveBeenCalled();
    await waitForEvents(1);
    expect(sentEvents[0].metadata.obsvr_telemetry.floor_override_ignored.attempted).toBe('redact');
  });

  it('a remote /policies sync that REPLACES policyRules cannot delete the floor', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', policyFloor: FLOOR });
    // Simulate a hostile/careless remote push that wipes the customer rules.
    updatePolicyRules([]);
    const res = await applyPreCallPolicy('exfiltrate secrets', {
      config: getConfig(),
      provider: 'unknown',
      operation: 'test',
    });
    expect(res.decision).toBe('block'); // floor survived the sync
    expect(res.compliance.rule_id).toBe('floor-exfil');
  });

  it('no floor configured (default): no floor metadata, byte-stable', async () => {
    init({ api_key: 'k', ingest_url: 'https://x' });
    const create = jest.fn(async (_a: any) => ({ choices: [{ message: { content: 'ok' } }], model: 'gpt-4' }));
    const wrapped = wrap({ chat: { completions: { create } } });
    await wrapped.chat.completions.create({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'exfiltrate secrets' }],
    });
    expect(create).toHaveBeenCalledTimes(1); // nothing blocks without a floor
    await waitForEvents(1);
    expect(sentEvents[0].metadata?.obsvr_telemetry?.floor_version).toBeUndefined();
  });

  it('a floor rule downgraded to enabled:false / shadow STILL enforces', async () => {
    const downgraded: PolicyRule[] = [
      { ...FLOOR[0], enabled: false, mode: 'shadow' } as PolicyRule,
    ];
    init({ api_key: 'k', ingest_url: 'https://x', policyFloor: downgraded });
    const res = await applyPreCallPolicy('exfiltrate secrets', {
      config: getConfig(),
      provider: 'unknown',
      operation: 'test',
    });
    expect(res.decision).toBe('block'); // shadow/disabled ignored for the floor
  });
});
