import { jest } from '@jest/globals';
import { init, _reset, getConfig, updatePolicyRules } from '../../src/proxy/config';
import { wrap } from '../../src/proxy/wrapper';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { applyPreCallPolicy } from '../../src/integrations/core';
import { obsvrGovernMCP } from '../../src/integrations/mcp';
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

// ── the floor must not be gated behind an unrelated feature ──────────────────
//
// Twin of sdk-python/tests/test_policy_floor_wiring.py. The floor is enforced
// inside the shared pre-call evaluation, and MCP ran that evaluation only when a
// pii_policy, a pre-call hook, a minted canary or a tainted session existed.
// `policyFloor` was not in that list in EITHER SDK, so a deployment that
// configured the operator baseline and nothing else got no floor at all on MCP
// tool calls — silently, on the surface the documentation singles out as the
// strongest. Measured live on the Python side before the fix: the tool executed
// and the record read `allowed`.

describe('a policy floor configured alone still reaches MCP tool calls', () => {
  const FLOOR_ONLY = [
    {
      id: 'floor-only',
      name: 'floor blocks the secret',
      // Declared in the weakened shape a floor rule must ignore, so the
      // non-overridable property is exercised by construction.
      enabled: false,
      mode: 'shadow',
      action: 'block',
      type: 'keyword',
      conditions: { keywords: ['launch codes'] },
    },
  ];

  function governedSession(toolRuns: string[]) {
    return obsvrGovernMCP(
      {
        callTool: async (p: any) => {
          toolRuns.push(String(p?.name ?? 'unknown'));
          return 'ok';
        },
        listTools: async () => ({ tools: [] }),
      },
      getConfig(),
    ) as { callTool: (p: unknown) => Promise<unknown> };
  }

  it('blocks the tool call with no other policy feature configured', async () => {
    init({ api_key: 'test', sample_rate: 1, policyFloor: FLOOR_ONLY } as any);
    const toolRuns: string[] = [];
    const client = governedSession(toolRuns);

    await expect(
      client.callTool({
        name: 'write_note',
        arguments: { text: 'the launch codes are 1234' },
      }),
    ).rejects.toThrow();

    expect(toolRuns).toEqual([]);
    await waitForEvents(1);
    expect(sentEvents.some((e) => e.action_taken === 'blocked')).toBe(true);
  });

  it('lets clean arguments through under the same floor', async () => {
    // The control. Without it the test above passes for a gate that blocks all.
    init({ api_key: 'test', sample_rate: 1, policyFloor: FLOOR_ONLY } as any);
    const toolRuns: string[] = [];
    const client = governedSession(toolRuns);

    await client.callTool({
      name: 'write_note',
      arguments: { text: 'an ordinary note' },
    });

    expect(toolRuns).toEqual(['write_note']);
    await waitForEvents(1);
    expect(sentEvents.some((e) => e.action_taken === 'blocked')).toBe(false);
  });
});
