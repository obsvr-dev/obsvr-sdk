import { init, _reset, getConfig } from '../../src/proxy/config';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { applyPreCallPolicy } from '../../src/integrations/core';
import { obsvrGovernMCP } from '../../src/integrations/mcp';
import { _resetAllQuotas, getQuotaStatus } from '../../src/governance/quota';
import type { PolicyRule } from '../../src/policy/rules';

/**
 * Phase-1A quota residual: applyPreCallPolicy (the integration seam) had no
 * user/principal metadata, so USER-SCOPED quota rules metered the 'default'
 * bucket on the integration path instead of the caller's bucket. These tests
 * pin that identity is now threaded through to the quota meter.
 */

const userQuota = (limit: number): PolicyRule[] => [
  {
    id: 'uq',
    name: 'per-user quota',
    enabled: true,
    action: 'block',
    type: 'quota',
    conditions: { quota_limit: limit, quota_window_ms: 60_000, quota_scope: 'user_id' },
  },
];

beforeEach(() => {
  _reset();
  _resetSender();
  _resetAllQuotas();
  (global as any).fetch = async () => ({ ok: true, status: 200 });
});

afterEach(() => {
  _reset();
  _resetSender();
  _resetAllQuotas();
});

describe('applyPreCallPolicy threads caller identity to the quota bucket', () => {
  it('meters the user bucket, not the default bucket', async () => {
    init({ apiKey: 'k', sampleRate: 1, policyRules: userQuota(5) } as any);
    const cfg = getConfig();
    await applyPreCallPolicy('hi', { config: cfg, provider: 'openai', operation: 'op', userId: 'alice' });
    expect(getQuotaStatus('user_id', 'alice', 5, 60_000).used).toBe(1);
    expect(getQuotaStatus('user_id', 'default', 5, 60_000).used).toBe(0);
  });

  it('without identity, falls back to the default bucket (documents the old behavior)', async () => {
    init({ apiKey: 'k', sampleRate: 1, policyRules: userQuota(5) } as any);
    const cfg = getConfig();
    await applyPreCallPolicy('hi', { config: cfg, provider: 'openai', operation: 'op' });
    expect(getQuotaStatus('user_id', 'default', 5, 60_000).used).toBe(1);
    expect(getQuotaStatus('user_id', 'alice', 5, 60_000).used).toBe(0);
  });

  it('a user-scoped limit blocks the over-quota user but not others', async () => {
    init({ apiKey: 'k', sampleRate: 1, policyRules: userQuota(1) } as any);
    const cfg = getConfig();
    const call = (userId: string) =>
      applyPreCallPolicy('hi', { config: cfg, provider: 'openai', operation: 'op', userId });
    expect((await call('alice')).decision).toBe('allow');
    expect((await call('alice')).decision).toBe('block'); // alice exhausted
    expect((await call('bob')).decision).toBe('allow'); // separate bucket
  });

  it('falls back to the ambient useSubject() subject when identity is not passed', async () => {
    const { useSubject } = await import('../../src/proxy/subject');
    init({ apiKey: 'k', sampleRate: 1, policyRules: userQuota(5) } as any);
    const cfg = getConfig();
    await useSubject('user:carol', async () => {
      await applyPreCallPolicy('hi', { config: cfg, provider: 'openai', operation: 'op' });
    });
    expect(getQuotaStatus('user_id', 'carol', 5, 60_000).used).toBe(1);
    expect(getQuotaStatus('user_id', 'default', 5, 60_000).used).toBe(0);
  });
});

describe('user-scoped quota via the MCP framework integration', () => {
  function fakeClient() {
    return {
      async callTool(_p: { name: string; arguments?: Record<string, unknown> }) {
        return { content: [{ type: 'text', text: 'ok' }] };
      },
    };
  }

  it('meters the caller principal bucket, not default', async () => {
    // piiPolicy:{} opens the pre-call gate so the quota rule is evaluated.
    init({ apiKey: 'k', sampleRate: 1, piiPolicy: {}, policyRules: userQuota(1) } as any);
    const cfg = getConfig();
    const alice = obsvrGovernMCP(fakeClient(), cfg, { user_id: 'alice' });
    const bob = obsvrGovernMCP(fakeClient(), cfg, { user_id: 'bob' });

    await alice.callTool({ name: 'read', arguments: {} }); // alice unit 1/1
    await expect(alice.callTool({ name: 'read', arguments: {} })).rejects.toThrow(/blocked/i);
    // bob's bucket is independent — still allowed.
    await expect(bob.callTool({ name: 'read', arguments: {} })).resolves.toBeDefined();

    expect(getQuotaStatus('user_id', 'default', 1, 60_000).used).toBe(0);
  });
});
