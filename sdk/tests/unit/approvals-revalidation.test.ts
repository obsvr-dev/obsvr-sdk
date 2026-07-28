import { jest } from '@jest/globals';
import { init, _reset, getConfig } from '../../src/proxy/config';
import { wrap } from '../../src/proxy/wrapper';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { applyPreCallPolicy } from '../../src/integrations/core';
import { updateApprovals, _resetApprovals } from '../../src/policy/approvals';
import { deriveRuleHash, type PolicyRule } from '../../src/policy/rules';

/**
 * An approval is re-checked after the layers that can delay a call, not only
 * when the rules engine first consults it. Twin:
 * sdk-python/tests/test_approvals_revalidation.py.
 *
 * The window this closes is real rather than theoretical: the customer hook
 * has a two-second budget by default and an external policy backend has its
 * own, so a grant can be revoked or expire between "approved" and "sent". A
 * revoking policy poll during the hook is the deterministic way to stand that
 * window up — and revocation-mid-call is the case an operator actually cares
 * about, since it is what a human clicking "revoke" does.
 */

const RULE: PolicyRule = {
  id: 'r-wire',
  name: 'Wire transfer needs approval',
  enabled: true,
  action: 'block',
  type: 'action_gate',
  conditions: { require_approval: true, action_types: ['wire_transfer'] },
};

const FUTURE = new Date(Date.now() + 3_600_000).toISOString();

function liveGrant() {
  return [
    {
      id: 'g1',
      rule_id: 'r-wire',
      expires_at: FUTURE,
      rule_hash: deriveRuleHash(RULE),
    },
  ];
}

let sentEvents: Array<Record<string, unknown>> = [];

beforeEach(() => {
  _reset();
  _resetSender();
  _resetApprovals();
  sentEvents = [];
  (global as unknown as { fetch: unknown }).fetch = async (_url: unknown, opts: { body?: string }) => {
    if (typeof opts?.body === 'string') {
      try {
        const body = JSON.parse(opts.body);
        Array.isArray(body) ? sentEvents.push(...body) : sentEvents.push(body);
      } catch {
        /* the approval-request POST is not an event batch */
      }
    }
    return { ok: true, status: 200, json: async () => ({}) };
  };
});

afterEach(() => {
  delete (global as unknown as { fetch?: unknown }).fetch;
  _reset();
  _resetSender();
  _resetApprovals();
});

async function waitForEvents(n = 1): Promise<void> {
  for (let i = 0; i < 400 && sentEvents.length < n; i++) {
    await new Promise((r) => setTimeout(r, 5));
  }
}

describe('approvals are revalidated before the call goes out', () => {
  it('a grant revoked during the customer hook does not authorize the call', async () => {
    init({
      api_key: 'k',
      ingest_url: 'https://x',
      policy_rules: [RULE],
      // Stands in for a /policies poll landing mid-call, or a human clicking
      // revoke: the grant is gone by the time the request would be sent.
      on_pre_call: async () => {
        updateApprovals([]);
        return { decision: 'allow' as const };
      },
    });
    updateApprovals(liveGrant());

    const create = jest.fn(async (_a: unknown) => ({ choices: [{ message: { content: 'ok' } }] }));
    const wrapped = wrap({ chat: { completions: { create } } }) as {
      chat: { completions: { create: (a: unknown) => Promise<unknown> } };
    };
    await expect(
      wrapped.chat.completions.create({
        model: 'gpt-4',
        messages: [{ role: 'user', content: 'please wire_transfer the funds' }],
        metadata: { action_name: 'wire_transfer' },
      }),
    ).rejects.toThrow(/blocked/i);
    expect(create).not.toHaveBeenCalled();

    await waitForEvents(1);
    expect(sentEvents[0].action_taken).toBe('blocked');
    expect(sentEvents[0].rule_id).toBe('r-wire');
    expect(sentEvents[0].policy_reason).toContain('approval_expired_before_execution');
  });

  it('a grant that survives the hook still authorizes the call', async () => {
    init({
      api_key: 'k',
      ingest_url: 'https://x',
      policy_rules: [RULE],
      on_pre_call: async () => ({ decision: 'allow' as const }),
    });
    updateApprovals(liveGrant());

    const create = jest.fn(async (_a: unknown) => ({ choices: [{ message: { content: 'ok' } }] }));
    const wrapped = wrap({ chat: { completions: { create } } }) as {
      chat: { completions: { create: (a: unknown) => Promise<unknown> } };
    };
    await wrapped.chat.completions.create({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'please wire_transfer the funds' }],
      metadata: { action_name: 'wire_transfer' },
    });
    expect(create).toHaveBeenCalled();
  });

  it('the integrations path revalidates too', async () => {
    init({
      api_key: 'k',
      ingest_url: 'https://x',
      policy_rules: [RULE],
      on_pre_call: async () => {
        updateApprovals([]);
        return { decision: 'allow' as const };
      },
    });
    updateApprovals(liveGrant());
    const res = await applyPreCallPolicy('please wire_transfer the funds', {
      config: getConfig(),
      provider: 'openai',
      operation: 'test',
      model: 'gpt-4',
      metadata: { action_name: 'wire_transfer' },
    });
    expect(res.decision).toBe('block');
    expect(res.compliance.policy_reason).toContain('approval_expired_before_execution');
  });

  it('an approval-required block on the integrations path files a request', async () => {
    const posted: Array<Record<string, unknown>> = [];
    (global as unknown as { fetch: unknown }).fetch = async (url: unknown, opts: { body?: string }) => {
      if (String(url).includes('/approvals/request') && typeof opts.body === 'string') {
        posted.push(JSON.parse(opts.body));
      }
      return { ok: true, status: 200, json: async () => ({}) };
    };
    init({ api_key: 'k', ingest_url: 'https://x', policy_rules: [RULE] });
    // No grant: the rule blocks and a human has to be asked. Before this the
    // integrations path could reach approval_required and then ask nobody, so
    // the block was permanent rather than pending.
    const res = await applyPreCallPolicy('please wire_transfer the funds', {
      config: getConfig(),
      provider: 'openai',
      operation: 'chat.completions.create',
      metadata: { action_name: 'wire_transfer' },
    });
    expect(res.decision).toBe('block');
    await new Promise((r) => setTimeout(r, 20));
    expect(posted).toHaveLength(1);
    expect(posted[0].rule_id).toBe('r-wire');
    // The request names the exact call, so the grant can be bound to it.
    expect(typeof posted[0].action_hash).toBe('string');
    expect((posted[0].action_hash as string)).toHaveLength(64);
  });
});
