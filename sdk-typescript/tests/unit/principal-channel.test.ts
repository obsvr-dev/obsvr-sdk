import { init, _reset, getConfig } from '../../src/proxy/config';
import { wrap } from '../../src/proxy/wrapper';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { useSubject } from '../../src/proxy/subject';
import { _resetAllQuotas, getQuotaStatus } from '../../src/governance/quota';
import { _resetApprovals } from '../../src/policy/approvals';
import type { PolicyRule } from '../../src/policy/rules';

/**
 * ONE invariant, stated as a test: every layer of the wrap path that consumes
 * a principal reads the SAME resolved channel the signed event resolves.
 *
 * A principal reaches a wrapped call by three channels — per-call metadata,
 * the wrap-time option, and the ambient useSubject() scope. The event builder
 * resolves all three; layers that read `audit_fields.metadata` directly saw
 * only the first, so the enforcing view and the recorded view disagreed about
 * who made the call. Measured consequences, both fixed here:
 *
 *   - a per-user quota metered the 'default' bucket for a wrap-time or
 *     ambient principal, so ONE user's spend exhausted the limit for
 *     everyone and an unrelated user's FIRST call was refused;
 *   - the approval request filed for a human reviewer carried no user_id
 *     while the blocked event for the same call named one, so the reviewer
 *     was asked to authorise an action without being told who asked.
 *
 * The twin for the integrations seam is quota-residual.test.ts; Python pins
 * the same invariant off its choke-point fold (policy.apply_pre_call_policy).
 *
 * Each channel is asserted SEPARATELY on purpose: a fix that resolves only
 * one of the three passes a merged test and still drops the other two.
 */

const userQuota = (limit: number): PolicyRule[] => [
  {
    id: 'uq',
    name: 'per-user quota',
    enabled: true,
    action: 'block',
    type: 'quota',
    conditions: { quota_limit: limit, quota_window_ms: 60_000, quota_scope: 'user_id' },
  } as unknown as PolicyRule,
];

const APPROVAL_RULE: PolicyRule[] = [
  {
    id: 'appr',
    name: 'wire transfers need a human',
    enabled: true,
    action: 'block',
    type: 'keyword',
    conditions: { keywords: ['wire transfer'], require_approval: true },
  } as unknown as PolicyRule,
];

let sentEvents: any[] = [];
let approvalRequests: any[] = [];

beforeEach(() => {
  _reset();
  _resetSender();
  _resetAllQuotas();
  _resetApprovals();
  sentEvents = [];
  approvalRequests = [];
  (global as any).fetch = async (url: any, opts: any) => {
    const body = opts?.body ? JSON.parse(opts.body) : undefined;
    if (String(url).includes('/approvals/request')) {
      approvalRequests.push(body);
    } else if (body !== undefined) {
      Array.isArray(body) ? sentEvents.push(...body) : sentEvents.push(body);
    }
    return { ok: true, status: 200, json: async () => ({}) };
  };
});

afterEach(() => {
  delete (global as any).fetch;
  _reset();
  _resetSender();
  _resetAllQuotas();
  _resetApprovals();
});

const waitFor = async (n: number) => {
  for (let i = 0; i < 200 && sentEvents.length < n; i++) {
    await new Promise((r) => setTimeout(r, 5));
  }
};

const fakeClient = () => ({
  chat: {
    completions: {
      create: async (_args: any) => ({
        id: 'chatcmpl-1',
        choices: [{ message: { content: 'Hello!' } }],
      }),
    },
  },
});

const say = async (client: any, content: string, metadata?: Record<string, unknown>) => {
  try {
    await client.chat.completions.create({
      model: 'gpt-4',
      messages: [{ role: 'user', content }],
      ...(metadata ? { metadata } : {}),
    });
    return 'ran';
  } catch {
    return 'refused';
  }
};

describe('wrap(): a scoped quota buckets by the RESOLVED principal', () => {
  it('meters the wrap-time principal, not the default bucket', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', policy_rules: userQuota(5) } as any);
    const client = wrap(fakeClient(), { user_id: 'alice' });

    expect(await say(client, 'hi')).toBe('ran');

    expect(getQuotaStatus('user_id', 'alice', 5, 60_000).used).toBe(1);
    expect(getQuotaStatus('user_id', 'default', 5, 60_000).used).toBe(0);
  });

  it('meters the AMBIENT principal, not the default bucket', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', policy_rules: userQuota(5) } as any);
    const client = wrap(fakeClient());

    await useSubject('user:carol', () => say(client, 'hi'));

    expect(getQuotaStatus('user_id', 'carol', 5, 60_000).used).toBe(1);
    expect(getQuotaStatus('user_id', 'default', 5, 60_000).used).toBe(0);
  });

  it('a limit-1 per-user quota refuses the OVER-quota principal only (wrap-time)', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', policy_rules: userQuota(1) } as any);
    const alice = wrap(fakeClient(), { user_id: 'alice' });
    const bob = wrap(fakeClient(), { user_id: 'bob' });

    expect(await say(alice, 'one')).toBe('ran');
    expect(await say(alice, 'two')).toBe('refused');
    // The defect this pins: bob shared alice's 'default' bucket, so his FIRST
    // call was refused under a limit he had not spent a unit of.
    expect(await say(bob, 'one')).toBe('ran');
  });

  it('a limit-1 per-user quota refuses the OVER-quota principal only (ambient)', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', policy_rules: userQuota(1) } as any);
    const client = wrap(fakeClient());

    expect(await useSubject('user:alice', () => say(client, 'one'))).toBe('ran');
    expect(await useSubject('user:alice', () => say(client, 'two'))).toBe('refused');
    expect(await useSubject('user:bob', () => say(client, 'one'))).toBe('ran');
  });

  it('per-call metadata still wins over the wrap-time option', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', policy_rules: userQuota(5) } as any);
    const client = wrap(fakeClient(), { user_id: 'alice' });

    await say(client, 'hi', { user_id: 'dana' });

    expect(getQuotaStatus('user_id', 'dana', 5, 60_000).used).toBe(1);
    expect(getQuotaStatus('user_id', 'alice', 5, 60_000).used).toBe(0);
  });
});

describe('wrap(): the approval request names the principal the block names', () => {
  it('a wrap-time principal reaches the filed request', async () => {
    init({
      api_key: 'k',
      ingest_url: 'https://x',
      policy_rules: APPROVAL_RULE,
      approval_wait_ms: 0,
    } as any);
    const client = wrap(fakeClient(), { user_id: 'user_alice' });

    expect(await say(client, 'approve this wire transfer')).toBe('refused');
    await waitFor(1);

    const blocked = sentEvents.find((e) => e.event_type === 'blocked_call');
    expect(blocked?.user_id).toBe('user_alice');
    expect(approvalRequests.length).toBe(1);
    // The record and the request channel agree about the same call.
    expect(approvalRequests[0].user_id).toBe('user_alice');
  });

  it('an AMBIENT principal reaches the filed request', async () => {
    init({
      api_key: 'k',
      ingest_url: 'https://x',
      policy_rules: APPROVAL_RULE,
      approval_wait_ms: 0,
    } as any);
    const client = wrap(fakeClient());

    expect(
      await useSubject('user:amb_bob', () => say(client, 'approve this wire transfer')),
    ).toBe('refused');
    await waitFor(1);

    const blocked = sentEvents.find((e) => e.event_type === 'blocked_call');
    expect(blocked?.user_id).toBe('amb_bob');
    expect(approvalRequests.length).toBe(1);
    expect(approvalRequests[0].user_id).toBe('amb_bob');
  });

  it('a per-call metadata principal reaches the filed request', async () => {
    init({
      api_key: 'k',
      ingest_url: 'https://x',
      policy_rules: APPROVAL_RULE,
      approval_wait_ms: 0,
    } as any);
    const client = wrap(fakeClient());

    expect(
      await say(client, 'approve this wire transfer', { user_id: 'meta_eve' }),
    ).toBe('refused');
    await waitFor(1);

    expect(approvalRequests.length).toBe(1);
    expect(approvalRequests[0].user_id).toBe('meta_eve');
  });

  it('an unattributed call files a request with no principal to invent', async () => {
    init({
      api_key: 'k',
      ingest_url: 'https://x',
      policy_rules: APPROVAL_RULE,
      approval_wait_ms: 0,
    } as any);
    const client = wrap(fakeClient());

    expect(await say(client, 'approve this wire transfer')).toBe('refused');

    expect(approvalRequests.length).toBe(1);
    expect(approvalRequests[0].user_id).toBeUndefined();
  });
});

describe('wrap(): the decision record commits the principal it enforced on', () => {
  // The digest is opaque, so the principal's presence in it is measured the
  // only way it can be: two calls identical in every other committed field
  // must hash differently when they name different principals. A scope id
  // the digest never received leaves the two indistinguishable.
  const hashOf = async (run: (client: any) => Promise<unknown>) => {
    init({ api_key: 'k', ingest_url: 'https://x' } as any);
    const client = wrap(fakeClient());
    await run(client);
    await waitFor(1);
    const h = sentEvents[0]?.decision_input_hash;
    _reset();
    _resetSender();
    sentEvents = [];
    return h;
  };

  it('a per-call metadata principal reaches the decision-input scope id', async () => {
    const attributed = await hashOf((c) => say(c, 'hi', { user_id: 'dana' }));
    const anonymous = await hashOf((c) => say(c, 'hi'));

    expect(typeof attributed).toBe('string');
    expect(attributed).not.toBe(anonymous);
  });

  it('an ambient principal reaches the decision-input scope id', async () => {
    const attributed = await hashOf((c) => useSubject('user:alice', () => say(c, 'hi')));
    const anonymous = await hashOf((c) => say(c, 'hi'));

    expect(typeof attributed).toBe('string');
    expect(attributed).not.toBe(anonymous);
  });
});

describe('wrap(): options reach an ALREADY-GOVERNED client', () => {
  // Under auto-instrumentation every client a caller holds is already
  // governed, so wrap(client, { user_id }) is the documented way to attribute
  // one — and the de-duplication that stops a second audit layer was
  // discarding those options with it. Governance stays single-layer; the
  // attribution survives. Python's twin: tests/test_wrap_idempotent.py.
  it('a second wrap with no options returns the very same object', () => {
    init({ api_key: 'k', ingest_url: 'https://x' } as any);
    const once = wrap(fakeClient());
    expect(wrap(once)).toBe(once);
  });

  it('a second wrap carrying a principal attributes the call', async () => {
    init({ api_key: 'k', ingest_url: 'https://x' } as any);
    const governed = wrap(fakeClient());
    const attributed = wrap(governed, { user_id: 'alice' });

    await say(attributed, 'hi');
    await waitFor(1);

    expect(sentEvents[0].user_id).toBe('alice');
  });

  it('and still records exactly ONE audit event', async () => {
    init({ api_key: 'k', ingest_url: 'https://x' } as any);
    const attributed = wrap(wrap(fakeClient()), { user_id: 'alice' });

    await say(attributed, 'hi');
    await waitFor(1);
    // Give a second, duplicate event time to arrive if the layer stacked.
    await new Promise((r) => setTimeout(r, 50));

    expect(sentEvents.filter((e) => e.event_type !== 'blocked_call').length).toBe(1);
  });

  it('options merge over the ones the client already carried', async () => {
    init({ api_key: 'k', ingest_url: 'https://x' } as any);
    const governed = wrap(fakeClient(), { user_id: 'alice', source: 'first' });
    const attributed = wrap(governed, { user_id: 'bob' });

    await say(attributed, 'hi');
    await waitFor(1);

    expect(sentEvents[0].user_id).toBe('bob');
    expect(sentEvents[0].source).toBe('first');
  });

  it('a re-attributed client meters the NEW principal’s quota bucket', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', policy_rules: userQuota(5) } as any);
    const attributed = wrap(wrap(fakeClient()), { user_id: 'alice' });

    await say(attributed, 'hi');

    // The two fixes meeting: the option survives the rebind AND reaches the
    // enforcing channel.
    expect(getQuotaStatus('user_id', 'alice', 5, 60_000).used).toBe(1);
    expect(getQuotaStatus('user_id', 'default', 5, 60_000).used).toBe(0);
  });
});

describe('the quota bucket and the config are read consistently', () => {
  it('getConfig() is unchanged by the enforcing view (no metadata mutation)', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', policy_rules: userQuota(5) } as any);
    const client = wrap(fakeClient(), { user_id: 'alice' });
    const caller = { user_id: 'dana', keep: 'me' };

    await say(client, 'hi', caller);

    // The enforcing view is derived, never a mutation of what the caller
    // passed (Python builds a fresh dict for exactly this reason).
    expect(caller).toEqual({ user_id: 'dana', keep: 'me' });
    expect(getConfig().api_key).toBe('k');
  });
});
