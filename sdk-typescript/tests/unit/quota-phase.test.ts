/**
 * Quota phase-awareness regression tests (pre-launch F4).
 *
 * A single governed call runs the rules engine TWICE (pre-call over the
 * prompt, post-call over the response). Quota rules must meter once per
 * call: rules in scope for both phases consume on the request phase only;
 * rules explicitly scoped to the response consume on the response phase.
 * Scoped rules must always meter their own bucket (user/service/tenant),
 * never fall back to 'default'.
 */
import { evaluatePolicyRules, type PolicyRule } from '../../src/policy/rules';
import { getQuotaStatus, _resetAllQuotas } from '../../src/governance/quota';
import { applyPostCallPolicy } from '../../src/integrations/core';
import { init, getConfig, _reset } from '../../src/proxy/config';
import { wrap } from '../../src/proxy/wrapper';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';

const realFetch = globalThis.fetch;

beforeEach(() => {
  _reset();
  _resetSender();
  _resetAllQuotas();
  // Swallow fire-and-forget audit sends: no network in unit tests.
  globalThis.fetch = (async () => ({
    status: 200,
    ok: true,
    json: async () => ({ count: 1 }),
  })) as unknown as typeof fetch;
});

afterEach(() => {
  globalThis.fetch = realFetch;
});

function quotaRule(overrides: Partial<PolicyRule> = {}): PolicyRule {
  return {
    id: 'q1',
    name: 'quota',
    enabled: true,
    action: 'block',
    type: 'quota',
    conditions: { quota_limit: 10, quota_window_ms: 60_000, quota_scope: 'project' },
    ...overrides,
  } as PolicyRule;
}

describe('quota consumption is phase-aware (no double-count)', () => {
  it('both-scoped rule + 1 simulated call (prompt then response phase) => used === 1', async () => {
    const rules = [quotaRule({ applies_to: 'both' })];
    init({ api_key: 'test', policy_rules: rules });

    // One call = one prompt-phase evaluation + one response-phase evaluation.
    evaluatePolicyRules(rules, 'hello', 'prompt');
    await applyPostCallPolicy('the response', {}, getConfig());

    expect(getQuotaStatus('project', 'project', 10, 60_000).used).toBe(1);
  });

  it('rule without applies_to (defaults to both) burns 1 unit per wrapped call end-to-end', async () => {
    init({ api_key: 'test', sample_rate: 1, policy_rules: [quotaRule()] });

    const mockClient = {
      chat: {
        completions: {
          create: async (_args: unknown) => ({
            choices: [{ message: { role: 'assistant', content: 'hi there' } }],
            model: 'gpt-4o',
            usage: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 },
          }),
        },
      },
    };
    const wrapped = wrap(mockClient);
    await wrapped.chat.completions.create({
      model: 'gpt-4o',
      messages: [{ role: 'user', content: 'hello' }],
    } as any);

    expect(getQuotaStatus('project', 'project', 10, 60_000).used).toBe(1);
  });

  it('response-only rule increments exactly once, on the response phase', async () => {
    const rules = [quotaRule({ applies_to: 'response' })];
    init({ api_key: 'test', policy_rules: rules });

    // Prompt phase must not touch the counter (rule out of scope).
    evaluatePolicyRules(rules, 'hello', 'prompt');
    expect(getQuotaStatus('project', 'project', 10, 60_000).used).toBe(0);

    // Response phase consumes the single unit.
    await applyPostCallPolicy('the response', {}, getConfig());
    expect(getQuotaStatus('project', 'project', 10, 60_000).used).toBe(1);
  });

  it('checkOnly (EV-22) never consumes in either phase', () => {
    const rules = [quotaRule({ applies_to: 'both' }), quotaRule({ id: 'q2', applies_to: 'response' })];
    evaluatePolicyRules(rules, 'hello', 'prompt', undefined, { checkOnly: true });
    evaluatePolicyRules(rules, 'the response', 'response', undefined, { checkOnly: true });
    expect(getQuotaStatus('project', 'project', 10, 60_000).used).toBe(0);
  });
});

describe('scoped-bucket selection (user bucket, never default)', () => {
  const userRule = (overrides: Partial<PolicyRule> = {}) =>
    quotaRule({
      conditions: { quota_limit: 10, quota_window_ms: 60_000, quota_scope: 'user_id' },
      ...overrides,
    });

  it('prompt phase: context.metadata.user_id selects the user bucket', () => {
    evaluatePolicyRules([userRule()], 'hello', 'prompt', { metadata: { user_id: 'u1' } });
    expect(getQuotaStatus('user_id', 'u1', 10, 60_000).used).toBe(1);
    expect(getQuotaStatus('user_id', 'default', 10, 60_000).used).toBe(0);
  });

  it('prompt phase: wrapper-style top-level user_id (spread metadata) selects the user bucket', () => {
    // The proxy wrapper spreads audit metadata at the TOP level of the
    // eval context; the engine must honor that shape too.
    evaluatePolicyRules([userRule()], 'hello', 'prompt', { user_id: 'u1' } as any);
    expect(getQuotaStatus('user_id', 'u1', 10, 60_000).used).toBe(1);
    expect(getQuotaStatus('user_id', 'default', 10, 60_000).used).toBe(0);
  });

  it('response phase: event identity selects the user bucket, never default', async () => {
    init({ api_key: 'test', policy_rules: [userRule({ applies_to: 'response' })] });
    await applyPostCallPolicy('the response', { user_id: 'u1' }, getConfig());
    expect(getQuotaStatus('user_id', 'u1', 10, 60_000).used).toBe(1);
    expect(getQuotaStatus('user_id', 'default', 10, 60_000).used).toBe(0);
  });

  it('both-scoped user rule across both phases: user bucket used === 1, default untouched', async () => {
    const rules = [userRule({ applies_to: 'both' })];
    init({ api_key: 'test', policy_rules: rules });
    evaluatePolicyRules(rules, 'hello', 'prompt', { metadata: { user_id: 'u1' } });
    await applyPostCallPolicy('the response', { user_id: 'u1' }, getConfig());
    expect(getQuotaStatus('user_id', 'u1', 10, 60_000).used).toBe(1);
    expect(getQuotaStatus('user_id', 'default', 10, 60_000).used).toBe(0);
  });
});
