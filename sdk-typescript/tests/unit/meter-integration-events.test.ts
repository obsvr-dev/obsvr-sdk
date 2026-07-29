/**
 * Cost and token-quota metering on the framework-integration path, opt-in.
 *
 * The `wrap()` client-proxy path has always metered. This one never has — the
 * integration event builder imported nothing from governance/cost or
 * governance/quota and called neither — so every framework integration
 * (LangChain, LlamaIndex, Vercel AI, the agent frameworks) has been invisible
 * to cost reporting and to token budgets since it shipped.
 *
 * That is deliberately NOT fixed unconditionally. A `quota_unit: "tokens"`
 * budget that has never bound on framework traffic would begin binding, and
 * calls that previously succeeded would start being blocked once the budget was
 * reached. For someone already running a token quota that is an outage, not a
 * fix. So the default is off and these tests pin BOTH halves: that off changes
 * nothing, and that on produces real figures.
 */
import { init, getConfig, _reset } from '../../src/proxy/config';
import { buildIntegrationEvent } from '../../src/integrations/core';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { _resetAllQuotas, checkTokenBudget } from '../../src/governance/quota';
import { COST_METADATA_KEY } from '../../src/governance/cost';

const COST_POLICY = {
  rates: { 'gpt-4o-mini': { input_micros_per_1k: 150, output_micros_per_1k: 600 } },
};

const TOKEN_QUOTA_RULE = {
  id: 'tokens-per-user',
  name: 'token budget',
  enabled: true,
  action: 'block' as const,
  type: 'quota' as const,
  conditions: {
    quota_unit: 'tokens' as const,
    quota_limit: 1000,
    quota_window_ms: 60_000,
    quota_scope: 'user_id' as const,
  },
};

function buildEvent() {
  return buildIntegrationEvent({
    config: getConfig(),
    provider: 'openai',
    model: 'gpt-4o-mini',
    operation: 'llm',
    source: 'langchain',
    prompt: 'what is 2+2',
    response: 'four',
    inputTokens: 1000,
    outputTokens: 500,
    totalTokens: 1500,
    options: { user_id: 'alice' },
  });
}

/** The cost fragment rides one reserved metadata key, `obsvr_cost`. */
const costFragment = (e: { metadata?: unknown }) =>
  ((e.metadata ?? {}) as Record<string, unknown>)[COST_METADATA_KEY] as
    | Record<string, unknown>
    | undefined;

beforeEach(() => {
  _reset();
  _resetSender();
  _resetAllQuotas();
});

describe('default (flag absent): the framework path is unmetered', () => {
  it('stamps no cost fragment even with a cost policy configured', () => {
    init({ api_key: 'test', sample_rate: 1, costPolicy: COST_POLICY });
    expect(getConfig().meterIntegrationEvents).toBeUndefined();
    expect(costFragment(buildEvent())).toBeUndefined();
  });

  it('does not increment a token quota, so a budget never binds on this traffic', () => {
    init({ api_key: 'test', sample_rate: 1, policy_rules: [TOKEN_QUOTA_RULE] as never });
    // Four events at 1500 tokens each: four times the 1000-token budget.
    for (let i = 0; i < 4; i++) buildEvent();
    // Nothing recorded, so the budget still reads as fully available.
    const verdict = checkTokenBudget('user_id', 'alice', 1000, 60_000);
    expect(verdict.allowed).toBe(true);
    expect(verdict.remaining).toBe(1000);
  });
});

describe('flag on: the framework path meters exactly as the proxy path does', () => {
  it('stamps a metered cost from the counts the provider reported', () => {
    init({
      api_key: 'test',
      sample_rate: 1,
      costPolicy: COST_POLICY,
      meterIntegrationEvents: true,
    });
    const fragment = costFragment(buildEvent());
    expect(fragment).toBeDefined();
    // 1000 input @150/1k + 500 output @600/1k = 150 + 300 = 450 micros.
    expect(fragment!.metered_micros).toBe(450);
  });

  it('increments the token quota, so the budget starts binding', () => {
    init({
      api_key: 'test',
      sample_rate: 1,
      policy_rules: [TOKEN_QUOTA_RULE] as never,
      meterIntegrationEvents: true,
    });
    expect(checkTokenBudget('user_id', 'alice', 1000, 60_000).remaining).toBe(1000);
    buildEvent(); // 1500 tokens, over the 1000 budget
    const after = checkTokenBudget('user_id', 'alice', 1000, 60_000);
    expect(after.remaining).toBe(0);
    expect(after.allowed).toBe(false); // the budget now binds
  });

  it('meters nothing when neither cost policy nor quota rule is configured', () => {
    // The flag only removes the path-level block; the two halves stay
    // independently configured, so enabling it alone changes no event.
    init({ api_key: 'test', sample_rate: 1, meterIntegrationEvents: true });
    expect(costFragment(buildEvent())).toBeUndefined();
  });

  it('does not count a FAILED call against the budget', () => {
    init({
      api_key: 'test',
      sample_rate: 1,
      policy_rules: [TOKEN_QUOTA_RULE] as never,
      meterIntegrationEvents: true,
    });
    buildIntegrationEvent({
      config: getConfig(),
      provider: 'openai',
      model: 'gpt-4o-mini',
      operation: 'llm',
      source: 'langchain',
      prompt: 'x',
      response: '',
      inputTokens: 1000,
      outputTokens: 500,
      totalTokens: 1500,
      success: false,
      options: { user_id: 'alice' },
    });
    expect(checkTokenBudget('user_id', 'alice', 1000, 60_000).remaining).toBe(1000);
  });
});
