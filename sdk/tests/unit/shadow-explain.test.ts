import {
  evaluatePolicyRules,
  evaluateShadowRules,
  derivePolicyVersion,
  PolicyRule,
} from '../../src/policy/rules';
import { checkQuota, _resetAllQuotas } from '../../src/governance/quota';

/**
 * Shadow mode (EV-20/21) and check-only evaluation
 * (EV-22): shadow rules never affect active decisions (byte-identical
 * results), record would-have outcomes, and consume no quota.
 */

const blockRule: PolicyRule = {
  id: 'r-active',
  name: 'Active block',
  enabled: true,
  action: 'block',
  type: 'keyword',
  conditions: { keywords: ['forbidden'] },
};

const shadowRule: PolicyRule = {
  id: 'r-shadow',
  name: 'Shadow block candidate',
  enabled: true,
  mode: 'shadow',
  action: 'block',
  type: 'keyword',
  conditions: { keywords: ['candidate'] },
};

describe('EV-20: shadow rules are inert in active evaluation', () => {
  it('active decision is byte-identical with and without shadow rules', () => {
    const inputs = [
      'a perfectly fine prompt',
      'this mentions candidate territory',
      'this is forbidden content',
      'both forbidden and candidate',
    ];
    for (const text of inputs) {
      const withoutShadow = evaluatePolicyRules([blockRule], text, 'prompt');
      const withShadow = evaluatePolicyRules([blockRule, shadowRule], text, 'prompt');
      expect(JSON.stringify(withShadow)).toBe(JSON.stringify(withoutShadow));
    }
  });

  it('a shadow-only rule set never blocks', () => {
    const result = evaluatePolicyRules([shadowRule], 'candidate text', 'prompt');
    expect(result.decision).toBe('allow');
    expect(result.rule_id).toBeUndefined();
  });
});

describe('EV-21: shadow outcomes are recorded', () => {
  it('reports would-block with rule id and reason', () => {
    const outcome = evaluateShadowRules([blockRule, shadowRule], 'candidate text', 'prompt');
    expect(outcome).toEqual({
      rule_id: 'r-shadow',
      would: 'block',
      reason_code: 'SHADOW_WOULD_BLOCK',
      reason: 'Shadow block candidate',
    });
  });

  it('returns null when no shadow rule matches', () => {
    expect(evaluateShadowRules([blockRule, shadowRule], 'harmless', 'prompt')).toBeNull();
  });

  it('returns null when there are no shadow rules', () => {
    expect(evaluateShadowRules([blockRule], 'candidate text', 'prompt')).toBeNull();
  });
});

describe('EV-16: shadow flag is part of the canonical hash', () => {
  it('flipping a rule to shadow changes the rules hash', () => {
    const enforcing: PolicyRule = { ...shadowRule, mode: 'enforce' };
    expect(derivePolicyVersion([shadowRule])).not.toBe(derivePolicyVersion([enforcing]));
  });

  it('mode "enforce" hashes identically to mode omitted (back-compat)', () => {
    const withMode: PolicyRule = { ...blockRule, mode: 'enforce' };
    expect(derivePolicyVersion([withMode])).toBe(derivePolicyVersion([blockRule]));
  });
});

describe('EV-22: check-only evaluation consumes no quota', () => {
  const quotaRule: PolicyRule = {
    id: 'r-quota',
    name: 'Two per user',
    enabled: true,
    action: 'block',
    type: 'quota',
    conditions: { quota_limit: 2, quota_window_ms: 60_000, quota_scope: 'user_id' },
  };

  beforeEach(() => _resetAllQuotas());

  it('checkOnly runs do not decrement the quota window', () => {
    const ctx = { metadata: { user_id: 'u1' } } as never;
    for (let i = 0; i < 5; i++) {
      const r = evaluatePolicyRules([quotaRule], 'hi', 'prompt', ctx, { checkOnly: true });
      expect(r.decision).toBe('allow');
    }
    // The real quota is untouched: both slots still available.
    expect(checkQuota('user_id', 'u1', 2, 60_000).remaining).toBe(2);
  });

  it('shadow quota rules do not consume the active quota', () => {
    const shadowQuota: PolicyRule = { ...quotaRule, id: 'r-shadow-quota', mode: 'shadow' };
    const ctx = { metadata: { user_id: 'u2' } } as never;
    for (let i = 0; i < 5; i++) {
      evaluateShadowRules([shadowQuota], 'hi', 'prompt', ctx);
    }
    expect(checkQuota('user_id', 'u2', 2, 60_000).remaining).toBe(2);
  });
});
