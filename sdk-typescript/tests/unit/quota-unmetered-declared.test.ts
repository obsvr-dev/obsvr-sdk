/**
 * A quota scope the bounded store refuses is NOT enforced. Both halves matter:
 * the call's own event has to say so (otherwise it is byte-identical to a call
 * that was counted and found under limit, and an auditor replaying it reads a
 * rule that was in force and never exceeded), and whether the call proceeds is
 * the operator's failMode choice, not a silent default.
 *
 * Twin: sdk-python/tests/test_rules.py (TestUnmeteredQuotaIsDeclared).
 */
import { jest } from '@jest/globals';
import {
  evaluatePolicyRules,
  evaluateFloor,
  evaluateShadowRules,
  PolicyRule,
} from '../../src/policy/rules';
import { incrementQuota, _resetAllQuotas } from '../../src/governance/quota';
import { ReasonCode } from '../../src/governance/reason-codes';

/** Mirrors MAX_QUOTA_SCOPES in src/governance/quota.ts (not exported). */
const CAP = 10_000;

function rule(over: Partial<PolicyRule> = {}): PolicyRule {
  return {
    id: 'r1',
    name: 'test',
    enabled: true,
    action: 'block',
    type: 'quota',
    conditions: { quota_limit: 5, quota_window_ms: 60_000, quota_scope: 'user_id' },
    ...over,
  } as PolicyRule;
}

/** Fill every counter slot with live windows, so a new scope is refused. */
function saturate(): void {
  for (let i = 0; i < CAP; i++) incrementQuota('user_id', `filler${i}`, 5, 60_000);
}

const newcomer = { metadata: { user_id: 'newcomer' } };

/** Saturation logs a loud warning by design; keep it out of the test output. */
const silenceWarn = () => jest.spyOn(console, 'warn').mockImplementation(() => {});

describe('unmetered quota is declared, and resolved by failMode', () => {
  let warn: ReturnType<typeof silenceWarn>;
  beforeEach(() => {
    _resetAllQuotas();
    warn = silenceWarn();
  });
  afterEach(() => warn.mockRestore());

  it('fails open by default: allows, and declares the unmetered rule', () => {
    saturate();
    const result = evaluatePolicyRules([rule()], 'hi', 'prompt', newcomer);
    expect(result.decision).toBe('allow');
    expect(result.quota_unmetered).toEqual({
      rule_id: 'r1',
      scope: 'user_id',
      unit: 'requests',
      resolution: 'open',
    });
  });

  it('fails closed on request, with its own reason code', () => {
    saturate();
    const result = evaluatePolicyRules([rule()], 'hi', 'prompt', newcomer, {
      failMode: 'closed',
    });
    expect(result.decision).toBe('block');
    // NOT QUOTA_EXCEEDED: that asserts the limit was passed, which is not
    // known here and probably false.
    expect(result.reason_code).toBe(ReasonCode.QUOTA_UNMETERED);
    expect(result.reason_code).not.toBe(ReasonCode.QUOTA_EXCEEDED);
    expect(result.quota_unmetered?.resolution).toBe('closed');
  });

  it('declares nothing when the rule was actually metered', () => {
    const result = evaluatePolicyRules([rule()], 'hi', 'prompt', {
      metadata: { user_id: 'alice' },
    });
    expect(result.decision).toBe('allow');
    expect(result.quota_unmetered).toBeUndefined();
  });

  it('keeps the declaration when a LATER rule is what decides', () => {
    // "This call's quota rule did not run" is true of the call whatever ends
    // up deciding it.
    saturate();
    const rules = [
      rule(),
      rule({ id: 'kw', type: 'keyword', conditions: { keywords: ['badword'] } }),
    ];
    const result = evaluatePolicyRules(rules, 'this is badword', 'prompt', newcomer);
    expect(result.decision).toBe('block');
    expect(result.rule_id).toBe('kw');
    expect(result.quota_unmetered?.rule_id).toBe('r1');
  });

  it('blocks in the floor regardless of failMode', () => {
    // Floor class: a baseline that CANNOT RUN is the strongest form of
    // "cannot guarantee", so it never fails open.
    saturate();
    const result = evaluateFloor([rule()], 'hi', 'prompt', newcomer);
    expect(result.decision).toBe('block');
    expect(result.quota_unmetered?.resolution).toBe('closed');
  });

  it('never produces a would-have block from a shadow rule it could not meter', () => {
    // Shadow mode promises it cannot affect the call, and evaluateShadowRules
    // deliberately passes no failMode. Were it to leak in, the unmeterable
    // scope would surface as would: "block" here.
    saturate();
    const shadow = rule({ id: 'sh', mode: 'shadow' });
    const outcome = evaluateShadowRules([shadow], 'hi', 'prompt', newcomer);
    expect(outcome).toBeNull();
  });

  it('declares a token-unit budget it could not meter', () => {
    for (let i = 0; i < CAP; i++) {
      evaluatePolicyRules(
        [rule({ conditions: { quota_limit: 5, quota_window_ms: 60_000, quota_scope: 'user_id', quota_unit: 'tokens' } })],
        'hi',
        'prompt',
        { metadata: { user_id: `filler${i}` } },
      );
    }
    const result = evaluatePolicyRules(
      [rule({ conditions: { quota_limit: 5, quota_window_ms: 60_000, quota_scope: 'user_id', quota_unit: 'tokens' } })],
      'hi',
      'prompt',
      newcomer,
    );
    expect(result.decision).toBe('allow');
    expect(result.quota_unmetered?.unit).toBe('tokens');
  });
});
