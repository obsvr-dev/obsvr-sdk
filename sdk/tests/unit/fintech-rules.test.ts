import {
  evaluateActionGate,
  resolveThresholdField,
  compareThreshold,
  classifyFintechRisk,
} from '../../src/policy/industry/fintech';
import type { PolicyRule, PolicyEvalContext } from '../../src/policy/rules';

function makeRule(overrides: Partial<PolicyRule['conditions']> = {}): PolicyRule {
  return {
    id: 'fintech-1',
    name: 'FinTech gate',
    enabled: true,
    action: 'block',
    type: 'action_gate',
    conditions: { ...overrides },
  };
}

describe('FinTech: evaluateActionGate', () => {
  it('matches action types in context', () => {
    const rule = makeRule({ action_types: ['wire_transfer'] });
    const ctx: PolicyEvalContext = { actionName: 'wire_transfer' };
    expect(evaluateActionGate(rule, '', ctx)).toBe(true);
  });

  it('does not match when action type differs', () => {
    const rule = makeRule({ action_types: ['wire_transfer'] });
    const ctx: PolicyEvalContext = { actionName: 'balance_check' };
    expect(evaluateActionGate(rule, '', ctx)).toBe(false);
  });

  it('falls back to text when no context actionName', () => {
    const rule = makeRule({ action_types: ['wire_transfer'] });
    expect(evaluateActionGate(rule, 'execute wire_transfer', undefined)).toBe(true);
  });

  it('enforces threshold > operator', () => {
    const rule = makeRule({
      action_types: ['transfer'],
      threshold: { field: 'amount', operator: '>', value: 10000 },
    });
    const ctx: PolicyEvalContext = { actionName: 'transfer', amount: 50000 };
    expect(evaluateActionGate(rule, '', ctx)).toBe(true);
  });

  it('does not fire threshold when below', () => {
    const rule = makeRule({
      action_types: ['transfer'],
      threshold: { field: 'amount', operator: '>', value: 10000 },
    });
    const ctx: PolicyEvalContext = { actionName: 'transfer', amount: 5000 };
    expect(evaluateActionGate(rule, '', ctx)).toBe(false);
  });

  it('threshold reads metadata fields', () => {
    const rule = makeRule({
      threshold: { field: 'risk_score', operator: '>=', value: 0.8 },
    });
    const ctx: PolicyEvalContext = { metadata: { risk_score: 0.9 } };
    expect(evaluateActionGate(rule, '', ctx)).toBe(true);
  });

  it('returns false when threshold field is missing', () => {
    const rule = makeRule({
      threshold: { field: 'amount', operator: '>', value: 100 },
    });
    expect(evaluateActionGate(rule, '', undefined)).toBe(false);
  });
});

describe('FinTech: compareThreshold', () => {
  it.each([
    [10, '>' as const, 5, true],
    [5, '>' as const, 10, false],
    [10, '<' as const, 20, true],
    [10, '>=' as const, 10, true],
    [10, '<=' as const, 10, true],
    [10, '==' as const, 10, true],
    [10, '==' as const, 11, false],
  ])('compareThreshold(%d, %s, %d) = %s', (a: number, op: '>' | '<' | '>=' | '<=' | '==', b: number, expected: boolean) => {
    expect(compareThreshold(a, op, b)).toBe(expected);
  });
});

describe('FinTech: resolveThresholdField', () => {
  it('resolves "amount" field', () => {
    expect(resolveThresholdField('amount', { amount: 500 })).toBe(500);
  });

  it('resolves metadata field', () => {
    expect(resolveThresholdField('risk', { metadata: { risk: 0.7 } })).toBe(0.7);
  });

  it('returns undefined for missing context', () => {
    expect(resolveThresholdField('amount', undefined)).toBeUndefined();
  });
});

describe('FinTech: classifyFintechRisk', () => {
  it('classifies critical for large wire transfer', () => {
    expect(classifyFintechRisk('wire_transfer', 100000)).toBe('critical');
  });

  it('classifies low for small balance check', () => {
    expect(classifyFintechRisk('balance_check', 50)).toBe('low');
  });

  it('classifies medium for high-risk action without amount', () => {
    expect(classifyFintechRisk('wire_transfer')).toBe('medium');
  });
});
