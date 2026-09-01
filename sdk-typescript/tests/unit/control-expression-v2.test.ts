import {
  ControlExpressionValidationError,
  evaluateControlExpressionV2,
  validateControlExpressionV2,
} from '../../src/governance/control-expression-v2';
import { evaluatePolicyRules, type PolicyRule } from '../../src/policy/rules';

const expression = {
  all: [
    { predicate: { path: 'context.environment', operator: 'equals', value: 'production' } },
    { any: [
      { predicate: { path: 'context.metadata.role', operator: 'not_equals', value: 'admin' } },
      { predicate: { path: 'context.amount', operator: 'greater_than', value: 1000 } },
    ] },
  ],
} as const;

describe('control expression v2', () => {
  it('matches the shared cross-language fixture', () => {
    const fixture = JSON.parse(readFileSync(
      new URL('../../../conformance/fixtures/control_expression_v2.json', import.meta.url),
      'utf8',
    )) as { cases: Array<{ expression: unknown; input: Parameters<typeof evaluateControlExpressionV2>[1]; matches: boolean }> };
    for (const item of fixture.cases) {
      expect(evaluateControlExpressionV2(item.expression, item.input)).toBe(item.matches);
    }
  });

  it('evaluates bounded nested expressions deterministically', () => {
    expect(evaluateControlExpressionV2(expression, {
      input: { text: 'wire funds', target: 'prompt' },
      context: { environment: 'production', amount: 10, metadata: { role: 'member' } },
    })).toBe(true);
    expect(evaluateControlExpressionV2(expression, {
      input: { text: 'wire funds', target: 'prompt' },
      context: { environment: 'staging', amount: 5000, metadata: { role: 'member' } },
    })).toBe(false);
  });

  it('refuses ambiguous and unsafe documents', () => {
    expect(() => validateControlExpressionV2({ all: [], any: [] })).toThrow(ControlExpressionValidationError);
    expect(() => validateControlExpressionV2({ predicate: {
      path: 'context.metadata.value', operator: 'matches', value: '(a+)+$',
    } })).toThrow(/ReDoS/);
    expect(() => validateControlExpressionV2({ predicate: {
      path: 'context.métadata', operator: 'equals', value: 'x',
    } })).toThrow(/bounded input\/context path/);
    expect(() => validateControlExpressionV2({ predicate: {
      path: 'context.amount', operator: 'greater_than', value: '100',
    } })).toThrow(/must be a number/);
    expect(() => validateControlExpressionV2({ predicate: {
      path: 'context.label', operator: 'contains', value: 100,
    } })).toThrow(/must be a string/);
  });

  it('maps steer to a real pre-call refusal with corrective context', () => {
    const rule: PolicyRule = {
      id: 'control:external-write',
      name: 'External writes need an owner',
      enabled: true,
      type: 'control',
      action: 'steer',
      conditions: {
        expression: { predicate: { path: 'context.metadata.owner', operator: 'not_equals', value: 'legal' } },
        steering_context: 'Route the draft to Legal and retry with metadata.owner="legal".',
      },
    };
    const result = evaluatePolicyRules([rule], 'send contract', 'prompt', {
      metadata: { owner: 'sales' },
    });
    expect(result.decision).toBe('block');
    expect(result.steering).toEqual({
      outcome: 'MODIFY',
      guidance: 'Route the draft to Legal and retry with metadata.owner="legal".',
    });
  });
});
import { readFileSync } from 'node:fs';
