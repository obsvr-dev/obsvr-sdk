import { evaluatePolicyRules, derivePolicyVersion, PolicyRule } from '../../src/policy/rules';

describe('evaluatePolicyRules', () => {
  it('allows when no rules match', () => {
    const rules: PolicyRule[] = [{
      id: 'r1', name: 'test', enabled: true, action: 'block',
      type: 'keyword', conditions: { keywords: ['badword'] },
    }];
    expect(evaluatePolicyRules(rules, 'hello world').decision).toBe('allow');
  });

  it('blocks on keyword match', () => {
    const rules: PolicyRule[] = [{
      id: 'r1', name: 'block-bad', enabled: true, action: 'block',
      type: 'keyword', conditions: { keywords: ['badword'] },
    }];
    const result = evaluatePolicyRules(rules, 'this is badword here');
    expect(result.decision).toBe('block');
    expect(result.rule_id).toBe('r1');
  });

  it('skips disabled rules', () => {
    const rules: PolicyRule[] = [{
      id: 'r1', name: 'disabled', enabled: false, action: 'block',
      type: 'keyword', conditions: { keywords: ['badword'] },
    }];
    expect(evaluatePolicyRules(rules, 'badword').decision).toBe('allow');
  });

  it('first match wins (redact before block)', () => {
    const rules: PolicyRule[] = [
      { id: 'r1', name: 'redact-first', enabled: true, action: 'redact', type: 'keyword', conditions: { keywords: ['info'] } },
      { id: 'r2', name: 'block-second', enabled: true, action: 'block', type: 'keyword', conditions: { keywords: ['secret'] } },
    ];
    const result = evaluatePolicyRules(rules, 'info and secret here');
    expect(result.decision).toBe('redact');
    expect(result.rule_id).toBe('r1');
  });

  it('topic_allow short-circuits to allow', () => {
    const rules: PolicyRule[] = [{
      id: 'r1', name: 'allow-science', enabled: true, action: 'flag',
      type: 'topic_allow', conditions: { topics: ['science'] },
    }];
    const result = evaluatePolicyRules(rules, 'discussing science topics');
    expect(result.decision).toBe('allow');
    expect(result.rule_id).toBe('r1');
  });

  it('regex rule matches', () => {
    const rules: PolicyRule[] = [{
      id: 'r1', name: 'regex-rule', enabled: true, action: 'block',
      type: 'regex', conditions: { pattern: '\\d{4}-\\d{4}' },
    }];
    expect(evaluatePolicyRules(rules, 'code 1234-5678').decision).toBe('block');
  });
});

describe('derivePolicyVersion', () => {
  it('returns none for empty rules', () => {
    expect(derivePolicyVersion([])).toBe('none');
  });

  it('returns consistent hash for same rules', () => {
    const rules: PolicyRule[] = [{
      id: 'r1', name: 'test', enabled: true, action: 'block',
      type: 'keyword', conditions: { keywords: ['bad'] },
    }];
    expect(derivePolicyVersion(rules)).toBe(derivePolicyVersion(rules));
  });

  it('changes hash when rules change', () => {
    const rules1: PolicyRule[] = [{ id: 'r1', name: 'a', enabled: true, action: 'block', type: 'keyword', conditions: { keywords: ['a'] } }];
    const rules2: PolicyRule[] = [{ id: 'r1', name: 'b', enabled: true, action: 'block', type: 'keyword', conditions: { keywords: ['b'] } }];
    expect(derivePolicyVersion(rules1)).not.toBe(derivePolicyVersion(rules2));
  });
});
