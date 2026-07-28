import { evaluatePolicyRules } from '../../src/policy/rules';
import type { PolicyRule, PolicyEvalContext } from '../../src/policy/rules';

describe('evaluatePolicyRules: backward compatibility', () => {
  const keywordRule: PolicyRule = {
    id: 'kw-1',
    name: 'Block bad words',
    enabled: true,
    action: 'block',
    type: 'keyword',
    conditions: { keywords: ['secret', 'password'] },
  };

  it('still blocks keyword matches without context', () => {
    const result = evaluatePolicyRules([keywordRule], 'my secret key');
    expect(result.decision).toBe('block');
    expect(result.rule_id).toBe('kw-1');
  });

  it('still allows non-matching text without context', () => {
    const result = evaluatePolicyRules([keywordRule], 'hello world');
    expect(result.decision).toBe('allow');
  });

  it('keyword rule ignores context (works the same with or without)', () => {
    const ctx: PolicyEvalContext = { actionName: 'test', amount: 100 };
    const result = evaluatePolicyRules([keywordRule], 'my secret key', 'prompt', ctx);
    expect(result.decision).toBe('block');
  });
});

describe('evaluatePolicyRules: action_gate', () => {
  const actionGateRule: PolicyRule = {
    id: 'ag-1',
    name: 'Block large transfers',
    enabled: true,
    action: 'block',
    type: 'action_gate',
    conditions: {
      action_types: ['wire_transfer'],
      threshold: { field: 'amount', operator: '>', value: 10000 },
    },
  };

  it('blocks when action and threshold match', () => {
    const ctx: PolicyEvalContext = { actionName: 'wire_transfer', amount: 50000 };
    const result = evaluatePolicyRules([actionGateRule], '', 'prompt', ctx);
    expect(result.decision).toBe('block');
    expect(result.rule_id).toBe('ag-1');
  });

  it('allows when amount is below threshold', () => {
    const ctx: PolicyEvalContext = { actionName: 'wire_transfer', amount: 5000 };
    const result = evaluatePolicyRules([actionGateRule], '', 'prompt', ctx);
    expect(result.decision).toBe('allow');
  });

  it('allows when action type does not match', () => {
    const ctx: PolicyEvalContext = { actionName: 'balance_check', amount: 50000 };
    const result = evaluatePolicyRules([actionGateRule], '', 'prompt', ctx);
    expect(result.decision).toBe('allow');
  });
});

describe('evaluatePolicyRules: namespace_isolation', () => {
  const nsRule: PolicyRule = {
    id: 'ns-1',
    name: 'Namespace isolation',
    enabled: true,
    action: 'block',
    type: 'namespace_isolation',
    conditions: {},
  };

  it('blocks when namespaces differ', () => {
    const ctx: PolicyEvalContext = {
      callerNamespace: 'tenant-a',
      targetNamespace: 'tenant-b',
    };
    const result = evaluatePolicyRules([nsRule], '', 'prompt', ctx);
    expect(result.decision).toBe('block');
  });

  it('allows when namespaces match', () => {
    const ctx: PolicyEvalContext = {
      callerNamespace: 'tenant-a',
      targetNamespace: 'tenant-a',
    };
    const result = evaluatePolicyRules([nsRule], '', 'prompt', ctx);
    expect(result.decision).toBe('allow');
  });

  it('allows when no context (backward compat)', () => {
    const result = evaluatePolicyRules([nsRule], 'some text');
    expect(result.decision).toBe('allow');
  });
});

describe('evaluatePolicyRules: cross_tenant_block', () => {
  const ctRule: PolicyRule = {
    id: 'ct-1',
    name: 'Cross-tenant block',
    enabled: true,
    action: 'block',
    type: 'cross_tenant_block',
    conditions: {},
  };

  it('blocks cross-tenant access', () => {
    const ctx: PolicyEvalContext = {
      callerNamespace: 'org-1',
      targetNamespace: 'org-2',
    };
    const result = evaluatePolicyRules([ctRule], '', 'prompt', ctx);
    expect(result.decision).toBe('block');
  });
});

describe('evaluatePolicyRules: destructive_op_gate', () => {
  const destRule: PolicyRule = {
    id: 'dest-1',
    name: 'Destructive op gate',
    enabled: true,
    action: 'block',
    type: 'destructive_op_gate',
    conditions: { destructive_operations: ['DROP TABLE', 'rm -rf'] },
  };

  it('blocks destructive operations in text', () => {
    const result = evaluatePolicyRules([destRule], 'please DROP TABLE users', 'prompt');
    expect(result.decision).toBe('block');
  });

  it('allows safe operations', () => {
    const result = evaluatePolicyRules([destRule], 'SELECT * FROM users', 'prompt');
    expect(result.decision).toBe('allow');
  });
});

describe('evaluatePolicyRules: source_grounding', () => {
  const sgRule: PolicyRule = {
    id: 'sg-1',
    name: 'Source grounding check',
    enabled: true,
    action: 'flag',
    type: 'source_grounding',
    conditions: { min_grounding_ratio: 0.7 },
  };

  it('flags poorly grounded output', () => {
    const ctx: PolicyEvalContext = {
      sourceDocuments: ['Contract terms and conditions apply.'],
    };
    const result = evaluatePolicyRules(
      [sgRule],
      'Quantum mechanics explains entanglement phenomena.',
      'response',
      ctx,
    );
    // flag action = allow with rule_id
    expect(result.rule_id).toBe('sg-1');
  });
});

describe('evaluatePolicyRules: environment_gate', () => {
  const envRule: PolicyRule = {
    id: 'env-1',
    name: 'Production gate',
    enabled: true,
    action: 'block',
    type: 'environment_gate',
    conditions: { target_environments: ['production'] },
  };

  it('blocks in production environment', () => {
    const ctx: PolicyEvalContext = { currentEnvironment: 'production' };
    const result = evaluatePolicyRules([envRule], '', 'prompt', ctx);
    expect(result.decision).toBe('block');
  });

  it('allows in development environment', () => {
    const ctx: PolicyEvalContext = { currentEnvironment: 'development' };
    const result = evaluatePolicyRules([envRule], '', 'prompt', ctx);
    expect(result.decision).toBe('allow');
  });

  it('allows when no context', () => {
    const result = evaluatePolicyRules([envRule], '');
    expect(result.decision).toBe('allow');
  });
});

describe('evaluatePolicyRules: mixed rules (old + new)', () => {
  const rules: PolicyRule[] = [
    {
      id: 'kw-1',
      name: 'Block secrets',
      enabled: true,
      action: 'block',
      type: 'keyword',
      conditions: { keywords: ['secret'] },
    },
    {
      id: 'env-1',
      name: 'Prod gate',
      enabled: true,
      action: 'block',
      type: 'environment_gate',
      conditions: { target_environments: ['production'] },
    },
  ];

  it('keyword rule fires first on keyword match', () => {
    const ctx: PolicyEvalContext = { currentEnvironment: 'development' };
    const result = evaluatePolicyRules(rules, 'my secret', 'prompt', ctx);
    expect(result.rule_id).toBe('kw-1');
    expect(result.decision).toBe('block');
  });

  it('env gate fires when no keyword match but in production', () => {
    const ctx: PolicyEvalContext = { currentEnvironment: 'production' };
    const result = evaluatePolicyRules(rules, 'hello world', 'prompt', ctx);
    expect(result.rule_id).toBe('env-1');
    expect(result.decision).toBe('block');
  });

  it('allows when neither matches', () => {
    const ctx: PolicyEvalContext = { currentEnvironment: 'development' };
    const result = evaluatePolicyRules(rules, 'hello world', 'prompt', ctx);
    expect(result.decision).toBe('allow');
  });
});
