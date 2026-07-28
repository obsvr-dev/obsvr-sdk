import {
  evaluateCrossTenantBlock,
  evaluateDestructiveOpGate,
  isDestructiveOperation,
  detectCrossTenantAccess,
  DEFAULT_DESTRUCTIVE_OPS,
} from '../../src/policy/industry/saas';
import type { PolicyRule, PolicyEvalContext } from '../../src/policy/rules';

function makeRule(overrides: Partial<PolicyRule['conditions']> = {}): PolicyRule {
  return {
    id: 'saas-1',
    name: 'SaaS gate',
    enabled: true,
    action: 'block',
    type: 'cross_tenant_block',
    conditions: { ...overrides },
  };
}

describe('SaaS: evaluateCrossTenantBlock', () => {
  it('blocks when namespaces differ', () => {
    const ctx: PolicyEvalContext = {
      callerNamespace: 'tenant-a',
      targetNamespace: 'tenant-b',
    };
    expect(evaluateCrossTenantBlock(makeRule(), ctx)).toBe(true);
  });

  it('allows when namespaces match', () => {
    const ctx: PolicyEvalContext = {
      callerNamespace: 'tenant-a',
      targetNamespace: 'tenant-a',
    };
    expect(evaluateCrossTenantBlock(makeRule(), ctx)).toBe(false);
  });

  it('returns false when no context', () => {
    expect(evaluateCrossTenantBlock(makeRule())).toBe(false);
  });

  // Asymmetric contexts fail CLOSED (see healthcare-rules.test.ts): nulling
  // one side of the tenant pair must read as a cross-tenant access, not slip
  // through as "not applicable".
  it('blocks when caller namespace is missing (fail-closed)', () => {
    const ctx: PolicyEvalContext = { targetNamespace: 'tenant-b' };
    expect(evaluateCrossTenantBlock(makeRule(), ctx)).toBe(true);
  });

  it('blocks when target namespace is missing (fail-closed)', () => {
    const ctx: PolicyEvalContext = { callerNamespace: 'tenant-a' };
    expect(evaluateCrossTenantBlock(makeRule(), ctx)).toBe(true);
  });

  it('does not fire when neither namespace is set (unnamespaced call)', () => {
    expect(evaluateCrossTenantBlock(makeRule(), {})).toBe(false);
  });
});

describe('SaaS: evaluateDestructiveOpGate', () => {
  it('detects destructive operation in text', () => {
    const rule = makeRule({ destructive_operations: ['DROP TABLE', 'DELETE ALL'] });
    rule.type = 'destructive_op_gate';
    expect(evaluateDestructiveOpGate(rule, 'please DROP TABLE users')).toBe(true);
  });

  it('detects destructive operation in context actionName', () => {
    const rule = makeRule({ destructive_operations: ['purge'] });
    rule.type = 'destructive_op_gate';
    const ctx: PolicyEvalContext = { actionName: 'purge_records' };
    expect(evaluateDestructiveOpGate(rule, '', ctx)).toBe(true);
  });

  it('does not fire for safe operations', () => {
    const rule = makeRule({ destructive_operations: ['DROP TABLE'] });
    rule.type = 'destructive_op_gate';
    expect(evaluateDestructiveOpGate(rule, 'SELECT * FROM users')).toBe(false);
  });

  it('returns false when no destructive_operations configured', () => {
    const rule = makeRule({});
    rule.type = 'destructive_op_gate';
    expect(evaluateDestructiveOpGate(rule, 'DROP TABLE')).toBe(false);
  });
});

describe('SaaS: isDestructiveOperation', () => {
  it('detects default destructive ops', () => {
    expect(isDestructiveOperation('please destroy the database')).toBe(true);
  });

  it('allows safe operations', () => {
    expect(isDestructiveOperation('read user profile')).toBe(false);
  });

  it('uses custom ops list', () => {
    expect(isDestructiveOperation('nuke it', ['nuke'])).toBe(true);
  });
});

describe('SaaS: detectCrossTenantAccess', () => {
  it('detects cross-tenant access', () => {
    const result = detectCrossTenantAccess('tenant-a', 'tenant-b');
    expect(result.isCrossTenant).toBe(true);
    expect(result.callerTenant).toBe('tenant-a');
    expect(result.targetTenant).toBe('tenant-b');
  });

  it('allows same-tenant access', () => {
    const result = detectCrossTenantAccess('tenant-a', 'tenant-a');
    expect(result.isCrossTenant).toBe(false);
  });
});

describe('SaaS: DEFAULT_DESTRUCTIVE_OPS', () => {
  it('contains expected operations', () => {
    expect(DEFAULT_DESTRUCTIVE_OPS).toContain('drop table');
    expect(DEFAULT_DESTRUCTIVE_OPS).toContain('truncate');
    expect(DEFAULT_DESTRUCTIVE_OPS).toContain('destroy');
  });
});
