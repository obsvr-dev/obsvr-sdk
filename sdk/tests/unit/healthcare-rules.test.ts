import {
  evaluateNamespaceIsolation,
  isWithinNamespace,
} from '../../src/policy/industry/healthcare';
import type { PolicyRule, PolicyEvalContext } from '../../src/policy/rules';

function makeRule(): PolicyRule {
  return {
    id: 'hc-1',
    name: 'Namespace isolation',
    enabled: true,
    action: 'block',
    type: 'namespace_isolation',
    conditions: {},
  };
}

describe('Healthcare: evaluateNamespaceIsolation', () => {
  it('blocks when namespaces differ', () => {
    const ctx: PolicyEvalContext = {
      callerNamespace: 'hospital-a',
      targetNamespace: 'hospital-b',
    };
    expect(evaluateNamespaceIsolation(makeRule(), ctx)).toBe(true);
  });

  it('allows when namespaces match', () => {
    const ctx: PolicyEvalContext = {
      callerNamespace: 'hospital-a',
      targetNamespace: 'hospital-a',
    };
    expect(evaluateNamespaceIsolation(makeRule(), ctx)).toBe(false);
  });

  it('returns false when no context', () => {
    expect(evaluateNamespaceIsolation(makeRule(), undefined)).toBe(false);
  });

  // Asymmetric contexts fail CLOSED: one namespace present and the other
  // missing is exactly how an attacker nulls out a namespace to defeat
  // isolation. (A previous industry-pack copy of this evaluator returned
  // false here — allow — and these tests pinned that; the copy is gone and
  // the canonical engine evaluator is the only implementation.)
  it('blocks when caller namespace is missing (fail-closed)', () => {
    const ctx: PolicyEvalContext = { targetNamespace: 'hospital-b' };
    expect(evaluateNamespaceIsolation(makeRule(), ctx)).toBe(true);
  });

  it('blocks when target namespace is missing (fail-closed)', () => {
    const ctx: PolicyEvalContext = { callerNamespace: 'hospital-a' };
    expect(evaluateNamespaceIsolation(makeRule(), ctx)).toBe(true);
  });

  it('blocks when one namespace is an empty string (fail-closed)', () => {
    const ctx: PolicyEvalContext = { callerNamespace: '', targetNamespace: 'hospital-b' };
    expect(evaluateNamespaceIsolation(makeRule(), ctx)).toBe(true);
  });

  it('does not fire when neither namespace is set (unnamespaced call)', () => {
    expect(evaluateNamespaceIsolation(makeRule(), {})).toBe(false);
  });
});

describe('Healthcare: isWithinNamespace', () => {
  it('returns true for same namespace', () => {
    expect(isWithinNamespace('ns-1', 'ns-1')).toBe(true);
  });

  it('returns false for different namespace', () => {
    expect(isWithinNamespace('ns-1', 'ns-2')).toBe(false);
  });
});
