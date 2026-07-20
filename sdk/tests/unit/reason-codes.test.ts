import * as fs from 'fs';
import * as path from 'path';
import {
  ReasonCode,
  REASON_CODES,
  RULE_TYPE_TO_REASON_CODE,
  ruleTypeToReasonCode,
} from '../../src/governance/reason-codes';
import {
  evaluatePolicyRules,
  evaluateShadowRules,
  PolicyRule,
} from '../../src/policy/rules';
import { VALID_RULE_TYPES } from '../../src/proxy/config';

/**
 * Reserved-reason-registry staleness check (TS side). Twin:
 * sdk-python/tests/test_reason_codes.py. Mirrors the repo's shared-fixture
 * contract-test pattern: the closed reason-code registry is pinned in
 * conformance/fixtures/reason_codes.json, and this suite fails if
 *  - the TS registry drifts from the fixture (which also guarantees TS/Python
 *    parity, since the Python twin pins to the same fixture),
 *  - a PolicyRule type gains no explicit reason-code mapping, or
 *  - the rules engine can emit a reason_code outside the registry.
 */

function findFixture(rel: string): string {
  let dir = process.cwd();
  for (let i = 0; i < 6; i++) {
    const candidate = path.join(dir, rel);
    if (fs.existsSync(candidate)) return candidate;
    dir = path.dirname(dir);
  }
  throw new Error(`fixture not found upward from ${process.cwd()}: ${rel}`);
}

const fixture = JSON.parse(
  fs.readFileSync(findFixture('conformance/fixtures/reason_codes.json'), 'utf-8'),
) as { codes: string[]; rule_type_to_reason_code: Record<string, string> };

const registrySet = new Set<string>(REASON_CODES);

describe('reason-code registry: fixture parity', () => {
  it('the enum, REASON_CODES, and the fixture are the identical sorted set', () => {
    const enumValues = (Object.values(ReasonCode) as string[]).slice().sort();
    expect(REASON_CODES.slice()).toEqual(enumValues);
    // Fixture is the cross-language pin; equality here + in the Python twin
    // guarantees TS and Python never diverge.
    expect(REASON_CODES.slice()).toEqual(fixture.codes.slice().sort());
    expect(fixture.codes.slice().sort()).toEqual(fixture.codes);
  });

  it('the rule-type -> reason-code mapping matches the fixture exactly', () => {
    expect(RULE_TYPE_TO_REASON_CODE).toEqual(fixture.rule_type_to_reason_code);
  });
});

describe('reason-code registry: coverage of every enforceable rule type', () => {
  it('every VALID_RULE_TYPES entry has an explicit, in-registry mapping (never UNKNOWN_BLOCKED)', () => {
    for (const type of VALID_RULE_TYPES) {
      const code = ruleTypeToReasonCode(type);
      expect(code).not.toBe(ReasonCode.UNKNOWN_BLOCKED);
      expect(registrySet.has(code)).toBe(true);
      expect(fixture.rule_type_to_reason_code[type]).toBe(code);
    }
  });

  it('the fixture mapping covers exactly the enforceable rule types', () => {
    expect(Object.keys(fixture.rule_type_to_reason_code).sort()).toEqual(
      Array.from(VALID_RULE_TYPES).sort(),
    );
  });
});

describe('reason-code registry: the engine only emits registry codes', () => {
  // A matrix that fires each verdict path. Every emitted reason_code must be
  // defined and drawn from the registry; a new engine path emitting an
  // unregistered code fails here.
  const cases: Array<{ label: string; rules: PolicyRule[]; text: string; target?: 'prompt' | 'response'; context?: unknown }> = [
    { label: 'no match -> permitted', rules: [], text: 'hello' },
    { label: 'keyword block', rules: [{ id: 'k', name: 'k', enabled: true, action: 'block', type: 'keyword', conditions: { keywords: ['trigger'] } }], text: 'a trigger word' },
    { label: 'regex redact', rules: [{ id: 'r', name: 'r', enabled: true, action: 'redact', type: 'regex', conditions: { pattern: 'trig+er' } }], text: 'trigger' },
    { label: 'keyword flag', rules: [{ id: 'f', name: 'f', enabled: true, action: 'flag', type: 'keyword', conditions: { keywords: ['trigger'] } }], text: 'trigger' },
    { label: 'topic_deny block', rules: [{ id: 'td', name: 'td', enabled: true, action: 'block', type: 'topic_deny', conditions: { topics: ['trigger'] } }], text: 'trigger' },
    { label: 'topic_allow allow', rules: [{ id: 'ta', name: 'ta', enabled: true, action: 'flag', type: 'topic_allow', conditions: { topics: ['trigger'] } }], text: 'trigger' },
    { label: 'action_gate block', rules: [{ id: 'ag', name: 'ag', enabled: true, action: 'block', type: 'action_gate', conditions: { action_types: ['wire'] } }], text: 'wire', context: { actionName: 'wire' } },
    { label: 'namespace_isolation block', rules: [{ id: 'ns', name: 'ns', enabled: true, action: 'block', type: 'namespace_isolation', conditions: {} }], text: 'x', context: { callerNamespace: 'a', targetNamespace: 'b' } },
    { label: 'cross_tenant_block block', rules: [{ id: 'ct', name: 'ct', enabled: true, action: 'block', type: 'cross_tenant_block', conditions: {} }], text: 'x', context: { callerNamespace: 'a', targetNamespace: 'b' } },
    { label: 'destructive_op_gate block', rules: [{ id: 'do', name: 'do', enabled: true, action: 'block', type: 'destructive_op_gate', conditions: { destructive_operations: ['drop table'] } }], text: 'drop table users' },
    { label: 'source_grounding flag', rules: [{ id: 'sg', name: 'sg', enabled: true, action: 'flag', type: 'source_grounding', conditions: { min_grounding_ratio: 0.9 } }], text: 'ungrounded claim about the moon' },
    { label: 'environment_gate block', rules: [{ id: 'eg', name: 'eg', enabled: true, action: 'block', type: 'environment_gate', conditions: { target_environments: ['prod'] } }], text: 'x', context: { currentEnvironment: 'prod' } },
    { label: 'model_gate block', rules: [{ id: 'mg', name: 'mg', enabled: true, action: 'block', type: 'model_gate', conditions: { denied_models: ['gpt-4'] } }], text: 'x', context: { model: 'gpt-4' } },
    { label: 'approval_required block', rules: [{ id: 'ap', name: 'ap', enabled: true, action: 'block', type: 'keyword', conditions: { keywords: ['trigger'], require_approval: true } }], text: 'trigger' },
  ];

  for (const c of cases) {
    it(`${c.label} emits a registry reason_code`, () => {
      const result = evaluatePolicyRules(c.rules, c.text, c.target ?? 'prompt', c.context as never);
      expect(result.reason_code).toBeDefined();
      expect(registrySet.has(result.reason_code as string)).toBe(true);
    });
  }

  it('quota exhaustion emits QUOTA_EXCEEDED (in registry)', () => {
    const quotaRule: PolicyRule = {
      id: 'q', name: 'q', enabled: true, action: 'block', type: 'quota',
      conditions: { quota_limit: 1, quota_window_ms: 60000, quota_scope: 'project' },
    };
    evaluatePolicyRules([quotaRule], 'x'); // consume the single unit
    const blocked = evaluatePolicyRules([quotaRule], 'x');
    expect(blocked.decision).toBe('block');
    expect(blocked.reason_code).toBe(ReasonCode.QUOTA_EXCEEDED);
    expect(registrySet.has(blocked.reason_code as string)).toBe(true);
  });

  it('shadow outcomes emit SHADOW_WOULD_BLOCK (in registry)', () => {
    const shadow = evaluateShadowRules(
      [{ id: 's', name: 's', enabled: true, mode: 'shadow', action: 'block', type: 'keyword', conditions: { keywords: ['trigger'] } }],
      'trigger',
      'prompt',
    );
    expect(shadow?.reason_code).toBe(ReasonCode.SHADOW_WOULD_BLOCK);
    expect(registrySet.has(shadow?.reason_code as string)).toBe(true);
  });
});
