import { evaluate, explain } from '../../src/governance/evaluate';
import { applyPreCallPolicy } from '../../src/integrations/core';
import { engineVersionFor } from '../../src/policy/decision-record';
import { derivePolicyVersion } from '../../src/policy/rules';
import type { PolicyRule } from '../../src/policy/rules';
import { init, _reset, getConfig } from '../../src/proxy/config';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';

/**
 * The declared conflict-resolution mode, end to end. Twin:
 * sdk-python/tests/test_rule_resolution_optin.py.
 *
 * `ruleResolution: 'deny_wins'` is the opt-in: the engine evaluates
 * order-insensitively with the strongest action prevailing, the stamped
 * policy_version commits to the declared semantics, decisions carry engine
 * version obsvr-rules/2, and explain() predicts the mode in force.
 * Undeclared keeps the original first-match contract and hash bytes; an
 * unknown declaration is refused at init. Engine-level semantics are pinned
 * in rule-precedence.test.ts — this suite proves the declaration reaches
 * them.
 */

const ALLOW_FIRST: PolicyRule[] = [
  {
    id: 'allow-topic',
    name: 'allow the topic',
    enabled: true,
    action: 'flag',
    type: 'topic_allow',
    conditions: { topics: ['trigger'] },
  },
  {
    id: 'block-keyword',
    name: 'block the keyword',
    enabled: true,
    action: 'block',
    type: 'keyword',
    conditions: { keywords: ['trigger'] },
  },
];
const BLOCK_FIRST = [...ALLOW_FIRST].reverse();

beforeEach(() => {
  _reset();
  _resetSender();
  (global as any).fetch = async () => ({ ok: true, status: 200, json: async () => ({}) });
});

afterEach(() => {
  delete (global as any).fetch;
  _reset();
  _resetSender();
});

describe('declared deny_wins resolution', () => {
  it('reaches the integration pipeline in both orders', async () => {
    for (const rules of [ALLOW_FIRST, BLOCK_FIRST]) {
      _reset();
      init({ api_key: 'k', policy_rules: rules, rule_resolution: 'deny_wins' } as never);
      const result = await applyPreCallPolicy('a trigger word', {
        config: getConfig(),
        provider: 'bedrock',
        operation: 'test',
      });
      expect(result.decision).toBe('block');
      expect(result.compliance.engine_version).toBe(engineVersionFor('deny_wins'));
      expect(result.compliance.policy_version).toBe(derivePolicyVersion(rules, 'deny_wins'));
    }
  });

  it('keeps the first-match contract when undeclared', async () => {
    init({ api_key: 'k', policy_rules: ALLOW_FIRST } as never);
    const result = await applyPreCallPolicy('a trigger word', {
      config: getConfig(),
      provider: 'bedrock',
      operation: 'test',
    });
    expect(result.decision).toBe('allow');
    expect(result.compliance.engine_version).toBe(engineVersionFor(undefined));
    expect(result.compliance.policy_version).toBe(derivePolicyVersion(ALLOW_FIRST));
  });

  it('reaches the governance evaluate() surface', async () => {
    init({ api_key: 'k', policy_rules: ALLOW_FIRST, rule_resolution: 'deny_wins' } as never);
    const refused = await evaluate({ action_type: 'test', payload: { data: 'a trigger word' } });
    expect(refused.decision).toBe('BLOCKED');
    expect(refused.rule_id).toBe('block-keyword');
  });

  it('explain() predicts the declared mode', () => {
    init({ api_key: 'k', policy_rules: ALLOW_FIRST, rule_resolution: 'deny_wins' } as never);
    const prediction = explain('a trigger word');
    expect(prediction.decision).toBe('block');
    expect(prediction.rule_id).toBe('block-keyword');
  });

  it('refuses an unknown declaration at init', () => {
    expect(() => init({ api_key: 'k', rule_resolution: 'deny-wins' } as never)).toThrow(
      /rule resolution/i,
    );
  });
});
