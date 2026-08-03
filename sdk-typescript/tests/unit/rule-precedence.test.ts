/**
 * Conflict-resolution precedence (twin: sdk-python/tests/test_rule_precedence.py).
 *
 * Two contracts, both pinned:
 *
 * - first_match (the default, and what an undeclared ruleset gets): rules
 *   evaluate in document order and the first rule that renders an outcome
 *   decides, so a matched topic_allow pre-empts every rule after it. List
 *   position is load-bearing, which is exactly what the tests here pin.
 * - deny_wins (the declared opt-in): every enforcing rule is evaluated and
 *   the strongest action prevails — refusal over redaction over flag over
 *   permit — with the smallest rule id (UTF-16 code-unit order) breaking
 *   ties. The verdict and the recorded rule_id are identical for every
 *   permutation of the same rule list.
 *
 * The two modes stamp different policy_version values (the declared mode is
 * committed into the hash — see rules-hash.test.ts), and deny_wins evaluation
 * carries its own engine_version marker, so the audit record alone says which
 * resolution produced a verdict.
 */
import {
  RULE_RESOLUTION_MODES,
  PolicyRule,
  derivePolicyVersion,
  ensureRuleResolution,
  evaluatePolicyRules,
} from '../../src/policy/rules';
import {
  DENY_WINS_SEMANTICS_VERSION,
  ENGINE_VERSION,
  buildDecisionInput,
  engineVersionFor,
} from '../../src/policy/decision-record';
import { _resetAllQuotas } from '../../src/governance/quota';

const TEXT = 'a billing question';

const allowRule = (): PolicyRule => ({
  id: 'r-allow',
  name: 'Allow billing topics',
  enabled: true,
  action: 'flag',
  type: 'topic_allow',
  conditions: { topics: ['billing'] },
});

const blockRule = (): PolicyRule => ({
  id: 'r-block',
  name: 'Block billing',
  enabled: true,
  action: 'block',
  type: 'keyword',
  conditions: { keywords: ['billing'] },
});

const rule = (overrides: Partial<PolicyRule>): PolicyRule => ({
  id: 'r1',
  name: 'rule',
  enabled: true,
  action: 'block',
  type: 'keyword',
  conditions: {},
  ...overrides,
});

describe('first_match pins the default behavior', () => {
  it('an allow listed first pre-empts the block', () => {
    const result = evaluatePolicyRules([allowRule(), blockRule()], TEXT);
    expect(result.decision).toBe('allow');
    expect(result.rule_id).toBe('r-allow');
  });

  it('a block listed first blocks', () => {
    const result = evaluatePolicyRules([blockRule(), allowRule()], TEXT);
    expect(result.decision).toBe('block');
    expect(result.rule_id).toBe('r-block');
  });

  it('the two orderings decide differently', () => {
    const a = evaluatePolicyRules([allowRule(), blockRule()], TEXT);
    const b = evaluatePolicyRules([blockRule(), allowRule()], TEXT);
    expect(a.decision).not.toBe(b.decision);
  });

  it('a declared first_match agrees with the undeclared default', () => {
    for (const rules of [[allowRule(), blockRule()], [blockRule(), allowRule()]]) {
      const undeclared = evaluatePolicyRules(rules, TEXT);
      const declared = evaluatePolicyRules(rules, TEXT, 'prompt', undefined, {
        resolution: 'first_match',
      });
      expect(declared).toEqual(undeclared);
    }
  });
});

describe('deny_wins resolution', () => {
  it('both orderings block identically', () => {
    const a = evaluatePolicyRules([allowRule(), blockRule()], TEXT, 'prompt', undefined, {
      resolution: 'deny_wins',
    });
    const b = evaluatePolicyRules([blockRule(), allowRule()], TEXT, 'prompt', undefined, {
      resolution: 'deny_wins',
    });
    expect(a).toEqual(b);
    expect(a.decision).toBe('block');
    expect(a.rule_id).toBe('r-block');
  });

  it('redact prevails over flag', () => {
    const flag = rule({ id: 'r-flag', action: 'flag', conditions: { keywords: ['billing'] } });
    const redact = rule({ id: 'r-redact', action: 'redact', conditions: { keywords: ['billing'] } });
    for (const rules of [[flag, redact], [redact, flag]]) {
      const result = evaluatePolicyRules(rules, TEXT, 'prompt', undefined, {
        resolution: 'deny_wins',
      });
      expect(result.decision).toBe('redact');
      expect(result.rule_id).toBe('r-redact');
    }
  });

  it('a flag prevails over a permit (nothing blocks either way)', () => {
    const flag = rule({ id: 'r-flag', action: 'flag', conditions: { keywords: ['billing'] } });
    for (const rules of [[allowRule(), flag], [flag, allowRule()]]) {
      const result = evaluatePolicyRules(rules, TEXT, 'prompt', undefined, {
        resolution: 'deny_wins',
      });
      expect(result.decision).toBe('allow');
      expect(result.rule_id).toBe('r-flag');
    }
  });

  it('ties break to the smallest rule id', () => {
    const b1 = rule({ id: 'r-block-b', conditions: { keywords: ['billing'] } });
    const b2 = rule({ id: 'r-block-a', conditions: { keywords: ['billing'] } });
    for (const rules of [[b1, b2], [b2, b1]]) {
      const result = evaluatePolicyRules(rules, TEXT, 'prompt', undefined, {
        resolution: 'deny_wins',
      });
      expect(result.decision).toBe('block');
      expect(result.rule_id).toBe('r-block-a');
    }
  });

  it('an unrecognized action on a matched rule refuses under deny_wins only', () => {
    // The parse boundary rejects unknown actions (EV-12); for a rule
    // constructed in-process, deny_wins resolves the unrankable action to
    // the strongest outcome. first_match keeps its historical shape (the
    // flag fallthrough), pinned here so the difference is deliberate.
    const odd = rule({
      id: 'r-odd',
      action: 'quarantine' as unknown as 'block',
      conditions: { keywords: ['billing'] },
    });
    expect(evaluatePolicyRules([odd], TEXT).decision).toBe('allow');
    const strict = evaluatePolicyRules([odd], TEXT, 'prompt', undefined, {
      resolution: 'deny_wins',
    });
    expect(strict.decision).toBe('block');
    expect(strict.rule_id).toBe('r-odd');
  });

  it('a quota block prevails over an earlier permit', () => {
    _resetAllQuotas();
    try {
      const quota = rule({
        id: 'r-quota',
        type: 'quota',
        conditions: { quota_limit: 1, quota_window_ms: 60_000, quota_scope: 'project' },
      });
      const rules = [allowRule(), quota];
      const first = evaluatePolicyRules(rules, TEXT, 'prompt', undefined, {
        resolution: 'deny_wins',
      });
      expect(first.decision).toBe('allow');
      const second = evaluatePolicyRules(rules, TEXT, 'prompt', undefined, {
        resolution: 'deny_wins',
      });
      expect(second.decision).toBe('block');
      expect(second.rule_id).toBe('r-quota');
    } finally {
      _resetAllQuotas();
    }
  });

  it('first_match never reaches a quota behind a permit (the pinned contrast)', () => {
    _resetAllQuotas();
    try {
      const quota = rule({
        id: 'r-quota',
        type: 'quota',
        conditions: { quota_limit: 1, quota_window_ms: 60_000, quota_scope: 'project' },
      });
      const rules = [allowRule(), quota];
      for (let i = 0; i < 3; i++) {
        expect(evaluatePolicyRules(rules, TEXT).decision).toBe('allow');
      }
    } finally {
      _resetAllQuotas();
    }
  });
});

describe('resolution validation', () => {
  it('known modes and undefined pass', () => {
    expect(ensureRuleResolution(undefined)).toBeUndefined();
    for (const mode of RULE_RESOLUTION_MODES) {
      expect(ensureRuleResolution(mode)).toBe(mode);
    }
  });

  it('an unknown resolution throws instead of evaluating', () => {
    // House posture: a typo'd mode invalidates loudly, never silently
    // evaluates under semantics the author did not choose.
    expect(() =>
      evaluatePolicyRules([blockRule()], TEXT, 'prompt', undefined, {
        resolution: 'deny-wins' as unknown as 'deny_wins',
      }),
    ).toThrow(/unknown rule resolution/);
  });
});

describe('policy_version ties to the ordering hazard', () => {
  it('orderings that decide differently stamp different versions', () => {
    const listed = [allowRule(), blockRule()];
    const reordered = [blockRule(), allowRule()];
    expect(evaluatePolicyRules(listed, TEXT).decision).not.toBe(
      evaluatePolicyRules(reordered, TEXT).decision,
    );
    expect(derivePolicyVersion(listed, 'first_match')).not.toBe(
      derivePolicyVersion(reordered, 'first_match'),
    );
  });

  it('deny_wins orderings that decide identically share a version', () => {
    const listed = [allowRule(), blockRule()];
    const reordered = [blockRule(), allowRule()];
    expect(
      evaluatePolicyRules(listed, TEXT, 'prompt', undefined, { resolution: 'deny_wins' }),
    ).toEqual(
      evaluatePolicyRules(reordered, TEXT, 'prompt', undefined, { resolution: 'deny_wins' }),
    );
    expect(derivePolicyVersion(listed, 'deny_wins')).toBe(
      derivePolicyVersion(reordered, 'deny_wins'),
    );
  });
});

describe('order insensitivity across every permutation', () => {
  const fourMatchingRules = (): PolicyRule[] => [
    allowRule(),
    rule({ id: 'r-flag', action: 'flag', conditions: { keywords: ['billing'] } }),
    blockRule(),
    rule({ id: 'r-redact', action: 'redact', conditions: { keywords: ['billing'] } }),
  ];

  const permutations = <T,>(items: T[]): T[][] => {
    if (items.length <= 1) return [items];
    return items.flatMap((item, i) =>
      permutations([...items.slice(0, i), ...items.slice(i + 1)]).map((rest) => [item, ...rest]),
    );
  };

  it('deny_wins resolves all 24 permutations identically', () => {
    const outcomes = new Set(
      permutations(fourMatchingRules()).map((perm) => {
        const result = evaluatePolicyRules(perm, TEXT, 'prompt', undefined, {
          resolution: 'deny_wins',
        });
        return `${result.decision}:${result.rule_id}`;
      }),
    );
    expect([...outcomes]).toEqual(['block:r-block']);
  });
});

describe('engine version marker', () => {
  it('deny_wins evaluation carries its own marker', () => {
    expect(ENGINE_VERSION).toBe('obsvr-rules/1');
    expect(engineVersionFor(undefined)).toBe(ENGINE_VERSION);
    expect(engineVersionFor('first_match')).toBe(ENGINE_VERSION);
    expect(engineVersionFor('deny_wins')).toBe(`obsvr-rules/${DENY_WINS_SEMANTICS_VERSION}`);
    expect(engineVersionFor('deny_wins')).not.toBe(ENGINE_VERSION);
  });

  it('the marker reaches the decision-input document', () => {
    const doc = buildDecisionInput({
      rulesHash: 'abc',
      degraded: false,
      target: 'request',
      evaluatedText: 'x',
      hook: 'not_configured',
      engineVersion: engineVersionFor('deny_wins'),
    });
    expect(doc.engine_version).toBe('obsvr-rules/2');
    const dflt = buildDecisionInput({
      rulesHash: 'abc',
      degraded: false,
      target: 'request',
      evaluatedText: 'x',
      hook: 'not_configured',
    });
    expect(dflt.engine_version).toBe('obsvr-rules/1');
  });
});
