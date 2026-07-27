import * as fs from 'fs';
import * as path from 'path';
import {
  evaluatePolicyRules,
  evaluateShadowRules,
  PolicyRule,
} from '../../src/policy/rules';
import { isValidPolicyRule, init, _reset, getConfig, _getPolicySyncState } from '../../src/proxy/config';
import { applyPreCallPolicy } from '../../src/integrations/core';
import { explain } from '../../src/governance/evaluate';
import { _resetAllQuotas } from '../../src/governance/quota';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';

/**
 * Cross-SDK conformance harness (TS side). Twin:
 * sdk-python/tests/test_conformance.py. Runs every case in
 * conformance/fixtures/eval_semantics.json through validator +
 * evaluator + shadow evaluator. A divergence from the fixture (or from
 * the Python harness) is a release blocker unless recorded in
 * conformance/known-divergences.md.
 *
 * Three case modes:
 *   rules     (default) drive the rules engine directly
 *   pipeline  drive the full pre-call pipeline - the only way to pin
 *             statements about step composition and the integrity gate
 *   explain   drive check-only evaluation and prove it consumes nothing
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

interface FixtureCase {
  id: string;
  ev: string;
  mode?: 'rules' | 'pipeline' | 'explain';
  desc?: string;
  rules: unknown[];
  input: { text: string; target?: 'prompt' | 'response'; context?: Record<string, unknown> };
  expect?: { decision: string; rule_id?: string | null; approval_required?: boolean };
  expect_shadow?: { rule_id: string; would: string } | null;
  expect_valid_rule_ids?: string[];
  pipeline?: {
    degraded_reason?: string;
    hook?: 'allow' | 'block';
    pii_policy?: Record<string, unknown>;
  };
  expect_pipeline?: {
    decision: string;
    action_reason?: string;
    action_source?: string;
    rule_id?: string | null;
    hook_ran?: boolean;
  };
  explain_runs?: number;
  expect_first_real_call?: { decision: string; rule_id?: string | null };
  expect_second_real_call?: { decision: string; rule_id?: string | null };
}

const fixture = JSON.parse(
  fs.readFileSync(findFixture('conformance/fixtures/eval_semantics.json'), 'utf-8'),
) as { cases: FixtureCase[] };

function validRulesOf(c: FixtureCase): PolicyRule[] {
  return c.rules.filter(isValidPolicyRule) as PolicyRule[];
}

describe('conformance: eval_semantics fixtures', () => {
  afterEach(() => {
    _getPolicySyncState().remoteDisabled = false;
    _reset();
    _resetSender();
    _resetAllQuotas();
  });

  for (const c of fixture.cases) {
    const mode = c.mode ?? 'rules';

    if (mode === 'rules') {
      it(`${c.id} (${c.ev})`, () => {
        // 1. Validator pass (EV-12): malformed rules are dropped.
        const validRules = validRulesOf(c);
        if (c.expect_valid_rule_ids) {
          expect(validRules.map((r) => r.id)).toEqual(c.expect_valid_rule_ids);
        }

        // 2. Active evaluation.
        const target = c.input.target ?? 'prompt';
        const result = evaluatePolicyRules(
          validRules,
          c.input.text,
          target,
          c.input.context as never,
        );
        expect(result.decision).toBe(c.expect!.decision);
        if (c.expect!.rule_id === null) {
          expect(result.rule_id).toBeUndefined();
        } else if (c.expect!.rule_id !== undefined) {
          expect(result.rule_id).toBe(c.expect!.rule_id);
        }
        if (c.expect!.approval_required !== undefined) {
          expect(result.approval_required).toBe(c.expect!.approval_required);
        }

        // 3. Shadow evaluation (EV-20/21).
        const shadow = evaluateShadowRules(
          validRules,
          c.input.text,
          target,
          c.input.context as never,
        );
        if (c.expect_shadow === undefined) {
          // Case does not exercise shadow: it must be null (no shadow rules).
          expect(shadow).toBeNull();
        } else if (c.expect_shadow === null) {
          expect(shadow).toBeNull();
        } else {
          expect(shadow?.rule_id).toBe(c.expect_shadow.rule_id);
          expect(shadow?.would).toBe(c.expect_shadow.would);
        }
      });
      continue;
    }

    if (mode === 'pipeline') {
      it(`${c.id} (${c.ev}): ${c.desc ?? ''}`, async () => {
        let hookRan = false;
        init({
          api_key: 'test',
          policy_rules: validRulesOf(c),
          ...(c.pipeline?.pii_policy ? { pii_policy: c.pipeline.pii_policy as never } : {}),
          ...(c.pipeline?.hook
            ? {
                on_pre_call: () => {
                  hookRan = true;
                  return c.pipeline!.hook as 'allow' | 'block';
                },
              }
            : {}),
        });

        // The integrity gate is driven by sync state, not by policy input:
        // a paused project or revoked key is what the server told this client.
        if (c.pipeline?.degraded_reason) {
          _getPolicySyncState().remoteDisabled = true;
        }

        const result = await applyPreCallPolicy(c.input.text, {
          config: getConfig(),
          provider: 'openai',
          operation: 'chat.completions.create',
        });

        const expected = c.expect_pipeline!;
        expect(result.decision).toBe(expected.decision);
        if (expected.action_reason !== undefined) {
          expect(result.compliance.action_reason).toBe(expected.action_reason);
        }
        if (expected.action_source !== undefined) {
          expect(result.compliance.action_source).toBe(expected.action_source);
        }
        if (expected.rule_id !== undefined) {
          expect(result.compliance.rule_id ?? null).toBe(expected.rule_id);
        }
        if (expected.hook_ran !== undefined) {
          expect(hookRan).toBe(expected.hook_ran);
        }
      });
      continue;
    }

    // mode === 'explain'
    it(`${c.id} (${c.ev}): ${c.desc ?? ''}`, () => {
      const rules = validRulesOf(c);
      init({ api_key: 'test', policy_rules: rules });

      // Check-only evaluation, repeated: if it consumed anything, the budget
      // below would already be gone.
      for (let i = 0; i < (c.explain_runs ?? 1); i++) {
        const explained = explain(c.input.text, { config: getConfig() });
        expect(explained.decision).toBe(c.expect!.decision);
        if (c.expect!.rule_id === null) {
          expect(explained.rule_id ?? null).toBeNull();
        } else if (c.expect!.rule_id !== undefined) {
          expect(explained.rule_id).toBe(c.expect!.rule_id);
        }
      }

      // A real evaluation consumes; the first one still fits the budget...
      const first = evaluatePolicyRules(rules, c.input.text, 'prompt');
      expect(first.decision).toBe(c.expect_first_real_call!.decision);
      if (c.expect_first_real_call!.rule_id === null) {
        expect(first.rule_id).toBeUndefined();
      } else if (c.expect_first_real_call!.rule_id !== undefined) {
        expect(first.rule_id).toBe(c.expect_first_real_call!.rule_id);
      }

      // ...and the next one does not, proving the counter moves for real
      // calls and did not move for the explains.
      const second = evaluatePolicyRules(rules, c.input.text, 'prompt');
      expect(second.decision).toBe(c.expect_second_real_call!.decision);
      if (c.expect_second_real_call!.rule_id !== undefined && c.expect_second_real_call!.rule_id !== null) {
        expect(second.rule_id).toBe(c.expect_second_real_call!.rule_id);
      }
    });
  }
});

describe('ev_coverage: the EV coverage map cannot drift from the cases', () => {
  // The uncovered list is the RECORDED gap: statements exercised only
  // indirectly, whose divergence would not fail CI. Recording it as data
  // (with these checks, mirrored in Python) means closing or opening a gap
  // is a reviewable fixture edit, never a silent drift.
  const cov = (fixture as unknown as {
    ev_coverage: { all: string[]; covered: Record<string, string[]>; uncovered: string[] };
  }).ev_coverage;

  it('covered and uncovered partition the full EV list exactly', () => {
    const partition = [...Object.keys(cov.covered), ...cov.uncovered].sort();
    expect(partition).toEqual(cov.all.slice().sort());
    for (const ev of cov.uncovered) expect(cov.covered[ev]).toBeUndefined();
  });

  it('the EV tokens on the cases are exactly the statements covered by THIS fixture', () => {
    const pinnedHere = new Set<string>();
    for (const c of fixture.cases) {
      for (const m of (c.ev ?? '').match(/EV-\d+/g) ?? []) pinnedHere.add(m);
    }
    const coveredHere = Object.entries(cov.covered)
      .filter(([, files]) => files.includes('eval_semantics.json'))
      .map(([ev]) => ev);
    expect([...pinnedHere].sort()).toEqual(coveredHere.sort());
  });

  it('every fixture file named in the coverage map exists', () => {
    for (const files of Object.values(cov.covered)) {
      for (const f of files) {
        expect(fs.existsSync(findFixture(`conformance/fixtures/${f}`))).toBe(true);
      }
    }
  });
});
