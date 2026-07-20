import * as fs from 'fs';
import * as path from 'path';
import {
  evaluatePolicyRules,
  evaluateShadowRules,
  PolicyRule,
} from '../../src/policy/rules';
import { isValidPolicyRule } from '../../src/proxy/config';

/**
 * Cross-SDK conformance harness (TS side). Twin:
 * sdk-python/tests/test_conformance.py. Runs every case in
 * conformance/fixtures/eval_semantics.json through validator +
 * evaluator + shadow evaluator. A divergence from the fixture (or from
 * the Python harness) is a release blocker unless recorded in
 * conformance/known-divergences.md.
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
  rules: unknown[];
  input: { text: string; target?: 'prompt' | 'response'; context?: Record<string, unknown> };
  expect: { decision: string; rule_id?: string | null; approval_required?: boolean };
  expect_shadow?: { rule_id: string; would: string } | null;
  expect_valid_rule_ids?: string[];
}

const fixture = JSON.parse(
  fs.readFileSync(findFixture('conformance/fixtures/eval_semantics.json'), 'utf-8'),
) as { cases: FixtureCase[] };

describe('conformance: eval_semantics fixtures', () => {
  for (const c of fixture.cases) {
    it(`${c.id} (${c.ev})`, () => {
      // 1. Validator pass (EV-12): malformed rules are dropped.
      const validRules = c.rules.filter(isValidPolicyRule) as PolicyRule[];
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
      expect(result.decision).toBe(c.expect.decision);
      if (c.expect.rule_id === null) {
        expect(result.rule_id).toBeUndefined();
      } else if (c.expect.rule_id !== undefined) {
        expect(result.rule_id).toBe(c.expect.rule_id);
      }
      if (c.expect.approval_required !== undefined) {
        expect(result.approval_required).toBe(c.expect.approval_required);
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
  }
});
