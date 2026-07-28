import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  extractSqlFacets,
  stripSqlComments,
  MAX_FACET_INPUT,
} from '../../src/policy/protocol-facets';
import { evaluatePolicyRules, type PolicyRule } from '../../src/policy/rules';

/**
 * Cross-SDK protocol-facet conformance (TS side). Twin:
 * sdk-python/tests/test_protocol_facets_conformance.py.
 *
 * Two layers are pinned: the decomposition itself, and the rule semantics on
 * top of it — including the direction that matters most, which is that text
 * the decomposer cannot speak about MATCHES rather than passing.
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

interface FacetCase {
  id: string;
  desc?: string;
  text: unknown;
  expect: Record<string, unknown>;
}
interface RuleCase {
  id: string;
  desc?: string;
  rule: PolicyRule;
  text: string;
  expect: { decision: string; rule_id?: string; reason_code?: string };
}

const fixture = JSON.parse(
  fs.readFileSync(findFixture('conformance/fixtures/protocol_facets.json'), 'utf-8'),
) as { facet_cases: FacetCase[]; rule_cases: RuleCase[] };

describe('conformance: SQL facet decomposition', () => {
  for (const c of fixture.facet_cases) {
    it(c.id, () => {
      expect(JSON.parse(JSON.stringify(extractSqlFacets(c.text)))).toEqual(c.expect);
    });
  }
});

describe('conformance: the protocol_facet rule type', () => {
  for (const c of fixture.rule_cases) {
    it(c.id, () => {
      const result = evaluatePolicyRules([c.rule], c.text);
      expect(result.decision).toBe(c.expect.decision);
      if (c.expect.rule_id !== undefined) expect(result.rule_id).toBe(c.expect.rule_id);
      if (c.expect.reason_code !== undefined) {
        expect(result.reason_code).toBe(c.expect.reason_code);
      }
    });
  }
});

describe('protocol facets: bounds and purity', () => {
  it('refuses input past the length bound rather than scanning it', () => {
    const huge = 'SELECT 1 FROM t WHERE x = ' + 'a'.repeat(MAX_FACET_INPUT);
    const facets = extractSqlFacets(huge);
    expect(facets.parsed).toBe(false);
    expect(facets.reason).toBe('input_too_long');
  });

  it('refuses input past the token bound', () => {
    // Comma-separated columns produce two tokens each, so this clears the cap
    // well inside the character bound.
    const wide =
      'SELECT ' + Array.from({ length: 1500 }, (_, i) => `c${i}`).join(',') + ' FROM t';
    expect(wide.length).toBeLessThanOrEqual(MAX_FACET_INPUT);
    const facets = extractSqlFacets(wide);
    expect(facets.parsed).toBe(false);
    expect(facets.reason).toBe('too_many_tokens');
  });

  it('is total: never throws, whatever it is handed', () => {
    const inputs: unknown[] = [
      undefined,
      null,
      0,
      [],
      {},
      '',
      "'",
      '"',
      '/*',
      '--',
      ';;;',
      '((((',
      'SELECT ' + '('.repeat(500),
      ' ',
      'DROP TABLE "unterminated',
    ];
    for (const input of inputs) {
      expect(() => extractSqlFacets(input)).not.toThrow();
      expect(typeof extractSqlFacets(input).parsed).toBe('boolean');
    }
  });

  it('is pure: the same text decomposes identically every time', () => {
    const q = 'SELECT lower(a) FROM x JOIN y ON 1=1';
    expect(extractSqlFacets(q)).toEqual(extractSqlFacets(q));
  });

  it('comment stripping leaves literals intact', () => {
    expect(stripSqlComments("SELECT '/* not a comment */' FROM t")).toBe(
      "SELECT '/* not a comment */' FROM t",
    );
    expect(stripSqlComments('SELECT 1 /* gone */ FROM t')).toBe('SELECT 1   FROM t');
  });
});
