import * as fs from 'fs';
import * as path from 'path';
import {
  derivePolicyVersion,
  deriveRuleHash,
  stableStringify,
  PolicyRule, deriveFloorVersion } from '../../src/policy/rules';

// Walk up from cwd to find the repo-root conformance fixture; works under
// both the ESM and CJS jest configs (no __dirname / import.meta needed).
function findFixture(rel: string): string {
  let dir = process.cwd();
  for (let i = 0; i < 6; i++) {
    const candidate = path.join(dir, rel);
    if (fs.existsSync(candidate)) return candidate;
    dir = path.dirname(dir);
  }
  throw new Error(`fixture not found upward from ${process.cwd()}: ${rel}`);
}

const fixturePath = findFixture('conformance/fixtures/rules_hash.json');
const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf-8'));
const rules: PolicyRule[] = fixture.rules;

describe('canonical rules hash (cross-SDK fixture)', () => {
  it('derives the fixture set hash', () => {
    expect(derivePolicyVersion(rules)).toBe(fixture.expected.set_hash);
  });

  it('is insensitive to rule order', () => {
    const reversed = [...rules].reverse();
    expect(derivePolicyVersion(reversed)).toBe(fixture.expected.set_hash);
  });

  it('excludes disabled rules from the set hash', () => {
    const enabledOnly = rules.filter((r) => r.enabled);
    expect(derivePolicyVersion(enabledOnly)).toBe(fixture.expected.set_hash);
  });

  it('returns "none" for empty and all-disabled sets', () => {
    expect(derivePolicyVersion([])).toBe(fixture.expected.empty_set_hash);
    const disabledOnly = rules.filter((r) => !r.enabled);
    expect(derivePolicyVersion(disabledOnly)).toBe(
      fixture.expected.all_disabled_hash,
    );
  });

  it('derives per-rule hashes matching the fixture', () => {
    for (const [id, expected] of Object.entries(
      fixture.expected.rule_hashes as Record<string, string>,
    )) {
      const rule = rules.find((r) => r.id === id)!;
      expect(deriveRuleHash(rule)).toBe(expected);
    }
  });

  it('per-rule hash changes when the rule definition changes', () => {
    const rule = rules.find((r) => r.id === 'r-block-ssn')!;
    const edited = { ...rule, conditions: { ...rule.conditions, min_confidence: 0.9 } };
    expect(deriveRuleHash(edited)).not.toBe(deriveRuleHash(rule));
  });

  it('ignores unknown/cosmetic fields on rules', () => {
    const decorated = rules.map((r) => ({
      ...r,
      updated_at: '2026-07-07T00:00:00Z',
      _editor_note: 'anything',
    })) as unknown as PolicyRule[];
    expect(derivePolicyVersion(decorated)).toBe(fixture.expected.set_hash);
  });
});

describe('stableStringify canonical form', () => {
  it('sorts keys recursively and uses compact separators', () => {
    expect(stableStringify({ b: 1, a: { d: [2, { z: 1, y: 2 }], c: null } })).toBe(
      '{"a":{"c":null,"d":[2,{"y":2,"z":1}]},"b":1}',
    );
  });

  it('drops undefined-valued object keys and nullifies undefined in arrays', () => {
    expect(stableStringify({ a: undefined, b: 1 })).toBe('{"b":1}');
    expect(stableStringify([undefined, 1])).toBe('[null,1]');
  });
});

/**
 * A-4: the two rule-id sort sites. Both languages sort ids before hashing, and
 * they sorted differently — Python by code point, TypeScript by UTF-16 code
 * unit. Every id in the fixture above is ASCII, so both orders agree on all of
 * them and the divergence survived the whole corpus.
 *
 * The case that catches it needs an ASTRAL id beside a BMP id in
 * U+E000..U+FFFF. That is the only region where the orders differ, so a pair
 * chosen anywhere else would pass whatever the sort key is — a fixture that
 * cannot fail.
 */
describe('conformance: rule-id ordering across the two sort implementations', () => {
  const ordering = fixture.ordering as {
    rules: PolicyRule[];
    expected: {
      utf16_order: string[];
      codepoint_order_do_not_use: string[];
      set_hash: string;
      floor_hash: string;
    };
  };

  it('the two orders genuinely differ on this pair (the case is not vacuous)', () => {
    const ids = ordering.rules.map((r) => r.id);
    const byCodePoint = [...ids].sort((a, b) => {
      const A = [...a].map((c) => c.codePointAt(0)!);
      const B = [...b].map((c) => c.codePointAt(0)!);
      for (let i = 0; i < Math.min(A.length, B.length); i++) {
        if (A[i] !== B[i]) return A[i] - B[i];
      }
      return A.length - B.length;
    });
    const byCodeUnit = [...ids].sort();
    expect(byCodeUnit).toEqual(ordering.expected.utf16_order);
    expect(byCodePoint).toEqual(ordering.expected.codepoint_order_do_not_use);
    expect(byCodeUnit).not.toEqual(byCodePoint);
  });

  it('derivePolicyVersion stamps the pinned hash', () => {
    expect(derivePolicyVersion(ordering.rules)).toBe(ordering.expected.set_hash);
  });

  it('deriveFloorVersion stamps the pinned hash', () => {
    expect(deriveFloorVersion(ordering.rules)).toBe(ordering.expected.floor_hash);
  });
});
