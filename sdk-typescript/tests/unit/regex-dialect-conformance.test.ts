import * as fs from 'fs';
import * as path from 'path';
import { validateRegexPattern } from '../../src/utils/safe-regex';

/**
 * A-3 — cross-SDK regex dialect. Twin:
 * sdk-python/tests/test_regex_dialect_conformance.py.
 *
 * A `regex` rule is authored once and run by two engines. Before this fixture
 * the corpus held exactly ONE regex case — `(a+)+$`, a pattern both validators
 * reject — so it asserted only that a rejected pattern never matches. Thirty
 * diverging verdicts across seventeen construct families survived it.
 *
 * Both validators must agree on ok/not-ok for every pattern here. The REASON is
 * deliberately not pinned: each engine's own parser legitimately catches some of
 * these first and reports its own wording, and pinning the reason would make
 * this fixture fail on a cosmetic difference while missing a real one.
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

interface DialectCase {
  id: string;
  pattern: string;
  portable: boolean;
  family: string;
  note?: string;
}

const fixture = JSON.parse(
  fs.readFileSync(findFixture('conformance/fixtures/regex_dialect.json'), 'utf-8'),
) as { cases: DialectCase[] };

describe('conformance: regex dialect portability', () => {
  it('the fixture carries both verdicts (a one-sided corpus proves nothing)', () => {
    // The single pre-existing regex case in the whole corpus was a REJECT.
    // Without portable controls here, "every pattern is rejected" would pass.
    expect(fixture.cases.some((c) => c.portable)).toBe(true);
    expect(fixture.cases.some((c) => !c.portable)).toBe(true);
  });

  for (const c of fixture.cases) {
    it(`${c.portable ? 'accepts' : 'rejects'} ${c.id} — ${c.family}`, () => {
      expect(validateRegexPattern(c.pattern).ok).toBe(c.portable);
    });
  }
});
