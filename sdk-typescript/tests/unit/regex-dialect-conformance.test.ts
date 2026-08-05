import * as fs from 'fs';
import * as path from 'path';
import { safeRegexTest, validateRegexPattern } from '../../src/utils/safe-regex';

/**
 * A-3 — cross-SDK regex dialect. Twin:
 * sdk-python/tests/test_regex_dialect_conformance.py.
 *
 * A `regex` rule is authored once and run by two engines. Before this fixture
 * the corpus held exactly ONE regex case — `(a+)+$`, a pattern both validators
 * reject — so it asserted only that a rejected pattern never matches. Thirty
 * diverging verdicts across seventeen construct families survived it.
 *
 * TWO HALVES, because the split has two. `cases` is the SYNTAX half: both
 * validators must agree on ok/not-ok for every pattern. The REASON is
 * deliberately not pinned — each engine's own parser legitimately catches some
 * of these first and reports its own wording, and pinning the reason would make
 * this fixture fail on a cosmetic difference while missing a real one.
 *
 * `semantic_cases` is the half that used to be open. `\d` `\w` `\s` `\b` `$`
 * and `.` read differently in `re` and `RegExp` and carry no syntactic marker,
 * so they could not be rejected without banning the most common constructs in
 * the language. They are closed by normalizing the PYTHON side to ECMAScript's
 * meaning at that SDK's one compile call, which is why this engine needs no
 * change and why these rows are a REGRESSION guard here rather than a repair:
 * every one of them describes what this engine already did.
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

/** A pattern, an input, and the one match verdict both SDKs must reach. */
interface SemanticCase {
  id: string;
  pattern: string;
  input: string;
  matches: boolean;
  family: string;
  note?: string;
}

const fixture = JSON.parse(
  fs.readFileSync(findFixture('conformance/fixtures/regex_dialect.json'), 'utf-8'),
) as { cases: DialectCase[]; semantic_cases: SemanticCase[] };

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

describe('conformance: regex dialect semantics', () => {
  it('the fixture carries both verdicts', () => {
    // A corpus of nothing but non-matches would agree with any broken engine.
    expect(fixture.semantic_cases.some((c) => c.matches)).toBe(true);
    expect(fixture.semantic_cases.some((c) => !c.matches)).toBe(true);
  });

  it('every semantic case uses a pattern the validator accepts', () => {
    // A rejected pattern never matches, so a typo'd row would read as a
    // passing "does not match" case rather than as the mistake it is.
    const rejected = fixture.semantic_cases
      .filter((c) => !validateRegexPattern(c.pattern).ok)
      .map((c) => c.id);

    expect(rejected).toEqual([]);
  });

  for (const c of fixture.semantic_cases) {
    it(`${c.id} — ${c.family}`, () => {
      expect(safeRegexTest(c.pattern, c.input)).toBe(c.matches);
    });
  }
});
