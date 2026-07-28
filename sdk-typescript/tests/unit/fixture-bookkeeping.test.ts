/**
 * Conformance-corpus bookkeeping (TS side). Twin:
 * sdk-python/tests/test_fixture_bookkeeping.py — both suites validate the
 * SAME structural vocabulary over the SAME corpus, so a malformed entry
 * fails CI in either language.
 *
 * Three pieces of bookkeeping, and why each is validated rather than merely
 * described:
 *
 * 1. `sdk_support` — per-case `{ts, py}` support levels, each one of
 *    "required" | "optional" | "skip". "skip" turns "language X hasn't done
 *    this yet" from a missing test into a reviewable datum: the case exists,
 *    the runner shows it as skipped, and flipping it to "required" is the
 *    port's acceptance gate. A typo'd level would silently run (or silently
 *    not-skip), so the vocabulary is enforced here.
 *
 * 2. `claimable` — a boolean marking a fixture (or case) that backs a claim
 *    made in the PUBLIC docs (README/SECURITY/BENCHMARKS), as opposed to one that
 *    merely exercises behavior. The assignment rule is objective: a fixture
 *    is claimable iff a public doc cites it. Enforced bidirectionally below
 *    so the marking cannot drift from the docs.
 *
 * 3. known-divergences.json — the drift catalog: the machine-readable
 *    allowlist of ACCEPTED cross-SDK divergences. Exact key set per entry,
 *    `status` restricted to "intended", `sdk` to a real SDK name, `category`
 *    to the catalog's own declared vocabulary. An allowlist that cannot be
 *    validated degrades into prose.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';

function findUp(rel: string): string {
  let dir = process.cwd();
  for (let i = 0; i < 6; i++) {
    const candidate = path.join(dir, rel);
    if (fs.existsSync(candidate)) return candidate;
    dir = path.dirname(dir);
  }
  throw new Error(`not found upward from ${process.cwd()}: ${rel}`);
}

const FIXTURES_DIR = findUp('conformance/fixtures');
const REPO_ROOT = path.dirname(path.dirname(FIXTURES_DIR));
const SUPPORT_LEVELS = new Set(['required', 'optional', 'skip']);
const SDK_NAMES = new Set(['ts', 'py']);

/** Where a harness for each language lives. */
const TEST_DIRS: Record<string, string> = {
  ts: path.join(REPO_ROOT, 'sdk-typescript', 'tests'),
  py: path.join(REPO_ROOT, 'sdk-python', 'tests'),
};

/**
 * These two read `sdk_support` in order to VALIDATE it, never to honor it.
 * Counting them as harnesses would let every case vouch for itself.
 */
const NOT_A_HARNESS = new Set(['fixture-bookkeeping.test.ts', 'test_fixture_bookkeeping.py']);

/**
 * Harness SOURCE under `dir`, as { name, text }. Extension-filtered on
 * purpose: `__pycache__` holds compiled copies that still carry the source's
 * string literals, so a stale .pyc would answer "yes, this harness reads
 * sdk_support" for a harness that no longer exists.
 */
function readHarnesses(dir: string): Array<{ name: string; text: string }> {
  const out: Array<{ name: string; text: string }> = [];
  const walk = (d: string): void => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (e.name === '__pycache__') continue;
      const full = path.join(d, e.name);
      if (e.isDirectory()) {
        walk(full);
      } else if (/\.(ts|py)$/.test(e.name) && !NOT_A_HARNESS.has(e.name)) {
        out.push({ name: e.name, text: fs.readFileSync(full, 'utf-8') });
      }
    }
  };
  walk(dir);
  return out;
}

/** Every fixture file, parsed. */
function allFixtures(): Array<{ name: string; data: unknown }> {
  return fs
    .readdirSync(FIXTURES_DIR)
    .filter((f) => f.endsWith('.json'))
    .map((name) => ({
      name,
      data: JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, name), 'utf-8')),
    }));
}

/** Recursively collect every value stored under `key` anywhere in the doc. */
function collect(value: unknown, key: string, out: unknown[]): void {
  if (Array.isArray(value)) {
    for (const v of value) collect(v, key, out);
  } else if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) {
      if (k === key) out.push(v);
      collect(v, key, out);
    }
  }
}

describe('fixture bookkeeping: sdk_support vocabulary', () => {
  it('every sdk_support anywhere in the corpus is {ts?, py?} with known levels', () => {
    for (const { name, data } of allFixtures()) {
      const found: unknown[] = [];
      collect(data, 'sdk_support', found);
      for (const s of found) {
        expect(s && typeof s === 'object' && !Array.isArray(s)).toBe(true);
        const entries = Object.entries(s as Record<string, unknown>);
        expect(entries.length).toBeGreaterThan(0);
        for (const [sdk, level] of entries) {
          expect(SDK_NAMES.has(sdk)).toBe(true);
          expect(SUPPORT_LEVELS.has(level as string)).toBe(true);
        }
      }
      void name;
    }
  });

  it('a case cannot be skip for BOTH languages (that is deletion, not support)', () => {
    for (const { data } of allFixtures()) {
      const found: unknown[] = [];
      collect(data, 'sdk_support', found);
      for (const s of found) {
        const levels = Object.values(s as Record<string, string>);
        expect(levels.every((l) => l === 'skip')).toBe(false);
      }
    }
  });
});

describe('fixture bookkeeping: a non-required level must be one its harness reads', () => {
  /**
   * The gap this closes. Every case carries `sdk_support`, but only a harness
   * that BRANCHES on it can act on a level. Everywhere else a "skip" is inert
   * prose: the case runs anyway and fails at its own assertion, which is a
   * confusing failure precisely because the bookkeeping looks right.
   *
   * So "required" is free — it asks nothing of the harness. Any other level
   * is a claim that something will happen at run time, and is allowed only
   * where a harness consuming that fixture reads the field.
   *
   * The honoring set is GREPPED, never listed. A hardcoded list is one more
   * thing to forget the day a harness is wired; derived, this relaxes by
   * itself the moment the code it describes becomes true.
   *
   * Its limit, stated plainly: this proves the consuming harness reads
   * `sdk_support` somewhere, not that it reads it on the array your case
   * happens to live in. It catches a harness that ignores the field entirely,
   * which is the failure mode that exists today; it would not catch one that
   * honors the field for one case array and not another.
   */
  const harnesses: Record<string, Array<{ name: string; text: string }>> = {
    ts: readHarnesses(TEST_DIRS.ts),
    py: readHarnesses(TEST_DIRS.py),
  };

  it('locates harness source for both languages, so a bad path cannot pass this vacuously', () => {
    for (const sdk of SDK_NAMES) expect(harnesses[sdk].length).toBeGreaterThan(0);
  });

  it('every non-required level sits in a fixture whose harness reads sdk_support', () => {
    const problems = new Set<string>();
    for (const { name, data } of allFixtures()) {
      const found: unknown[] = [];
      collect(data, 'sdk_support', found);
      for (const s of found as Array<Record<string, string>>) {
        for (const [sdk, level] of Object.entries(s)) {
          if (level === 'required') continue;
          const consuming = (harnesses[sdk] ?? []).filter((f) => f.text.includes(name));
          if (consuming.some((f) => f.text.includes('sdk_support'))) continue;
          problems.add(
            `${name}: sdk_support ${sdk}:"${level}", but no ${sdk} harness consuming it reads ` +
              `the field (consumers: ${consuming.map((f) => f.name).join(', ') || 'none'}). ` +
              `Branch on sdk_support in that harness, or set the level to "required".`,
          );
        }
      }
    }
    expect([...problems].sort()).toEqual([]);
  });
});

describe('fixture bookkeeping: claimable matches the public docs', () => {
  it('claimable is always a boolean', () => {
    for (const { data } of allFixtures()) {
      const found: unknown[] = [];
      collect(data, 'claimable', found);
      for (const c of found) expect(typeof c).toBe('boolean');
    }
  });

  it('a fixture is claimable iff a public doc cites it', () => {
    // The assignment rule made checkable: one of the PUBLISHED docs citing
    // `fixtures/<name>.json` is what "backs a public claim" MEANS here.
    // Marking without a citation or citing without a marking both fail, so
    // the two cannot drift. BENCHMARKS.md is in the set because a published
    // number is a claim like any other: a fixture cited only there must come
    // out claimable, and dropping it would silently require the opposite.
    const docs = ['README.md', 'SECURITY.md', 'BENCHMARKS.md', 'sdk-typescript/README.md', 'sdk-python/README.md']
      .map((d) => path.join(REPO_ROOT, d))
      .filter((d) => fs.existsSync(d))
      .map((d) => fs.readFileSync(d, 'utf-8'))
      .join('\n');
    for (const { name, data } of allFixtures()) {
      const cited = docs.includes(name);
      const marked = (data as { claimable?: boolean }).claimable === true;
      expect({ fixture: name, claimable: marked }).toEqual({ fixture: name, claimable: cited });
    }
  });
});

describe('fixture bookkeeping: the drift catalog validates', () => {
  const catalog = JSON.parse(
    fs.readFileSync(findUp('conformance/known-divergences.json'), 'utf-8'),
  ) as {
    categories: Record<string, string>;
    entries: Array<Record<string, unknown>>;
  };
  const ENTRY_KEYS = [
    'id', 'sdk', 'category', 'status', 'description',
    'parity_scope', 'allowed_difference', 'tracking',
  ];

  it('every entry carries exactly the required keys', () => {
    for (const e of catalog.entries) {
      expect(Object.keys(e).sort()).toEqual(ENTRY_KEYS.slice().sort());
      for (const k of ENTRY_KEYS) {
        expect(typeof e[k]).toBe('string');
        expect((e[k] as string).length).toBeGreaterThan(0);
      }
    }
  });

  it('status has exactly one legal value: intended', () => {
    for (const e of catalog.entries) expect(e.status).toBe('intended');
  });

  it('sdk and category are drawn from the declared vocabularies', () => {
    for (const e of catalog.entries) {
      expect(SDK_NAMES.has(e.sdk as string)).toBe(true);
      expect(Object.keys(catalog.categories)).toContain(e.category);
    }
  });

  it('ids are unique and KD-numbered', () => {
    const ids = catalog.entries.map((e) => e.id as string);
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids) expect(id).toMatch(/^KD-\d+$/);
  });
});
