/**
 * The frozen rules-hash canonicalizer, from both directions.
 *
 * `stableStringify` feeds policy_version and rules_hash, so it has to agree
 * with the Python `_canonical_json` byte for byte or the same policy stamps
 * two different versions depending on which SDK polled it.
 *
 * Two instruments, because they catch different things:
 *   - the shared fixture pins the specific shapes the two SDKs used to
 *     disagree on, and fails here without needing a Python interpreter;
 *   - fast-check generates fresh documents and checks the properties the
 *     format must satisfy universally, which is what finds the NEXT class.
 * The cross-language half is scripts/check-canonical-json-parity.mjs, which
 * runs this generator against hypothesis in the conformance CI job.
 */
import fc from 'fast-check';
import * as fs from 'fs';
import * as path from 'path';
import { stableStringify } from '../../src/policy/rules';

/** Resolve the fixture from the repo root, wherever the suite is invoked from. */
function findFixture(rel: string): string {
  let dir = process.cwd();
  for (let i = 0; i < 6; i++) {
    const candidate = path.join(dir, rel);
    if (fs.existsSync(candidate)) return candidate;
    dir = path.dirname(dir);
  }
  throw new Error(`fixture not found upward from ${process.cwd()}: ${rel}`);
}

const FIXTURE = JSON.parse(
  fs.readFileSync(findFixture('conformance/fixtures/canonical_json.json'), 'utf-8'),
) as { cases: { group: string; note: string; input: string; expect: string }[] };

describe('canonical_json fixture (shared with the Python SDK)', () => {
  it.each(FIXTURE.cases.map((c, i) => [`${c.group}#${i}`, c] as const))(
    '%s',
    (_id, c) => {
      expect(stableStringify(JSON.parse(c.input))).toBe(c.expect);
    },
  );

  it('covers every divergence class the differential test found', () => {
    const groups = new Set(FIXTURE.cases.map((c) => c.group));
    expect([...groups].sort()).toEqual([
      'agreeing_baseline',
      'astral_key_order',
      'exponent_padding',
      'exponent_threshold',
      'int_past_2_53',
      'negative_zero',
      'unpaired_surrogate',
      'whole_valued_floats',
    ]);
  });
});

// ── Properties ──────────────────────────────────────────────────────────────
// Deliberately stated as properties of the FORMAT, not of the implementation:
// each one is something the Python twin must satisfy too, so a property that
// fails here would have failed there.

const jsonValue = fc.letrec((tie) => ({
  node: fc.oneof(
    { maxDepth: 3, depthSize: 'small' },
    fc.constant(null),
    fc.boolean(),
    fc.integer({ min: -9007199254740991, max: 9007199254740991 }),
    fc.double({ noNaN: true, noDefaultInfinity: true }),
    fc.string({ unit: 'binary' }),
    fc.array(tie('node'), { maxLength: 4 }),
    fc.dictionary(fc.string({ unit: 'binary' }), tie('node'), { maxKeys: 4 }),
  ),
})).node;

describe('stableStringify properties', () => {
  it('is a fixed point: re-canonicalizing its own output changes nothing', () => {
    fc.assert(
      fc.property(jsonValue, (v) => {
        const once = stableStringify(v);
        expect(stableStringify(JSON.parse(once))).toBe(once);
      }),
      { numRuns: 500 },
    );
  });

  it('does not depend on the order keys were inserted in', () => {
    fc.assert(
      fc.property(
        fc.dictionary(fc.string({ unit: 'binary' }), jsonValue, { maxKeys: 6 }),
        (obj) => {
          // Null-prototype, so re-inserting is a faithful shuffle. On a plain
          // `{}` the key "__proto__" hits the inherited Object.prototype
          // setter instead of becoming an own property, so the shuffled copy
          // silently loses it and the test fails against a canonicalizer that
          // was right: Object.keys reports an own "__proto__", and
          // JSON.stringify emits it, so stableStringify must too.
          const shuffled: Record<string, unknown> = Object.create(null);
          for (const k of Object.keys(obj).reverse()) shuffled[k] = obj[k];
          expect(stableStringify(shuffled)).toBe(stableStringify(obj));
        },
      ),
      { numRuns: 500 },
    );
  });

  it('emits UTF-8-encodable output, so the hash input always exists', () => {
    // The Python twin used to fail exactly here: an unpaired surrogate went
    // out raw and .encode("utf-8") raised instead of returning a hash.
    fc.assert(
      fc.property(jsonValue, (v) => {
        const s = stableStringify(v);
        expect(Buffer.from(s, 'utf8').toString('utf8')).toBe(s);
      }),
      { numRuns: 500 },
    );
  });

  it('never emits a bare newline, so a canonical form is always one line', () => {
    fc.assert(
      fc.property(jsonValue, (v) => {
        expect(stableStringify(v)).not.toMatch(/[\n\r]/);
      }),
      { numRuns: 500 },
    );
  });

  it('round-trips to an equal value', () => {
    fc.assert(
      fc.property(jsonValue, (v) => {
        expect(JSON.parse(stableStringify(v))).toEqual(JSON.parse(JSON.stringify(v)));
      }),
      { numRuns: 500 },
    );
  });
});
