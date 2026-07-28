import * as fs from 'fs';
import * as path from 'path';
import {
  canonicalToolDescriptor,
  toolDescriptorHash,
  evaluateToolPin,
  createToolPinStore,
} from '../../src/policy/tool-pinning';
import { stableStringify } from '../../src/policy/rules';

/**
 * Cross-SDK tool-descriptor pinning conformance harness (TS side). Twin:
 * sdk-python/tests/test_tool_pinning_conformance.py. Runs every case in
 * conformance/fixtures/tool_pinning.json; a divergence from the fixture (or
 * from the Python harness) is a release blocker unless recorded in
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

interface HashCase {
  id: string;
  descriptor: Record<string, unknown>;
  expect: { canonical: string; hash: string };
}

interface DecisionCase {
  id: string;
  input: {
    config_pin: string | null;
    tofu_pin: string | null;
    observed_hash: string | null;
    mode: 'warn' | 'block';
    require_pin: boolean;
  };
  expect: {
    status: string;
    enforcement: string;
    expected: string | null;
    observed: string | null;
    source: string | null;
    reason: string | null;
  };
}

interface HashErrorCase {
  id: string;
  descriptor: Record<string, unknown>;
}

const fixture = JSON.parse(
  fs.readFileSync(findFixture('conformance/fixtures/tool_pinning.json'), 'utf-8'),
) as { hash_cases: HashCase[]; hash_error_cases: HashErrorCase[]; decision_cases: DecisionCase[] };

describe('conformance: tool descriptor canonicalization + hash', () => {
  for (const c of fixture.hash_cases) {
    it(c.id, () => {
      // stableStringify agrees with the dedicated canonicalizer for the
      // non-numeric cases; toolDescriptorHash is the authoritative pin.
      expect(toolDescriptorHash(c.descriptor)).toBe(c.expect.hash);
    });
  }
  void stableStringify;
});

describe('conformance: cross-SDK-unstable descriptors fail closed (throw)', () => {
  for (const c of fixture.hash_error_cases) {
    it(c.id, () => {
      expect(() => toolDescriptorHash(c.descriptor)).toThrow();
    });
  }
});

describe('conformance: pin decision (evaluateToolPin)', () => {
  for (const c of fixture.decision_cases) {
    it(c.id, () => {
      const v = evaluateToolPin({
        configPin: c.input.config_pin ?? undefined,
        tofuPin: c.input.tofu_pin ?? undefined,
        observedHash: c.input.observed_hash ?? undefined,
        mode: c.input.mode,
        requirePin: c.input.require_pin,
      });
      expect(v.status).toBe(c.expect.status);
      expect(v.enforcement).toBe(c.expect.enforcement);
      expect(v.expected ?? null).toBe(c.expect.expected);
      expect(v.observed ?? null).toBe(c.expect.observed);
      expect(v.source ?? null).toBe(c.expect.source);
      expect(v.reason ?? null).toBe(c.expect.reason);
    });
  }
});

describe('tool pin store invariants (not fixture-expressible: stateful)', () => {
  it('TOFU never silently re-pins: the first hash wins for the store lifetime', () => {
    const store = createToolPinStore();
    store.recordTofuPin('t', 'aaaa');
    store.recordTofuPin('t', 'bbbb'); // attacker swap trying to ratify itself
    expect(store.getTofuPin('t')).toBe('aaaa');
  });

  it('verdicts are per-name and overwritable (latest discovery wins)', () => {
    const store = createToolPinStore();
    store.setVerdict('t', { status: 'ok', enforcement: 'none' });
    store.setVerdict('t', { status: 'mismatch', enforcement: 'block' });
    expect(store.getVerdict('t')?.status).toBe('mismatch');
  });

  it('pinnedNames reflects TOFU recordings (removal-detection input)', () => {
    const store = createToolPinStore();
    store.recordTofuPin('a', 'h1');
    store.recordTofuPin('b', 'h2');
    expect(store.pinnedNames().sort()).toEqual(['a', 'b']);
    expect(store.saturated()).toBe(false);
  });
});
