import * as fs from 'fs';
import * as path from 'path';
import {
  deriveSessionKey,
  evaluateSessionTaint,
  markTainted,
  taintReason,
  touchTaint,
  sessionTaintSize,
  _resetSessionTaint,
} from '../../src/policy/session-taint';

/**
 * Cross-SDK session-taint conformance harness (TS side). Twin:
 * sdk-python/tests/test_session_taint_conformance.py. Pins the deterministic
 * key derivation + enforcement decision, plus the store invariants (monotonic
 * reason, bounded eviction).
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

interface KeyCase {
  id: string;
  metadata: Record<string, unknown> | null;
  expect: string;
}
interface DecisionCase {
  id: string;
  tainted: boolean;
  config: { enabled?: boolean; action?: 'block' | 'flag' } | null;
  expect: { enforcement: string };
}

const fixture = JSON.parse(
  fs.readFileSync(findFixture('conformance/fixtures/session_taint.json'), 'utf-8'),
) as { key_cases: KeyCase[]; decision_cases: DecisionCase[] };

describe('conformance: session key derivation', () => {
  for (const c of fixture.key_cases) {
    it(c.id, () => {
      expect(deriveSessionKey(c.metadata ?? undefined)).toBe(c.expect);
    });
  }
});

describe('conformance: taint enforcement decision', () => {
  for (const c of fixture.decision_cases) {
    it(c.id, () => {
      _resetSessionTaint();
      if (c.tainted) markTainted('k', 'prompt_injection', 1.0);
      expect(evaluateSessionTaint('k', c.config ?? undefined).enforcement).toBe(c.expect.enforcement);
      _resetSessionTaint();
    });
  }
});

describe('taint store invariants (not fixture-expressible: stateful)', () => {
  beforeEach(() => _resetSessionTaint());
  afterEach(() => _resetSessionTaint());

  it('the latch is monotonic: the FIRST reason is kept when re-marked', () => {
    markTainted('s', 'prompt_injection', 1);
    markTainted('s', 'canary_leak', 2); // later signal must not overwrite the reason
    expect(taintReason('s')).toBe('prompt_injection');
  });

  it('an untainted session has no reason', () => {
    expect(taintReason('never')).toBeUndefined();
    expect(sessionTaintSize()).toBe(0);
  });

  it('bounded: past the cap the oldest is evicted, newest kept', () => {
    for (let i = 0; i < 10_000; i++) markTainted(`s${i}`, 'prompt_injection', i);
    expect(sessionTaintSize()).toBe(10_000);
    markTainted('newest', 'canary_leak', 10_001); // evicts s0 (oldest)
    expect(sessionTaintSize()).toBe(10_000);
    expect(taintReason('newest')).toBe('canary_leak');
    expect(taintReason('s0')).toBeUndefined();
  });

  it('touch keeps an enforced victim from being flushed by an attacker flood', () => {
    markTainted('victim', 'prompt_injection', 0);
    touchTaint('victim', 1_000_000); // enforce keeps it recent
    for (let i = 0; i < 9_999; i++) markTainted(`flood${i}`, 'prompt_injection', 100 + i);
    markTainted('attacker', 'prompt_injection', 200_000); // evicts the OLDEST (a flood entry)
    expect(taintReason('victim')).toBe('prompt_injection'); // survived
  });
});
