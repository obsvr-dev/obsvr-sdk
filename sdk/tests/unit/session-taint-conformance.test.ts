import * as fs from 'fs';
import * as path from 'path';
import {
  deriveSessionKey,
  evaluateSessionTaint,
  evaluateToolTaintGate,
  markTainted,
  taintReason,
  touchTaint,
  sessionTaintSize,
  _resetSessionTaint,
} from '../../src/policy/session-taint';
import { declaresDestructive } from '../../src/policy/capability-hints';

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
interface ToolGateCase {
  id: string;
  desc?: string;
  tainted: boolean;
  /** Fixture configs use the wire spelling; destructive_tools maps to the
   * TS resolved-config key destructiveTools. */
  config: {
    enabled?: boolean;
    action?: 'block' | 'flag';
    destructive_tools?: string[];
    honor_destructive_hints?: boolean;
  } | null;
  tool_name: string;
  /** Whether the tool's descriptor declared it destructive at discovery. */
  declared_destructive?: boolean;
  expect: { enforcement: string; destructive?: boolean; destructive_source?: string };
}
interface DescriptorHintCase {
  id: string;
  desc?: string;
  tool: { annotations?: unknown } | null;
  expect: boolean;
}

const fixture = JSON.parse(
  fs.readFileSync(findFixture('conformance/fixtures/session_taint.json'), 'utf-8'),
) as {
  key_cases: KeyCase[];
  decision_cases: DecisionCase[];
  tool_gate_cases: { cases: ToolGateCase[] };
  descriptor_hint_cases: { cases: DescriptorHintCase[] };
};

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

describe('conformance: tool-aware taint gate (destructive-capability set)', () => {
  for (const c of fixture.tool_gate_cases.cases) {
    it(c.id, () => {
      _resetSessionTaint();
      if (c.tainted) markTainted('k', 'prompt_injection', 1.0);
      const cfg = c.config
        ? {
            enabled: c.config.enabled,
            action: c.config.action,
            destructiveTools: c.config.destructive_tools,
            honorDestructiveHints: c.config.honor_destructive_hints,
          }
        : undefined;
      const verdict = evaluateToolTaintGate('k', cfg, c.tool_name, c.declared_destructive === true);
      expect(verdict.enforcement).toBe(c.expect.enforcement);
      expect(verdict.destructive).toBe(c.expect.destructive);
      expect(verdict.destructiveSource).toBe(c.expect.destructive_source);
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

describe('conformance: descriptor destructiveHint is read one-directionally', () => {
  for (const c of fixture.descriptor_hint_cases.cases) {
    it(c.id, () => {
      expect(declaresDestructive(c.tool)).toBe(c.expect);
    });
  }
});
