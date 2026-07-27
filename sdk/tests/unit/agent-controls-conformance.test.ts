import * as fs from 'fs';
import * as path from 'path';
import { createLoopDetector } from '../../src/policy/industry/devops';
import {
  createDelegationTracker,
  hasCircularDelegation,
} from '../../src/policy/industry/agentic';

/**
 * Cross-SDK agent-run control conformance harness (TS side). Twin:
 * sdk-python/tests/test_agent_controls_conformance.py. Runs every case in
 * conformance/fixtures/agent_controls.json; a divergence from the fixture (or
 * from the Python harness) is a release blocker unless recorded in
 * conformance/known-divergences.json.
 *
 * Fixture keys are snake_case and language-neutral; the mapping to this SDK's
 * camelCase config and result fields happens here, so the shared file never
 * has to pick a side.
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

interface LoopCase {
  id: string;
  detector: { max_iterations: number; window_ms: number; action: 'block' | 'escalate' };
  iterations: number;
  expect: Array<null | { action: string; iteration_count: number }>;
}

interface DelegationCase {
  id: string;
  tracker: { max_depth: number; allowed_delegates?: string[]; block_circular: boolean };
  delegations: Array<[string, string]>;
  expect: Array<null | { type: string; message: string; chain: string[]; depth: number }>;
}

const FIXTURE = JSON.parse(fs.readFileSync(findFixture('conformance/fixtures/agent_controls.json'), 'utf-8')) as {
  loop_cases: LoopCase[];
  delegation_cases: DelegationCase[];
  circular_chain_cases: Array<{ id: string; chain: string[]; expect: boolean }>;
};

describe('agent controls conformance: loop detector', () => {
  for (const c of FIXTURE.loop_cases) {
    it(c.id, () => {
      const detector = createLoopDetector({
        maxIterations: c.detector.max_iterations,
        windowMs: c.detector.window_ms,
        action: c.detector.action,
      });
      const results = Array.from({ length: c.iterations }, () => {
        const r = detector.recordIteration();
        return r === null ? null : { action: r.action, iteration_count: r.iterationCount };
      });
      expect(results).toEqual(c.expect);
      // The window is far wider than this test takes, so nothing was pruned.
      expect(detector.getIterationCount()).toBe(c.iterations);
    });
  }
});

describe('agent controls conformance: delegation tracker', () => {
  for (const c of FIXTURE.delegation_cases) {
    it(c.id, () => {
      const tracker = createDelegationTracker({
        maxDepth: c.tracker.max_depth,
        ...(c.tracker.allowed_delegates !== undefined
          ? { allowedDelegates: c.tracker.allowed_delegates }
          : {}),
        blockCircular: c.tracker.block_circular,
      });
      const results = c.delegations.map(([from, to]) => tracker.recordDelegation(from, to));
      expect(results).toEqual(c.expect);
      // A refused delegation never joins the chain, so the surviving depth is
      // exactly the number of delegations the tracker accepted.
      expect(tracker.getDepth()).toBe(c.expect.filter((r) => r === null).length);
    });
  }
});

describe('agent controls conformance: hasCircularDelegation', () => {
  for (const c of FIXTURE.circular_chain_cases) {
    it(c.id, () => {
      expect(hasCircularDelegation(c.chain)).toBe(c.expect);
    });
  }
});
