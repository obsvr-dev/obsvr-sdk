import * as fs from 'fs';
import * as path from 'path';
import { evaluateFloor, deriveFloorVersion, type PolicyRule } from '../../src/policy/rules';

/**
 * Cross-SDK anti-tamper policy-floor conformance harness (TS side). Twin:
 * sdk-python/tests/test_policy_floor_conformance.py. Pins the floor evaluation
 * (downgraded floor rule still enforces; empty floor allows) and the floor
 * version hash (downgrade hashes identically to enforced).
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

interface DecisionCase { id: string; floor: PolicyRule[]; input: string; expect: { decision: string } }
interface VersionCase { id: string; floor: PolicyRule[]; expect: { floor_version: string } }

const fixture = JSON.parse(
  fs.readFileSync(findFixture('conformance/fixtures/policy_floor.json'), 'utf-8'),
) as { decision_cases: DecisionCase[]; version_cases: VersionCase[] };

describe('conformance: floor evaluation (enforce coercion, deny-wins)', () => {
  for (const c of fixture.decision_cases) {
    it(c.id, () => {
      expect(evaluateFloor(c.floor.length ? c.floor : undefined, c.input, 'prompt').decision).toBe(
        c.expect.decision,
      );
    });
  }
});

describe('conformance: floor version hash', () => {
  for (const c of fixture.version_cases) {
    it(c.id, () => {
      expect(deriveFloorVersion(c.floor.length ? c.floor : undefined)).toBe(c.expect.floor_version);
    });
  }
});
