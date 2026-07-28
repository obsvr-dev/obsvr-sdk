import * as fs from 'fs';
import * as path from 'path';
import {
  hasEscrow,
  applyEscrowGrant,
  applyEscrowResponse,
  spendEscrowShare,
  peekEscrowShare,
  snapshotConsumption,
  _resetEscrow,
  type EscrowShare,
} from '../../src/governance/escrow';
import { evaluatePolicyRules, PolicyRule } from '../../src/policy/rules';
import { _resetAllQuotas } from '../../src/governance/quota';

/**
 * Cross-SDK conformance harness (TS side) for fleet-quota escrow (ADR-7).
 * Twin: sdk-python/tests/test_escrow_conformance.py. Both drive every
 * (grant, spend, report) sequence in conformance/fixtures/quota_escrow.json
 * and must reach identical allow/block decisions and consumption reports.
 * A divergence is a release blocker.
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

interface Step {
  op: 'grant' | 'poll_response' | 'spend' | 'peek' | 'has_escrow' | 'report';
  rule_id?: string;
  share?: number;
  epoch?: number;
  escrow?: Record<string, EscrowShare> | null;
  expect?:
    | boolean
    | { escrow: boolean; allowed: boolean; remaining: number }
    | Record<string, { consumed: number; epoch: number }>;
}

interface FixtureCase {
  id: string;
  desc: string;
  steps: Step[];
}

const fixture = JSON.parse(
  fs.readFileSync(findFixture('conformance/fixtures/quota_escrow.json'), 'utf-8'),
) as { cases: FixtureCase[] };

describe('conformance: quota_escrow fixtures', () => {
  beforeEach(() => {
    _resetEscrow();
  });

  for (const c of fixture.cases) {
    it(`${c.id}: ${c.desc}`, () => {
      for (const [i, step] of c.steps.entries()) {
        const where = `${c.id} step ${i} (${step.op})`;
        switch (step.op) {
          case 'grant':
            applyEscrowGrant(step.rule_id!, step.share!, step.epoch!);
            break;
          case 'poll_response':
            applyEscrowResponse(step.escrow ?? undefined);
            break;
          case 'spend': {
            const r = spendEscrowShare(step.rule_id!);
            expect({ where, ...r }).toEqual({ where, ...(step.expect as object) });
            break;
          }
          case 'peek': {
            const r = peekEscrowShare(step.rule_id!);
            expect({ where, ...r }).toEqual({ where, ...(step.expect as object) });
            break;
          }
          case 'has_escrow':
            expect(hasEscrow(step.rule_id!)).toBe(step.expect as boolean);
            break;
          case 'report':
            expect(snapshotConsumption()).toEqual(step.expect as object);
            break;
          default:
            throw new Error(`${where}: unknown op`);
        }
      }
    });
  }
});

/**
 * Wiring: the rules engine must route a quota rule through the escrow share
 * when a grant is in effect, and fall back to the per-process meter otherwise.
 */
describe('escrow ↔ rules engine integration', () => {
  beforeEach(() => {
    _resetEscrow();
    _resetAllQuotas();
  });

  const quotaRule: PolicyRule = {
    id: 'q1',
    name: 'request quota',
    enabled: true,
    action: 'block',
    type: 'quota',
    conditions: { quota_limit: 100, quota_window_ms: 60_000, quota_scope: 'project' },
  };

  it('spends the escrow share (not the per-process limit) when escrow is in effect', () => {
    // Escrow grants only 1, even though the rule limit is 100: the fleet
    // allocator, not the local limit, bounds this instance.
    applyEscrowGrant('q1', 1, 1);
    expect(evaluatePolicyRules([quotaRule], 'hello').decision).toBe('allow');
    const blocked = evaluatePolicyRules([quotaRule], 'hello');
    expect(blocked.decision).toBe('block');
    expect(blocked.rule_id).toBe('q1');
    // The consumption was tracked against the grant (one allowed spend).
    expect(snapshotConsumption()).toEqual({ q1: { consumed: 1, epoch: 1 } });
  });

  it('falls back to the per-process meter when no escrow grant is present', () => {
    // No grant for q1 -> uses the local limit of 100, so the first call allows
    // and nothing is tracked as escrow consumption.
    expect(evaluatePolicyRules([quotaRule], 'hello').decision).toBe('allow');
    expect(hasEscrow('q1')).toBe(false);
    expect(snapshotConsumption()).toEqual({});
  });

  it('checkOnly evaluation peeks the escrow share without consuming it', () => {
    applyEscrowGrant('q1', 1, 4);
    // Shadow/explain path (checkOnly) must not burn the share.
    evaluatePolicyRules([quotaRule], 'hello', 'prompt', undefined, { checkOnly: true });
    expect(snapshotConsumption()).toEqual({ q1: { consumed: 0, epoch: 4 } });
    // A real (consuming) call then still has its full share.
    expect(evaluatePolicyRules([quotaRule], 'hello').decision).toBe('allow');
    expect(snapshotConsumption()).toEqual({ q1: { consumed: 1, epoch: 4 } });
  });
});
