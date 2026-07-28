/**
 * The typed policy-block error (TS side).
 *
 * Twin: sdk-python/tests/test_policy_error.py. Both drive every case in
 * conformance/fixtures/error_parity.json through their own construction choke
 * point and must produce the same serialized fields, because the promise is
 * that a caller can branch on a policy block identically in either language.
 */
import * as fs from 'fs';
import * as path from 'path';
import {
  ObsvrPolicyError,
  ObsvrUnknownPolicyError,
  createPolicyError,
  policyBlockMessage,
} from '../../src/policy/policy-error';
import { REASON_CODES } from '../../src/governance/reason-codes';
import { blockedCallError, type ComplianceInfo } from '../../src/integrations/core';

function findFixture(rel: string): string {
  let dir = process.cwd();
  for (let i = 0; i < 6; i++) {
    const candidate = path.join(dir, rel);
    if (fs.existsSync(candidate)) return candidate;
    dir = path.dirname(dir);
  }
  throw new Error(`fixture not found upward from ${process.cwd()}: ${rel}`);
}

interface ParityCase {
  id: string;
  desc: string;
  input: Record<string, unknown>;
  expect: {
    type: string;
    reason_code: string;
    rule_id: string | null;
    message: string;
    decision: Record<string, unknown>;
  };
}

const fixture = JSON.parse(
  readFixture('conformance/fixtures/error_parity.json'),
) as { cases: ParityCase[] };

function readFixture(rel: string): string {
  return fs.readFileSync(findFixture(rel), 'utf-8');
}

/** Drop the fixture's explicit nulls: they mean "absent", not "null". */
function inputToParams(input: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(input).filter(([, v]) => v !== null));
}

describe('conformance: error_parity vectors', () => {
  it('has cases to run', () => {
    expect(fixture.cases.length).toBeGreaterThan(0);
  });

  for (const testCase of fixture.cases) {
    it(`${testCase.id}: ${testCase.desc}`, () => {
      const err = createPolicyError(inputToParams(testCase.input));

      expect(err.type).toBe(testCase.expect.type);
      expect(err.reason_code).toBe(testCase.expect.reason_code);
      expect(err.rule_id ?? null).toBe(testCase.expect.rule_id);
      expect(err.message).toBe(testCase.expect.message);
      expect(err.decision).toEqual(testCase.expect.decision);
    });
  }

  it('draws every reason_code from the closed registry', () => {
    for (const testCase of fixture.cases) {
      expect(REASON_CODES).toContain(testCase.expect.reason_code);
    }
  });
});

describe('policy error: what callers can rely on', () => {
  it('is catchable as an Error, so existing catch blocks still work', () => {
    const err = createPolicyError({ action_reason: 'pii_detected' });
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(ObsvrPolicyError);
  });

  it('distinguishes a policy block from a provider failure without string matching', () => {
    const providerFailure = new Error('503 Service Unavailable');
    const policyBlock = createPolicyError({ action_reason: 'policy_violation' });

    expect(policyBlock instanceof ObsvrPolicyError).toBe(true);
    expect(providerFailure instanceof ObsvrPolicyError).toBe(false);
  });

  it('carries a stable type string that does not depend on the class name', () => {
    // Minifiers rename classes; the wire string must survive that, so it is
    // set literally rather than read from constructor.name.
    const err = createPolicyError({ action_reason: 'pii_detected' });
    expect(err.type).toBe('obsvr_policy_error');
    expect(err.name).toBe('ObsvrPolicyError');
  });

  it('serializes to the same shape the fixture pins', () => {
    const err = createPolicyError({
      action_reason: 'policy_violation',
      action_source: 'policy_rules',
      rule_id: 'r1',
    });
    expect(err.toJSON()).toEqual({
      type: 'obsvr_policy_error',
      reason_code: 'POLICY_VIOLATION',
      rule_id: 'r1',
      decision: {
        action_taken: 'blocked',
        action_reason: 'policy_violation',
        action_source: 'policy_rules',
      },
      message: '[obsvr] Request blocked by policy (policy violation)',
    });
  });

  it('never produces an untyped error for an unknown category', () => {
    const err = createPolicyError({ action_reason: 'something_new', action_source: 'server' });
    expect(err).toBeInstanceOf(ObsvrUnknownPolicyError);
    expect(err).toBeInstanceOf(ObsvrPolicyError);
    expect(err.type).toBe('obsvr_unknown_policy_error');
    expect(err.reason_code).toBe('UNKNOWN_BLOCKED');
  });
});

describe('policy error: the message is a compatibility contract', () => {
  it('preserves the exact strings callers were matching on', () => {
    expect(policyBlockMessage('pii_detected')).toBe('[obsvr] Request blocked by policy (PII detected)');
    expect(policyBlockMessage('policy_violation')).toBe('[obsvr] Request blocked by policy (policy violation)');
  });

  it('keeps the old wording even for categories it cannot classify', () => {
    // The pre-existing code produced this string for anything that was not
    // pii_detected; an unknown category must not change what callers read.
    expect(policyBlockMessage('anything_else')).toBe('[obsvr] Request blocked by policy (policy violation)');
    expect(policyBlockMessage(undefined)).toBe('[obsvr] Request blocked by policy (policy violation)');
  });
});

describe('every block-throw surface uses the one choke point', () => {
  it('the integrations helper returns the typed error, not a plain one', () => {
    const compliance = {
      event_type: 'blocked_call',
      policy_version: 'a1b2c3d4e5f60718',
      action_taken: 'blocked',
      action_reason: 'pii_detected',
      action_source: 'builtin',
      redacted_types: [],
      blocked_types: ['email'],
    } as unknown as ComplianceInfo;

    const err = blockedCallError(compliance);
    expect(err).toBeInstanceOf(ObsvrPolicyError);
    expect(err.reason_code).toBe('PII_DETECTED');
    expect(err.decision.policy_version).toBe('a1b2c3d4e5f60718');
    expect(err.message).toBe('[obsvr] Request blocked by policy (PII detected)');
  });

  it('no source file constructs a policy error outside the choke point', () => {
    // The old pattern was `new Error("[obsvr] Request blocked by policy ...")`
    // inlined per call site, which is how two sites come to classify the same
    // block differently. Only policy-error.ts may build one.
    const srcDir = path
      .dirname(findFixture('sdk-typescript/src/policy/policy-error.ts'))
      .replace(/\/policy$/, '');
    const offenders: string[] = [];
    const walk = (dir: string) => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(full);
        else if (entry.name.endsWith('.ts') && entry.name !== 'policy-error.ts') {
          const body = fs.readFileSync(full, 'utf8');
          if (/new Error\([^)]*Request blocked by policy/.test(body)) offenders.push(full);
        }
      }
    };
    walk(srcDir);
    expect(offenders).toEqual([]);
  });
});
