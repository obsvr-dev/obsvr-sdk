/**
 * Duplicate-SDK-instance guard (TS side).
 *
 * Twin: sdk-python/tests/test_instance_guard.py. Both drive the claim
 * sequences in conformance/fixtures/instance_guard.json and must reach the
 * same outcome, because "one governing instance per process" has to mean the
 * same thing in a mixed-language shop.
 */
import * as fs from 'fs';
import * as path from 'path';
import {
  claimGoverningInstance,
  duplicateInstanceMessage,
  governingInstance,
  isGoverningInstance,
  _resetInstanceGuard,
} from '../../src/proxy/instance-guard';
import { init, _reset, getConfig } from '../../src/proxy/config';
import { obsvr } from '../../src/index';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';

function findFixture(rel: string): string {
  let dir = process.cwd();
  for (let i = 0; i < 6; i++) {
    const candidate = path.join(dir, rel);
    if (fs.existsSync(candidate)) return candidate;
    dir = path.dirname(dir);
  }
  throw new Error(`fixture not found upward from ${process.cwd()}: ${rel}`);
}

interface GuardCase {
  id: string;
  desc: string;
  claims: Array<{ version: string; instance_id: string }>;
  expect: Array<{
    governing: boolean;
    logs: number;
    incumbent_version?: string;
    incumbent_is_older?: boolean;
    message_contains?: string;
  }>;
}

const fixture = JSON.parse(
  fs.readFileSync(findFixture('conformance/fixtures/instance_guard.json'), 'utf-8'),
) as { cases: GuardCase[] };

describe('conformance: instance_guard sequences', () => {
  beforeEach(() => _resetInstanceGuard());
  afterEach(() => _resetInstanceGuard());

  for (const testCase of fixture.cases) {
    it(`${testCase.id}: ${testCase.desc}`, () => {
      // Each copy logs at most once, which is what the fixture's cumulative
      // `logs` count tracks.
      const logged = new Set<string>();
      let logCount = 0;

      testCase.claims.forEach((claim, i) => {
        const result = claimGoverningInstance(claim.version, claim.instance_id);
        if (!result.governing && !logged.has(claim.instance_id)) {
          logged.add(claim.instance_id);
          logCount += 1;
        }

        const expected = testCase.expect[i];
        expect(result.governing).toBe(expected.governing);
        expect(logCount).toBe(expected.logs);

        if (expected.incumbent_version !== undefined) {
          expect(result.incumbent?.version).toBe(expected.incumbent_version);
        }
        if (expected.incumbent_is_older !== undefined) {
          expect(result.incumbentIsOlder ?? false).toBe(expected.incumbent_is_older);
        }
        if (expected.message_contains !== undefined) {
          expect(duplicateInstanceMessage(result)).toContain(expected.message_contains);
        }
      });
    });
  }
});

describe('instance guard: the slot itself', () => {
  beforeEach(() => _resetInstanceGuard());
  afterEach(() => _resetInstanceGuard());

  it('is keyed by Symbol.for so every copy of the module sees the same slot', () => {
    claimGoverningInstance('0.10.0', 'copy-a');
    // A second copy of this module would compute Symbol.for(...) identically;
    // reading through the global with the same key is what that copy does.
    const slot = (globalThis as unknown as Record<symbol, unknown>)[
      Symbol.for('obsvr.sdk.governing_instance')
    ];
    expect(slot).toEqual({ version: '0.10.0', instanceId: 'copy-a' });
  });

  it('reports who governs and who does not', () => {
    claimGoverningInstance('0.10.0', 'copy-a');
    expect(governingInstance()?.instanceId).toBe('copy-a');
    expect(isGoverningInstance('copy-a')).toBe(true);
    expect(isGoverningInstance('copy-b')).toBe(false);
  });

  it('says what happened and what to do about it', () => {
    claimGoverningInstance('0.10.0', 'copy-a');
    const message = duplicateInstanceMessage(claimGoverningInstance('0.10.0', 'copy-b'));
    expect(message).toContain('[obsvr]');
    expect(message).toContain('NOT governed');
    expect(message).toContain('Deduplicate');
  });
});

describe('instance guard: end-to-end through init and wrap', () => {
  const realWarn = console.warn;
  beforeEach(() => {
    _resetInstanceGuard();
    _reset();
    _resetSender();
  });
  afterEach(() => {
    console.warn = realWarn;
    _resetInstanceGuard();
    _reset();
    _resetSender();
  });

  it('governs and wraps when this copy holds the slot', () => {
    obsvr.init({ api_key: 'test', policyRefreshIntervalMs: 0 });
    const client = { chat: { completions: { create: async () => ({}) } } };
    const wrapped = obsvr.wrap(client);
    expect(wrapped).not.toBe(client);
    expect(getConfig().api_key).toBe('test');
  });

  it('passes clients through untouched when another copy already governs', () => {
    // Simulate the other copy having initialized first.
    claimGoverningInstance('0.10.0', 'some-other-copy');

    const warnings: string[] = [];
    console.warn = (...args: unknown[]) => {
      warnings.push(args.join(' '));
    };

    obsvr.init({ api_key: 'test', policyRefreshIntervalMs: 0 });

    const client = { chat: { completions: { create: async () => ({}) } } };
    expect(obsvr.wrap(client)).toBe(client);
    expect(warnings.filter((w) => w.includes('already')).length).toBe(1);
  });

  it('still resolves config on the yielded copy, so callers do not crash', () => {
    claimGoverningInstance('0.10.0', 'some-other-copy');
    console.warn = () => {};
    obsvr.init({ api_key: 'test', policyRefreshIntervalMs: 0 });
    // Yielding is not disabling: config is resolved and readable, the copy
    // simply does not govern.
    expect(getConfig().api_key).toBe('test');
  });

  it('does not warn when the same copy re-initializes', () => {
    const warnings: string[] = [];
    console.warn = (...args: unknown[]) => {
      warnings.push(args.join(' '));
    };
    obsvr.init({ api_key: 'test', policyRefreshIntervalMs: 0 });
    obsvr.init({ api_key: 'test-2', policyRefreshIntervalMs: 0 });
    expect(warnings.filter((w) => w.includes('already governing')).length).toBe(0);
  });
});
