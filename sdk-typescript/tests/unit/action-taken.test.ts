/**
 * The closed `action_taken` set, pinned against the shared fixture.
 *
 * Twin: sdk-python/tests/test_action_taken.py. Neither language compares itself
 * to the other; both compare themselves to
 * `conformance/fixtures/action_taken.json`, which makes the agreement transitive
 * and makes a divergence fail in the language that caused it.
 *
 * WHY THIS FIXTURE EXISTS. `not_evaluated` was a live production value in both
 * SDKs, emitted from several surfaces, and pinned by nothing: only `allowed`,
 * `blocked` and a single `null` appeared anywhere in 31 fixtures. The two
 * languages agreed because they had been widened in the same commit — agreement
 * by coincidence, and the pattern every other cross-language defect in this
 * codebase followed.
 *
 * The union-to-set binding is checked by the COMPILER, in
 * `src/governance/action-taken.ts`, because the union is declared in two places
 * and neither derives from the other. This file pins the set to the fixture and
 * checks containment on real emission paths.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as url from 'node:url';
import { init, getConfig, _reset } from '../../src/proxy/config';
import { _resetSender, flushQueue } from '../../src/proxy/sender/fire-and-forget';
import { ACTION_TAKEN } from '../../src/governance/action-taken';
import { obsvrGovernTool } from '../../src/integrations/tools';
import { toolGateNotEvaluatedCompliance } from '../../src/integrations/core';

const HERE = path.dirname(url.fileURLToPath(import.meta.url));
const FIXTURE = JSON.parse(
  fs.readFileSync(
    path.resolve(HERE, '../../../conformance/fixtures/action_taken.json'),
    'utf8',
  ),
) as {
  verdicts: string[];
  semantics: Array<Record<string, string>>;
};

let sentEvents: Record<string, unknown>[] = [];
const realFetch = globalThis.fetch;

beforeEach(() => {
  _reset();
  _resetSender();
  sentEvents = [];
  globalThis.fetch = (async (_u: unknown, opts?: { body?: string }) => {
    const body = JSON.parse(opts?.body ?? '[]');
    sentEvents.push(...(Array.isArray(body) ? body : [body]));
    return { ok: true, status: 200, json: async () => ({ count: 1 }) };
  }) as unknown as typeof fetch;
});

afterEach(() => {
  globalThis.fetch = realFetch;
});

describe('the closed action_taken set', () => {
  it('equals the fixture', () => {
    expect([...ACTION_TAKEN]).toEqual(FIXTURE.verdicts);
  });

  it('is stored sorted in the fixture', () => {
    // So an order-sensitive comparison is safe on both sides. One language
    // sorting at assertion time and the other not would hide a real difference.
    expect(FIXTURE.verdicts).toEqual([...FIXTURE.verdicts].sort());
  });

  it('has no duplicates', () => {
    expect(new Set(ACTION_TAKEN).size).toBe(ACTION_TAKEN.length);
  });

  it('documents semantics for every verdict', () => {
    const documented = new Set(FIXTURE.semantics.map((e) => e.verdict));
    expect([...documented].sort()).toEqual([...FIXTURE.verdicts].sort());
  });

  it('pins the three things not_evaluated must never do', () => {
    // Each was a real defect here: a record claiming `allowed` about a call no
    // gate saw, one claiming `blocked` about a call that completed, and an
    // absent field the server then defaulted to `allowed`.
    const entry = FIXTURE.semantics.find((e) => e.verdict === 'not_evaluated')!;
    expect(entry.must_not_be_read_as).toContain('allowed');
    expect(entry.must_not_be_read_as).toContain('blocked');
    expect(entry.must_not_be_omitted).toBeTruthy();
    expect(entry.reason_travels_on).toContain('policy_not_evaluated');
  });
});

describe('containment', () => {
  it('the shared not-evaluated helper stays inside the set', () => {
    expect(ACTION_TAKEN).toContain(toolGateNotEvaluatedCompliance('s', 'g', 'r').action_taken);
  });

  it('every verdict a real emission path produces is in the set', async () => {
    // Containment over an emission path rather than over a helper. A
    // helper-only check passes while an integration hand-builds a compliance
    // object carrying a value nothing pins — which is how this value came to
    // exist in several places at once.
    init({
      api_key: 'test',
      sample_rate: 1,
      ingest_url: 'https://sink.invalid/v1',
      agent_policy: { deniedTools: ['send_money'] },
    } as never);

    const allowed = obsvrGovernTool(
      { name: 'get_weather', execute: () => 'ok' },
      { name: 'get_weather' },
    ) as { execute: (i: unknown) => unknown };
    await allowed.execute({});

    const denied = obsvrGovernTool(
      { name: 'send_money', execute: () => 'ran' },
      { name: 'send_money' },
    ) as { execute: (i: unknown) => unknown };
    await expect(denied.execute({ amount: 1 })).rejects.toThrow();

    await new Promise((r) => setTimeout(r, 20));
    await flushQueue(getConfig());

    expect(sentEvents.length).toBeGreaterThan(0);
    const seen = new Set(
      sentEvents.map((e) => e.action_taken).filter((v): v is string => typeof v === 'string'),
    );
    expect(seen.size).toBeGreaterThan(0);
    for (const verdict of seen) expect(ACTION_TAKEN).toContain(verdict);
    // Both directions of the gate are exercised, so the containment assertion
    // is not passing over a path that only ever emits one value.
    expect(seen.has('allowed')).toBe(true);
    expect(seen.has('blocked')).toBe(true);
  });
});
