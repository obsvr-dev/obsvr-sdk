import { jest } from '@jest/globals';
import { init, _reset, getConfig } from '../../src/proxy/config';
import { wrap } from '../../src/proxy/wrapper';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { _resetInjectionSessions } from '../../src/policy/injection-session';
import { _resetCanaries } from '../../src/policy/canary';
import { _resetSessionTaint } from '../../src/policy/session-taint';
import { applyPreCallPolicy } from '../../src/integrations/core';
import { obsvrGovernTool, _resetGovernedToolNames } from '../../src/integrations/tools';
import type { PolicyRule } from '../../src/policy/rules';

/**
 * THE INVARIANT: an `allowed` verdict must be EVIDENCED.
 *
 *     action_taken == "allowed"  =>  the record carries decision_input_hash
 *
 * and a surface that could not consult a CONFIGURED policy layer records
 * `not_evaluated` instead of `allowed`.
 *
 * WHY THIS IS THE OTHER HALF OF THE ENFORCEMENT SUITE
 * ---------------------------------------------------
 * enforcement-reporting-invariant.test.ts polices "blocked implies not
 * executed" — that a refusal is real. Nothing policed the reverse, and the
 * reverse is where a Severity 1 got through: a deployment whose only policy was
 * a customer rule set did not arm the pre-call pipeline at the tool and MCP
 * boundaries, so a call whose arguments matched a block rule EXECUTED, returned
 * its result, and recorded `allowed` — a verdict the rule set was never asked
 * for. Every "blocked implies not executed" assertion held throughout, because
 * nothing ever claimed `blocked`. An invariant that only grades refusals cannot
 * see a gate that stopped running.
 *
 * WHY decision_input_hash IS THE EVIDENCE, RATHER THAN A NEW FIELD
 * ----------------------------------------------------------------
 * It is the SHA-256 of the canonical decision-input document (ADR-2), computed
 * at exactly one place per language, INSIDE the pipeline, from the inputs the
 * decision was actually made on. A surface that skipped evaluation has no
 * decision input, so it cannot produce one — which is what makes its absence
 * meaningful rather than merely untidy.
 *
 * The fields that look like they would serve do not:
 *   - `policy_version` is derived from the CONFIGURED rules, so the unarmed MCP
 *     path stamped a real rules hash on a call the rules never saw.
 *   - `action_source` is "unknown" on a legitimate permit that matched no rule,
 *     so it cannot separate "evaluated, nothing matched" from "never ran".
 * Both were measured before this file was written; neither can carry the claim.
 *
 * WHAT IT DELIBERATELY DOES NOT ASSERT
 * ------------------------------------
 * That an `allowed` record with NO policy configured carries evidence. With
 * nothing configured there is no policy verdict to evidence, and the record
 * claims none — `action_source` is "unknown" and no layer is named. The defect
 * class is a CONFIGURED policy that silently did not run, so that is the
 * condition every row below holds.
 */

const BLOCK_RULE: PolicyRule = {
  id: 'r-forbidden',
  name: 'r-forbidden',
  enabled: true,
  action: 'block',
  type: 'keyword',
  conditions: { keywords: ['forbidden'] },
} as PolicyRule;

let sent: any[] = [];

beforeEach(() => {
  _reset();
  _resetSender();
  _resetInjectionSessions();
  _resetCanaries();
  _resetSessionTaint();
  _resetGovernedToolNames();
  sent = [];
  (global as any).fetch = async (_url: any, opts: any) => {
    const body = JSON.parse(opts.body);
    Array.isArray(body) ? sent.push(...body) : sent.push(body);
    return { ok: true, status: 200, json: async () => ({}) };
  };
});

afterEach(() => {
  delete (global as any).fetch;
  _reset();
  _resetSender();
  _resetSessionTaint();
});

/** The invariant, as one function every surface below is graded by. */
function assertAllowedIsEvidenced(event: any, where: string) {
  if (event.action_taken !== 'allowed') return; // blocked / redacted / not_evaluated are out of scope
  expect({
    where,
    action_taken: event.action_taken,
    has_decision_input_hash: Boolean(event.decision_input_hash),
    engine_version: event.engine_version ?? null,
  }).toEqual({
    where,
    action_taken: 'allowed',
    has_decision_input_hash: true,
    engine_version: expect.any(String),
  });
}

async function settle() {
  await new Promise((r) => setTimeout(r, 10));
}

// ── Surface 1: the proxy wrapper (LLM calls) ────────────────────────────────
describe('allowed implies evaluated: wrap() LLM path', () => {
  const client = () => {
    const create = jest.fn(async (_a: any) => ({ choices: [{ message: { content: 'ok' } }] }));
    return wrap({ chat: { completions: { create } } });
  };

  it('a rule set that PERMITS still evidences the evaluation', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', policy_rules: [BLOCK_RULE] });
    await client().chat.completions.create({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'perfectly fine' }],
      metadata: { user_id: 'alice' },
    } as any);
    await settle();
    const ev = sent.find((e) => e.operation === 'chat.completions.create');
    expect(ev.action_taken).toBe('allowed');
    assertAllowedIsEvidenced(ev, 'wrap/permit');
  });

  it('the same rule set REFUSES the matching call, and says so', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', policy_rules: [BLOCK_RULE] });
    await expect(
      client().chat.completions.create({
        model: 'gpt-4',
        messages: [{ role: 'user', content: 'this is forbidden' }],
        metadata: { user_id: 'alice' },
      } as any),
    ).rejects.toThrow();
    await settle();
    const ev = sent.find((e) => e.operation === 'chat.completions.create');
    expect(ev.action_taken).toBe('blocked');
    expect(ev.action_source).toBe('policy_rules');
  });
});

// ── Surface 2: the shared integrations pre-call pipeline ────────────────────
describe('allowed implies evaluated: applyPreCallPolicy (the integrations seam)', () => {
  // Each policy kind ALONE. The Severity 1 was invisible precisely because any
  // OTHER entry in the arming list — even an empty PII policy — made the rule
  // set work, so a table that always configures two layers cannot see it.
  const ONLY: Array<[string, Record<string, unknown>]> = [
    ['policy_rules alone', { policy_rules: [BLOCK_RULE] }],
    ['pii_policy alone', { pii_policy: { default: 'detect_only' } }],
    ['policyFloor alone', { policyFloor: [BLOCK_RULE] }],
  ];

  for (const [label, cfg] of ONLY) {
    it(`${label}: a permitted call carries the evaluation evidence`, async () => {
      init({ api_key: 'k', ingest_url: 'https://x', ...(cfg as any) });
      const r = await applyPreCallPolicy('perfectly fine', {
        config: getConfig(),
        provider: 'unknown',
        operation: 'tool.call',
        metadata: { user_id: 'alice' },
      });
      expect(r.decision).toBe('allow');
      expect(r.compliance.action_taken).toBe('allowed');
      expect(r.compliance.decision_input_hash).toEqual(expect.any(String));
      expect(r.compliance.engine_version).toEqual(expect.any(String));
    });
  }

  it('policyRules alone REFUSES a matching call (the arming leg, from the block side)', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', policy_rules: [BLOCK_RULE] });
    const r = await applyPreCallPolicy('this is forbidden', {
      config: getConfig(),
      provider: 'unknown',
      operation: 'tool.call',
      metadata: { user_id: 'alice' },
    });
    expect(r.decision).toBe('block');
    expect(r.compliance.action_taken).toBe('blocked');
  });
});

// ── Surface 3: obsvrGovernTool ─────────────────────────────────────────────
describe('allowed implies evaluated: obsvrGovernTool', () => {
  const governed = (ran: { v: boolean }) =>
    obsvrGovernTool(
      { name: 'calc', execute: (_i: unknown) => { ran.v = true; return 'done'; } },
      { name: 'calc', metadata: { user_id: 'alice' } },
    );

  it('with NO policy configured the permit is honest: it names no deciding layer', () => {
    init({ api_key: 'k', ingest_url: 'https://x' });
    const ran = { v: false };
    expect(governed(ran).execute({ q: 'hello' })).toBe('done');
    const ev = sent.find((e) => e.operation === 'tool.call');
    expect(ev.action_taken).toBe('allowed');
    // Nothing was configured, so nothing was skipped and nothing is claimed.
    // `policy_rules` here was the false attribution this invariant removed.
    expect(ev.action_source).toBe('unknown');
  });

  it('with a rule set CONFIGURED the record says not_evaluated, never allowed', () => {
    // This synchronous gate cannot await the async pre-call pipeline, so the
    // rule set genuinely does not run here. That is a coverage gap. Recording
    // `allowed` for it was a false record, and this is the line between them.
    init({ api_key: 'k', ingest_url: 'https://x', policy_rules: [BLOCK_RULE] });
    const ran = { v: false };
    expect(governed(ran).execute({ q: 'forbidden' })).toBe('done');
    const ev = sent.find((e) => e.operation === 'tool.call');
    expect(ev.action_taken).toBe('not_evaluated');
    expect(ev.action_taken).not.toBe('allowed');
    assertAllowedIsEvidenced(ev, 'governTool/rules-configured');
  });

  it('the skipped layer is NAMED on the record, not merely omitted', () => {
    init({
      api_key: 'k',
      ingest_url: 'https://x',
      policy_rules: [BLOCK_RULE],
      pii_policy: { default: 'detect_only' },
    });
    governed({ v: false }).execute({ q: 'hello' });
    const ev = sent.find((e) => e.operation === 'tool.call');
    const notEvaluated = ev.metadata?.obsvr_telemetry?.policy_not_evaluated;
    expect(notEvaluated).toBeDefined();
    expect(notEvaluated.surface).toBe('obsvr_tool');
    expect(notEvaluated.gate).toContain('policy_rules');
    expect(notEvaluated.gate).toContain('pii_policy');
    expect(notEvaluated.reason).toMatch(/cannot await the pre-call pipeline/i);
  });

  it('a gate this surface DOES own still refuses, and is recorded as a block', () => {
    // The point of the row above is that not_evaluated is scoped to the layers
    // that did not run — it must not become a blanket excuse that swallows the
    // enforcement this boundary really does perform.
    init({ api_key: 'k', ingest_url: 'https://x', agent_policy: { deniedTools: ['calc'] } });
    const ran = { v: false };
    expect(() => governed(ran).execute({ q: 'hello' })).toThrow(/blocked by agent policy/i);
    expect(ran.v).toBe(false);
    const ev = sent.find((e) => e.operation === 'tool.policy.tool_blocked');
    expect(ev.action_taken).toBe('blocked');
  });
});

// ── The sweep: nothing anywhere claims an unevidenced permit ───────────────
describe('allowed implies evaluated: every event emitted by the drives above', () => {
  it('holds across a mixed workload', async () => {
    init({
      api_key: 'k',
      ingest_url: 'https://x',
      policy_rules: [BLOCK_RULE],
      pii_policy: { default: 'detect_only' },
    });
    const create = jest.fn(async (_a: any) => ({ choices: [{ message: { content: 'ok' } }] }));
    const c = wrap({ chat: { completions: { create } } });
    await c.chat.completions.create({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'fine' }],
      metadata: { user_id: 'alice' },
    } as any);
    obsvrGovernTool(
      { name: 'calc', execute: (_i: unknown) => 'done' },
      { name: 'calc', metadata: { user_id: 'alice' } },
    ).execute({ q: 'hello' });
    await settle();

    expect(sent.length).toBeGreaterThanOrEqual(2);
    for (const ev of sent) {
      assertAllowedIsEvidenced(ev, `${ev.operation}/${ev.source}`);
    }
  });
});
