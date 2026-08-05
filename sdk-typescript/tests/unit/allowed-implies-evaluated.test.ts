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
//
// WHY THIS SURFACE IS ASYNC, AND WHY THAT WAS THE RIGHT ANSWER.
//
// The gate here was synchronous and never consulted the pre-call pipeline at
// all, so the floor, the rule set, the PII policy, the hook and the external
// backend were inert on every governed tool call while Python enforced all of
// them — the largest functional divergence between the two SDKs. Three routes
// were measured before this one was taken:
//
//   a SYNCHRONOUS entry point into the pipeline. Feasible on paper: every
//     `await` in applyPreCallPolicy sits behind an opt-in (Presidio, the
//     approval wait, the customer hook, the external backend), so the
//     deterministic layers need no I/O. Rejected because those awaits are
//     INTERLEAVED with the deterministic ones rather than bookending them, so a
//     sync path has to re-implement the orchestration — precedence,
//     floor-over-rules, monitor conversion, reason-code resolution — and two
//     copies of that rule drifting apart is the defect class this repository
//     keeps finding.
//
//   a SPLIT, sync layers inline and async layers opt-in. Same duplicated
//     orchestration, plus a verdict whose meaning depends on configuration.
//
//   an ASYNC gate (this). One pipeline, no second copy, full parity — and the
//     only route that can run the awaited layers at all. Its cost is a
//     breaking contract: a wrapped tool returns a Promise even around a
//     synchronous tool, and a refusal rejects instead of throwing.
//
// That cost was measured, not assumed: every framework whose tool shape
// `resolveExecKey` resolves awaits what it gets back — LangChain
// (`await this._call` into `this.func`), Vercel AI (`await executeToolCall`),
// the OpenAI tool runner (`await fn.function`), `@openai/agents` (async
// `invoke`), MCP (async by protocol), and LlamaIndex, whose tool return type is
// declared `JSONValue | Promise<JSONValue>`. The 679-check integration harness,
// which drives the real client libraries, is unchanged by it.
describe('allowed implies evaluated: obsvrGovernTool', () => {
  const governed = (ran: { v: boolean }) =>
    obsvrGovernTool(
      { name: 'calc', execute: (_i: unknown) => { ran.v = true; return 'done'; } },
      { name: 'calc', metadata: { user_id: 'alice' } },
    );

  it('with NO policy configured the permit is honest: it names no deciding layer', async () => {
    init({ api_key: 'k', ingest_url: 'https://x' });
    const ran = { v: false };
    expect(await governed(ran).execute({ q: 'hello' })).toBe('done');
    const ev = sent.find((e) => e.operation === 'tool.call');
    expect(ev.action_taken).toBe('allowed');
    // Nothing was configured, so nothing evaluated and nothing is claimed.
    // `policy_rules` here was the false attribution this invariant removed.
    expect(ev.action_source).toBe('unknown');
  });

  it('a rule set that PERMITS is evidenced, exactly as the wrap() path is', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', policy_rules: [BLOCK_RULE] });
    const ran = { v: false };
    expect(await governed(ran).execute({ q: 'perfectly fine' })).toBe('done');
    expect(ran.v).toBe(true); // control: a permit really is a permit
    const ev = sent.find((e) => e.operation === 'tool.call');
    expect(ev.action_taken).toBe('allowed');
    assertAllowedIsEvidenced(ev, 'governTool/permit');
  });

  it('the same rule set REFUSES the matching call before the tool body runs', async () => {
    // The whole point of the change: this call used to execute, return its
    // result to the caller, and record a permit the rule set was never asked
    // for. Graded on the side effect and the record, not on the rejection.
    init({ api_key: 'k', ingest_url: 'https://x', policy_rules: [BLOCK_RULE] });
    const ran = { v: false };
    await expect(governed(ran).execute({ q: 'forbidden' })).rejects.toThrow(
      /Tool blocked by policy/i,
    );
    expect(ran.v).toBe(false);
    const ev = sent.find((e) => e.operation === 'tool.call');
    expect(ev.action_taken).toBe('blocked');
    expect(ev.action_source).toBe('policy_rules');
  });

  it('a PII policy alone reaches this surface too', async () => {
    // Each layer armed ALONE, because the Severity 1 was invisible precisely
    // when a second layer was present to arm the pipeline for the first.
    init({ api_key: 'k', ingest_url: 'https://x', pii_policy: { default: 'block' } });
    const ran = { v: false };
    await expect(governed(ran).execute({ ssn: '123-45-6789' })).rejects.toThrow(/\[obsvr\]/);
    expect(ran.v).toBe(false);
    const ev = sent.find((e) => e.operation === 'tool.call');
    expect(ev.action_taken).toBe('blocked');
  });

  it('the wrapped tool is a Promise even around a SYNCHRONOUS tool', async () => {
    // The contract this surface now makes, stated where a reader will meet it.
    // The tool below returns a string; the gate hands back a Promise, because
    // consulting the pipeline means awaiting it. A framework awaits this and
    // never notices; direct callers must.
    init({ api_key: 'k', ingest_url: 'https://x', policy_rules: [BLOCK_RULE] });
    const returned = governed({ v: false }).execute({ q: 'fine' });
    expect(returned).toBeInstanceOf(Promise);
    expect(await returned).toBe('done');
  });

  it('a gate this surface owns ITSELF still refuses, and is recorded as a block', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', agent_policy: { deniedTools: ['calc'] } });
    const ran = { v: false };
    await expect(governed(ran).execute({ q: 'hello' })).rejects.toThrow(
      /blocked by agent policy/i,
    );
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
