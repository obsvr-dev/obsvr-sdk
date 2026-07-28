import { jest } from '@jest/globals';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { init, _reset, getConfig } from '../../src/proxy/config';
import { wrap } from '../../src/proxy/wrapper';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { applyPreCallPolicy, type IntegrationProvider } from '../../src/integrations/core';
import type { PolicyRule } from '../../src/policy/rules';

/**
 * Cross-SDK, cross-ENTRY-POINT pre-call eval-context conformance (TS side).
 * Twin: sdk-python/tests/test_eval_context_conformance.py.
 *
 * Each fixture case is asserted TWICE here — once through wrap() and once
 * through applyPreCallPolicy — because those are the two doors into the
 * TypeScript pre-call pipeline and they build the rules context separately.
 * Python has one shared pre-call, so its twin asserts once. A model_gate or
 * environment_gate rule reads nothing but this context, which is what makes
 * the two rule types the probe: if the context differs by door, they are the
 * first thing to notice, and they notice silently by never firing.
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

interface ContextCase {
  id: string;
  rule: PolicyRule;
  environment: 'development' | 'staging' | 'production';
  model: string;
  provider: string;
  prompt: string;
  expect: { decision: 'allow' | 'block' | 'redact'; rule_id?: string };
}

const fixture = JSON.parse(
  fs.readFileSync(findFixture('conformance/fixtures/eval_context.json'), 'utf-8'),
) as { precall_context_cases: ContextCase[] };

/** decision -> the action_taken the wrapper stamps on the emitted event. */
const ACTION_FOR: Record<string, string> = {
  allow: 'allowed',
  block: 'blocked',
  redact: 'redacted',
};

let sentEvents: Array<Record<string, unknown>> = [];

beforeEach(() => {
  _reset();
  _resetSender();
  sentEvents = [];
  (global as unknown as { fetch: unknown }).fetch = async (_url: unknown, opts: { body: string }) => {
    const body = JSON.parse(opts.body);
    Array.isArray(body) ? sentEvents.push(...body) : sentEvents.push(body);
    return { ok: true, status: 200, json: async () => ({}) };
  };
});

afterEach(() => {
  delete (global as unknown as { fetch?: unknown }).fetch;
  _reset();
  _resetSender();
});

async function waitForEvents(n = 1): Promise<void> {
  for (let i = 0; i < 200 && sentEvents.length < n; i++) {
    await new Promise((r) => setTimeout(r, 5));
  }
}

describe('conformance: pre-call eval context via the integrations path', () => {
  for (const c of fixture.precall_context_cases) {
    it(c.id, async () => {
      init({
        api_key: 'k',
        ingest_url: 'https://x',
        environment: c.environment,
        policy_rules: [c.rule],
      });
      const res = await applyPreCallPolicy(c.prompt, {
        config: getConfig(),
        provider: c.provider as IntegrationProvider,
        operation: 'test',
        model: c.model,
      });
      expect(res.decision).toBe(c.expect.decision);
      if (c.expect.rule_id !== undefined) {
        expect(res.compliance.rule_id).toBe(c.expect.rule_id);
      }
    });
  }
});

describe('conformance: pre-call eval context via the proxy wrapper', () => {
  for (const c of fixture.precall_context_cases) {
    it(c.id, async () => {
      init({
        api_key: 'k',
        ingest_url: 'https://x',
        environment: c.environment,
        policy_rules: [c.rule],
      });
      const create = jest.fn(async (_a: unknown) => ({
        choices: [{ message: { content: 'ok' } }],
      }));
      // An OpenAI-shaped stub, so detectProvider resolves the provider the
      // fixture declares and all three paths gate on one value.
      const wrapped = wrap({ chat: { completions: { create } } }) as {
        chat: { completions: { create: (a: unknown) => Promise<unknown> } };
      };
      const call = wrapped.chat.completions.create({
        model: c.model,
        messages: [{ role: 'user', content: c.prompt }],
      });
      if (c.expect.decision === 'block') {
        await expect(call).rejects.toThrow(/blocked/i);
        expect(create).not.toHaveBeenCalled();
      } else {
        await call;
        expect(create).toHaveBeenCalled();
      }
      await waitForEvents(1);
      expect(sentEvents[0].action_taken).toBe(ACTION_FOR[c.expect.decision]);
      if (c.expect.rule_id !== undefined) {
        expect(sentEvents[0].rule_id).toBe(c.expect.rule_id);
      }
    });
  }
});
