import { jest } from '@jest/globals';
import { init, _reset, getConfig } from '../../src/proxy/config';
import { wrap } from '../../src/proxy/wrapper';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { applyPreCallPolicy } from '../../src/integrations/core';
import type { PolicyRule } from '../../src/policy/rules';

/**
 * A policy rule declaring action "redact" has to redact on the proxy wrapper
 * path, the same way it already does through every framework integration and
 * through the Python shared pre-call. The wrapper previously handled only the
 * block verdict from the rules engine, so a redact rule let the call out
 * untouched and recorded "allowed" — the audit trail disagreeing with the
 * policy that was in force.
 *
 * Also pinned: the failure direction. Application of an enforcement decision
 * fails CLOSED regardless of failMode, because policy already decided the
 * content must be removed and forwarding it under a "redacted" record is
 * strictly worse than refusing the call.
 */

const REDACT_RULE: PolicyRule[] = [
  {
    id: 'r-redact',
    name: 'Redact outbound support transcripts',
    enabled: true,
    action: 'redact',
    type: 'keyword',
    conditions: { keywords: ['support transcript'] },
  } as PolicyRule,
];

const PROMPT = 'support transcript from customer casey@example.com';

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

describe('policy rules: a redact verdict is applied on the wrapper path', () => {
  it('redacts the outgoing prompt and records the deciding rule', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', policy_rules: REDACT_RULE });
    const create = jest.fn(async (_a: unknown) => ({ choices: [{ message: { content: 'ok' } }] }));
    const wrapped = wrap({ chat: { completions: { create } } }) as {
      chat: { completions: { create: (a: unknown) => Promise<unknown> } };
    };
    await wrapped.chat.completions.create({
      model: 'gpt-4',
      messages: [{ role: 'user', content: PROMPT }],
    });

    expect(create).toHaveBeenCalled();
    const forwarded = JSON.stringify((create.mock.calls[0] as unknown[])[0]);
    expect(forwarded).not.toContain('casey@example.com');

    await waitForEvents(1);
    expect(sentEvents[0].action_taken).toBe('redacted');
    expect(sentEvents[0].action_reason).toBe('policy_violation');
    expect(sentEvents[0].rule_id).toBe('r-redact');
  });

  it('reaches the same verdict as the integrations path for the same rule', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', policy_rules: REDACT_RULE });
    const res = await applyPreCallPolicy(PROMPT, {
      config: getConfig(),
      provider: 'openai',
      operation: 'test',
      model: 'gpt-4',
    });
    expect(res.decision).toBe('redact');
    expect(res.compliance.rule_id).toBe('r-redact');
  });

  it('blocks rather than forwards when the redaction cannot be applied', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', policy_rules: REDACT_RULE });
    const create = jest.fn(async (_a: unknown) => ({ choices: [{ message: { content: 'ok' } }] }));
    const wrapped = wrap({ chat: { completions: { create } } }) as {
      chat: { completions: { create: (a: unknown) => Promise<unknown> } };
    };
    // A message the redactor can read but cannot COPY. This was a frozen
    // message, back when the walk wrote to the caller's object; it now copies,
    // so a frozen message is redacted successfully and the call goes through
    // (pinned in detector-guard-outbound.test.ts). A message that cannot be
    // copied at all is still a genuine "the removal could not be carried out",
    // which is what this phase means and what must still fail closed.
    const frozen = new Proxy(
      { role: 'user', content: PROMPT },
      {
        ownKeys() {
          throw new Error('message cannot be copied');
        },
      },
    );
    // The redactor logs the failure itself; keep the suite output clean.
    const errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    try {
      await expect(
        wrapped.chat.completions.create({ model: 'gpt-4', messages: [frozen] }),
      ).rejects.toThrow(/blocked/i);
    } finally {
      errSpy.mockRestore();
    }
    expect(create).not.toHaveBeenCalled();

    await waitForEvents(1);
    expect(sentEvents[0].action_taken).toBe('blocked');
    expect(sentEvents[0].redacted_types).toEqual([]);
    expect(
      (sentEvents[0].metadata as { obsvr_telemetry?: { detector_failure?: { phase?: string } } })
        ?.obsvr_telemetry?.detector_failure?.phase,
    ).toBe('enforcement_application');
  });
});
