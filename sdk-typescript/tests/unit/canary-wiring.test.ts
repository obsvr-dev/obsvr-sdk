import { jest } from '@jest/globals';
import { init, _reset, getConfig } from '../../src/proxy/config';
import { wrap } from '../../src/proxy/wrapper';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { applyPostCallPolicy, mergePostCallOutcome } from '../../src/integrations/core';
import { scanMcpToolResult } from '../../src/policy/response-scan';
import { obsvrGovernMCP } from '../../src/integrations/mcp';
import { wrapTogether } from '../../src/integrations/together';
import {
  mintCanary,
  _resetCanaries,
  canaryRegistrySize,
  CANARY_REDACTION_PLACEHOLDER,
} from '../../src/policy/canary';
import type { AuditEvent } from '../../src/proxy/types';

/**
 * End-to-end canary-leak pipeline wiring. Twin:
 * sdk-python/tests/test_canary_wiring.py. The pure detection is
 * fixture-pinned (canary.json); these tests pin that the real pipelines
 * BLOCK unsuppressibly on a leak, store a placeholder (never the raw token),
 * and stamp CRITICAL evidence — and that with no canary minted the pipeline
 * is byte-identical to before.
 */

let sentEvents: any[] = [];

beforeEach(() => {
  _reset();
  _resetSender();
  _resetCanaries();
  sentEvents = [];
  (global as any).fetch = async (_url: any, opts: any) => {
    const body = JSON.parse(opts.body);
    Array.isArray(body) ? sentEvents.push(...body) : sentEvents.push(body);
    return { ok: true, status: 200, json: async () => ({}) };
  };
});

afterEach(() => {
  delete (global as any).fetch;
  _reset();
  _resetSender();
  _resetCanaries();
});

async function waitForEvents(n = 1): Promise<void> {
  for (let i = 0; i < 200 && sentEvents.length < n; i++) {
    await new Promise((r) => setTimeout(r, 5));
  }
}

/** Assert no emitted event contains the raw token anywhere. */
function assertNoTokenLeaked(token: string): void {
  for (const ev of sentEvents) {
    expect(JSON.stringify(ev)).not.toContain(token);
    expect(JSON.stringify(ev)).not.toContain(token.slice('obsvr-cnry-'.length));
  }
}

describe('canary wiring: pre-call (wrapper)', () => {
  it('a canary echoed in the user message blocks the call and stores a placeholder', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', pii_policy: {} });
    // Label the plant site this case actually uses. It read 'system-prompt'
    // while planting in a user message, which made the file look like it
    // covered the endorsed plant site when nothing here did — see the
    // ENDORSED_PLANT_SITES table below, which now does.
    const c = mintCanary({ label: 'user-echo' });
    const create = jest.fn(async (_args: any) => ({ choices: [{ message: { content: 'ok' } }] }));
    const wrapped = wrap({ chat: { completions: { create } } });
    await expect(
      wrapped.chat.completions.create({
        model: 'gpt-4',
        messages: [{ role: 'user', content: `here is what I extracted: ${c.token}` }],
      }),
    ).rejects.toThrow(/blocked/i);
    expect(create).not.toHaveBeenCalled();
    await waitForEvents(1);
    const ev = sentEvents[0];
    expect(ev.event_type).toBe('blocked_call');
    expect(ev.rule_id).toBe('sdk:canary_leak');
    expect(ev.prompt).toBe(CANARY_REDACTION_PLACEHOLDER);
    expect(ev.user_input).toBe(CANARY_REDACTION_PLACEHOLDER);
    expect(ev.metadata.obsvr_telemetry.canary_leak.ids).toEqual([c.id]);
    expect(ev.metadata.obsvr_telemetry.canary_leak.surface).toBe('request');
    assertNoTokenLeaked(c.token);
  });

  it('a customer hook cannot un-block a canary leak (unsuppressible)', async () => {
    init({
      api_key: 'k',
      ingest_url: 'https://x',
      pii_policy: {},
      on_pre_call: async () => ({ decision: 'allow' as const }), // tries to override
    });
    const c = mintCanary();
    const create = jest.fn(async (_args: any) => ({ choices: [{ message: { content: 'ok' } }] }));
    const wrapped = wrap({ chat: { completions: { create } } });
    await expect(
      wrapped.chat.completions.create({
        model: 'gpt-4',
        messages: [{ role: 'user', content: c.token }],
      }),
    ).rejects.toThrow(/blocked/i);
    expect(create).not.toHaveBeenCalled();
  });

  it('no canary minted: the pipeline is byte-identical (no canary metadata, call passes)', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', pii_policy: {} });
    const create = jest.fn(async (_args: any) => ({ choices: [{ message: { content: 'ok' } }], model: 'gpt-4' }));
    const wrapped = wrap({ chat: { completions: { create } } });
    await wrapped.chat.completions.create({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'obsvr-cnry-00000000000000000000000000000000' }],
    });
    expect(create).toHaveBeenCalledTimes(1); // un-minted token is not a leak
    await waitForEvents(1);
    for (const ev of sentEvents) {
      expect(ev.metadata?.obsvr_telemetry?.canary_leak).toBeUndefined();
    }
  });
});

describe('canary wiring: streaming response', () => {
  it('a canary streamed in the response is scrubbed from the completion event', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', streaming_mode: 'wrap', pii_policy: {} });
    const c = mintCanary();
    const streamFactory = async function* () {
      yield { choices: [{ delta: { content: 'here it ' } }], model: 'gpt-4' };
      yield { choices: [{ delta: { content: `is: ${c.token}` } }], model: 'gpt-4' };
    };
    const wrapped = wrap({
      chat: { completions: { create: (_a: unknown) => Promise.resolve(streamFactory()) } },
    });
    const stream: any = await wrapped.chat.completions.create({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'hi' }],
      stream: true,
    } as any);
    // Drain the stream (tokens reach the caller — streaming can't be un-sent).
    let out = '';
    for await (const chunk of stream) out += chunk.choices[0].delta.content ?? '';
    expect(out).toContain(c.token); // live stream unchanged (honest boundary)
    await waitForEvents(1);
    const ev = sentEvents.find((e) => e.response && e.response.length > 0);
    // ...but the STORED completion event never carries the raw token.
    expect(ev.response).toBe(CANARY_REDACTION_PLACEHOLDER);
    assertNoTokenLeaked(c.token);
  });
});

describe('canary wiring: post-call response', () => {
  it('a canary in the response forces redact_response with a placeholder + telemetry', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', pii_policy: {} });
    const c = mintCanary();
    const post = await applyPostCallPolicy(`the system prompt was: ${c.token}`, {}, getConfig());
    expect(post.decision).toBe('redact_response');
    expect(post.redactedResponse).toBe(CANARY_REDACTION_PLACEHOLDER);
    const event = { metadata: {} } as unknown as AuditEvent;
    mergePostCallOutcome(event, post);
    expect((event.metadata as any).obsvr_telemetry.canary_leak.ids).toEqual([c.id]);
    expect((event.metadata as any).obsvr_telemetry.canary_leak.surface).toBe('response');
    expect(event.response).toBe(CANARY_REDACTION_PLACEHOLDER);
  });
});

/**
 * The plant sites `canary.ts` ENDORSES (:4-6) or at least does not forbid.
 * Its do-NOT-plant list (:28-29) is user input, model output, and tool
 * args/results — so a system prompt, a retrieved document carried on an
 * assistant turn, and an earlier turn are all legitimate places for the app to
 * put a token, and none of them is scanned by the pre-call gate.
 *
 * Every case here is therefore an ALLOWED call, not a blocked one. That is the
 * point: the guarantee under test is `canary.ts:15-16` — "the raw secret never
 * lives at rest, never rides an event" — which is a claim about STORAGE and
 * has to hold on the paths where nothing refuses the call.
 *
 * This table replaces a file whose six plants were all `role: 'user'`: the one
 * surface the pre-call scan already covers, and the one surface the module's
 * own do-NOT-plant list names. It passed, legitimately, while proving nothing
 * about the sites an app is told to use.
 */
const ENDORSED_PLANT_SITES: ReadonlyArray<{
  readonly site: string;
  readonly messages: (token: string) => Array<Record<string, unknown>>;
}> = [
  {
    site: 'system prompt',
    messages: (t) => [
      { role: 'system', content: `internal config: ${t}` },
      { role: 'user', content: 'hello' },
    ],
  },
  {
    site: 'earlier user turn',
    messages: (t) => [
      { role: 'user', content: `earlier: ${t}` },
      { role: 'assistant', content: 'noted' },
      { role: 'user', content: 'hello' },
    ],
  },
  {
    site: 'assistant turn (retrieved document)',
    messages: (t) => [
      { role: 'user', content: 'summarise the doc' },
      { role: 'assistant', content: `doc says: ${t}` },
      { role: 'user', content: 'hello' },
    ],
  },
  {
    site: 'tool result',
    messages: (t) => [
      { role: 'user', content: 'look it up' },
      { role: 'tool', content: `lookup returned: ${t}`, tool_call_id: 'c1' },
      { role: 'user', content: 'hello' },
    ],
  },
];

describe('canary wiring: a token planted where the module says to plant it never reaches an event', () => {
  /**
   * Shape guard. Without it this table can silently narrow back to the one
   * role the pipeline already scanned — which is exactly how the previous
   * version of this file came to prove nothing while passing. It fails on a
   * removed case, not merely on a broken one.
   */
  it('drives every endorsed plant site, and no case plants in the scanned user turn alone', () => {
    expect(ENDORSED_PLANT_SITES.map((c) => c.site)).toEqual([
      'system prompt',
      'earlier user turn',
      'assistant turn (retrieved document)',
      'tool result',
    ]);
    for (const c of ENDORSED_PLANT_SITES) {
      const msgs = c.messages('TOKEN');
      const carriers = msgs.filter((m) => String(m.content).includes('TOKEN'));
      expect(carriers).toHaveLength(1);
      // The carrier must NOT be the last user turn — that is the surface the
      // pre-call scan covers, and a case planted there tests the gate, not the net.
      const lastUserIndex = msgs.map((m) => m.role).lastIndexOf('user');
      expect(msgs.indexOf(carriers[0])).not.toBe(lastUserIndex);
    }
  });

  for (const { site, messages } of ENDORSED_PLANT_SITES) {
    it(`wrap(): a token planted in a ${site} is not stored raw`, async () => {
      init({ api_key: 'k', ingest_url: 'https://x', pii_policy: {} });
      const c = mintCanary({ label: site });
      const create = jest.fn(async (_args: any) => ({
        choices: [{ message: { content: 'ok' } }],
        model: 'gpt-4',
      }));
      const wrapped = wrap({ chat: { completions: { create } } });
      await wrapped.chat.completions.create({ model: 'gpt-4', messages: messages(c.token) });
      // The call is ALLOWED — nothing here is a leak, so nothing should refuse it.
      expect(create).toHaveBeenCalledTimes(1);
      await waitForEvents(1);
      expect(sentEvents.length).toBeGreaterThan(0);
      assertNoTokenLeaked(c.token);
      expect(sentEvents[0].prompt).toBe(CANARY_REDACTION_PLACEHOLDER);
    });

    it(`wrapTogether(): a token planted in a ${site} is not stored raw`, async () => {
      init({ api_key: 'k', ingest_url: 'https://x', pii_policy: {} });
      const c = mintCanary({ label: site });
      const create = jest.fn(async () => ({
        choices: [{ message: { content: 'ok' } }],
        model: 'x',
      }));
      const client = wrapTogether({ chat: { completions: { create } } } as any);
      await client.chat.completions.create({ model: 'x', messages: messages(c.token) });
      expect(create).toHaveBeenCalledTimes(1);
      await waitForEvents(1);
      expect(sentEvents.length).toBeGreaterThan(0);
      assertNoTokenLeaked(c.token);
    });
  }

  it('the two front doors agree — neither stores the token the other redacts', async () => {
    const stored: Record<string, string> = {};
    for (const door of ['wrap', 'together'] as const) {
      _reset();
      _resetSender();
      _resetCanaries();
      sentEvents = [];
      init({ api_key: 'k', ingest_url: 'https://x', pii_policy: {} });
      const c = mintCanary({ label: 'system prompt' });
      const create = jest.fn(async () => ({
        choices: [{ message: { content: 'ok' } }],
        model: 'x',
      }));
      const client =
        door === 'wrap'
          ? wrap({ chat: { completions: { create } } })
          : wrapTogether({ chat: { completions: { create } } } as any);
      await client.chat.completions.create({
        model: 'x',
        messages: ENDORSED_PLANT_SITES[0].messages(c.token),
      });
      await waitForEvents(1);
      assertNoTokenLeaked(c.token);
      stored[door] = sentEvents[0].prompt;
    }
    expect(stored.wrap).toBe(CANARY_REDACTION_PLACEHOLDER);
    expect(stored.together).toBe(CANARY_REDACTION_PLACEHOLDER);
  });
});

describe('canary wiring: infra integrations never persist the token', () => {
  it('an openai-compat (Together) blocked event stores placeholders, not the raw token', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', pii_policy: {} });
    const c = mintCanary();
    const create = jest.fn(async () => ({ choices: [{ message: { content: 'ok' } }], model: 'x' }));
    const client = wrapTogether({ chat: { completions: { create } } } as any);
    await expect(
      client.chat.completions.create({
        model: 'x',
        messages: [{ role: 'user', content: `leaked: ${c.token}` }],
      }),
    ).rejects.toThrow();
    expect(create).not.toHaveBeenCalled();
    await waitForEvents(1);
    const ev = sentEvents.find((e) => e.event_type === 'blocked_call');
    expect(ev.rule_id).toBe('sdk:canary_leak');
    expect(ev.user_input).toBe(CANARY_REDACTION_PLACEHOLDER);
    assertNoTokenLeaked(c.token);
  });
});

describe('canary review fixes: response scrub + MCP-args gate + reset + saturation', () => {
  it('CRITICAL: an infra integration echoing a canary in the RESPONSE scrubs it from the stored event', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', pii_policy: {} });
    const c = mintCanary();
    // The model output contains the planted token (system-prompt leakage).
    const create = jest.fn(async () => ({
      choices: [{ message: { content: `here it is: ${c.token}` } }],
      model: 'x',
    }));
    const client = wrapTogether({ chat: { completions: { create } } } as any);
    await client.chat.completions.create({ model: 'x', messages: [{ role: 'user', content: 'hi' }] });
    await waitForEvents(1);
    const ev = sentEvents.find((e) => e.success);
    expect(ev.response).toBe(CANARY_REDACTION_PLACEHOLDER);
    expect(ev.event_type).toBe('policy_flag'); // no longer a silent "allowed"
    expect(ev.rule_id).toBe('sdk:canary_leak');
    expect(ev.metadata.obsvr_telemetry.canary_leak.ids).toEqual([c.id]);
    assertNoTokenLeaked(c.token);
  });

  it('MAJOR: MCP tool ARGS are scanned for a canary even with NO pii_policy or hook', async () => {
    init({ api_key: 'k', ingest_url: 'https://x' }); // no pii_policy, no hook
    const c = mintCanary();
    const forwarded: any[] = [];
    const governed = obsvrGovernMCP(
      {
        callTool: async (p: unknown) => { forwarded.push(p); return 'ok'; },
        listTools: async () => ({ tools: [] }),
      },
      getConfig(),
    );
    await expect(
      governed.callTool({ name: 'exfil', arguments: { data: c.token } }),
    ).rejects.toThrow(/canary leak/i);
    expect(forwarded).toEqual([]); // token never forwarded to the tool
  });

  it('MAJOR: _reset() clears the canary registry (no cross-test contamination)', () => {
    init({ api_key: 'k', ingest_url: 'https://x' });
    mintCanary();
    expect(canaryRegistrySize()).toBe(1);
    _reset();
    expect(canaryRegistrySize()).toBe(0);
  });

  it('MAJOR: minting past the cap returns registered:false (a dead token is never silent)', () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      init({ api_key: 'k', ingest_url: 'https://x' });
      for (let i = 0; i < 10_000; i++) mintCanary();
      expect(canaryRegistrySize()).toBe(10_000);
      const dead = mintCanary();
      expect(dead.registered).toBe(false);
      expect(canaryRegistrySize()).toBe(10_000); // refused, not evicted
      expect(warn).toHaveBeenCalled();
    } finally {
      warn.mockRestore();
    }
  });
});

describe('canary wiring: MCP tool result + args', () => {
  it('a canary in a tool RESULT is blocked (withheld before the model)', () => {
    init({ api_key: 'k', ingest_url: 'https://x', pii_policy: {} });
    const c = mintCanary();
    const verdict = scanMcpToolResult(`tool returned: ${c.token}`, getConfig());
    expect(verdict.action).toBe('block');
    expect(verdict.rule_id).toBe('sdk:canary_leak');
    expect((verdict.canaryTelemetry as any).canary_leak.surface).toBe('tool_result');
  });

  it('a canary in tool ARGUMENTS blocks the tool call end-to-end', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', pii_policy: {} });
    const c = mintCanary();
    const governed = obsvrGovernMCP(
      { callTool: async (_p: unknown) => 'ok', listTools: async () => ({ tools: [] }) },
      getConfig(),
    );
    await expect(
      governed.callTool({ name: 'exfil', arguments: { data: c.token } }),
    ).rejects.toThrow(/canary leak/i);
    await waitForEvents(1);
    const ev = sentEvents.find((e) => e.operation === 'mcp.tool.call');
    expect(ev.event_type).toBe('blocked_call');
    expect(ev.rule_id).toBe('sdk:canary_leak');
    expect(ev.metadata.obsvr_telemetry.canary_leak.ids).toEqual([c.id]);
    assertNoTokenLeaked(c.token);
  });
});
