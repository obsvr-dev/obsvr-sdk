import { jest } from '@jest/globals';
import { init, _reset } from '../../src/proxy/config';
import { wrap } from '../../src/proxy/wrapper';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';

/**
 * The layered cost reaches the record. Twin:
 * sdk-python/tests/test_cost_wiring.py.
 *
 * The resolution itself is pinned in cost.json; what these pin is that a real
 * call resolves it from real usage, that all three layers survive to the event
 * rather than being collapsed to the best one, and that an unconfigured
 * deployment's events are byte-identical to before.
 */

const RATES = {
  currency: 'USD',
  rates: { 'gpt-4': { input_micros_per_1k: 30_000, output_micros_per_1k: 60_000 } },
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
  for (let i = 0; i < 400 && sentEvents.length < n; i++) {
    await new Promise((r) => setTimeout(r, 5));
  }
}

function stubClient(usage: { prompt_tokens: number; completion_tokens: number }) {
  const create = jest.fn(async (_a: unknown) => ({
    choices: [{ message: { content: 'ok' } }],
    model: 'gpt-4',
    usage: {
      ...usage,
      total_tokens: usage.prompt_tokens + usage.completion_tokens,
    },
  }));
  const wrapped = wrap({ chat: { completions: { create } } }) as {
    chat: { completions: { create: (a: unknown) => Promise<unknown> } };
  };
  return { create, wrapped };
}

function costOf(event: Record<string, unknown>): Record<string, unknown> | undefined {
  return (event.metadata as { obsvr_cost?: Record<string, unknown> } | undefined)?.obsvr_cost;
}

describe('layered cost reaches the record', () => {
  it('meters real usage at the operator rates', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', costPolicy: RATES });
    const { wrapped } = stubClient({ prompt_tokens: 1000, completion_tokens: 500 });
    await wrapped.chat.completions.create({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'hi' }],
    });
    await waitForEvents(1);
    expect(costOf(sentEvents[0])).toEqual({
      currency: 'USD',
      metered_micros: 30_000 + 30_000, // 1000@30k/1k + 500@60k/1k
    });
  });

  it('keeps the caller estimate alongside the correction, with the gap', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', costPolicy: RATES });
    const { wrapped } = stubClient({ prompt_tokens: 1000, completion_tokens: 0 });
    await wrapped.chat.completions.create({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'hi' }],
      metadata: { cost_estimate_micros: 1_000 },
    });
    await waitForEvents(1);
    // The estimate was thirty times under. That is exactly the finding the
    // record has to preserve, so both numbers and their difference survive.
    expect(costOf(sentEvents[0])).toEqual({
      currency: 'USD',
      estimate_micros: 1_000,
      estimate_source: 'caller',
      metered_micros: 30_000,
      delta_micros: 29_000,
    });
  });

  it('an operator-declared cost overrides what the caller claimed', async () => {
    init({
      api_key: 'k',
      ingest_url: 'https://x',
      costPolicy: { ...RATES, declared: { 'gpt-4': 50_000 } },
    });
    const { wrapped } = stubClient({ prompt_tokens: 1000, completion_tokens: 0 });
    await wrapped.chat.completions.create({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'hi' }],
      metadata: { cost_estimate_micros: 1_000 },
    });
    await waitForEvents(1);
    const cost = costOf(sentEvents[0]);
    expect(cost?.estimate_micros).toBe(50_000);
    expect(cost?.estimate_source).toBe('policy');
    expect(cost?.delta_micros).toBe(-20_000);
  });

  it('a caller cannot overwrite the sealed cost with its own metadata key', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', costPolicy: RATES });
    const { wrapped } = stubClient({ prompt_tokens: 1000, completion_tokens: 0 });
    await wrapped.chat.completions.create({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'hi' }],
      metadata: { obsvr_cost: { metered_micros: 1 } },
    });
    await waitForEvents(1);
    expect(costOf(sentEvents[0])?.metered_micros).toBe(30_000);
  });

  it('no cost policy: no cost metadata, events byte-stable', async () => {
    init({ api_key: 'k', ingest_url: 'https://x' });
    const { wrapped } = stubClient({ prompt_tokens: 1000, completion_tokens: 500 });
    await wrapped.chat.completions.create({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'hi' }],
    });
    await waitForEvents(1);
    expect(costOf(sentEvents[0])).toBeUndefined();
  });

  it('a model with no declared rate gets no metered figure rather than a guess', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', costPolicy: RATES });
    const create = jest.fn(async (_a: unknown) => ({
      choices: [{ message: { content: 'ok' } }],
      model: 'some-unpriced-model',
      usage: { prompt_tokens: 1000, completion_tokens: 0, total_tokens: 1000 },
    }));
    const wrapped = wrap({ chat: { completions: { create } } }) as {
      chat: { completions: { create: (a: unknown) => Promise<unknown> } };
    };
    await wrapped.chat.completions.create({
      model: 'some-unpriced-model',
      messages: [{ role: 'user', content: 'hi' }],
    });
    await waitForEvents(1);
    expect(costOf(sentEvents[0])).toBeUndefined();
  });
});
