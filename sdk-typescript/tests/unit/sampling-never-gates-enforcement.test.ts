import { jest } from '@jest/globals';
import { init, _reset } from '../../src/proxy/config';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { wrapOpenAICompatible } from '../../src/integrations/openai-compat';

/**
 * The sampling invariant, which is stated in five comments
 * (proxy/sender/sampling.ts, proxy/types.ts x2, proxy/wrapper.ts:1263,
 * sdk-python/obsvr/config.py) and, until this file, asserted by no test:
 *
 *   "Sampling gates audit EMISSION only - it never gates enforcement:
 *    PII/policy/hook/kill-switch checks run on every call regardless of
 *    sample_rate. Lowering sample_rate reduces ingest volume, not the
 *    per-call enforcement cost."
 *
 * sampling.test.ts covers the pure shouldSample(rate) frequency function, which
 * is a different claim. Nothing checked that the pipelines honour it, and they
 * did not: every integration that early-returned on an unsampled call returned
 * ABOVE its policy call, so at sample_rate 0 a blocking PII rule did not fire
 * and the provider received the raw SSN.
 *
 * Both halves are asserted here on purpose. Testing only H1 would pass an
 * implementation that emits unconditionally, trading a security bug for an
 * ingest-volume bug; and H2 is what makes H1 falsifiable, by proving
 * sample_rate really does reach this surface.
 *
 * Twin: sdk-python/tests/test_sampling_never_gates_enforcement.py
 */

const SSN = '123-45-6789';
let sentEvents: any[] = [];

beforeEach(() => {
  _reset();
  _resetSender();
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
});

async function settle(): Promise<void> {
  for (let i = 0; i < 100 && sentEvents.length === 0; i++) {
    await new Promise((r) => setTimeout(r, 5));
  }
  await new Promise((r) => setTimeout(r, 20));
}

function makeClient(reached: string[]) {
  const create = jest.fn(async (req: any) => {
    reached.push(JSON.stringify(req?.messages ?? req));
    return {
      id: 'cmpl-test',
      model: 'fake-model',
      choices: [{ message: { role: 'assistant', content: 'ok' }, finish_reason: 'stop' }],
      usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
    };
  });
  return { chat: { completions: { create } } };
}

async function call(sampleRate: number, content: string) {
  init({
    api_key: 'k',
    ingest_url: 'https://x',
    sample_rate: sampleRate,
    pii_policy: { rules: { ssn: 'block' } },
  } as any);
  const reached: string[] = [];
  const client = wrapOpenAICompatible(makeClient(reached), {
    provider: 'together',
    source: 'together',
  });
  let threw = false;
  try {
    await client.chat.completions.create({
      model: 'fake-model',
      messages: [{ role: 'user', content }],
    });
  } catch {
    threw = true;
  }
  await settle();
  return { threw, reached, providerSawRaw: reached.some((s) => s.includes(SSN)) };
}

describe('sampling gates emission, never enforcement', () => {
  // H1. The security half. Pre-fix this failed at sample_rate 0: the call was
  // not blocked and the provider received the SSN.
  it('blocks a PII violation at sample_rate 0, and never leaks it to the provider', async () => {
    const r = await call(0, `my ssn is ${SSN}`);
    expect(r.threw).toBe(true);
    expect(r.reached).toHaveLength(0);
    expect(r.providerSawRaw).toBe(false);
  });

  it('emits the blocked event at sample_rate 0 - enforcement evidence is never sampled out', async () => {
    await call(0, `my ssn is ${SSN}`);
    expect(sentEvents.length).toBeGreaterThanOrEqual(1);
    expect(sentEvents.map((e) => e.action_taken)).toContain('blocked');
  });

  it('behaves identically at sample_rate 1', async () => {
    const r = await call(1, `my ssn is ${SSN}`);
    expect(r.threw).toBe(true);
    expect(r.providerSawRaw).toBe(false);
    expect(sentEvents.map((e) => e.action_taken)).toContain('blocked');
  });

  // H2. The volume half, and the falsifiability control for H1: it proves
  // sample_rate genuinely reaches this surface, so the blocked event surviving
  // rate 0 above is an exemption for governed events rather than a dead gate.
  it('still samples OUT a clean allowed call at sample_rate 0', async () => {
    const r = await call(0, 'what is a good tomato variety for a cold climate');
    expect(r.threw).toBe(false);
    expect(r.reached).toHaveLength(1);
    expect(sentEvents).toHaveLength(0);
  });

  it('emits a clean allowed call at sample_rate 1', async () => {
    const r = await call(1, 'what is a good tomato variety for a cold climate');
    expect(r.threw).toBe(false);
    expect(sentEvents.length).toBeGreaterThanOrEqual(1);
    expect(sentEvents.map((e) => e.action_taken)).toContain('allowed');
  });
});
