import { init, _reset } from '../../src/proxy/config';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { wrapWorkersAI } from '../../src/integrations/cloudflare';

let sentEvents: any[] = [];
let fetchCalls: { url: string; opts: any }[] = [];

beforeEach(() => {
  _reset();
  _resetSender();
  sentEvents = [];
  fetchCalls = [];
  (global as any).fetch = async (url: any, opts: any) => {
    fetchCalls.push({ url: String(url), opts });
    sentEvents.push(JSON.parse(opts.body));
    return { ok: true, status: 200 };
  };
});

async function waitForEvents(n = 1): Promise<void> {
  for (let i = 0; i < 100 && sentEvents.length < n; i++) {
    await new Promise((r) => setTimeout(r, 5));
  }
}

describe('wrapWorkersAI', () => {
  it('audits ai.run with messages input', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const ai = wrapWorkersAI({
      run: async (_model: string, _inputs: any) => ({
        response: 'Workers AI says hi',
        usage: { prompt_tokens: 8, completion_tokens: 4, total_tokens: 12 },
      }),
    });

    const out: any = await ai.run('@cf/meta/llama-3-8b-instruct', {
      messages: [{ role: 'user', content: 'Hello' }],
    });

    expect(out.response).toBe('Workers AI says hi');
    await waitForEvents(1);
    const e = sentEvents[0];
    expect(e.provider).toBe('cloudflare');
    expect(e.source).toBe('cloudflare');
    expect(e.model).toBe('@cf/meta/llama-3-8b-instruct');
    expect(e.prompt).toContain('user: Hello');
    expect(e.response).toBe('Workers AI says hi');
    expect(e.input_tokens).toBe(8);
    expect(e.output_tokens).toBe(4);
  });

  it('supports prompt-style inputs', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const ai = wrapWorkersAI({
      run: async (_model: string, _inputs: any) => ({ response: 'ok' }),
    });

    await ai.run('@cf/model', { prompt: 'raw prompt text' });
    await waitForEvents(1);
    expect(sentEvents[0].prompt).toBe('raw prompt text');
  });

  it('delivers via ctx.waitUntil when provided', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const waited: Promise<unknown>[] = [];
    const ctx = { waitUntil: (p: Promise<unknown>) => waited.push(p) };

    const ai = wrapWorkersAI(
      { run: async (_model: string, _inputs: any) => ({ response: 'ok' }) },
      { ctx },
    );

    await ai.run('@cf/model', { prompt: 'hi' });
    expect(waited.length).toBe(1);
    await Promise.all(waited);

    expect(fetchCalls).toHaveLength(1);
    expect(fetchCalls[0].url).toContain('/ingest');
    expect(fetchCalls[0].opts.headers['X-API-Key']).toBe('test');
    expect(sentEvents[0].provider).toBe('cloudflare');
  });

  it('blocks calls containing an SSN', async () => {
    init({ api_key: 'test', sample_rate: 1, pii_policy: {} });
    let called = false;
    const ai = wrapWorkersAI({
      run: async (_model: string, _inputs: any) => {
        called = true;
        return { response: 'ok' };
      },
    });

    await expect(
      ai.run('@cf/model', {
        messages: [{ role: 'user', content: 'ssn 123-45-6789' }],
      }),
    ).rejects.toThrow('[obsvr] Request blocked by policy');

    expect(called).toBe(false);
    await waitForEvents(1);
    expect(sentEvents[0].event_type).toBe('blocked_call');
  });

  it('redacts email in inputs before calling', async () => {
    init({ api_key: 'test', sample_rate: 1, pii_policy: {} });
    let sentInputs: any = null;
    const ai = wrapWorkersAI({
      run: async (_m: string, inputs: any) => {
        sentInputs = inputs;
        return { response: 'ok' };
      },
    });

    await ai.run('@cf/model', { prompt: 'email john@example.com' });
    expect(sentInputs.prompt).toContain('[REDACTED_EMAIL]');
    await waitForEvents(1);
    expect(sentEvents[0].action_taken).toBe('redacted');
  });

  it('strips audit fields from inputs', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    let sentInputs: any = null;
    const ai = wrapWorkersAI({
      run: async (_m: string, inputs: any) => {
        sentInputs = inputs;
        return { response: 'ok' };
      },
    });

    await ai.run('@cf/model', {
      prompt: 'hi',
      request_id: 'req_9',
      source: 'worker-app',
    });

    expect(sentInputs).toEqual({ prompt: 'hi' });
    await waitForEvents(1);
    expect(sentEvents[0].request_id).toBe('req_9');
    expect(sentEvents[0].source).toBe('worker-app');
  });

  it('emits failure event when run throws', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const ai = wrapWorkersAI({
      run: async (_model: string, _inputs: any) => {
        throw new Error('model not found');
      },
    });

    await expect(ai.run('@cf/bad', { prompt: 'hi' })).rejects.toThrow(
      'model not found',
    );
    await waitForEvents(1);
    expect(sentEvents[0].success).toBe(false);
  });
});
