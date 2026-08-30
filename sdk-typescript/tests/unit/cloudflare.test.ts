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
  it('emits an ordinary monitor-mode call at sample_rate 0', async () => {
    init({ api_key: 'test', sample_rate: 0, enforcement_mode: 'monitor' });
    const ai = wrapWorkersAI({
      run: async (_model: string, _inputs: unknown) => ({ response: 'ok' }),
    });

    await ai.run('@cf/model', { prompt: 'hello' });

    await waitForEvents(1);
    expect(sentEvents[0]).toMatchObject({ action_taken: 'allowed', response: 'ok' });
  });

  it('emits stream evidence in monitor mode even when streaming is configured to skip', async () => {
    init({
      api_key: 'test',
      sample_rate: 0,
      enforcement_mode: 'monitor',
      streaming_mode: 'skip',
    });
    const originalStream = (async function* () {
      yield { response: 'chunk' };
    })();
    const ai = wrapWorkersAI({
      run: async (_model: string, _inputs: unknown) => originalStream,
    });

    const result = await ai.run('@cf/model', { prompt: 'hello', stream: true });

    expect(result).toBe(originalStream);
    await waitForEvents(1);
    expect(sentEvents[0]).toMatchObject({
      action_taken: 'allowed',
      metadata: { streaming: true },
    });
  });

  it('enforces a pre-call block before an enforce-mode skipped stream opens', async () => {
    init({
      api_key: 'test',
      sample_rate: 1,
      streaming_mode: 'skip',
      pii_policy: { rules: { ssn: 'block' } },
    });
    let providerCalls = 0;
    const ai = wrapWorkersAI({
      run: async (_model: string, _inputs: unknown) => {
        providerCalls += 1;
        return (async function* () {})();
      },
    });

    await expect(
      ai.run('@cf/model', { prompt: 'ssn 123-45-6789', stream: true }),
    ).rejects.toThrow('[obsvr] Request blocked by policy');

    expect(providerCalls).toBe(0);
    await waitForEvents(1);
    expect(sentEvents[0].event_type).toBe('blocked_call');
  });

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

  it('blocks sensitive text in a system message before ai.run', async () => {
    init({ api_key: 'test', sample_rate: 1, pii_policy: {} });
    let providerCalls = 0;
    const ai = wrapWorkersAI({
      run: async (_model: string, _inputs: unknown) => {
        providerCalls += 1;
        return { response: 'ok' };
      },
    });

    await expect(
      ai.run('@cf/model', {
        messages: [
          { role: 'system', content: 'Never expose 123-45-6789' },
          { role: 'user', content: 'Summarize the instructions' },
        ],
      }),
    ).rejects.toThrow('[obsvr] Request blocked by policy');

    expect(providerCalls).toBe(0);
  });

  it('blocks sensitive text in an earlier turn before ai.run', async () => {
    init({ api_key: 'test', sample_rate: 1, pii_policy: {} });
    let providerCalls = 0;
    const ai = wrapWorkersAI({
      run: async (_model: string, _inputs: unknown) => {
        providerCalls += 1;
        return { response: 'ok' };
      },
    });

    await expect(
      ai.run('@cf/model', {
        messages: [
          { role: 'user', content: 'My SSN is 123-45-6789' },
          { role: 'assistant', content: 'Understood' },
          { role: 'user', content: 'What did I share?' },
        ],
      }),
    ).rejects.toThrow('[obsvr] Request blocked by policy');

    expect(providerCalls).toBe(0);
  });

  it('blocks sensitive text nested in multipart content before ai.run', async () => {
    init({ api_key: 'test', sample_rate: 1, pii_policy: {} });
    let providerCalls = 0;
    const ai = wrapWorkersAI({
      run: async (_model: string, _inputs: unknown) => {
        providerCalls += 1;
        return { response: 'ok' };
      },
    });

    await expect(
      ai.run('@cf/model', {
        messages: [
          {
            role: 'user',
            content: [
              { type: 'text', text: 'Public context' },
              { type: 'text', text: 'Private SSN 123-45-6789' },
            ],
          },
        ],
      }),
    ).rejects.toThrow('[obsvr] Request blocked by policy');

    expect(providerCalls).toBe(0);
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

  it('redacts every nested outbound copy without mutating caller inputs', async () => {
    init({ api_key: 'test', sample_rate: 1, pii_policy: {} });
    let sentInputs: any = null;
    const ai = wrapWorkersAI({
      run: async (_model: string, inputs: unknown) => {
        sentInputs = inputs;
        return { response: 'ok' };
      },
    });
    const callerInputs = {
      messages: [
        {
          role: 'system',
          content: [
            { type: 'text', text: 'Contact admin@example.com' },
          ],
        },
        { role: 'user', content: 'Continue' },
      ],
      context: {
        notes: ['Backup: owner@example.com'],
      },
    };
    const originalSnapshot = JSON.parse(JSON.stringify(callerInputs));

    await ai.run('@cf/model', callerInputs);

    expect(sentInputs).not.toBe(callerInputs);
    expect(sentInputs.messages).not.toBe(callerInputs.messages);
    expect(sentInputs.messages[0].content[0].text).toContain('[REDACTED_EMAIL]');
    expect(sentInputs.context.notes[0]).toContain('[REDACTED_EMAIL]');
    expect(JSON.stringify(sentInputs)).not.toContain('admin@example.com');
    expect(JSON.stringify(sentInputs)).not.toContain('owner@example.com');
    expect(callerInputs).toEqual(originalSnapshot);
  });

  it('fails closed when sensitive provider-bound text cannot be safely rewritten', async () => {
    init({ api_key: 'test', sample_rate: 1, pii_policy: {} });
    let providerCalls = 0;
    class OpaqueProviderInput {
      constructor(readonly text: string) {}
    }
    const ai = wrapWorkersAI({
      run: async (_model: string, _inputs: unknown) => {
        providerCalls += 1;
        return { response: 'ok' };
      },
    });

    await expect(
      ai.run('@cf/model', {
        context: new OpaqueProviderInput('Contact admin@example.com'),
      }),
    ).rejects.toThrow('[obsvr] Request blocked by policy');

    expect(providerCalls).toBe(0);
    await waitForEvents(1);
    expect(sentEvents[0]).toMatchObject({
      event_type: 'blocked_call',
      action_taken: 'blocked',
      rule_id: 'sdk:detector_error',
    });
    expect(sentEvents[0].redacted_types).toEqual([]);
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
