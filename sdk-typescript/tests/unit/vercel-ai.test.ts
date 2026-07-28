import { init, _reset } from '../../src/proxy/config';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { obsvrMiddleware } from '../../src/integrations/vercel-ai';

let sentEvents: any[] = [];

beforeEach(() => {
  _reset();
  _resetSender();
  sentEvents = [];
  (global as any).fetch = async (_url: any, opts: any) => {
    sentEvents.push(JSON.parse(opts.body));
    return { ok: true, status: 200 };
  };
});

async function waitForEvents(n = 1): Promise<void> {
  for (let i = 0; i < 100 && sentEvents.length < n; i++) {
    await new Promise((r) => setTimeout(r, 5));
  }
}

const MODEL = { modelId: 'gpt-4o', provider: 'openai.chat' };

function userParams(text: string): Record<string, unknown> {
  return {
    prompt: [{ role: 'user', content: [{ type: 'text', text }] }],
  };
}

describe('obsvrMiddleware', () => {
  it('wrapGenerate emits event with v1 result shape', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const mw = obsvrMiddleware();
    const params = userParams('Hi there');

    const transformed = await mw.transformParams({ params, model: MODEL });
    const result = await mw.wrapGenerate({
      doGenerate: async () => ({
        text: 'Hello back',
        usage: { promptTokens: 9, completionTokens: 3 },
      }),
      params: transformed,
      model: MODEL,
    });

    expect((result as any).text).toBe('Hello back');
    await waitForEvents(1);
    const e = sentEvents[0];
    expect(e.source).toBe('vercel_ai');
    expect(e.provider).toBe('openai');
    expect(e.model).toBe('gpt-4o');
    expect(e.prompt).toContain('user: Hi there');
    expect(e.response).toBe('Hello back');
    expect(e.input_tokens).toBe(9);
    expect(e.output_tokens).toBe(3);
    expect(e.total_tokens).toBe(12);
  });

  it('wrapGenerate captures the resolved model from response.modelId', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const mw = obsvrMiddleware();
    const params = userParams('Hi');

    await mw.transformParams({ params, model: MODEL });
    await mw.wrapGenerate({
      doGenerate: async () => ({
        text: 'ok',
        usage: { inputTokens: 1, outputTokens: 1, totalTokens: 2 },
        response: { modelId: 'gpt-4o-2024-08-06' },
      }),
      params,
      model: MODEL,
    });

    await waitForEvents(1);
    expect(sentEvents[0].model).toBe('gpt-4o');
    expect(sentEvents[0].model_resolved).toBe('gpt-4o-2024-08-06');
    // Read from the AI SDK's response abstraction → framework-mediated tier.
    expect(sentEvents[0].provenance_source).toBe('framework_reported');
  });

  it('wrapGenerate handles v2 content-array results', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const mw = obsvrMiddleware();
    const params = userParams('Hi');

    await mw.transformParams({ params, model: MODEL });
    await mw.wrapGenerate({
      doGenerate: async () => ({
        content: [{ type: 'text', text: 'v2 response' }],
        usage: { inputTokens: 5, outputTokens: 2, totalTokens: 7 },
      }),
      params,
      model: MODEL,
    });

    await waitForEvents(1);
    expect(sentEvents[0].response).toBe('v2 response');
    expect(sentEvents[0].input_tokens).toBe(5);
    expect(sentEvents[0].total_tokens).toBe(7);
  });

  it('transformParams blocks SSN prompts (real pre-call enforcement)', async () => {
    init({ api_key: 'test', sample_rate: 1, pii_policy: {} });
    const mw = obsvrMiddleware();

    await expect(
      mw.transformParams({
        params: userParams('my ssn is 123-45-6789'),
        model: MODEL,
      }),
    ).rejects.toThrow('[obsvr] Request blocked by policy');

    await waitForEvents(1);
    expect(sentEvents[0].event_type).toBe('blocked_call');
    expect(sentEvents[0].status_code).toBe(403);
  });

  it('transformParams redacts email in params', async () => {
    init({ api_key: 'test', sample_rate: 1, pii_policy: {} });
    const mw = obsvrMiddleware();
    const params = userParams('mail john@example.com');

    const transformed: any = await mw.transformParams({ params, model: MODEL });
    expect(transformed.prompt[0].content[0].text).toContain(
      '[REDACTED_EMAIL]',
    );
    expect(transformed.prompt[0].content[0].text).not.toContain(
      'john@example.com',
    );
  });

  it('wrapStream accumulates text-delta chunks (v1 + v2 shapes)', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const mw = obsvrMiddleware();
    const params = userParams('Hi');
    await mw.transformParams({ params, model: MODEL });

    const chunks = [
      { type: 'text-delta', textDelta: 'Hel' },
      { type: 'text-delta', delta: 'lo' },
      { type: 'finish', usage: { inputTokens: 4, outputTokens: 2 } },
    ];
    const stream = new ReadableStream({
      start(controller) {
        for (const c of chunks) controller.enqueue(c);
        controller.close();
      },
    });

    const result: any = await mw.wrapStream({
      doStream: async () => ({ stream }),
      params,
      model: MODEL,
    });

    const reader = result.stream.getReader();
    const seen: unknown[] = [];
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      seen.push(value);
    }
    expect(seen).toHaveLength(3);

    await waitForEvents(1);
    expect(sentEvents[0].operation).toBe('stream');
    expect(sentEvents[0].response).toBe('Hello');
    expect(sentEvents[0].input_tokens).toBe(4);
    expect(sentEvents[0].output_tokens).toBe(2);
  });

  it('emits failure event when doGenerate throws', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const mw = obsvrMiddleware();
    const params = userParams('Hi');
    await mw.transformParams({ params, model: MODEL });

    await expect(
      mw.wrapGenerate({
        doGenerate: async () => {
          throw new Error('provider down');
        },
        params,
        model: MODEL,
      }),
    ).rejects.toThrow('provider down');

    await waitForEvents(1);
    expect(sentEvents[0].success).toBe(false);
  });

  it('skips audit when not sampled', async () => {
    init({ api_key: 'test', sample_rate: 0 });
    const mw = obsvrMiddleware();
    const params = userParams('Hi');
    await mw.transformParams({ params, model: MODEL });
    await mw.wrapGenerate({
      doGenerate: async () => ({ text: 'x', usage: {} }),
      params,
      model: MODEL,
    });
    await new Promise((r) => setTimeout(r, 20));
    expect(sentEvents).toHaveLength(0);
  });

  it('exposes a configurable middlewareVersion', () => {
    expect((obsvrMiddleware() as any).middlewareVersion).toBe('v1');
    expect(
      (obsvrMiddleware({ middlewareVersion: 'v2' }) as any).middlewareVersion,
    ).toBe('v2');
  });
});
