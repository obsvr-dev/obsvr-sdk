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

  it('wrapGenerate reads spec-v3 NESTED usage (the shape that silently emptied the counts)', async () => {
    // Measured off ai@7.0.41. `inputTokens`/`outputTokens` kept their NAMES and
    // became objects, and `totalTokens` was deleted outright — so every
    // `typeof v === "number"` guard answered "no tokens" while the event kept
    // arriving with prompt, response and resolved model intact. Nothing threw
    // and nothing was logged; only the numbers money depends on went missing.
    init({ api_key: 'test', sample_rate: 1 });
    const mw = obsvrMiddleware();
    const params = userParams('Hi there');

    const transformed = await mw.transformParams({ params, model: MODEL });
    await mw.wrapGenerate({
      doGenerate: async () => ({
        content: [{ type: 'text', text: 'Hello back' }],
        usage: {
          inputTokens: { total: 9, noCache: 9, cacheRead: 0, cacheWrite: 0 },
          outputTokens: { total: 3, text: 3, reasoning: 0 },
          raw: { input_tokens: 9, output_tokens: 3 },
        },
      }),
      params: transformed,
      model: MODEL,
    });

    await waitForEvents(1);
    const e = sentEvents[0];
    expect(e.input_tokens).toBe(9);
    expect(e.output_tokens).toBe(3);
    // Derived from the two counts, since the spec no longer states a total.
    expect(e.total_tokens).toBe(12);
  });

  it('wrapGenerate leaves counts ABSENT and says why when the usage shape is unknown', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const mw = obsvrMiddleware();
    const params = userParams('Hi there');

    const transformed = await mw.transformParams({ params, model: MODEL });
    await mw.wrapGenerate({
      doGenerate: async () => ({
        text: 'Hello back',
        usage: { tokens_consumed: 42 },
      }),
      params: transformed,
      model: MODEL,
    });

    await waitForEvents(1);
    const e = sentEvents[0];
    // Absent, NOT zero: a fabricated 0 here is indistinguishable from a call
    // that genuinely consumed nothing.
    expect(e.input_tokens).toBeUndefined();
    expect(e.output_tokens).toBeUndefined();
    expect(e.total_tokens).toBeUndefined();
    // ...and the reason rides reserved telemetry, so "obsvr could not read the
    // usage" is distinguishable from "the provider reported no usage".
    expect((e.metadata as any).obsvr_telemetry.usage_shape).toBe('unrecognized');
  });

  it('does not stamp a usage_shape reason when the provider simply reported nothing', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const mw = obsvrMiddleware();
    const params = userParams('Hi there');

    const transformed = await mw.transformParams({ params, model: MODEL });
    await mw.wrapGenerate({
      doGenerate: async () => ({ text: 'Hello back' }),
      params: transformed,
      model: MODEL,
    });

    await waitForEvents(1);
    const e = sentEvents[0];
    expect(e.input_tokens).toBeUndefined();
    expect((e.metadata as any)?.obsvr_telemetry?.usage_shape).toBeUndefined();
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
    expect(params.prompt).toEqual([
      { role: 'user', content: [{ type: 'text', text: 'mail john@example.com' }] },
    ]);
  });

  it('blocks PII in the system prompt before the model body runs', async () => {
    init({ api_key: 'test', sample_rate: 1, pii_policy: { rules: { ssn: 'block' } } });
    const mw = obsvrMiddleware();
    let modelCalls = 0;
    const params = { system: 'SSN 123-45-6789', ...userParams('safe request') };

    await expect(
      (async () => {
        const transformed = await mw.transformParams({ params, model: MODEL });
        return mw.wrapGenerate({
          doGenerate: async () => {
            modelCalls += 1;
            return { text: 'should not run' };
          },
          params: transformed,
          model: MODEL,
        });
      })(),
    ).rejects.toThrow('[obsvr] Request blocked by policy');
    expect(modelCalls).toBe(0);
  });

  it('blocks PII in an earlier message before the model body runs', async () => {
    init({ api_key: 'test', sample_rate: 1, pii_policy: { rules: { ssn: 'block' } } });
    const mw = obsvrMiddleware();
    let modelCalls = 0;
    const params = {
      prompt: [
        { role: 'user', content: [{ type: 'text', text: 'SSN 123-45-6789' }] },
        { role: 'assistant', content: [{ type: 'text', text: 'noted' }] },
        { role: 'user', content: [{ type: 'text', text: 'safe request' }] },
      ],
    };

    await expect(
      (async () => {
        const transformed = await mw.transformParams({ params, model: MODEL });
        return mw.wrapGenerate({
          doGenerate: async () => {
            modelCalls += 1;
            return { text: 'should not run' };
          },
          params: transformed,
          model: MODEL,
        });
      })(),
    ).rejects.toThrow('[obsvr] Request blocked by policy');
    expect(modelCalls).toBe(0);
  });

  it.each([
    ['V1 result', { type: 'tool-result', result: { value: 'SSN 123-45-6789' } }],
    [
      'V2 output',
      {
        type: 'tool-result',
        output: { type: 'json', value: { secret: 'SSN 123-45-6789' } },
      },
    ],
  ])('blocks PII in %s prompt parts', async (_label, part) => {
    init({ api_key: 'test', sample_rate: 1, pii_policy: { rules: { ssn: 'block' } } });
    const mw = obsvrMiddleware();
    let modelCalls = 0;
    const params = { prompt: [{ role: 'tool', content: [part] }] };

    await expect(
      (async () => {
        const transformed = await mw.transformParams({ params, model: MODEL });
        return mw.wrapGenerate({
          doGenerate: async () => {
            modelCalls += 1;
            return { text: 'should not run' };
          },
          params: transformed,
          model: MODEL,
        });
      })(),
    ).rejects.toThrow('[obsvr] Request blocked by policy');
    expect(modelCalls).toBe(0);
  });

  it('redacts system, string prompt, and tool output in provider-bound params', async () => {
    init({ api_key: 'test', sample_rate: 1, pii_policy: { rules: { email: 'redact' } } });
    const mw = obsvrMiddleware();
    const stringParams = { system: 'sys@example.com', prompt: 'user@example.com' };

    const transformedString: any = await mw.transformParams({
      params: stringParams,
      model: MODEL,
    });
    expect(JSON.stringify(transformedString)).not.toMatch(/sys@example|user@example/);
    expect(transformedString.system).toBe('[REDACTED_EMAIL]');
    expect(transformedString.prompt).toBe('[REDACTED_EMAIL]');

    const toolParams = {
      prompt: [
        {
          role: 'tool',
          content: [
            {
              type: 'tool-result',
              output: { type: 'json', value: { email: 'tool@example.com' } },
            },
          ],
        },
      ],
    };
    const transformedTool: any = await mw.transformParams({
      params: toolParams,
      model: MODEL,
    });
    expect(JSON.stringify(transformedTool)).not.toContain('tool@example.com');
    expect(JSON.stringify(transformedTool)).toContain('[REDACTED_EMAIL]');
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

  it('emits an ordinary monitor-mode call when not sampled', async () => {
    init({ api_key: 'test', sample_rate: 0, enforcement_mode: 'monitor' });
    const mw = obsvrMiddleware();
    const params = userParams('Hi');
    await mw.transformParams({ params, model: MODEL });
    await mw.wrapGenerate({
      doGenerate: async () => ({ text: 'x', usage: {} }),
      params,
      model: MODEL,
    });

    await waitForEvents(1);
    expect(sentEvents[0]).toMatchObject({ action_taken: 'allowed', response: 'x' });
  });

  it('exposes a configurable middlewareVersion', () => {
    expect((obsvrMiddleware() as any).middlewareVersion).toBe('v1');
    expect(
      (obsvrMiddleware({ middlewareVersion: 'v2' }) as any).middlewareVersion,
    ).toBe('v2');
  });
});
