/** The proxy wrapper driven through the real maintained `@google/genai` package. */
import { GoogleGenAI } from '@google/genai';

import { init, _reset, wrap } from '../../src/proxy/index';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';

const realFetch = globalThis.fetch;
let sentEvents: any[] = [];
let providerCalls: Array<{ url: string; body: any }> = [];

const responseBody = (text: string, totalTokens = 10) => ({
  candidates: [
    {
      content: { role: 'model', parts: [{ text }] },
      finishReason: 'STOP',
      index: 0,
    },
  ],
  usageMetadata: {
    promptTokenCount: 7,
    candidatesTokenCount: totalTokens - 7,
    totalTokenCount: totalTokens,
  },
  modelVersion: 'gemini-2.5-flash-001',
});

const BLOCK_RULE = {
  id: 'block-launch',
  name: 'block launch codes',
  enabled: true,
  action: 'block' as const,
  type: 'keyword' as const,
  conditions: { keywords: ['launch codes'] },
};

function buildClient() {
  return new GoogleGenAI({ apiKey: 'test-key-not-real' });
}

async function waitForEvents(n = 1): Promise<void> {
  for (let i = 0; i < 200 && sentEvents.length < n; i++) {
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

beforeEach(() => {
  _reset();
  _resetSender();
  sentEvents = [];
  providerCalls = [];
  globalThis.fetch = (async (input: string | URL | Request, options?: RequestInit) => {
    const url = String(input);
    const rawBody = typeof options?.body === 'string' ? options.body : '{}';
    const parsedUrl = URL.canParse(url) ? new URL(url) : null;
    if (parsedUrl?.hostname === 'generativelanguage.googleapis.com') {
      providerCalls.push({ url, body: JSON.parse(rawBody) });
      if (url.includes('streamGenerateContent')) {
        const chunks = [responseBody('a ', 8), responseBody('fine answer', 10)];
        return new Response(
          chunks.map((chunk) => `data: ${JSON.stringify(chunk)}\n\n`).join(''),
          { status: 200, headers: { 'content-type': 'text/event-stream' } },
        );
      }
      const structured = rawBody.includes('application/json');
      return new Response(
        JSON.stringify(responseBody(structured ? '{"answer":"fine"}' : 'a fine answer')),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }

    const body = JSON.parse(rawBody);
    const batch = Array.isArray(body) ? body : [body];
    sentEvents.push(...batch);
    return {
      status: 200,
      ok: true,
      json: async () => ({ count: batch.length }),
    } as Response;
  }) as typeof fetch;
});

afterEach(() => {
  globalThis.fetch = realFetch;
  _reset();
  _resetSender();
});

describe('wrap() against the real maintained @google/genai package', () => {
  it('allows a unary call and audits the package response getter and usage', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const client = wrap(buildClient());

    const result = await client.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: 'hello there',
    });
    await waitForEvents();

    expect(result.text).toBe('a fine answer');
    expect(providerCalls).toHaveLength(1);
    expect(providerCalls[0].url).toContain('gemini-2.5-flash:generateContent');
    expect(sentEvents.find((event) => event.operation === 'models.generateContent')).toMatchObject({
      provider: 'google',
      model: 'gemini-2.5-flash',
      model_resolved: 'gemini-2.5-flash-001',
      prompt: 'hello there',
      response: 'a fine answer',
      total_tokens: 10,
      action_taken: 'allowed',
    });
  });

  it('blocks before the maintained package reaches its transport', async () => {
    init({ api_key: 'test', sample_rate: 1, policy_rules: [BLOCK_RULE] });
    const client = wrap(buildClient());

    await expect(
      client.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: 'tell me the launch codes',
      }),
    ).rejects.toThrow(/blocked by policy/i);
    await waitForEvents();

    expect(providerCalls).toEqual([]);
    expect(sentEvents.find((event) => event.action_taken === 'blocked')).toMatchObject({
      operation: 'models.generateContent',
      rule_id: BLOCK_RULE.id,
    });
  });

  it('redacts text before the real package serializes the provider request', async () => {
    init({ api_key: 'test', sample_rate: 1, pii_policy: { default: 'redact' } });
    const request = {
      model: 'gemini-2.5-flash',
      contents: 'email john@example.com please',
      config: { systemInstruction: 'Reply to jane@example.com' },
    };
    const original = structuredClone(request);

    await wrap(buildClient()).models.generateContent(request);

    expect(request).toEqual(original);
    expect(providerCalls).toHaveLength(1);
    const providerBody = JSON.stringify(providerCalls[0].body);
    expect(providerBody).toContain('[REDACTED_EMAIL]');
    expect(providerBody).not.toContain('john@example.com');
    expect(providerBody).not.toContain('jane@example.com');
  });

  it('preserves structured-output config through the real package transport', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const client = wrap(buildClient());

    const result = await client.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: 'return a structured answer',
      config: {
        responseMimeType: 'application/json',
        responseJsonSchema: {
          type: 'object',
          properties: { answer: { type: 'string' } },
          required: ['answer'],
        },
      },
    });
    await waitForEvents();

    expect(result.text).toBe('{"answer":"fine"}');
    expect(providerCalls[0].body.generationConfig).toMatchObject({
      responseMimeType: 'application/json',
      responseJsonSchema: { required: ['answer'] },
    });
    expect(sentEvents.find((event) => event.operation === 'models.generateContent')).toMatchObject({
      response: '{"answer":"fine"}',
    });
  });

  it('wraps the real async stream and audits its drained aggregate', async () => {
    init({ api_key: 'test', sample_rate: 1, streaming_mode: 'wrap' });
    const client = wrap(buildClient());

    const stream = await client.models.generateContentStream({
      model: 'gemini-2.5-flash',
      contents: 'stream this',
    });
    const chunks: string[] = [];
    for await (const chunk of stream) chunks.push(chunk.text ?? '');
    await waitForEvents();

    expect(chunks).toEqual(['a ', 'fine answer']);
    expect(providerCalls[0].url).toContain('streamGenerateContent');
    expect(sentEvents.find((event) => event.operation === 'models.generateContentStream')).toMatchObject({
      model: 'gemini-2.5-flash',
      model_resolved: 'gemini-2.5-flash-001',
      prompt: 'stream this',
      response: 'a fine answer',
      total_tokens: 10,
      action_taken: 'allowed',
    });
  });
});
