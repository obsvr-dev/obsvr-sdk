/** Maintained @google/genai client shape: client.models.*. */
import { init, _reset, wrap } from '../../src/proxy/index';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';

const realFetch = globalThis.fetch;
let auditEvents: any[] = [];
let providerRequests: any[] = [];

const response = (text: string, model = 'gemini-2.5-flash-001') => ({
  text,
  modelVersion: model,
  candidates: [{ content: { role: 'model', parts: [{ text }] }, finishReason: 'STOP' }],
  usageMetadata: {
    promptTokenCount: 4,
    candidatesTokenCount: 2,
    totalTokenCount: 6,
  },
});

class FakeGoogleGenAI {
  models = {
    generateContent: async (request: any) => {
      providerRequests.push(request);
      return response(
        request.config?.responseMimeType === 'application/json'
          ? '{"answer":"fine"}'
          : 'a fine answer',
      );
    },
    generateContentStream: async (request: any) => {
      providerRequests.push(request);
      return (async function* () {
        yield response('a ', 'gemini-2.5-flash-001');
        yield response('fine answer', 'gemini-2.5-flash-001');
      })();
    },
  };
}

const BLOCK_RULE = {
  id: 'block-launch',
  name: 'block launch codes',
  enabled: true,
  action: 'block' as const,
  type: 'keyword' as const,
  conditions: { keywords: ['launch codes'] },
};

async function waitForEvents(n = 1): Promise<void> {
  for (let i = 0; i < 200 && auditEvents.length < n; i++) {
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

beforeEach(() => {
  _reset();
  _resetSender();
  auditEvents = [];
  providerRequests = [];
  globalThis.fetch = (async (_url: unknown, options?: { body?: string }) => {
    const body = JSON.parse(options?.body ?? '{}');
    auditEvents.push(...(Array.isArray(body) ? body : [body]));
    return { status: 200, ok: true, json: async () => ({ count: Array.isArray(body) ? body.length : 1 }) };
  }) as unknown as typeof fetch;
});

afterEach(() => {
  globalThis.fetch = realFetch;
  _reset();
  _resetSender();
});

describe('wrap() maintained @google/genai shape', () => {
  it('allows and audits models.generateContent with request and resolved models', async () => {
    init({ api_key: 'test', ingest_url: 'https://audit.example', sample_rate: 1 });
    const client = wrap(new FakeGoogleGenAI());

    const result = await client.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: 'hello there',
    });
    await waitForEvents();

    expect(result.text).toBe('a fine answer');
    expect(providerRequests).toHaveLength(1);
    const event = auditEvents.find((candidate) => candidate.operation === 'models.generateContent');
    expect(event).toMatchObject({
      provider: 'google',
      model: 'gemini-2.5-flash',
      model_resolved: 'gemini-2.5-flash-001',
      prompt: 'hello there',
      response: 'a fine answer',
      total_tokens: 6,
      action_taken: 'allowed',
    });
  });

  it('blocks before models.generateContent reaches the provider', async () => {
    init({
      api_key: 'test',
      ingest_url: 'https://audit.example',
      sample_rate: 1,
      policy_rules: [BLOCK_RULE],
    });
    const client = wrap(new FakeGoogleGenAI());

    await expect(
      client.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: 'tell me the launch codes',
      }),
    ).rejects.toThrow(/blocked by policy/i);
    await waitForEvents();

    expect(providerRequests).toEqual([]);
    expect(auditEvents.find((event) => event.action_taken === 'blocked')).toMatchObject({
      operation: 'models.generateContent',
      model: 'gemini-2.5-flash',
      rule_id: BLOCK_RULE.id,
    });
  });

  it('blocks a stream before models.generateContentStream reaches the provider', async () => {
    init({
      api_key: 'test',
      ingest_url: 'https://audit.example',
      sample_rate: 1,
      streaming_mode: 'wrap',
      policy_rules: [BLOCK_RULE],
    });
    const client = wrap(new FakeGoogleGenAI());

    await expect(
      client.models.generateContentStream({
        model: 'gemini-2.5-flash',
        contents: 'tell me the launch codes',
      }),
    ).rejects.toThrow(/blocked by policy/i);
    await waitForEvents();

    expect(providerRequests).toEqual([]);
    expect(auditEvents.find((event) => event.action_taken === 'blocked')).toMatchObject({
      operation: 'models.generateContentStream',
      rule_id: BLOCK_RULE.id,
    });
  });

  it('redacts string contents and system instruction without mutating the caller', async () => {
    init({
      api_key: 'test',
      ingest_url: 'https://audit.example',
      sample_rate: 1,
      pii_policy: { default: 'redact' },
    });
    const request = {
      model: 'gemini-2.5-flash',
      contents: 'email john@example.com please',
      config: { systemInstruction: 'Reply to jane@example.com' },
    };
    const original = structuredClone(request);

    await wrap(new FakeGoogleGenAI()).models.generateContent(request);

    expect(request).toEqual(original);
    expect(providerRequests[0].contents).toContain('[REDACTED_EMAIL]');
    expect(providerRequests[0].config.systemInstruction).toContain('[REDACTED_EMAIL]');
  });

  it('preserves structured-output config and audits its JSON text', async () => {
    init({ api_key: 'test', ingest_url: 'https://audit.example', sample_rate: 1 });
    const request = {
      model: 'gemini-2.5-flash',
      contents: [{ role: 'user', parts: [{ text: 'return a structured answer' }] }],
      config: {
        responseMimeType: 'application/json',
        responseJsonSchema: {
          type: 'object',
          properties: { answer: { type: 'string' } },
          required: ['answer'],
        },
      },
    };

    const result = await wrap(new FakeGoogleGenAI()).models.generateContent(request);
    await waitForEvents();

    expect(result.text).toBe('{"answer":"fine"}');
    expect(providerRequests[0].config).toEqual(request.config);
    expect(auditEvents.find((event) => event.operation === 'models.generateContent')).toMatchObject({
      prompt: 'user: return a structured answer',
      response: '{"answer":"fine"}',
    });
  });

  it('wraps models.generateContentStream and audits the drained aggregate', async () => {
    init({
      api_key: 'test',
      ingest_url: 'https://audit.example',
      sample_rate: 1,
      streaming_mode: 'wrap',
    });
    const stream = await wrap(new FakeGoogleGenAI()).models.generateContentStream({
      model: 'gemini-2.5-flash',
      contents: 'stream this',
    });
    const seen: string[] = [];
    for await (const chunk of stream) seen.push(chunk.text);
    await waitForEvents();

    expect(seen).toEqual(['a ', 'fine answer']);
    expect(auditEvents.find((event) => event.operation === 'models.generateContentStream')).toMatchObject({
      model: 'gemini-2.5-flash',
      model_resolved: 'gemini-2.5-flash-001',
      prompt: 'stream this',
      response: 'a fine answer',
      total_tokens: 6,
      action_taken: 'allowed',
    });
  });
});
