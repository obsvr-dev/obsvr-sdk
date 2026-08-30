/** Vertex chat enforcement through the official package object shapes. */
import { VertexAI } from '@google-cloud/vertexai';
import { jest } from '@jest/globals';

import { wrapVertexAI } from '../../src/integrations/vertex';
import { wrap } from '../../src/proxy/index';
import { init, _reset } from '../../src/proxy/config';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';

const realFetch = globalThis.fetch;
let sentEvents: any[] = [];
let providerCalls: Array<{ request: unknown; history: unknown }> = [];

const RESPONSE = {
  candidates: [
    {
      content: { role: 'model', parts: [{ text: 'done' }] },
      finishReason: 'STOP',
    },
  ],
  usageMetadata: {
    promptTokenCount: 2,
    candidatesTokenCount: 1,
    totalTokenCount: 3,
  },
  modelVersion: 'gemini-1.5-pro-002',
};

function buildModel() {
  const vertex = new VertexAI({ project: 'test-project', location: 'us-central1' });
  return vertex.getGenerativeModel({
    model: 'gemini-1.5-pro',
  });
}

function buildPreviewModel() {
  const vertex = new VertexAI({ project: 'test-project', location: 'us-central1' });
  return vertex.preview.getGenerativeModel({ model: 'gemini-1.5-pro' });
}

async function waitForEvents(n = 1): Promise<void> {
  for (let i = 0; i < 100 && sentEvents.length < n; i++) {
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

beforeEach(() => {
  _reset();
  _resetSender();
  sentEvents = [];
  providerCalls = [];
  globalThis.fetch = (async (_input: string | URL | Request, options?: RequestInit) => {
    const body = JSON.parse(typeof options?.body === 'string' ? options.body : '{}');
    sentEvents.push(...(Array.isArray(body) ? body : [body]));
    return { status: 200, ok: true, json: async () => ({}) } as Response;
  }) as typeof fetch;
});

afterEach(() => {
  globalThis.fetch = realFetch;
  _reset();
  _resetSender();
  jest.restoreAllMocks();
});

describe('wrapVertexAI() against the real @google-cloud/vertexai package', () => {
  it('blocks preview chat messages before the package method runs', async () => {
    init({ api_key: 'test', pii_policy: { rules: { ssn: 'block' } } });
    const sample = buildPreviewModel().startChat();
    jest.spyOn(Object.getPrototypeOf(sample), 'sendMessage').mockImplementation(
      async function (this: any, request: unknown) {
        providerCalls.push({ request, history: this.historyInternal });
        return { response: RESPONSE } as any;
      },
    );
    const chat = wrapVertexAI(buildPreviewModel()).startChat();

    await expect(chat.sendMessage('ssn 123-45-6789')).rejects.toThrow(
      /blocked by policy/i,
    );

    expect(providerCalls).toEqual([]);
  });

  it('blocks a chat message before the package method runs', async () => {
    init({ api_key: 'test', pii_policy: { rules: { ssn: 'block' } } });
    const sample = buildModel().startChat();
    jest.spyOn(Object.getPrototypeOf(sample), 'sendMessage').mockImplementation(
      async function (this: any, request: unknown) {
        providerCalls.push({ request, history: this.historyInternal });
        return { response: RESPONSE } as any;
      },
    );
    const chat = wrapVertexAI(buildModel()).startChat();

    await expect(chat.sendMessage('ssn 123-45-6789')).rejects.toThrow(
      /blocked by policy/i,
    );

    expect(providerCalls).toEqual([]);
  });

  it('blocks when a chat would resend prohibited retained history', async () => {
    init({ api_key: 'test', pii_policy: { rules: { ssn: 'block' } } });
    const sample = buildModel().startChat();
    jest.spyOn(Object.getPrototypeOf(sample), 'sendMessage').mockImplementation(
      async function (this: any, request: unknown) {
        providerCalls.push({ request, history: this.historyInternal });
        return { response: RESPONSE } as any;
      },
    );
    const history = [
      { role: 'user', parts: [{ text: 'old ssn 123-45-6789' }] },
      { role: 'model', parts: [{ text: 'acknowledged' }] },
    ];
    const chat = wrapVertexAI(buildModel()).startChat({ history });

    await expect(chat.sendMessage('continue safely')).rejects.toThrow(
      /blocked by policy/i,
    );

    expect(providerCalls).toEqual([]);
  });

  it('redacts current and retained chat content without mutating caller input', async () => {
    init({ api_key: 'test', sample_rate: 1, pii_policy: { rules: { email: 'redact' } } });
    const sample = buildModel().startChat();
    jest.spyOn(Object.getPrototypeOf(sample), 'sendMessage').mockImplementation(
      async function (this: any, request: unknown) {
        providerCalls.push({ request, history: this.historyInternal });
        return { response: RESPONSE } as any;
      },
    );
    const history = [
      { role: 'user', parts: [{ text: 'old@example.com' }] },
      { role: 'model', parts: [{ text: 'acknowledged' }] },
    ];
    const chat = wrapVertexAI(buildModel()).startChat({ history });

    await chat.sendMessage('new@example.com');
    await waitForEvents();

    expect(history[0].parts[0].text).toBe('old@example.com');
    expect(providerCalls[0].request).toBe('[REDACTED_EMAIL]');
    expect(JSON.stringify(providerCalls[0].history)).toContain('[REDACTED_EMAIL]');
    expect(JSON.stringify(providerCalls[0].history)).not.toContain('old@example.com');
    const event = sentEvents.find((item) => item.operation === 'sendMessage');
    expect(event.prompt).toContain('[REDACTED_EMAIL]');
  });

  it('blocks a chat stream before it opens', async () => {
    init({ api_key: 'test', pii_policy: { rules: { ssn: 'block' } } });
    const sample = buildModel().startChat();
    jest.spyOn(Object.getPrototypeOf(sample), 'sendMessageStream').mockImplementation(
      async function (this: any, request: unknown) {
        providerCalls.push({ request, history: this.historyInternal });
        return {
          stream: (async function* () { yield RESPONSE; })(),
          response: Promise.resolve(RESPONSE),
        } as any;
      },
    );
    const chat = wrapVertexAI(buildModel()).startChat();

    await expect(chat.sendMessageStream('ssn 123-45-6789')).rejects.toThrow(
      /blocked by policy/i,
    );

    expect(providerCalls).toEqual([]);
  });

  it('blocks sensitive text in the chat array shorthand', async () => {
    init({ api_key: 'test', pii_policy: { rules: { ssn: 'block' } } });
    const sample = buildModel().startChat();
    jest.spyOn(Object.getPrototypeOf(sample), 'sendMessage').mockImplementation(
      async function (this: any, request: unknown) {
        providerCalls.push({ request, history: this.historyInternal });
        return { response: RESPONSE } as any;
      },
    );
    const chat = wrapVertexAI(buildModel()).startChat();

    await expect(
      chat.sendMessage(['safe prefix', { text: 'ssn 123-45-6789' }]),
    ).rejects.toThrow(/blocked by policy/i);

    expect(providerCalls).toEqual([]);
  });

  it('redacts sensitive text in the chat array shorthand', async () => {
    init({ api_key: 'test', pii_policy: { rules: { email: 'redact' } } });
    const sample = buildModel().startChat();
    jest.spyOn(Object.getPrototypeOf(sample), 'sendMessage').mockImplementation(
      async function (this: any, request: unknown) {
        providerCalls.push({ request, history: this.historyInternal });
        return { response: RESPONSE } as any;
      },
    );
    const chat = wrapVertexAI(buildModel()).startChat();

    await chat.sendMessage(['safe prefix', { text: 'person@example.com' }]);

    expect(providerCalls[0].request).toEqual([
      'safe prefix',
      { text: '[REDACTED_EMAIL]' },
    ]);
  });

  it('generic wrap blocks prohibited retained Vertex chat history', async () => {
    init({ api_key: 'test', pii_policy: { rules: { ssn: 'block' } } });
    const sample = buildModel().startChat();
    jest.spyOn(Object.getPrototypeOf(sample), 'sendMessage').mockImplementation(
      async function (this: any, request: unknown) {
        providerCalls.push({ request, history: this.historyInternal });
        return { response: RESPONSE } as any;
      },
    );
    const chat = wrap(buildModel()).startChat({
      history: [{ role: 'user', parts: [{ text: 'old ssn 123-45-6789' }] }],
    });

    await expect(chat.sendMessage('continue safely')).rejects.toThrow(
      /blocked by policy/i,
    );

    expect(providerCalls).toEqual([]);
  });

  it('blocks sensitive function-response payloads before transport', async () => {
    init({ api_key: 'test', pii_policy: { rules: { ssn: 'block' } } });
    const sample = buildModel().startChat();
    jest.spyOn(Object.getPrototypeOf(sample), 'sendMessage').mockImplementation(
      async function (this: any, request: unknown) {
        providerCalls.push({ request, history: this.historyInternal });
        return { response: RESPONSE } as any;
      },
    );
    const chat = wrapVertexAI(buildModel()).startChat();

    await expect(
      chat.sendMessage([{
        functionResponse: {
          name: 'lookup',
          response: { record: { ssn: '123-45-6789' } },
        },
      }]),
    ).rejects.toThrow(/blocked by policy/i);

    expect(providerCalls).toEqual([]);
  });

  it('generic wrap governs nested Vertex system instructions', async () => {
    init({ api_key: 'test', pii_policy: { rules: { ssn: 'block' } } });
    const sample = buildModel().startChat();
    jest.spyOn(Object.getPrototypeOf(sample), 'sendMessage').mockImplementation(
      async function (this: any, request: unknown) {
        providerCalls.push({ request, history: this.historyInternal });
        return { response: RESPONSE } as any;
      },
    );
    const rawChat: any = buildModel().startChat();
    rawChat.systemInstruction = {
      role: 'system',
      parts: [{ text: 'system ssn 123-45-6789' }],
    };

    await expect(wrap(rawChat).sendMessage('continue safely')).rejects.toThrow(
      /blocked by policy/i,
    );

    expect(providerCalls).toEqual([]);
  });

  it('fails closed when cached Vertex context is opaque', async () => {
    init({ api_key: 'test' });
    const raw: any = buildModel();
    raw.cachedContent = 'projects/test/locations/us-central1/cachedContents/opaque';
    jest.spyOn(raw, 'generateContent').mockImplementation(async (request: unknown) => {
      providerCalls.push({ request, history: undefined });
      return { response: RESPONSE } as any;
    });

    await expect(
      wrapVertexAI(raw).generateContent('continue safely'),
    ).rejects.toThrow(/cached context is opaque/i);

    expect(providerCalls).toEqual([]);
  });
});
