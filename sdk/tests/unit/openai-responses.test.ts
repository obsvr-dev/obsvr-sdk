/**
 * OpenAI Responses API governance (pre-launch F13).
 *
 * wrap() must govern `responses.create` like the other text-generation
 * surfaces: pre-call scan (policy rules + PII) over instructions/input,
 * post-call governance over the extracted output text, and a full audit
 * event (prompt, response, tokens, model) on the wire.
 */
import {
  extractPrompt,
  extractResponse,
  extractModel,
  extractTokenUsage,
  accumulateResponsesStream,
} from '../../src/proxy/extractors/openai-responses';
import { init, getConfig, _reset } from '../../src/proxy/config';
import { wrap } from '../../src/proxy/wrapper';
import { _resetSender, flushQueue } from '../../src/proxy/sender/fire-and-forget';
import type { AuditEvent } from '../../src/proxy/types';

// ---------------------------------------------------------------------------
// Extractors — pure functions, no mocking needed
// ---------------------------------------------------------------------------

describe('openai-responses extractors', () => {
  it('extracts prompt from string input + instructions', () => {
    const prompt = extractPrompt({
      model: 'gpt-4o',
      instructions: 'You are terse.',
      input: 'What is the capital of France?',
    });
    expect(prompt).toBe('system: You are terse.\nuser: What is the capital of France?');
  });

  it('extracts prompt from an input item list (string and part-array content)', () => {
    const prompt = extractPrompt({
      model: 'gpt-4o',
      input: [
        { role: 'user', content: 'first turn' },
        { role: 'assistant', content: [{ type: 'output_text', text: 'reply' }] },
        { role: 'user', content: [{ type: 'input_text', text: 'second turn' }] },
      ],
    });
    expect(prompt).toBe('user: first turn\nassistant: reply\nuser: second turn');
  });

  it('extracts response text from the output item list', () => {
    const text = extractResponse({
      output: [
        { type: 'reasoning' },
        {
          type: 'message',
          role: 'assistant',
          content: [{ type: 'output_text', text: 'Paris.' }],
        },
        { type: 'function_call', name: 'lookup', arguments: '{"q":1}' },
      ],
    });
    expect(text).toBe('Paris.\n[Function call: lookup({"q":1})]');
  });

  it('prefers the SDK output_text aggregate when present', () => {
    expect(extractResponse({ output_text: 'Paris.', output: [] })).toBe('Paris.');
  });

  it('maps native usage fields to TokenUsage', () => {
    expect(
      extractTokenUsage({ usage: { input_tokens: 7, output_tokens: 3, total_tokens: 10 } }),
    ).toEqual({ input_tokens: 7, output_tokens: 3, total_tokens: 10 });
    expect(extractTokenUsage({})).toBeUndefined();
  });

  it('extracts model from the request', () => {
    expect(extractModel({ model: ' gpt-4o ' })).toBe('gpt-4o');
    expect(extractModel({})).toBe('unknown');
  });

  it('accumulates output_text deltas + completed usage/model from an event stream', () => {
    const result = accumulateResponsesStream([
      { type: 'response.created', response: { model: 'gpt-4o-2024-08-06' } },
      { type: 'response.output_text.delta', delta: 'Par' },
      { type: 'response.output_text.delta', delta: 'is.' },
      {
        type: 'response.completed',
        response: {
          model: 'gpt-4o-2024-08-06',
          usage: { input_tokens: 7, output_tokens: 3, total_tokens: 10 },
        },
      },
    ]);
    expect(result.text).toBe('Paris.');
    expect(result.model).toBe('gpt-4o-2024-08-06');
    expect(result.usage).toEqual({ input_tokens: 7, output_tokens: 3, total_tokens: 10 });
  });
});

// ---------------------------------------------------------------------------
// wrap() end-to-end governance over responses.create
// ---------------------------------------------------------------------------

const realFetch = globalThis.fetch;
let sentEvents: AuditEvent[] = [];

beforeEach(() => {
  _reset();
  _resetSender();
  sentEvents = [];
  globalThis.fetch = (async (_url: unknown, opts?: { body?: string }) => {
    const body = JSON.parse(opts?.body ?? '[]') as AuditEvent | AuditEvent[];
    const batch = Array.isArray(body) ? body : [body];
    sentEvents.push(...batch);
    return { status: 200, ok: true, json: async () => ({ count: batch.length }) };
  }) as unknown as typeof fetch;
});

afterEach(() => {
  globalThis.fetch = realFetch;
});

const RESPONSE_PAYLOAD = {
  id: 'resp_1',
  model: 'gpt-4o-2024-08-06',
  output: [
    {
      type: 'message',
      role: 'assistant',
      content: [{ type: 'output_text', text: 'The SSN is 123-45-6789' }],
    },
  ],
  usage: { input_tokens: 7, output_tokens: 6, total_tokens: 13 },
};

function mockResponsesClient(capture?: { lastArgs?: unknown }) {
  return {
    chat: { completions: { create: async () => ({}) } },
    responses: {
      create: async (args: unknown) => {
        if (capture) capture.lastArgs = args;
        return RESPONSE_PAYLOAD;
      },
    },
  };
}

describe('wrap() governs responses.create', () => {
  it('pre-call policy rule blocks the call before the provider is reached', async () => {
    init({
      api_key: 'test',
      sample_rate: 1,
      policy_rules: [{
        id: 'kw1', name: 'no secrets', enabled: true, action: 'block',
        type: 'keyword', conditions: { keywords: ['launch code'] },
      }],
    });
    const capture: { lastArgs?: unknown } = {};
    const wrapped = wrap(mockResponsesClient(capture));

    await expect(
      wrapped.responses.create({ model: 'gpt-4o', input: 'give me the launch code' } as any),
    ).rejects.toThrow('[obsvr] Request blocked by policy');
    expect(capture.lastArgs).toBeUndefined(); // provider never reached

    await flushQueue(getConfig());
    const blocked = sentEvents.find((e) => e.event_type === 'blocked_call');
    expect(blocked).toBeDefined();
    expect(blocked!.operation).toBe('responses.create');
    expect(blocked!.rule_id).toBe('kw1');
  });

  it('pre-call PII redaction rewrites string input before the provider sees it', async () => {
    init({ api_key: 'test', sample_rate: 1, pii_policy: { default: 'redact' } });
    const capture: { lastArgs?: unknown } = {};
    const wrapped = wrap(mockResponsesClient(capture));

    await wrapped.responses.create({
      model: 'gpt-4o',
      input: 'my email is bob@example.com',
    } as any);

    const sent = capture.lastArgs as { input: string };
    expect(sent.input).not.toContain('bob@example.com');
    expect(sent.input).toContain('[REDACTED_EMAIL]');
  });

  it('post-call governance redacts PII in the STORED response; caller copy untouched', async () => {
    init({ api_key: 'test', sample_rate: 1, pii_policy: { default: 'redact' } });
    const wrapped = wrap(mockResponsesClient());

    const resp = await wrapped.responses.create({
      model: 'gpt-4o',
      instructions: 'be helpful',
      input: 'look up the record',
    } as any);
    // Caller-visible response is never modified.
    expect((resp as typeof RESPONSE_PAYLOAD).output[0].content[0].text).toContain('123-45-6789');

    await flushQueue(getConfig());
    const event = sentEvents.find((e) => e.operation === 'responses.create');
    expect(event).toBeDefined();
    // Prompt + response were extracted from the Responses API shape...
    expect(event!.prompt).toBe('system: be helpful\nuser: look up the record');
    expect(event!.response).toContain('The SSN is');
    // ...and the stored copy is governed (response-side PII redaction).
    expect(event!.response).not.toContain('123-45-6789');
    expect(event!.model).toBe('gpt-4o');
    expect(event!.model_resolved).toBe('gpt-4o-2024-08-06');
    expect(event!.total_tokens).toBe(13);
  });

  it('streaming responses.create is accumulated and audited on completion', async () => {
    init({ api_key: 'test', sample_rate: 1, streaming_mode: 'wrap' });
    const streamFactory = async function* () {
      yield { type: 'response.created', response: { model: 'gpt-4o-2024-08-06' } };
      yield { type: 'response.output_text.delta', delta: 'Hello' };
      yield { type: 'response.output_text.delta', delta: ' world' };
      yield {
        type: 'response.completed',
        response: {
          model: 'gpt-4o-2024-08-06',
          usage: { input_tokens: 2, output_tokens: 2, total_tokens: 4 },
        },
      };
    };
    const client = {
      chat: { completions: { create: async () => ({}) } },
      responses: { create: async (_args: unknown) => streamFactory() },
    };
    const wrapped = wrap(client);

    const stream = await wrapped.responses.create({
      model: 'gpt-4o',
      input: 'hi',
      stream: true,
    } as any);
    const chunks: unknown[] = [];
    for await (const chunk of stream as AsyncIterable<unknown>) chunks.push(chunk);
    expect(chunks).toHaveLength(4);

    await flushQueue(getConfig());
    const event = sentEvents.find((e) => e.operation === 'responses.create');
    expect(event).toBeDefined();
    expect(event!.response).toBe('Hello world');
    expect(event!.total_tokens).toBe(4);
    expect(event!.model_resolved).toBe('gpt-4o-2024-08-06');
  });
});
