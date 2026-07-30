/**
 * The FRONT DOOR must record where the call actually went.
 *
 * `provider-attribution.test.ts` covers the compat integrations, which were
 * repaired first. This file covers `obsvr.wrap()`, which was not — and which is
 * the documented entry point both READMEs lead with.
 *
 * THE DEFECT. `wrap()` labelled through `detectProvider()`, which duck-types on
 * the client's shape: anything exposing `chat.completions.create` is "openai",
 * whatever host it points at. Measured live against a local server before this
 * change, the event read `provider: "openai"` with `model:
 * "qwen2.5-coder:14b"` — a model that endpoint does not serve, sitting beside a
 * vendor the request never reached, in the field a compliance reviewer reads
 * for data residency.
 *
 * NON-VACUITY. `records the vendor when the call really goes there` is the
 * control: a fix that simply stopped saying "openai" would satisfy every other
 * assertion here and fail that one. `keeps the duck-typed label when no base
 * URL can be read` is the second control — it fails if attribution is dropped
 * rather than qualified.
 *
 * THE SHAPE/DESTINATION SPLIT is asserted directly at the bottom, because
 * collapsing those two back into one field is the specific regression that
 * would reintroduce this defect, and it would do so while every label assertion
 * above still passed for OpenAI-shaped clients.
 */

import { init, _reset } from '../../src/proxy/config';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { wrap } from '../../src/proxy/wrapper';

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
  for (let i = 0; i < 200 && sentEvents.length < n; i++) {
    await new Promise((r) => setTimeout(r, 5));
  }
}

const OK_RESPONSE = {
  id: 'chatcmpl-1',
  model: 'qwen2.5-coder:14b',
  choices: [{ message: { content: 'Hello!' } }],
  usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
};

/** An OpenAI-shaped client that reports a base URL, the way the real one does. */
function openAiShapedClientAt(baseURL?: string) {
  return {
    ...(baseURL === undefined ? {} : { baseURL }),
    chat: {
      completions: { create: () => Promise.resolve(OK_RESPONSE) },
    },
  };
}

/** An Anthropic-shaped client. Its extractor must survive a non-vendor host. */
function anthropicShapedClientAt(baseURL?: string) {
  return {
    ...(baseURL === undefined ? {} : { baseURL }),
    messages: {
      create: () =>
        Promise.resolve({
          id: 'msg_1',
          model: 'claude-x',
          content: [{ type: 'text', text: 'Hello!' }],
          usage: { input_tokens: 10, output_tokens: 5 },
        }),
    },
  };
}

function initSdk() {
  init({ apiKey: 'k', ingestUrl: 'https://ingest.example', environment: 'development', sampleRate: 1 });
}

async function callOpenAiShaped(baseURL?: string) {
  initSdk();
  const client = wrap(openAiShapedClientAt(baseURL)) as any;
  await client.chat.completions.create({
    model: 'qwen2.5-coder:14b',
    messages: [{ role: 'user', content: 'hi' }],
  });
  await waitForEvents(1);
  return sentEvents[0];
}

describe('front door: the recorded provider is the destination', () => {
  it('does NOT name a vendor for a local endpoint', async () => {
    const ev = await callOpenAiShaped('http://localhost:11434/v1');
    expect(ev.provider).not.toBe('openai');
    expect(ev.provider).toBe('unknown');
    expect(ev.metadata.provider_detail).toBe('local');
    expect(ev.metadata.endpoint_host).toBe('localhost:11434');
    expect(ev.metadata.provider_attribution).toBe('endpoint');
  });

  it('records the vendor when the call really goes there (CONTROL)', async () => {
    const ev = await callOpenAiShaped('https://api.openai.com/v1');
    expect(ev.provider).toBe('openai');
    expect(ev.metadata.provider_detail).toBe('openai');
    expect(ev.metadata.endpoint_host).toBe('api.openai.com');
    expect(ev.metadata.provider_attribution).toBe('endpoint');
  });

  it('keeps the duck-typed label when no base URL can be read (CONTROL)', async () => {
    const ev = await callOpenAiShaped(undefined);
    expect(ev.provider).toBe('openai');
    expect(ev.metadata.provider_attribution).toBe('client_declared');
    expect(ev.metadata.endpoint_host).toBeUndefined();
  });

  it('records unknown, not a guess, for a host it cannot name', async () => {
    const ev = await callOpenAiShaped('https://llm.internal.example.com/v1');
    expect(ev.provider).toBe('unknown');
    expect(ev.metadata.provider_detail).toBe('unrecognized_endpoint');
    expect(ev.metadata.endpoint_host).toBe('llm.internal.example.com');
  });

  it('names a third-party vendor the canonical enum cannot express', async () => {
    const ev = await callOpenAiShaped('https://api.groq.com/openai/v1');
    expect(ev.provider).toBe('unknown');
    expect(ev.metadata.provider_detail).toBe('groq');
    expect(ev.metadata.endpoint_host).toBe('api.groq.com');
  });

  it('never lets a base URL credential reach the record', async () => {
    const ev = await callOpenAiShaped('https://user:sk-secret-token@api.openai.com/v1');
    expect(JSON.stringify(ev)).not.toContain('sk-secret-token');
    expect(ev.metadata.endpoint_host).toBe('api.openai.com');
  });

  it('attribution wins over caller metadata of the same name', async () => {
    initSdk();
    const client = wrap(openAiShapedClientAt('http://localhost:11434/v1')) as any;
    await client.chat.completions.create(
      { model: 'qwen2.5-coder:14b', messages: [{ role: 'user', content: 'hi' }] },
      { metadata: { provider_detail: 'openai', endpoint_host: 'api.openai.com' } },
    );
    await waitForEvents(1);
    expect(sentEvents[0].metadata.provider_detail).toBe('local');
    expect(sentEvents[0].metadata.endpoint_host).toBe('localhost:11434');
  });
});

describe('front door: shape and destination stay separate', () => {
  it('an Anthropic-shaped client on a non-vendor host keeps its extractor', async () => {
    initSdk();
    const client = wrap(anthropicShapedClientAt('http://localhost:8080/v1')) as any;
    await client.messages.create({
      model: 'claude-x',
      messages: [{ role: 'user', content: 'hi there' }],
    });
    await waitForEvents(1);
    const ev = sentEvents[0];

    // The destination is recorded honestly...
    expect(ev.provider).toBe('unknown');
    expect(ev.metadata.provider_detail).toBe('local');

    // ...and the Anthropic extractor still ran, which is what proves the shape
    // was not overwritten by the destination. If one variable answered both
    // questions again, the response text would be empty here.
    expect(ev.prompt).toContain('hi there');
    expect(ev.response).toContain('Hello!');
    expect(ev.input_tokens).toBe(10);
    expect(ev.output_tokens).toBe(5);
  });
});
