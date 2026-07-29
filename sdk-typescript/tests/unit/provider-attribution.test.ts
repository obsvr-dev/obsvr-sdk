/**
 * The recorded provider must describe where the call actually went.
 *
 * The defect: `wrapTogether` hardcoded `provider: "together"`, so one wrapper
 * pointed at Groq's API recorded "together", and pointed at a localhost server
 * recorded "together" as well — filing a local model as served by a US cloud
 * vendor. No event field anywhere derived from the real destination: no
 * base_url, no endpoint, no host, and `region` was "unknown" for everything.
 *
 * That is a lie about a destination in the field a compliance reviewer reads for
 * data residency, which is why it was treated as blocking rather than as a
 * cosmetic label problem.
 *
 * The two "same wrapper, wrong label" cases below are the ones that were
 * demonstrated live. They are the reason this file exists, so they are the first
 * things it checks.
 */

import { init, _reset } from '../../src/proxy/config';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { wrapTogether } from '../../src/integrations/together';
import { wrapOpenAICompatible } from '../../src/integrations/openai-compat';

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
  model: 'llama-3-70b',
  choices: [{ message: { content: 'Hello!' } }],
  usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
};

/** An OpenAI-shaped client that reports a base URL, the way the real one does. */
function clientAt(baseURL?: string) {
  return {
    ...(baseURL === undefined ? {} : { baseURL }),
    chat: {
      completions: {
        create: () => Promise.resolve(OK_RESPONSE),
      },
    },
  };
}

async function callThrough(client: any): Promise<any> {
  init({ api_key: 'test', sample_rate: 1 });
  const wrapped = wrapTogether(client as any);
  await wrapped.chat.completions.create({
    model: 'llama-3-70b',
    messages: [{ role: 'user', content: 'Hi' }],
  } as any);
  await waitForEvents(1);
  return sentEvents[0];
}

describe('provider attribution follows the endpoint', () => {
  it('does not call a Groq endpoint "together"', async () => {
    const event = await callThrough(clientAt('https://api.groq.com/openai/v1'));

    expect(event.provider).not.toBe('together');
    expect(event.provider).toBe('unknown');
    expect(event.metadata.provider_detail).toBe('groq');
    expect(event.metadata.endpoint_host).toBe('api.groq.com');
    expect(event.metadata.provider_attribution).toBe('endpoint');
  });

  it('does not call a localhost endpoint "together"', async () => {
    const event = await callThrough(clientAt('http://localhost:11434/v1'));

    expect(event.provider).not.toBe('together');
    expect(event.provider).toBe('unknown');
    expect(event.metadata.provider_detail).toBe('local');
    expect(event.metadata.endpoint_host).toBe('localhost:11434');
  });

  it('does call a real Together endpoint "together"', async () => {
    // The control. Without it, "stop saying together" would be satisfied by a
    // wrapper that had stopped attributing anything at all.
    const event = await callThrough(clientAt('https://api.together.xyz/v1'));

    expect(event.provider).toBe('together');
    expect(event.metadata.provider_detail).toBe('together');
    expect(event.metadata.provider_attribution).toBe('endpoint');
  });

  it('marks a label it could not check as declared rather than verified', async () => {
    // No baseURL to read. The declared label is all there is — but the record
    // says which kind of answer it is, so a reader can tell a checked value from
    // an asserted one.
    const event = await callThrough(clientAt(undefined));

    expect(event.provider).toBe('together');
    expect(event.metadata.provider_attribution).toBe('client_declared');
    expect(event.metadata.endpoint_host).toBeUndefined();
  });

  it('refuses to guess for a host it has no name for', async () => {
    const event = await callThrough(clientAt('https://llm.internal.corp/v1'));

    expect(event.provider).toBe('unknown');
    expect(event.metadata.provider_detail).toBe('unrecognized_endpoint');
    expect(event.metadata.endpoint_host).toBe('llm.internal.corp');
  });

  it('is not fooled by a lookalike suffix', async () => {
    // `together.xyz.evil.com` must not match the Together rule. The patterns are
    // anchored at the end of the hostname for exactly this reason.
    const event = await callThrough(clientAt('https://api.together.xyz.evil.com/v1'));

    expect(event.provider).toBe('unknown');
    expect(event.metadata.provider_detail).toBe('unrecognized_endpoint');
  });

  it('never puts base-URL credentials in the record', async () => {
    // A base URL is somewhere people put secrets, and this value is shipped and
    // stored. Host and port only.
    const event = await callThrough(clientAt('https://someone:sk-secret@api.groq.com/openai/v1'));

    expect(event.metadata.endpoint_host).toBe('api.groq.com');
    const serialized = JSON.stringify(event);
    expect(serialized).not.toContain('sk-secret');
    expect(serialized).not.toContain('someone');
  });

  it('survives a client whose baseURL getter throws', async () => {
    const client: any = {
      chat: { completions: { create: () => Promise.resolve(OK_RESPONSE) } },
    };
    Object.defineProperty(client, 'baseURL', {
      get() {
        throw new Error('nope');
      },
    });

    const event = await callThrough(client);

    // A non-answer, not a crash. Governance must not depend on a label lookup.
    expect(event.provider).toBe('together');
    expect(event.metadata.provider_attribution).toBe('client_declared');
  });

  it('keeps attribution when the caller supplies their own metadata', async () => {
    // Per-request metadata used to replace the wrap-time metadata outright, so
    // the destination evidence would vanish exactly when a caller attached
    // fields of their own.
    init({ api_key: 'test', sample_rate: 1 });
    const wrapped = wrapOpenAICompatible(clientAt('https://api.groq.com/openai/v1') as any, {
      provider: 'openai',
      source: 'custom',
      metadata: { team: 'platform' },
    });

    await wrapped.chat.completions.create({
      model: 'llama-3-70b',
      messages: [{ role: 'user', content: 'Hi' }],
    } as any);
    await waitForEvents(1);

    expect(sentEvents[0].metadata.team).toBe('platform');
    expect(sentEvents[0].metadata.provider_detail).toBe('groq');
    expect(sentEvents[0].metadata.endpoint_host).toBe('api.groq.com');
  });

  it('does not let a caller label override the endpoint', async () => {
    // The general form of the original defect: any caller of the shared wrapper
    // could assert a destination. The endpoint wins now.
    init({ api_key: 'test', sample_rate: 1 });
    const wrapped = wrapOpenAICompatible(clientAt('https://api.groq.com/openai/v1') as any, {
      provider: 'bedrock',
      source: 'custom',
    });

    await wrapped.chat.completions.create({
      model: 'llama-3-70b',
      messages: [{ role: 'user', content: 'Hi' }],
    } as any);
    await waitForEvents(1);

    expect(sentEvents[0].provider).not.toBe('bedrock');
    expect(sentEvents[0].metadata.provider_detail).toBe('groq');
  });
});

describe('the recorded provider stays inside the ingest enum', () => {
  const CANONICAL = [
    'openai',
    'anthropic',
    'google',
    'azure_openai',
    'bedrock',
    'vertex_ai',
    'together',
    'cloudflare',
    'mcp',
    'unknown',
  ];

  it.each([
    ['https://api.groq.com/v1'],
    ['http://localhost:11434/v1'],
    ['https://api.mistral.ai/v1'],
    ['https://llm.internal.corp/v1'],
    ['https://api.together.xyz/v1'],
    ['https://my-thing.openai.azure.com/'],
  ])('%s resolves to a canonical provider value', async (baseURL) => {
    // Destinations the canonical enum cannot express record `unknown` and keep
    // their identity in `provider_detail` — the carriage MCP already uses.
    // Widening the union instead would emit values the backend rejects.
    const event = await callThrough(clientAt(baseURL));

    expect(CANONICAL).toContain(event.provider);
  });
});
