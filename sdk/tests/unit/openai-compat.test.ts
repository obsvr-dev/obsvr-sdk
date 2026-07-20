import { init, _reset } from '../../src/proxy/config';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { wrapAzureOpenAI } from '../../src/integrations/azure-openai';
import { wrapTogether } from '../../src/integrations/together';

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

function mockClient(response: any, capture?: (args: unknown[]) => void) {
  return {
    chat: {
      completions: {
        create: (...args: unknown[]) => {
          capture?.(args);
          return Promise.resolve(response);
        },
      },
    },
  };
}

const OK_RESPONSE = {
  id: 'chatcmpl-1',
  model: 'gpt-4o',
  choices: [{ message: { content: 'Hello!' } }],
  usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
};

describe('wrapAzureOpenAI / wrapTogether', () => {
  it('labels events with azure_openai provider and source', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const client = wrapAzureOpenAI(mockClient(OK_RESPONSE));

    const res = await client.chat.completions.create({
      model: 'gpt-4o',
      messages: [{ role: 'user', content: 'Hi' }],
    } as any);

    expect(res).toEqual(OK_RESPONSE);
    await waitForEvents(1);
    expect(sentEvents[0].provider).toBe('azure_openai');
    expect(sentEvents[0].source).toBe('azure_openai');
    expect(sentEvents[0].response).toBe('Hello!');
    expect(sentEvents[0].input_tokens).toBe(10);
    expect(sentEvents[0].output_tokens).toBe(5);
    // Resolved model read directly from the native response.model → highest trust.
    expect(sentEvents[0].model_resolved).toBe('gpt-4o');
    expect(sentEvents[0].provenance_source).toBe('provider_response');
  });

  it('labels events with together provider', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const client = wrapTogether(mockClient(OK_RESPONSE));

    await client.chat.completions.create({
      model: 'llama-3-70b',
      messages: [{ role: 'user', content: 'Hi' }],
    } as any);

    await waitForEvents(1);
    expect(sentEvents[0].provider).toBe('together');
    expect(sentEvents[0].source).toBe('together');
    // Together delegates to the openai-compatible base, so it inherits provider_response.
    expect(sentEvents[0].provenance_source).toBe('provider_response');
  });

  it('strips audit fields before calling the provider', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    let received: unknown[] = [];
    const client = wrapAzureOpenAI(
      mockClient(OK_RESPONSE, (args) => (received = args)),
    );

    await client.chat.completions.create({
      model: 'gpt-4o',
      messages: [{ role: 'user', content: 'Hi' }],
      request_id: 'req_1',
      source: 'custom-source',
      metadata: { team: 'x' },
    } as any);

    expect(received[0]).toEqual({
      model: 'gpt-4o',
      messages: [{ role: 'user', content: 'Hi' }],
    });
    await waitForEvents(1);
    expect(sentEvents[0].request_id).toBe('req_1');
    expect(sentEvents[0].source).toBe('custom-source');
    // User metadata rides through. The SDK also stamps an obsvr_span envelope
    // (M3: every governed call is a graph node), so assert containment, not
    // exact equality.
    expect(sentEvents[0].metadata).toMatchObject({ team: 'x' });
  });

  it('blocks calls with SSN and emits forensic event', async () => {
    init({ api_key: 'test', sample_rate: 1, pii_policy: {} });
    let called = false;
    const client = wrapAzureOpenAI(
      mockClient(OK_RESPONSE, () => (called = true)),
    );

    await expect(
      client.chat.completions.create({
        model: 'gpt-4o',
        messages: [{ role: 'user', content: 'my ssn is 123-45-6789' }],
      } as any),
    ).rejects.toThrow('[obsvr] Request blocked by policy');

    expect(called).toBe(false);
    await waitForEvents(1);
    expect(sentEvents[0].event_type).toBe('blocked_call');
    expect(sentEvents[0].status_code).toBe(403);
    expect(sentEvents[0].success).toBe(false);
    expect(sentEvents[0].blocked_types).toContain('ssn');
    expect(sentEvents[0].prompt).toContain('[REDACTED_SSN]');
  });

  it('redacts email in the outgoing request', async () => {
    init({ api_key: 'test', sample_rate: 1, pii_policy: {} });
    let received: any[] = [];
    const client = wrapTogether(
      mockClient(OK_RESPONSE, (args) => (received = args as any[])),
    );

    await client.chat.completions.create({
      model: 'llama-3',
      messages: [{ role: 'user', content: 'email me at john@example.com' }],
    } as any);

    expect(received[0].messages[0].content).toContain('[REDACTED_EMAIL]');
    expect(received[0].messages[0].content).not.toContain('john@example.com');
    await waitForEvents(1);
    expect(sentEvents[0].action_taken).toBe('redacted');
    expect(sentEvents[0].redacted_types).toContain('email');
  });

  it('emits failure event when the provider throws', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const err = Object.assign(new Error('rate limit exceeded'), {
      status: 429,
    });
    const client = wrapAzureOpenAI({
      chat: { completions: { create: (_req: any) => Promise.reject(err) } },
    });

    await expect(
      client.chat.completions.create({
        model: 'gpt-4o',
        messages: [{ role: 'user', content: 'Hi' }],
      } as any),
    ).rejects.toThrow('rate limit exceeded');

    await waitForEvents(1);
    expect(sentEvents[0].success).toBe(false);
    expect(sentEvents[0].status_code).toBe(429);
    expect(sentEvents[0].error_type).toBe('rate_limit');
  });

  it('accumulates streaming chunks into one event', async () => {
    init({ api_key: 'test', sample_rate: 1, streaming_mode: 'wrap' as any });
    const stream = (async function* () {
      yield { model: 'gpt-4o', choices: [{ delta: { content: 'Hel' } }] };
      yield { choices: [{ delta: { content: 'lo' } }] };
      yield {
        choices: [{ delta: {} }],
        usage: { prompt_tokens: 4, completion_tokens: 2, total_tokens: 6 },
      };
    })();
    const client = wrapAzureOpenAI(mockClient(stream));

    const result: any = await client.chat.completions.create({
      model: 'gpt-4o',
      messages: [{ role: 'user', content: 'Hi' }],
      stream: true,
    } as any);

    const chunks: unknown[] = [];
    for await (const chunk of result) chunks.push(chunk);
    expect(chunks).toHaveLength(3);

    await waitForEvents(1);
    expect(sentEvents[0].response).toBe('Hello');
    expect(sentEvents[0].total_tokens).toBe(6);
    // Streamed native response snapshot (chunk.model) → highest trust.
    expect(sentEvents[0].model_resolved).toBe('gpt-4o');
    expect(sentEvents[0].provenance_source).toBe('provider_response');
  });

  it('skips auditing when not sampled', async () => {
    init({ api_key: 'test', sample_rate: 0 });
    const client = wrapTogether(mockClient(OK_RESPONSE));
    await client.chat.completions.create({
      model: 'llama-3',
      messages: [{ role: 'user', content: 'Hi' }],
    } as any);
    await new Promise((r) => setTimeout(r, 20));
    expect(sentEvents).toHaveLength(0);
  });

  it('does not double-wrap', () => {
    init({ api_key: 'test' });
    const client = mockClient(OK_RESPONSE);
    const w1 = wrapAzureOpenAI(client);
    const w2 = wrapAzureOpenAI(w1);
    expect(w2).toBe(w1);
  });
});
