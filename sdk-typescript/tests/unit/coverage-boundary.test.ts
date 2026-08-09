/**
 * The wrap() coverage boundary, pinned.
 *
 * Two things had no regression guard at all before this file existed:
 *
 * 1. Which method paths are audited. `beta.messages.create` carries exactly the
 *    payload `messages.create` carries and produced ZERO audit events, because
 *    the allow-list matched the full dotted path exactly. Nothing failed when
 *    that gap was there, and nothing would fail if the list silently widened
 *    either — a governance product should not be able to change what it
 *    governs without a test noticing.
 *
 * 2. That each audited path reaches the extractor for the dialect it actually
 *    speaks. The two OpenAI surfaces disagree on both request and response
 *    shape, and every extractor returns "" rather than throwing when handed a
 *    foreign payload. So a path routed to the wrong extractor does not fail
 *    loudly: it emits a signed, chain-linked, success:true event asserting an
 *    empty conversation. That is worse evidence than the missing event it
 *    replaced, and it is the specific failure a "just strip the beta. prefix"
 *    fix would have shipped.
 */
import { init, getConfig, _reset } from '../../src/proxy/config';
import { wrap } from '../../src/proxy/wrapper';
import { _resetSender, flushQueue } from '../../src/proxy/sender/fire-and-forget';
import type { AuditEvent } from '../../src/proxy/types';

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

// --- provider payloads ------------------------------------------------------

const ANTHROPIC_RESPONSE = {
  id: 'msg_1',
  model: 'claude-sonnet-4-5-20250929',
  content: [{ type: 'text', text: 'four' }],
  usage: { input_tokens: 11, output_tokens: 2 },
};

const RESPONSES_RESPONSE = {
  id: 'resp_1',
  model: 'gpt-4o-2024-08-06',
  output: [
    { type: 'message', role: 'assistant', content: [{ type: 'output_text', text: 'four' }] },
  ],
  usage: { input_tokens: 7, output_tokens: 6, total_tokens: 13 },
};

const CHAT_RESPONSE = {
  id: 'chatcmpl_1',
  model: 'gpt-4o-mini-2024-07-18',
  choices: [{ message: { role: 'assistant', content: 'four' } }],
  usage: { prompt_tokens: 9, completion_tokens: 1, total_tokens: 10 },
};

/**
 * A client shaped like the real Anthropic one: `beta.messages.create` is a
 * distinct function object from `messages.create`, exactly as it is upstream.
 */
function anthropicClient(seen: string[]) {
  const create = (label: string) => async (_body: unknown) => {
    seen.push(label);
    return ANTHROPIC_RESPONSE;
  };
  return {
    messages: { create: create('messages.create') },
    beta: { messages: { create: create('beta.messages.create') } },
  } as any;
}

function openaiClient(seen: string[]) {
  const chatCreate = async (_body: unknown) => {
    seen.push('chat.completions.create');
    return CHAT_RESPONSE;
  };
  const responsesCreate = (label: string) => async (_body: unknown) => {
    seen.push(label);
    return RESPONSES_RESPONSE;
  };
  return {
    chat: { completions: { create: chatCreate } },
    responses: { create: responsesCreate('responses.create') },
    beta: { responses: { create: responsesCreate('beta.responses.create') } },
  } as any;
}

// --- 1. the beta namespaces are audited -------------------------------------

describe('wrap() audits the beta namespaces', () => {
  it('beta.messages.create emits one complete event, like messages.create', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const seen: string[] = [];
    const client = wrap(anthropicClient(seen));

    await client.beta.messages.create({
      model: 'claude-sonnet-4-5',
      messages: [{ role: 'user', content: 'what is 2+2' }],
    });

    await flushQueue(getConfig());
    expect(seen).toEqual(['beta.messages.create']);

    // Exactly one event: the beta method must not re-enter the audited GA
    // method underneath and double-count the call.
    expect(sentEvents).toHaveLength(1);
    const event = sentEvents[0];
    expect(event.operation).toBe('beta.messages.create');
    expect(event.provider).toBe('anthropic');
    expect(event.prompt).toBe('user: what is 2+2');
    expect(event.response).toBe('four');
    expect(event.model).toBe('claude-sonnet-4-5');
    expect(event.input_tokens).toBe(11);
    expect(event.output_tokens).toBe(2);
  });

  it('the GA path is unchanged by the beta entry', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const seen: string[] = [];
    const client = wrap(anthropicClient(seen));

    await client.messages.create({
      model: 'claude-sonnet-4-5',
      messages: [{ role: 'user', content: 'what is 2+2' }],
    });

    await flushQueue(getConfig());
    expect(seen).toEqual(['messages.create']);
    expect(sentEvents).toHaveLength(1);
    expect(sentEvents[0].operation).toBe('messages.create');
    expect(sentEvents[0].response).toBe('four');
  });
});

// --- 2. shape routing, not path-string routing ------------------------------

describe('each audited path reaches the extractor for its own dialect', () => {
  it('beta.responses.create is read as Responses, not as Chat Completions', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const seen: string[] = [];
    const client = wrap(openaiClient(seen));

    await client.beta.responses.create({
      model: 'gpt-4o',
      instructions: 'be terse',
      input: 'what is 2+2',
    });

    await flushQueue(getConfig());
    expect(seen).toEqual(['beta.responses.create']);
    expect(sentEvents).toHaveLength(1);
    const event = sentEvents[0];
    expect(event.operation).toBe('beta.responses.create');

    // The Chat Completions extractor would return "" for both of these, since
    // a Responses request has no `messages[]` and a Responses reply has no
    // `choices[]`. Empty strings here mean the path was routed by its name
    // rather than by its shape.
    expect(event.prompt).toBe('system: be terse\nuser: what is 2+2');
    expect(event.response).toBe('four');
    expect(event.model).toBe('gpt-4o');
    expect(event.total_tokens).toBe(13);
  });

  it('the Chat Completions path still reads as Chat Completions', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const seen: string[] = [];
    const client = wrap(openaiClient(seen));

    await client.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: 'what is 2+2' }],
    });

    await flushQueue(getConfig());
    expect(sentEvents).toHaveLength(1);
    expect(sentEvents[0].operation).toBe('chat.completions.create');
    expect(sentEvents[0].prompt).toBe('user: what is 2+2');
    expect(sentEvents[0].response).toBe('four');
    expect(sentEvents[0].total_tokens).toBe(10);
  });
});

// --- 3. the boundary itself -------------------------------------------------

describe('the coverage boundary holds in both directions', () => {
  it('non-text surfaces stay ungoverned even under a beta namespace', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const seen: string[] = [];
    const client = wrap({
      messages: { create: async () => ANTHROPIC_RESPONSE },
      embeddings: {
        create: async () => {
          seen.push('embeddings.create');
          return { data: [] };
        },
      },
      beta: {
        embeddings: {
          create: async () => {
            seen.push('beta.embeddings.create');
            return { data: [] };
          },
        },
        // A namespace no allow-list entry names. A prefix-stripping rule would
        // have to prove it does not reach these; enumeration proves it by
        // construction.
        messages: {
          countTokens: async () => {
            seen.push('beta.messages.countTokens');
            return { input_tokens: 4 };
          },
          batches: {
            create: async () => {
              seen.push('beta.messages.batches.create');
              return { id: 'batch_1' };
            },
          },
        },
      },
    } as any);

    await client.embeddings.create({ input: 'x' });
    await client.beta.embeddings.create({ input: 'x' });
    await client.beta.messages.countTokens({ messages: [] });
    await client.beta.messages.batches.create({ requests: [] });

    await flushQueue(getConfig());
    expect(seen).toEqual([
      'embeddings.create',
      'beta.embeddings.create',
      'beta.messages.countTokens',
      'beta.messages.batches.create',
    ]);
    expect(sentEvents).toHaveLength(0);
  });

  it('the .stream() helpers are governed, and return synchronously', async () => {
    // They cannot go through the probe below: that awaits the call result, and
    // these return a runner object rather than a promise — which is the entire
    // reason they needed a different wrapper.
    init({ api_key: 'test', sample_rate: 1 });
    const seen: string[] = [];
    const client = wrap({
      messages: {
        create: async () => ANTHROPIC_RESPONSE,
        stream: (_body: unknown) => {
          seen.push('messages.stream');
          return {
            on() {
              return this;
            },
            async done() {},
            async finalMessage() {
              return ANTHROPIC_RESPONSE;
            },
          };
        },
      },
    } as any);

    const runner = client.messages.stream({
      model: 'claude-sonnet-4-5',
      messages: [{ role: 'user', content: 'what is 2+2' }],
    });

    // Synchronous return, and chaining still works.
    expect(typeof runner.on).toBe('function');
    expect(runner.on('text', () => undefined)).toBeDefined();
    // Not a promise — awaiting one would hang if this regressed.
    expect((runner as Record<string, unknown>).then).toBeUndefined();

    await runner.done();
    await new Promise((r) => setTimeout(r, 10));
    await flushQueue(getConfig());

    // The provider was reached exactly once, and one event was recorded.
    expect(seen).toEqual(['messages.stream']);
    const ev = sentEvents.find((e) => e.operation === 'messages.stream');
    expect(ev).toBeDefined();
    expect(ev!.provider).toBe('anthropic');
    expect(ev!.response).toBe('four');
    expect(ev!.input_tokens).toBe(11);
  });

  it('pins the audited set exactly, so widening it is never silent', async () => {
    // Every path below is asserted by wrapping a client that exposes it and
    // checking whether an event appears. That tests the real gate rather than
    // re-reading the table the gate is built from.
    const AUDITED = [
      ['chat', 'completions', 'create'],
      ['chat', 'completions', 'parse'],
      ['messages', 'create'],
      ['messages', 'parse'],
      ['responses', 'create'],
      ['responses', 'parse'],
      ['generateContent'],
      ['models', 'generateContent'],
      ['models', 'generateContentStream'],
      ['beta', 'messages', 'create'],
      ['beta', 'responses', 'create'],
      ['beta', 'chat', 'completions', 'create'],
      ['beta', 'chat', 'completions', 'parse'],
    ];
    // The `.stream()` helpers and the tool runners ARE governed now, but
    // through the deferred runner rather than the async method wrapper — they
    // return their runner synchronously, so they are asserted separately
    // rather than by the await-the-result probe this list uses.
    const NOT_AUDITED = [
      ['messages', 'countTokens'],
      ['messages', 'batches', 'create'],
      ['generateContentStream'],
      ['startChat'],
      ['embeddings', 'create'],
      ['images', 'generate'],
      ['beta', 'messages', 'countTokens'],
      ['beta', 'threads', 'runs', 'create'],
    ];

    const probe = async (path: string[]): Promise<number> => {
      _reset();
      _resetSender();
      sentEvents = [];
      init({ api_key: 'test', sample_rate: 1 });

      // Build a nested object exposing exactly this one path, plus the
      // messages.create marker the provider detector duck-types on.
      const leaf = async () => ANTHROPIC_RESPONSE;
      let node: Record<string, unknown> = { [path[path.length - 1]]: leaf };
      for (let i = path.length - 2; i >= 0; i--) node = { [path[i]]: node };
      const client = wrap({
        messages: { create: async () => ANTHROPIC_RESPONSE },
        ...node,
      } as any);

      let cursor: any = client;
      for (const seg of path) cursor = cursor[seg];
      await cursor({ model: 'm', messages: [{ role: 'user', content: 'hi' }] });
      await flushQueue(getConfig());
      return sentEvents.length;
    };

    for (const path of AUDITED) {
      expect([path.join('.'), await probe(path)]).toEqual([path.join('.'), 1]);
    }
    for (const path of NOT_AUDITED) {
      expect([path.join('.'), await probe(path)]).toEqual([path.join('.'), 0]);
    }
  });
});
