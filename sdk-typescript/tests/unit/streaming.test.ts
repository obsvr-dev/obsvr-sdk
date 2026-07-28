import { accumulateOpenAIStream } from '../../src/proxy/extractors/openai-chat';
import { init, _reset } from '../../src/proxy/config';
import { wrap } from '../../src/proxy/wrapper';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';

// ---------------------------------------------------------------------------
// accumulateOpenAIStream — pure function, no mocking needed
// ---------------------------------------------------------------------------

describe('accumulateOpenAIStream', () => {
  it('should concatenate delta content from successive chunks', () => {
    const chunks = [
      { choices: [{ delta: { content: 'Hello' } }], model: 'gpt-4' },
      { choices: [{ delta: { content: ' world' } }], model: 'gpt-4' },
      { choices: [{ delta: {} }], model: 'gpt-4' },
    ];

    const result = accumulateOpenAIStream(chunks);
    expect(result.text).toBe('Hello world');
  });

  it('should extract token usage from a chunk that carries usage', () => {
    const chunks = [
      { choices: [{ delta: { content: 'Hi' } }], model: 'gpt-4' },
      {
        choices: [{ delta: {} }],
        usage: { prompt_tokens: 10, completion_tokens: 2, total_tokens: 12 },
        model: 'gpt-4',
      },
    ];

    const result = accumulateOpenAIStream(chunks);
    expect(result.usage).toBeDefined();
    expect(result.usage!.input_tokens).toBe(10);
    expect(result.usage!.output_tokens).toBe(2);
    expect(result.usage!.total_tokens).toBe(12);
  });

  it('should return undefined usage when no chunk contains usage', () => {
    const chunks = [
      { choices: [{ delta: { content: 'Hello' } }], model: 'gpt-4' },
    ];

    const result = accumulateOpenAIStream(chunks);
    expect(result.usage).toBeUndefined();
  });

  it('should pick up model from any chunk', () => {
    const chunks = [
      { choices: [{ delta: { content: 'A' } }], model: 'gpt-4-turbo' },
    ];

    const result = accumulateOpenAIStream(chunks);
    expect(result.model).toBe('gpt-4-turbo');
  });

  it('should return "unknown" model when no chunk has a model field', () => {
    const chunks = [{ choices: [{ delta: { content: 'B' } }] }];

    const result = accumulateOpenAIStream(chunks);
    expect(result.model).toBe('unknown');
  });

  it('should return empty text for an empty chunk array', () => {
    const result = accumulateOpenAIStream([]);
    expect(result.text).toBe('');
    expect(result.usage).toBeUndefined();
    expect(result.model).toBe('unknown');
  });

  it('should skip chunks whose delta content is not a string', () => {
    const chunks = [
      { choices: [{ delta: { content: null } }], model: 'gpt-4' },
      { choices: [{ delta: { content: 'real' } }], model: 'gpt-4' },
    ];

    const result = accumulateOpenAIStream(chunks);
    expect(result.text).toBe('real');
  });
});

// ---------------------------------------------------------------------------
// wrap() streaming_mode:"wrap" — observable behaviour tests (no mock needed)
// ---------------------------------------------------------------------------

describe('wrap with streaming_mode:"wrap"', () => {
  beforeEach(() => {
    _reset();
    _resetSender();
  });

  it('should return an AsyncIterable for streaming calls', async () => {
    init({ api_key: 'test', sample_rate: 1, streaming_mode: 'wrap' });

    const mockStreamFactory = async function* () {
      yield { choices: [{ delta: { content: 'Hello' } }], model: 'gpt-4' };
      yield { choices: [{ delta: { content: ' world' } }], model: 'gpt-4' };
    };

    const mockClient = {
      chat: {
        completions: {
          create: (_args: unknown) => Promise.resolve(mockStreamFactory()),
        },
      },
    };

    const wrapped = wrap(mockClient);
    const result = await wrapped.chat.completions.create({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'Hi' }],
      stream: true,
    } as any);

    expect(result).toBeDefined();
    expect(typeof (result as any)[Symbol.asyncIterator]).toBe('function');
  });

  it('should yield all original chunks unchanged (passthrough)', async () => {
    init({ api_key: 'test', sample_rate: 1, streaming_mode: 'wrap' });

    const chunk1 = { choices: [{ delta: { content: 'Hello' } }], model: 'gpt-4' };
    const chunk2 = { choices: [{ delta: { content: ' world' } }], model: 'gpt-4' };
    const chunk3 = {
      choices: [{ delta: {} }],
      usage: { prompt_tokens: 10, completion_tokens: 2, total_tokens: 12 },
      model: 'gpt-4',
    };

    const mockStreamFactory = async function* () {
      yield chunk1;
      yield chunk2;
      yield chunk3;
    };

    const mockClient = {
      chat: {
        completions: {
          create: (_args: unknown) => Promise.resolve(mockStreamFactory()),
        },
      },
    };

    const wrapped = wrap(mockClient);
    const stream = await wrapped.chat.completions.create({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'Hi' }],
      stream: true,
    } as any);

    const collected: unknown[] = [];
    for await (const chunk of stream as AsyncIterable<unknown>) {
      collected.push(chunk);
    }

    expect(collected).toEqual([chunk1, chunk2, chunk3]);
  });

  it('should fully consume the stream without throwing', async () => {
    init({ api_key: 'test', sample_rate: 1, streaming_mode: 'wrap' });

    const mockStreamFactory = async function* () {
      yield { choices: [{ delta: { content: 'A' } }], model: 'gpt-4' };
      yield { choices: [{ delta: { content: 'B' } }], model: 'gpt-4' };
      yield { choices: [{ delta: { content: 'C' } }], model: 'gpt-4' };
    };

    const mockClient = {
      chat: {
        completions: {
          create: (_args: unknown) => Promise.resolve(mockStreamFactory()),
        },
      },
    };

    const wrapped = wrap(mockClient);
    const stream = await wrapped.chat.completions.create({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'Hi' }],
      stream: true,
    } as any);

    const chunks: unknown[] = [];
    await expect(
      (async () => {
        for await (const chunk of stream as AsyncIterable<unknown>) {
          chunks.push(chunk);
        }
      })()
    ).resolves.toBeUndefined();

    expect(chunks).toHaveLength(3);
  });

  it('should propagate stream errors to the caller', async () => {
    init({ api_key: 'test', sample_rate: 1, streaming_mode: 'wrap' });

    const streamError = new Error('upstream stream failure');
    const mockStreamFactory = async function* () {
      yield { choices: [{ delta: { content: 'partial' } }], model: 'gpt-4' };
      throw streamError;
    };

    const mockClient = {
      chat: {
        completions: {
          create: (_args: unknown) => Promise.resolve(mockStreamFactory()),
        },
      },
    };

    const wrapped = wrap(mockClient);
    const stream = await wrapped.chat.completions.create({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'Hi' }],
      stream: true,
    } as any);

    await expect(
      (async () => {
        for await (const _chunk of stream as AsyncIterable<unknown>) {
          // consume
        }
      })()
    ).rejects.toThrow('upstream stream failure');
  });
});

// ---------------------------------------------------------------------------
// wrap() streaming_mode:"skip" — passes stream through without wrapping
// ---------------------------------------------------------------------------

describe('wrap with streaming_mode:"skip"', () => {
  beforeEach(() => {
    _reset();
    _resetSender();
  });

  it('should return the exact same stream object reference when skip mode', async () => {
    init({ api_key: 'test', sample_rate: 1, streaming_mode: 'skip' });

    const originalStream = (async function* () {
      yield { choices: [{ delta: { content: 'Hello' } }] };
    })();

    const mockClient = {
      chat: {
        completions: {
          create: (_args: unknown) => Promise.resolve(originalStream),
        },
      },
    };

    const wrapped = wrap(mockClient);
    const result = await wrapped.chat.completions.create({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'Hi' }],
      stream: true,
    } as any);

    expect(result).toBe(originalStream);
  });

  it('should be iterable when returned from skip mode', async () => {
    init({ api_key: 'test', sample_rate: 1, streaming_mode: 'skip' });

    const mockStreamFactory = async function* () {
      yield { choices: [{ delta: { content: 'A' } }] };
      yield { choices: [{ delta: { content: 'B' } }] };
    };

    const mockClient = {
      chat: {
        completions: {
          create: (_args: unknown) => Promise.resolve(mockStreamFactory()),
        },
      },
    };

    const wrapped = wrap(mockClient);
    const stream = await wrapped.chat.completions.create({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'Hi' }],
      stream: true,
    } as any);

    const chunks: unknown[] = [];
    for await (const chunk of stream as AsyncIterable<unknown>) {
      chunks.push(chunk);
    }
    expect(chunks).toHaveLength(2);
  });
});
