/**
 * Module-level interception tests (auto/index.ts).
 *
 * Proves the construct-trap Proxy design: provider classes and prototypes
 * are never mutated, instances constructed before init() pass through and
 * pick up governance after init(), and explicit wrap() never double-wraps.
 */
import { init, _reset } from '../../src/proxy/config';
import { wrap } from '../../src/proxy/wrapper';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import {
  interceptProviderClass,
  autoInstrument,
  isInterceptionActive,
  _resetInterception,
} from '../../src/auto/index';
import { getConfig } from '../../src/proxy/config';

/** OpenAI-shaped fake with a private field to prove brand checks survive. */
class FakeOpenAI {
  #brand = 'private-ok';
  static VERSION = '4.0.0';
  apiKey: string;
  chat: {
    completions: {
      create: (req: Record<string, unknown>) => Promise<Record<string, unknown>>;
    };
  };

  constructor(opts: { apiKey: string }) {
    this.apiKey = opts.apiKey;
    this.chat = {
      completions: {
        create: async (req: Record<string, unknown>) => ({
          id: 'cmpl-1',
          model: req.model,
          choices: [{ message: { role: 'assistant', content: 'hello' } }],
          usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
        }),
      },
    };
  }

  checkBrand(): string {
    return this.#brand;
  }
}

/** Google-shaped fake: client hands out models via getGenerativeModel(). */
class FakeGoogleClient {
  getGenerativeModel(_opts: { model: string }) {
    return {
      generateContent: async (_prompt: string) => ({
        response: { text: () => 'gemini says hi' },
      }),
    };
  }
}

const SSN_PROMPT = {
  model: 'gpt-4o',
  messages: [{ role: 'user', content: 'My SSN is 123-45-6789' }],
};

describe('auto/interceptProviderClass', () => {
  beforeEach(() => {
    _reset();
    _resetSender();
    _resetInterception();
  });

  test('does not mutate the original class or its prototype', () => {
    const protoBefore = Object.getOwnPropertyNames(FakeOpenAI.prototype).sort();
    const brandMethodBefore = FakeOpenAI.prototype.checkBrand;

    const Intercepted = interceptProviderClass('openai', FakeOpenAI);

    expect(Object.getOwnPropertyNames(FakeOpenAI.prototype).sort()).toEqual(protoBefore);
    expect(FakeOpenAI.prototype.checkBrand).toBe(brandMethodBefore);
    // The proxy forwards statics and prototype to the real class
    expect(Intercepted.VERSION).toBe('4.0.0');
    expect(Intercepted.prototype).toBe(FakeOpenAI.prototype);
    // Instances made from the raw class stay completely untouched
    const raw = new FakeOpenAI({ apiKey: 'k' });
    expect(raw.checkBrand()).toBe('private-ok');
  });

  test('instances keep instanceof and private-field access', () => {
    const Intercepted = interceptProviderClass('openai', FakeOpenAI);
    const client = new Intercepted({ apiKey: 'k' });

    expect(client instanceof FakeOpenAI).toBe(true);
    // Pre-init passthrough binds methods to the raw instance, so private
    // field brand checks do not blow up
    expect(client.checkBrand()).toBe('private-ok');
  });

  test('pre-init: calls pass through to the raw client', async () => {
    const Intercepted = interceptProviderClass('openai', FakeOpenAI);
    const client = new Intercepted({ apiKey: 'k' });

    const res = await client.chat.completions.create({ model: 'gpt-4o', messages: [] });
    expect(res.id).toBe('cmpl-1');
  });

  test('post-init: governance engages (PII block enforced)', async () => {
    const Intercepted = interceptProviderClass('openai', FakeOpenAI);
    init({ api_key: 'test', sample_rate: 1, pii_policy: {} });
    const client = new Intercepted({ apiKey: 'k' });

    await expect(client.chat.completions.create(SSN_PROMPT)).rejects.toThrow();
  });

  test('constructed before init, governed after init', async () => {
    const Intercepted = interceptProviderClass('openai', FakeOpenAI);
    const client = new Intercepted({ apiKey: 'k' });

    // Ungoverned while uninitialized
    const ok = await client.chat.completions.create({ model: 'gpt-4o', messages: [] });
    expect(ok.id).toBe('cmpl-1');

    init({ api_key: 'test', sample_rate: 1, pii_policy: {} });

    // Same instance is now governed
    await expect(client.chat.completions.create(SSN_PROMPT)).rejects.toThrow();
  });

  test('explicit wrap() on an intercepted instance does not double-wrap', () => {
    const Intercepted = interceptProviderClass('openai', FakeOpenAI);
    init({ api_key: 'test', sample_rate: 1 });
    const client = new Intercepted({ apiKey: 'k' });

    expect(wrap(client)).toBe(client);
  });

  test('config.providers narrows coverage: unlisted provider passes through', async () => {
    const Intercepted = interceptProviderClass('openai', FakeOpenAI);
    init({
      api_key: 'test',
      sample_rate: 1,
      pii_policy: {},
      providers: ['anthropic'],
    });
    const client = new Intercepted({ apiKey: 'k' });

    // openai not listed, so the SSN prompt is NOT blocked
    const res = await client.chat.completions.create(SSN_PROMPT);
    expect(res.id).toBe('cmpl-1');
  });

  test('google: models from getGenerativeModel() are governed', async () => {
    const Intercepted = interceptProviderClass('google', FakeGoogleClient);
    init({ api_key: 'test', sample_rate: 1, pii_policy: {} });

    const genAI = new Intercepted();
    const model = genAI.getGenerativeModel({ model: 'gemini-2.5-flash' });

    await expect(model.generateContent('My SSN is 123-45-6789')).rejects.toThrow();
    // Clean prompts still flow
    const res = await model.generateContent('hello there');
    expect(res.response.text()).toBe('gemini says hi');
  });

  test('non-class input is returned unchanged', () => {
    const notAClass = { foo: 1 };
    expect(interceptProviderClass('openai', notAClass)).toBe(notAClass);
    expect(isInterceptionActive()).toBe(false);
  });
});

describe('auto/autoInstrument', () => {
  beforeEach(() => {
    _reset();
    _resetSender();
    _resetInterception();
  });

  function captureWarns(fn: () => void): string[] {
    const original = console.warn;
    const calls: string[] = [];
    console.warn = (...args: unknown[]) => {
      calls.push(args.map(String).join(' '));
    };
    try {
      fn();
    } finally {
      console.warn = original;
    }
    return calls;
  }

  test('warns when config.providers is set but the interceptor is absent', () => {
    const warns = captureWarns(() => {
      init({ api_key: 'test', providers: ['openai'] });
      autoInstrument(getConfig());
    });

    expect(warns.some((w) => w.includes('--import @obsvr/sdk/register'))).toBe(true);
  });

  test('does not warn when the interceptor is active', () => {
    interceptProviderClass('openai', FakeOpenAI);
    const warns = captureWarns(() => {
      init({ api_key: 'test', providers: ['openai'] });
      autoInstrument(getConfig());
    });

    expect(warns.some((w) => w.includes('--import @obsvr/sdk/register'))).toBe(false);
  });
});
