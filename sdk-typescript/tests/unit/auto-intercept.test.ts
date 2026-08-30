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
  autoGovernanceStatus,
  interceptProviderNamespace,
  interceptMcpClientClass,
  interceptMcpNamespace,
  interceptOpenAIAgentClass,
  interceptOpenAIAgentsNamespace,
  isInterceptorInstalled,
  markInterceptorInstalled,
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

/** Maintained @google/genai shape: generation methods live under `.models`. */
class FakeMaintainedGoogleClient {
  models = {
    generateContent: async (req: { model: string; contents: string }) => ({
      modelVersion: `${req.model}-001`,
      text: `gemini says: ${req.contents}`,
    }),
  };
}

class FakeMcpClient {
  calls: string[] = [];

  async callTool(params: { name: string }): Promise<{ content: unknown[] }> {
    this.calls.push(params.name);
    return { content: [] };
  }
}

class FakeAgent {
  tools: unknown[];
  handoffs: unknown[];

  constructor(config: { tools?: unknown[]; handoffs?: unknown[] }) {
    this.tools = config.tools ?? [];
    this.handoffs = config.handoffs ?? [];
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

  test('google: maintained client.models calls are governed', async () => {
    const Intercepted = interceptProviderClass('google', FakeMaintainedGoogleClient);
    init({ api_key: 'test', sample_rate: 1, pii_policy: {} });

    const genAI = new Intercepted();
    await expect(
      genAI.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: 'My SSN is 123-45-6789',
      }),
    ).rejects.toThrow();
    const res = await genAI.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: 'hello there',
    });
    expect(res.text).toBe('gemini says: hello there');
  });

  test('non-class input is returned unchanged', () => {
    const notAClass = { foo: 1 };
    expect(interceptProviderClass('openai', notAClass)).toBe(notAClass);
    expect(isInterceptionActive()).toBe(false);
  });

  test('namespace client exports are intercepted without mutating the namespace', () => {
    const namespace = { OpenAI: FakeOpenAI, helper: 'unchanged' };
    const governed = interceptProviderNamespace('openai', namespace, ['OpenAI']);

    expect(governed).not.toBe(namespace);
    expect(namespace.OpenAI).toBe(FakeOpenAI);
    expect(governed.helper).toBe('unchanged');
    expect(governed.OpenAI).not.toBe(FakeOpenAI);
    expect(isInterceptionActive()).toBe(true);
    expect(autoGovernanceStatus().boundProviders).toEqual(['openai']);
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

  test('does not warn while a startup interceptor is armed before provider import', () => {
    markInterceptorInstalled('esm');
    const warns = captureWarns(() => {
      init({ api_key: 'test', providers: ['openai'] });
      autoInstrument(getConfig());
    });

    expect(isInterceptorInstalled('esm')).toBe(true);
    expect(isInterceptionActive()).toBe(false);
    expect(warns.some((w) => w.includes('--import @obsvr/sdk/register'))).toBe(false);
  });

  test('status distinguishes armed hooks from bound providers', () => {
    markInterceptorInstalled('cjs');
    expect(autoGovernanceStatus()).toEqual({
      interceptors: { esm: false, cjs: true },
      boundProviders: [],
      active: false,
    });

    interceptProviderClass('anthropic', FakeOpenAI);
    expect(autoGovernanceStatus()).toEqual({
      interceptors: { esm: false, cjs: true },
      boundProviders: ['anthropic'],
      active: true,
    });
  });
});

describe('auto/MCP construction interception', () => {
  beforeEach(() => {
    _reset();
    _resetSender();
    _resetInterception();
  });

  test('a denied tool never reaches a Client constructed after init', async () => {
    const Intercepted = interceptMcpClientClass(FakeMcpClient);
    init({
      api_key: 'test',
      sample_rate: 1,
      mcpToolPolicy: { deniedTools: ['send_contract'] },
    });
    const client = new Intercepted();

    await expect(client.callTool({ name: 'send_contract' })).rejects.toThrow();
    expect(client.calls).toEqual([]);
  });

  test('a Client constructed before init becomes governed after init', async () => {
    const Intercepted = interceptMcpClientClass(FakeMcpClient);
    const client = new Intercepted();

    await client.callTool({ name: 'read_contract' });
    init({
      api_key: 'test',
      sample_rate: 1,
      mcpToolPolicy: { deniedTools: ['send_contract'] },
    });
    await expect(client.callTool({ name: 'send_contract' })).rejects.toThrow();

    expect(client.calls).toEqual(['read_contract']);
  });

  test('the CommonJS namespace is proxied without mutation', () => {
    const namespace = { Client: FakeMcpClient, helper: 'unchanged' };
    const intercepted = interceptMcpNamespace(namespace);

    expect(intercepted).not.toBe(namespace);
    expect(namespace.Client).toBe(FakeMcpClient);
    expect(intercepted.Client).not.toBe(FakeMcpClient);
    expect(intercepted.helper).toBe('unchanged');
  });
});

describe('auto/OpenAI Agents construction interception', () => {
  beforeEach(() => {
    _reset();
    _resetSender();
    _resetInterception();
  });

  test('new Agents receive a pre-execution function-tool guardrail', async () => {
    const Intercepted = interceptOpenAIAgentClass(FakeAgent);
    init({
      api_key: 'test',
      sample_rate: 1,
      agent_policy: { deniedTools: ['send_contract'] },
    } as any);
    const tool = {
      type: 'function',
      name: 'send_contract',
      inputGuardrails: [] as Array<{ name: string; run: (data: unknown) => Promise<any> }>,
    };
    const agent = new Intercepted({ tools: [tool] });

    expect(tool.inputGuardrails.map((guardrail) => guardrail.name)).toContain(
      'obsvr_tool_gate',
    );
    const verdict = await tool.inputGuardrails[0].run({
      toolCall: { name: 'send_contract', callId: 'call-1' },
    });
    expect(verdict.behavior.type).toBe('rejectContent');
    expect(agent.tools).toContain(tool);
  });

  test('the CommonJS package namespace is proxied without mutation', () => {
    const namespace = { Agent: FakeAgent, helper: 'unchanged' };
    const intercepted = interceptOpenAIAgentsNamespace(namespace);

    expect(intercepted).not.toBe(namespace);
    expect(namespace.Agent).toBe(FakeAgent);
    expect(intercepted.Agent).not.toBe(FakeAgent);
    expect(intercepted.helper).toBe('unchanged');
  });
});
