import { init, _reset } from '../../src/proxy/config';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { obsvrLlamaIndexHandler } from '../../src/integrations/llamaindex';

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

class FakeCallbackManager {
  handlers = new Map<string, Array<(event: unknown) => void>>();

  on(event: string, handler: (event: unknown) => void) {
    const arr = this.handlers.get(event) ?? [];
    arr.push(handler);
    this.handlers.set(event, arr);
    return this;
  }

  dispatch(event: string, detail: unknown) {
    for (const h of this.handlers.get(event) ?? []) h({ detail });
  }
}

describe('obsvrLlamaIndexHandler', () => {
  it('throws a helpful error without a callback manager', () => {
    expect(() => obsvrLlamaIndexHandler(undefined)).toThrow(
      'requires a CallbackManager',
    );
  });

  it('samples out a clean observe-only call at sample_rate 0 in enforce mode', async () => {
    init({ api_key: 'test', sample_rate: 0 });
    const manager = new FakeCallbackManager();
    obsvrLlamaIndexHandler(manager);

    manager.dispatch('llm-start', {
      id: 'evt-sampled',
      messages: [{ role: 'user', content: 'hello' }],
    });
    manager.dispatch('llm-end', {
      id: 'evt-sampled',
      response: { message: { content: 'ok' } },
    });

    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(sentEvents).toHaveLength(0);
  });

  it('attributes the provider and captures tokens off the raw provider response', async () => {
    // Two defects at once, and neither was a reader that broke: `provider` was
    // a hardcoded "unknown" literal, and there was no token-reading code on
    // this path AT ALL. So LlamaIndex traffic could never be attributed to a
    // provider in any report, and could never be metered or counted against a
    // token budget, at any version.
    init({ api_key: 'test', sample_rate: 1 });
    const manager = new FakeCallbackManager();
    obsvrLlamaIndexHandler(manager);

    manager.dispatch('llm-start', {
      id: 'evt-p',
      messages: [{ role: 'user', content: 'what is 2+2' }],
    });
    manager.dispatch('llm-end', {
      id: 'evt-p',
      response: {
        message: { content: 'four' },
        raw: {
          model: 'gpt-4o-mini-2024-07-18',
          usage: { prompt_tokens: 12, completion_tokens: 1, total_tokens: 13 },
        },
      },
    });

    await waitForEvents(1);
    const e = sentEvents[0];
    expect(e.provider).toBe('openai');
    expect(e.model).toBe('gpt-4o-mini-2024-07-18');
    expect(e.model_resolved).toBe('gpt-4o-mini-2024-07-18');
    expect(e.input_tokens).toBe(12);
    expect(e.output_tokens).toBe(1);
    expect(e.total_tokens).toBe(13);
  });

  it('reads Gemini-shaped usage off the same raw response', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const manager = new FakeCallbackManager();
    obsvrLlamaIndexHandler(manager);

    manager.dispatch('llm-start', { id: 'evt-g', messages: [{ role: 'user', content: 'hi' }] });
    manager.dispatch('llm-end', {
      id: 'evt-g',
      response: {
        message: { content: 'ok' },
        raw: {
          modelVersion: 'gemini-2.5-flash',
          usageMetadata: { promptTokenCount: 4, candidatesTokenCount: 2, totalTokenCount: 6 },
        },
      },
    });

    await waitForEvents(1);
    const e = sentEvents[0];
    expect(e.provider).toBe('google');
    expect(e.model).toBe('gemini-2.5-flash');
    expect(e.input_tokens).toBe(4);
    expect(e.total_tokens).toBe(6);
  });

  it('says unknown only when the provider is genuinely undetermined', async () => {
    // "unknown" has to keep meaning something. With no raw response there is
    // nothing to infer from, and the counts stay absent rather than zero.
    init({ api_key: 'test', sample_rate: 1 });
    const manager = new FakeCallbackManager();
    obsvrLlamaIndexHandler(manager);

    manager.dispatch('llm-start', { id: 'evt-u', messages: [{ role: 'user', content: 'hi' }] });
    manager.dispatch('llm-end', { id: 'evt-u', response: { message: { content: 'ok' } } });

    await waitForEvents(1);
    const e = sentEvents[0];
    expect(e.provider).toBe('unknown');
    expect(e.model).toBe('unknown');
    expect(e.input_tokens).toBeUndefined();
    expect(e.total_tokens).toBeUndefined();
  });

  it('pairs llm-start -> llm-end by id', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const manager = new FakeCallbackManager();
    obsvrLlamaIndexHandler(manager);

    manager.dispatch('llm-start', {
      id: 'evt-1',
      model: 'gpt-4o',
      messages: [{ role: 'user', content: 'Summarize this' }],
    });
    manager.dispatch('llm-end', {
      id: 'evt-1',
      response: { message: { role: 'assistant', content: 'Summary done.' } },
    });

    await waitForEvents(1);
    const e = sentEvents[0];
    expect(e.source).toBe('llamaindex_ts');
    expect(e.model).toBe('gpt-4o');
    expect(e.prompt).toContain('user: Summarize this');
    expect(e.response).toBe('Summary done.');
    expect(e.user_input).toBe('Summarize this');
  });

  it('captures the resolved model from response.raw as framework_reported', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const manager = new FakeCallbackManager();
    obsvrLlamaIndexHandler(manager);

    manager.dispatch('llm-start', {
      id: 'evt-raw',
      model: 'gpt-4o',
      messages: [{ role: 'user', content: 'Hi' }],
    });
    manager.dispatch('llm-end', {
      id: 'evt-raw',
      response: {
        message: { role: 'assistant', content: 'ok' },
        raw: { model: 'gpt-4o-2024-08-06' },
      },
    });

    await waitForEvents(1);
    expect(sentEvents[0].model_resolved).toBe('gpt-4o-2024-08-06');
    // LlamaIndex reads response.raw — framework-mediated, not a direct provider read.
    expect(sentEvents[0].provenance_source).toBe('framework_reported');
  });

  it('accumulates llm-stream chunks as fallback response', async () => {
    init({ api_key: 'test', sample_rate: 0, enforcement_mode: 'monitor' });
    const manager = new FakeCallbackManager();
    obsvrLlamaIndexHandler(manager);

    manager.dispatch('llm-start', {
      id: 'evt-2',
      messages: [{ role: 'user', content: 'Hi' }],
    });
    manager.dispatch('llm-stream', { id: 'evt-2', chunk: { delta: 'Hel' } });
    manager.dispatch('llm-stream', { id: 'evt-2', chunk: { delta: 'lo' } });
    manager.dispatch('llm-end', { id: 'evt-2' });

    await waitForEvents(1);
    expect(sentEvents[0].response).toBe('Hello');
  });

  it('redacts stored copy when PII is present (observe-only)', async () => {
    init({ api_key: 'test', sample_rate: 1, pii_policy: {} });
    const manager = new FakeCallbackManager();
    obsvrLlamaIndexHandler(manager);

    manager.dispatch('llm-start', {
      id: 'evt-3',
      messages: [{ role: 'user', content: 'ssn 123-45-6789' }],
    });
    manager.dispatch('llm-end', {
      id: 'evt-3',
      response: { message: { content: 'ok' } },
    });

    await waitForEvents(1);
    expect(sentEvents[0].event_type).toBe('llm_call');
    expect(sentEvents[0].action_taken).toBe('not_evaluated');
    expect(sentEvents[0].prompt).toContain('[REDACTED_SSN]');
    expect(sentEvents[0].metadata.obsvr_telemetry).toMatchObject({
      stored_redaction_scope: 'observe_only',
      stored_redaction_types: ['ssn'],
      stored_redaction_outbound_unmodified: true,
      stored_redaction_requested_action: 'block',
    });
  });

  it('ignores llm-end with no matching start', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const manager = new FakeCallbackManager();
    obsvrLlamaIndexHandler(manager);

    manager.dispatch('llm-end', { id: 'ghost', response: 'x' });
    await new Promise((r) => setTimeout(r, 20));
    expect(sentEvents).toHaveLength(0);
  });

  it('is a no-op when SDK is not initialized', async () => {
    const manager = new FakeCallbackManager();
    obsvrLlamaIndexHandler(manager);

    manager.dispatch('llm-start', {
      id: 'evt-4',
      messages: [{ role: 'user', content: 'Hi' }],
    });
    manager.dispatch('llm-end', { id: 'evt-4', response: 'x' });
    await new Promise((r) => setTimeout(r, 20));
    expect(sentEvents).toHaveLength(0);
  });
});
