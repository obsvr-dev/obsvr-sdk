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
    init({ api_key: 'test', sample_rate: 1 });
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
    expect(sentEvents[0].action_taken).toBe('redacted');
    expect(sentEvents[0].prompt).toContain('[REDACTED_SSN]');
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
