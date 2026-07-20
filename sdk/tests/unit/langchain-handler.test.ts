import { init, _reset } from '../../src/proxy/config';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { ObsvrCallbackHandler } from '../../src/integrations/langchain';

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

const SERIALIZED_OPENAI = {
  id: ['langchain', 'chat_models', 'openai', 'ChatOpenAI'],
  kwargs: { model: 'gpt-4o-mini' },
};

describe('ObsvrCallbackHandler', () => {
  it('pairs handleLLMStart -> handleLLMEnd by runId', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const handler = new ObsvrCallbackHandler();

    await handler.handleLLMStart(SERIALIZED_OPENAI, ['What is 2+2?'], 'run-1');
    await handler.handleLLMEnd(
      {
        generations: [[{ text: 'The answer is 4.' }]],
        llmOutput: {
          tokenUsage: { promptTokens: 12, completionTokens: 6, totalTokens: 18 },
        },
      },
      'run-1',
    );

    await waitForEvents(1);
    const e = sentEvents[0];
    expect(e.source).toBe('langchain_js');
    expect(e.provider).toBe('openai');
    expect(e.model).toBe('gpt-4o-mini');
    expect(e.prompt).toBe('What is 2+2?');
    expect(e.response).toBe('The answer is 4.');
    expect(e.input_tokens).toBe(12);
    expect(e.output_tokens).toBe(6);
    expect(e.total_tokens).toBe(18);
  });

  it('captures the resolved model from generation response_metadata', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const handler = new ObsvrCallbackHandler();

    await handler.handleLLMStart(SERIALIZED_OPENAI, ['ping'], 'run-r');
    await handler.handleLLMEnd(
      {
        generations: [
          [
            {
              text: 'pong',
              message: { response_metadata: { model_name: 'gpt-4o-mini-2024-07-18' } },
            },
          ],
        ],
        llmOutput: {
          tokenUsage: { promptTokens: 1, completionTokens: 1, totalTokens: 2 },
        },
      },
      'run-r',
    );

    await waitForEvents(1);
    expect(sentEvents[0].model).toBe('gpt-4o-mini');
    expect(sentEvents[0].model_resolved).toBe('gpt-4o-mini-2024-07-18');
    // Read from LangChain's response abstraction → framework-mediated tier.
    expect(sentEvents[0].provenance_source).toBe('framework_reported');
  });

  it('handles chat model starts with message arrays', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const handler = new ObsvrCallbackHandler();

    await handler.handleChatModelStart(
      { id: ['langchain', 'chat_models', 'anthropic', 'ChatAnthropic'] },
      [[{ role: 'user', content: 'Hello Claude' }]],
      'run-2',
    );
    await handler.handleLLMEnd(
      { generations: [[{ message: { content: 'Hi human' } }]] },
      'run-2',
    );

    await waitForEvents(1);
    expect(sentEvents[0].provider).toBe('anthropic');
    expect(sentEvents[0].prompt).toContain('user: Hello Claude');
    expect(sentEvents[0].response).toBe('Hi human');
    expect(sentEvents[0].user_input).toBe('Hello Claude');
  });

  it('emits failure event on handleLLMError', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const handler = new ObsvrCallbackHandler();

    await handler.handleLLMStart(SERIALIZED_OPENAI, ['Hi'], 'run-3');
    await handler.handleLLMError(new Error('connection reset'), 'run-3');

    await waitForEvents(1);
    expect(sentEvents[0].success).toBe(false);
    expect(sentEvents[0].error_message).toBe('connection reset');
  });

  it('redacts stored copy when PII is present (observe-only downgrade)', async () => {
    init({ api_key: 'test', sample_rate: 1, pii_policy: {} });
    const handler = new ObsvrCallbackHandler();

    await handler.handleLLMStart(
      SERIALIZED_OPENAI,
      ['my ssn is 123-45-6789'],
      'run-4',
    );
    await handler.handleLLMEnd(
      { generations: [[{ text: 'noted' }]] },
      'run-4',
    );

    await waitForEvents(1);
    const e = sentEvents[0];
    // Block is downgraded to redact-in-event; call already happened
    expect(e.event_type).toBe('llm_call');
    expect(e.action_taken).toBe('redacted');
    expect(e.action_reason).toBe('pii_detected');
    expect(e.prompt).toContain('[REDACTED_SSN]');
    expect(e.prompt).not.toContain('123-45-6789');
  });

  it('ignores ends with no matching start', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const handler = new ObsvrCallbackHandler();
    await handler.handleLLMEnd({ generations: [[{ text: 'x' }]] }, 'ghost');
    await new Promise((r) => setTimeout(r, 20));
    expect(sentEvents).toHaveLength(0);
  });

  it('is a no-op when SDK is not initialized', async () => {
    const handler = new ObsvrCallbackHandler();
    await expect(
      handler.handleLLMStart(SERIALIZED_OPENAI, ['Hi'], 'run-5'),
    ).resolves.toBeUndefined();
    await handler.handleLLMEnd({ generations: [[{ text: 'x' }]] }, 'run-5');
    expect(sentEvents).toHaveLength(0);
  });
});
