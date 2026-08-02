import { init, _reset } from '../../src/proxy/config';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { ObsvrCallbackHandler } from '../../src/integrations/langchain';

let sentEvents: any[] = [];

beforeEach(() => {
  _reset();
  _resetSender();
  sentEvents = [];
  (global as any).fetch = async (_url: any, opts: any) => {
    // Agent runs emit several events, which the sender batches into one body.
    const body = JSON.parse(opts.body);
    Array.isArray(body) ? sentEvents.push(...body) : sentEvents.push(body);
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

// ── Loop detection wiring (twin: sdk-python/tests/test_integrations.py) ──────

describe('ObsvrCallbackHandler: agent loop detection', () => {
  const AGENT_SERIALIZED = { id: ['langchain', 'agents', 'AgentExecutor'] };
  const ACTION = { tool: 'search', toolInput: 'q' };

  it('blocks the run and emits LOOP_DETECTED past the iteration limit', async () => {
    init({
      api_key: 'test',
      sample_rate: 1,
      agent_policy: { loopDetection: { maxIterations: 2, windowMs: 60_000, action: 'block' } },
    });
    const handler = new ObsvrCallbackHandler();
    await handler.handleChainStart(AGENT_SERIALIZED, { input: 'go' }, 'run-loop');
    await handler.handleAgentAction(ACTION, 'run-loop');
    await handler.handleAgentAction(ACTION, 'run-loop');
    await expect(handler.handleAgentAction(ACTION, 'run-loop')).rejects.toThrow(
      /\[obsvr\] Loop detected/,
    );

    for (let i = 0; i < 100 && !sentEvents.some((e) => e.operation === 'langchain.agent.loop_detected'); i++) {
      await new Promise((r) => setTimeout(r, 5));
    }
    const loop = sentEvents.filter((e) => e.operation === 'langchain.agent.loop_detected');
    expect(loop).toHaveLength(1);
    expect(loop[0].reason_code).toBe('LOOP_DETECTED');
    expect(loop[0].event_type).toBe('loop_detected');
    expect(loop[0].action_taken).toBe('blocked');
    expect(loop[0].metadata.loop_iteration_count).toBe(3);
    expect(loop[0].metadata.loop_action).toBe('block');
  });

  it('emits nothing when loopDetection is not configured', async () => {
    init({ api_key: 'test', sample_rate: 1, agent_policy: {} });
    const handler = new ObsvrCallbackHandler();
    await handler.handleChainStart(AGENT_SERIALIZED, { input: 'go' }, 'run-noloop');
    for (let i = 0; i < 5; i++) {
      await handler.handleAgentAction(ACTION, 'run-noloop');
    }
    await new Promise((r) => setTimeout(r, 20));
    expect(sentEvents.filter((e) => String(e.operation).includes('loop_detected'))).toEqual([]);
  });
});

// ── The double-gate credit (twin: sdk-python/tests/test_integrations.py) ─────
//
// The classic executor delivers BOTH pre-tool callbacks for one tool call, so
// the second delivery is discounted. Discounting it with a flag disarmed the
// gate for everything after the first agent-action dispatch, and `copy()`
// returns `this`, so one handler instance carries that across every child
// manager and every later run.

describe('ObsvrCallbackHandler: the double-gate credit is per call', () => {
  const AGENT_SERIALIZED = { id: ['langchain', 'agents', 'AgentExecutor'] };
  const TOOL_SER = { id: ['langchain', 'tools', 'DynamicStructuredTool'] };
  const ACTION = { tool: 'send_money', toolInput: '{}' };

  it('still gates handleToolStart after an agent-action dispatch', async () => {
    init({ api_key: 'test', sample_rate: 1, agent_policy: { deniedTools: ['send_money'] } });
    const handler = new ObsvrCallbackHandler();

    // A run that delivers the legacy callback. Nothing in the shipped JS agent
    // stack dispatches it any more, but the core callback manager still exposes
    // it, so any caller can — and one call used to be enough.
    await handler.handleChainStart(AGENT_SERIALIZED, { input: 'go' }, 'run-a');
    await expect(handler.handleAgentAction(ACTION, 'run-a')).rejects.toThrow(
      /\[obsvr\] Tool blocked/,
    );
    await handler.handleChainError(new Error('blocked'), 'run-a');

    // A LATER run on the SAME handler, delivering only the modern callback.
    await handler.handleChainStart(AGENT_SERIALIZED, { input: 'go' }, 'run-b');
    await expect(
      handler.handleToolStart(TOOL_SER, '{}', 'tool-b', 'run-b', undefined, undefined, 'send_money'),
    ).rejects.toThrow(/\[obsvr\] Tool blocked/);
  });

  it('charges one step when both callbacks arrive for one tool call', async () => {
    init({ api_key: 'test', sample_rate: 1, agent_policy: {} });
    const handler = new ObsvrCallbackHandler();
    await handler.handleChainStart(AGENT_SERIALIZED, { input: 'go' }, 'run-c');
    for (let i = 0; i < 2; i++) {
      await handler.handleAgentAction({ tool: 'search', toolInput: 'q' }, 'run-c');
      await handler.handleToolStart(TOOL_SER, 'q', `tool-c${i}`, 'run-c', undefined, undefined, 'search');
    }
    await waitForEvents(2);
    const calls = sentEvents.filter((e) => e.operation === 'langchain.tool.call');
    expect(calls.map((e) => e.metadata.step_index)).toEqual([0, 1]);
  });

  it('finds the credit through the node that dispatched the tool', async () => {
    // The graph runtimes put a node run between the agent run and the tool run,
    // so a credit granted on the agent run is not on the tool's direct parent.
    init({ api_key: 'test', sample_rate: 1, agent_policy: {} });
    const handler = new ObsvrCallbackHandler();
    await handler.handleChainStart(AGENT_SERIALIZED, { input: 'go' }, 'run-d');
    await handler.handleChainStart({ id: ['tools'] }, {}, 'node-d', 'run-d');
    await handler.handleAgentAction({ tool: 'search', toolInput: 'q' }, 'run-d');
    await handler.handleToolStart(TOOL_SER, 'q', 'tool-d', 'node-d', undefined, undefined, 'search');
    await waitForEvents(1);
    const calls = sentEvents.filter((e) => e.operation === 'langchain.tool.call');
    expect(calls).toHaveLength(1);
  });
});
