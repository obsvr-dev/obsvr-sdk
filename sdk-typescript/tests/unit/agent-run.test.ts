import { init, _reset } from '../../src/proxy/config';
import { wrap } from '../../src/proxy/wrapper';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { agentRun } from '../../src/integrations/agent-run';
import { obsvrGovernTool } from '../../src/integrations/tools';
import { currentAgentRunId } from '../../src/proxy/agent-run';
import { span } from '../../src/proxy/span';

/**
 * Agent-run lifecycle: `agentRun(...)` forms one run and every governed action
 * inside it (proxy LLM calls, obsvrGovernTool tool calls) auto-joins it via the
 * ambient agent_run_id. This is what populates the dashboard Runs tab for
 * tool-governed frameworks (LlamaIndex, Vercel AI).
 */
describe('agentRun lifecycle', () => {
  let sent: any[] = [];

  beforeEach(() => {
    _reset();
    _resetSender();
    sent = [];
    (global as any).fetch = async (_url: any, opts: any) => {
      const body = JSON.parse(opts.body);
      Array.isArray(body) ? sent.push(...body) : sent.push(body);
      return { ok: true, status: 200, json: async () => ({}) };
    };
  });

  afterEach(() => {
    delete (global as any).fetch;
  });

  async function drain(n: number): Promise<void> {
    for (let i = 0; i < 200 && sent.length < n; i++) {
      await new Promise((r) => setTimeout(r, 5));
    }
  }

  it('emits signed run.start and run.finish with a shared agent_run_id', async () => {
    init({ api_key: 'test', sample_rate: 1 });

    await agentRun('my-agent', async () => {
      // no-op body
    }, { source: 'llamaindex_ts' });

    await drain(2);
    const start = sent.find((e) => e.operation === 'llamaindex_ts.agent.run.start');
    const finish = sent.find((e) => e.operation === 'llamaindex_ts.agent.run.finish');
    expect(start).toBeDefined();
    expect(finish).toBeDefined();
    expect(start.metadata.agent_run_id).toBeTruthy();
    // start and finish share the run id
    expect(finish.metadata.agent_run_id).toBe(start.metadata.agent_run_id);
    // both are fully signed
    expect(start.sdk_sig).toHaveLength(64);
    expect(finish.sdk_sig).toHaveLength(64);
    expect(finish.success).toBe(true);
  });

  it('stamps agent_run_id on a span() emitted inside the run', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    let runId: string | undefined;
    await agentRun('agent', async () => {
      runId = currentAgentRunId();
      span('child-step', 'tool', () => 'ok');
    }, { source: 'llamaindex_ts' });

    await drain(3);
    const spanEvent = sent.find((e) => e.source === 'span' && e.operation === 'child-step');
    expect(spanEvent).toBeDefined();
    // Before the fix, TS emitSpanEvent skipped withRunMetadata, so a span inside
    // a run carried only trace_id and was orphaned from the run — while the
    // identical Python span (stamped in build_audit_event) grouped correctly.
    expect(spanEvent.metadata.agent_run_id).toBe(runId);
  });

  it('groups a proxied LLM call under the run', async () => {
    init({ api_key: 'test', sample_rate: 1 });

    const client = wrap({
      chat: {
        completions: {
          create: async (..._a: any[]) => ({
            id: 'x',
            model: 'gpt-4o',
            choices: [{ message: { content: 'hi' } }],
            usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
          }),
        },
      },
    });

    let runIdInside: string | undefined;
    await agentRun('llm-agent', async () => {
      runIdInside = currentAgentRunId();
      await client.chat.completions.create({
        model: 'gpt-4o',
        messages: [{ role: 'user', content: 'hi' }],
      } as any);
    }, { source: 'vercel_ai' });

    await drain(3);
    const start = sent.find((e) => e.operation === 'vercel_ai.agent.run.start');
    const call = sent.find((e) => e.operation === 'chat.completions.create');
    expect(start).toBeDefined();
    expect(call).toBeDefined();
    // the LLM call carries the SAME run id as the run envelope
    expect(call.metadata.agent_run_id).toBe(start.metadata.agent_run_id);
    expect(call.metadata.agent_run_id).toBe(runIdInside);
  });

  it('groups an obsvrGovernTool tool call under the run', async () => {
    init({ api_key: 'test', sample_rate: 1 });

    const tool = obsvrGovernTool(
      { name: 'calculator', execute: async (_i: unknown) => 42 },
      { name: 'calculator' },
    );

    await agentRun('tool-agent', async () => {
      await (tool as any).execute({ a: 1, b: 2 });
    }, { source: 'llamaindex_ts' });

    await drain(3);
    const start = sent.find((e) => e.operation === 'llamaindex_ts.agent.run.start');
    const toolCall = sent.find((e) => e.operation === 'tool.call');
    expect(start).toBeDefined();
    expect(toolCall).toBeDefined();
    expect(toolCall.metadata.agent_run_id).toBe(start.metadata.agent_run_id);
  });

  it('emits run.finish with success=false when the body throws, and re-throws', async () => {
    init({ api_key: 'test', sample_rate: 1 });

    await expect(
      agentRun('boom-agent', async () => {
        throw new Error('agent exploded');
      }, { source: 'llamaindex_ts' }),
    ).rejects.toThrow('agent exploded');

    await drain(2);
    const finish = sent.find((e) => e.operation === 'llamaindex_ts.agent.run.finish');
    expect(finish).toBeDefined();
    expect(finish.success).toBe(false);
  });

  it('does NOT stamp agent_run_id on events outside any run scope', async () => {
    init({ api_key: 'test', sample_rate: 1 });

    const client = wrap({
      chat: {
        completions: {
          create: async (..._a: any[]) => ({ id: 'x', choices: [{ message: { content: 'hi' } }] }),
        },
      },
    });
    await client.chat.completions.create({
      model: 'gpt-4o',
      messages: [{ role: 'user', content: 'hi' }],
    } as any);

    await drain(1);
    const call = sent.find((e) => e.operation === 'chat.completions.create');
    expect(call).toBeDefined();
    expect(call.metadata?.agent_run_id).toBeUndefined();
    expect(currentAgentRunId()).toBeUndefined();
  });
});
