/**
 * The provider tool runners, governed and emitted as a SEQUENCE.
 *
 * Two properties are load-bearing here and each is asserted directly rather
 * than inferred from an event count:
 *
 * 1. **The provider is not reached until governance resolves, and not at all
 *    when it refuses.** Same invariant as the `.stream()` helpers, same reason:
 *    enforcement is asynchronous, so a runner constructed first and governed
 *    afterwards would be a cancellation after disclosure rather than a block.
 *
 * 2. **The stand-in mirrors the real runner's thenability, in BOTH
 *    directions.** The `.stream()` runners are not thenable, and synthesising a
 *    `then` for them made `await client.messages.stream(...)` hang forever.
 *    Anthropic's tool runner IS thenable by design — `await runner` is
 *    documented as equivalent to `runUntilDone()` — so refusing a `then` there
 *    fails the opposite way and more quietly: `await` hands back the stand-in
 *    itself instead of the final message, and nothing throws. The second case
 *    is the one this file exists to pin, because it cannot announce itself.
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

const settle = () => new Promise((r) => setTimeout(r, 10));

async function drain() {
  await settle();
  await flushQueue(getConfig());
}

const ops = () => sentEvents.map((e) => e.operation);
const byOp = (op: string) => sentEvents.filter((e) => e.operation === op);

// ---------------------------------------------------------------------------
// OpenAI — chat.completions.runTools
// ---------------------------------------------------------------------------

/**
 * A stand-in for `ChatCompletionRunner`. It emits the same two events the real
 * one does — `chatCompletion` per model call and `message` per appended
 * message — because those, not the positional `functionToolCall` pair, are
 * what carry the tool_call ids.
 */
function fakeRunTools(script: {
  turns: { completion: unknown; assistant?: unknown; tools?: unknown[] }[];
}) {
  const listeners = new Map<string, ((...a: unknown[]) => void)[]>();
  const emit = (ev: string, arg: unknown) =>
    (listeners.get(ev) ?? []).forEach((l) => l(arg));

  // A real runner starts on construction and settles once; `done()` only
  // AWAITS that. Replaying the script per `done()` call would make the fake
  // emit twice as soon as both the caller and the wrapper awaited it — which
  // is a property of the fake, not of the code under test.
  let started: Promise<void> | undefined;
  const run = () =>
    (started ??= (async () => {
      await Promise.resolve();
      for (const t of script.turns) {
        emit('chatCompletion', t.completion);
        if (t.assistant) emit('message', t.assistant);
        for (const tool of t.tools ?? []) emit('message', tool);
      }
    })());

  const runner: Record<string, unknown> = {
    messages: [] as unknown[],
    on(event: string, listener: (...a: unknown[]) => void) {
      listeners.set(event, [...(listeners.get(event) ?? []), listener]);
      return runner;
    },
    off() {
      return runner;
    },
    done() {
      return run();
    },
  };
  return runner;
}

const completion = (text: string) => ({
  id: 'cmpl',
  model: 'gpt-4o-mini-2024-07-18',
  choices: [{ message: { role: 'assistant', content: text } }],
  usage: { prompt_tokens: 12, completion_tokens: 3, total_tokens: 15 },
});

describe('chat.completions.runTools', () => {
  it('governs every internal model turn and blocks before the next transport', async () => {
    init({
      api_key: 'test',
      sample_rate: 1,
      pii_policy: { rules: { ssn: 'block' } },
    });

    let providerCalls = 0;
    const root: Record<string, any> = {};
    const completions: Record<string, any> = {
      _client: root,
      async create(_body: unknown) {
        providerCalls += 1;
        return completion('ok');
      },
      runTools: undefined,
    };
    // The resource reads its client through `this._client`; using the captured
    // variable here would measure the test rather than the runner receiver.
    completions.runTools = function runTools(this: { _client: Record<string, any> }) {
      let run: Promise<void> | undefined;
      return {
        on() { return this; },
        off() { return this; },
        done: () => (run ??= (async () => {
          await this._client.chat.completions.create({
            model: 'gpt-4o-mini',
            messages: [{ role: 'user', content: 'clean first turn' }],
          });
          await this._client.chat.completions.create({
            model: 'gpt-4o-mini',
            messages: [
              { role: 'user', content: 'clean first turn' },
              { role: 'tool', content: 'tool returned 123-45-6789' },
            ],
          });
        })()),
      };
    };
    root.chat = { completions };

    const client = wrap(root);
    const runner = client.chat.completions.runTools({
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: 'clean first turn' }],
      tools: [],
    });

    await expect(runner.done()).rejects.toThrow();
    expect(providerCalls).toBe(1);
  });

  it('emits one event per model call and per tool call, inside a run pair', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    let reached = 0;
    const client = wrap({
      chat: {
        completions: {
          create: async () => completion('x'),
          runTools: () => {
            reached += 1;
            return fakeRunTools({
              turns: [
                {
                  completion: completion('calling'),
                  assistant: {
                    role: 'assistant',
                    tool_calls: [
                      { id: 'call_a', function: { name: 'get_weather', arguments: '{"city":"NYC"}' } },
                    ],
                  },
                  tools: [{ role: 'tool', tool_call_id: 'call_a', content: '72F and clear' }],
                },
                { completion: completion('it is 72F') },
              ],
            });
          },
        },
      },
    } as any);

    const runner = client.chat.completions.runTools({
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: 'weather?' }],
      tools: [],
    });

    // Synchronous return, and NOT a thenable — the OpenAI runner is not one.
    expect(typeof runner.on).toBe('function');
    expect((runner as Record<string, unknown>).then).toBeUndefined();

    await runner.done();
    await drain();

    expect(reached).toBe(1);
    expect(ops()).toEqual([
      'chat.completions.runTools.start',
      'chat.completions.runTools.llm',
      'chat.completions.runTools.tool',
      'chat.completions.runTools.llm',
      'chat.completions.runTools.finish',
    ]);

    // Every event belongs to the same run.
    const runIds = new Set(
      sentEvents.map((e) => (e.metadata as Record<string, unknown>)?.agent_run_id),
    );
    expect(runIds.size).toBe(1);
    expect([...runIds][0]).toBeTruthy();

    // The model calls carry real content and real counts.
    const llm = byOp('chat.completions.runTools.llm');
    expect(llm).toHaveLength(2);
    expect(llm[0].provider).toBe('openai');
    expect(llm[0].response).toBe('calling');
    expect(llm[0].input_tokens).toBe(12);
    expect(llm[0].output_tokens).toBe(3);
    expect(llm[0].model_resolved).toBe('gpt-4o-mini-2024-07-18');

    // The tool call carries BOTH halves and says where its text came from.
    const tool = byOp('chat.completions.runTools.tool');
    expect(tool).toHaveLength(1);
    expect(tool[0].prompt).toBe('{"city":"NYC"}');
    expect(tool[0].response).toBe('72F and clear');
    const meta = tool[0].metadata as Record<string, unknown>;
    expect(meta.tool_name).toBe('get_weather');
    expect(meta.tool_call_id).toBe('call_a');
    // Rides in metadata until ingest has its own column.
    expect(JSON.stringify(tool[0])).toContain('tool_result');

    // NO TOOL GATE RAN, and the event says so. This config declares no
    // tool-level control at all, so there is nothing for the callback gate to
    // decide and it is not installed — which is a different absence from a gate
    // that could not be installed, and the record distinguishes them. A live
    // probe watched a tainted session execute a tool named in
    // `destructiveTools` while the event called it allowed.
    const tel = (tool[0].metadata as Record<string, unknown>)
      .obsvr_telemetry as Record<string, unknown>;
    expect(tel?.policy_not_evaluated).toEqual({
      surface: 'chat.completions.runTools.tool',
      gate: 'tool_gate',
      reason:
        "this tool's callback is invoked by the provider's runner and obsvr is not on that boundary",
    });
    expect(meta.tool_gate).toBe('absent');
    expect(meta.tool_gate_absent_reason).toBe('no_tools_in_request');
    // The model-call events are NOT marked: those genuinely went through the
    // invocation's pre-call pipeline, so marking them would be the opposite
    // error.
    expect(
      ((llm[0].metadata as Record<string, unknown>)?.obsvr_telemetry as Record<string, unknown>)
        ?.policy_not_evaluated,
    ).toBeUndefined();

    const finish = byOp('chat.completions.runTools.finish')[0];
    expect(finish.success).toBe(true);
    expect((finish.metadata as Record<string, unknown>).model_calls).toBe(2);
    expect((finish.metadata as Record<string, unknown>).tool_calls).toBe(1);
  });

  it('pairs parallel tool calls by id, not by arrival order', async () => {
    // A model asking for two tools in one turn is the normal case, and the
    // runner's own functionToolCall/functionToolCallResult events carry no id
    // on either side. Pairing those positionally mis-attributes every result
    // the moment the tools finish out of order, which they routinely do.
    init({ api_key: 'test', sample_rate: 1 });
    const client = wrap({
      chat: {
        completions: {
          create: async () => completion('x'),
          runTools: () =>
            fakeRunTools({
              turns: [
                {
                  completion: completion('calling both'),
                  assistant: {
                    role: 'assistant',
                    tool_calls: [
                      { id: 'call_a', function: { name: 'weather', arguments: '{"city":"NYC"}' } },
                      { id: 'call_b', function: { name: 'stocks', arguments: '{"sym":"ACME"}' } },
                    ],
                  },
                  // Deliberately the reverse of the requested order.
                  tools: [
                    { role: 'tool', tool_call_id: 'call_b', content: '$41.20' },
                    { role: 'tool', tool_call_id: 'call_a', content: '72F' },
                  ],
                },
              ],
            }),
        },
      },
    } as any);

    const runner = client.chat.completions.runTools({
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: 'both please' }],
      tools: [],
    });
    await runner.done();
    await drain();

    const tools = byOp('chat.completions.runTools.tool');
    expect(tools).toHaveLength(2);
    const paired = tools.map((t) => [
      (t.metadata as Record<string, unknown>).tool_name,
      t.prompt,
      t.response,
    ]);
    expect(paired).toEqual([
      ['stocks', '{"sym":"ACME"}', '$41.20'],
      ['weather', '{"city":"NYC"}', '72F'],
    ]);
  });
});

// ---------------------------------------------------------------------------
// Anthropic — beta.messages.toolRunner
// ---------------------------------------------------------------------------

const betaMessage = (content: unknown[]) => ({
  id: 'msg_x',
  model: 'claude-haiku-4-5-20251001',
  content,
  usage: { input_tokens: 9, output_tokens: 4 },
});

/**
 * A stand-in for `BetaToolRunner`: an async iterable with no event emitter, a
 * live `params.messages` conversation it mutates as it goes, and a real `then`
 * that delegates to running itself to completion — all four of which are
 * properties of the real class that the wrapper has to cope with.
 */
function fakeToolRunner() {
  const params = {
    model: 'claude-haiku-4-5',
    messages: [{ role: 'user', content: 'weather?' }] as unknown[],
  };
  const assistant = betaMessage([
    { type: 'tool_use', id: 'tu_1', name: 'get_weather', input: { city: 'NYC' } },
  ]);
  const final = betaMessage([{ type: 'text', text: 'It is 72F.' }]);
  let consumed = false;

  const runner = {
    params,
    async *[Symbol.asyncIterator]() {
      if (consumed) throw new Error('Cannot iterate over a consumed stream');
      consumed = true;
      yield assistant;
      // The real runner pushes the assistant turn and the tool results while
      // producing the NEXT turn, which is what makes them visible then.
      params.messages.push({ role: 'assistant', content: assistant.content });
      params.messages.push({
        role: 'user',
        content: [
          { type: 'tool_result', tool_use_id: 'tu_1', content: [{ type: 'text', text: '72F' }] },
        ],
      });
      yield final;
      params.messages.push({ role: 'assistant', content: final.content });
    },
    async done() {
      return final;
    },
    then(onF?: (v: unknown) => unknown, onR?: (e: unknown) => unknown) {
      return (async () => {
        for await (const _ of runner) void _;
        return final;
      })().then(onF, onR);
    },
  };
  return { runner, final };
}

describe('beta.messages.toolRunner', () => {
  it('is awaitable — the thenable case, which fails silently if unmirrored', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const { final } = fakeToolRunner();
    const client = wrap({
      messages: { create: async () => betaMessage([{ type: 'text', text: 'hi' }]) },
      beta: {
        messages: {
          create: async () => betaMessage([{ type: 'text', text: 'hi' }]),
          toolRunner: () => fakeToolRunner().runner,
        },
      },
    } as any);

    const runner = client.beta.messages.toolRunner({
      model: 'claude-haiku-4-5',
      messages: [{ role: 'user', content: 'weather?' }],
      tools: [],
    });

    // The real runner IS a thenable, so the stand-in must be one too.
    expect(typeof (runner as Record<string, unknown>).then).toBe('function');

    // The assertion that matters: awaiting resolves to the FINAL MESSAGE, not
    // to the stand-in object. A stand-in that refuses `then` would satisfy
    // `await` by handing itself back, and nothing would throw.
    const awaited = (await runner) as typeof final;
    expect(awaited).not.toBe(runner);
    expect(awaited?.content).toEqual([{ type: 'text', text: 'It is 72F.' }]);

    await drain();
    // Chronological, not grouped: the tool ran BETWEEN the two model calls,
    // and the sequence says so. Reading this back tells an auditor what the
    // model saw before it answered, which grouping by kind would destroy.
    expect(ops()).toEqual([
      'beta.messages.toolRunner.start',
      'beta.messages.toolRunner.llm',
      'beta.messages.toolRunner.tool',
      'beta.messages.toolRunner.llm',
      'beta.messages.toolRunner.finish',
    ]);

    const tool = byOp('beta.messages.toolRunner.tool')[0];
    expect((tool.metadata as Record<string, unknown>).tool_name).toBe('get_weather');
    expect(tool.prompt).toBe('{"city":"NYC"}');
    expect(tool.response).toBe('72F');

    const llm = byOp('beta.messages.toolRunner.llm');
    expect(llm[0].provider).toBe('anthropic');
    expect(llm[0].input_tokens).toBe(9);
    expect(llm[0].output_tokens).toBe(4);
  });

  it('drives the run exactly once, however the caller consumes it', async () => {
    // The real runner can be consumed once and throws on a second pass, so a
    // stand-in that iterated on the caller's behalf AND again to complete the
    // run would break every caller who iterates.
    init({ api_key: 'test', sample_rate: 1 });
    const client = wrap({
      messages: { create: async () => betaMessage([{ type: 'text', text: 'hi' }]) },
      beta: {
        messages: {
          create: async () => betaMessage([{ type: 'text', text: 'hi' }]),
          toolRunner: () => fakeToolRunner().runner,
        },
      },
    } as any);

    const runner = client.beta.messages.toolRunner({
      model: 'claude-haiku-4-5',
      messages: [{ role: 'user', content: 'weather?' }],
      tools: [],
    });

    await runner;
    // A second await must resolve from the same completed run rather than
    // starting another one.
    await expect(runner).resolves.toBeDefined();
    await drain();

    expect(byOp('beta.messages.toolRunner.llm')).toHaveLength(2);
    expect(byOp('beta.messages.toolRunner.finish')).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// The invariant the whole mechanism exists for
// ---------------------------------------------------------------------------

describe('a refused tool run', () => {
  it('never reaches the provider, on either surface', async () => {
    init({
      api_key: 'test',
      sample_rate: 1,
      pii_policy: { rules: { ssn: 'block' } },
    });

    let openaiReached = 0;
    let anthropicReached = 0;
    const client = wrap({
      messages: { create: async () => betaMessage([{ type: 'text', text: 'hi' }]) },
      chat: {
        completions: {
          create: async () => completion('x'),
          runTools: () => {
            openaiReached += 1;
            return fakeRunTools({ turns: [] });
          },
        },
      },
      beta: {
        messages: {
          create: async () => betaMessage([{ type: 'text', text: 'hi' }]),
          toolRunner: () => {
            anthropicReached += 1;
            return fakeToolRunner().runner;
          },
        },
      },
    } as any);

    const secret = 'my ssn is 123-45-6789';

    const openaiRunner = client.chat.completions.runTools({
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: secret }],
      tools: [],
    });
    await expect(openaiRunner.done()).rejects.toThrow();

    const anthropicRunner = client.beta.messages.toolRunner({
      model: 'claude-haiku-4-5',
      messages: [{ role: 'user', content: secret }],
      tools: [],
    });
    // The thenable path must REJECT, not resolve with the stand-in.
    await expect(anthropicRunner).rejects.toThrow();

    await drain();

    expect(openaiReached).toBe(0);
    expect(anthropicReached).toBe(0);

    // A refused run is not a run that started: no start/finish pair claims one.
    expect(ops().filter((o) => o.endsWith('.start'))).toEqual([]);
    expect(ops().filter((o) => o.endsWith('.finish'))).toEqual([]);
    // But the refusal itself is recorded.
    expect(sentEvents.some((e) => e.action_taken === 'blocked')).toBe(true);
  });
});
