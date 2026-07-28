/**
 * What the Agents SDK tracing processor can and cannot know about the model.
 *
 * Two different situations that both used to look identical in the evidence:
 *
 *  - RESPONSE spans (the DEFAULT path): the configured alias is genuinely not
 *    observable. ResponseSpanData carries only response_id/_input/_response, the
 *    agent span carries no model, and trace metadata is caller-supplied. So
 *    `model` necessarily holds the served snapshot, and `model === model_resolved`
 *    means "the alias was never visible" rather than "the caller pinned a
 *    snapshot". Left unstated, a temporal-provenance check over this source
 *    always passes and reads as evidence of no drift.
 *
 *  - GENERATION spans (Chat Completions): the alias IS on the span, and the
 *    served snapshot is recoverable too — the raw provider completion sits in
 *    spanData.output[0]. Except on the streamed path, where the SDK synthesises
 *    a stand-in completion whose model is a copy of the configured alias.
 *    Reading that blindly would mint a provider-verified snapshot out of the
 *    request, which is a worse record than no snapshot at all.
 */
import { init, getConfig, _reset } from '../../src/proxy/config';
import { ObsvrTraceProcessor } from '../../src/integrations/openai-agents';
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

/** A completed span in the shape processSpan parses. */
function span(spanData: Record<string, unknown>) {
  return {
    trace_id: 'trace_1',
    span_data: { ...spanData, ended_at: '2026-07-29T00:00:00Z' },
  };
}

const llm = () => sentEvents.find((e) => e.operation === 'llm');

describe('response spans: the alias is not observable, and the record says so', () => {
  it('records the served snapshot and marks the alias unavailable', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    new ObsvrTraceProcessor().processSpan(
      span({
        type: 'response',
        response_id: 'resp_1',
        _input: [{ role: 'user', content: 'what is 2+2' }],
        _response: {
          model: 'gpt-4o-mini-2024-07-18',
          output: [{ content: [{ type: 'output_text', text: 'four' }] }],
          usage: { input_tokens: 21, output_tokens: 2, total_tokens: 23 },
        },
      }),
    );

    await flushQueue(getConfig());
    const e = llm()!;
    expect(e).toBeDefined();
    expect(e.model).toBe('gpt-4o-mini-2024-07-18');
    expect(e.model_resolved).toBe('gpt-4o-mini-2024-07-18');
    expect(e.prompt).toBe('user: what is 2+2');
    expect(e.response).toBe('four');
    expect(e.input_tokens).toBe(21);
    expect(e.total_tokens).toBe(23);
    // The part that keeps `model === model_resolved` from reading as a
    // successful drift check.
    expect((e.metadata as any).model_alias_unavailable).toBe(true);
  });

  it('derives a total the payload did not state, rather than dropping it', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    new ObsvrTraceProcessor().processSpan(
      span({
        type: 'response',
        _input: [{ role: 'user', content: 'hi' }],
        _response: {
          model: 'gpt-4o-mini',
          output: [{ content: [{ type: 'output_text', text: 'ok' }] }],
          usage: { input_tokens: 5, output_tokens: 1 },
        },
      }),
    );
    await flushQueue(getConfig());
    expect(llm()!.total_tokens).toBe(6);
  });

  it('leaves counts absent when the payload has no usage', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    new ObsvrTraceProcessor().processSpan(
      span({
        type: 'response',
        _input: [{ role: 'user', content: 'hi' }],
        _response: { model: 'gpt-4o-mini', output: [] },
      }),
    );
    await flushQueue(getConfig());
    const e = llm()!;
    expect(e.input_tokens).toBeUndefined();
    expect(e.total_tokens).toBeUndefined();
  });
});

describe('generation spans: the alias is on the span, the snapshot is recoverable', () => {
  it('keeps the configured alias in model and lifts the snapshot from the provider body', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    new ObsvrTraceProcessor().processSpan(
      span({
        type: 'generation',
        model: 'gpt-4o-mini',
        input: [{ role: 'user', content: '2+2' }],
        output: [
          {
            id: 'chatcmpl_real',
            model: 'gpt-4o-mini-2024-07-18',
            choices: [{ message: { role: 'assistant', content: 'four' } }],
          },
        ],
      }),
    );

    await flushQueue(getConfig());
    const e = llm()!;
    expect(e.model).toBe('gpt-4o-mini');
    expect(e.model_resolved).toBe('gpt-4o-mini-2024-07-18');
    expect(e.provenance_source).toBe('provider_response');
    // The alias IS observable here, so no substitution marker belongs on it.
    expect((e.metadata as any).model_alias_unavailable).toBeUndefined();
  });

  it('refuses the synthesized stand-in on the streamed path', async () => {
    // The SDK builds this object locally when streaming and copies the
    // CONFIGURED alias into its model field. Treating it as a provider-verified
    // snapshot would fabricate provenance out of the request itself.
    init({ api_key: 'test', sample_rate: 1 });
    new ObsvrTraceProcessor().processSpan(
      span({
        type: 'generation',
        model: 'gpt-4o-mini',
        input: [{ role: 'user', content: '2+2' }],
        output: [{ id: 'FAKE_ID', model: 'gpt-4o-mini', choices: [] }],
      }),
    );

    await flushQueue(getConfig());
    const e = llm()!;
    expect(e.model).toBe('gpt-4o-mini');
    expect(e.model_resolved).toBeUndefined();
    expect(e.provenance_source).toBeUndefined();
  });

  it('stays quiet when the span carries no provider body at all', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    new ObsvrTraceProcessor().processSpan(
      span({
        type: 'generation',
        model: 'gpt-4o-mini',
        input: 'hello',
        output: 'world',
      }),
    );
    await flushQueue(getConfig());
    const e = llm()!;
    expect(e.model).toBe('gpt-4o-mini');
    expect(e.model_resolved).toBeUndefined();
  });
});
