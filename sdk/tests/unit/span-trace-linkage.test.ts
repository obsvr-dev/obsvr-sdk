import { init, getConfig, _reset } from '../../src/proxy/config';
import { withSpan, span, currentSpan } from '../../src/proxy/span';
import { _resetSender, flushQueue } from '../../src/proxy/sender/fire-and-forget';
import type { AuditEvent } from '../../src/proxy/types';

/**
 * Span-to-trace linkage (SPAN_TRACE_LINKAGE.md): persists the functional proof
 * as a regression suite. A span scope carries a trace_id with the precedence
 *   explicit opts.trace_id > enclosing scope's trace_id > own span_id (self-root)
 * and emitSpanEvent stamps it into metadata.trace_id so ingest groups the span
 * with its run instead of orphaning it. Twin: sdk-python/tests/test_span_trace.py.
 */

const realFetch = globalThis.fetch;
let sentEvents: AuditEvent[] = [];

beforeEach(() => {
  _reset();
  _resetSender();
  sentEvents = [];
  globalThis.fetch = (async (_url: unknown, opts?: { body?: string }) => {
    // Single-event path POSTs one object; batch path POSTs an array.
    const body = JSON.parse(opts?.body ?? '[]') as AuditEvent | AuditEvent[];
    const batch = Array.isArray(body) ? body : [body];
    sentEvents.push(...batch);
    return {
      status: 200,
      ok: true,
      json: async () => ({ count: batch.length }),
    };
  }) as unknown as typeof fetch;
});

afterEach(() => {
  globalThis.fetch = realFetch;
});

describe('span trace_id precedence (scope)', () => {
  it('explicit trace_id wins and is inherited by nested scopes', () => {
    withSpan('checkout_flow', 'agent', () => {
      expect(currentSpan()!.trace_id).toBe('run-1');
      withSpan('plan_step', 'chain', () => {
        expect(currentSpan()!.trace_id).toBe('run-1'); // inherited
      });
    }, { trace_id: 'run-1' });
  });

  it('a nested explicit trace_id overrides the inherited one', () => {
    withSpan('outer', 'agent', () => {
      withSpan('inner', 'chain', () => {
        expect(currentSpan()!.trace_id).toBe('run-B');
      }, { trace_id: 'run-B' });
    }, { trace_id: 'run-A' });
  });

  it('a root scope with no explicit id self-roots: trace_id === its span_id', () => {
    withSpan('standalone', 'chain', () => {
      const ctx = currentSpan()!;
      expect(ctx.trace_id).toBe(ctx.span_id);
    });
  });
});

describe('span trace_id on the wire (metadata.trace_id)', () => {
  it('spans emitted inside withSpan(trace_id) all carry metadata.trace_id', async () => {
    init({ api_key: 'test', debug: false });
    withSpan('checkout_flow', 'agent', () => {
      span('kb_search', 'retrieval', () => 'docs');
      span('write_note', 'memory', () => undefined);
    }, { trace_id: 'run-verify-1' });
    await flushQueue(getConfig());

    const spans = sentEvents.filter((e) => e.event_class === 'execution_span');
    expect(spans.length).toBe(2);
    for (const s of spans) {
      expect((s.metadata as Record<string, unknown>).trace_id).toBe('run-verify-1');
    }
  });

  it('a standalone span self-roots a distinct trace_id equal to its own span_id', async () => {
    init({ api_key: 'test', debug: false });
    span('orphan_check', 'tool', () => 'ok');
    await flushQueue(getConfig());

    const spans = sentEvents.filter((e) => e.operation === 'orphan_check');
    expect(spans.length).toBe(1);
    const meta = spans[0].metadata as Record<string, unknown>;
    const envelope = meta.obsvr_span as { span_id: string };
    expect(meta.trace_id).toBe(envelope.span_id);
  });

  it('an explicit span trace_id overrides the enclosing scope', async () => {
    init({ api_key: 'test', debug: false });
    withSpan('outer', 'agent', () => {
      span('pinned', 'tool', () => 'ok', { trace_id: 'run-pinned' });
    }, { trace_id: 'run-outer' });
    await flushQueue(getConfig());

    const spans = sentEvents.filter((e) => e.operation === 'pinned');
    expect(spans.length).toBe(1);
    expect((spans[0].metadata as Record<string, unknown>).trace_id).toBe('run-pinned');
  });
});
