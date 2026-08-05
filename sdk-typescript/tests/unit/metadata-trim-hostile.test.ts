/**
 * Host metadata cannot break the caller's call.
 *
 * `trimMetadataToBudget` measures the metadata bag with `JSON.stringify` before
 * deciding whether to shrink it, and that bag is CALLER-SUPPLIED. Four ordinary
 * shapes make `JSON.stringify` throw — a getter that raises, a `BigInt`, a
 * circular reference, a hostile `toJSON` — and the trim runs on the SYNCHRONOUS
 * enqueue path, so the throw came back out of the sender into the application's
 * own call. It was the single named exception to "an exception inside any
 * detector layer never reaches your application".
 *
 * A bag that cannot be measured is treated as over budget and takes the trimming
 * branch that already exists for an oversized one — the posture ingest already
 * expects, rather than a new one. The Python twin is in
 * sdk-python/tests/test_metadata_trim_hostile.py.
 */
import { init, _reset } from '../../src/proxy/config';
import {
  sendAuditAsync,
  _resetSender,
  getSenderStats,
} from '../../src/proxy/sender/fire-and-forget';
import { getConfig } from '../../src/proxy/config';
import type { AuditEvent } from '../../src/proxy/types';

let sent: any[] = [];

beforeEach(() => {
  _reset();
  _resetSender();
  sent = [];
  (global as any).fetch = async (_url: any, opts: any) => {
    sent.push(JSON.parse(opts.body));
    return { ok: true, status: 200 };
  };
  init({ api_key: 'k', ingest_url: 'https://example.test', sample_rate: 1 } as never);
});

afterEach(() => {
  _reset();
  _resetSender();
});

/** The public enqueue path: the caller's own synchronous call. */
function send(event: AuditEvent): void {
  sendAuditAsync(getConfig(), event);
}

function eventWith(metadata: Record<string, unknown>): AuditEvent {
  return {
    request_id: 'req-1',
    environment: 'test',
    region: 'us',
    provider: 'openai',
    model: 'gpt-4o',
    operation: 'chat.completions.create',
    source: 'test',
    prompt: 'hello',
    response: 'hi',
    success: true,
    trace_id: 'trace-keep-me',
    metadata,
  } as unknown as AuditEvent;
}

/** The four ordinary shapes a host can attach that JSON.stringify refuses. */
const HOSTILE: Array<[string, () => Record<string, unknown>]> = [
  [
    'a getter that throws',
    () => ({
      trace_id: 'trace-keep-me',
      get tenant(): string {
        throw new Error('this property is not readable');
      },
    }),
  ],
  ['a BigInt', () => ({ trace_id: 'trace-keep-me', rows: BigInt(9007199254740993n) })],
  [
    'a circular reference',
    () => {
      const md: Record<string, unknown> = { trace_id: 'trace-keep-me' };
      md.self = md;
      return md;
    },
  ],
  [
    'a toJSON that throws',
    () => ({
      trace_id: 'trace-keep-me',
      ctx: {
        toJSON() {
          throw new Error('nope');
        },
      },
    }),
  ],
];

describe('unserializable host metadata does not reach the caller', () => {
  it.each(HOSTILE)('%s', (_name, build) => {
    expect(() => send(eventWith(build()))).not.toThrow();
  });

  it.each(HOSTILE)('%s — the event is still delivered', async (_name, build) => {
    send(eventWith(build()));
    await new Promise((r) => setTimeout(r, 60));

    expect(sent.length).toBeGreaterThan(0);
  });

  it.each(HOSTILE)('%s — the trim keeps the grouping key', async (_name, build) => {
    // The whole point of the existing over-budget branch: `trace_id` survives,
    // so the event is still joined to its trace rather than orphaned.
    send(eventWith(build()));
    await new Promise((r) => setTimeout(r, 60));

    const md = sent.flatMap((b) => b.events ?? [b])[0].metadata;
    expect(md._obsvr_metadata_trimmed).toBe(true);
    expect(md.trace_id).toBe('trace-keep-me');
  });

  it('a reserved key that is ITSELF unreadable is dropped rather than thrown', async () => {
    // The trim copies the reserved keys by name, so a hostile getter ON one of
    // them is the one read the guard above does not cover.
    const md: Record<string, unknown> = {
      agent_run_id: 'run-1',
      get trace_id(): string {
        throw new Error('not readable either');
      },
    };
    md.self = md; // force the unmeasurable path

    expect(() => send(eventWith(md))).not.toThrow();
    await new Promise((r) => setTimeout(r, 60));

    const out = sent.flatMap((b) => b.events ?? [b])[0].metadata;
    expect(out._obsvr_metadata_trimmed).toBe(true);
    expect(out.agent_run_id).toBe('run-1');
    expect(out.trace_id).toBeUndefined();
  });
});

describe('the ordinary paths are unchanged', () => {
  it('metadata under budget rides through untouched', async () => {
    send(eventWith({ trace_id: 'trace-keep-me', tenant: 'acme' }));
    await new Promise((r) => setTimeout(r, 60));

    const md = sent.flatMap((b) => b.events ?? [b])[0].metadata;
    expect(md.tenant).toBe('acme');
    expect(md._obsvr_metadata_trimmed).toBeUndefined();
  });

  it('metadata over budget still trims to the reserved keys', async () => {
    send(
      eventWith({ trace_id: 'trace-keep-me', blob: 'x'.repeat(20_000), tenant: 'acme' }),
    );
    await new Promise((r) => setTimeout(r, 60));

    const md = sent.flatMap((b) => b.events ?? [b])[0].metadata;
    expect(md._obsvr_metadata_trimmed).toBe(true);
    expect(md.trace_id).toBe('trace-keep-me');
    expect(md.tenant).toBeUndefined();
  });

  it('the span attribute bag is still collapsed first', async () => {
    send(
      eventWith({
        trace_id: 'trace-keep-me',
        tenant: 'acme',
        obsvr_span: { name: 's', attributes: { big: 'y'.repeat(20_000) } },
      }),
    );
    await new Promise((r) => setTimeout(r, 60));

    const md = sent.flatMap((b) => b.events ?? [b])[0].metadata;
    // Shrinking the span alone got it under budget, so `tenant` survived.
    expect(md._obsvr_metadata_trimmed).toBe(true);
    expect(md.tenant).toBe('acme');
    expect(md.obsvr_span.attributes).toEqual({ _trimmed: true });
  });

  it('nothing was counted as dropped', () => {
    send(eventWith({ trace_id: 't' }));

    expect(getSenderStats().dropped_permanent).toBe(0);
  });
});
