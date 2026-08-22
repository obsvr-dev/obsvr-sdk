/**
 * Delivery-counter accounting for the fire-and-forget sender.
 *
 * The public promise is that every drop is visible in the per-client delivery
 * counters reported on the /policies poll. The case this file pins is the one
 * that used to be invisible: a batch POST the server answers 2xx while
 * refusing individual events inside the body. Those events were delivered and
 * refused - a different audit story from "never delivered" - so they land in
 * their own `dropped_rejected` bucket and are never counted as sent.
 */
import { enqueueAuditEvent, flushQueue, getSenderStats, _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { init, getConfig, _reset, startPolicyPolling, stopPolicyPolling } from '../../src/proxy/config';
import type { AuditEvent, ResolvedConfig } from '../../src/proxy/types';
import { jest } from '@jest/globals';

const realFetch = globalThis.fetch;

function auditEvent(id: string): AuditEvent {
  return {
    request_id: id,
    region: 'us-east-1',
    provider: 'openai',
    model: 'gpt-4o',
    operation: 'chat.completion',
    source: 'test',
    prompt: 'hello',
    response: 'hi',
    success: true,
    event_type: 'llm_call',
    policy_version: 'v1',
    action_taken: 'allowed',
    action_reason: 'none',
    action_source: 'builtin',
    redacted_types: [],
  } as AuditEvent;
}

/**
 * The sender takes the single-event path when exactly one event is queued and
 * the batch path when more than one is. Enqueuing synchronously in a row gives
 * a deterministic split: the first event is already in flight (awaiting fetch)
 * when the rest are queued, so they drain together as one batch.
 */
async function sendOneThenBatchOf(n: number, config: ResolvedConfig): Promise<void> {
  enqueueAuditEvent(config, auditEvent('single'));
  for (let i = 0; i < n; i++) enqueueAuditEvent(config, auditEvent(`batched-${i}`));
  await flushQueue(config, 2000);
}

describe('delivery counters: per-event rejects inside an accepted batch', () => {
  beforeEach(() => {
    _reset();
    _resetSender();
  });

  afterEach(() => {
    globalThis.fetch = realFetch;
    stopPolicyPolling();
  });

  it('increments dropped_rejected once per rejected event and excludes them from sent', async () => {
    // 2xx for both paths; the batch response refuses two of its three events.
    globalThis.fetch = (async (url: string) => ({
      status: 200,
      ok: true,
      json: async () =>
        String(url).includes('/batch')
          ? {
              count: 1,
              rejected: [
                { index: 0, error: 'policy_blocked' },
                { index: 2, error: 'schema_invalid' },
              ],
            }
          : { count: 1 },
    })) as unknown as typeof fetch;

    init({ api_key: 'test-key', ingest_url: 'https://ingest.example.com' });
    await sendOneThenBatchOf(3, getConfig());

    const stats = getSenderStats();
    expect(stats.enqueued).toBe(5); // four calls plus the accepted gap marker
    expect(stats.dropped_rejected).toBe(2);
    // 1 single-event send + 1 accepted event out of the batch of 3.
    expect(stats.sent).toBe(3); // two calls plus the marker
    // Rejects are not a transport failure: nothing retried, permanently
    // discarded, or overflowed.
    expect(stats.retries).toBe(0);
    expect(stats.dropped_permanent).toBe(0);
    expect(stats.dropped_overflow).toBe(0);
    expect(stats.dropped_retry_exhausted).toBe(0);
    // Every enqueued event is accounted for exactly once.
    expect(stats.sent + stats.dropped_rejected).toBe(stats.enqueued);
  });

  it('leaves dropped_permanent semantics unchanged on a whole-request 4xx', async () => {
    globalThis.fetch = (async () => ({
      status: 400,
      ok: false,
      json: async () => ({ error: 'bad_request' }),
    })) as unknown as typeof fetch;

    init({ api_key: 'test-key', ingest_url: 'https://ingest.example.com' });
    await sendOneThenBatchOf(2, getConfig());

    const stats = getSenderStats();
    expect(stats.enqueued).toBe(5); // two failed requests each arm a marker
    expect(stats.dropped_permanent).toBe(5); // the always-400 sink also drops both markers
    expect(stats.dropped_rejected).toBe(0);
    expect(stats.sent).toBe(0);
  });

  it('counts a per-event duplicate_event reject as sent, never as a drop', async () => {
    globalThis.fetch = (async (url: string) => ({
      status: 200,
      ok: true,
      json: async () =>
        String(url).includes('/batch')
          ? {
              count: 1,
              rejected: [
                { index: 0, error: 'duplicate_event' },
                { index: 1, error: 'policy_blocked' },
              ],
            }
          : { count: 1 },
    })) as unknown as typeof fetch;

    init({ api_key: 'test-key', ingest_url: 'https://ingest.example.com' });
    await sendOneThenBatchOf(3, getConfig());

    const stats = getSenderStats();
    // The duplicate is already recorded, so it is a delivery: 1 single + the
    // duplicate + the one clean event = 3 sent, 1 refused.
    expect(stats.sent).toBe(4); // includes the accepted gap marker
    expect(stats.dropped_rejected).toBe(1);
    expect(stats.sent + stats.dropped_rejected).toBe(stats.enqueued);
  });

  it('reports dropped_rejected as its own bucket in the X-Obsvr-Counters poll header', async () => {
    const headers: Array<Record<string, string>> = [];
    globalThis.fetch = (async (url: string, opts?: { headers?: Record<string, string> }) => {
      if (String(url).includes('/policies')) {
        headers.push(opts?.headers ?? {});
        return { status: 200, ok: true, json: async () => ({ rules: [] }) };
      }
      return {
        status: 200,
        ok: true,
        json: async () =>
          String(url).includes('/batch')
            ? { count: 1, rejected: [{ index: 0, error: 'policy_blocked' }] }
            : { count: 1 },
      };
    }) as unknown as typeof fetch;

    init({ api_key: 'test-key', ingest_url: 'https://ingest.example.com' });
    await sendOneThenBatchOf(2, getConfig());

    startPolicyPolling(getConfig());
    // The poll fires immediately; give its fetch a turn to run.
    await new Promise((resolve) => setTimeout(resolve, 20));

    expect(headers.length).toBeGreaterThan(0);
    const counters = headers[0]['X-Obsvr-Counters'];
    expect(counters).toContain('dropped_rejected=1');
    // The never-delivered aggregate stays separate from the refused bucket.
    expect(counters).toContain('dropped=0');
  });
});

/**
 * HTTP 409 duplicate_event.
 *
 * A duplicate means a retry raced a lost 2xx: the event is already durably
 * recorded. Classifying it as a permanent drop - which every other 4xx is -
 * would fabricate a coverage gap for evidence that exists, so it counts as
 * idempotent success. Only that exact code: a 409 sequence_fork means the
 * chain position belongs to a different signature and must stay a failure.
 * The platform's own reference emitter absorbs 409 the same way.
 */
describe('delivery counters: 409 duplicate_event is idempotent success', () => {
  beforeEach(() => {
    _reset();
    _resetSender();
  });

  afterEach(() => {
    globalThis.fetch = realFetch;
    stopPolicyPolling();
  });

  const conflict = (body: unknown) =>
    (async () => ({ status: 409, ok: false, json: async () => body })) as unknown as typeof fetch;

  it('counts a single-event 409 duplicate as sent, with no drop counted', async () => {
    globalThis.fetch = conflict({ ok: false, error: 'duplicate_event', reason: 'replay' });
    init({ api_key: 'test-key', ingest_url: 'https://ingest.example.com' });
    enqueueAuditEvent(getConfig(), auditEvent('dup'));
    await flushQueue(getConfig(), 2000);

    const stats = getSenderStats();
    expect(stats.sent).toBe(1);
    expect(stats.dropped_permanent).toBe(0);
    expect(stats.dropped_rejected).toBe(0);
    expect(stats.retries).toBe(0);
  });

  it('counts a whole-batch 409 duplicate as sent for every event in it', async () => {
    globalThis.fetch = conflict({ ok: false, error: 'duplicate_event' });
    init({ api_key: 'test-key', ingest_url: 'https://ingest.example.com' });
    await sendOneThenBatchOf(3, getConfig());

    const stats = getSenderStats();
    expect(stats.sent).toBe(4);
    expect(stats.dropped_permanent).toBe(0);
    expect(stats.dropped_rejected).toBe(0);
  });

  it('keeps a non-duplicate 409 permanent (sequence_fork must surface)', async () => {
    globalThis.fetch = conflict({ ok: false, error: 'sequence_fork' });
    init({ api_key: 'test-key', ingest_url: 'https://ingest.example.com' });
    enqueueAuditEvent(getConfig(), auditEvent('fork'));
    await flushQueue(getConfig(), 2000);

    const stats = getSenderStats();
    expect(stats.sent).toBe(0);
    expect(stats.dropped_permanent).toBe(2); // original plus the non-recursively-failed marker
  });

  it('does not absorb a 409 whose body cannot be read', async () => {
    globalThis.fetch = (async () => ({
      status: 409,
      ok: false,
      json: async () => {
        throw new Error('not json');
      },
    })) as unknown as typeof fetch;
    init({ api_key: 'test-key', ingest_url: 'https://ingest.example.com' });
    enqueueAuditEvent(getConfig(), auditEvent('opaque'));
    await flushQueue(getConfig(), 2000);

    const stats = getSenderStats();
    expect(stats.sent).toBe(0);
    expect(stats.dropped_permanent).toBe(2); // original plus the non-recursively-failed marker
  });
});

describe('sender lifecycle reset', () => {
  beforeEach(() => {
    _reset();
    _resetSender();
  });

  afterEach(() => {
    globalThis.fetch = realFetch;
    _resetSender();
    _reset();
  });

  it('does not let an in-flight prior lifecycle retry or warn after reset', async () => {
    let release!: () => void;
    const firstResponse = new Promise<void>((resolve) => {
      release = resolve;
    });
    let attempts = 0;
    globalThis.fetch = (async () => {
      attempts++;
      if (attempts === 1) await firstResponse;
      return { status: 500, ok: false, json: async () => ({ error: 'unavailable' }) };
    }) as unknown as typeof fetch;
    const random = jest.spyOn(Math, 'random').mockReturnValue(-1);
    const warning = jest.spyOn(console, 'warn').mockImplementation(() => undefined);

    init({ api_key: 'test-key', ingest_url: 'https://ingest.example.com' });
    enqueueAuditEvent(getConfig(), auditEvent('old-lifecycle'));
    expect(attempts).toBe(1);

    _resetSender();
    release();
    await new Promise((resolve) => setTimeout(resolve, 25));

    expect(attempts).toBe(1);
    expect(getSenderStats()).toMatchObject({
      enqueued: 0,
      sent: 0,
      retries: 0,
      dropped_retry_exhausted: 0,
    });
    expect(warning).not.toHaveBeenCalled();
    warning.mockRestore();
    random.mockRestore();
  });
});
