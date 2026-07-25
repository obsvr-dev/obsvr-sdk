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
    expect(stats.enqueued).toBe(4);
    expect(stats.dropped_rejected).toBe(2);
    // 1 single-event send + 1 accepted event out of the batch of 3.
    expect(stats.sent).toBe(2);
    // Rejects are not a transport failure: nothing retried, nothing
    // dead-lettered, nothing overflowed.
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
    expect(stats.enqueued).toBe(3);
    expect(stats.dropped_permanent).toBe(3);
    expect(stats.dropped_rejected).toBe(0);
    expect(stats.sent).toBe(0);
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
