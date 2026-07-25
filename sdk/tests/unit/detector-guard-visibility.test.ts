/**
 * A guard nobody can see is only half a guard.
 *
 * ADR-021 gives a resolved detector failure two reporting channels: its own
 * `detector_errors` key on the fleet-poll counter header (deliberately NOT
 * folded into `dropped`, which means delivery loss and would report a lost
 * CONTROL as a lost EVENT), and a per-layer record on the call's own event
 * under reserved telemetry (never a second event, which would break the
 * one-event-per-call correspondence).
 *
 * TypeScript had the guards but neither channel: the counter existed and was
 * read by nothing, and the per-event record was built and then dropped by the
 * event builder. An operator could not tell that a control had stopped
 * running, and Python could. These assert both halves, under the key names
 * the two languages agree on.
 */
import { init, _reset, getConfig, startPolicyPolling, stopPolicyPolling } from '../../src/proxy/config';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { wrap } from '../../src/proxy/wrapper';
import { recordDetectorFailure, _resetDetectorErrors } from '../../src/policy/detector-guard';

const realError = console.error;
let pollHeaders: Array<Record<string, string>> = [];
let sentEvents: any[] = [];

beforeEach(() => {
  _reset();
  _resetSender();
  _resetDetectorErrors();
  pollHeaders = [];
  sentEvents = [];
  console.error = () => {};
  (global as any).fetch = async (url: any, opts: any) => {
    if (String(url).includes('/policies')) {
      pollHeaders.push(opts?.headers ?? {});
      return { ok: true, status: 200, json: async () => ({ rules: [] }) };
    }
    const body = JSON.parse(opts.body);
    Array.isArray(body) ? sentEvents.push(...body) : sentEvents.push(body);
    return { ok: true, status: 200, json: async () => ({ count: 1 }) };
  };
});

afterEach(() => {
  stopPolicyPolling();
  console.error = realError;
  delete (global as any).fetch;
  _reset();
  _resetSender();
});

/** Throws on the FIRST read only, so the vector stays aimed at the detector
 *  read rather than also breaking event serialization downstream. */
function hostileMetadata(): Record<string, unknown> {
  let thrown = false;
  return Object.defineProperty({}, 'user_id', {
    get() {
      if (thrown) return 'u1';
      thrown = true;
      throw new Error('detector bug');
    },
    enumerable: true,
    configurable: true,
  }) as Record<string, unknown>;
}

async function pollOnce() {
  startPolicyPolling(getConfig());
  // The poll fires immediately; give its fetch a turn to run.
  await new Promise((resolve) => setTimeout(resolve, 20));
}

describe('the fleet-poll counter', () => {
  it('publishes detector_errors under its own key', async () => {
    init({ api_key: 'test', ingest_url: 'https://x.test' });
    recordDetectorFailure('policy_rules', new Error('x'), { failMode: 'open' } as never);
    recordDetectorFailure('canary', new Error('x'), { failMode: 'open' } as never);

    await pollOnce();

    expect(pollHeaders.length).toBeGreaterThan(0);
    expect(pollHeaders[0]['X-Obsvr-Counters']).toContain('detector_errors=2');
  });

  it('is not folded into dropped - enforcement loss is not delivery loss', async () => {
    init({ api_key: 'test', ingest_url: 'https://x.test' });
    recordDetectorFailure('policy_rules', new Error('x'), { failMode: 'open' } as never);

    await pollOnce();

    const counters = pollHeaders[0]?.['X-Obsvr-Counters'] ?? '';
    expect(counters).toContain('dropped=0');
    expect(counters).toContain('detector_errors=1');
  });

  it('reads zero on a healthy process', async () => {
    init({ api_key: 'test', ingest_url: 'https://x.test' });
    await pollOnce();
    expect(pollHeaders[0]?.['X-Obsvr-Counters'] ?? '').toContain('detector_errors=0');
  });
});

describe("the per-event record, on the proxy wrapper's own path", () => {
  function client() {
    return wrap({
      chat: {
        completions: {
          create: async (_args: unknown) => ({ choices: [{ message: { content: 'ok' } }] }),
        },
      },
    });
  }

  it('names the lost layer on the call it was lost for', async () => {
    init({ api_key: 'test', ingest_url: 'https://x.test', fail_mode: 'open' });

    await client().chat.completions.create({
      model: 'gpt-4o',
      messages: [{ role: 'user', content: 'hello' }],
      metadata: hostileMetadata(),
    } as never);
    await new Promise((resolve) => setTimeout(resolve, 20));

    const event = sentEvents.find(
      (e) => (e.metadata as Record<string, unknown> | undefined)?.obsvr_telemetry,
    );
    expect(event).toBeDefined();
    const failure = (event.metadata.obsvr_telemetry as Record<string, unknown>)
      .detector_failure as Record<string, unknown>;
    expect(failure).toBeDefined();
    expect(failure.layer).toBe('session_taint');
    expect(failure.resolution).toBe('open');
    expect(failure.phase).toBe('pre_call');
    expect(failure.floor_class).toBe(false);
    expect(String(failure.error)).toContain('detector bug');
  });

  it('leaves a healthy call with no detector_failure record', async () => {
    init({ api_key: 'test', ingest_url: 'https://x.test', fail_mode: 'open' });

    await client().chat.completions.create({
      model: 'gpt-4o',
      messages: [{ role: 'user', content: 'hello' }],
      metadata: { user_id: 'u1' },
    } as never);
    await new Promise((resolve) => setTimeout(resolve, 20));

    for (const e of sentEvents) {
      const telemetry = (e.metadata as Record<string, unknown> | undefined)?.obsvr_telemetry as
        | Record<string, unknown>
        | undefined;
      expect(telemetry?.detector_failure).toBeUndefined();
    }
  });
});
