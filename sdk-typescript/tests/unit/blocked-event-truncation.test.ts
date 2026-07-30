import { init, _reset } from '../../src/proxy/config';
import { wrap } from '../../src/proxy/wrapper';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';

/**
 * A blocked event is truncated like every other event this wrapper builds.
 *
 * `wrapper.ts` builds three AuditEvent literals by hand. The allowed literal and
 * the streaming literal call `truncate(..., max_payload_chars)`; the BLOCKED one
 * had drifted and did not, on two fields:
 *
 *   - `prompt`, full length whenever the block reason is `pii_detected`
 *     (a keyword or canary block stores a short placeholder instead);
 *   - `user_input`, full length for EVERY block reason.
 *
 * Why that matters more than a large field: `MAX_QUEUE_SIZE` bounds the event
 * COUNT and nothing bounds the bytes. An oversized event is refused by ingest
 * with a 4xx, which `fire-and-forget.ts` classifies `permanent` and
 * DEAD-LETTERS rather than retrying — so the enforcement evidence became the
 * event class most likely to be silently discarded.
 *
 * The allowed case is the control. It has always truncated, so if it ever fails
 * here the cap itself is not being applied and the blocked assertions would be
 * passing for the wrong reason.
 */
const CAP = 500;
const HUGE = 'A'.repeat(20_000);

let sentEvents: any[] = [];

beforeEach(() => {
  _reset();
  _resetSender();
  sentEvents = [];
  (global as any).fetch = async (url: any, opts: any) => {
    // Only the ingest POST carries events; a provider call would be a different
    // URL, and these tests never reach one because the calls are blocked.
    try {
      const body = JSON.parse(opts.body);
      Array.isArray(body) ? sentEvents.push(...body) : sentEvents.push(body);
    } catch {
      /* not an ingest body */
    }
    return {
      ok: true,
      status: 200,
      json: async () => ({ choices: [{ message: { content: 'ok' } }] }),
    };
  };
});

afterEach(() => {
  delete (global as any).fetch;
  _reset();
  _resetSender();
});

async function waitForEvents(n = 1): Promise<void> {
  for (let i = 0; i < 400 && sentEvents.length < n; i++) {
    await new Promise((r) => setTimeout(r, 5));
  }
}

/** A minimal client whose method the wrapper will govern. */
function fakeClient() {
  return {
    chat: {
      completions: {
        create: async () => ({ choices: [{ message: { content: 'ok' } }], model: 'm' }),
      },
    },
  };
}

async function callWith(content: string): Promise<void> {
  const client: any = wrap(fakeClient() as never);
  try {
    await client.chat.completions.create({ model: 'm', messages: [{ role: 'user', content }] });
  } catch {
    /* a blocked call throws ObsvrPolicyError; the EVENT is what is asserted */
  }
  await waitForEvents(1);
}

describe('blocked events are truncated to max_payload_chars', () => {
  it('truncates prompt AND user_input on a PII block', async () => {
    init({
      api_key: 'k',
      ingest_url: 'http://127.0.0.1:1',
      max_payload_chars: CAP,
      policy_refresh_interval_ms: 0,
      pii_policy: { default: 'block' },
    } as never);

    await callWith(`my ssn is 123-45-6789 ${HUGE}`);

    const ev = sentEvents.find((e) => e.event_type === 'blocked_call');
    expect(ev).toBeDefined();
    expect(ev.action_reason).toBe('pii_detected');
    // Both fields, because they were two separate untruncated lines.
    expect(String(ev.prompt).length).toBeLessThanOrEqual(CAP + 64);
    expect(String(ev.user_input).length).toBeLessThanOrEqual(CAP + 64);
  });

  it('truncates user_input on a keyword block, whose prompt is a placeholder', async () => {
    init({
      api_key: 'k',
      ingest_url: 'http://127.0.0.1:1',
      max_payload_chars: CAP,
      policy_refresh_interval_ms: 0,
      policy_rules: [
        {
          id: 'kw',
          name: 'kw',
          enabled: true,
          type: 'keyword',
          action: 'block',
          conditions: { keywords: ['SECRETWORD'] },
        },
      ],
    } as never);

    await callWith(`SECRETWORD ${HUGE}`);

    const ev = sentEvents.find((e) => e.event_type === 'blocked_call');
    expect(ev).toBeDefined();
    // The prompt here is a short placeholder by design — this case exists for
    // `user_input`, which carries the caller's text whatever the block reason.
    expect(String(ev.user_input).length).toBeLessThanOrEqual(CAP + 64);
  });

  it('control: the allowed literal truncates too, so the cap is really applied', async () => {
    init({
      api_key: 'k',
      ingest_url: 'http://127.0.0.1:1',
      max_payload_chars: CAP,
      policy_refresh_interval_ms: 0,
    } as never);

    await callWith(`benign ${HUGE}`);

    const ev = sentEvents.find((e) => e.event_type !== 'blocked_call');
    expect(ev).toBeDefined();
    expect(String(ev.prompt).length).toBeLessThanOrEqual(CAP + 64);
  });
});
