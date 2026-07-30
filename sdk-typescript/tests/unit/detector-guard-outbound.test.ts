/**
 * Enforcement APPLICATION: a redaction that could not be carried out.
 *
 * A third phase, and deliberately not the pre-call rule. Pre-call resolves by
 * failMode because a DETECTION failure means the SDK does not know whether
 * sensitive content is present. Here the scan already ran, already found
 * something, and policy already said remove it - so failing open would
 * transmit to a third-party provider exactly the content the SDK was told to
 * strip. It fails CLOSED regardless of failMode, on the same reasoning the
 * policy floor already uses: never forward content that cannot be guaranteed
 * redacted.
 *
 * The other half is the audit record. An event claiming a redaction that did
 * not happen is worse than no event, because it tells an auditor the content
 * was cleaned.
 */
import { init, _reset, getConfig } from '../../src/proxy/config';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { wrap } from '../../src/proxy/wrapper';
import {
  applyOutboundRedaction,
  applyOutboundRedactionAsync,
  getDetectorErrorCount,
  _resetDetectorErrors,
} from '../../src/policy/detector-guard';
import { outboundRedactionBlockedCompliance, type ComplianceInfo } from '../../src/integrations/core';

const realError = console.error;
let sentEvents: any[] = [];

beforeEach(() => {
  _reset();
  _resetSender();
  _resetDetectorErrors();
  sentEvents = [];
  console.error = () => {};
  (global as any).fetch = async (_url: any, opts: any) => {
    const body = JSON.parse(opts.body);
    Array.isArray(body) ? sentEvents.push(...body) : sentEvents.push(body);
    return { ok: true, status: 200, json: async () => ({ count: 1 }) };
  };
});

afterEach(() => {
  console.error = realError;
  delete (global as any).fetch;
  _reset();
  _resetSender();
});

describe('the application rule itself', () => {
  it('fails closed on both failMode settings - failMode does not reach it', () => {
    for (const failMode of ['open', 'closed'] as const) {
      _resetDetectorErrors();
      init({ api_key: 'test', ingest_url: 'https://x.test', fail_mode: failMode });
      const failed = applyOutboundRedaction(() => {
        throw new Error('redactor bug');
      });
      expect(failed).toBeDefined();
      expect(failed!.failure.resolution).toBe('closed');
      expect(failed!.failure.phase).toBe('enforcement_application');
      expect(failed!.ruleId).toBe('sdk:detector_error');
      expect(getDetectorErrorCount()).toBe(1);
      _reset();
    }
  });

  it('reports nothing when the redaction succeeds', () => {
    init({ api_key: 'test', ingest_url: 'https://x.test' });
    let ran = false;
    expect(applyOutboundRedaction(() => { ran = true; })).toBeUndefined();
    expect(ran).toBe(true);
    expect(getDetectorErrorCount()).toBe(0);
  });

  it('the async twin behaves identically for awaited redactors', async () => {
    init({ api_key: 'test', ingest_url: 'https://x.test' });
    const failed = await applyOutboundRedactionAsync(async () => {
      throw new Error('anonymizer bug');
    });
    expect(failed!.failure.resolution).toBe('closed');
    expect(await applyOutboundRedactionAsync(async () => {})).toBeUndefined();
  });
});

describe('the event must never claim a redaction that did not happen', () => {
  const base: ComplianceInfo = {
    event_type: 'llm_call',
    policy_version: 'v1',
    action_taken: 'redacted',
    action_reason: 'pii_detected',
    action_source: 'builtin',
    redacted_types: ['email', 'ssn'],
    blocked_types: [],
  };

  it('strips the redaction claim and re-files the types as blocked', () => {
    const failed = applyOutboundRedaction(() => { throw new Error('redactor bug'); })!;
    const corrected = outboundRedactionBlockedCompliance(base, failed);

    expect(corrected.action_taken).toBe('blocked');
    expect(corrected.event_type).toBe('blocked_call');
    expect(corrected.redacted_types).toEqual([]);
    // What the scan found is now the reason for the refusal, not a list of
    // things removed - nothing was removed.
    expect(corrected.blocked_types).toEqual(['email', 'ssn']);
    expect(corrected.rule_id).toBe('sdk:detector_error');
    expect(corrected.detector_failure?.phase).toBe('enforcement_application');
  });

  it('keeps the provenance fields the policy already established', () => {
    const failed = applyOutboundRedaction(() => { throw new Error('x'); })!;
    const corrected = outboundRedactionBlockedCompliance(base, failed);
    expect(corrected.policy_version).toBe('v1');
    expect(corrected.action_source).toBe('builtin');
  });
});

describe('the proxy wrapper, end to end', () => {
  /**
   * A request the redactor can read but cannot COPY. The scan sees the SSN and
   * resolves to "redact"; the redaction walk then throws while rebuilding the
   * message, inside the guarded span rather than ahead of it.
   *
   * This used to be `Object.freeze`, because the walk wrote to the caller's
   * message and a frozen one made the assignment throw. It no longer writes —
   * it copies — so a frozen message is now redacted successfully, which is what
   * `a frozen caller message is redacted, not refused` below pins. Refusing a
   * call because the caller's object was immutable meant blocking them for
   * protecting the very object obsvr was about to corrupt.
   *
   * The application rule itself is unchanged and still fails CLOSED, so it
   * still needs an end-to-end trigger: a message that cannot be copied at all.
   * That is a genuine "the removal could not be carried out", which is what
   * this phase means, and `fail_mode.json`'s `redaction_application_closed`
   * qualifier continues to describe observed behaviour.
   */
  function uncopyableMessages() {
    return [
      new Proxy(
        { role: 'user', content: 'my ssn is 123-45-6789' },
        {
          ownKeys() {
            throw new Error('message cannot be copied');
          },
        },
      ),
    ];
  }

  function frozenMessages() {
    return [Object.freeze({ role: 'user', content: 'my ssn is 123-45-6789' })];
  }

  function client() {
    return wrap({
      chat: {
        completions: {
          create: async (_args: unknown) => ({ choices: [{ message: { content: 'ok' } }] }),
        },
      },
    });
  }

  it('blocks under failMode open rather than forwarding a partial redaction', async () => {
    init({
      api_key: 'test',
      ingest_url: 'https://x.test',
      fail_mode: 'open',
      pii_policy: { default: 'redact' },
    });

    await expect(
      client().chat.completions.create({ model: 'gpt-4o', messages: uncopyableMessages() } as never),
    ).rejects.toThrow(/blocked by policy/i);
    expect(getDetectorErrorCount()).toBe(1);
  });

  it("the event says blocked, not redacted, and names the phase", async () => {
    init({
      api_key: 'test',
      ingest_url: 'https://x.test',
      fail_mode: 'open',
      pii_policy: { default: 'redact' },
    });

    await expect(
      client().chat.completions.create({ model: 'gpt-4o', messages: uncopyableMessages() } as never),
    ).rejects.toThrow();
    await new Promise((resolve) => setTimeout(resolve, 20));

    const event = sentEvents.find((e) => e.rule_id === 'sdk:detector_error');
    expect(event).toBeDefined();
    expect(event.action_taken).toBe('blocked');
    expect(event.redacted_types).toEqual([]);
    const failure = (event.metadata.obsvr_telemetry as Record<string, unknown>)
      .detector_failure as Record<string, unknown>;
    expect(failure.phase).toBe('enforcement_application');
    expect(failure.resolution).toBe('closed');
  });

  it('a frozen caller message is redacted, not refused, and is left unchanged', async () => {
    // The behaviour this replaces: a frozen message used to make the redaction
    // walk throw, which resolved closed and refused the call. That refusal
    // punished a caller for handing over an object obsvr was about to rewrite.
    init({
      api_key: 'test',
      ingest_url: 'https://x.test',
      fail_mode: 'open',
      pii_policy: { default: 'redact' },
    });

    let sentToProvider = '';
    const wrapped = wrap({
      chat: {
        completions: {
          create: async (args: unknown) => {
            sentToProvider = JSON.stringify(args);
            return { choices: [{ message: { content: 'ok' } }] };
          },
        },
      },
    }) as { chat: { completions: { create: (a: unknown) => Promise<unknown> } } };

    const messages = frozenMessages();
    const res = await wrapped.chat.completions.create({ model: 'gpt-4o', messages });

    // The call SUCCEEDS...
    expect(res).toEqual({ choices: [{ message: { content: 'ok' } }] });
    expect(getDetectorErrorCount()).toBe(0);
    // ...the provider got the redacted text, so this is not "redaction was
    // skipped to make the call work"...
    expect(sentToProvider).not.toContain('123-45-6789');
    expect(sentToProvider).toContain('[REDACTED_SSN]');
    // ...and the caller's frozen object is untouched, which is the whole point.
    expect(messages[0].content).toBe('my ssn is 123-45-6789');

    // The stored copy is redacted too — the record must not carry what the
    // provider was not allowed to see.
    await new Promise((resolve) => setTimeout(resolve, 20));
    const event = sentEvents.find((e) => e.action_taken === 'redacted');
    expect(event).toBeDefined();
    expect(event.prompt).not.toContain('123-45-6789');
  });

  it('a healthy redaction still redacts and still sends', async () => {
    init({
      api_key: 'test',
      ingest_url: 'https://x.test',
      fail_mode: 'open',
      pii_policy: { default: 'redact' },
    });

    const res = await client().chat.completions.create({
      model: 'gpt-4o',
      messages: [{ role: 'user', content: 'my ssn is 123-45-6789' }],
    } as never);
    expect(res).toEqual({ choices: [{ message: { content: 'ok' } }] });
    expect(getDetectorErrorCount()).toBe(0);
  });
});
