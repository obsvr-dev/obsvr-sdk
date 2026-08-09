import { jest } from '@jest/globals';
import { init, _reset } from '../../src/proxy/config';
import { wrap } from '../../src/proxy/wrapper';
import { wrapTogether } from '../../src/integrations/together';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { getConfig } from '../../src/proxy/config';
import { buildIntegrationEvent } from '../../src/integrations/core';

/**
 * The README promise this pins, in its own words:
 *
 *   "Policy decisions scan the last user message; earlier turns and system
 *    prompts are still stored (and redacted if configured)..."
 *
 * The first clause was true and the second was not. Measured across
 * block x redact x flag x four roles, NO configuration redacted content the
 * decision scan never reached — the full multi-role prompt went into the
 * signed event verbatim. "Still stored" was the half that was true, and that
 * was the harm.
 *
 * Twin: sdk-python/tests/test_stored_content_net.py.
 *
 * Both halves are asserted here, because a fix satisfying only the first would
 * trade a storage leak for a worse defect:
 *
 *   H1  content outside the decision scan is redacted in the stored copy when
 *       a PII type is configured block/redact;
 *   H2  a detect_only-only policy leaves the record ALONE — that mode exists so
 *       an operator can baseline what actually flows, and scrubbing the record
 *       destroys the only thing it produces;
 *   H3  the event says the outbound request was NOT modified, so a redacted
 *       stored prompt beside `action_taken: "allowed"` cannot be read as
 *       prevention.
 *
 * H2 is also what makes H1 falsifiable: without it, a redacted stored prompt
 * could mean "this net fired" or "this SDK redacts everything always", and the
 * test could not tell them apart.
 */

const SSN = '123-45-6789';

let sentEvents: any[] = [];

beforeEach(() => {
  _reset();
  _resetSender();
  sentEvents = [];
  (global as any).fetch = async (_url: any, opts: any) => {
    const body = JSON.parse(opts.body);
    Array.isArray(body) ? sentEvents.push(...body) : sentEvents.push(body);
    return { ok: true, status: 200, json: async () => ({}) };
  };
});

afterEach(() => {
  delete (global as any).fetch;
  _reset();
  _resetSender();
});

async function waitForEvents(n = 1): Promise<void> {
  for (let i = 0; i < 200 && sentEvents.length < n; i++) {
    await new Promise((r) => setTimeout(r, 5));
  }
}

/** The four roles the decision scan does not reach. */
const UNSCANNED_ROLES: ReadonlyArray<{
  readonly role: string;
  readonly messages: (payload: string) => Array<Record<string, unknown>>;
}> = [
  {
    role: 'system',
    messages: (p) => [
      { role: 'system', content: `operator note: ${p}` },
      { role: 'user', content: 'hello' },
    ],
  },
  {
    role: 'earlier user turn',
    messages: (p) => [
      { role: 'user', content: `earlier: ${p}` },
      { role: 'assistant', content: 'noted' },
      { role: 'user', content: 'hello' },
    ],
  },
  {
    role: 'assistant',
    messages: (p) => [
      { role: 'user', content: 'summarise' },
      { role: 'assistant', content: `doc says: ${p}` },
      { role: 'user', content: 'hello' },
    ],
  },
  {
    role: 'tool result',
    messages: (p) => [
      { role: 'user', content: 'look it up' },
      { role: 'tool', content: `lookup returned: ${p}`, tool_call_id: 'c1' },
      { role: 'user', content: 'hello' },
    ],
  },
];

async function driveWrap(
  piiPolicy: { default?: any; rules?: Record<string, any> },
  messages: Array<Record<string, unknown>>,
): Promise<{ event: any; sentToProvider: string }> {
  init({ api_key: 'k', ingest_url: 'https://x', pii_policy: piiPolicy });
  let seen = '';
  const create = jest.fn(async (args: any) => {
    seen = JSON.stringify(args);
    return { choices: [{ message: { content: 'ok' } }], model: 'gpt-4' };
  });
  const wrapped = wrap({ chat: { completions: { create } } });
  await wrapped.chat.completions.create({ model: 'gpt-4', messages });
  expect(create).toHaveBeenCalledTimes(1);
  await waitForEvents(1);
  return { event: sentEvents[0], sentToProvider: seen };
}

describe('stored-content net: content outside the decision scan', () => {
  for (const { role, messages } of UNSCANNED_ROLES) {
    it(`H1 wrap(): an SSN in a ${role} is redacted in the STORED prompt under pii_policy block`, async () => {
      const { event } = await driveWrap({ rules: { ssn: 'block' } }, messages(SSN));
      // The call was allowed — enforcement scope is unchanged by this net.
      expect(event.action_taken).toBe('allowed');
      expect(event.prompt).not.toContain(SSN);
      expect(event.prompt).toContain('[REDACTED_SSN]');
    });

    it(`H1 wrap(): the same holds under pii_policy redact in a ${role}`, async () => {
      const { event } = await driveWrap({ rules: { ssn: 'redact' } }, messages(SSN));
      expect(event.prompt).not.toContain(SSN);
    });

    it(`H2 wrap(): a detect_only policy leaves a ${role} readable in the record`, async () => {
      const { event } = await driveWrap({ rules: { ssn: 'detect_only' } }, messages(SSN));
      expect(event.prompt).toContain(SSN);
    });
  }

  it('H3 the event states the outbound request was not modified', async () => {
    const { event, sentToProvider } = await driveWrap(
      { rules: { ssn: 'block' } },
      UNSCANNED_ROLES[0].messages(SSN),
    );
    const tel = event.metadata?.obsvr_telemetry;
    expect(tel?.stored_redaction_scope).toBe('unscanned_roles');
    expect(tel?.stored_redaction_types).toEqual(['ssn']);
    expect(tel?.stored_redaction_outbound_unmodified).toBe(true);
    // ...and that claim is TRUE: the provider did receive the raw value.
    // Recording a redacted prompt without saying this would assert an
    // enforcement that did not happen.
    expect(sentToProvider).toContain(SSN);
  });

  it('a single-turn call is decided by the ordinary gate, not by this net', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', pii_policy: { rules: { ssn: 'block' } } });
    const create = jest.fn(async (_args: any) => ({
      choices: [{ message: { content: 'ok' } }],
      model: 'gpt-4',
    }));
    const wrapped = wrap({ chat: { completions: { create } } });
    await expect(
      wrapped.chat.completions.create({
        model: 'gpt-4',
        messages: [{ role: 'user', content: `my ssn is ${SSN}` }],
      }),
    ).rejects.toThrow();
    // The provider is never reached — that is the enforcement this net does
    // NOT provide and must not be credited with. The control matters because a
    // storage net that also blocked would look identical from the record alone.
    expect(create).not.toHaveBeenCalled();
    await waitForEvents(1);
    expect(sentEvents[0].event_type).toBe('blocked_call');
    expect(sentEvents[0].metadata?.obsvr_telemetry?.stored_redaction_scope).toBeUndefined();
  });

  /**
   * The finding was never "wrap() has a gap" — it was "the two front doors
   * disagree, and the flagship is the unsafe one". A fix that closes one door
   * INVERTS the disagreement instead of ending it, which is what the live probe
   * caught after the first pass here was already green: `wrap()` redacted an
   * unreached-role SSN that `wrapOpenAICompatible()` still stored raw.
   *
   * So the pin is the AGREEMENT, not either door's behaviour.
   */
  for (const { role, messages } of UNSCANNED_ROLES) {
    it(`both front doors agree on a ${role} — neither stores what the other redacts`, async () => {
      const stored: Record<string, string> = {};
      for (const door of ['wrap', 'together'] as const) {
        _reset();
        _resetSender();
        sentEvents = [];
        init({ api_key: 'k', ingest_url: 'https://x', pii_policy: { rules: { ssn: 'block' } } });
        const create = jest.fn(async (_args: any) => ({
          choices: [{ message: { content: 'ok' } }],
          model: 'x',
        }));
        const client =
          door === 'wrap'
            ? wrap({ chat: { completions: { create } } })
            : wrapTogether({ chat: { completions: { create } } } as any);
        await client.chat.completions.create({ model: 'x', messages: messages(SSN) });
        expect(create).toHaveBeenCalledTimes(1);
        await waitForEvents(1);
        stored[door] = sentEvents[0].prompt;
      }
      expect(stored.wrap).not.toContain(SSN);
      expect(stored.together).not.toContain(SSN);
    });
  }

  it('no pii_policy at all: the net never fires', async () => {
    init({ api_key: 'k', ingest_url: 'https://x' });
    const create = jest.fn(async (_args: any) => ({
      choices: [{ message: { content: 'ok' } }],
      model: 'gpt-4',
    }));
    const wrapped = wrap({ chat: { completions: { create } } });
    await wrapped.chat.completions.create({
      model: 'gpt-4',
      messages: UNSCANNED_ROLES[0].messages(SSN),
    });
    await waitForEvents(1);
    expect(sentEvents[0].prompt).toContain(SSN);
    expect(sentEvents[0].metadata?.obsvr_telemetry?.stored_redaction_scope).toBeUndefined();
  });

  it('redacts response-only PII from the stored event', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', pii_policy: { rules: { ssn: 'redact' } } });
    const create = jest.fn(async (_args: any) => ({
      choices: [{ message: { content: `generated ssn ${SSN}` } }],
      model: 'gpt-4',
    }));
    const wrapped = wrap({ chat: { completions: { create } } });
    const response = await wrapped.chat.completions.create({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'hello' }],
    });
    expect(response.choices[0].message.content).toContain(SSN);
    await waitForEvents(1);
    expect(sentEvents[0].response).not.toContain(SSN);
    expect(sentEvents[0].response).toContain('[REDACTED_SSN]');
    expect(sentEvents[0].metadata?.obsvr_telemetry).toMatchObject({
      response_pii_detected: true,
      response_pii_types: ['ssn'],
      response_pii_action: 'redacted',
    });
  });

  it('applies the response storage net to integration-built events', () => {
    init({ api_key: 'k', ingest_url: 'https://x', pii_policy: { rules: { ssn: 'redact' } } });
    const event = buildIntegrationEvent({
      config: getConfig(),
      provider: 'unknown',
      model: 'gpt-4',
      operation: 'framework.callback',
      source: 'test',
      prompt: 'hello',
      response: `generated ssn ${SSN}`,
    });
    expect(event.response).not.toContain(SSN);
    expect(event.response).toContain('[REDACTED_SSN]');
    expect(event.metadata?.obsvr_telemetry).toMatchObject({
      stored_redaction_scope: 'all_event_content',
      stored_redaction_types: ['ssn'],
      stored_redaction_outbound_unmodified: true,
    });
  });
});
