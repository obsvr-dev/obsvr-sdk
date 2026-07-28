import { init, _reset, getConfig } from '../../src/proxy/config';
import {
  _resetSender,
  CONTENT_PROVENANCE_METADATA_KEY,
} from '../../src/proxy/sender/fire-and-forget';
import { buildIntegrationEvent, emitIntegrationEvent } from '../../src/integrations/core';
import type { IntegrationEventParams } from '../../src/integrations/core';

/**
 * Content-provenance on audit events. Twin:
 * sdk-python/tests/test_content_provenance.py.
 *
 * `source` names the integration that emitted an event; `content_provenance`
 * names where inside the payload the content came from. The distinction is an
 * incident-triage one — a prompt_injection in a `user_turn` is someone probing
 * your bot, the identical finding in a `tool_result` means an upstream source
 * is already compromised.
 *
 * The property under test is as much about ABSENCE as presence: the field is
 * set only where an integration genuinely knows, and a guessed value is worse
 * than no value, because it gets read as evidence in exactly the incident where
 * being wrong costs the most.
 */

let sentEvents: any[] = [];

beforeEach(() => {
  _reset();
  _resetSender();
  sentEvents = [];
  (global as any).fetch = async (_url: any, opts: any) => {
    sentEvents.push(JSON.parse(opts.body));
    return { ok: true, status: 200 };
  };
});

afterEach(() => {
  _reset();
  _resetSender();
});

function params(extra: Partial<IntegrationEventParams> = {}): IntegrationEventParams {
  init({ api_key: 'test-key', sample_rate: 1 });
  return {
    config: getConfig(),
    provider: 'mcp',
    model: 'mcp',
    operation: 'mcp.tool.call',
    source: 'mcp',
    prompt: 'p',
    response: 'r',
    ...extra,
  } as IntegrationEventParams;
}

async function waitForEvents(n = 1): Promise<void> {
  for (let i = 0; i < 500 && sentEvents.length < n; i++) {
    await new Promise((r) => setTimeout(r, 10));
  }
}

describe('content_provenance on the built event', () => {
  it('is absent by default — an unset field is the honest one', () => {
    const event = buildIntegrationEvent(params());
    expect(event.content_provenance).toBeUndefined();
    expect('content_provenance' in JSON.parse(JSON.stringify(event))).toBe(false);
  });

  it('is present when the integration genuinely knows', () => {
    const event = buildIntegrationEvent(params({ contentProvenance: 'tool_result' }));
    expect(event.content_provenance).toBe('tool_result');
  });

  it('is never derived from the operation name', () => {
    // "mcp.tool.call" looks like it implies tool_result. It does not: the
    // pre-call sites emit that same operation with the tool's ARGUMENTS as
    // content, so inferring here would mislabel every blocked request.
    const event = buildIntegrationEvent(params({ operation: 'mcp.tool.call' }));
    expect(event.content_provenance).toBeUndefined();
  });
});

describe('carriage to the wire', () => {
  it('rides the reserved metadata key, because ingest has no column yet', async () => {
    emitIntegrationEvent(params({ contentProvenance: 'tool_result' }));
    await waitForEvents(1);
    const wire = sentEvents[0].events?.[0] ?? sentEvents[0];
    expect(wire.content_provenance).toBe('tool_result');
    expect(wire.metadata[CONTENT_PROVENANCE_METADATA_KEY]).toBe('tool_result');
  });

  it('stamps no metadata key when unset', async () => {
    emitIntegrationEvent(params());
    await waitForEvents(1);
    const wire = sentEvents[0].events?.[0] ?? sentEvents[0];
    expect(wire.content_provenance).toBeUndefined();
    expect(wire.metadata?.[CONTENT_PROVENANCE_METADATA_KEY]).toBeUndefined();
  });
});

describe('it is not a policy input', () => {
  it('moves no compliance field', () => {
    // Audit-record completeness only. obsvr gates on session-taint
    // reachability, not on source classification, and this field must never
    // quietly become a trust signal.
    const plain = buildIntegrationEvent(params()) as any;
    const tagged = buildIntegrationEvent(params({ contentProvenance: 'tool_result' })) as any;
    for (const key of [
      'action_taken',
      'action_reason',
      'action_source',
      'event_type',
      'reason_code',
      'blocked_types',
      'redacted_types',
      'policy_version',
    ]) {
      expect(tagged[key]).toEqual(plain[key]);
    }
  });
});
