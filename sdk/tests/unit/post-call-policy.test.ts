import { init, _reset, getConfig } from '../../src/proxy/config';
import { applyPostCallPolicy, mergePostCallOutcome } from '../../src/integrations/core';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';

beforeEach(() => { _reset(); _resetSender(); });

describe('applyPostCallPolicy', () => {
  it('returns pass for clean response', async () => {
    init({ api_key: 'test' });
    const result = await applyPostCallPolicy('nice response', {}, getConfig());
    expect(result.decision).toBe('pass');
  });

  it('flag decision from hook sets policy_flag event type', async () => {
    init({
      api_key: 'test',
      on_post_call: () => ({ decision: 'flag' as const, reason: 'flagged' }),
    });
    const result = await applyPostCallPolicy('response text', {}, getConfig());
    expect(result.decision).toBe('flag');
    expect(result.compliance.event_type).toBe('policy_flag');
  });

  it('redact_response decision modifies response text', async () => {
    init({
      api_key: 'test',
      on_post_call: () => ({ decision: 'redact_response' as const }),
    });
    const result = await applyPostCallPolicy('call me at 555-123-4567', {}, getConfig());
    expect(result.decision).toBe('redact_response');
    expect(result.redactedResponse).toBeDefined();
    expect(result.redactedResponse).not.toContain('555-123-4567');
  });

  it('hook error falls back to pass', async () => {
    init({
      api_key: 'test',
      on_post_call: () => { throw new Error('hook error'); },
    });
    const result = await applyPostCallPolicy('response', {}, getConfig());
    expect(result.decision).toBe('pass');
  });
});

describe('built-in response-side PII scan (post_call phase)', () => {
  it('detects + redacts stored copy for redact-severity types when pii_policy configured', async () => {
    init({ api_key: 'test', pii_policy: { default: 'redact' } });
    const result = await applyPostCallPolicy(
      'the SSN is 123-45-6789',
      {},
      getConfig(),
    );
    expect(result.decision).toBe('redact_response');
    expect(result.responsePii?.detected).toBe(true);
    expect(result.responsePii?.types).toContain('ssn');
    expect(result.responsePii?.action).toBe('redacted');
    expect(result.redactedResponse).not.toContain('123-45-6789');
    expect(result.compliance.policy_reason).toBe('pii_detected_in_response');
  });

  it('detect_only types record the verdict without redacting', async () => {
    init({ api_key: 'test', pii_policy: { default: 'detect_only' } });
    const result = await applyPostCallPolicy('the SSN is 123-45-6789', {}, getConfig());
    expect(result.decision).toBe('pass');
    expect(result.responsePii?.detected).toBe(true);
    expect(result.responsePii?.action).toBe('detected_only');
    expect(result.redactedResponse).toBeUndefined();
  });

  it('response-side block severity cannot un-send: it redacts the stored copy', async () => {
    init({ api_key: 'test', pii_policy: { default: 'block' } });
    const result = await applyPostCallPolicy('card 4111 1111 1111 1111', {}, getConfig());
    expect(result.decision).toBe('redact_response');
    expect(result.responsePii?.action).toBe('redacted');
  });

  it('no pii_policy configured -> no response scan (pre-call parity)', async () => {
    init({ api_key: 'test' });
    const result = await applyPostCallPolicy('the SSN is 123-45-6789', {}, getConfig());
    expect(result.responsePii).toBeUndefined();
  });
});

describe('mergePostCallOutcome', () => {
  it('replaces stored response, overlays compliance, stamps response_pii_* telemetry', () => {
    const event: any = { response: 'raw 123-45-6789', metadata: { obsvr_telemetry: { finish_reason: 'stop' } } };
    mergePostCallOutcome(event, {
      decision: 'redact_response',
      redactedResponse: 'raw [SSN]',
      compliance: { event_type: 'policy_flag', policy_reason: 'pii_detected_in_response' },
      responsePii: { detected: true, types: ['ssn'], action: 'redacted' },
    });
    expect(event.response).toBe('raw [SSN]');
    expect(event.event_type).toBe('policy_flag');
    expect(event.policy_reason).toBe('pii_detected_in_response');
    const t = event.metadata.obsvr_telemetry;
    expect(t.finish_reason).toBe('stop'); // existing telemetry preserved
    expect(t.response_pii_detected).toBe(true);
    expect(t.response_pii_types).toEqual(['ssn']);
    expect(t.response_pii_action).toBe('redacted');
  });

  it('creates the metadata channel when absent', () => {
    const event: any = { response: 'ok' };
    mergePostCallOutcome(event, {
      decision: 'pass',
      compliance: {},
      responsePii: { detected: true, types: ['email'], action: 'detected_only' },
    });
    expect(event.metadata.obsvr_telemetry.response_pii_action).toBe('detected_only');
  });
});
