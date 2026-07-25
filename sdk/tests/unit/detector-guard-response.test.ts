/**
 * The RESPONSE-phase and check-only guards.
 *
 * A different rule from the pre-call span, and the difference is the point:
 * once the provider has answered, "closed" is not an available action - not
 * even for the floor class - because blocking cannot un-produce the answer
 * and the published contract is that a response-side control never withholds
 * the value returned to the caller. What DOES fail closed is the stored audit
 * copy, under a marker deliberately unlike a redaction token.
 *
 * The one exception is the MCP tool-result scanner, which resolves by
 * failMode: its result has NOT yet reached the model, so withholding it is
 * still real prevention.
 *
 * Failures are injected as REAL throws through a caller-supplied object, not
 * by mocking a module (ES module namespaces are read-only here).
 */
import { init, _reset, getConfig } from '../../src/proxy/config';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import {
  applyPostCallPolicy,
  applyObservePolicy,
  buildIntegrationEvent,
} from '../../src/integrations/core';
import { explain } from '../../src/governance/evaluate';
import { resolveResponseScanFailure } from '../../src/policy/response-scan';
import {
  UNSCANNED_PLACEHOLDER,
  getDetectorErrorCount,
  responsePhaseFailureCompliance,
  _resetDetectorErrors,
} from '../../src/policy/detector-guard';

const realError = console.error;

beforeEach(() => {
  _reset();
  _resetSender();
  _resetDetectorErrors();
  console.error = () => {};
});

afterEach(() => {
  console.error = realError;
});

/**
 * A policy rule the engine will choke on: it passes the activation filter,
 * then the matcher reads a condition whose getter throws. A real defect
 * inside the rules layer, driven entirely through config.
 *
 * Armed AFTER init() on purpose - init hashes the rules to derive the policy
 * version, so a getter that throws immediately fires at configuration time,
 * outside the span under test.
 */
function hostileRule(): { rule: Record<string, unknown>; arm: () => void } {
  let armed = false;
  const rule: Record<string, unknown> = {
    id: 'r1',
    name: 'hostile',
    type: 'keyword',
    enabled: true,
    mode: 'enforce',
    action: 'block',
    applies_to: 'both',
  };
  Object.defineProperty(rule, 'conditions', {
    get() {
      if (armed) throw new Error('detector bug');
      return { keywords: ['zzz-never-matches'] };
    },
    enumerable: true,
    configurable: true,
  });
  return { rule, arm: () => { armed = true; } };
}

function initWith(failMode: 'open' | 'closed', extra: Record<string, unknown> = {}) {
  init({
    api_key: 'test',
    ingest_url: 'https://x.test',
    fail_mode: failMode,
    ...extra,
  } as never);
  return getConfig();
}

describe('the response-phase rule itself', () => {
  it('never resolves closed, and never mints an illegal action_taken', () => {
    const legal = ['allowed', 'blocked', 'redacted', 'hook_error', 'hook_timeout'];
    for (const layer of ['policy_floor', 'canary', 'policy_rules', 'builtin_pii_scan']) {
      const c = responsePhaseFailureCompliance(layer, new Error('x'), 'v1');
      expect(legal).toContain(c.action_taken);
      expect(c.action_taken).toBe('allowed');
      expect(c.detector_failure.resolution).toBe('open');
      expect(c.detector_failure.phase).toBe('response');
    }
  });

  it('the floor class does NOT fail closed here, unlike pre-call', () => {
    // Pre-call, a crashed floor blocks. Post-call there is nothing to block.
    const c = responsePhaseFailureCompliance('policy_floor', new Error('x'), 'v1');
    expect(c.detector_failure.floor_class).toBe(true);
    expect(c.detector_failure.resolution).toBe('open');
  });

  it('the stored copy is flagged as unscanned, not as redacted', () => {
    const c = responsePhaseFailureCompliance('canary', new Error('x'), 'v1');
    expect(c.detector_failure.stored_unscanned).toBe(true);
    expect(UNSCANNED_PLACEHOLDER.startsWith('[REDACTED')).toBe(false);
  });
});

describe('applyPostCallPolicy', () => {
  it('delivers the response unchanged and withholds only the stored copy', async () => {
    const h = hostileRule();
    const config = initWith('open', { policy_rules: [h.rule] });
    h.arm();
    const result = await applyPostCallPolicy('the model answer', {}, config);

    expect(result.decision).toBe('flag'); // never redact_response
    expect(result.redactedResponse).toBe(UNSCANNED_PLACEHOLDER);
    expect(result.compliance.rule_id).toBe('sdk:detector_error');
    expect(getDetectorErrorCount()).toBe(1);
  });

  it('failMode closed does not change that - the answer already exists', async () => {
    const h = hostileRule();
    const config = initWith('closed', { policy_rules: [h.rule] });
    h.arm();
    const result = await applyPostCallPolicy('the model answer', {}, config);

    expect(result.decision).toBe('flag');
    expect(result.redactedResponse).toBe(UNSCANNED_PLACEHOLDER);
  });

  it('a healthy post-call pass is unaffected', async () => {
    const config = initWith('open');
    const result = await applyPostCallPolicy('the model answer', {}, config);
    expect(result.decision).toBe('pass');
    expect(result.redactedResponse).toBeUndefined();
    expect(getDetectorErrorCount()).toBe(0);
  });
});

describe('applyObservePolicy', () => {
  it('signals that the stored copy was never scanned', () => {
    const config = initWith('open', { pii_policy: { default: 'redact' } });
    // Force the scan itself to raise: a truthy non-string reaches
    // `text.normalize` inside the matcher and throws there.
    const result = applyObservePolicy({} as unknown as string, config);

    expect(result.shouldRedactStored).toBe(true);
    expect(result.storedUnscanned).toBe(true);
    expect(result.compliance.rule_id).toBe('sdk:detector_error');
    expect(getDetectorErrorCount()).toBe(1);
  });

  it('a healthy observe pass is unaffected', () => {
    const config = initWith('open', { pii_policy: { default: 'redact' } });
    const result = applyObservePolicy('nothing sensitive', config);
    expect(result.shouldRedactStored).toBe(false);
    expect(result.storedUnscanned).toBeUndefined();
    expect(getDetectorErrorCount()).toBe(0);
  });
});

describe('buildIntegrationEvent (the event-construction net)', () => {
  it("records a guarded site's failure on the call's own event", () => {
    const config = initWith('open');
    const event = buildIntegrationEvent({
      config,
      provider: 'openai',
      model: 'gpt-4o',
      operation: 'chat',
      source: 'test',
      prompt: 'hello',
      compliance: {
        ...responsePhaseFailureCompliance('policy_rules', new Error('detector bug'), 'v1'),
      } as never,
    });

    const telemetry = (event.metadata as Record<string, unknown>)
      .obsvr_telemetry as Record<string, unknown>;
    const failure = telemetry.detector_failure as Record<string, unknown>;
    expect(failure.layer).toBe('policy_rules');
    expect(failure.stored_unscanned).toBe(true);
    expect(String(failure.error)).toContain('detector bug');
  });

  it('does not stamp the channel on a healthy event', () => {
    const config = initWith('open');
    const event = buildIntegrationEvent({
      config, provider: 'openai', model: 'gpt-4o', operation: 'chat', source: 'test', prompt: 'hello',
    });
    const telemetry = (event.metadata as Record<string, unknown> | undefined)
      ?.obsvr_telemetry as Record<string, unknown> | undefined;
    expect(telemetry?.detector_failure).toBeUndefined();
  });
});

describe('explain() (check-only)', () => {
  it('reports what it could not predict instead of a confident allow', () => {
    const h = hostileRule();
    initWith('open', { policy_rules: [h.rule] });
    h.arm();
    const result = explain('some text');

    expect(result.decision).toBe('allow'); // it truly did not find a block
    expect(result.not_evaluated).toContain('policy_rules');
    expect(result.rule_id).toBe('sdk:detector_error');
    expect(getDetectorErrorCount()).toBe(1);
  });

  it('a healthy explain is unaffected', () => {
    initWith('open');
    const result = explain('some text');
    expect(result.rule_id).not.toBe('sdk:detector_error');
    expect(result.not_evaluated).toEqual(['customer_hook', 'multi_turn_injection']);
    expect(getDetectorErrorCount()).toBe(0);
  });
});

describe('the MCP tool-result scanner', () => {
  it('resolves by failMode, not fail-closed: the tool has already run', () => {
    const open = resolveResponseScanFailure(new Error('x'), initWith('open'));
    expect(open.action).toBe('allow');
    expect(open.event_type).toBe('policy_flag'); // never a clean tool_call
    expect(open.rule_id).toBe('sdk:detector_error');

    _reset();
    const closed = resolveResponseScanFailure(new Error('x'), initWith('closed'));
    expect(closed.action).toBe('block');
    expect(closed.event_type).toBe('blocked_call');
  });
});
