/**
 * A detector defect must never surface as an unhandled error in the host app.
 *
 * Covers every PRE-CALL path - the proxy wrapper, the integrations core, the
 * governance surface and tool execution - and asserts the split the
 * disposition registry draws: the scanning layers resolve by failMode, while
 * the floor class (policy_floor, canary) blocks regardless, because a floor is
 * by definition the thing failMode cannot move.
 *
 * The failure is injected as a REAL one rather than by mocking a module: a
 * metadata object whose property getter throws makes the session-key
 * derivation raise inside the detector section, which is exactly the shape of
 * defect this guard exists for. (ES module namespaces are read-only here, so
 * module-level spying is not available - and a genuine throw is the stronger
 * test regardless.)
 */
import { init, _reset, getConfig } from '../../src/proxy/config';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { applyPreCallPolicy } from '../../src/integrations/core';
import { evaluate } from '../../src/governance/evaluate';
import { wrap } from '../../src/proxy/wrapper';
import { obsvrGovernTool } from '../../src/integrations/tools';
import { markTainted, _resetSessionTaint } from '../../src/policy/session-taint';
import {
  FLOOR_CLASS_LAYERS,
  UNSCANNED_PLACEHOLDER,
  getDetectorErrorCount,
  preCallFailureCompliance,
  recordDetectorFailure,
  safeStoredCopy,
  _resetDetectorErrors,
} from '../../src/policy/detector-guard';

const realError = console.error;

beforeEach(() => {
  _reset();
  _resetSender();
  _resetDetectorErrors();
  console.error = () => {}; // the guard logs loudly by design
  (global as any).fetch = async () => ({ ok: true, status: 200, json: async () => ({}) });
});

afterEach(() => {
  console.error = realError;
  delete (global as any).fetch;
});

/** Metadata whose read throws - a real defect vector, not a mock. */
function hostileMetadata(): Record<string, unknown> {
  return Object.defineProperty({}, 'user_id', {
    get() {
      throw new Error('detector bug');
    },
    enumerable: true,
    configurable: true,
  }) as Record<string, unknown>;
}

/**
 * The same defect, but transient: the getter throws on its FIRST read only.
 *
 * Needed on the wrap() path because a permanently-throwing getter also breaks
 * `JSON.stringify` later, inside the audit sender's metadata trim - a
 * different subsystem with its own posture, not a detector layer. Throwing
 * once keeps the vector aimed at the thing under test: the detector read.
 */
function hostileMetadataOnce(): Record<string, unknown> {
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

function initWith(failMode: 'open' | 'closed') {
  init({
    api_key: 'test',
    ingest_url: 'https://x.test',
    fail_mode: failMode,
    pii_policy: { default: 'block' },
    multi_turn_injection: { enabled: true },
  });
  return getConfig();
}

describe('the rule itself: one resolution point', () => {
  it('scanning layers resolve by failMode', () => {
    expect(recordDetectorFailure('builtin_pii_scan', new Error('x'), { failMode: 'open' } as never)).toBe(false);
    expect(recordDetectorFailure('builtin_pii_scan', new Error('x'), { failMode: 'closed' } as never)).toBe(true);
  });

  it('the floor class resolves closed regardless of failMode', () => {
    for (const layer of ['policy_floor', 'canary']) {
      expect(recordDetectorFailure(layer, new Error('x'), { failMode: 'open' } as never)).toBe(true);
      expect(FLOOR_CLASS_LAYERS.has(layer)).toBe(true);
    }
  });

  it('counts every failure it resolves', () => {
    _resetDetectorErrors();
    recordDetectorFailure('policy_rules', new Error('x'), { failMode: 'open' } as never);
    recordDetectorFailure('canary', new Error('x'), { failMode: 'open' } as never);
    expect(getDetectorErrorCount()).toBe(2);
  });

  it('never mints an action_taken value outside the closed wire enum', () => {
    const legal = ['allowed', 'blocked', 'redacted', 'hook_error', 'hook_timeout'];
    for (const failClosed of [true, false]) {
      const c = preCallFailureCompliance('policy_rules', new Error('x'), failClosed, 'v1');
      expect(legal).toContain(c.action_taken);
      expect(c.rule_id).toBe('sdk:detector_error');
    }
  });

  it('the unscanned marker cannot be mistaken for a redaction', () => {
    expect(UNSCANNED_PLACEHOLDER.startsWith('[REDACTED')).toBe(false);
    expect(safeStoredCopy(() => { throw new Error('redactor broke'); })).toBe(UNSCANNED_PLACEHOLDER);
    expect(safeStoredCopy(() => 'clean copy')).toBe('clean copy');
  });
});

describe('pre-call guard: applyPreCallPolicy (integrations path)', () => {
  it('a real detector defect does not reach the caller, and is counted', async () => {
    const config = initWith('open');
    const result = await applyPreCallPolicy('hello', {
      config, provider: 'openai', operation: 'chat', metadata: hostileMetadata(),
    } as never);

    expect(result.decision).toBe('allow');
    expect(result.compliance.rule_id).toBe('sdk:detector_error');
    expect(getDetectorErrorCount()).toBeGreaterThan(0);
  });

  it('the same defect blocks under failMode closed', async () => {
    const config = initWith('closed');
    const result = await applyPreCallPolicy('hello', {
      config, provider: 'openai', operation: 'chat', metadata: hostileMetadata(),
    } as never);
    expect(result.decision).toBe('block');
  });

  it("records which layer was lost, on the call's own event", async () => {
    const config = initWith('open');
    const result = await applyPreCallPolicy('hello', {
      config, provider: 'openai', operation: 'chat', metadata: hostileMetadata(),
    } as never);
    const failure = (result.compliance as never as { detector_failure: Record<string, unknown> })
      .detector_failure;
    expect(failure).toBeDefined();
    expect(failure.phase).toBe('pre_call');
    expect(String(failure.error)).toContain('detector bug');
  });

  it('a healthy call is completely unaffected', async () => {
    const config = initWith('open');
    const result = await applyPreCallPolicy('hello', {
      config, provider: 'openai', operation: 'chat',
    });
    expect(result.decision).toBe('allow');
    expect(result.compliance.rule_id).not.toBe('sdk:detector_error');
    expect(getDetectorErrorCount()).toBe(0);
  });
});

describe('pre-call guard: evaluate() (governance path)', () => {
  it('resolves instead of throwing at whoever called evaluate()', async () => {
    initWith('open');
    const res = await evaluate({
      action_type: 'chat',
      payload: { prompt: 'hello' },
      metadata: hostileMetadata(),
    } as never);
    expect(['PERMITTED', 'BLOCKED']).toContain(res.decision);
  });

  it('a healthy evaluate is unaffected', async () => {
    initWith('open');
    const res = await evaluate({ action_type: 'chat', payload: { prompt: 'hello' } });
    expect(res.decision).toBe('PERMITTED');
    expect(res.rule_id).not.toBe('sdk:detector_error');
  });
});

describe('pre-call guard: the proxy wrapper (the host call itself)', () => {
  function client() {
    return wrap({
      chat: {
        completions: {
          create: async (_args: unknown) => ({ choices: [{ message: { content: 'ok' } }] }),
        },
      },
    });
  }

  it('governance really is running (else the rest proves nothing)', async () => {
    initWith('open');
    await expect(
      client().chat.completions.create({
        model: 'gpt-4o',
        messages: [{ role: 'user', content: 'my ssn is 123-45-6789' }],
      }),
    ).rejects.toThrow(/blocked by policy/i);
  });

  // The wrapper's session-taint step derives the session key by spreading the
  // call's metadata, so a throwing getter raises INSIDE the guarded span - a
  // real detector defect on the SDK's most-used path, end to end through
  // wrap(). Until the taint step moved inside the span this same call threw
  // "detector bug" straight out of the host's own create().
  it('a defect inside the span does not reach the host, and is counted', async () => {
    initWith('open');
    const res = await client().chat.completions.create({
      model: 'gpt-4o',
      messages: [{ role: 'user', content: 'hello' }],
      metadata: hostileMetadataOnce(),
    } as never);

    expect(res).toEqual({ choices: [{ message: { content: 'ok' } }] });
    expect(getDetectorErrorCount()).toBe(1);
  });

  it('the same defect blocks under failMode closed, as a policy error', async () => {
    initWith('closed');
    await expect(
      client().chat.completions.create({
        model: 'gpt-4o',
        messages: [{ role: 'user', content: 'hello' }],
        metadata: hostileMetadataOnce(),
      } as never),
    ).rejects.toThrow(/blocked by policy/i);
    expect(getDetectorErrorCount()).toBe(1);
  });

  it('a healthy call on the same path is unaffected', async () => {
    initWith('open');
    const res = await client().chat.completions.create({
      model: 'gpt-4o',
      messages: [{ role: 'user', content: 'hello' }],
      metadata: { user_id: 'u1' },
    } as never);
    expect(res).toEqual({ choices: [{ message: { content: 'ok' } }] });
    expect(getDetectorErrorCount()).toBe(0);
  });
});

describe('pre-call guard: obsvrGovernTool (the tool-execution path)', () => {
  function governed(metadata: Record<string, unknown>) {
    return obsvrGovernTool(
      { name: 'calc', execute: async (_input: unknown) => 'tool ran' },
      { name: 'calc', metadata },
    );
  }

  /** The taint layer only derives a key once a session is actually tainted. */
  function seedTaintedSession() {
    markTainted('someone-else', 'prompt_injection', Date.now());
  }

  beforeEach(() => {
    _resetSessionTaint();
  });

  it('a defect in the taint layer does not reach the host; the tool still runs', async () => {
    init({
      api_key: 'test',
      ingest_url: 'https://x.test',
      fail_mode: 'open',
      sessionTaint: { enabled: true, action: 'block' },
    });
    seedTaintedSession();

    await expect(governed(hostileMetadata()).execute('2+2')).resolves.toBe('tool ran');
    expect(getDetectorErrorCount()).toBe(1);
  });

  it('the same defect refuses the tool under failMode closed', async () => {
    init({
      api_key: 'test',
      ingest_url: 'https://x.test',
      fail_mode: 'closed',
      sessionTaint: { enabled: true, action: 'block' },
    });
    seedTaintedSession();

    // The refusal is raised before the tool function is entered, so it
    // surfaces synchronously - the same shape the allow/deny gate uses.
    await expect(governed(hostileMetadata()).execute('2+2')).rejects.toThrow(
      /session_taint detector failed/i,
    );
    expect(getDetectorErrorCount()).toBe(1);
  });

  it('the guard does not swallow the taint latch\'s own block', async () => {
    init({
      api_key: 'test',
      ingest_url: 'https://x.test',
      fail_mode: 'open',
      sessionTaint: { enabled: true, action: 'block' },
    });
    markTainted('u1', 'canary_leak', Date.now());

    await expect(governed({ user_id: 'u1' }).execute('2+2')).rejects.toThrow(
      /session tainted \(canary_leak\)/i,
    );
    expect(getDetectorErrorCount()).toBe(0);
  });

  it('a healthy tool call is unaffected', async () => {
    init({
      api_key: 'test',
      ingest_url: 'https://x.test',
      fail_mode: 'open',
      sessionTaint: { enabled: true, action: 'block' },
    });
    seedTaintedSession();

    await expect(governed({ user_id: 'u1' }).execute('2+2')).resolves.toBe('tool ran');
    expect(getDetectorErrorCount()).toBe(0);
  });
});
