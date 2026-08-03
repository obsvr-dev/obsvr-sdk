/**
 * Security regression tests: failMode ('open' | 'closed') enforcement, and the
 * central failure-disposition registry that declares what every governance
 * layer does when it cannot render a verdict.
 *
 * fail_open (default): hook timeout/error → allow (audit-friendly).
 * fail_closed: hook timeout/error → block (a policy engine that cannot
 * render a verdict must not be treated as approval).
 *
 * The registry half asserts three things: the TS registry matches the shared
 * fixture (which is also what the Python twin pins to, so this is the parity
 * check), every detector module has a declaration (so a new detector cannot
 * land without stating its posture), and the declarations match what the code
 * actually does for every state a unit test can drive.
 */
import * as fs from 'fs';
import * as path from 'path';
import { init, _reset, getConfig, _getPolicySyncState } from '../../src/proxy/config';
import { applyPreCallPolicy, applyPostCallPolicy } from '../../src/integrations/core';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import {
  FAILURE_DISPOSITIONS,
  DECLARED_LAYER_IDS,
  dispositionFor,
  getFailureDisposition,
  unguardedLayerIds,
  type FailureState,
} from '../../src/policy/failure-dispositions';

beforeEach(() => { _reset(); _resetSender(); });

describe('failMode default (open)', () => {
  it('defaults to open in resolved config', () => {
    init({ api_key: 'test' });
    expect(getConfig().failMode).toBe('open');
  });

  it('allows the call when the hook times out', async () => {
    init({
      api_key: 'test',
      hook_timeout_ms: 50,
      on_pre_call: () => new Promise(() => {}), // never resolves
    });
    const result = await applyPreCallPolicy('hello', {
      config: getConfig(),
      provider: 'openai',
      operation: 'chat',
    });
    expect(result.decision).toBe('allow');
  });

  it('allows the call when the hook throws', async () => {
    init({
      api_key: 'test',
      on_pre_call: () => { throw new Error('hook exploded'); },
    });
    const result = await applyPreCallPolicy('hello', {
      config: getConfig(),
      provider: 'openai',
      operation: 'chat',
    });
    expect(result.decision).toBe('allow');
    expect(result.compliance.action_taken).toBe('hook_error');
  });
});

describe('failMode: closed', () => {
  it('is carried through config resolution (snake_case)', () => {
    init({ api_key: 'test', fail_mode: 'closed' });
    expect(getConfig().failMode).toBe('closed');
  });

  it('is carried through config resolution (camelCase ObsvrConfig)', () => {
    init({ apiKey: 'test', failMode: 'closed' });
    expect(getConfig().failMode).toBe('closed');
  });

  it('blocks the call when the hook times out', async () => {
    init({
      api_key: 'test',
      fail_mode: 'closed',
      hook_timeout_ms: 50,
      on_pre_call: () => new Promise(() => {}), // never resolves
    });
    const result = await applyPreCallPolicy('hello', {
      config: getConfig(),
      provider: 'openai',
      operation: 'chat',
    });
    expect(result.decision).toBe('block');
  });

  it('blocks the call when the hook throws', async () => {
    init({
      api_key: 'test',
      fail_mode: 'closed',
      on_pre_call: () => { throw new Error('hook exploded'); },
    });
    const result = await applyPreCallPolicy('hello', {
      config: getConfig(),
      provider: 'openai',
      operation: 'chat',
    });
    expect(result.decision).toBe('block');
  });

  it('does not affect calls where the hook renders a verdict normally', async () => {
    init({
      api_key: 'test',
      fail_mode: 'closed',
      on_pre_call: () => 'allow' as const,
    });
    const result = await applyPreCallPolicy('hello', {
      config: getConfig(),
      provider: 'openai',
      operation: 'chat',
    });
    expect(result.decision).toBe('allow');
  });
});

// ── Central failure-disposition registry ─────────────────────────────────────

function findFixture(rel: string): string {
  let dir = process.cwd();
  for (let i = 0; i < 6; i++) {
    const candidate = path.join(dir, rel);
    if (fs.existsSync(candidate)) return candidate;
    dir = path.dirname(dir);
  }
  throw new Error(`fixture not found upward from ${process.cwd()}: ${rel}`);
}

interface FixtureLayer {
  id: string;
  module_ts: string;
  module_py: string;
  timeout: { disposition: string; qualifier?: string };
  error: { disposition: string; qualifier?: string };
  degraded: { disposition: string; qualifier?: string };
  hook_overridable: boolean;
  notes: string;
}

const fixture = JSON.parse(
  fs.readFileSync(findFixture('conformance/fixtures/fail_mode.json'), 'utf-8'),
) as {
  vocabulary: { states: FailureState[]; dispositions: Record<string, string>; qualifiers: Record<string, string> };
  layers: FixtureLayer[];
};

describe('failure-disposition registry: pinned to the shared fixture', () => {
  it('declares exactly the layers the fixture pins, in the same order', () => {
    expect(DECLARED_LAYER_IDS).toEqual(fixture.layers.map((l) => l.id));
  });

  it('matches the fixture on every field, for every layer', () => {
    for (const expected of fixture.layers) {
      const entry = getFailureDisposition(expected.id);
      expect(entry).toBeDefined();
      expect(entry!.module).toBe(expected.module_ts);
      expect(entry!.hookOverridable).toBe(expected.hook_overridable);
      expect(entry!.notes).toBe(expected.notes);
      for (const state of fixture.vocabulary.states) {
        expect(entry![state]).toEqual(expected[state]);
      }
    }
  });

  it('declares all three failure states for every layer, using the pinned vocabulary', () => {
    const validDispositions = Object.keys(fixture.vocabulary.dispositions);
    const validQualifiers = Object.keys(fixture.vocabulary.qualifiers);
    for (const entry of FAILURE_DISPOSITIONS) {
      for (const state of fixture.vocabulary.states) {
        const declared = entry[state];
        expect(validDispositions).toContain(declared.disposition);
        if (declared.qualifier) expect(validQualifiers).toContain(declared.qualifier);
      }
    }
  });

  it('has no duplicate layer ids', () => {
    expect(new Set(DECLARED_LAYER_IDS).size).toBe(DECLARED_LAYER_IDS.length);
  });
});

describe('failure-disposition registry: the gate', () => {
  /**
   * Modules under src/policy/ that are NOT governance layers, and therefore
   * need no declaration. Adding a file here is a deliberate statement that it
   * decides nothing; adding a detector without a declaration fails below.
   */
  const NON_DETECTOR_MODULES = new Set([
    'approvals.ts', // approval bookkeeping consumed by the rules engine
    'decision-record.ts', // canonical decision document + hashing
    'normalize.ts', // text normalization primitives
    'pii-types.ts', // the PII type vocabulary
    'policy-error.ts', // typed policy-block error and its construction choke point
    'policy-log.ts', // policy-change audit emission
    'rego-export.ts', // one-way policy export, never an evaluator
    'tool-content-hash.ts', // evidence producer, decides nothing
    'failure-dispositions.ts', // this registry
    'detector-guard.ts', // the resolution point itself, not a layer that can fail
    // Builds the STORED copy of content the decision scan never reached
    // (system prompts, earlier turns, assistant turns, tool results). It
    // decides nothing: the verdict is already final when it runs, and no value
    // it returns can block, allow, or change what went to the provider. Its
    // own failure resolution is a stored-copy one and is already declared
    // elsewhere — the scan it runs is `builtin_pii_scan`, which is what it
    // records a failure against, and the redactor it calls is
    // `deobfuscation_views`, whose declaration is the one that says a stored
    // copy fails CLOSED to [UNSCANNED:detector_error] rather than persist text
    // nothing vetted. Every call site is on the emit path, so both exported
    // functions hold the whole body inside one guard: nothing raises into the
    // host. Same exemption reason as tool-content-hash.ts, plus that
    // inherited disposition. Twin: sdk-python/obsvr/stored_content.py.
    'stored-content.ts',
  ]);

  it('declares every detector module in src/policy/', () => {
    const policyDir = path.dirname(findFixture('sdk-typescript/src/policy/hook.ts'));
    const declaredModules = new Set(FAILURE_DISPOSITIONS.map((e) => path.basename(e.module)));
    const undeclared = fs
      .readdirSync(policyDir, { withFileTypes: true })
      .filter((entry) => entry.isFile() && entry.name.endsWith('.ts'))
      .map((entry) => entry.name)
      .filter((name) => !NON_DETECTOR_MODULES.has(name) && !declaredModules.has(name));

    // A new detector must declare its failure disposition before it can land.
    expect(undeclared).toEqual([]);
  });

  it('no layer lets its failure escape to the host', () => {
    // This list was the eight in-process layers with no error channel at all.
    // Every one is now guarded, so the correct assertion is that the list is
    // EMPTY - and it stays a tripwire in the other direction: a new detector
    // that ships without an error channel, or a guard someone removes, turns
    // this red rather than passing unnoticed.
    expect(unguardedLayerIds()).toEqual([]);
  });
});

describe('failure-disposition registry: declarations match observed behavior', () => {
  const originalFetch = global.fetch;
  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('customer_hook is declared fail_mode, and behaves that way in both modes', async () => {
    expect(dispositionFor('customer_hook', 'timeout')).toEqual({ disposition: 'fail_mode' });
    expect(dispositionFor('customer_hook', 'error')).toEqual({ disposition: 'fail_mode' });

    init({ api_key: 'test', on_pre_call: () => { throw new Error('boom'); } });
    expect((await applyPreCallPolicy('hello', {
      config: getConfig(), provider: 'openai', operation: 'chat',
    })).decision).toBe('allow');

    _reset();
    init({ api_key: 'test', fail_mode: 'closed', on_pre_call: () => { throw new Error('boom'); } });
    expect((await applyPreCallPolicy('hello', {
      config: getConfig(), provider: 'openai', operation: 'chat',
    })).decision).toBe('block');
  });

  it('customer_hook_post_call is declared open, and a failing hook keeps the rendered decision', async () => {
    // The response-phase hook has its own row because its failure states
    // resolve differently from the request phase: the provider has already
    // answered, so timeout and error leave standing whatever decision the
    // response layers rendered, and fail_mode is not consulted on this path.
    expect(dispositionFor('customer_hook_post_call', 'timeout')).toEqual({ disposition: 'open' });
    expect(dispositionFor('customer_hook_post_call', 'error')).toEqual({ disposition: 'open' });

    const responseBlockRule = {
      id: 'r-resp-block',
      name: 'Block leaked codenames',
      enabled: true,
      action: 'block' as const,
      type: 'keyword' as const,
      conditions: { keywords: ['aurora'] },
      applies_to: 'response' as const,
    };

    init({
      api_key: 'test',
      policy_rules: [responseBlockRule],
      fail_mode: 'closed',
      on_post_call: () => { throw new Error('hook exploded'); },
    });
    const errored = await applyPostCallPolicy('the codename is aurora', {}, getConfig());
    expect(errored.decision).toBe('redact_response');

    _reset();
    init({
      api_key: 'test',
      policy_rules: [responseBlockRule],
      fail_mode: 'closed',
      post_call_timeout_ms: 50,
      on_post_call: () => new Promise((resolve) => setTimeout(() => resolve({ decision: 'flag' }), 1000)),
    });
    const timedOut = await applyPostCallPolicy('the codename is aurora', {}, getConfig());
    expect(timedOut.decision).toBe('redact_response');

    _reset();
    init({
      api_key: 'test',
      fail_mode: 'closed',
      on_post_call: () => { throw new Error('hook exploded'); },
    });
    const clean = await applyPostCallPolicy('a clean answer', {}, getConfig());
    expect(clean.decision).toBe('pass');
  });

  it('external_backend is declared closed with a shadow exemption, and behaves that way', async () => {
    expect(dispositionFor('external_backend', 'error')).toEqual({
      disposition: 'closed',
      qualifier: 'shadow_exempt',
    });

    const failingFetch = (async () => { throw new Error('ECONNREFUSED'); }) as unknown as typeof fetch;

    global.fetch = failingFetch;
    init({ api_key: 't', external_policy_backend: { type: 'opa', url: 'https://8.8.8.8/v1/data/obsvr/allow' } });
    expect((await applyPreCallPolicy('hello world', {
      config: getConfig(), provider: 'openai', operation: 'chat.completions.create',
    })).decision).toBe('block');

    _reset();
    global.fetch = failingFetch;
    init({
      api_key: 't',
      external_policy_backend: { type: 'opa', url: 'https://8.8.8.8/v1/data/obsvr/allow', shadow: true },
    });
    expect((await applyPreCallPolicy('hello world', {
      config: getConfig(), provider: 'openai', operation: 'chat.completions.create',
    })).decision).toBe('allow');
  });

  it('enforcement_integrity_gate is declared closed when degraded, and blocks when degraded', async () => {
    expect(dispositionFor('enforcement_integrity_gate', 'degraded')).toEqual({ disposition: 'closed' });

    init({ api_key: 'test' });
    _getPolicySyncState().remoteDisabled = true;
    try {
      expect((await applyPreCallPolicy('hello', {
        config: getConfig(), provider: 'openai', operation: 'chat',
      })).decision).toBe('block');
    } finally {
      _getPolicySyncState().remoteDisabled = false;
    }
  });

});
