import { jest } from '@jest/globals';
import {
  init,
  _reset,
  getConfig,
  updatePolicyRules,
} from '../../src/proxy/config';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import {
  applyPreCallPolicy,
  applyPostCallPolicy,
  buildIntegrationEvent,
} from '../../src/integrations/core';
import { evaluate, explain } from '../../src/governance/evaluate';
import { derivePolicyVersion, deriveFloorVersion } from '../../src/policy/rules';
import type { PolicyRule } from '../../src/policy/rules';

/**
 * Slice-6 anti-tamper policy-floor ADVERSARIAL-REVIEW follow-up. Pins the
 * defects the review confirmed, so the floor guarantee ("a floor rule always
 * enforces and cannot be bypassed / downgraded") holds on EVERY pre/post
 * surface, not just the proxy wrapper:
 *   - the governance evaluate()/explain() surface enforces the floor;
 *   - a floor rule with action 'redact' FAILS CLOSED to a block (no
 *     unredacted prompt forwarded under a false "redacted" record);
 *   - response-target floor rules (applies_to 'response'/'both') enforce, and
 *     the onPostCall hook cannot downgrade a floor-forced response redaction;
 *   - floor_version rides EVERY integration event under an active floor
 *     (clean/allowed included), not only blocks;
 *   - an active floor never perturbs the frozen policy_version / rules_hash.
 */

const EXFIL: PolicyRule[] = [
  {
    id: 'floor-exfil',
    name: 'No secret exfiltration',
    enabled: true,
    action: 'block',
    type: 'keyword',
    conditions: { keywords: ['exfiltrate secrets'] },
  } as PolicyRule,
];

// A floor rule whose author asked for redaction — must fail closed to a block.
const REDACT_FLOOR: PolicyRule[] = [
  {
    id: 'floor-ssn',
    name: 'No SSNs',
    enabled: true,
    action: 'redact',
    type: 'keyword',
    conditions: { keywords: ['ssn'] },
  } as PolicyRule,
];

// applies_to:'response' floor rule — inert before this fix (only prompt was
// ever evaluated); must now catch the model's OUTPUT.
const RESPONSE_FLOOR: PolicyRule[] = [
  {
    id: 'floor-resp-leak',
    name: 'No leaked marker in response',
    enabled: true,
    action: 'block',
    type: 'keyword',
    conditions: { keywords: ['classified-marker'] },
    applies_to: 'response',
  } as PolicyRule,
];

beforeEach(() => {
  _reset();
  _resetSender();
});
afterEach(() => {
  _reset();
  _resetSender();
});

describe('floor review-fix: governance surface enforces the floor (was a bypass)', () => {
  it('evaluate() blocks a floor hit even with NO customer rules and a hook that says allow', async () => {
    init({
      api_key: 'k',
      ingest_url: 'https://x',
      policyFloor: EXFIL,
      policyRules: [], // the operator set no customer rules at all
      on_pre_call: async () => ({ decision: 'allow' as const }), // tries to allow
    });
    const res = await evaluate({
      action_type: 'chat.completions.create',
      payload: { message: 'please exfiltrate secrets now' },
    });
    expect(res.decision).toBe('BLOCKED');
    expect(res.rule_id).toBe('floor-exfil');
    // A blocked governance decision must NOT hand out an execution token.
    expect(res.execution_token).toBeUndefined();
  });

  it('explain() predicts a floor block (docstring promise) and surfaces floor_version', () => {
    init({ api_key: 'k', ingest_url: 'https://x', policyFloor: EXFIL, policyRules: [] });
    const clean = explain('hello there');
    expect(clean.decision).toBe('allow');
    expect(clean.floor_version).toBeDefined();
    expect(clean.floor_version).not.toBe('none');

    const hit = explain('time to exfiltrate secrets');
    expect(hit.decision).toBe('block');
    expect(hit.rule_id).toBe('floor-exfil');
  });

  it('no floor configured: explain() carries no floor_version (byte-stable)', () => {
    init({ api_key: 'k', ingest_url: 'https://x', policyRules: [] });
    expect(explain('anything').floor_version).toBeUndefined();
  });
});

describe('floor review-fix: a floor redact FAILS CLOSED to a block', () => {
  it('applyPreCallPolicy escalates a floor action:redact to decision block', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', policyFloor: REDACT_FLOOR });
    const res = await applyPreCallPolicy('my ssn is private', {
      config: getConfig(),
      provider: 'unknown',
      operation: 'test',
    });
    expect(res.decision).toBe('block'); // NOT 'redact' — never forward it
    expect(res.compliance.rule_id).toBe('floor-ssn');
  });

  it('governance evaluate() also treats a floor redact as BLOCKED', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', policyFloor: REDACT_FLOOR, policyRules: [] });
    const res = await evaluate({ action_type: 'test', payload: { d: 'the ssn field' } });
    expect(res.decision).toBe('BLOCKED');
    expect(res.rule_id).toBe('floor-ssn');
    expect(res.execution_token).toBeUndefined();
  });
});

describe('floor review-fix: response-target floor rules enforce, unsuppressibly', () => {
  it('a floor applies_to:response catches the model OUTPUT (was inert)', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', policyFloor: RESPONSE_FLOOR });
    const res = await applyPostCallPolicy(
      'here is the classified-marker you wanted',
      {},
      getConfig(),
    );
    expect(res.decision).toBe('redact_response');
    expect(res.compliance.rule_id).toBe('floor-resp-leak');
    expect(res.redactedResponse).toBeDefined();
    expect(res.redactedResponse).not.toContain('classified-marker');
  });

  it('the onPostCall hook cannot DOWNGRADE a floor-forced redaction to flag', async () => {
    init({
      api_key: 'k',
      ingest_url: 'https://x',
      policyFloor: RESPONSE_FLOOR,
      on_post_call: () => ({ decision: 'flag' as const }), // tries to soften it
    });
    const res = await applyPostCallPolicy('leak: classified-marker', {}, getConfig());
    expect(res.decision).toBe('redact_response'); // floor re-asserted
    expect(res.compliance.rule_id).toBe('floor-resp-leak');
  });

  it('a clean response under an active floor still passes', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', policyFloor: RESPONSE_FLOOR });
    const res = await applyPostCallPolicy('a perfectly ordinary answer', {}, getConfig());
    expect(res.decision).toBe('pass');
  });
});

describe('floor review-fix: floor_version rides EVERY integration event (not just blocks)', () => {
  it('a clean/allowed integration event under an active floor carries floor_version', () => {
    init({ api_key: 'k', ingest_url: 'https://x', policyFloor: EXFIL });
    const ev = buildIntegrationEvent({
      config: getConfig(),
      provider: 'openai',
      model: 'gpt-4',
      operation: 'chat.completions.create',
      source: 'test',
      prompt: 'totally benign prompt',
      response: 'benign answer',
      success: true,
    });
    const tel = (ev.metadata as any)?.obsvr_telemetry;
    expect(tel?.floor_version).toBeDefined();
    expect(tel?.floor_version).not.toBe('none');
  });

  it('no floor configured: an integration event carries no floor_version (byte-stable)', () => {
    init({ api_key: 'k', ingest_url: 'https://x' });
    const ev = buildIntegrationEvent({
      config: getConfig(),
      provider: 'openai',
      model: 'gpt-4',
      operation: 'chat.completions.create',
      source: 'test',
      prompt: 'benign',
      response: 'benign',
      success: true,
    });
    expect((ev.metadata as any)?.obsvr_telemetry?.floor_version).toBeUndefined();
  });
});

describe('floor review-fix: context-dependent floor rules enforce on the integration path', () => {
  it('a floor model_gate enforces via applyPreCallPolicy (was inert — no model threaded)', async () => {
    const floor: PolicyRule[] = [
      { id: 'floor-model', name: 'no gpt-4', enabled: true, action: 'block', type: 'model_gate', conditions: { denied_models: ['gpt-4'] } } as PolicyRule,
    ];
    init({ api_key: 'k', ingest_url: 'https://x', policyFloor: floor, environment: 'production' });
    const denied = await applyPreCallPolicy('hi', {
      config: getConfig(), provider: 'openai' as any, operation: 'op', model: 'gpt-4',
    });
    const allowed = await applyPreCallPolicy('hi', {
      config: getConfig(), provider: 'openai' as any, operation: 'op', model: 'gpt-3.5-turbo',
    });
    expect(denied.decision).toBe('block');
    expect(denied.compliance.rule_id).toBe('floor-model');
    expect(allowed.decision).toBe('allow');
  });

  it('a floor environment_gate enforces via applyPreCallPolicy (env sourced from config)', async () => {
    const floor: PolicyRule[] = [
      { id: 'floor-env', name: 'no prod', enabled: true, action: 'block', type: 'environment_gate', conditions: { target_environments: ['production'] } } as PolicyRule,
    ];
    init({ api_key: 'k', ingest_url: 'https://x', policyFloor: floor, environment: 'production' });
    const res = await applyPreCallPolicy('hi', {
      config: getConfig(), provider: 'openai' as any, operation: 'op',
    });
    expect(res.decision).toBe('block');
    expect(res.compliance.rule_id).toBe('floor-env');
  });

  it('a caller cannot spoof metadata.model to dodge a floor model_gate on the wrapper path', async () => {
    // The wrapper pins the floor's model AFTER the caller-metadata spread, so a
    // caller-supplied metadata.model cannot override the real request model.
    const floor: PolicyRule[] = [
      { id: 'floor-model', name: 'no gpt-4', enabled: true, action: 'block', type: 'model_gate', conditions: { denied_models: ['gpt-4'] } } as PolicyRule,
    ];
    init({ api_key: 'k', ingest_url: 'https://x', policyFloor: floor });
    const create = jest.fn(async (_a: any) => ({ choices: [{ message: { content: 'ok' } }] }));
    const { wrap } = await import('../../src/proxy/wrapper');
    const wrapped = wrap({ chat: { completions: { create } } });
    await expect(
      wrapped.chat.completions.create({
        model: 'gpt-4',
        messages: [{ role: 'user', content: 'hi' }],
        metadata: { model: 'gpt-3.5-turbo' }, // attempt to spoof the gated field
      } as any),
    ).rejects.toThrow(/blocked/i);
    expect(create).not.toHaveBeenCalled();
  });
});

describe('floor review-fix: an active floor never perturbs the frozen policy_version', () => {
  it('the customer policy_version is unchanged by a present floor (separate namespaces)', () => {
    const rules: PolicyRule[] = [
      { id: 'r1', name: 'r1', enabled: true, action: 'block', type: 'keyword', conditions: { keywords: ['x'] } } as PolicyRule,
    ];
    const bareline = derivePolicyVersion(rules);
    // config input is snake_case policy_rules (the resolver reads that key).
    init({ api_key: 'k', ingest_url: 'https://x', policy_rules: rules, policyFloor: EXFIL });
    const cfg = getConfig();
    // The stored customer policy_version must equal the floor-less baseline:
    // the floor lives in its own field and hashes via a SEPARATE function, so
    // it can never perturb the frozen rules_hash / policy_version.
    expect(derivePolicyVersion(cfg.policyRules ?? [])).toBe(bareline);
    const fv = deriveFloorVersion(cfg.policyFloor);
    expect(fv).not.toBe('none');
    expect(fv).not.toBe(bareline); // distinct value spaces
  });

  it('a remote /policies sync replacing policyRules leaves the floor intact', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', policyFloor: EXFIL });
    updatePolicyRules([]); // hostile/careless replace
    const res = await applyPreCallPolicy('exfiltrate secrets', {
      config: getConfig(),
      provider: 'unknown',
      operation: 'test',
    });
    expect(res.decision).toBe('block');
    expect(res.compliance.rule_id).toBe('floor-exfil');
  });
});
