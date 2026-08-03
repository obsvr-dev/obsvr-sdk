import { applyPreCallPolicy } from '../../src/integrations/core';
import { ReasonCode } from '../../src/governance/reason-codes';
import { updateApprovals } from '../../src/policy/approvals';
import { init, _reset, getConfig, _getPolicySyncState } from '../../src/proxy/config';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { wrap } from '../../src/proxy/wrapper';
import type { PolicyRule } from '../../src/policy/rules';

/**
 * Monitor mode and the blocking approval wait on the proxy wrapper and the
 * integrations pipeline — the two pre-call paths that do not route through
 * governance evaluate(), wired to the same conversion carve-out
 * (monitorConversionApplies) and the same awaitApproval primitive. Twin
 * behaviour: sdk-python/tests/test_monitor_mode.py and
 * test_approval_blocking.py, which drive the one shared Python pipeline.
 */

const RULE_KEY: PolicyRule = {
  id: 'r-key',
  name: 'no forbidden topics',
  enabled: true,
  action: 'block',
  type: 'keyword',
  conditions: { keywords: ['forbidden'] },
};

const RULE_APPROVAL: PolicyRule = {
  id: 'r-app',
  name: 'needs a human',
  enabled: true,
  action: 'block',
  type: 'keyword',
  conditions: { keywords: ['restricted'], require_approval: true },
};

let sentEvents: any[] = [];

beforeEach(() => {
  _reset();
  _resetSender();
  updateApprovals([]);
  sentEvents = [];
  (global as any).fetch = async (_url: any, opts: any) => {
    try {
      const body = JSON.parse(opts?.body ?? 'null');
      if (Array.isArray(body)) sentEvents.push(...body);
      else if (body) sentEvents.push(body);
    } catch {
      /* not an event body (policy poll) */
    }
    return { ok: true, status: 200, json: async () => ({}) };
  };
});

afterEach(() => {
  _getPolicySyncState().remoteDisabled = false;
  updateApprovals([]);
  delete (global as any).fetch;
  _reset();
  _resetSender();
});

const waitForEvents = async (n: number) => {
  for (let i = 0; i < 200 && sentEvents.length < n; i++) {
    await new Promise((r) => setTimeout(r, 5));
  }
};

const grantFor = (ruleId: string) => ({
  id: 'g-1',
  rule_id: ruleId,
  expires_at: '2999-01-01T00:00:00Z',
});

const fakeClient = () => ({
  chat: {
    completions: {
      create: async (_args: any) => ({
        id: 'chatcmpl-1',
        choices: [{ message: { content: 'Hello!' } }],
      }),
    },
  },
});

describe('integrations pipeline: monitor mode', () => {
  it('converts the block and carries the enforcing classification on shadow_outcome', async () => {
    // Control: the enforcing verdict for this exact call.
    init({ api_key: 'k', policy_rules: [RULE_KEY] } as never);
    const control = await applyPreCallPolicy('a forbidden request', {
      config: getConfig(),
      provider: 'bedrock',
      operation: 'test',
    });
    expect(control.compliance.action_taken).toBe('blocked');

    _reset();
    _resetSender();
    init({ api_key: 'k', policy_rules: [RULE_KEY], enforcement_mode: 'monitor' } as never);
    const result = await applyPreCallPolicy('a forbidden request', {
      config: getConfig(),
      provider: 'bedrock',
      operation: 'test',
    });

    expect(result.decision).toBe('allow');
    expect(result.compliance.action_taken).toBe('allowed');
    expect(result.compliance.event_type).toBe('llm_call');
    const shadow = result.compliance.shadow_outcome;
    expect(shadow?.would).toBe('block');
    expect(shadow?.rule_id).toBe(control.compliance.rule_id);
    expect(shadow?.reason_code).toBe(control.compliance.reason_code);
  });

  it('does not disarm the enforcement-integrity gate', async () => {
    init({ api_key: 'k', policy_rules: [RULE_KEY], enforcement_mode: 'monitor' } as never);
    _getPolicySyncState().remoteDisabled = true;
    const result = await applyPreCallPolicy('anything at all', {
      config: getConfig(),
      provider: 'bedrock',
      operation: 'test',
    });
    expect(result.decision).toBe('block');
    expect(result.compliance.rule_id).toBe('sdk:project_paused_or_key_revoked');
  });
});

describe('integrations pipeline: blocking approval wait', () => {
  it('holds the call and proceeds when the grant lands mid-wait', async () => {
    init({
      api_key: 'k',
      policy_rules: [RULE_APPROVAL],
      approval_wait_ms: 2000,
      approval_poll_ms: 20,
    } as never);
    const timer = setTimeout(() => updateApprovals([grantFor('r-app')]), 60);
    try {
      const result = await applyPreCallPolicy('a restricted request', {
        config: getConfig(),
        provider: 'bedrock',
        operation: 'test',
      });
      expect(result.decision).toBe('allow');
      expect(result.compliance.reason_code).toBe(ReasonCode.APPROVAL_GRANTED);
      expect(result.compliance.policy_reason).toContain('approval_granted_after_wait');
    } finally {
      clearTimeout(timer);
    }
  });

  it('stamps APPROVAL_TIMEOUT when the hold expires with no grant', async () => {
    init({
      api_key: 'k',
      policy_rules: [RULE_APPROVAL],
      approval_wait_ms: 80,
      approval_poll_ms: 20,
    } as never);
    const result = await applyPreCallPolicy('a restricted request', {
      config: getConfig(),
      provider: 'bedrock',
      operation: 'test',
    });
    expect(result.decision).toBe('block');
    expect(result.compliance.reason_code).toBe(ReasonCode.APPROVAL_TIMEOUT);
    expect(result.compliance.policy_reason).toContain('approval_wait_timeout');
    // The record asserts only what is true in both worlds: the grant channel
    // carries no verdicts, so an explicit denial surfaces exactly like no
    // decision — and the record SAYS so instead of claiming nobody answered
    // (SECURITY.md, "The approval-status contract").
    expect(result.compliance.policy_reason).toContain(
      'denial and no-decision are indistinguishable',
    );
  });

  it('keeps the fire-and-forget refusal at the default of zero', async () => {
    init({ api_key: 'k', policy_rules: [RULE_APPROVAL] } as never);
    const result = await applyPreCallPolicy('a restricted request', {
      config: getConfig(),
      provider: 'bedrock',
      operation: 'test',
    });
    expect(result.decision).toBe('block');
    expect(result.compliance.reason_code).toBe(ReasonCode.APPROVAL_REQUIRED);
  });
});

describe('proxy wrapper: monitor mode', () => {
  it('lets the call proceed and emits the would-be verdict even at sample_rate 0', async () => {
    // sample_rate 0 pins the sampling exemption: a monitor-converted event
    // is enforcement evidence, not a plain allowed call.
    init({
      api_key: 'k',
      ingest_url: 'https://x',
      policy_rules: [RULE_KEY],
      enforcement_mode: 'monitor',
      sample_rate: 0,
    } as never);
    const wrapped = wrap(fakeClient());

    const response = await wrapped.chat.completions.create({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'a forbidden request' }],
    });
    expect(response.choices[0].message.content).toBe('Hello!');

    await waitForEvents(1);
    const event = sentEvents.find((e) => e.shadow_outcome);
    expect(event).toBeDefined();
    expect(event.action_taken).toBe('allowed');
    expect(event.shadow_outcome.would).toBe('block');
    expect(event.shadow_outcome.rule_id).toBe('r-key');
    expect(event.shadow_outcome.reason_code).toBe(ReasonCode.KEYWORD_BLOCKED);
  });

  it('converts a floor VERDICT but keeps the would-be block on shadow_outcome', async () => {
    // A floor that evaluated and said block is a would-be verdict; recording
    // would-be verdicts without enforcing them is monitor mode's job, and the
    // operator's own enforcement_mode flip is not one of the weakening vectors
    // (customer rule, hook, policy sync) the floor is guaranteed against. So
    // the floor VERDICT converts, with the verdict preserved. (A floor that
    // could not RUN is a different case, pinned in monitor-floor-fail-closed.)
    init({
      api_key: 'k',
      ingest_url: 'https://x',
      policyFloor: [
        {
          id: 'floor-secret',
          name: 'no secrets',
          enabled: true,
          action: 'block',
          type: 'keyword',
          conditions: { keywords: ['secret'] },
        },
      ],
      enforcement_mode: 'monitor',
      sample_rate: 0,
    } as never);
    const wrapped = wrap(fakeClient());

    const response = await wrapped.chat.completions.create({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'a secret request' }],
    });
    expect(response.choices[0].message.content).toBe('Hello!');

    await waitForEvents(1);
    const event = sentEvents.find((e) => e.shadow_outcome);
    expect(event).toBeDefined();
    expect(event.action_taken).toBe('allowed');
    expect(event.shadow_outcome.would).toBe('block');
    expect(event.shadow_outcome.rule_id).toBe('floor-secret');
  });

  it('does not disarm the enforcement-integrity gate', async () => {
    init({
      api_key: 'k',
      ingest_url: 'https://x',
      policy_rules: [RULE_KEY],
      enforcement_mode: 'monitor',
    } as never);
    _getPolicySyncState().remoteDisabled = true;
    const wrapped = wrap(fakeClient());

    await expect(
      wrapped.chat.completions.create({
        model: 'gpt-4',
        messages: [{ role: 'user', content: 'anything at all' }],
      }),
    ).rejects.toThrow();
  });
});

describe('proxy wrapper: blocking approval wait', () => {
  it('holds the call and proceeds when the grant lands mid-wait', async () => {
    init({
      api_key: 'k',
      ingest_url: 'https://x',
      policy_rules: [RULE_APPROVAL],
      approval_wait_ms: 2000,
      approval_poll_ms: 20,
    } as never);
    const wrapped = wrap(fakeClient());
    const timer = setTimeout(() => updateApprovals([grantFor('r-app')]), 60);
    try {
      const response = await wrapped.chat.completions.create({
        model: 'gpt-4',
        messages: [{ role: 'user', content: 'a restricted request' }],
      });
      expect(response.choices[0].message.content).toBe('Hello!');
    } finally {
      clearTimeout(timer);
    }
  });

  it('stamps APPROVAL_TIMEOUT when the hold expires with no grant', async () => {
    init({
      api_key: 'k',
      ingest_url: 'https://x',
      policy_rules: [RULE_APPROVAL],
      approval_wait_ms: 80,
      approval_poll_ms: 20,
    } as never);
    const wrapped = wrap(fakeClient());

    await expect(
      wrapped.chat.completions.create({
        model: 'gpt-4',
        messages: [{ role: 'user', content: 'a restricted request' }],
      }),
    ).rejects.toThrow();

    await waitForEvents(1);
    const blocked = sentEvents.find((e) => e.action_taken === 'blocked');
    expect(blocked).toBeDefined();
    expect(blocked.reason_code).toBe(ReasonCode.APPROVAL_TIMEOUT);
    expect(blocked.policy_reason).toContain('approval_wait_timeout');
    expect(blocked.policy_reason).toContain(
      'denial and no-decision are indistinguishable',
    );
  });
});
