import { evaluate, evaluateAction } from '../../src/governance/evaluate';
import { ReasonCode } from '../../src/governance/reason-codes';
import { init, _reset, _getPolicySyncState } from '../../src/proxy/config';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import type { PolicyRule } from '../../src/policy/rules';

// Use ObsvrConfig (camelCase) so policyRules is recognized by the config resolver
const BASE_CONFIG = {
  apiKey: 'test-key-governance',
  ingestUrl: 'https://localhost:19999/ingest',
  environment: 'development' as const,
};

beforeEach(() => {
  _reset();
  _resetSender();
});

describe('evaluate()', () => {
  it('returns PERMITTED when no rules match', async () => {
    init({ ...BASE_CONFIG, policyRules: [] });
    const result = await evaluate({
      action_type: 'chat.completions.create',
      payload: { message: 'hello' },
    });
    expect(result.decision).toBe('PERMITTED');
    expect(result.reason_code).toBe(ReasonCode.PERMITTED);
    expect(result.execution_token).toBeTruthy();
    expect(result.timestamp).toBeTruthy();
    expect(result.nonce).toBeTruthy();
  });

  it('returns BLOCKED when keyword rule matches', async () => {
    const rules: PolicyRule[] = [{
      id: 'r1', name: 'block-secret', enabled: true, action: 'block',
      type: 'keyword', conditions: { keywords: ['secret'] },
    }];
    init({ ...BASE_CONFIG, policyRules: rules });
    const result = await evaluate({
      action_type: 'test',
      payload: { data: 'this is secret' },
    });
    expect(result.decision).toBe('BLOCKED');
    expect(result.reason_code).toBe(ReasonCode.KEYWORD_BLOCKED);
    expect(result.rule_id).toBe('r1');
    expect(result.execution_token).toBeUndefined();
  });

  it('returns BLOCKED with PII_DETECTED when PII found and policy blocks', async () => {
    init({
      ...BASE_CONFIG,
      piiPolicy: { default: 'block' },
      policyRules: [],
    });
    const result = await evaluate({
      action_type: 'test',
      payload: { email: 'user@example.com' },
    });
    expect(result.decision).toBe('BLOCKED');
    expect(result.reason_code).toBe(ReasonCode.PII_DETECTED);
  });

  it('execution token is valid JWT', async () => {
    init({ ...BASE_CONFIG, policyRules: [] });
    const result = await evaluate({
      action_type: 'chat',
      payload: { msg: 'hi' },
    });
    expect(result.execution_token).toBeTruthy();
    expect(result.execution_token!.split('.')).toHaveLength(3);
  });

  it('throws when not initialized and no config provided', async () => {
    await expect(evaluate({
      action_type: 'test',
      payload: {},
    })).rejects.toThrow('not initialized');
  });

  it('kill switch (project paused / key revoked) blocks evaluate(), not PERMITTED', async () => {
    init({ ...BASE_CONFIG, policyRules: [] });
    // Simulate a 401/403 from /policies (key revoked or project paused).
    _getPolicySyncState().remoteDisabled = true;
    const result = await evaluate({
      action_type: 'test',
      payload: { msg: 'hello' },
    });
    expect(result.decision).toBe('BLOCKED');
    expect(result.reason_code).toBe(ReasonCode.POLICY_VIOLATION);
    expect(result.rule_id).toBe('sdk:project_paused_or_key_revoked');
    expect(result.reason).toContain('SDK kill switch');
    expect(result.execution_token).toBeUndefined();
  });

  it('kill switch is not customer-overridable: on_pre_call never runs', async () => {
    let hookRan = false;
    init({
      ...BASE_CONFIG,
      policyRules: [],
      onPreCall: () => { hookRan = true; return { decision: 'allow' as const }; },
    });
    _getPolicySyncState().remoteDisabled = true;
    const result = await evaluate({ action_type: 'test', payload: { msg: 'hello' } });
    expect(result.decision).toBe('BLOCKED');
    expect(hookRan).toBe(false);
  });

  it('failMode=closed with stale policy sync blocks evaluate()', async () => {
    init({ ...BASE_CONFIG, policyRules: [], failMode: 'closed' });
    // Polling started long ago and never succeeded: past the staleness budget.
    const sync = _getPolicySyncState();
    sync.startedAt = Date.now() - 10 * 60_000;
    sync.lastSuccessAt = null;
    const result = await evaluate({ action_type: 'test', payload: { msg: 'hello' } });
    expect(result.decision).toBe('BLOCKED');
    expect(result.rule_id).toBe('sdk:policy_sync_never_succeeded');
    expect(result.reason).toContain('failMode=closed');
  });

  it('blocks on regex rule', async () => {
    const rules: PolicyRule[] = [{
      id: 'r2', name: 'block-ssn', enabled: true, action: 'block',
      type: 'regex', conditions: { pattern: '\\d{3}-\\d{2}-\\d{4}' },
    }];
    init({ ...BASE_CONFIG, policyRules: rules });
    const result = await evaluate({
      action_type: 'test',
      payload: { ssn: '123-45-6789' },
    });
    expect(result.decision).toBe('BLOCKED');
    expect(result.reason_code).toBe(ReasonCode.REGEX_MATCHED);
  });
});

describe('evaluateAction()', () => {
  it('works with singleton config', async () => {
    init({ ...BASE_CONFIG, policyRules: [] });
    const result = await evaluateAction('test', { msg: 'hello' });
    expect(result.decision).toBe('PERMITTED');
  });

  it('passes tenant_id and user_id', async () => {
    init({ ...BASE_CONFIG, policyRules: [] });
    const result = await evaluateAction('test', { msg: 'hello' }, {
      tenant_id: 't1',
      user_id: 'u1',
    });
    expect(result.decision).toBe('PERMITTED');
    expect(result.nonce).toBeTruthy();
  });
});
