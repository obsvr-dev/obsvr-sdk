import { evaluate } from '../../src/governance/evaluate';
import { ReasonCode } from '../../src/governance/reason-codes';
import { applyPreCallPolicy } from '../../src/integrations/core';
import { obsvrGovernTool } from '../../src/integrations/tools';
import { init, _reset, getConfig, _getPolicySyncState } from '../../src/proxy/config';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { useSubject } from '../../src/proxy/subject';

/**
 * Fail closed on a missing principal (opt-in). Twin:
 * sdk-python/tests/test_require_principal.py.
 *
 * `requirePrincipal: true` refuses a governed call whose enforcing channel
 * carries no user_id at all, with PRINCIPAL_REQUIRED, before any scanning
 * layer runs. Empty and whitespace-only strings are unattributed. The
 * enforcement-integrity gate still wins outright, and monitor
 * mode converts the refusal like any non-integrity block.
 */

beforeEach(() => {
  _reset();
  _resetSender();
  (global as any).fetch = async () => ({ ok: true, status: 200, json: async () => ({}) });
});

afterEach(() => {
  _getPolicySyncState().remoteDisabled = false;
  delete (global as any).fetch;
  _reset();
  _resetSender();
});

describe('integration pre-call pipeline', () => {
  it('refuses an unattributed call with PRINCIPAL_REQUIRED', async () => {
    init({ api_key: 'k', require_principal: true } as never);
    const result = await applyPreCallPolicy('hello', {
      config: getConfig(),
      provider: 'bedrock',
      operation: 'test',
    });
    expect(result.compliance.action_taken).toBe('blocked');
    expect(result.compliance.reason_code).toBe(ReasonCode.PRINCIPAL_REQUIRED);
    expect(result.compliance.rule_id).toBe('sdk:principal_required');
  });

  it('passes an explicit ctx identity', async () => {
    init({ api_key: 'k', require_principal: true } as never);
    const result = await applyPreCallPolicy('hello', {
      config: getConfig(),
      provider: 'bedrock',
      operation: 'test',
      userId: 'alice',
    });
    expect(result.compliance.action_taken).toBe('allowed');
  });

  it.each(['', '   '])('refuses a blank principal (%j)', async (userId) => {
    init({ api_key: 'k', require_principal: true } as never);
    const result = await applyPreCallPolicy('hello', {
      config: getConfig(),
      provider: 'bedrock',
      operation: 'test',
      metadata: { user_id: userId },
    });
    expect(result.compliance.action_taken).toBe('blocked');
    expect(result.compliance.reason_code).toBe(ReasonCode.PRINCIPAL_REQUIRED);
  });

  it('resolves the ambient useSubject() identity', async () => {
    init({ api_key: 'k', require_principal: true } as never);
    const result = await useSubject('user:carol', () =>
      applyPreCallPolicy('hello', {
        config: getConfig(),
        provider: 'bedrock',
        operation: 'test',
      }),
    );
    expect(result.compliance.action_taken).toBe('allowed');
  });

  it('never counts an unreadable metadata principal as attributed', async () => {
    // A metadata object whose property getter throws: the gate reads it
    // defensively (never escaping to the caller) and treats it as absent.
    // The same unreadable object then fails the taint-key derivation inside
    // the guarded detector section, whose failMode disposition resolves the
    // whole call — the guard's own contract, identical in both SDKs and
    // pinned for the flag-off case by the detector-guard suite. Under
    // failMode closed the refusal therefore holds end to end.
    init({ api_key: 'k', require_principal: true, fail_mode: 'closed' } as never);
    const hostile = Object.defineProperty({}, 'user_id', {
      get() {
        throw new Error('detector bug');
      },
      enumerable: true,
      configurable: true,
    });
    const result = await applyPreCallPolicy('hello', {
      config: getConfig(),
      provider: 'bedrock',
      operation: 'test',
      metadata: hostile as never,
    });
    expect(result.decision).toBe('block');
  });

  it('lets the enforcement-integrity gate verdict win outright', async () => {
    init({ api_key: 'k', require_principal: true } as never);
    _getPolicySyncState().remoteDisabled = true;
    const result = await applyPreCallPolicy('hello', {
      config: getConfig(),
      provider: 'bedrock',
      operation: 'test',
    });
    expect(result.compliance.action_taken).toBe('blocked');
    expect(result.compliance.rule_id).toBe('sdk:project_paused_or_key_revoked');
    expect(result.compliance.reason_code).not.toBe(ReasonCode.PRINCIPAL_REQUIRED);
  });
});

describe('governance evaluate() surface', () => {
  it('refuses unattributed and blank evaluations', async () => {
    init({ api_key: 'k', require_principal: true } as never);
    const refused = await evaluate({ action_type: 'test', payload: { data: 'hi' } });
    expect(refused.decision).toBe('BLOCKED');
    expect(refused.reason_code).toBe(ReasonCode.PRINCIPAL_REQUIRED);
    expect(refused.rule_id).toBe('sdk:principal_required');

    const empty = await evaluate({
      action_type: 'test',
      payload: { data: 'hi' },
      user_id: '',
    });
    expect(empty.decision).toBe('BLOCKED');
    const whitespace = await evaluate({
      action_type: 'test',
      payload: { data: 'hi' },
      user_id: '   ',
    });
    expect(whitespace.decision).toBe('BLOCKED');
  });

  it('converts the refusal in monitor mode and keeps the classification', async () => {
    init({ api_key: 'k', require_principal: true, enforcement_mode: 'monitor' } as never);
    const result = await evaluate({ action_type: 'test', payload: { data: 'hi' } });
    expect(result.decision).toBe('PERMITTED');
    expect(result.reason_code).toBe(ReasonCode.PRINCIPAL_REQUIRED);
  });
});

describe('generic tool governor', () => {
  it('refuses an unattributed tool call and passes an attributed one', async () => {
    init({ api_key: 'k', require_principal: true } as never);
    let bodyRuns = 0;
    const tool = {
      name: 'calculator',
      execute: async (_input: unknown) => {
        bodyRuns += 1;
        return 'ok';
      },
    };

    const anonymous = obsvrGovernTool(tool) as typeof tool;
    // The refusal is thrown synchronously from the gate, before the tool's
    // async body is entered — same shape as the deny-list refusal.
    await expect(anonymous.execute('2+2')).rejects.toThrow(/principal/i);
    expect(bodyRuns).toBe(0);

    const attributed = obsvrGovernTool(tool, { user_id: 'alice' }) as typeof tool;
    await expect(attributed.execute('2+2')).resolves.toBe('ok');
    expect(bodyRuns).toBe(1);
  });
});

describe('config surface', () => {
  it('defaults to off', () => {
    init({ api_key: 'k' } as never);
    expect(getConfig().requirePrincipal).toBe(false);
  });

  it('refuses a non-boolean flag at init', () => {
    expect(() => init({ api_key: 'k', require_principal: 'yes' } as never)).toThrow(
      /requirePrincipal/,
    );
  });
});
