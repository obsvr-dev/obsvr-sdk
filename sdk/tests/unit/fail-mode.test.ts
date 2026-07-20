/**
 * Security regression tests: failMode ('open' | 'closed') enforcement.
 *
 * fail_open (default): hook timeout/error → allow (audit-friendly).
 * fail_closed: hook timeout/error → block (a policy engine that cannot
 * render a verdict must not be treated as approval).
 */
import { init, _reset, getConfig } from '../../src/proxy/config';
import { applyPreCallPolicy } from '../../src/integrations/core';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';

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
