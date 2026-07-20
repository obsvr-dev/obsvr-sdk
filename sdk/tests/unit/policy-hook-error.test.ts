import { init, _reset, getConfig } from '../../src/proxy/config';
import { applyPreCallPolicy } from '../../src/integrations/core';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';

beforeEach(() => { _reset(); _resetSender(); });

describe('hook error', () => {
  it('returns hook_error action when hook throws', async () => {
    init({
      api_key: 'test',
      on_pre_call: () => { throw new Error('hook failed'); },
    });
    const result = await applyPreCallPolicy('hello', {
      config: getConfig(),
      provider: 'openai',
      operation: 'chat',
    });
    expect(result.compliance.action_taken).toBe('hook_error');
    expect(result.decision).toBe('allow');
  });

  it('preserves a builtin PII block when the hook throws in fail-open', async () => {
    init({
      api_key: 'test',
      pii_policy: {}, // ssn defaults to block
      on_pre_call: () => { throw new Error('hook failed'); },
      // failMode defaults to "open"
    });
    const result = await applyPreCallPolicy('my ssn is 123-45-6789', {
      config: getConfig(),
      provider: 'openai',
      operation: 'chat',
    });
    // A broken hook must NOT un-block a builtin PII block (fail-open applies to
    // the hook's own verdict, not to overriding other enforcement).
    expect(result.decision).toBe('block');
    expect(result.compliance.action_taken).toBe('blocked');
  });
});
