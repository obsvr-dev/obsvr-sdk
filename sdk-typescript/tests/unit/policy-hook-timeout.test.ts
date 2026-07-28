import { init, _reset, getConfig } from '../../src/proxy/config';
import { applyPreCallPolicy } from '../../src/integrations/core';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';

beforeEach(() => { _reset(); _resetSender(); });

describe('hook timeout', () => {
  it('returns hook_timeout action when hook never resolves', async () => {
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
    expect(result.compliance.action_taken).toBe('hook_timeout');
    expect(result.decision).toBe('allow');
  });
});
