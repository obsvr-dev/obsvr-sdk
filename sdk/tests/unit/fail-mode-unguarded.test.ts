/**
 * Proof for the `unguarded` disposition.
 *
 * The failure-disposition registry declares that several in-process detectors
 * have no error channel: an unexpected exception inside them propagates out to
 * the host application rather than resolving to allow or block. That claim is
 * the uncomfortable one in the table, so it gets a test rather than a comment.
 * If someone later wraps the pipeline in a guard - which would be an
 * improvement - this fails and tells them the table now lies.
 *
 * It lives in its own file because proving it needs module mocking, which under
 * the ESM runner requires registering the mock before the module under test is
 * imported. The Python twin asserts the same property directly
 * (sdk-python/tests/test_fail_mode.py).
 */
import { jest } from '@jest/globals';

const hookPath = '../../src/policy/hook';

const actualHook = await import(hookPath);

jest.unstable_mockModule(hookPath, () => ({
  ...actualHook,
  runBuiltinPiiScan: () => {
    throw new Error('detector bug');
  },
}));

const { init, _reset, getConfig } = await import('../../src/proxy/config');
const { applyPreCallPolicy } = await import('../../src/integrations/core');
const { dispositionFor } = await import('../../src/policy/failure-dispositions');

describe('unguarded layers: the exception reaches the caller', () => {
  beforeEach(() => {
    _reset();
  });

  it('is what the registry declares for the builtin PII scan', () => {
    expect(dispositionFor('builtin_pii_scan', 'error')).toEqual({ disposition: 'unguarded' });
  });

  it('propagates a detector exception to the host instead of deciding', async () => {
    init({ api_key: 'test', pii_policy: { default: 'block' } });

    await expect(
      applyPreCallPolicy('hello a@b.com', {
        config: getConfig(),
        provider: 'openai',
        operation: 'chat',
      }),
    ).rejects.toThrow('detector bug');
  });
});
