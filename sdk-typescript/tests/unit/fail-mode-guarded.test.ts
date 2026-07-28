/**
 * Proof that the guard is real, injected the hard way.
 *
 * This file used to prove the opposite. The registry once declared that
 * several in-process detectors had no error channel - an exception inside one
 * propagated out to the host application rather than resolving to allow or
 * block - and that claim was uncomfortable enough to deserve a test rather
 * than a comment. The note on it said that if someone later wrapped the
 * pipeline in a guard, this file would fail and tell them the table now lies.
 * That is exactly what happened, so the assertions are inverted rather than
 * deleted: the same injected defect must now resolve instead of escaping.
 *
 * It keeps its own file because injecting into `runBuiltinPiiScan` needs
 * module mocking, which under the ESM runner requires registering the mock
 * before the module under test is imported. Every other detector-guard test
 * injects a REAL defect through caller-supplied data instead; this one covers
 * the case those vectors cannot reach - a fault inside the scanner itself.
 * The Python twin asserts the same property directly
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
const { getDetectorErrorCount, _resetDetectorErrors } = await import(
  '../../src/policy/detector-guard'
);

const realError = console.error;

describe('a detector defect resolves instead of reaching the caller', () => {
  beforeEach(() => {
    _reset();
    _resetDetectorErrors();
    console.error = () => {}; // the guard logs loudly by design
  });

  afterEach(() => {
    console.error = realError;
  });

  it('is what the registry declares for the builtin PII scan', () => {
    expect(dispositionFor('builtin_pii_scan', 'error')).toEqual({
      disposition: 'fail_mode',
      qualifier: 'redaction_application_closed',
    });
  });

  it('resolves open by default, and the caller still gets an answer', async () => {
    init({ api_key: 'test', pii_policy: { default: 'block' } });

    const result = await applyPreCallPolicy('hello a@b.com', {
      config: getConfig(),
      provider: 'openai',
      operation: 'chat',
    });

    expect(result.decision).toBe('allow');
    expect(result.compliance.rule_id).toBe('sdk:detector_error');
    expect(getDetectorErrorCount()).toBe(1);
  });

  it('resolves closed when the operator opted in', async () => {
    init({ api_key: 'test', fail_mode: 'closed', pii_policy: { default: 'block' } });

    const result = await applyPreCallPolicy('hello a@b.com', {
      config: getConfig(),
      provider: 'openai',
      operation: 'chat',
    });

    expect(result.decision).toBe('block');
  });
});
