import { integrationBindings, _resetBindings } from '../../src/binding-report.js';
import { governFn } from '../../src/governance/govern-fn.js';
import { init, _reset } from '../../src/proxy/config.js';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget.js';
import { ObsvrPolicyError } from '../../src/policy/policy-error.js';

beforeEach(() => {
  _reset();
  _resetSender();
  _resetBindings();
});

describe('governFn', () => {
  test('denies before entering the application function', async () => {
    init({ api_key: 'test', sample_rate: 1, agent_policy: { deniedTools: ['contract.send'] } });
    let calls = 0;
    const send = governFn((contract: string) => {
      calls += 1;
      return contract;
    }, { name: 'contract.send', consequence: 'external_write' });

    await expect(send('nda')).rejects.toThrow('Tool blocked');
    expect(calls).toBe(0);
  });

  test('applies redaction to the arguments the function receives', async () => {
    init({ api_key: 'test', sample_rate: 1, pii_policy: { rules: { ssn: 'redact' } } });
    let received = '';
    const store = governFn((value: string) => {
      received = value;
      return value;
    }, { name: 'customer.store' });

    const result = await store('SSN 078-05-1120');
    expect(received).not.toContain('078-05-1120');
    expect(result).toBe(received);
  });

  test('steers with corrective context before entering the application function', async () => {
    init({
      api_key: 'test',
      sample_rate: 1,
      policy_rules: [{
        id: 'control:external-write',
        name: 'External writes require review',
        enabled: true,
        type: 'control',
        action: 'steer',
        conditions: {
          expression: {
            predicate: {
              path: 'context.metadata.obsvr_action.name',
              operator: 'equals',
              value: 'contract.send',
            },
          },
          steering_context: 'Route the contract to Legal, then retry.',
        },
      }],
    });
    let calls = 0;
    const send = governFn(() => { calls += 1; return 'sent'; }, { name: 'contract.send' });

    const error = await send().catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(ObsvrPolicyError);
    expect((error as ObsvrPolicyError).steering).toEqual({
      outcome: 'MODIFY',
      guidance: 'Route the contract to Legal, then retry.',
    });
    expect((error as ObsvrPolicyError).toJSON().steering).toEqual((error as ObsvrPolicyError).steering);
    expect(calls).toBe(0);
  });

  test('supports async functions and records an honest coverage binding', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const lookup = governFn(async (value: number) => value + 1, {
      name: 'record.lookup',
      surface: 'workflow',
    });

    await expect(lookup(3)).resolves.toBe(4);
    expect(integrationBindings().govern_fn['record.lookup']).toMatchObject({
      bound: true,
      enforcementDepth: 'enforce',
      exclusions: ['calls through retained raw function aliases'],
    });
  });

  test('is idempotent and rejects unstable anonymous names', () => {
    const named = governFn(function calculate() { return 1; });
    expect(governFn(named)).toBe(named);
    expect(() => governFn((() => 1) as (() => number), { name: ' ' })).toThrow(
      'name must be a nonblank string',
    );
  });
});
