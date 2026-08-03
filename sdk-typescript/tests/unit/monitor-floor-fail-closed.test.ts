/**
 * A floor that COULD NOT RUN blocks under monitor mode, not converts.
 *
 * Monitor mode converts would-be VERDICTS into allows and records them on
 * shadow_outcome. "The floor said block" is a verdict; "the floor crashed and
 * could not be evaluated" is not — converting the latter would ship a call
 * that nothing evaluated, un-blocking exactly the fail-closed guarantee
 * SECURITY.md gives the floor class in every mode.
 *
 * The Python pipeline resolves a detector crash by returning before its
 * monitor-conversion point, so a crashed floor blocks there regardless. This
 * wrapper's catch continues past its conversion point, so the carve-out is an
 * explicit `detectorFailedClosed` flag; this file is the regression that keeps
 * it. It needs its own file because forcing the floor evaluator to throw is a
 * module-level mock. Twin: sdk-python/tests/test_monitor_mode.py
 * (TestFloorUnderMonitor.test_a_crashed_floor_still_blocks_under_monitor).
 */
import { jest } from '@jest/globals';

// The wrapper imports `../policy/rules.js` WITH the extension, so the mock
// path must carry it too or jest treats them as different module ids and the
// wrapper keeps the real evaluateFloor.
const rulesPath = '../../src/policy/rules.js';
const actualRules = (await import(rulesPath)) as Record<string, unknown>;

jest.unstable_mockModule(rulesPath, () => ({
  ...actualRules,
  evaluateFloor: () => {
    throw new Error('floor exploded');
  },
}));

// Import WITH the .js extension so these modules share the graph the mock
// above was registered against; a no-extension import resolves to a separate
// module instance that keeps the real evaluateFloor.
const { init, _reset } = await import('../../src/proxy/config.js');
const { wrap } = await import('../../src/proxy/wrapper.js');
const { _resetSender } = await import('../../src/proxy/sender/fire-and-forget.js');
const { _resetDetectorErrors } = await import('../../src/policy/detector-guard.js');

const realError = console.error;
let sentEvents: any[] = [];

beforeEach(() => {
  _reset();
  _resetSender();
  _resetDetectorErrors();
  sentEvents = [];
  console.error = () => {}; // the detector guard logs loudly by design
  (global as any).fetch = async (_url: any, opts: any) => {
    try {
      const body = JSON.parse(opts?.body ?? 'null');
      if (Array.isArray(body)) sentEvents.push(...body);
      else if (body) sentEvents.push(body);
    } catch {
      /* not an event body */
    }
    return { ok: true, status: 200, json: async () => ({}) };
  };
});

afterEach(() => {
  console.error = realError;
  delete (global as any).fetch;
  _reset();
  _resetSender();
});

const fakeClient = () => ({
  chat: {
    completions: {
      create: async (_args: any) => ({ id: 'x', choices: [{ message: { content: 'Hello!' } }] }),
    },
  },
});

const waitForEvents = async (n: number) => {
  for (let i = 0; i < 200 && sentEvents.length < n; i++) {
    await new Promise((r) => setTimeout(r, 5));
  }
};

describe('monitor mode does not convert a crashed floor', () => {
  it('a floor that could not run blocks the call, monitor or not', async () => {
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
    } as never);
    const wrapped = wrap(fakeClient());

    await expect(
      wrapped.chat.completions.create({
        model: 'gpt-4',
        messages: [{ role: 'user', content: 'anything at all' }],
      }),
    ).rejects.toThrow();

    await waitForEvents(1);
    const blocked = sentEvents.find((e) => e.action_taken === 'blocked');
    expect(blocked).toBeDefined();
    expect(blocked.rule_id).toBe('sdk:detector_error');
    // The fail-closed block was NOT converted: no shadow_outcome, real block.
    expect(blocked.shadow_outcome).toBeUndefined();
  });
});
