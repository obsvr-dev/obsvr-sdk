import { init, _reset } from '../../src/proxy/config';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { obsvrGovernTool } from '../../src/integrations/tools';

/**
 * Idempotence of the generic tool governor: governing twice yields ONE gate.
 *
 * The governed proxy answers a marker symbol from its get trap, and
 * obsvrGovernTool returns an already-marked object unchanged. Without the
 * marker a second wrap re-gates the first proxy's gated function, so one
 * invocation is evaluated and audited twice — how a step budget silently
 * drifts. The marker is served by the trap only: it is never written onto
 * the caller's original object, and a tool whose shape resolved no execute
 * key comes back unchanged and unmarked so a later legitimate attempt still
 * runs.
 */

let sentEvents: any[] = [];

beforeEach(() => {
  _reset();
  _resetSender();
  sentEvents = [];
  (global as any).fetch = async (_url: any, opts: any) => {
    const body = JSON.parse(opts.body);
    Array.isArray(body) ? sentEvents.push(...body) : sentEvents.push(body);
    return { ok: true, status: 200, json: async () => ({}) };
  };
});

afterEach(() => {
  delete (global as any).fetch;
  _reset();
  _resetSender();
});

const waitForSettle = async () => {
  for (let i = 0; i < 40; i++) {
    await new Promise((r) => setTimeout(r, 5));
  }
};

describe('obsvrGovernTool idempotence', () => {
  it('governing twice audits exactly once per invocation', async () => {
    init({ api_key: 'k', ingest_url: 'https://x' });
    let bodyRuns = 0;
    const tool = {
      name: 'calculator',
      execute: async (_input: unknown) => {
        bodyRuns += 1;
        return 'ok';
      },
    };

    const governedOnce = obsvrGovernTool(tool);
    const governedTwice = obsvrGovernTool(governedOnce);
    expect(governedTwice).toBe(governedOnce);

    await (governedTwice as any).execute({ a: 1 });
    await waitForSettle();

    expect(bodyRuns).toBe(1);
    const calls = sentEvents.filter((e) => e.operation === 'tool.call');
    expect(calls.length).toBe(1);
  });

  it('never writes the marker onto the caller\'s original object', () => {
    init({ api_key: 'k', ingest_url: 'https://x' });
    const tool = { name: 'calculator', execute: async () => 'ok' };
    const before = Object.getOwnPropertySymbols(tool).length;

    obsvrGovernTool(tool);

    expect(Object.getOwnPropertySymbols(tool).length).toBe(before);
    // The ORIGINAL is not the governed proxy, so a fresh wrap of it must
    // still be possible (two proxies over one target is the caller's choice;
    // a marker leaked onto the target would silently forbid it).
    const again = obsvrGovernTool(tool);
    expect(again).not.toBe(tool);
  });

  it('a tool where nothing was gateable is not marked, so a later attempt still runs', async () => {
    init({
      api_key: 'k',
      ingest_url: 'https://x',
      agent_policy: { deniedTools: ['locked_tool'] },
    });
    const tool: Record<string, unknown> = { name: 'locked_tool' };

    const ungoverned = obsvrGovernTool(tool);
    expect(ungoverned).toBe(tool);
    expect((tool as any)[Symbol.for('obsvr.governedTool')]).toBeUndefined();

    // The shape becomes gateable — a legitimate re-attempt must install a
    // real gate, not be refused by a stale claim.
    tool.execute = async () => {
      throw new Error('body must not run');
    };
    const governed = obsvrGovernTool(tool);
    expect(governed).not.toBe(tool);
    // The refusal precedes the body, so it reaches the caller as a rejection
    // rather than the tool's own error — the body never runs either way.
    await expect((governed as any).execute({})).rejects.toThrow(/blocked by agent policy/);
  });

  it('mutation-check: a marker claimed without an installed gate disables governance', async () => {
    // The mutant this guard must not become: marking the object even when
    // nothing was gateable. Simulate it and require the later-attempt proof
    // above to break — pinning that the guard's condition is load-bearing.
    init({
      api_key: 'k',
      ingest_url: 'https://x',
      agent_policy: { deniedTools: ['locked_tool'] },
    });
    const tool: Record<PropertyKey, unknown> = { name: 'locked_tool' };
    obsvrGovernTool(tool);
    // the mutant's behaviour, applied by hand:
    tool[Symbol.for('obsvr.governedTool')] = true;

    tool.execute = async () => 'ran anyway';
    const governed = obsvrGovernTool(tool);
    // The stale claim makes the governor hand the tool back ungated…
    expect(governed).toBe(tool);
    // …and the denied tool's body runs: the exact failure the real
    // marker-only-on-install rule exists to prevent.
    await expect((governed as any).execute({})).resolves.toBe('ran anyway');
  });
});
