import { init, _reset, getConfig } from '../../src/proxy/config';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { obsvrGovernMCP } from '../../src/integrations/mcp';
import { markTainted, _resetSessionTaint } from '../../src/policy/session-taint';
import { createCapabilityStore } from '../../src/policy/capability-hints';

/**
 * End-to-end: a tool that declares itself destructive in its MCP descriptor
 * joins the destructive-capability set at discovery, with NO operator
 * configuration. Twin: sdk-python/tests/test_capability_hints_wiring.py.
 *
 * The gap this closes is that the capability gate — the strongest control in
 * the SDK — used to require an operator to write a list of tool names, and a
 * deployment that wrote none got no gate at all and no warning about it.
 * The decision table itself is pinned in session_taint.json; what these tests
 * pin is that discovery actually feeds it, and that the hint stays one-way.
 */

let sentEvents: Array<Record<string, unknown>> = [];

beforeEach(() => {
  _reset();
  _resetSender();
  _resetSessionTaint();
  sentEvents = [];
  (global as unknown as { fetch: unknown }).fetch = async (_url: unknown, opts: { body: string }) => {
    const body = JSON.parse(opts.body);
    Array.isArray(body) ? sentEvents.push(...body) : sentEvents.push(body);
    return { ok: true, status: 200, json: async () => ({}) };
  };
});

afterEach(() => {
  delete (global as unknown as { fetch?: unknown }).fetch;
  _reset();
  _resetSender();
  _resetSessionTaint();
});

async function waitForEvents(n = 1): Promise<void> {
  for (let i = 0; i < 400 && sentEvents.length < n; i++) {
    await new Promise((r) => setTimeout(r, 5));
  }
}

const DESTRUCTIVE_TOOL = {
  name: 'delete_row',
  description: 'Removes a row.',
  annotations: { readOnlyHint: false, destructiveHint: true },
};
const SAFE_TOOL = {
  name: 'read_row',
  description: 'Reads a row.',
  annotations: { readOnlyHint: true, destructiveHint: false },
};
const UNANNOTATED_TOOL = { name: 'search', description: 'Searches.' };

function governedClient(calls: unknown[], tools: unknown[]) {
  return obsvrGovernMCP(
    {
      callTool: async (p: unknown) => {
        calls.push(p);
        return 'ok';
      },
      listTools: async () => ({ tools }),
    },
    getConfig(),
  ) as {
    callTool: (p: unknown) => Promise<unknown>;
    listTools: () => Promise<unknown>;
  };
}

describe('destructive-capability hints: discovery feeds the taint gate', () => {
  it('blocks a hinted-destructive tool for a tainted session with NO operator list', async () => {
    init({
      api_key: 'k',
      ingest_url: 'https://x',
      sessionTaint: { enabled: true }, // default flag action, no destructiveTools
    });
    const calls: unknown[] = [];
    const client = governedClient(calls, [DESTRUCTIVE_TOOL, SAFE_TOOL, UNANNOTATED_TOOL]);
    await client.listTools();
    markTainted('global', 'prompt_injection', Date.now());

    await expect(client.callTool({ name: 'delete_row', arguments: {} })).rejects.toThrow(
      /blocked/i,
    );
    expect(calls).toEqual([]); // the side effect never ran

    await waitForEvents(2);
    const blocked = sentEvents.find((e) => e.event_type === 'blocked_call');
    expect(blocked).toBeDefined();
    // The record says WHICH source put the tool in the set: an operator who
    // configured nothing needs to be able to tell where the block came from.
    expect(blocked?.policy_reason).toContain('tool descriptor hint');
    expect(blocked?.rule_id).toBe('sdk:session_tainted');
  });

  it('a tool whose descriptor claims it is harmless is still only flagged, not blocked', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', sessionTaint: { enabled: true } });
    const calls: unknown[] = [];
    const client = governedClient(calls, [DESTRUCTIVE_TOOL, SAFE_TOOL]);
    await client.listTools();
    markTainted('global', 'prompt_injection', Date.now());

    await client.callTool({ name: 'read_row', arguments: {} });
    expect(calls).toHaveLength(1); // flag posture: ordinary egress still runs
  });

  it('an unannotated server does not turn flag mode into a blanket block', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', sessionTaint: { enabled: true } });
    const calls: unknown[] = [];
    const client = governedClient(calls, [UNANNOTATED_TOOL]);
    await client.listTools();
    markTainted('global', 'prompt_injection', Date.now());

    await client.callTool({ name: 'search', arguments: { q: 'x' } });
    expect(calls).toHaveLength(1);
  });

  it('records the hinted names on the discovery inventory event', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', sessionTaint: { enabled: true } });
    const client = governedClient([], [DESTRUCTIVE_TOOL, SAFE_TOOL]);
    await client.listTools();
    await waitForEvents(1);
    const inventory = sentEvents.find((e) => e.operation === 'mcp.tools.list');
    expect((inventory?.metadata as { destructive_hinted_tools?: string[] })?.destructive_hinted_tools).toEqual([
      'delete_row',
    ]);
  });

  it('a later listing dropping the hint does NOT un-declare the tool', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', sessionTaint: { enabled: true } });
    const calls: unknown[] = [];
    const client = governedClient(calls, [DESTRUCTIVE_TOOL]);
    await client.listTools();
    // The server rug-pulls its own annotation: same name, now claiming safety.
    const relisted = governedClient(calls, []);
    void relisted;
    await client.listTools();
    markTainted('global', 'prompt_injection', Date.now());

    await expect(client.callTool({ name: 'delete_row', arguments: {} })).rejects.toThrow(
      /blocked/i,
    );
    expect(calls).toEqual([]);
  });

  it('honorDestructiveHints:false restricts the set to the operator list', async () => {
    init({
      api_key: 'k',
      ingest_url: 'https://x',
      sessionTaint: { enabled: true, honorDestructiveHints: false },
    });
    const calls: unknown[] = [];
    const client = governedClient(calls, [DESTRUCTIVE_TOOL]);
    await client.listTools();
    markTainted('global', 'prompt_injection', Date.now());

    await client.callTool({ name: 'delete_row', arguments: {} });
    expect(calls).toHaveLength(1);
  });

  it('an untainted session reaches a hinted-destructive tool normally', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', sessionTaint: { enabled: true } });
    const calls: unknown[] = [];
    const client = governedClient(calls, [DESTRUCTIVE_TOOL]);
    await client.listTools();
    await client.callTool({ name: 'delete_row', arguments: {} });
    expect(calls).toHaveLength(1);
  });

  it('two governed clients do not share hints for a same-named tool', async () => {
    init({ api_key: 'k', ingest_url: 'https://x', sessionTaint: { enabled: true } });
    const callsA: unknown[] = [];
    const callsB: unknown[] = [];
    const hinting = governedClient(callsA, [DESTRUCTIVE_TOOL]);
    const benign = governedClient(callsB, [{ name: 'delete_row', description: 'Different server.' }]);
    await hinting.listTools();
    await benign.listTools();
    markTainted('global', 'prompt_injection', Date.now());

    await expect(hinting.callTool({ name: 'delete_row', arguments: {} })).rejects.toThrow(
      /blocked/i,
    );
    await benign.callTool({ name: 'delete_row', arguments: {} });
    expect(callsA).toEqual([]);
    expect(callsB).toHaveLength(1);
  });
});

describe('capability store invariants', () => {
  it('a false hint records nothing', () => {
    const store = createCapabilityStore();
    store.record('read_row', false);
    expect(store.isDestructive('read_row')).toBe(false);
    expect(store.size()).toBe(0);
  });

  it('recording is add-only and idempotent', () => {
    const store = createCapabilityStore();
    store.record('delete_row', true);
    store.record('delete_row', false); // cannot be talked out of it
    expect(store.isDestructive('delete_row')).toBe(true);
    expect(store.names()).toEqual(['delete_row']);
  });

  it('refuses past the cap rather than evicting a live restriction', () => {
    const store = createCapabilityStore();
    for (let i = 0; i < 10_000; i++) store.record(`t${i}`, true);
    expect(store.saturated()).toBe(false);
    store.record('one_too_many', true);
    expect(store.saturated()).toBe(true);
    expect(store.isDestructive('one_too_many')).toBe(false);
    expect(store.isDestructive('t0')).toBe(true); // the earlier one survived
  });
});
