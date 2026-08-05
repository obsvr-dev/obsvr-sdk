/**
 * The MCP half of "allowed implies evaluated", driven against the REAL
 * `@modelcontextprotocol/sdk` — the surface both instances of this defect class
 * were measured on.
 *
 * Two shapes, one property. Each records `allowed` on a call no policy layer
 * judged, and each is invisible to "blocked implies not executed", because
 * neither ever claims `blocked`:
 *
 *   THE ARMING GAP        a configured rule set is not on the boundary's
 *                         "is any policy configured" list, so the pre-call
 *                         pipeline never runs. The permit leg is where this
 *                         hides: the block leg looks like an ordinary allow.
 *
 *   THE FAIL-OPEN         the pipeline runs and CRASHES. failMode=open lets the
 *                         call proceed, which is the documented behaviour — but
 *                         the compliance was left undefined and the event fell
 *                         through to the default, stamping `allowed` on a call
 *                         the engine had errored on.
 *
 * The fail-open leg needs a fault INSIDE the pipeline, which caller-supplied
 * data cannot reach (core.ts guards its own detector layers and resolves them
 * internally). So it is injected by module mock, registered before the module
 * under test is imported — the same technique, and the same reason, as
 * fail-mode-guarded.test.ts.
 */
import { jest } from '@jest/globals';

const corePath = '../../src/integrations/core';
const actualCore = await import(corePath);

/** Flipped per-test: the pipeline throws only where a test asks it to. */
let crashPipeline = false;

jest.unstable_mockModule(corePath, () => ({
  ...actualCore,
  applyPreCallPolicy: async (...args: unknown[]) => {
    if (crashPipeline) throw new Error('policy engine exploded');
    return (actualCore as any).applyPreCallPolicy(...args);
  },
}));

const { Client } = await import('@modelcontextprotocol/sdk/client/index.js');
const { McpServer } = await import('@modelcontextprotocol/sdk/server/mcp.js');
const { InMemoryTransport } = await import('@modelcontextprotocol/sdk/inMemory.js');
const { init, _reset, getConfig } = await import('../../src/proxy/config');
const { _resetSender } = await import('../../src/proxy/sender/fire-and-forget');
const { obsvrGovernMCP } = await import('../../src/integrations/mcp');

const RULE = {
  id: 'r-badword',
  name: 'r-badword',
  enabled: true,
  action: 'block',
  type: 'keyword',
  conditions: { keywords: ['badword'] },
};

let sentEvents: any[] = [];

beforeEach(() => {
  crashPipeline = false;
  _reset();
  _resetSender();
  sentEvents = [];
  (global as any).fetch = async (_url: any, opts: any) => {
    sentEvents.push(JSON.parse(opts.body));
    return { ok: true, status: 200 };
  };
});

afterEach(() => {
  crashPipeline = false;
  delete (global as any).fetch;
  _reset();
  _resetSender();
});

async function connectRealPair() {
  const executed: string[] = [];
  const server = new McpServer({ name: 'obsvr-test-server', version: '1.0.0' });
  server.registerTool('send_money', { description: 'Transfer funds.' }, async () => {
    executed.push('send_money');
    return { content: [{ type: 'text' as const, text: 'sent' }] };
  });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'obsvr-test-client', version: '1.0.0' }, { capabilities: {} });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return {
    client,
    executed,
    close: async () => {
      await client.close();
      await server.close();
    },
  };
}

async function waitForEvents(n = 1) {
  for (let i = 0; i < 300 && sentEvents.length < n; i++) {
    await new Promise((r) => setTimeout(r, 10));
  }
  return sentEvents.flatMap((b: any) => b.events ?? [b]);
}

describe('MCP: the arming gap, caught from the PERMIT leg', () => {
  it('a rule set ALONE evidences the evaluation on a call it permits', async () => {
    // The leg the Severity 1 hid on. With the boundary unarmed this call still
    // succeeds and still records `allowed`; only the missing evidence tells
    // the two apart, which is why the block leg alone never caught it.
    init({ api_key: 'test-key', sample_rate: 1, policy_rules: [RULE] } as never);
    const { client, executed, close } = await connectRealPair();
    try {
      const governed = obsvrGovernMCP(client, getConfig());
      await governed.callTool({ name: 'send_money', arguments: { memo: 'perfectly fine' } });
      const events = await waitForEvents(1);

      expect(executed).toEqual(['send_money']); // control: the call really happened
      const ev = events.find((e: any) => e.operation === 'mcp.tool.call');
      expect(ev.action_taken).toBe('allowed');
      expect(ev.decision_input_hash).toEqual(expect.any(String));
      expect(ev.engine_version).toEqual(expect.any(String));
    } finally {
      await close();
    }
  });

  it('and refuses the matching call, without executing the body', async () => {
    init({ api_key: 'test-key', sample_rate: 1, policy_rules: [RULE] } as never);
    const { client, executed, close } = await connectRealPair();
    try {
      const governed = obsvrGovernMCP(client, getConfig());
      await expect(
        governed.callTool({ name: 'send_money', arguments: { memo: 'this has badword' } }),
      ).rejects.toThrow();
      const events = await waitForEvents(1);

      expect(executed).toEqual([]);
      expect(events.find((e: any) => e.action_taken === 'blocked')).toBeDefined();
      expect(events.find((e: any) => e.action_taken === 'allowed')).toBeUndefined();
    } finally {
      await close();
    }
  });
});

describe('MCP: the fail-open, which proceeds but must not claim a permit', () => {
  it('a crashed policy engine records not_evaluated, never allowed', async () => {
    init({ api_key: 'test-key', sample_rate: 1, policy_rules: [RULE], fail_mode: 'open' } as never);
    crashPipeline = true;
    const { client, executed, close } = await connectRealPair();
    try {
      const governed = obsvrGovernMCP(client, getConfig());
      await governed.callTool({ name: 'send_money', arguments: { memo: 'anything' } });
      const events = await waitForEvents(1);

      // failMode=open is documented: the call proceeds. That is not the defect.
      expect(executed).toEqual(['send_money']);

      const ev = events.find((e: any) => e.operation === 'mcp.tool.call');
      expect(ev.action_taken).toBe('not_evaluated');
      expect(ev.action_taken).not.toBe('allowed');
      // And it says WHICH layer could not decide, so the gap is auditable
      // rather than merely absent from the record.
      const why = ev.metadata?.obsvr_telemetry?.policy_not_evaluated;
      expect(why?.surface).toBe('mcp');
      expect(why?.gate).toBe('pre_call_pipeline');
      expect(why?.reason).toMatch(/policy engine exploded/);
    } finally {
      await close();
    }
  });

  it('CONTROL: with the engine healthy the same call is an evidenced permit', async () => {
    // Without this, the row above would also be satisfied by a boundary that
    // had started recording not_evaluated for every call.
    init({ api_key: 'test-key', sample_rate: 1, policy_rules: [RULE], fail_mode: 'open' } as never);
    const { client, executed, close } = await connectRealPair();
    try {
      const governed = obsvrGovernMCP(client, getConfig());
      await governed.callTool({ name: 'send_money', arguments: { memo: 'fine' } });
      const events = await waitForEvents(1);

      expect(executed).toEqual(['send_money']);
      const ev = events.find((e: any) => e.operation === 'mcp.tool.call');
      expect(ev.action_taken).toBe('allowed');
      expect(ev.decision_input_hash).toEqual(expect.any(String));
    } finally {
      await close();
    }
  });

  it('failMode=closed still refuses outright, and the body never runs', async () => {
    init({ api_key: 'test-key', sample_rate: 1, policy_rules: [RULE], fail_mode: 'closed' } as never);
    crashPipeline = true;
    const { client, executed, close } = await connectRealPair();
    try {
      const governed = obsvrGovernMCP(client, getConfig());
      await expect(
        governed.callTool({ name: 'send_money', arguments: { memo: 'anything' } }),
      ).rejects.toThrow(/failMode=closed/i);
      expect(executed).toEqual([]);
    } finally {
      await close();
    }
  });
});
