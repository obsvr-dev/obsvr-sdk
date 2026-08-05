/**
 * tool_content_hash at the real tool boundaries.
 *
 * The producer module is fixture-pinned elsewhere; this file pins that the
 * shipping paths actually stamp it, on the right events, in the right place.
 * Three things have to hold together or the evidence is worthless: the value
 * must equal what an offline recomputation produces from the disclosed parts,
 * caller metadata must never be able to overwrite it, and a value neither
 * language can canonicalize must omit the field rather than seal a hash the
 * Python twin cannot reproduce.
 */
import { init, _reset, getConfig } from '../../src/proxy/config';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { obsvrGovernMCP } from '../../src/integrations/mcp';
import { obsvrGovernTool } from '../../src/integrations/tools';
import {
  TOOL_CONTENT_HASH_METADATA_KEY,
  computeToolContentHash,
} from '../../src/policy/tool-content-hash';
import { toolDescriptorHash } from '../../src/policy/tool-pinning';

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
  _reset();
  _resetSender();
  delete (global as any).fetch;
});

async function waitForEvents(n = 1): Promise<void> {
  for (let i = 0; i < 500 && sentEvents.length < n; i++) {
    await new Promise((r) => setTimeout(r, 10));
  }
}

function stubMcpClient(result: unknown = 'ok') {
  return {
    callTool: async (_params: unknown) => result,
    listTools: async () => ({ tools: [] }),
  };
}

const hashOf = (metadata: Record<string, unknown> | undefined): unknown =>
  metadata?.[TOOL_CONTENT_HASH_METADATA_KEY];

describe('tool_content_hash on the MCP tool boundary', () => {
  it('stamps a hash an auditor can recompute from the disclosed parts', async () => {
    init({ api_key: 'k', ingest_url: 'https://x' });
    const governed = obsvrGovernMCP(stubMcpClient(), getConfig(), {});
    await governed.callTool({ name: 'readFile', arguments: { path: '/tmp/a', depth: 2 } });
    await waitForEvents(1);

    const ev = sentEvents.find((e) => e.operation === 'mcp.tool.call');
    expect(ev).toBeDefined();
    // call_tool carries no descriptor, so the document commits to the name and
    // arguments with the empty-descriptor digest - what this producer saw.
    expect(hashOf(ev.metadata)).toBe(
      computeToolContentHash({ toolName: 'readFile', args: { path: '/tmp/a', depth: 2 } }),
    );
  });

  it('is argument-sensitive: the same tool called differently hashes differently', async () => {
    init({ api_key: 'k', ingest_url: 'https://x' });
    const governed = obsvrGovernMCP(stubMcpClient(), getConfig(), {});
    await governed.callTool({ name: 'readFile', arguments: { path: '/tmp/a' } });
    await governed.callTool({ name: 'readFile', arguments: { path: '/etc/shadow' } });
    await waitForEvents(2);

    const calls = sentEvents.filter((e) => e.operation === 'mcp.tool.call');
    expect(calls.length).toBe(2);
    expect(hashOf(calls[0].metadata)).not.toBe(hashOf(calls[1].metadata));
  });

  it('stamps blocked tool calls too - what was refused is the record', async () => {
    init({
      api_key: 'k',
      ingest_url: 'https://x',
      mcpToolPolicy: { deniedTools: ['dangerous'] },
    });
    const governed = obsvrGovernMCP(stubMcpClient(), getConfig(), {});
    await expect(
      governed.callTool({ name: 'dangerous', arguments: { x: 1 } }),
    ).rejects.toThrow(/\[obsvr\]/);
    await waitForEvents(1);

    const ev = sentEvents.find((e) => e.event_type === 'blocked_call');
    expect(ev).toBeDefined();
    expect(hashOf(ev.metadata)).toBe(
      computeToolContentHash({ toolName: 'dangerous', args: { x: 1 } }),
    );
  });

  it('caller metadata cannot overwrite the sealed value', async () => {
    init({ api_key: 'k', ingest_url: 'https://x' });
    const governed = obsvrGovernMCP(stubMcpClient(), getConfig(), {
      metadata: { [TOOL_CONTENT_HASH_METADATA_KEY]: 'caller-spoof' },
    });
    await governed.callTool({ name: 'readFile', arguments: { path: '/tmp/a' } });
    await waitForEvents(1);

    const ev = sentEvents.find((e) => e.operation === 'mcp.tool.call');
    expect(hashOf(ev.metadata)).toBe(
      computeToolContentHash({ toolName: 'readFile', args: { path: '/tmp/a' } }),
    );
  });

  it('omits the field rather than sealing a hash Python cannot reproduce', async () => {
    init({ api_key: 'k', ingest_url: 'https://x' });
    const governed = obsvrGovernMCP(stubMcpClient(), getConfig(), {});
    // An integer past 2^53 canonicalizes differently in the two runtimes, so
    // the producer throws and the boundary drops the field - the call itself
    // must still go through.
    const result = await governed.callTool({
      name: 'readFile',
      arguments: { size: 9007199254740993 },
    });
    expect(result).toBe('ok');
    await waitForEvents(1);

    const ev = sentEvents.find((e) => e.operation === 'mcp.tool.call');
    expect(ev.metadata.tool_name).toBe('readFile');
    expect(hashOf(ev.metadata)).toBeUndefined();
  });

  it('leaves the descriptor-pinning hash untouched', async () => {
    const descriptor = {
      name: 'readFile',
      description: 'reads a file',
      inputSchema: { type: 'object' },
    };
    init({
      api_key: 'k',
      ingest_url: 'https://x',
      mcpToolPolicy: { pinning: { enabled: true, mode: 'warn' } },
    });
    const client = {
      callTool: async (_params: unknown) => 'ok',
      listTools: async () => ({ tools: [descriptor] }),
    };
    const governed = obsvrGovernMCP(client, getConfig(), {});
    await governed.listTools();
    await governed.callTool({ name: 'readFile', arguments: { path: '/tmp/a' } });
    await waitForEvents(1);

    const ev = sentEvents.find((e) => e.operation === 'mcp.tool.call');
    // Two different hashes on one event, both correct, neither substituted:
    // the pin identifies the descriptor, the content hash identifies the call.
    expect(ev.metadata.tool_descriptor_hash).toBe(toolDescriptorHash(descriptor));
    expect(hashOf(ev.metadata)).toBe(
      computeToolContentHash({ toolName: 'readFile', args: { path: '/tmp/a' } }),
    );
    expect(ev.metadata.tool_descriptor_hash).not.toBe(hashOf(ev.metadata));
  });
});

describe('tool_content_hash on the framework tool boundary', () => {
  const calculator = {
    name: 'calculator',
    description: 'adds two numbers',
    inputSchema: { type: 'object', properties: { a: { type: 'number' } } },
    execute: async (input: unknown) => ({ ok: true, input }),
  };

  it('covers the descriptor as well as the arguments', async () => {
    init({ api_key: 'k', ingest_url: 'https://x' });
    const governed = obsvrGovernTool(calculator);
    await governed.execute({ a: 1, b: 2 });
    await waitForEvents(1);

    const ev = sentEvents.find((e) => e.operation === 'tool.call');
    expect(ev).toBeDefined();
    expect(hashOf(ev.metadata)).toBe(
      computeToolContentHash({
        toolName: 'calculator',
        descriptor: {
          name: 'calculator',
          description: calculator.description,
          inputSchema: calculator.inputSchema,
        },
        args: { a: 1, b: 2 },
      }),
    );
  });

  it('changes when the descriptor changes, even for identical arguments', async () => {
    init({ api_key: 'k', ingest_url: 'https://x' });
    const swapped = { ...calculator, description: 'also emails your API key' };
    await obsvrGovernTool(calculator).execute({ a: 1 });
    await obsvrGovernTool(swapped).execute({ a: 1 });
    await waitForEvents(2);

    const calls = sentEvents.filter((e) => e.operation === 'tool.call');
    expect(calls.length).toBe(2);
    expect(hashOf(calls[0].metadata)).not.toBe(hashOf(calls[1].metadata));
  });

  it('stamps a policy-blocked tool call', async () => {
    init({
      api_key: 'k',
      ingest_url: 'https://x',
      agent_policy: { deniedTools: ['calculator'] },
    });
    const governed = obsvrGovernTool(calculator);
    // The gate throws synchronously, before the tool's own promise exists.
    await expect(governed.execute({ a: 1 })).rejects.toThrow(/\[obsvr\]/);
    await waitForEvents(1);

    const ev = sentEvents.find((e) => e.event_type === 'blocked_call');
    expect(hashOf(ev.metadata)).toBeDefined();
    expect(ev.metadata.reason).toBe('tool_denied');
    // Reachability pin for TOOL_DENIED (named in reason-codes.test.ts).
    expect(ev.reason_code).toBe('TOOL_DENIED');
  });
});
