import { init, _reset, getConfig } from '../../src/proxy/config';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { obsvrGovernMCP } from '../../src/integrations/mcp';
import { scanMcpToolResult, sanitizeMcpResult } from '../../src/policy/response-scan';
import type { PolicyRule } from '../../src/policy/rules';

/**
 * ADR-6 response-side interception: a governed MCP tool RESULT is scanned for
 * PII / secrets / injection and BLOCK / SANITIZE / LOG'd before it reaches the
 * caller. Tool results are the exfil/poisoning channel — this closes the other
 * half of the control (request-side was already covered).
 */

let sentEvents: any[] = [];

beforeEach(() => {
  _reset();
  _resetSender();
  sentEvents = [];
  (global as any).fetch = async (_url: any, opts: any) => {
    sentEvents.push(JSON.parse(opts.body));
    return { ok: true, status: 200 };
  };
});

afterEach(() => {
  _reset();
  _resetSender();
});

async function waitForEvents(n = 1): Promise<void> {
  for (let i = 0; i < 500 && sentEvents.length < n; i++) {
    await new Promise((r) => setTimeout(r, 5));
  }
}

/** A minimal fake MCP client whose callTool returns a preset result. */
function fakeClient(result: unknown) {
  return {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    async callTool(_params: { name: string; arguments?: Record<string, unknown> }) {
      return result;
    },
  };
}

// ── Unit: scanMcpToolResult ─────────────────────────────────────────────────

describe('scanMcpToolResult', () => {
  it('passes a clean result', () => {
    init({ apiKey: 'k', sampleRate: 1, piiPolicy: {} } as any);
    const scan = scanMcpToolResult('all quiet on the western front', getConfig());
    expect(scan.action).toBe('allow');
    expect(scan.action_taken).toBe('allowed');
  });

  it('sanitizes a result containing a redact-configured PII type', () => {
    init({ apiKey: 'k', sampleRate: 1, piiPolicy: { rules: { ssn: 'redact' } } } as any);
    const scan = scanMcpToolResult('the ssn is 123-45-6789', getConfig());
    expect(scan.action).toBe('sanitize');
    expect(scan.action_taken).toBe('redacted');
    expect(scan.detected_types).toContain('ssn');
  });

  it('blocks a result containing a block-configured PII type', () => {
    init({ apiKey: 'k', sampleRate: 1, piiPolicy: { rules: { ssn: 'block' } } } as any);
    const scan = scanMcpToolResult('the ssn is 123-45-6789', getConfig());
    expect(scan.action).toBe('block');
    expect(scan.action_taken).toBe('blocked');
    expect(scan.event_type).toBe('blocked_call');
  });

  it('blocks a result matching a block policy rule (response target)', () => {
    const rules: PolicyRule[] = [
      { id: 'r1', name: 'no exfil marker', enabled: true, action: 'block', type: 'keyword', conditions: { keywords: ['EXFIL_TOKEN'] }, applies_to: 'response' },
    ];
    init({ apiKey: 'k', sampleRate: 1, policyRules: rules } as any);
    const scan = scanMcpToolResult('here is your EXFIL_TOKEN payload', getConfig());
    expect(scan.action).toBe('block');
    expect(scan.rule_id).toBe('r1');
  });

  it('sees through a zero-width-split secret (normalization applies to matching)', () => {
    init({ apiKey: 'k', sampleRate: 1, piiPolicy: { rules: { ssn: 'block' } } } as any);
    // U+200B inside the SSN dodges a naive scan but not the normalized one.
    const scan = scanMcpToolResult('leaked: 1​23-45-6789', getConfig());
    expect(scan.action).toBe('block');
  });

  it('threads principal into response-scoped rule context', () => {
    // A user-scoped quota rule on the response target meters the principal's
    // bucket; a limit of 0 blocks immediately for the identified caller.
    const rules: PolicyRule[] = [
      { id: 'q', name: 'resp quota', enabled: true, action: 'block', type: 'quota', applies_to: 'response', conditions: { quota_limit: 1, quota_window_ms: 60000, quota_scope: 'user_id' } },
    ];
    init({ apiKey: 'k', sampleRate: 1, policyRules: rules } as any);
    // First response for alice consumes her unit; second blocks.
    expect(scanMcpToolResult('ok', getConfig(), { user_id: 'alice' }).action).toBe('allow');
    expect(scanMcpToolResult('ok', getConfig(), { user_id: 'alice' }).action).toBe('block');
    // bob is a different bucket — still allowed.
    expect(scanMcpToolResult('ok', getConfig(), { user_id: 'bob' }).action).toBe('allow');
  });
});

// ── Unit: sanitizeMcpResult ─────────────────────────────────────────────────

describe('sanitizeMcpResult', () => {
  it('redacts text in the content blocks and preserves structure', () => {
    const result = { content: [{ type: 'text', text: 'ssn 123-45-6789' }, { type: 'image', data: 'xyz' }], isError: false };
    const out = sanitizeMcpResult(result) as any;
    expect(out.content[0].text).toContain('[REDACTED_SSN]');
    expect(out.content[0].text).not.toContain('123-45-6789');
    expect(out.content[1]).toEqual({ type: 'image', data: 'xyz' });
    expect(out.isError).toBe(false);
    // The original object is not mutated.
    expect(result.content[0].text).toBe('ssn 123-45-6789');
  });

  it('redacts a bare string result', () => {
    expect(sanitizeMcpResult('call me at 555-123-4567')).toContain('[REDACTED_PHONE]');
  });
});

// ── Integration: obsvrGovernMCP response governance ─────────────────────────

describe('obsvrGovernMCP response-side governance', () => {
  it('a clean result passes through unchanged and is audited', async () => {
    init({ apiKey: 'k', sampleRate: 1, piiPolicy: {} } as any);
    const governed = obsvrGovernMCP(fakeClient({ content: [{ type: 'text', text: 'clean output' }] }), getConfig());
    const result: any = await governed.callTool({ name: 'read', arguments: { path: '/tmp' } });
    expect(result.content[0].text).toBe('clean output');
    await waitForEvents(1);
    const ev = sentEvents.find((e) => e.operation === 'mcp.tool.call' && e.success);
    expect(ev).toBeDefined();
    expect(ev.event_type).toBe('tool_call');
    expect(ev.action_taken).toBe('allowed');
  });

  it('SANITIZES a result containing PII before it reaches the caller', async () => {
    init({ apiKey: 'k', sampleRate: 1, piiPolicy: { rules: { ssn: 'redact' } } } as any);
    const governed = obsvrGovernMCP(
      fakeClient({ content: [{ type: 'text', text: 'user ssn 123-45-6789 leaked' }] }),
      getConfig(),
    );
    const result: any = await governed.callTool({ name: 'lookup', arguments: { id: 1 } });
    expect(result.content[0].text).toContain('[REDACTED_SSN]');
    expect(result.content[0].text).not.toContain('123-45-6789');
    await waitForEvents(1);
    const ev = sentEvents.find((e) => e.operation === 'mcp.tool.call' && e.success);
    expect(ev.action_taken).toBe('redacted');
  });

  it('BLOCKS a result with a blocked pattern (result withheld, caller throws)', async () => {
    init({ apiKey: 'k', sampleRate: 1, piiPolicy: { rules: { ssn: 'block' } } } as any);
    const governed = obsvrGovernMCP(
      fakeClient({ content: [{ type: 'text', text: 'exfiltrated ssn 123-45-6789' }] }),
      getConfig(),
    );
    await expect(governed.callTool({ name: 'lookup', arguments: { id: 1 } })).rejects.toThrow(
      /\[obsvr\] MCP tool result blocked by policy/,
    );
    await waitForEvents(1);
    const ev = sentEvents.find((e) => e.event_type === 'blocked_call');
    expect(ev).toBeDefined();
    expect(ev.action_taken).toBe('blocked');
  });

  it('emits the mcp.tools.list inventory event on a CLEAN discovery (parity: Python twin)', async () => {
    init({ apiKey: 'k', sampleRate: 1 } as any);
    const client = {
      async callTool() {
        return {};
      },
      async listTools() {
        return { tools: [{ name: 'read_file', description: 'Reads a file at a path.' }] };
      },
    };
    const governed = obsvrGovernMCP(client, getConfig());
    const result: any = await governed.listTools();
    expect(result.tools).toHaveLength(1);
    await waitForEvents(1);
    const ev = sentEvents.find((e) => e.operation === 'mcp.tools.list');
    expect(ev).toBeDefined();
    expect(ev.event_type).toBe('tool_call');
    expect(ev.metadata.flagged_tools).toEqual([]);
  });

  it('audits the decision with the caller principal (user_id)', async () => {
    init({ apiKey: 'k', sampleRate: 1, piiPolicy: {} } as any);
    const governed = obsvrGovernMCP(
      fakeClient({ content: [{ type: 'text', text: 'ok' }] }),
      getConfig(),
      { user_id: 'alice' },
    );
    await governed.callTool({ name: 'read', arguments: {} });
    await waitForEvents(1);
    const ev = sentEvents.find((e) => e.operation === 'mcp.tool.call');
    expect(ev.user_id).toBe('alice');
  });
});
