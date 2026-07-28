import { init, _reset, getConfig } from '../../src/proxy/config';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { extractMcpPrompt, extractMcpResponse } from '../../src/proxy/extractors/mcp';
import { emitIntegrationEvent, tryGetConfig } from '../../src/integrations/core';
import { runBuiltinPiiScan } from '../../src/policy/hook';
import { patchMCP, _resetPatchMCPDeprecationWarning } from '../../src/integrations/mcp';

// ── Helpers ──────────────────────────────────────────────────────────────────

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
    await new Promise((r) => setTimeout(r, 10));
  }
}

// ── Policy check helper (mirrors mcp.ts logic) ──────────────────────────────

function checkMcpToolPolicy(
  toolName: string,
  policy: { allowedTools?: string[]; deniedTools?: string[] },
): { allowed: boolean; reason: string } {
  const denied = policy.deniedTools ?? [];
  const allowed = policy.allowedTools;
  if (denied.includes(toolName)) return { allowed: false, reason: 'tool_denied' };
  if (allowed !== undefined && !allowed.includes(toolName)) {
    return { allowed: false, reason: 'tool_not_in_allowlist' };
  }
  return { allowed: true, reason: '' };
}

// ── Extractor Tests ──────────────────────────────────────────────────────────

describe('MCP extractors', () => {
  it('formats tool call as prompt text', () => {
    const result = extractMcpPrompt('readFile', { path: '/tmp/test.txt' });
    expect(result).toBe('[MCP Tool call: readFile({"path":"/tmp/test.txt"})]');
  });

  it('handles undefined args', () => {
    const result = extractMcpPrompt('listTools', undefined);
    expect(result).toBe('[MCP Tool call: listTools()]');
  });

  it('formats string response', () => {
    expect(extractMcpResponse('hello')).toBe('hello');
  });

  it('formats object response as JSON', () => {
    const result = extractMcpResponse({ content: [{ type: 'text', text: 'ok' }] });
    expect(result).toBe('{"content":[{"type":"text","text":"ok"}]}');
  });

  it('handles null/undefined response', () => {
    expect(extractMcpResponse(null)).toBe('');
    expect(extractMcpResponse(undefined)).toBe('');
  });
});

// ── Integration Tests (manual patch simulation) ─────────────────────────────

describe('MCP integration - event emission', () => {
  it('emits audit event for a tool call with correct fields', async () => {
    init({ api_key: 'test-key', sample_rate: 1 });
    const config = getConfig();

    // Simulate what the patched callTool does internally
    const toolName = 'readFile';
    const toolArgs = { path: '/tmp/test' };
    const promptText = extractMcpPrompt(toolName, toolArgs);
    const toolResult = { content: [{ type: 'text', text: 'file contents' }] };
    const responseText = extractMcpResponse(toolResult);

    emitIntegrationEvent({
      config,
      provider: 'mcp',
      model: 'mcp',
      operation: 'mcp.tool.call',
      source: 'mcp_sdk',
      prompt: promptText,
      response: responseText,
      latencyMs: 42,
      success: true,
      metadata: { tool_name: toolName },
      compliance: {
        event_type: 'tool_call',
        policy_version: 'v1',
        action_taken: 'allowed',
        action_reason: 'none',
        action_source: 'unknown',
        redacted_types: [],
        blocked_types: [],
      },
    });

    await waitForEvents(1);

    expect(sentEvents.length).toBe(1);
    const event = sentEvents[0];
    expect(event.provider).toBe('mcp');
    expect(event.operation).toBe('mcp.tool.call');
    expect(event.event_type).toBe('tool_call');
    expect(event.prompt).toContain('[MCP Tool call: readFile');
    expect(event.response).toContain('file contents');
    expect(event.metadata.tool_name).toBe('readFile');
    expect(event.success).toBe(true);
    expect(event.action_taken).toBe('allowed');
    expect(event.latency_ms).toBe(42);
  });

  it('emits blocked_call event when tool call fails', async () => {
    init({ api_key: 'test-key', sample_rate: 1 });
    const config = getConfig();

    emitIntegrationEvent({
      config,
      provider: 'mcp',
      model: 'mcp',
      operation: 'mcp.tool.call',
      source: 'mcp_sdk',
      prompt: extractMcpPrompt('badTool', {}),
      response: '',
      success: false,
      error: new Error('tool execution failed'),
      metadata: { tool_name: 'badTool' },
      compliance: {
        event_type: 'blocked_call',
        policy_version: 'v1',
        action_taken: 'blocked',
        action_reason: 'policy_violation',
        action_source: 'builtin',
        redacted_types: [],
        blocked_types: [],
        policy_reason: 'tool_denied',
      },
    });

    await waitForEvents(1);

    expect(sentEvents.length).toBe(1);
    const event = sentEvents[0];
    expect(event.provider).toBe('mcp');
    expect(event.event_type).toBe('blocked_call');
    expect(event.action_taken).toBe('blocked');
    expect(event.success).toBe(false);
    expect(event.error_message).toBe('tool execution failed');
  });

  it('includes HMAC signature and chain fields', async () => {
    init({ api_key: 'test-key', sample_rate: 1 });
    const config = getConfig();

    emitIntegrationEvent({
      config,
      provider: 'mcp',
      model: 'mcp',
      operation: 'mcp.tool.call',
      source: 'mcp_sdk',
      prompt: extractMcpPrompt('tool1', {}),
      response: 'result1',
      success: true,
      metadata: { tool_name: 'tool1' },
    });

    await waitForEvents(1);

    const event = sentEvents[0];
    expect(event.sdk_session_id).toBeDefined();
    expect(event.seq_no).toBeGreaterThan(0);
    expect(event.timestamp_sdk).toBeGreaterThan(0);
    expect(event.sdk_sig).toBeDefined();
    expect(typeof event.sdk_sig).toBe('string');
    expect(event.sdk_sig.length).toBe(64); // HMAC-SHA256 hex
  });
});

// ── Tool Policy Tests ────────────────────────────────────────────────────────

describe('MCP tool policy enforcement', () => {
  it('blocks denied tools', () => {
    const result = checkMcpToolPolicy('dangerousTool', {
      deniedTools: ['dangerousTool', 'anotherBadTool'],
    });
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('tool_denied');
  });

  it('blocks tools not in allowlist', () => {
    const policy = { allowedTools: ['readFile', 'listDir'] };

    const allowed = checkMcpToolPolicy('readFile', policy);
    expect(allowed.allowed).toBe(true);

    const denied = checkMcpToolPolicy('writeFile', policy);
    expect(denied.allowed).toBe(false);
    expect(denied.reason).toBe('tool_not_in_allowlist');
  });

  it('allows all tools when no restrictions', () => {
    const result = checkMcpToolPolicy('anyTool', {});
    expect(result.allowed).toBe(true);
  });

  it('deniedTools takes precedence over allowedTools', () => {
    const result = checkMcpToolPolicy('readFile', {
      allowedTools: ['readFile'],
      deniedTools: ['readFile'],
    });
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('tool_denied');
  });

  it('persists mcpToolPolicy through config resolution', () => {
    init({
      api_key: 'test-key',
      sample_rate: 1,
      mcpToolPolicy: { deniedTools: ['blocked'] },
    } as any);

    const config = getConfig();
    expect(config.mcpToolPolicy).toBeDefined();
    expect(config.mcpToolPolicy!.deniedTools).toEqual(['blocked']);
  });

  it('mcpToolPolicy is undefined when not set', () => {
    init({ api_key: 'test-key', sample_rate: 1 });
    const config = getConfig();
    expect(config.mcpToolPolicy).toBeUndefined();
  });
});

// ── PII Detection in Tool Args ───────────────────────────────────────────────

describe('MCP PII detection in tool args', () => {
  it('detects PII in tool arguments formatted as prompt', () => {
    const promptText = extractMcpPrompt('sendEmail', {
      to: 'user@example.com',
      body: 'My SSN is 123-45-6789',
    });

    const { pii_detected, detected_types } = runBuiltinPiiScan(promptText);
    expect(pii_detected).toBe(true);
    expect(detected_types).toContain('ssn');
    expect(detected_types).toContain('email');
  });

  it('detects credit card numbers in tool args', () => {
    const promptText = extractMcpPrompt('processPayment', {
      card: '4111-1111-1111-1111',
    });

    const { pii_detected, detected_types } = runBuiltinPiiScan(promptText);
    expect(pii_detected).toBe(true);
    expect(detected_types).toContain('credit_card');
  });

  it('passes clean tool args without PII detection', () => {
    const promptText = extractMcpPrompt('listFiles', { directory: '/tmp' });
    const { pii_detected } = runBuiltinPiiScan(promptText);
    expect(pii_detected).toBe(false);
  });
});

// ── patchMCP deprecation (legacy prototype-mutating path) ───────────────────

describe('patchMCP deprecation warning', () => {
  it('emits a one-time console.warn pointing at obsvrGovernMCP', () => {
    init({ api_key: 'test-key', sample_rate: 1 });
    const config = getConfig();
    _resetPatchMCPDeprecationWarning();
    const warnings: string[] = [];
    const originalWarn = console.warn;
    console.warn = (...args: unknown[]) => { warnings.push(String(args[0])); };
    try {
      patchMCP(config);
      patchMCP(config); // second call must NOT warn again
      const deprecations = warnings.filter((w) => w.includes('patchMCP() is deprecated'));
      expect(deprecations).toHaveLength(1);
      expect(deprecations[0]).toContain('obsvrGovernMCP');
      expect(deprecations[0]).toContain('next major');
    } finally {
      console.warn = originalWarn;
    }
  });
});
