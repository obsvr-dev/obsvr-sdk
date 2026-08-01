/**
 * The openai-agents pre-execution tool gate: the guardrail mechanism.
 *
 * The tracing processor on this surface records and cannot refuse (its rows in
 * enforcement-reporting-invariant.test.ts pin that half). Refusal lives in
 * `attachToolGate`: obsvr's guardrail pushed into each function tool's own
 * `inputGuardrails`, which the executor awaits BEFORE invoking the tool. A
 * denied tool is refused by the guardrail contract's `rejectContent` sentinel
 * — the model receives the block message as the tool's result and the run
 * continues — and the record is `blocked`, true at the point it is written.
 *
 * The framework surface is modeled at the exact contract read off the
 * installed @openai/agents-core (0.13.4; byte-identical guardrail types at
 * 0.13.0 and 0.14.2): `tool()` returns a plain object whose `inputGuardrails`
 * is always an array on every build that also consults it, and the executor
 * reads that array fresh on every call. The live proof lives in the
 * integration harness, not here.
 */

import { init, _reset } from '../../src/proxy/config';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import {
  attachToolGate,
  makeToolGateGuardrail,
  ObsvrTraceProcessor,
} from '../../src/integrations/openai-agents';
import {
  isToolGoverned,
  registerGovernedToolName,
  _resetGovernedToolNames,
} from '../../src/integrations/tools';

const TOOL = 'gate_probe_tool';

let sentEvents: any[] = [];

beforeEach(() => {
  _reset();
  _resetSender();
  _resetGovernedToolNames();
  sentEvents = [];
  (global as any).fetch = async (_url: any, opts: any) => {
    sentEvents.push(JSON.parse(opts.body));
    return { ok: true, status: 200 };
  };
});

async function settle(): Promise<void> {
  for (let i = 0; i < 40; i++) await new Promise((r) => setTimeout(r, 5));
}

function guardrailData(name = TOOL) {
  return { toolCall: { name, callId: 'call-1', arguments: '{"a":1}' } };
}

function blocked() {
  return sentEvents.filter((e) => e.action_taken === 'blocked');
}

// ── the guardrail function ──────────────────────────────────────────────────

describe('makeToolGateGuardrail', () => {
  it('rejects a denied tool with a blocked record, before invocation', async () => {
    init({ api_key: 'test', sample_rate: 1, agent_policy: { deniedTools: [TOOL] } } as any);
    const out = await makeToolGateGuardrail().run(guardrailData());

    expect(out.behavior.type).toBe('rejectContent');
    const message = (out.behavior as { message: string }).message;
    expect(message).toContain(TOOL);
    expect(message).toContain('tool_denied');

    await settle();
    expect(blocked()).toHaveLength(1);
    const event = blocked()[0];
    expect(event.operation).toBe('openai_agents.agent.policy.tool_blocked');
    expect(event.reason_code).toBe('TOOL_DENIED');
    expect(event.metadata.tool_name).toBe(TOOL);
    expect(event.metadata.reason).toBe('tool_denied');
    expect(event.metadata.tool_call_id).toBe('call-1');
  });

  it('rejects an allowlist miss too', async () => {
    init({ api_key: 'test', sample_rate: 1, agent_policy: { allowedTools: ['other'] } } as any);
    const out = await makeToolGateGuardrail().run(guardrailData());

    expect(out.behavior.type).toBe('rejectContent');
    expect((out.behavior as { message: string }).message).toContain('tool_not_in_allowlist');
  });

  it('allows a permitted tool with an EXPLICIT behavior (the framework treats a missing one as allow)', async () => {
    init({ api_key: 'test', sample_rate: 1, agent_policy: { deniedTools: ['something_else'] } } as any);
    const out = await makeToolGateGuardrail().run(guardrailData());

    // The control: a gate that rejects everything passes the deny tests.
    expect(out.behavior).toEqual({ type: 'allow' });
    await settle();
    expect(blocked()).toHaveLength(0);
  });

  it('never throws on an internal failure, and follows failMode', async () => {
    // A throw from a guardrail becomes ToolCallError and aborts the caller's
    // whole run — an obsvr defect must not become the host's outage.
    const poisoned = {
      get toolCall(): never {
        throw new Error('detector imploded');
      },
    };

    init({ api_key: 'test', sample_rate: 1, agent_policy: { deniedTools: [TOOL] } } as any);
    const open = await makeToolGateGuardrail().run(poisoned);
    expect(open.behavior).toEqual({ type: 'allow' });

    init({
      api_key: 'test',
      sample_rate: 1,
      fail_mode: 'closed',
      agent_policy: { deniedTools: [TOOL] },
    } as any);
    const closed = await makeToolGateGuardrail().run(poisoned);
    expect(closed.behavior.type).toBe('rejectContent');
    expect((closed.behavior as { message: string }).message).toContain('failMode=closed');
  });
});

// ── attachToolGate ──────────────────────────────────────────────────────────

function functionTool(name: string): Record<string, unknown> {
  return {
    type: 'function',
    name,
    description: 'd',
    parameters: {},
    invoke: async () => 'x',
    inputGuardrails: [],
    outputGuardrails: [],
  };
}

function agentOf(
  tools: Array<Record<string, unknown>>,
  handoffs: unknown[] = [],
): Record<string, unknown> {
  return { tools, handoffs };
}

describe('attachToolGate', () => {
  it('gates tools and handoff targets, idempotently, and detaches cleanly', () => {
    init({ api_key: 'test', sample_rate: 1 } as any);
    const workerTool = functionTool('worker_probe_tool');
    const worker = agentOf([workerTool]);
    const hosted = { type: 'hosted_tool', name: 'hosted_probe_tool' };
    const triageTool = functionTool(TOOL);
    // The handoff() object shape: target reachable via .agent — and a cycle
    // back to triage that must terminate, not recurse forever.
    const triage = agentOf([triageTool, hosted], [{ agent: worker }]);
    worker.handoffs = [triage];

    const detach = attachToolGate(triage);

    expect((triageTool.inputGuardrails as unknown[]).length).toBe(1);
    expect((workerTool.inputGuardrails as unknown[]).length).toBe(1);
    expect('inputGuardrails' in hosted).toBe(false);
    expect(isToolGoverned(TOOL)).toBe(true);
    expect(isToolGoverned('worker_probe_tool')).toBe(true);
    expect(isToolGoverned('hosted_probe_tool')).toBe(false);

    const detachAgain = attachToolGate(triage);
    expect((triageTool.inputGuardrails as unknown[]).length).toBe(1);

    detach();
    detach(); // idempotent handle
    detachAgain();
    expect(triageTool.inputGuardrails).toEqual([]);
    expect(workerTool.inputGuardrails).toEqual([]);
  });

  it("leaves a caller's own guardrails in place, obsvr's after theirs", () => {
    init({ api_key: 'test', sample_rate: 1 } as any);
    const tool = functionTool(TOOL);
    const theirs = { type: 'tool_input', name: 'their_gate', run: async () => ({}) };
    (tool.inputGuardrails as unknown[]).push(theirs);

    const detach = attachToolGate(agentOf([tool]));
    expect((tool.inputGuardrails as Array<{ name: string }>).map((g) => g.name)).toEqual([
      'their_gate',
      'obsvr_tool_gate',
    ]);

    detach();
    expect(tool.inputGuardrails).toEqual([theirs]);
  });

  it('refuses loudly — and rolls back — when a function tool has no inputGuardrails array', () => {
    // The array is created by tool() on every build that also consults it, so
    // its absence means no executor ever asks. Arming the property anyway
    // would be the silent no-op shape; refusing must also UNDO the tools it
    // already gated, or the throw reads as not-installed while half the
    // agent is.
    init({ api_key: 'test', sample_rate: 1 } as any);
    const gateable = functionTool(TOOL);
    const legacy = { type: 'function', name: 'legacy_tool', invoke: async () => 'x' };

    expect(() => attachToolGate(agentOf([gateable, legacy]))).toThrow(/obsvrGovernTool/);
    expect(gateable.inputGuardrails).toEqual([]);
    expect('inputGuardrails' in legacy).toBe(false);
  });

  it('rejects a non-agent argument outright', () => {
    init({ api_key: 'test', sample_rate: 1 } as any);
    expect(() => attachToolGate({ tools: 'nope' })).toThrow(/Agent/);
  });
});

// ── the processor beside a real gate ────────────────────────────────────────

function functionSpan(name: string, spanId: string, endedAt?: string) {
  return {
    traceId: 'trace-gate-1',
    spanId,
    spanData: { type: 'function', name, input: '{"a":1}' },
    startedAt: new Date().toISOString(),
    endedAt,
  };
}

describe('the processor beside a real gate', () => {
  it('stays silent about a governed name instead of stamping not_evaluated', async () => {
    init({ api_key: 'test', sample_rate: 1, agent_policy: { deniedTools: [TOOL] } } as any);
    registerGovernedToolName(TOOL);
    const proc: any = new ObsvrTraceProcessor();

    await proc.onSpanEnd(functionSpan(TOOL, 'span-1', new Date().toISOString()));
    await settle();

    expect(sentEvents.filter((e) => e.action_taken === 'not_evaluated')).toHaveLength(0);
    // Still observed as a call — deference is not silence about the step.
    expect(sentEvents.some((e) => e.operation === 'openai_agents.tool.call')).toBe(true);
  });

  it('keeps the honest rail for a name no gate speaks for (the control)', async () => {
    init({ api_key: 'test', sample_rate: 1, agent_policy: { deniedTools: [TOOL] } } as any);
    const proc: any = new ObsvrTraceProcessor();

    await proc.onSpanEnd(functionSpan(TOOL, 'span-1', new Date().toISOString()));
    await settle();

    expect(sentEvents.filter((e) => e.action_taken === 'not_evaluated')).toHaveLength(1);
  });

  it('processes a function span once, not once per hook delivery', async () => {
    // onSpanStart and onSpanEnd both ran the function branch: two tool.call
    // events per call and stepCount charged twice, tripping maxSteps at half
    // its budget. The payload is complete at END; that is the one delivery.
    init({ api_key: 'test', sample_rate: 1, agent_policy: { maxSteps: 2 } } as any);
    const proc: any = new ObsvrTraceProcessor();

    // The agent span's START creates the per-trace step counter.
    await proc.onSpanStart({
      traceId: 'trace-gate-1',
      spanId: 'span-agent',
      spanData: { type: 'agent', name: 'A' },
    });

    for (const spanId of ['span-a', 'span-b']) {
      const span = functionSpan('some_tool', spanId, undefined);
      await proc.onSpanStart(span);
      await proc.onSpanEnd({ ...span, endedAt: new Date().toISOString() });
    }
    await settle();

    const calls = sentEvents.filter((e) => e.operation === 'openai_agents.tool.call');
    expect(calls).toHaveLength(2);
    expect(calls.map((e) => e.metadata.step_index)).toEqual([0, 1]);
    // Two calls under maxSteps 2: within budget, no step_limit event. The
    // double-charge used to trip it here.
    expect(
      sentEvents.filter((e) => e.operation === 'openai_agents.agent.policy.step_limit'),
    ).toHaveLength(0);
  });
});
