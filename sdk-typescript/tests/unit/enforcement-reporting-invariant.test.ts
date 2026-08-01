/**
 * The enforcement-reporting invariant, TypeScript half.
 *
 *     For every event where `action_taken === "blocked"`, the governed
 *     operation did not execute.
 *
 * The Python half of this exists as a table over every gated surface there. This
 * is its twin, and it is NOT a translation of the Python results: the two SDKs
 * have genuinely different tool-gate implementations, TypeScript has an
 * `obsvrGovernTool` wrapper Python has no equivalent of, and its LangChain
 * handler implements a pre-execution `handleToolStart` that Python's does not
 * have at all. Reading one language's grades across to the other is the specific
 * mistake the evaluation notes forbid, so every row here is measured.
 *
 * WHY OFFLINE. Same reason as the Python twin: this catches the CLASS on every
 * commit, cheaply and deterministically, with no provider and no key. Live
 * probing finds what the class does not cover; the two are different
 * instruments and neither substitutes for the other.
 *
 * WHAT MAKES IT MORE THAN A MOCK TEST. Each driver's ORDERING models what the
 * framework was observed to do:
 *
 * - `obsvrGovernTool` and MCP both wrap the invocation itself, so the driver
 *   calls the governed function and lets the gate decide whether the spy runs.
 * - The trace-processor driver runs the spy BEFORE the span callback, because a
 *   function span ends after its tool has returned — and it models the throw
 *   being SWALLOWED, which that integration's own source documents: the hooks
 *   are invoked fire-and-forget, so a throw there "cannot block anything".
 * - The LangChain driver delivers `handleToolStart` and awaits it, because that
 *   handler sets `awaitHandlers` and `raiseError`, which is what lets a refusal
 *   in a callback actually abort the tool.
 */

import { init, _reset } from '../../src/proxy/config';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as url from 'node:url';
import { getConfig } from '../../src/proxy/config';
import { obsvrGovernTool, _resetGovernedToolNames } from '../../src/integrations/tools';
import { obsvrGovernMCP } from '../../src/integrations/mcp';
import { ObsvrCallbackHandler } from '../../src/integrations/langchain';
import {
  ObsvrTraceProcessor,
  makeToolGateGuardrail,
} from '../../src/integrations/openai-agents';
import { governRunnerTools } from '../../src/proxy/runner-tool-gate';
import type { ResolvedConfig } from '../../src/proxy/types';

const SPY_TOOL = 'send_money';

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

/**
 * ENFORCES      the gate is at the invocation boundary: the spy must NOT run
 *               and the record must claim `blocked`.
 * RECORDS_ONLY  a gate runs but cannot stop the tool. The spy runs, and the
 *               record must NOT claim `blocked`.
 */
type Grade = 'enforces' | 'records_only';

class Spy {
  entries: string[] = [];
  enter(name: string): string {
    this.entries.push(name);
    return `result of ${name}`;
  }
  get entered(): boolean {
    return this.entries.length > 0;
  }
}

interface Outcome {
  spy: Spy;
  events: any[];
  threw?: unknown;
}

function claimsBlocked(o: Outcome): boolean {
  return o.events.some((e) => e.action_taken === 'blocked');
}

function describe_(o: Outcome): string {
  return `spy=${JSON.stringify(o.spy.entries)} verdicts=${JSON.stringify(
    o.events.map((e) => e.action_taken),
  )} operations=${JSON.stringify(o.events.map((e) => e.operation))}`;
}

function assertInvariant(grade: Grade, o: Outcome): void {
  if (grade === 'enforces') {
    expect(o.spy.entered).toBe(false);
    if (o.spy.entered) throw new Error(`denied tool ran: ${describe_(o)}`);
    expect(claimsBlocked(o)).toBe(true);
  } else {
    // The tool ran. If it did not, this surface now enforces and must be
    // regraded rather than quietly left in the weaker row.
    expect(o.spy.entered).toBe(true);
    // THE LIE: a record asserting a refusal of something that executed.
    expect(claimsBlocked(o)).toBe(false);
  }
}

// ── drivers ──────────────────────────────────────────────────────────────────

/** The generic wrapper: gates, then delegates. A real invocation boundary. */
async function driveGovernTool(spy: Spy): Promise<Outcome> {
  const tool = obsvrGovernTool(
    { name: SPY_TOOL, execute: (input: unknown) => spy.enter(SPY_TOOL) },
    { name: SPY_TOOL },
  ) as any;

  let threw: unknown;
  try {
    await tool.execute({ amount: 500 });
  } catch (e) {
    threw = e;
  }
  await settle();
  return { spy, events: sentEvents, threw };
}

/**
 * The trace processor. Ordering is the whole point: the tool has already run by
 * the time a function span ends, and the throw is swallowed by the framework's
 * fire-and-forget processor dispatch.
 */
async function driveTraceProcessor(spy: Spy): Promise<Outcome> {
  const proc: any = new ObsvrTraceProcessor();
  const span = {
    traceId: 'trace-inv-1',
    spanId: 'span-inv-1',
    spanData: { type: 'function', name: SPY_TOOL, input: '{"amount":500}' },
    startedAt: new Date().toISOString(),
    endedAt: new Date().toISOString(),
  };

  spy.enter(SPY_TOOL); // the framework invokes the tool here

  let threw: unknown;
  try {
    await proc.onSpanEnd(span);
  } catch (e) {
    // Recorded, not honoured. In production this is swallowed by the
    // processor dispatch, and the tool above has already run regardless.
    threw = e;
  }
  await settle();
  return { spy, events: sentEvents, threw };
}

/**
 * The LangChain handler on the modern path: `handleToolStart` fires BEFORE the
 * tool, and the handler opts into `awaitHandlers` + `raiseError` so a refusal
 * there aborts rather than being logged and ignored.
 */
async function driveLangChain(spy: Spy): Promise<Outcome> {
  const handler: any = new ObsvrCallbackHandler();
  await handler.handleChainStart(
    { id: ['langchain', 'agents', 'AgentExecutor'] },
    { input: 'move the money' },
    'run-inv-1',
  );

  let threw: unknown;
  try {
    await handler.handleToolStart(
      { id: ['langchain', 'tools', 'DynamicStructuredTool'] },
      '{"amount":500}',
      'tool-inv-1',
      'run-inv-1',
      undefined,
      undefined,
      SPY_TOOL, // runName — the reliable tool name on this path
    );
  } catch (e) {
    threw = e;
    await settle();
    // Refused before the tool: the executor does not proceed.
    return { spy, events: sentEvents, threw };
  }

  spy.enter(SPY_TOOL);
  await handler.handleToolEnd('ok', 'tool-inv-1', 'run-inv-1');
  await settle();
  return { spy, events: sentEvents, threw };
}

/**
 * The openai-agents guardrail gate. The executor awaits each tool's own
 * `inputGuardrails` BEFORE invoking it (@openai/agents-core
 * runner/toolExecution.js, read at 0.13.4 and shape-identical at 0.13.0 and
 * 0.14.2): `rejectContent` means the tool is NOT invoked and the message
 * becomes its model-visible result; `allow` proceeds to invocation. The
 * driver dispatches exactly that contract against obsvr's own guardrail.
 */
async function driveOpenAIAgentsGuardrail(spy: Spy): Promise<Outcome> {
  const guardrail = makeToolGateGuardrail();
  const out = await guardrail.run({
    toolCall: { name: SPY_TOOL, callId: 'call-inv-1', arguments: '{"amount":500}' },
  });
  if (out.behavior.type !== 'rejectContent') {
    spy.enter(SPY_TOOL);
  }
  await settle();
  return { spy, events: sentEvents };
}

/**
 * MCP. The gate precedes `callTool`, which is the actual invocation boundary,
 * and it reads a DIFFERENT config block from every other surface here — pinned
 * in the row so a rename cannot quietly disarm it.
 */
async function driveMcp(spy: Spy): Promise<Outcome> {
  const client = obsvrGovernMCP(
    {
      callTool: async (params: unknown) => {
        // Where the real client would reach the server, so where the tool runs.
        return spy.enter((params as { name: string }).name);
      },
      listTools: async () => ({ tools: [{ name: SPY_TOOL }] }),
    },
    getConfig() as ResolvedConfig,
  ) as { callTool: (p: unknown) => Promise<unknown> };

  let threw: unknown;
  try {
    await client.callTool({ name: SPY_TOOL, arguments: { amount: 500 } });
  } catch (e) {
    threw = e;
  }
  await settle();
  return { spy, events: sentEvents, threw };
}

/**
 * A provider tool runner's tools. The gate is installed on the tool callbacks
 * before the runner is constructed, so the driver has to do what the runner
 * does: take the tools it was handed back and invoke one.
 *
 * The tool entry is the shape one of the two runners really dispatches —
 * `{ name, run }`, resolved by name, callback at the top level. Driving the
 * gate's OUTPUT rather than a hand-built wrapper is the point: a gate that
 * silently declined to wrap this shape is exactly the defect that shipped, and
 * a driver that wrapped the callback itself would have passed straight over it.
 */
async function driveRunnerTools(spy: Spy): Promise<Outcome> {
  const entry = {
    name: SPY_TOOL,
    description: 'moves money',
    input_schema: { type: 'object', properties: {} },
    run: (input: unknown) => spy.enter(SPY_TOOL),
  };
  const { args, report } = governRunnerTools(
    [{ model: 'm', messages: [], tools: [entry] }],
    getConfig() as ResolvedConfig,
    {},
  );
  if (!report.installed) {
    throw new Error(
      `the runner tool gate was not installed, so this row would pass without ` +
        `gating anything: ${JSON.stringify(report)}`,
    );
  }
  const gated = (args[0] as { tools: Array<{ run: (i: unknown) => unknown }> }).tools[0];

  let threw: unknown;
  try {
    await gated.run({ amount: 500 });
  } catch (e) {
    threw = e;
  }
  await settle();
  return { spy, events: sentEvents, threw };
}

// ── the table ────────────────────────────────────────────────────────────────

/**
 * `policyKey` is the config field each surface reads. MCP deliberately reads a
 * different one from the rest, and pinning that here means a rename cannot
 * quietly disarm the gate — the row would go red instead. Same reason the Python
 * table carries it.
 *
 * `source` is the file the gate lives in, and it is what makes coverage itself a
 * test: a file that ships a tool gate without a row here fails the suite.
 */
const TABLE: Array<{
  name: string;
  source: string;
  drive: (spy: Spy) => Promise<Outcome>;
  grade: Grade;
  policyKey: 'agent_policy' | 'mcpToolPolicy';
}> = [
  {
    name: 'mcp',
    source: 'src/integrations/mcp.ts',
    drive: driveMcp,
    grade: 'enforces',
    policyKey: 'mcpToolPolicy',
  },
  {
    name: 'obsvrGovernTool',
    source: 'src/integrations/tools.ts',
    drive: driveGovernTool,
    grade: 'enforces',
    policyKey: 'agent_policy',
  },
  {
    name: 'langchain',
    source: 'src/integrations/langchain.ts',
    drive: driveLangChain,
    grade: 'enforces',
    policyKey: 'agent_policy',
  },
  {
    name: 'provider-tool-runners',
    source: 'src/proxy/runner-tool-gate.ts',
    drive: driveRunnerTools,
    grade: 'enforces',
    policyKey: 'agent_policy',
  },
  {
    name: 'openai-agents',
    source: 'src/integrations/openai-agents.ts',
    drive: driveTraceProcessor,
    grade: 'records_only',
    policyKey: 'agent_policy',
  },
  // Same file, second mechanism: the processor row above stays graded as the
  // audit rail it is; the guardrail is where refusal actually lives.
  {
    name: 'openai-agents:guardrail-gate',
    source: 'src/integrations/openai-agents.ts',
    drive: driveOpenAIAgentsGuardrail,
    grade: 'enforces',
    policyKey: 'agent_policy',
  },
];

describe('blocked implies not executed', () => {
  it.each(TABLE.map((r) => [r.name, r] as const))(
    '%s',
    async (_name, row) => {
      init({
        api_key: 'test',
        sample_rate: 1,
        [row.policyKey]: { deniedTools: [SPY_TOOL] },
      } as any);
      assertInvariant(row.grade, await row.drive(new Spy()));
    },
  );
});

// ── coverage is itself a test ────────────────────────────────────────────────
//
// The table is checked against the tree, not maintained by hand. A new surface
// that ships a tool gate and no row is the shape this whole file exists to catch:
// three of the eight graded surfaces were covered here for a while, which reads
// like a guard and is a sample.

describe('the table covers every tool gate in the tree', () => {
  // ESM: no __dirname. Resolved from this module's own URL so the check works
  // wherever the suite is run from — a path derived from cwd would make this
  // pass vacuously under a different working directory.
  const SRC = path.resolve(path.dirname(url.fileURLToPath(import.meta.url)), '../..');

  /** A file ships a tool gate if it reads the deny list. */
  function shipsAToolGate(rel: string): boolean {
    const full = path.join(SRC, rel);
    if (!fs.existsSync(full)) return false;
    return fs.readFileSync(full, 'utf8').includes('deniedTools');
  }

  function candidateFiles(): string[] {
    const dir = path.join(SRC, 'src/integrations');
    return [
      ...fs
        .readdirSync(dir)
        .filter((f) => f.endsWith('.ts'))
        .map((f) => `src/integrations/${f}`),
      'src/proxy/runner-tool-gate.ts',
    ];
  }

  it('every file that ships a tool gate has a row', () => {
    const graded = new Set(TABLE.map((r) => r.source));
    const ungraded = candidateFiles().filter((f) => shipsAToolGate(f) && !graded.has(f));

    expect(ungraded).toEqual([]);
  });

  it("every row's source still ships the gate it is grading", () => {
    // The other direction. A row pointing at a file that no longer gates
    // anything would keep passing on a driver that gates nothing, which is a
    // green invariant asserting a control that is gone.
    const stale = TABLE.filter((r) => !shipsAToolGate(r.source)).map((r) => r.name);

    expect(stale).toEqual([]);
  });

  it('the surfaces graded as carrying no gate still carry none', () => {
    // Governed per tool through `obsvrGovernTool` instead. If either grows a
    // gate of its own it needs a row here and a regrade in COMPATIBILITY.md and
    // both READMEs — silently gaining one is how a surface ends up ungraded.
    const shouldHaveNoGate = ['src/integrations/llamaindex.ts', 'src/integrations/vercel-ai.ts'];
    const surprises = shouldHaveNoGate.filter(shipsAToolGate);

    expect(surprises).toEqual([]);
  });
});

// ── non-vacuity ──────────────────────────────────────────────────────────────

describe('the invariant can fail', () => {
  it('rejects a fabricated denial', () => {
    const spy = new Spy();
    spy.enter(SPY_TOOL);
    const fabricated: Outcome = {
      spy,
      events: [{ action_taken: 'blocked', operation: 'x.tool' }],
    };

    expect(() => assertInvariant('records_only', fabricated)).toThrow();
  });

  it('rejects a silent refusal', () => {
    // Stopped the tool and recorded nothing: every blocked-call filter misses
    // it, so an operator reviewing refusals never learns it happened.
    const silent: Outcome = { spy: new Spy(), events: [] };

    expect(() => assertInvariant('enforces', silent)).toThrow();
  });

  it('rejects an enforcing surface that let the tool run', async () => {
    // A gate pointed at nothing: policy configured, but naming a different
    // tool, so the governed tool is permitted and the spy runs.
    init({
      api_key: 'test',
      sample_rate: 1,
      agent_policy: { deniedTools: ['something_else'] },
    } as any);
    const outcome = await driveGovernTool(new Spy());

    expect(outcome.spy.entered).toBe(true);
    expect(() => assertInvariant('enforces', outcome)).toThrow();
  });
});

// ── the control that stops every row passing vacuously ───────────────────────

describe('a permitted tool still runs', () => {
  it('obsvrGovernTool lets an unlisted tool through', async () => {
    init({
      api_key: 'test',
      sample_rate: 1,
      agent_policy: { deniedTools: ['something_else'] },
    } as any);
    const outcome = await driveGovernTool(new Spy());

    expect(outcome.spy.entries).toEqual([SPY_TOOL]);
    expect(claimsBlocked(outcome)).toBe(false);
  });

  it('langchain lets an unlisted tool through', async () => {
    init({
      api_key: 'test',
      sample_rate: 1,
      agent_policy: { deniedTools: ['something_else'] },
    } as any);
    const outcome = await driveLangChain(new Spy());

    expect(outcome.spy.entries).toEqual([SPY_TOOL]);
    expect(claimsBlocked(outcome)).toBe(false);
  });

  it('mcp lets an unlisted tool through', async () => {
    init({
      api_key: 'test',
      sample_rate: 1,
      mcpToolPolicy: { deniedTools: ['something_else'] },
    } as any);
    const outcome = await driveMcp(new Spy());

    expect(outcome.spy.entries).toEqual([SPY_TOOL]);
    expect(claimsBlocked(outcome)).toBe(false);
  });

  it('a runner tool the policy does not name still runs', async () => {
    init({
      api_key: 'test',
      sample_rate: 1,
      agent_policy: { deniedTools: ['something_else'] },
    } as any);
    const outcome = await driveRunnerTools(new Spy());

    expect(outcome.spy.entries).toEqual([SPY_TOOL]);
    expect(claimsBlocked(outcome)).toBe(false);
  });
});
