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
import { obsvrGovernTool } from '../../src/integrations/tools';
import { ObsvrCallbackHandler } from '../../src/integrations/langchain';
import { ObsvrTraceProcessor } from '../../src/integrations/openai-agents';

const SPY_TOOL = 'send_money';

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

// ── the table ────────────────────────────────────────────────────────────────

const TABLE: Array<{
  name: string;
  drive: (spy: Spy) => Promise<Outcome>;
  grade: Grade;
}> = [
  { name: 'obsvrGovernTool', drive: driveGovernTool, grade: 'enforces' },
  { name: 'langchain', drive: driveLangChain, grade: 'enforces' },
  { name: 'openai-agents', drive: driveTraceProcessor, grade: 'records_only' },
];

describe('blocked implies not executed', () => {
  it.each(TABLE.map((r) => [r.name, r] as const))(
    '%s',
    async (_name, row) => {
      init({
        api_key: 'test',
        sample_rate: 1,
        agent_policy: { deniedTools: [SPY_TOOL] },
      } as any);
      assertInvariant(row.grade, await row.drive(new Spy()));
    },
  );
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
});
