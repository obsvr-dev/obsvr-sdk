/**
 * The tool callbacks a provider tool runner invokes are behind the gate.
 *
 * THE MEASURED DEFECT. A tool runner holds the raw provider client and invokes
 * its tools itself, so pre-call governance ran once on the invocation and every
 * tool the loop executed afterwards ran outside every tool-level control. Driven
 * live before this existed: with the session latch armed and `action: "flag"` —
 * the default, and the composition the latch exists to provide — a session obsvr
 * had already marked tainted executed a tool named in `destructiveTools`.
 *
 * WHAT IS ASSERTED, AND IN WHICH ORDER. The side effect first: a denied tool's
 * own callback records whether it was entered, and that record is the evidence.
 * The event second. Either half alone is a defect that already shipped on this
 * codebase — a gate that refuses without recording, or a record of a refusal
 * that did not happen.
 *
 * EVERY DENIAL HAS A CONTROL. A callback that did not run proves nothing until
 * the same callback is shown running with the policy off, so each refusal here is
 * paired with a policy-off cell using the same tool and the same shape.
 *
 * The tool-entry shapes are taken from installed provider packages, not invented:
 * the nested `{ type: "function", function: { function } }` runnable, the schema
 * helper's `$callback`, and the top-level `run` the other runner dispatches.
 */
import { init, getConfig, _reset } from '../../src/proxy/config';
import { _resetSender, flushQueue } from '../../src/proxy/sender/fire-and-forget';
import { governRunnerTools } from '../../src/proxy/runner-tool-gate';
import { markTainted, _resetSessionTaint } from '../../src/policy/session-taint';
import type { ResolvedConfig } from '../../src/proxy/types';

const realFetch = globalThis.fetch;
let sentEvents: Record<string, unknown>[] = [];

beforeEach(() => {
  _reset();
  _resetSender();
  _resetSessionTaint();
  sentEvents = [];
  globalThis.fetch = (async (_url: unknown, opts?: { body?: string }) => {
    const body = JSON.parse(opts?.body ?? '[]');
    sentEvents.push(...(Array.isArray(body) ? body : [body]));
    return { status: 200, ok: true, json: async () => ({ count: 1 }) };
  }) as unknown as typeof fetch;
});

afterEach(() => {
  globalThis.fetch = realFetch;
});

// ── the three tool-entry shapes, each with a callback that records entry ──────

function openaiRunnable(name: string, entered: string[]) {
  return {
    type: 'function',
    function: {
      name,
      description: `${name} tool`,
      parameters: { type: 'object', properties: {} },
      function: (args: unknown) => {
        entered.push(name);
        return `ran ${name} with ${JSON.stringify(args)}`;
      },
    },
  };
}

function openaiAutoParseable(name: string, entered: string[]) {
  return {
    type: 'function',
    function: { name, parameters: {}, strict: true },
    $brand: 'auto-parseable-tool',
    $callback: (args: unknown) => {
      entered.push(name);
      return `ran ${name} with ${JSON.stringify(args)}`;
    },
    $parseRaw: (raw: string) => JSON.parse(raw),
  };
}

function anthropicRunnable(name: string, entered: string[]) {
  return {
    name,
    description: `${name} tool`,
    input_schema: { type: 'object', properties: {} },
    run: (input: unknown) => {
      entered.push(name);
      return `ran ${name} with ${JSON.stringify(input)}`;
    },
  };
}

/** The one place the gated callback is actually invoked, per shape. */
function invoke(entry: Record<string, unknown>, input: unknown): unknown {
  if (typeof entry.$callback === 'function') {
    return (entry.$callback as (a: unknown) => unknown)(input);
  }
  const inner = entry.function as Record<string, unknown> | undefined;
  if (inner && typeof inner.function === 'function') {
    return (inner.function as (a: unknown) => unknown)(input);
  }
  return (entry.run as (a: unknown) => unknown)(input);
}

/** Init with one extra config block, and hand back the resolved config. */
function configWith(extra: Record<string, unknown> = {}): ResolvedConfig {
  init({
    api_key: 'test',
    sample_rate: 1,
    ingest_url: 'https://sink.invalid/v1',
    ...extra,
  } as never);
  return getConfig() as ResolvedConfig;
}

function cfg(): ResolvedConfig {
  return configWith();
}

function gate(config: ResolvedConfig, tools: unknown[], metadata: Record<string, unknown> = {}) {
  const args = [{ model: 'm', messages: [{ role: 'user', content: 'hi' }], tools }];
  return governRunnerTools(args, config, { metadata });
}

function gatedTools(result: ReturnType<typeof gate>): Record<string, unknown>[] {
  return (result.args[0] as { tools: Record<string, unknown>[] }).tools;
}

const blockedEvents = () =>
  sentEvents.filter((e) => (e.compliance as Record<string, unknown>)?.action_taken === 'blocked'
    || e.action_taken === 'blocked');

// ── a denied tool's callback does not run, on every shape ────────────────────

describe.each([
  ['openai runnable', openaiRunnable],
  ['openai schema helper', openaiAutoParseable],
  ['anthropic runnable', anthropicRunnable],
])('%s', (_label, make) => {
  it('refuses a denied tool before its callback is entered', () => {
    const entered: string[] = [];
    const config = configWith({ agent_policy: { deniedTools: ['send_money'] } });

    const result = gate(config, [make('send_money', entered)]);
    expect(result.report.installed).toBe(true);
    expect(result.report.gated).toEqual(['send_money']);

    expect(() => invoke(gatedTools(result)[0], { amount: 500 })).toThrow(
      /Tool blocked by agent policy: send_money/,
    );
    expect(entered).toEqual([]);
  });

  it('CONTROL: the same callback runs with no policy naming it', () => {
    const entered: string[] = [];
    const config = configWith({ agent_policy: { deniedTools: ['something_else'] } });

    const result = gate(config, [make('send_money', entered)]);
    // The gate IS installed here — otherwise this control would pass because
    // nothing was gating, which proves nothing about the refusal above.
    expect(result.report.installed).toBe(true);
    expect(invoke(gatedTools(result)[0], { amount: 500 })).toContain('ran send_money');
    expect(entered).toEqual(['send_money']);
  });
});

// ── the measured case: destructiveTools under the DEFAULT flag action ────────

describe('a tainted session under action: "flag"', () => {
  function taintCfg() {
    return configWith({ sessionTaint: { enabled: true, action: 'flag', destructiveTools: ['send_money'] } });
  }

  it('loses its destructive capability instead of executing it', () => {
    const entered: string[] = [];
    const config = taintCfg();
    markTainted('u-1', 'prompt_injection', Date.now());

    const result = gate(config, [anthropicRunnable('send_money', entered)], { user_id: 'u-1' });

    expect(() => invoke(gatedTools(result)[0], { amount: 500 })).toThrow(/obsvr/);
    expect(entered).toEqual([]);
  });

  it('CONTROL: an UNTAINTED session executes the same tool', () => {
    const entered: string[] = [];
    const config = taintCfg();
    markTainted('someone-else', 'prompt_injection', Date.now());

    const result = gate(config, [anthropicRunnable('send_money', entered)], { user_id: 'u-1' });

    expect(result.report.installed).toBe(true);
    expect(invoke(gatedTools(result)[0], { amount: 500 })).toContain('ran send_money');
    expect(entered).toEqual(['send_money']);
  });

  it('CONTROL: a tainted session keeps a NON-destructive tool', () => {
    const entered: string[] = [];
    const config = taintCfg();
    markTainted('u-1', 'prompt_injection', Date.now());

    const result = gate(config, [anthropicRunnable('get_weather', entered)], { user_id: 'u-1' });

    expect(result.report.installed).toBe(true);
    expect(invoke(gatedTools(result)[0], { city: 'NYC' })).toContain('ran get_weather');
    expect(entered).toEqual(['get_weather']);
  });

  it('keys the latch on the identity the wrapper resolved, not on a fresh guess', () => {
    // THE DIVERGENCE TRAP. `deriveSessionKey`'s own contract is that SET and
    // ENFORCE must agree on the identity or the latch silently no-ops. The
    // runner path is a second egress point, so it is handed the identity
    // metadata the invocation already resolved rather than resolving it again.
    // Keyed on the wrong channel this test still passes the tool through and
    // nothing throws — which is why it is here.
    const entered: string[] = [];
    const config = taintCfg();
    markTainted('tenant-9', 'canary_leak', Date.now());

    const result = gate(config, [anthropicRunnable('send_money', entered)], {
      tenant_id: 'tenant-9',
    });

    expect(() => invoke(gatedTools(result)[0], { amount: 1 })).toThrow(/obsvr/);
    expect(entered).toEqual([]);
  });
});

// ── the report, and what it is for ──────────────────────────────────────────

describe('the gate report', () => {
  it('is not installed when no tool-level control is configured', () => {
    const config = cfg();
    const entered: string[] = [];
    const result = gate(config, [openaiRunnable('send_money', entered)]);

    expect(result.report).toEqual({
      installed: false,
      gated: [],
      ungatable: [],
      reason: 'no_tool_control_configured',
    });
    // Untouched by identity: a deployment that configured nothing gets exactly
    // the arguments it passed, and no per-tool event recording a verdict it
    // never asked for.
    expect(invoke(gatedTools(result)[0], {})).toContain('ran send_money');
    expect(entered).toEqual(['send_money']);
  });

  it('names a tool it could not gate rather than counting it', () => {
    const config = configWith({ agent_policy: { deniedTools: ['x'] } });
    const entered: string[] = [];

    // A hosted tool the provider executes on its own infrastructure carries no
    // local callback. It is genuinely not on this boundary, and the report says
    // WHICH tool that is — "some tools are ungated" is not actionable.
    const result = gate(config, [
      { type: 'web_search_20250305', name: 'web_search' },
      anthropicRunnable('send_money', entered),
    ]);

    expect(result.report.installed).toBe(true);
    expect(result.report.gated).toEqual(['send_money']);
    expect(result.report.ungatable).toEqual(['web_search']);
  });

  it('reports no gateable tool when every entry is hosted', () => {
    const config = configWith({ agent_policy: { deniedTools: ['x'] } });

    const result = gate(config, [{ type: 'web_search_20250305', name: 'web_search' }]);
    expect(result.report.installed).toBe(false);
    expect(result.report.reason).toBe('no_gateable_tool');
  });
});

// ── the caller's own objects are not written to ──────────────────────────────

describe('the caller keeps its request', () => {
  it('does not mutate the tools array or the entries in it', () => {
    const config = configWith({ agent_policy: { deniedTools: ['send_money'] } });

    const entered: string[] = [];
    const entry = anthropicRunnable('send_money', entered);
    const originalRun = entry.run;
    const tools = [entry];
    const args = [{ model: 'm', tools }];

    const result = governRunnerTools(args, config, {});

    expect(result.args).not.toBe(args);
    expect(result.args[0]).not.toBe(args[0]);
    expect((result.args[0] as { tools: unknown[] }).tools).not.toBe(tools);
    expect(tools[0]).toBe(entry);
    expect(entry.run).toBe(originalRun);

    // And the caller's own copy still runs, because it was never gated.
    expect(entry.run({ amount: 1 })).toContain('ran send_money');
    expect(entered).toEqual(['send_money']);
  });

  it('leaves a request carrying no tools completely alone', () => {
    const config = configWith({ agent_policy: { deniedTools: ['x'] } });

    const args = [{ model: 'm', messages: [] }];
    const result = governRunnerTools(args, config, {});
    expect(result.args).toBe(args);
    expect(result.report.reason).toBe('no_tools_in_request');
  });
});

// ── the refusal is recorded, not merely performed ────────────────────────────

describe('the record', () => {
  it('emits a blocked tool event naming the refused tool', async () => {
    const config = configWith({ agent_policy: { deniedTools: ['send_money'] } });
    const entered: string[] = [];

    const result = gate(config, [anthropicRunnable('send_money', entered)]);
    expect(() => invoke(gatedTools(result)[0], { amount: 500 })).toThrow();

    await new Promise((r) => setTimeout(r, 10));
    await flushQueue(config);

    const blocked = blockedEvents();
    expect(blocked.length).toBeGreaterThan(0);
    const meta = blocked[0].metadata as Record<string, unknown>;
    expect(meta.tool_name).toBe('send_money');
  });
});
