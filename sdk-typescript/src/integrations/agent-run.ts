/**
 * `agentRun(name, fn)` — the public, framework-agnostic agent-run scope.
 *
 * Wrap a top-level agent invocation so it forms ONE run in the dashboard's Runs
 * tab, with every governed action inside it (LLM calls, tool calls via
 * `obsvrGovernTool`, spans) grouped under the same `agent_run_id`:
 *
 *   await obsvr.agentRun("support-agent", () => agent.run(userMessage), {
 *     source: "llamaindex_ts",
 *   });
 *
 * It emits a signed `<source>.agent.run.start` on entry and a terminal
 * `<source>.agent.run.finish` on completion (success or failure) — the exact
 * operations the ingest run aggregator keys on — and binds an ambient run
 * context (proxy/agent-run.ts) that the event builders read to stamp
 * `agent_run_id` automatically. Deterministic and developer-declared: the run
 * boundary is this explicit scope, never inferred.
 *
 * Integrations that already manage their own run lifecycle (LangChain's
 * callback handler, the OpenAI-Agents trace processor) do NOT need this — they
 * thread their own `agent_run_id` and it always wins over the ambient one.
 *
 * @packageDocumentation
 */

import { tryGetConfig, emitIntegrationEvent } from "./core.js";
import { withSpan } from "../proxy/span.js";
import {
  withAgentRunContext,
  generateRunId,
  type AgentRunContext,
} from "../proxy/agent-run.js";

const DEFAULT_SOURCE = "agent";

export interface AgentRunOptions {
  /** Source/framework label stamped on run events and used for the operation
   *  prefix, e.g. "llamaindex_ts", "vercel_ai". Defaults to "agent". */
  source?: string;
  /** Explicit run id. Defaults to a fresh UUID. Pass your framework's own run
   *  / conversation id to align this run with external traces. */
  run_id?: string;
}

function emitRunEvent(
  source: string,
  runId: string,
  name: string,
  phase: "start" | "finish",
  ok: boolean,
): void {
  const config = tryGetConfig();
  if (!config) return;
  emitIntegrationEvent({
    config,
    provider: "unknown",
    model: "unknown",
    operation: `${source}.agent.run.${phase}`,
    source,
    prompt: "",
    response: "",
    success: ok,
    metadata: { agent_run_id: runId, agent_run_name: name },
  });
}

/**
 * Run `fn` as one agent run. Works with sync and async `fn`. Returns whatever
 * `fn` returns. On a thrown/rejected `fn`, emits the terminal finish event with
 * success=false and re-throws the original error unchanged.
 */
export function agentRun<T>(
  name: string,
  fn: () => T,
  opts: AgentRunOptions = {},
): T {
  const source = opts.source || DEFAULT_SOURCE;
  const runId = opts.run_id || generateRunId();
  const ctx: AgentRunContext = { run_id: runId, source, name };

  emitRunEvent(source, runId, name, "start", true);

  const finish = (ok: boolean): void => emitRunEvent(source, runId, name, "finish", ok);

  // Bind the ambient run AND a span scope carrying trace_id = runId, so spans
  // and governed calls inside also group by trace, exactly like withSpan.
  return withAgentRunContext(ctx, () =>
    withSpan(name, "agent", () => {
      let result: T;
      try {
        result = fn();
      } catch (e) {
        finish(false);
        throw e;
      }
      if (result && typeof (result as { then?: unknown }).then === "function") {
        return (result as unknown as Promise<unknown>).then(
          (v) => {
            finish(true);
            return v;
          },
          (e) => {
            finish(false);
            throw e;
          },
        ) as unknown as T;
      }
      finish(true);
      return result;
    }, { trace_id: runId }),
  );
}
