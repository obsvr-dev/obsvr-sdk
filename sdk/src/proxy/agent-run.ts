/**
 * Agent-run context — the run-lifecycle counterpart to the span primitive.
 *
 * An "agent run" is one agentic execution: a top-level agent invocation that
 * fans out into LLM calls, tool calls, retrievals, and sub-steps. The dashboard
 * groups these into a single row in the Runs tab, keyed on `agent_run_id`, and
 * the ingest run aggregator marks a run complete when it sees the terminal
 * `*.agent.run.finish` operation.
 *
 * Two integration styles already produce runs by threading an `agent_run_id`
 * through their own lifecycle callbacks (LangChain's ObsvrCallbackHandler,
 * the OpenAI-Agents trace processor). Frameworks that are governed at the TOOL
 * level instead (via `obsvrGovernTool` — LlamaIndex, Vercel AI) have no
 * run-lifecycle hook, so their events carried no `agent_run_id` and never
 * formed a run.
 *
 * This module supplies the missing, framework-agnostic piece: a developer-
 * declared run SCOPE. Wrap the agent invocation in `agentRun(...)` (see
 * integrations/agent-run.ts) and every governed action inside it — LLM calls,
 * tool calls, spans — auto-joins the run via the ambient context read here.
 *
 * Design mirrors span.ts: an AsyncLocalStorage scope, deterministic parent
 * links (never inferred), additive transport (the run id rides event metadata,
 * so the signed schema and its conformance fixtures are untouched). This file
 * holds only the PURE context (no event emission, no config/sender imports) so
 * both the proxy builder and the integration builder can read it without an
 * import cycle.
 *
 * @packageDocumentation
 */

import { AsyncLocalStorage } from "node:async_hooks";
import { randomUUID } from "node:crypto";

/** The ambient agent run for the current async context. */
export interface AgentRunContext {
  /** Stable id for the whole run; becomes `agent_run_id` on every event. */
  run_id: string;
  /** Integration/source label, e.g. "llamaindex_ts", "vercel_ai", "agent". */
  source: string;
  /** Human-readable run name (the agent/task name). */
  name: string;
}

const storage = new AsyncLocalStorage<AgentRunContext>();

/** Generate a fresh run id. */
export function generateRunId(): string {
  return randomUUID();
}

/** The enclosing agent run, if an `agentRun` scope is active. */
export function currentAgentRun(): AgentRunContext | undefined {
  return storage.getStore();
}

/** The enclosing run's id, if any. */
export function currentAgentRunId(): string | undefined {
  return storage.getStore()?.run_id;
}

/**
 * Run `fn` with `ctx` bound as the ambient agent run. Nested scopes keep the
 * OUTERMOST run id (a sub-agent's calls still belong to the enclosing run)
 * unless a caller explicitly opens a new run — the integration helper decides
 * that policy; this raw runner just binds whatever context it is given.
 */
export function withAgentRunContext<T>(ctx: AgentRunContext, fn: () => T): T {
  return storage.run(ctx, fn);
}

/**
 * Stamp `agent_run_id` onto an event's metadata from the ambient run, when one
 * is active and the caller has not already set it (an integration that manages
 * its own run id — LangChain, OpenAI-Agents — always wins). Additive and
 * non-destructive: returns the metadata unchanged when no run is active, so
 * events outside any run scope are byte-identical to before.
 */
export function withRunMetadata(
  metadata: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  const run = storage.getStore();
  if (!run) return metadata;
  if (metadata && "agent_run_id" in metadata && metadata.agent_run_id != null) {
    return metadata;
  }
  return { ...(metadata ?? {}), agent_run_id: run.run_id };
}
