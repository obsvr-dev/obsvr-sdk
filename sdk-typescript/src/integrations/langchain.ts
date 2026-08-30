/**
 * LangChain JS Integration
 *
 * Duck-typed callback handler compatible with LangChain JS
 * `CallbackHandlerMethods` - no hard dependency on `@langchain/core`.
 * Pass an instance via `callbacks: [...]` on any model/chain.
 *
 * Enforcing for LLM calls: LangChain awaits model-start callbacks before it
 * enters the model implementation. With `raiseError = true`, a policy refusal
 * propagates out of the callback and the provider dispatch never runs.
 * LangChain does not provide a stable API for replacing provider-bound prompt
 * values from a callback, so a requested redaction that cannot be applied is
 * resolved closed rather than forwarding the original content.
 *
 * Agent-level tracing: handleChainStart/End/Error track AgentExecutor runs
 * and enforce agentPolicy (tool restrictions, step limits, output controls).
 * handleAgentAction and handleToolEnd/Error capture individual tool calls.
 *
 * @example
 * ```ts
 * import { obsvr } from "@obsvr/sdk";
 * import { ObsvrCallbackHandler } from "@obsvr/sdk/langchain";
 *
 * obsvr.init({ apiKey: "..." });
 * const model = new ChatOpenAI({
 *   callbacks: [new ObsvrCallbackHandler()],
 * });
 * ```
 *
 * @packageDocumentation
 */

// Interception: LangChain callback API (non-mutating). Pass new ObsvrCallbackHandler() via callbacks:[...] - no LangChain internals are modified.

import {
  applyLoopDetection,
  applyDelegationPolicy,
  applyPreCallPolicy,
  blockedCallError,
  blockedPromptForStorage,
  blockedUserInputForStorage,
  createLoopDetector,
  createDelegationTracker,
  emitIntegrationEvent,
  inferProviderFromString,
  monitorModeRequiresEvidence,
  setupExitHandlers,
  shouldSample,
  tryGetConfig,
  type ComplianceInfo,
  type IntegrationOptions,
  type IntegrationProvider,
} from "./core.js";
import { ObsvrPolicyError } from "../policy/policy-error.js";
import type { AgentPolicy } from "../proxy/types.js";
import type { LoopDetector } from "../policy/industry/devops.js";
import type { DelegationTracker } from "../policy/industry/agentic.js";
import { ReasonCode } from "../governance/reason-codes.js";
import { emitSpan } from "../proxy/span.js";
import { SPAN_ATTR } from "../proxy/span-attributes.js";
import { createHash, randomUUID } from "node:crypto";

const SOURCE = "langchain_js";

/** Verdict for a policy-blocked tool/step, so it reads as BLOCKED (not the
 *  default "allowed"/"llm_call"). */
const BLOCKED_COMPLIANCE: ComplianceInfo = {
  event_type: "blocked_call",
  policy_version: "none",
  action_taken: "blocked",
  action_reason: "policy_violation",
  action_source: "policy_rules",
  redacted_types: [],
  blocked_types: [],
};

/** Verdict for an allowed tool call (typed as tool_call, not llm_call). */
const TOOL_CALL_COMPLIANCE: ComplianceInfo = {
  event_type: "tool_call",
  policy_version: "none",
  action_taken: "allowed",
  action_reason: "none",
  action_source: "policy_rules",
  redacted_types: [],
  blocked_types: [],
};

/** In-flight retriever invocation, keyed by LangChain runId. */
interface RetrievalState {
  startTime: number;
  source: string;
  queryHash: string;
  /** Enclosing agent run id, when resolvable — links the span into the run's trace. */
  agentRunId?: string;
}

interface RunState {
  prompt: string;
  userText: string;
  model: string;
  provider: IntegrationProvider;
  startTime: number;
  compliance: ComplianceInfo;
  /** Sampled in, OR the policy acted — governed calls are always recorded. */
  auditThisCall: boolean;
  agentRunId?: string;
  floorTelemetry?: Record<string, unknown>;
}

interface AgentRunState {
  agentRunId: string;
  startTime: number;
  stepCount: number;
  loopDetector?: LoopDetector;
  delegationTracker?: DelegationTracker;
}

/** Duck-typed LangChain "Serialized" shape */
interface SerializedLike {
  id?: string[];
  name?: string;
  kwargs?: Record<string, unknown>;
}

/** Duck-typed AgentAction shape */
interface AgentActionLike {
  tool?: string;
  toolInput?: unknown;
  log?: string;
}

function messageText(msg: unknown): string {
  if (!msg || typeof msg !== "object") return "";
  const m = msg as Record<string, unknown>;
  if (typeof m.content === "string") return m.content;
  if (Array.isArray(m.content)) {
    return (m.content as Record<string, unknown>[])
      .map((p) => (typeof p.text === "string" ? p.text : ""))
      .filter((t) => t.length > 0)
      .join(" ");
  }
  return "";
}

function messageRole(msg: unknown): string {
  if (!msg || typeof msg !== "object") return "unknown";
  const m = msg as Record<string, unknown>;
  if (typeof (m as { _getType?: () => string })._getType === "function") {
    try {
      return (m as { _getType: () => string })._getType();
    } catch {
      /* fall through */
    }
  }
  if (typeof m.role === "string") return m.role;
  if (typeof m.type === "string") return m.type;
  return "unknown";
}

function extractModelName(
  serialized: SerializedLike | undefined,
  extraParams: Record<string, unknown> | undefined,
  metadata: Record<string, unknown> | undefined,
): string {
  const invocation = extraParams?.invocation_params as
    | Record<string, unknown>
    | undefined;
  if (invocation && typeof invocation.model === "string") {
    return invocation.model;
  }
  if (metadata && typeof metadata.ls_model_name === "string") {
    return metadata.ls_model_name;
  }
  const kwargsModel = serialized?.kwargs?.model;
  if (typeof kwargsModel === "string") return kwargsModel;
  const id = serialized?.id;
  if (Array.isArray(id) && id.length > 0) return String(id[id.length - 1]);
  return "unknown";
}

function inferProvider(
  serialized: SerializedLike | undefined,
): IntegrationProvider {
  const id = Array.isArray(serialized?.id) ? serialized.id.join(".") : "";
  const name = serialized?.name ?? "";
  return inferProviderFromString(`${id}.${name}`);
}

/**
 * Provider-RESOLVED model snapshot for temporal provenance. LangChain surfaces
 * the serving model (e.g. `gpt-4o-2024-08-06`) on the generation's
 * `response_metadata.model_name` / `generationInfo.model_name`, or on
 * `llmOutput.model_name`. Undefined when the provider does not report it.
 */
function extractResolvedModel(
  firstGeneration: Record<string, unknown> | undefined,
  llmOutput: Record<string, unknown> | undefined,
): string | undefined {
  const str = (v: unknown): string | undefined =>
    typeof v === "string" && v.trim().length > 0 ? v.trim() : undefined;
  const message = firstGeneration?.message as Record<string, unknown> | undefined;
  const respMeta = message?.response_metadata as Record<string, unknown> | undefined;
  const genInfo = firstGeneration?.generationInfo as Record<string, unknown> | undefined;
  return (
    str(respMeta?.model_name) ??
    str(respMeta?.model) ??
    str(genInfo?.model_name) ??
    str(genInfo?.model) ??
    str(llmOutput?.model_name) ??
    str(llmOutput?.model)
  );
}

// The ancestry map is fed by chain starts and drained by chain ends. A caller
// that abandons a stream mid-run leaves ends undelivered, so it is bounded
// rather than trusted to drain.
const MAX_TRACKED_CHAINS = 4096;
const MAX_ANCESTRY_HOPS = 64;

function isAgentChain(
  chain: SerializedLike | undefined,
  tags: string[] | undefined,
): boolean {
  const idStr = Array.isArray(chain?.id) ? chain.id.join(".").toLowerCase() : "";
  if (idStr.includes("agentexecutor") || idStr.includes("agent")) return true;
  // LangGraph compiled graphs serialize as langgraph.pregel.Pregel (no
  // "agent" substring) - detect them so run tracking + step limits engage.
  if (idStr.includes("langgraph") || idStr.includes("pregel")) return true;
  const name = (chain?.name ?? "").toLowerCase();
  if (name.includes("agent") || name.includes("langgraph")) return true;
  if (Array.isArray(tags) && tags.some((t) => String(t).toLowerCase() === "agent")) {
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Agent policy helpers
// ---------------------------------------------------------------------------

function checkTool(
  toolName: string,
  policy: AgentPolicy,
): { allowed: boolean; reason: string } {
  const denied = policy.deniedTools ?? [];
  const allowed = policy.allowedTools; // undefined = all allowed
  if (denied.includes(toolName)) return { allowed: false, reason: "tool_denied" };
  if (allowed !== undefined && !allowed.includes(toolName)) {
    return { allowed: false, reason: "tool_not_in_allowlist" };
  }
  return { allowed: true, reason: "" };
}

function checkSteps(
  count: number,
  policy: AgentPolicy,
): "allow" | "block" | "escalate" {
  const limit = policy.maxSteps;
  if (limit === undefined) return "allow";
  return count < limit ? "allow" : (policy.stepLimitAction ?? "block");
}

function generateRunId(): string {
  return randomUUID();
}

/**
 * LangChain JS callback handler that audits LLM calls.
 * Implements the subset of CallbackHandlerMethods we need; LangChain
 * accepts plain handler objects in `callbacks: [...]`.
 */
export class ObsvrCallbackHandler {
  readonly name = "obsvr_audit_handler";
  // BaseCallbackHandler-compatible flags
  ignoreLLM = false;
  ignoreChain = false;
  ignoreAgent = false;
  ignoreRetriever = false;
  // Await handlers and re-raise their errors so a policy BLOCK in a pre-tool
  // hook (handleToolStart / handleAgentAction) actually aborts the tool
  // instead of being logged-and-ignored. Every handler method internally
  // catches and swallows non-"[obsvr]" errors, so raiseError only ever
  // propagates deliberate policy blocks — never obsvr's own internal errors
  // or unrelated app noise. Without these two flags, LangChain treats
  // callbacks as fire-and-forget observation and tool-deny cannot enforce.
  awaitHandlers = true;
  raiseError = true;

  private readonly opts: IntegrationOptions;
  private readonly runs = new Map<string, RunState>();
  private readonly _agentRuns = new Map<string, AgentRunState>();
  private readonly _retrievals = new Map<string, RetrievalState>();
  // Tool calls the legacy agent-action callback has already ruled on, keyed by
  // the run it arrived on. Both pre-tool callbacks reach one gate and a runtime
  // delivering BOTH for one tool call must be charged once, so the second
  // delivery is discounted — but the discount has to be a per-call credit, not
  // a flag. As a flag it was set the first time handleAgentAction fired and read
  // forever after, so every later handleToolStart returned before the gate. That
  // is a fail-open rather than a double-charge, and `copy()` below returns
  // `this`, so it spread to every child manager and every later run.
  private readonly _actionGated = new Map<string, number>();
  // runId -> parentRunId for every chain run seen. A callback is handed its
  // IMMEDIATE parent only; under the graph runtimes a tool's immediate parent is
  // the node that dispatched it, so the credit has to be findable further up.
  // Rebuildable because every node traces its own chain start.
  private readonly _chainParents = new Map<string, string | undefined>();

  constructor(opts: IntegrationOptions = {}) {
    this.opts = opts;
    const config = tryGetConfig();
    if (config) setupExitHandlers(config);
  }

  /**
   * Deliberately the same instance, not a clone: the run state this handler
   * keeps has to survive being handed to every child callback manager, and a
   * per-manager copy would lose the run a tool call belongs to. That makes
   * every field above shared across the whole tree, which is why none of them
   * may be a process-wide flag — they are keyed by run id instead.
   */
  copy(): ObsvrCallbackHandler {
    return this;
  }

  // -- run ancestry ---------------------------------------------------------

  /** Record one chain edge, bounded so an abandoned stream cannot grow it. */
  private rememberParent(runId: string, parentRunId?: string): void {
    if (this._chainParents.size >= MAX_TRACKED_CHAINS) {
      let dropped = 0;
      for (const key of this._chainParents.keys()) {
        this._chainParents.delete(key);
        if (++dropped >= MAX_TRACKED_CHAINS / 4) break;
      }
    }
    this._chainParents.set(runId, parentRunId);
  }

  private forgetRun(runId: string): void {
    this._chainParents.delete(runId);
    this._actionGated.delete(runId);
  }

  /**
   * Whether the legacy callback already ruled on THIS tool call. Credited per
   * call and spent per call, walking up the recorded ancestry because the tool
   * run is not a direct child of the run the credit was granted on.
   */
  private consumeActionGate(runId: string, parentRunId?: string): boolean {
    for (const start of [parentRunId, runId]) {
      let key: string | undefined = start;
      let hops = 0;
      while (key !== undefined && hops < MAX_ANCESTRY_HOPS) {
        const pending = this._actionGated.get(key) ?? 0;
        if (pending > 0) {
          this._actionGated.set(key, pending - 1);
          return true;
        }
        key = this._chainParents.get(key);
        hops += 1;
      }
    }
    return false;
  }

  // -- agent chain start / end / error -------------------------------------

  async handleChainStart(
    chain: SerializedLike,
    inputs: Record<string, unknown>,
    runId: string,
    parentRunId?: string,
    extraParams?: Record<string, unknown>,
    tags?: string[],
  ): Promise<void> {
    // Recorded for EVERY chain, not only agent chains: the edges between a tool
    // call and the run it belongs to run through ordinary nodes.
    this.rememberParent(runId, parentRunId);
    if (!isAgentChain(chain, tags)) return;
    try {
      const config = tryGetConfig();
      if (!config) return;

      const agentRunId = generateRunId();
      const agentPolicy = config.agentPolicy;
      const agentState: AgentRunState = {
        agentRunId,
        startTime: performance.now(),
        stepCount: 0,
      };
      if (agentPolicy?.loopDetection) {
        agentState.loopDetector = createLoopDetector(agentPolicy.loopDetection);
      }
      if (agentPolicy?.delegationPolicy) {
        agentState.delegationTracker = createDelegationTracker(agentPolicy.delegationPolicy);
      }
      this._agentRuns.set(runId, agentState);

      emitIntegrationEvent({
        config,
        provider: "unknown",
        model: "unknown",
        operation: "langchain.agent.run.start",
        source: SOURCE,
        prompt: "",
        response: "",
        metadata: { agent_run_id: agentRunId },
        options: this.opts,
      });
    } catch {
      // Never throw inside a framework callback
    }
  }

  async handleChainEnd(
    outputs: Record<string, unknown>,
    runId: string,
  ): Promise<void> {
    this.forgetRun(runId);
    const agentState = this._agentRuns.get(runId);
    if (!agentState) return;
    this._agentRuns.delete(runId);

    try {
      const config = tryGetConfig();
      if (!config) return;

      const agentPolicy = config.agentPolicy;
      const deniedTopics = agentPolicy?.outputPolicy?.deniedTopics ?? [];

      let outputText = "";
      if (outputs && typeof outputs === "object") {
        for (const key of ["output", "result", "text", "answer"]) {
          if (typeof (outputs as Record<string, unknown>)[key] === "string") {
            outputText = (outputs as Record<string, string>)[key];
            break;
          }
        }
      }
      if (!outputText) outputText = outputs ? String(outputs) : "";

      const blockedTopic = deniedTopics.find((t) =>
        outputText.toLowerCase().includes(t.toLowerCase()),
      );

      if (blockedTopic) {
        emitIntegrationEvent({
          config,
          provider: "unknown",
          model: "unknown",
          operation: "langchain.agent.policy.output_blocked",
          source: SOURCE,
          prompt: "",
          response: outputText,
          success: false,
          metadata: {
            agent_run_id: agentState.agentRunId,
            blocked_topic: blockedTopic,
          },
          options: this.opts,
        });
        throw new Error("[obsvr] Output blocked by agent policy");
      }

      emitIntegrationEvent({
        config,
        provider: "unknown",
        model: "unknown",
        operation: "langchain.agent.run.finish",
        source: SOURCE,
        prompt: "",
        response: outputText,
        latencyMs: Math.round(performance.now() - agentState.startTime),
        metadata: { agent_run_id: agentState.agentRunId },
        options: this.opts,
      });
    } catch (err) {
      if (err instanceof Error && err.message.startsWith("[obsvr]")) throw err;
      // Never throw non-policy errors inside a framework callback
    }
  }

  async handleChainError(error: unknown, runId: string): Promise<void> {
    this.forgetRun(runId);
    const agentState = this._agentRuns.get(runId);
    if (!agentState) return;
    this._agentRuns.delete(runId);

    try {
      const config = tryGetConfig();
      if (!config) return;

      emitIntegrationEvent({
        config,
        provider: "unknown",
        model: "unknown",
        operation: "langchain.agent.run.finish",
        source: SOURCE,
        prompt: "",
        response: "",
        success: false,
        error,
        latencyMs: Math.round(performance.now() - agentState.startTime),
        metadata: { agent_run_id: agentState.agentRunId },
        options: this.opts,
      });
    } catch {
      // Never throw inside a framework callback
    }
  }

  // -- agent actions (tool calls) ------------------------------------------

  /**
   * Gate + record one tool call: allow/deny (agentPolicy.allowed/deniedTools),
   * step-limit enforcement, loop detection, and a signed `langchain.tool.call`
   * event. Shared by handleAgentAction (classic AgentExecutor) and
   * handleToolStart (modern LangGraph), which reach it with the same
   * tool-name/tool-input shape. Throws `[obsvr] ...` to BLOCK the tool
   * pre-execution when policy denies it.
   */
  private gateTool(
    config: NonNullable<ReturnType<typeof tryGetConfig>>,
    toolName: string,
    toolInputText: string,
    runId: string,
    parentRunId?: string,
  ): void {
      const agentState =
        (parentRunId ? this._agentRuns.get(parentRunId) : undefined) ??
        this._agentRuns.get(runId) ??
        // LangGraph: the tool run is not a direct child of the graph run, so
        // parentRunId/runId won't resolve. Fall back to the sole active agent
        // run when exactly one is in flight (the common single-agent case).
        (this._agentRuns.size === 1
          ? [...this._agentRuns.values()][0]
          : undefined);
      const agentRunId = agentState?.agentRunId ?? "";
      const stepIndex = agentState?.stepCount ?? 0;

      const agentPolicy = config.agentPolicy;

      if (toolName && agentPolicy) {
        const { allowed, reason } = checkTool(toolName, agentPolicy);
        if (!allowed) {
          emitIntegrationEvent({
            config,
            provider: "unknown",
            model: "unknown",
            operation: "langchain.agent.policy.tool_blocked",
            source: SOURCE,
            prompt: "",
            response: "",
            success: false,
            metadata: {
              agent_run_id: agentRunId,
              tool_name: toolName,
              reason,
              step_index: stepIndex,
            },
            compliance: { ...BLOCKED_COMPLIANCE, reason_code: ReasonCode.TOOL_DENIED },
            options: this.opts,
          });
          throw new Error(`[obsvr] Tool blocked by agent policy: ${toolName}`);
        }

        const stepAction = checkSteps(agentState?.stepCount ?? 0, agentPolicy);
        if (agentState) {
          agentState.stepCount += 1;
          // Loop detection
          if (agentState.loopDetector) {
            const loopResult = applyLoopDetection(agentState.loopDetector, config, {
              agentRunId: agentState.agentRunId,
              source: SOURCE,
              operation: "langchain.agent",
            });
            if (loopResult?.action === "block") {
              throw new Error("[obsvr] Loop detected: iteration limit exceeded");
            }
          }
        }

        if (stepAction === "block") {
          emitIntegrationEvent({
            config,
            provider: "unknown",
            model: "unknown",
            operation: "langchain.agent.policy.step_limit",
            source: SOURCE,
            prompt: "",
            response: "",
            success: false,
            metadata: {
              agent_run_id: agentRunId,
              step_count: stepIndex,
              step_index: stepIndex,
            },
            compliance: BLOCKED_COMPLIANCE,
            options: this.opts,
          });
          throw new Error("[obsvr] Step limit reached");
        }

        if (stepAction === "escalate") {
          emitIntegrationEvent({
            config,
            provider: "unknown",
            model: "unknown",
            operation: "langchain.agent.policy.step_limit",
            source: SOURCE,
            prompt: "",
            response: "",
            metadata: {
              agent_run_id: agentRunId,
              step_count: stepIndex,
              step_index: stepIndex,
              escalated: true,
            },
            options: this.opts,
          });
        }
      } else if (agentState) {
        agentState.stepCount += 1;
      }

      emitIntegrationEvent({
        config,
        provider: "unknown",
        model: "unknown",
        operation: "langchain.tool.call",
        source: SOURCE,
        prompt: toolInputText,
        response: "",
        metadata: {
          agent_run_id: agentRunId,
          tool_name: toolName,
          step_index: stepIndex,
        },
        compliance: TOOL_CALL_COMPLIANCE,
        options: this.opts,
      });
  }

  // -- agent action (classic AgentExecutor) + tool start (LangGraph) --------

  async handleAgentAction(
    action: AgentActionLike,
    runId: string,
    parentRunId?: string,
  ): Promise<void> {
    try {
      const config = tryGetConfig();
      if (!config) return;
      this._actionGated.set(runId, (this._actionGated.get(runId) ?? 0) + 1);
      const toolName = action.tool ?? "";
      const toolInputText =
        typeof action.toolInput === "string"
          ? action.toolInput
          : action.toolInput !== undefined
            ? JSON.stringify(action.toolInput)
            : "";
      this.gateTool(config, toolName, toolInputText, runId, parentRunId);
    } catch (err) {
      if (err instanceof Error && err.message.startsWith("[obsvr]")) throw err;
      // Never throw non-policy errors inside a framework callback
    }
  }

  /**
   * LangGraph tool-execution hook. handleAgentAction is NOT fired by LangGraph
   * agents (it was AgentExecutor-only, removed in LangChain v1), so this is the
   * pre-execution gate for modern agents. Skipped only for a tool call the
   * legacy callback has ALREADY ruled on — a credit granted and spent per call,
   * so a handler that once served an agent-action dispatch does not stop gating
   * everything after it.
   */
  async handleToolStart(
    toolSer: SerializedLike | undefined,
    input: unknown,
    runId: string,
    parentRunId?: string,
    _tags?: string[],
    _metadata?: Record<string, unknown>,
    runName?: string,
  ): Promise<void> {
    try {
      if (this.consumeActionGate(runId, parentRunId)) return;
      const config = tryGetConfig();
      if (!config) return;
      // The reliable tool name is runName (7th arg); the serialized id is the
      // tool CLASS ("DynamicStructuredTool"), not the instance name.
      const idArr = Array.isArray(toolSer?.id) ? toolSer.id : [];
      const toolName =
        (typeof runName === "string" && runName) ||
        (idArr.length ? String(idArr[idArr.length - 1]) : "");
      const toolInputText =
        typeof input === "string" ? input : input != null ? JSON.stringify(input) : "";
      this.gateTool(config, toolName, toolInputText, runId, parentRunId);
    } catch (err) {
      if (err instanceof Error && err.message.startsWith("[obsvr]")) throw err;
      // Never throw non-policy errors inside a framework callback
    }
  }

  // -- tool ends -----------------------------------------------------------

  async handleToolEnd(
    output: string,
    runId: string,
    parentRunId?: string,
  ): Promise<void> {
    try {
      const config = tryGetConfig();
      if (!config) return;

      const agentState =
        (parentRunId ? this._agentRuns.get(parentRunId) : undefined) ??
        this._agentRuns.get(runId);
      const agentRunId = agentState?.agentRunId ?? "";

      emitIntegrationEvent({
        config,
        provider: "unknown",
        model: "unknown",
        operation: "langchain.tool.result",
        source: SOURCE,
        // `output` is what the tool returned, handed to us by LangChain's own
        // tool-end callback — the one place in this integration where the
        // origin of the text is not in doubt.
        contentProvenance: "tool_result",
        prompt: "",
        response: typeof output === "string" ? output : String(output ?? ""),
        metadata: { agent_run_id: agentRunId },
        options: this.opts,
      });
    } catch {
      // Never throw inside a framework callback
    }
  }

  async handleToolError(error: unknown, runId: string): Promise<void> {
    try {
      const config = tryGetConfig();
      if (!config) return;

      const agentState = this._agentRuns.get(runId);
      const agentRunId = agentState?.agentRunId ?? "";

      emitIntegrationEvent({
        config,
        provider: "unknown",
        model: "unknown",
        operation: "langchain.tool.result",
        source: SOURCE,
        prompt: "",
        response: "",
        success: false,
        error,
        metadata: { agent_run_id: agentRunId },
        options: this.opts,
      });
    } catch {
      // Never throw inside a framework callback
    }
  }

  // -- retriever start / end / error ----------------------------------------
  //
  // Emitted as SIGNED execution spans through the M3B pipeline (emitSpan), so
  // retrieval steps join the trace DAG and the M8-10 span analytics without
  // the developer wrapping anything in obsvr.span(). Content policy: only the
  // query HASH and document COUNT are recorded, never retrieval text (the
  // span-attribute convention in proxy/span-attributes.ts).

  async handleRetrieverStart(
    retriever: SerializedLike,
    query: string,
    runId: string,
    parentRunId?: string,
    _tags?: string[],
    _metadata?: Record<string, unknown>,
    name?: string,
  ): Promise<void> {
    try {
      if (!tryGetConfig()) return;
      const agentState =
        (parentRunId ? this._agentRuns.get(parentRunId) : undefined) ??
        this._agentRuns.get(runId);
      const idPath = Array.isArray(retriever?.id) ? retriever.id : [];
      this._retrievals.set(runId, {
        startTime: performance.now(),
        source: name ?? (idPath[idPath.length - 1] as string | undefined) ?? "retriever",
        queryHash: createHash("sha256").update(String(query ?? ""), "utf8").digest("hex"),
        agentRunId: agentState?.agentRunId,
      });
    } catch {
      // Never throw inside a framework callback
    }
  }

  async handleRetrieverEnd(
    documents: unknown[],
    runId: string,
  ): Promise<void> {
    const state = this._retrievals.get(runId);
    if (!state) return;
    this._retrievals.delete(runId);
    try {
      emitSpan({
        kind: "retrieval",
        name: state.source,
        ok: true,
        trace_id: state.agentRunId,
        attributes: {
          [SPAN_ATTR.RETRIEVAL_SOURCE]: state.source,
          [SPAN_ATTR.RETRIEVAL_QUERY_HASH]: state.queryHash,
          [SPAN_ATTR.RETRIEVAL_DOCUMENT_COUNT]: Array.isArray(documents) ? documents.length : 0,
          duration_ms: Math.round(performance.now() - state.startTime),
        },
      });
    } catch {
      // Never throw inside a framework callback
    }
  }

  async handleRetrieverError(_error: unknown, runId: string): Promise<void> {
    const state = this._retrievals.get(runId);
    if (!state) return;
    this._retrievals.delete(runId);
    try {
      emitSpan({
        kind: "retrieval",
        name: state.source,
        ok: false,
        trace_id: state.agentRunId,
        attributes: {
          [SPAN_ATTR.RETRIEVAL_SOURCE]: state.source,
          [SPAN_ATTR.RETRIEVAL_QUERY_HASH]: state.queryHash,
          [SPAN_ATTR.RETRIEVAL_DOCUMENT_COUNT]: 0,
          duration_ms: Math.round(performance.now() - state.startTime),
        },
      });
    } catch {
      // Never throw inside a framework callback
    }
  }

  // -- LLM starts ----------------------------------------------------------

  async handleLLMStart(
    llm: SerializedLike,
    prompts: string[],
    runId: string,
    parentRunId?: string,
    extraParams?: Record<string, unknown>,
    _tags?: string[],
    metadata?: Record<string, unknown>,
  ): Promise<void> {
    const prompt = Array.isArray(prompts) ? prompts.join("\n") : "";
    await this.startRun(llm, prompt, prompt, runId, parentRunId, extraParams, metadata);
  }

  async handleChatModelStart(
    llm: SerializedLike,
    messages: unknown[][],
    runId: string,
    parentRunId?: string,
    extraParams?: Record<string, unknown>,
    _tags?: string[],
    metadata?: Record<string, unknown>,
  ): Promise<void> {
    const flat: unknown[] = Array.isArray(messages) ? messages.flat() : [];
    const prompt = flat
      .map((m) => `${messageRole(m)}: ${messageText(m)}`)
      .join("\n");
    let userText = "";
    for (let i = flat.length - 1; i >= 0; i--) {
      const role = messageRole(flat[i]);
      if (role === "user" || role === "human") {
        userText = messageText(flat[i]);
        break;
      }
    }
    await this.startRun(llm, prompt, userText || prompt, runId, parentRunId, extraParams, metadata);
  }

  private async startRun(
    llm: SerializedLike,
    prompt: string,
    userText: string,
    runId: string,
    parentRunId?: string,
    extraParams?: Record<string, unknown>,
    metadata?: Record<string, unknown>,
  ): Promise<void> {
    try {
      const config = tryGetConfig();
      if (!config) return;
      // Sampling gates only clean-event emission. The pre-call policy boundary
      // still runs on every invocation.
      const shouldAudit = shouldSample(config.sample_rate);

      const model = extractModelName(llm, extraParams, metadata);
      const provider = inferProvider(llm);
      const policy = await applyPreCallPolicy(prompt, {
        config,
        provider,
        operation: "llm",
        userId: this.opts.user_id,
        serviceName: this.opts.service_name,
        model,
        metadata: { ...this.opts.metadata, ...metadata },
      });

      // Link to parent agent run if available
      const parentAgentState = parentRunId
        ? this._agentRuns.get(parentRunId)
        : undefined;
      const agentRunId = parentAgentState?.agentRunId;

      let compliance = policy.compliance;
      if (policy.decision === "redact") {
        compliance = {
          ...compliance,
          event_type: "blocked_call",
          action_taken: "blocked",
          action_reason: "policy_violation",
          reason_code: ReasonCode.POLICY_VIOLATION,
          redacted_types: [],
          blocked_types: [
            ...new Set([...compliance.blocked_types, ...compliance.redacted_types]),
          ],
          rule_id: "sdk:outbound_redaction_unsupported",
          policy_reason:
            "LangChain model-start callbacks cannot replace the provider-bound request; blocked instead of forwarding unredacted content",
        };
      }

      if (policy.decision === "block" || compliance.action_taken === "blocked") {
        emitIntegrationEvent({
          config,
          provider,
          model,
          operation: "llm",
          source: SOURCE,
          prompt: blockedPromptForStorage(prompt, compliance, policy.securityNormalized),
          response: "",
          userInput: blockedUserInputForStorage(userText, policy),
          latencyMs: 0,
          success: false,
          statusCode: 403,
          metadata: agentRunId ? { agent_run_id: agentRunId } : undefined,
          options: this.opts,
          canaryTelemetry: policy.canaryTelemetry,
          floorTelemetry: policy.floorTelemetry,
          compliance,
        });
        throw blockedCallError(compliance);
      }

      this.runs.set(runId, {
        prompt,
        userText,
        model,
        provider,
        startTime: performance.now(),
        compliance,
        auditThisCall:
          monitorModeRequiresEvidence(config) ||
          shouldAudit ||
          compliance.action_reason !== "none",
        agentRunId,
        floorTelemetry: policy.floorTelemetry,
      });
    } catch (error) {
      if (error instanceof ObsvrPolicyError) throw error;
      // Callback bookkeeping and audit failures do not affect the model call.
      // Policy and detector failure behavior is already resolved inside the
      // shared pre-call pipeline and reaches this point as ObsvrPolicyError.
    }
  }

  // -- LLM end / error -----------------------------------------------------

  async handleLLMEnd(output: unknown, runId: string): Promise<void> {
    const state = this.runs.get(runId);
    if (!state) return;
    this.runs.delete(runId);
    // Sampled out and the scan found nothing: the run was still governed, only
    // this clean record is dropped. handleLLMError below always emits.
    if (!state.auditThisCall) return;

    try {
      const config = tryGetConfig();
      if (!config) return;

      const out = (output ?? {}) as Record<string, unknown>;
      let responseText = "";
      let firstGeneration: Record<string, unknown> | undefined;
      const generations = out.generations as unknown[][] | undefined;
      if (Array.isArray(generations) && Array.isArray(generations[0])) {
        const first = generations[0][0] as Record<string, unknown> | undefined;
        if (first) {
          firstGeneration = first;
          if (typeof first.text === "string" && first.text.length > 0) {
            responseText = first.text;
          } else if (first.message) {
            responseText = messageText(first.message);
          }
        }
      }

      const llmOutput = out.llmOutput as Record<string, unknown> | undefined;
      const tokenUsage = (llmOutput?.tokenUsage ??
        llmOutput?.estimatedTokenUsage) as Record<string, unknown> | undefined;
      const num = (v: unknown): number | undefined =>
        typeof v === "number" ? v : undefined;

      const metadata: Record<string, unknown> | undefined = state.agentRunId
        ? { agent_run_id: state.agentRunId }
        : undefined;

      const resolvedModel = extractResolvedModel(firstGeneration, llmOutput);
      emitIntegrationEvent({
        config,
        provider: state.provider,
        model: state.model,
        model_resolved: resolvedModel,
        // Read from LangChain's response abstraction (framework-mediated) → framework_reported.
        provenance_source: resolvedModel ? "framework_reported" : undefined,
        operation: "llm",
        source: SOURCE,
        prompt: state.prompt,
        response: responseText,
        userInput: state.userText,
        inputTokens: num(tokenUsage?.promptTokens),
        outputTokens: num(tokenUsage?.completionTokens),
        totalTokens: num(tokenUsage?.totalTokens),
        latencyMs: Math.round(performance.now() - state.startTime),
        metadata,
        options: this.opts,
        floorTelemetry: state.floorTelemetry,
        compliance: state.compliance,
      });
    } catch {
      // Never throw inside a framework callback
    }
  }

  async handleLLMError(error: unknown, runId: string): Promise<void> {
    const state = this.runs.get(runId);
    if (!state) return;
    this.runs.delete(runId);

    try {
      const config = tryGetConfig();
      if (!config) return;

      const metadata: Record<string, unknown> | undefined = state.agentRunId
        ? { agent_run_id: state.agentRunId }
        : undefined;

      emitIntegrationEvent({
        config,
        provider: state.provider,
        model: state.model,
        operation: "llm",
        source: SOURCE,
        prompt: state.prompt,
        response: "",
        userInput: state.userText,
        latencyMs: Math.round(performance.now() - state.startTime),
        success: false,
        error,
        metadata,
        options: this.opts,
        floorTelemetry: state.floorTelemetry,
        compliance: state.compliance,
      });
    } catch {
      // Never throw inside a framework callback
    }
  }
}
