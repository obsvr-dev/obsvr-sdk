/**
 * LangChain JS Integration
 *
 * Duck-typed callback handler compatible with LangChain JS
 * `CallbackHandlerMethods` - no hard dependency on `@langchain/core`.
 * Pass an instance via `callbacks: [...]` on any model/chain.
 *
 * Observe-only for LLM calls: the request has already been sent to the LLM
 * by the time callbacks fire, so PII policy applies to the *stored* copy
 * ("block" is downgraded to redact-in-event with action_reason "pii_detected").
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
  applyObservePolicy,
  createLoopDetector,
  createDelegationTracker,
  emitIntegrationEvent,
  inferProviderFromString,
  redactForStorage,
  type DeobfuscationView,
  setupExitHandlers,
  shouldSample,
  tryGetConfig,
  type ComplianceInfo,
  type IntegrationOptions,
  type IntegrationProvider,
} from "./core.js";
import type { AgentPolicy } from "../proxy/types.js";
import type { LoopDetector } from "../policy/industry/devops.js";
import type { DelegationTracker } from "../policy/industry/agentic.js";
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
  shouldRedactStored: boolean;
  /** View-only detection: stored copies use a whole-text placeholder. */
  storedRedactionVia?: DeobfuscationView["method"];
  agentRunId?: string;
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
  // True once handleAgentAction has fired (classic AgentExecutor path). Used so
  // handleToolStart only gates on the modern LangGraph path, where
  // handleAgentAction never fires — preventing double-gating on AgentExecutor.
  private _sawAgentAction = false;

  constructor(opts: IntegrationOptions = {}) {
    this.opts = opts;
    const config = tryGetConfig();
    if (config) setupExitHandlers(config);
  }

  copy(): ObsvrCallbackHandler {
    return this;
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
            compliance: BLOCKED_COMPLIANCE,
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
      this._sawAgentAction = true;
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
   * pre-execution gate for modern agents. Skipped when handleAgentAction has
   * already run (classic AgentExecutor) to avoid double-gating.
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
      if (this._sawAgentAction) return;
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
    this.startRun(llm, prompt, prompt, runId, parentRunId, extraParams, metadata);
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
    this.startRun(llm, prompt, userText || prompt, runId, parentRunId, extraParams, metadata);
  }

  private startRun(
    llm: SerializedLike,
    prompt: string,
    userText: string,
    runId: string,
    parentRunId?: string,
    extraParams?: Record<string, unknown>,
    metadata?: Record<string, unknown>,
  ): void {
    try {
      const config = tryGetConfig();
      if (!config) return;
      if (!shouldSample(config.sample_rate)) return;

      const { shouldRedactStored, compliance, storedRedactionVia } = applyObservePolicy(
        `${prompt} ${userText}`,
        config,
      );

      // Link to parent agent run if available
      const parentAgentState = parentRunId
        ? this._agentRuns.get(parentRunId)
        : undefined;
      const agentRunId = parentAgentState?.agentRunId;

      this.runs.set(runId, {
        prompt,
        userText,
        model: extractModelName(llm, extraParams, metadata),
        provider: inferProvider(llm),
        startTime: performance.now(),
        compliance,
        shouldRedactStored,
        storedRedactionVia,
        agentRunId,
      });
    } catch {
      // Never throw inside a framework callback
    }
  }

  // -- LLM end / error -----------------------------------------------------

  async handleLLMEnd(output: unknown, runId: string): Promise<void> {
    const state = this.runs.get(runId);
    if (!state) return;
    this.runs.delete(runId);

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
        prompt: state.shouldRedactStored
          ? redactForStorage(state.prompt, state.storedRedactionVia)
          : state.prompt,
        response: state.shouldRedactStored
          ? redactForStorage(responseText, state.storedRedactionVia)
          : responseText,
        userInput: state.shouldRedactStored
          ? redactForStorage(state.userText, state.storedRedactionVia)
          : state.userText,
        inputTokens: num(tokenUsage?.promptTokens),
        outputTokens: num(tokenUsage?.completionTokens),
        totalTokens: num(tokenUsage?.totalTokens),
        latencyMs: Math.round(performance.now() - state.startTime),
        metadata,
        options: this.opts,
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
        prompt: state.shouldRedactStored
          ? redactForStorage(state.prompt, state.storedRedactionVia)
          : state.prompt,
        response: "",
        userInput: state.shouldRedactStored
          ? redactForStorage(state.userText, state.storedRedactionVia)
          : state.userText,
        latencyMs: Math.round(performance.now() - state.startTime),
        success: false,
        error,
        metadata,
        options: this.opts,
        compliance: state.compliance,
      });
    } catch {
      // Never throw inside a framework callback
    }
  }
}
