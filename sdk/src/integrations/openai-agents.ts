/**
 * OpenAI Agents SDK Integration (TypeScript)
 *
 * Implements a SpanProcessor-compatible processor for the @openai/agents SDK.
 * Duck-typed against span shapes to avoid hard version coupling.
 *
 * Usage:
 *   import { ObsvrTraceProcessor } from "@obsvr/sdk/openai-agents";
 *   // Register via your SDK's tracing registration mechanism, e.g.:
 *   //   setTracingProcessors([new ObsvrTraceProcessor()])
 *   //   addTracingProcessor(new ObsvrTraceProcessor())
 *
 * The exact API for registering processors varies across openai-agents versions.
 * Consult the installed package's documentation for the current registration method.
 *
 * @packageDocumentation
 */

// Interception: OpenAI Agents SDK SpanProcessor interface (non-mutating).
// Register via the SDK's tracing processor API - no internal SDK mutation.

import {
  applyLoopDetection,
  applyDelegationPolicy,
  createLoopDetector,
  createDelegationTracker,
  emitIntegrationEvent,
  setupExitHandlers,
  tryGetConfig,
  type IntegrationOptions,
} from "./core.js";
import type { AgentPolicy } from "../proxy/types.js";
import type { LoopDetector } from "../policy/industry/devops.js";
import type { DelegationTracker } from "../policy/industry/agentic.js";

const SOURCE = "openai_agents_js";

/** Duck-typed shape of the current @openai/agents-core Span class getters. */
interface OpenAIAgentSpan {
  traceId?: unknown;
  spanData?: unknown;
  endedAt?: unknown;
}

/** Bridge a modern Span instance into the shape processSpan() parses. */
function adaptSpan(span: OpenAIAgentSpan): Record<string, unknown> {
  const spanData = (span.spanData ?? {}) as Record<string, unknown>;
  return {
    trace_id: span.traceId,
    span_data: spanData,
    type: spanData.type,
    ended_at: span.endedAt,
  };
}

interface TraceState {
  stepCount: number;
  startTime: number;
  loopDetector?: LoopDetector;
  delegationTracker?: DelegationTracker;
}

function checkTool(
  toolName: string,
  policy: AgentPolicy,
): { allowed: boolean; reason: string } {
  const denied = policy.deniedTools ?? [];
  const allowed = policy.allowedTools;
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

/**
 * SpanProcessor-compatible processor for the OpenAI Agents SDK.
 *
 * Emits audit events for agent run lifecycle, tool calls, and LLM generations.
 * Enforces `agentPolicy` tool restrictions and step limits at tool-call spans.
 *
 * @example
 * ```ts
 * import { ObsvrTraceProcessor } from "@obsvr/sdk/openai-agents";
 * // Register using your SDK version's registration function
 * ```
 */
export class ObsvrTraceProcessor {
  private readonly opts: IntegrationOptions;
  private readonly _traces = new Map<string, TraceState>();

  constructor(opts: IntegrationOptions = {}) {
    this.opts = opts;
    const config = tryGetConfig();
    if (config) setupExitHandlers(config);
  }

  // -- Modern TracingProcessor interface (current @openai/agents-core) -----
  //
  // The SDK registers processors that implement onTraceStart/onTraceEnd/
  // onSpanStart/onSpanEnd/shutdown/forceFlush (Trace/Span class instances
  // with camelCase getters), not the older processSpan(span) shape this
  // class was originally built against. Adapt the modern Span getters
  // (traceId/spanData/endedAt) into the snake_case-ish shape processSpan
  // already parses, so the run-lifecycle/tool/generation logic below is
  // reused unchanged. Agent run start/end is derived from agent-type spans
  // (see processSpan), so Trace-level hooks are no-ops; this processor keeps
  // no buffer of its own (delivery is async via the SDK's own sender), so
  // forceFlush/shutdown are no-ops too.

  async onTraceStart(_trace: unknown): Promise<void> {}
  async onTraceEnd(_trace: unknown): Promise<void> {}

  async onSpanStart(span: OpenAIAgentSpan): Promise<void> {
    this.processSpanAdvisory(adaptSpan(span));
  }

  async onSpanEnd(span: OpenAIAgentSpan): Promise<void> {
    this.processSpanAdvisory(adaptSpan(span));
  }

  /**
   * processSpan, but `[obsvr]` policy errors do NOT escape. The modern
   * TracingProcessor hooks are invoked fire-and-forget by
   * @openai/agents-core's MultiTracingProcessor, so a throw here cannot
   * block anything — it only surfaces as an unhandled promise rejection,
   * which agents-core's own global `unhandledRejection` handler turns into
   * a silent `process.exit(1)` of the HOST application. Enforcement lives
   * in `obsvrGovernTool` (tools.ts); the `tool_blocked` audit event has
   * already been emitted by processSpan before it throws, so nothing is
   * lost by swallowing the error at this boundary.
   */
  private processSpanAdvisory(span: Record<string, unknown>): void {
    try {
      this.processSpan(span);
    } catch {
      /* policy errors are advisory in the tracing path — event already emitted */
    }
  }

  async shutdown(_timeout?: number): Promise<void> {}
  async forceFlush(): Promise<void> {}

  /**
   * Process a span. Compatible with the SpanProcessor.processSpan() interface.
   * Called by the SDK after each span completes.
   */
  processSpan(span: Record<string, unknown>): void {
    const config = tryGetConfig();
    if (!config) return;

    try {
      // Duck-type the span fields - compatible with multiple SDK versions
      const traceId = String(span.trace_id ?? "");
      const spanData = (span.span_data ?? span) as Record<string, unknown>;
      const spanType = String(spanData.type ?? span.type ?? "");
      const endedAt = spanData.ended_at ?? span.ended_at;

      if (!traceId) return;

      // Agent span start (no ended_at yet)
      if (spanType === "agent" && !endedAt) {
        const agentPolicy = config.agentPolicy;
        const traceState: TraceState = {
          stepCount: 0,
          startTime: performance.now(),
        };
        if (agentPolicy?.loopDetection) {
          traceState.loopDetector = createLoopDetector(agentPolicy.loopDetection);
        }
        if (agentPolicy?.delegationPolicy) {
          traceState.delegationTracker = createDelegationTracker(agentPolicy.delegationPolicy);
        }
        this._traces.set(traceId, traceState);
        emitIntegrationEvent({
          config,
          provider: "unknown",
          model: "unknown",
          operation: "openai_agents.agent.run.start",
          source: SOURCE,
          prompt: "",
          response: "",
          metadata: { agent_run_id: traceId },
          options: this.opts,
        });
        return;
      }

      // Agent span end
      if (spanType === "agent" && endedAt) {
        const state = this._traces.get(traceId);
        this._traces.delete(traceId);
        emitIntegrationEvent({
          config,
          provider: "unknown",
          model: "unknown",
          operation: "openai_agents.agent.run.finish",
          source: SOURCE,
          prompt: "",
          response: "",
          latencyMs: state
            ? Math.round(performance.now() - state.startTime)
            : undefined,
          metadata: { agent_run_id: traceId },
          options: this.opts,
        });
        return;
      }

      // Function / tool call span
      if (spanType === "function") {
        const toolName = String(spanData.name ?? span.name ?? "");
        const state = this._traces.get(traceId);
        const stepIndex = state?.stepCount ?? 0;
        const agentPolicy = config.agentPolicy;

        if (toolName && agentPolicy) {
          const { allowed, reason } = checkTool(toolName, agentPolicy);
          if (!allowed) {
            emitIntegrationEvent({
              config,
              provider: "unknown",
              model: "unknown",
              operation: "openai_agents.agent.policy.tool_blocked",
              source: SOURCE,
              prompt: "",
              response: "",
              success: false,
              metadata: {
                agent_run_id: traceId,
                tool_name: toolName,
                reason,
                step_index: stepIndex,
              },
              options: this.opts,
            });
            throw new Error(`[obsvr] Tool blocked by agent policy: ${toolName}`);
          }

          const stepAction = checkSteps(stepIndex, agentPolicy);
          if (state) {
            state.stepCount += 1;
            // Loop detection
            if (state.loopDetector) {
              const loopResult = applyLoopDetection(state.loopDetector, config, {
                agentRunId: traceId,
                source: SOURCE,
                operation: "openai_agents.agent",
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
              operation: "openai_agents.agent.policy.step_limit",
              source: SOURCE,
              prompt: "",
              response: "",
              success: false,
              metadata: {
                agent_run_id: traceId,
                step_count: stepIndex,
                step_index: stepIndex,
              },
              options: this.opts,
            });
            throw new Error("[obsvr] Step limit reached");
          }

          if (stepAction === "escalate") {
            emitIntegrationEvent({
              config,
              provider: "unknown",
              model: "unknown",
              operation: "openai_agents.agent.policy.step_limit",
              source: SOURCE,
              prompt: "",
              response: "",
              metadata: {
                agent_run_id: traceId,
                step_count: stepIndex,
                step_index: stepIndex,
                escalated: true,
              },
              options: this.opts,
            });
          }
        } else if (state) {
          state.stepCount += 1;
        }

        const rawInput = spanData.input ?? span.input;
        const toolInputText =
          typeof rawInput === "string"
            ? rawInput
            : rawInput !== undefined
              ? JSON.stringify(rawInput)
              : "";

        emitIntegrationEvent({
          config,
          provider: "unknown",
          model: "unknown",
          operation: "openai_agents.tool.call",
          source: SOURCE,
          prompt: toolInputText,
          response: "",
          metadata: {
            agent_run_id: traceId,
            tool_name: toolName,
            step_index: stepIndex,
          },
          options: this.opts,
        });
        return;
      }

      // Generation (LLM call) span
      if (spanType === "generation") {
        // The Agents SDK generation span records only the configured `model`;
        // it exposes no separate provider-resolved snapshot, so model_resolved
        // stays absent (the proxy/openai-compat paths capture it when present).
        const model = String(spanData.model ?? span.model ?? "unknown");
        const rawInput = spanData.input ?? span.input;
        const rawOutput = spanData.output ?? span.output;
        const promptText =
          typeof rawInput === "string"
            ? rawInput
            : rawInput !== undefined
              ? JSON.stringify(rawInput)
              : "";
        const responseText =
          typeof rawOutput === "string"
            ? rawOutput
            : rawOutput !== undefined
              ? JSON.stringify(rawOutput)
              : "";

        emitIntegrationEvent({
          config,
          provider: "openai",
          model,
          operation: "llm",
          source: SOURCE,
          prompt: promptText,
          response: responseText,
          metadata: { agent_run_id: traceId },
          options: this.opts,
        });
        return;
      }

      // Response span: the REAL LLM-call span shape emitted by the
      // currently published @openai/agents-core (verified at runtime — the
      // "generation" type above never actually occurs there). Carries the
      // full OpenAI Responses API payload nested under `_input`/`_response`;
      // without this branch the entire prompt/model/response/token content
      // of every agent LLM call was silently dropped (only the agent-run
      // start/finish boundary events were ever emitted).
      // Only on span END: the response span fires processSpan twice (start +
      // end). At start `_response` isn't populated yet, so emitting there
      // produces a junk "openai/unknown" event with empty content. Wait for
      // completion, where the full payload is present.
      if (spanType === "response" && endedAt) {
        const resp = (spanData._response ?? {}) as Record<string, unknown>;
        const rawInputArr = spanData._input as unknown[] | undefined;
        const promptText = Array.isArray(rawInputArr)
          ? rawInputArr
              .map((m) => {
                const mm = (m ?? {}) as Record<string, unknown>;
                const content =
                  typeof mm.content === "string"
                    ? mm.content
                    : JSON.stringify(mm.content ?? "");
                return `${mm.role ?? "user"}: ${content}`;
              })
              .join("\n")
          : "";

        const outputArr = resp.output as unknown[] | undefined;
        const responseText = Array.isArray(outputArr)
          ? outputArr
              .flatMap((item) => {
                const it = (item ?? {}) as Record<string, unknown>;
                const content = it.content as unknown[] | undefined;
                if (!Array.isArray(content)) return [];
                return content
                  .map((c) => (c as Record<string, unknown>).text)
                  .filter((t): t is string => typeof t === "string");
              })
              .join("")
          : "";

        const model = typeof resp.model === "string" ? resp.model : "unknown";
        const usage = resp.usage as Record<string, unknown> | undefined;
        const inputTokens =
          typeof usage?.input_tokens === "number" ? usage.input_tokens : undefined;
        const outputTokens =
          typeof usage?.output_tokens === "number" ? usage.output_tokens : undefined;
        const totalTokens =
          typeof usage?.total_tokens === "number" ? usage.total_tokens : undefined;

        emitIntegrationEvent({
          config,
          provider: "openai",
          model,
          // The Responses API echoes the RESOLVED served model in the same
          // field used to request it, so this is a genuine provider-verified
          // snapshot, not just an echo of the caller's request.
          model_resolved: model,
          provenance_source: "provider_response",
          operation: "llm",
          source: SOURCE,
          prompt: promptText,
          response: responseText,
          inputTokens,
          outputTokens,
          totalTokens,
          metadata: {
            agent_run_id: traceId,
            response_id: spanData.response_id,
          },
          options: this.opts,
        });
      }
    } catch (err) {
      if (err instanceof Error && err.message.startsWith("[obsvr]")) throw err;
      // Never throw non-policy errors inside a tracing processor
    }
  }
}
