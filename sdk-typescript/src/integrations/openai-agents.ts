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
import { ReasonCode } from "../governance/reason-codes.js";
import { readTokenUsage } from "../proxy/extractors/token-usage.js";

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
              // Previously emitted with no compliance at all, so the refusal
              // was recorded as an ordinary allowed llm_call. A blocked tool
              // is a blocked_call with the TOOL_DENIED classification.
              compliance: {
                event_type: "blocked_call",
                policy_version: "none",
                action_taken: "blocked",
                action_reason: "policy_violation",
                reason_code: ReasonCode.TOOL_DENIED,
                action_source: "policy_rules",
                redacted_types: [],
                blocked_types: [],
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
        // The generation span's `model` IS the configured alias — this is the
        // one span type that carries it, and it is what the event schema wants.
        const model = String(spanData.model ?? span.model ?? "unknown");
        const rawInput = spanData.input ?? span.input;
        const rawOutput = spanData.output ?? span.output;
        // A resolved snapshot IS recoverable here, contrary to what this
        // branch used to claim: on the NON-streamed Chat Completions path the
        // raw provider ChatCompletion sits in spanData.output[0], and its
        // `model` is the served snapshot.
        //
        // The streamed path must be excluded, and the guard is not cosmetic:
        // there the SDK synthesises a stand-in completion whose `model` is
        // copied from the CONFIGURED alias, so reading it blindly would mint a
        // "provider-verified snapshot" that is really just the request echoed
        // back — a fabricated provenance claim, and worse than the absent one
        // it replaced. The stand-in announces itself with the placeholder id
        // the SDK exports as FAKE_ID; anything else is a real provider body.
        const firstOutput = Array.isArray(rawOutput)
          ? ((rawOutput[0] ?? {}) as Record<string, unknown>)
          : undefined;
        const isSynthesizedStandIn = firstOutput?.id === "FAKE_ID";
        const modelResolved =
          !isSynthesizedStandIn && typeof firstOutput?.model === "string"
            ? firstOutput.model
            : undefined;
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
          model_resolved: modelResolved,
          // Read off the provider's own completion body carried on the span,
          // not off a framework abstraction over it.
          provenance_source: modelResolved ? "provider_response" : undefined,
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
        const tokens = readTokenUsage(resp.usage);
        const inputTokens = tokens?.input_tokens;
        const outputTokens = tokens?.output_tokens;
        const totalTokens = tokens?.total_tokens;

        emitIntegrationEvent({
          config,
          provider: "openai",
          // Both fields hold the RESOLVED served snapshot, and on this path
          // that is the only model information that exists. ResponseSpanData
          // carries exactly (response_id, _input, _response); the agent span
          // carries name/handoffs/tools/output_type; trace metadata is
          // caller-supplied. Nothing in a Responses-path trace ever holds the
          // configured alias, so there is no other span to correlate against
          // and no version of this code that could recover it.
          //
          // That makes `model === model_resolved` here mean something
          // different from what it means elsewhere: not "the caller pinned an
          // exact snapshot" but "the alias was never observable". Those are
          // not distinguishable from the two fields alone, so the substitution
          // is stated outright rather than left for a reader to infer — a
          // temporal-provenance check over this source would otherwise always
          // pass and look like evidence of no drift.
          model,
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
            model_alias_unavailable: true,
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
