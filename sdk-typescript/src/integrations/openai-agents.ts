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
 * THE PROCESSOR RECORDS TOOL POLICY; THE GATE LIVES ELSEWHERE IN THIS MODULE.
 * The framework awaits each tool's own `inputGuardrails` BEFORE invoking it,
 * and {@link attachToolGate} puts obsvr's guardrail there: a denied tool is
 * refused by the guardrail contract's `rejectContent` sentinel — the model
 * receives the block message as the tool's result, the run continues, and the
 * tool's callable is never entered. `obsvrGovernTool` (tools.ts) remains the
 * wrapper alternative; its refusal throws out of `invoke`, which this
 * framework wraps into `ToolCallError` — the RUN ABORTS. Choose by what a
 * denial should do to the run.
 *
 * @packageDocumentation
 */

// Model-call policy is enforced separately from tracing. Pass a Model through
// governModel(), or a ModelProvider through governModelProvider(), before
// giving it to the runner. Those wrappers gate getResponse/getStreamedResponse
// before the underlying model is entered; the trace processor remains the
// post-call observation rail.

// Interception: OpenAI Agents SDK SpanProcessor interface (non-mutating).
// Register via the SDK's tracing processor API - no internal SDK mutation.

import {
  RedactionNotApplied,
  applyPreCallPolicy,
  applyLoopDetection,
  applyDelegationPolicy,
  applyObservePolicy,
  assertRedactionApplied,
  blockedCallError,
  blockedPromptForStorage,
  blockedUserInputForStorage,
  createLoopDetector,
  createDelegationTracker,
  emitIntegrationEvent,
  inferProviderFromModel,
  outboundRedactionBlockedCompliance,
  redactArguments,
  redactBuiltinPii,
  redactForStorage,
  setupExitHandlers,
  toolGateNotEvaluatedCompliance,
  tryGetConfig,
  type ComplianceInfo,
  type IntegrationOptions,
  type IntegrationProvider,
} from "./core.js";
import { applyOutboundRedaction } from "../policy/detector-guard.js";
import type { ResolvedConfig } from "../proxy/types.js";
import type { AgentPolicy } from "../proxy/types.js";
import type { LoopDetector } from "../policy/industry/devops.js";
import type { DelegationTracker } from "../policy/industry/agentic.js";
import { readTokenUsage } from "../proxy/extractors/token-usage.js";
import { isToolGoverned, registerGovernedToolName } from "./tools.js";
import { ReasonCode } from "../governance/reason-codes.js";
import { safeStringify } from "../utils/truncate.js";

const SOURCE = "openai_agents_js";

// ---------------------------------------------------------------------------
// Pre-execution model boundary
// ---------------------------------------------------------------------------

/** The stable request surface exposed by @openai/agents from 0.13 onward. */
interface AgentsModelRequest {
  systemInstructions?: string;
  input: unknown;
  prompt?: { variables?: unknown; [key: string]: unknown };
  [key: string]: unknown;
}

/** Duck-typed deliberately so @openai/agents remains an optional peer. */
interface AgentsModel {
  getResponse(request: AgentsModelRequest): Promise<any>;
  getStreamedResponse(request: AgentsModelRequest): AsyncIterable<any>;
}

interface AgentsModelProvider {
  getModel(modelName?: string): AgentsModel | Promise<AgentsModel>;
}

export interface GovernModelOptions extends IntegrationOptions {
  /** Model name used for policy evaluation and provider attribution. */
  model?: string;
  /** Override when the model name alone cannot identify the provider. */
  provider?: IntegrationProvider;
}

const GOVERNED_MODEL = Symbol.for("obsvr.openai_agents.governed_model");
const GOVERNED_PROVIDER = Symbol.for("obsvr.openai_agents.governed_provider");

function modelNameOf(model: AgentsModel, options: GovernModelOptions): string {
  if (options.model) return options.model;
  const candidate = Reflect.get(model, "model", model);
  return typeof candidate === "string" && candidate.trim() ? candidate : "unknown";
}

function requestText(request: AgentsModelRequest): string {
  const parts: string[] = [];
  if (typeof request.systemInstructions === "string") {
    parts.push(request.systemInstructions);
  }
  if (typeof request.input === "string") {
    parts.push(request.input);
  } else if (request.input !== undefined) {
    parts.push(safeStringify(request.input));
  }
  const variables = request.prompt?.variables;
  if (typeof variables === "string") {
    parts.push(variables);
  } else if (variables !== undefined) {
    parts.push(safeStringify(variables));
  }
  return parts.filter(Boolean).join("\n");
}

function redactRequest(
  request: AgentsModelRequest,
  compliance: ComplianceInfo,
): AgentsModelRequest {
  const types = compliance.redacted_types ?? [];
  // Rule/hook redactions may describe a non-locatable whole-request match.
  // The Agents request is structured, so guessing which string to replace
  // would create a false "redacted" claim. Refuse instead.
  if (
    types.length === 0 ||
    types.includes("all") ||
    (compliance.action_source !== "builtin" &&
      compliance.action_source !== "builtin+presidio")
  ) {
    throw new RedactionNotApplied("the redaction verdict has no safely locatable span");
  }

  // The TypeScript SDK's local outbound redactor is the built-in structured
  // PII tier. If an external analyzer alone located an entity, this boundary
  // cannot synchronously rewrite it and therefore fails closed.
  const nlpOnly = new Set([
    "name",
    "person",
    "address",
    "location",
    "medical",
    "national_id",
  ]);
  if (types.some((name) => nlpOnly.has(name))) {
    throw new RedactionNotApplied("an external-only PII span cannot be rewritten here");
  }

  const rewritten: AgentsModelRequest = { ...request };
  if (typeof request.systemInstructions === "string") {
    rewritten.systemInstructions = redactBuiltinPii(request.systemInstructions);
  }
  rewritten.input = redactArguments(request.input, redactBuiltinPii);
  if (request.prompt && request.prompt.variables !== undefined) {
    rewritten.prompt = {
      ...request.prompt,
      variables: redactArguments(request.prompt.variables, redactBuiltinPii),
    };
  }

  const before = requestText(request);
  const after = requestText(rewritten);
  if (before === after) {
    throw new RedactionNotApplied("the provider-bound request was unchanged");
  }
  assertRedactionApplied(after, compliance);
  return rewritten;
}

function emitModelBlock(
  config: ResolvedConfig,
  text: string,
  policy: Awaited<ReturnType<typeof applyPreCallPolicy>>,
  model: string,
  provider: IntegrationProvider,
  options: GovernModelOptions,
): void {
  emitIntegrationEvent({
    config,
    provider,
    model,
    operation: "openai_agents.model.request",
    source: SOURCE,
    prompt: blockedPromptForStorage(
      text,
      policy.compliance,
      policy.securityNormalized,
    ),
    userInput: blockedUserInputForStorage(text, policy),
    scannedText: text,
    response: "",
    success: false,
    compliance: policy.compliance,
    canaryTelemetry: policy.canaryTelemetry,
    floorTelemetry: policy.floorTelemetry,
    options,
  });
}

async function governModelRequest(
  request: AgentsModelRequest,
  model: string,
  options: GovernModelOptions,
): Promise<AgentsModelRequest> {
  const config = tryGetConfig();
  if (!config || config.disabled) return request;
  setupExitHandlers(config);

  const provider = options.provider ?? inferProviderFromModel(model);
  const text = requestText(request);
  const policy = await applyPreCallPolicy(text, {
    config,
    provider,
    operation: "openai_agents.model.request",
    model: model === "unknown" ? undefined : model,
    userId: options.user_id,
    serviceName: options.service_name,
    metadata: options.metadata,
  });

  if (policy.decision === "block") {
    emitModelBlock(config, text, policy, model, provider, options);
    throw blockedCallError(policy.compliance);
  }
  if (policy.decision !== "redact") return request;

  let rewritten: AgentsModelRequest | undefined;
  const failure = applyOutboundRedaction(() => {
    rewritten = redactRequest(request, policy.compliance);
  });
  if (failure) {
    const blocked = {
      ...policy,
      decision: "block" as const,
      compliance: outboundRedactionBlockedCompliance(policy.compliance, failure),
    };
    emitModelBlock(config, text, blocked, model, provider, options);
    throw blockedCallError(blocked.compliance);
  }
  return rewritten as AgentsModelRequest;
}

/**
 * Enforce obsvr policy at the OpenAI Agents SDK's actual Model boundary.
 *
 * This is separate from tracing: the wrapper awaits policy before calling
 * `getResponse` or starting `getStreamedResponse`, so a block cannot reach the
 * provider and a redact verdict changes the request the provider receives.
 */
export function governModel<T extends AgentsModel>(
  model: T,
  options: GovernModelOptions = {},
): T {
  if (Reflect.get(model, GOVERNED_MODEL, model) === true) return model;
  const modelName = modelNameOf(model, options);
  return new Proxy(model, {
    get(target, property) {
      if (property === GOVERNED_MODEL) return true;
      if (property === "getResponse") {
        return async (request: AgentsModelRequest) =>
          target.getResponse(await governModelRequest(request, modelName, options));
      }
      if (property === "getStreamedResponse") {
        return async function* (request: AgentsModelRequest): AsyncIterable<unknown> {
          const governed = await governModelRequest(request, modelName, options);
          for await (const event of target.getStreamedResponse(governed)) {
            yield event;
          }
        };
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

/** Wrap every Model resolved by an OpenAI Agents ModelProvider. */
export function governModelProvider<T extends AgentsModelProvider>(
  provider: T,
  options: GovernModelOptions = {},
): T {
  if (Reflect.get(provider, GOVERNED_PROVIDER, provider) === true) return provider;
  return new Proxy(provider, {
    get(target, property) {
      if (property === GOVERNED_PROVIDER) return true;
      if (property === "getModel") {
        return (modelName?: string) => {
          const resolved = target.getModel(modelName);
          const wrap = (model: AgentsModel) =>
            governModel(model, { ...options, model: modelName ?? options.model });
          return resolved instanceof Promise ? resolved.then(wrap) : wrap(resolved);
        };
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

/**
 * Run the observe-only PII net over what an event is about to STORE.
 *
 * This integration is a tracing processor and cannot refuse anything — the
 * framework wraps every processor callback in its own try/catch and only logs
 * — so this is emphatically NOT enforcement, and the returned compliance says
 * so: `redacted`, never `blocked`. The call has already happened by the time a
 * span ends.
 *
 * What it does stop is raw PII coming to rest in a signed event. Every other
 * observe-only integration in this SDK has run this net for as long as it has
 * existed; this one ran no policy pipeline of any kind, so at any sample rate
 * it wrote whatever the agent said straight into the chain. The canary half
 * was already covered — that net lives in `buildIntegrationEvent` and fires on
 * every path — so the gap was the PII half alone, and the README described it
 * as closed in both languages while it was closed in one.
 *
 * Twin: sdk-python/obsvr/integrations/openai_agents.py (`_govern_stored`),
 * deliberately, because a third spelling of the same decision is how two of
 * them drift.
 */
function governStored(
  promptText: string,
  responseText: string,
  config: ResolvedConfig,
): { prompt: string; response: string; compliance?: ComplianceInfo } {
  const joined = [promptText, responseText].filter(Boolean).join("\n");
  if (!joined) return { prompt: promptText, response: responseText };
  const { shouldRedactStored, compliance, storedRedactionVia } = applyObservePolicy(
    joined,
    config,
  );
  if (!shouldRedactStored) return { prompt: promptText, response: responseText, compliance };
  return {
    prompt: promptText ? redactForStorage(promptText, storedRedactionVia) : promptText,
    response: responseText ? redactForStorage(responseText, storedRedactionVia) : responseText,
    compliance,
  };
}

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

// ---------------------------------------------------------------------------
// Pre-execution tool gate — the guardrail mechanism
// ---------------------------------------------------------------------------

/** The one obsvr guardrail name; attachment is idempotent against it. */
const TOOL_GATE_GUARDRAIL_NAME = "obsvr_tool_gate";

/** Blocked-tool verdict (fresh per call so one event's compliance cannot
 *  bleed into the next — same posture as the Python twin). */
function toolDeniedCompliance(): ComplianceInfo {
  return {
    event_type: "blocked_call",
    policy_version: "none",
    action_taken: "blocked",
    action_reason: "policy_violation",
    reason_code: ReasonCode.TOOL_DENIED,
    action_source: "policy_rules",
    redacted_types: [],
    blocked_types: [],
  };
}

/** The guardrail contract's output shapes, spelled explicitly. A missing
 *  `behavior` is normalized to ALLOW by the framework — fail-open — so every
 *  return from the gate carries one on purpose. */
interface ToolGateGuardrailOutput {
  outputInfo?: unknown;
  behavior:
    | { type: "allow" }
    | { type: "rejectContent"; message: string };
}

/** Duck-typed shape of an @openai/agents tool input guardrail definition. */
export interface ObsvrToolInputGuardrail {
  type: "tool_input";
  name: string;
  run: (data: unknown) => Promise<ToolGateGuardrailOutput>;
}

/**
 * A tool input guardrail enforcing the `agentPolicy` tool list.
 *
 * The executor awaits tool input guardrails BEFORE invoking the tool, so a
 * refusal here binds: the tool's callable is never entered. Refusal is by the
 * guardrail contract's returned sentinel — `rejectContent` — which hands the
 * model the block message as the tool's result and lets the run continue. The
 * record is `blocked`/`TOOL_DENIED`, true on this path.
 *
 * The guardrail never throws. A throw from a guardrail becomes
 * `ToolInputGuardrailTripwireTriggered` → `ToolCallError` and aborts the
 * caller's WHOLE RUN — an internal obsvr failure must not become the host's
 * outage. So an internal failure follows `failMode`: the default "open"
 * allows the call with this layer lost, "closed" refuses it through the same
 * sentinel.
 *
 * Prefer {@link attachToolGate}, which attaches this across an agent's tools
 * and returns a detach handle.
 */
export function makeToolGateGuardrail(
  options: IntegrationOptions = {},
): ObsvrToolInputGuardrail {
  return {
    type: "tool_input",
    name: TOOL_GATE_GUARDRAIL_NAME,
    run: async (data: unknown): Promise<ToolGateGuardrailOutput> => {
      try {
        const config = tryGetConfig();
        if (!config) return { behavior: { type: "allow" } };
        const policy = config.agentPolicy;
        if (!policy) return { behavior: { type: "allow" } };
        const toolCall = ((data as Record<string, unknown> | undefined)
          ?.toolCall ?? {}) as Record<string, unknown>;
        const toolName = String(toolCall.name ?? "unknown_tool");
        const { allowed, reason } = checkTool(toolName, policy);
        if (allowed) return { behavior: { type: "allow" } };
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
            tool_name: toolName,
            reason,
            tool_call_id: String(toolCall.callId ?? ""),
          },
          compliance: toolDeniedCompliance(),
          options,
        });
        return {
          outputInfo: { obsvr: { reason } },
          behavior: {
            type: "rejectContent",
            message: `[obsvr] Tool '${toolName}' blocked by agent policy (${reason})`,
          },
        };
      } catch {
        if (tryGetConfig()?.failMode === "closed") {
          return {
            behavior: {
              type: "rejectContent",
              message:
                "[obsvr] Tool blocked: policy evaluation failed (failMode=closed)",
            },
          };
        }
        return { behavior: { type: "allow" } };
      }
    },
  };
}

export interface AttachToolGateOptions extends IntegrationOptions {
  /** Walk handoff targets reachable from this agent too (the default). */
  includeHandoffs?: boolean;
}

function isAgentLike(obj: unknown): obj is Record<string, unknown> {
  return (
    !!obj &&
    typeof obj === "object" &&
    Array.isArray((obj as Record<string, unknown>).tools) &&
    Array.isArray((obj as Record<string, unknown>).handoffs)
  );
}

function attachGateToAgent(
  agent: Record<string, unknown>,
  guardrail: ObsvrToolInputGuardrail,
  attached: Array<Record<string, unknown>>,
  ungateable: string[],
  visited: Set<unknown>,
  includeHandoffs: boolean,
): void {
  if (visited.has(agent)) return;
  visited.add(agent);
  for (const entry of agent.tools as unknown[]) {
    const tool = entry as Record<string, unknown> | undefined;
    // Hosted provider-side tools carry no client-side invocation to guard.
    if (tool?.type !== "function") continue;
    if (!Array.isArray(tool.inputGuardrails)) {
      // The array is created by tool() itself on every build that ALSO
      // consults it, so its absence means the build predates the mechanism.
      // Setting the property anyway would arm a gate no executor ever asks —
      // the silent no-op shape — so the tool is reported instead.
      ungateable.push(String(tool.name ?? "unknown_tool"));
      continue;
    }
    const guardrails = tool.inputGuardrails as Array<Record<string, unknown>>;
    if (guardrails.some((g) => g?.name === TOOL_GATE_GUARDRAIL_NAME)) continue;
    guardrails.push(guardrail as unknown as Record<string, unknown>);
    attached.push(tool);
    registerGovernedToolName(String(tool.name ?? "unknown_tool"));
  }
  if (!includeHandoffs) return;
  for (const entry of agent.handoffs as unknown[]) {
    const target = isAgentLike(entry)
      ? entry
      : isAgentLike((entry as Record<string, unknown> | undefined)?.agent)
        ? ((entry as Record<string, unknown>).agent as Record<string, unknown>)
        : undefined;
    if (target) {
      attachGateToAgent(
        target,
        guardrail,
        attached,
        ungateable,
        visited,
        includeHandoffs,
      );
    }
  }
}

/**
 * Attach the pre-execution tool gate to every function tool on `agent`.
 *
 * Pushes obsvr's guardrail into each function tool's own `inputGuardrails` —
 * the framework's per-tool extension point, read fresh by the executor before
 * every invocation. Attachment is BY TOOL OBJECT: a tool shared between two
 * agents is gated for both, and a tool constructed after this call is not
 * gated until it is attached too. With `includeHandoffs` (the default),
 * handoff targets reachable from this agent — directly or through a
 * `handoff()` object's agent reference — are walked as well, cycles included.
 *
 * Not covered, stated rather than implied: hosted provider-side tools (no
 * client-side invocation to guard) and MCP-server tools, which the framework
 * converts per turn after this call runs — govern those at the MCP boundary,
 * where obsvr already enforces.
 *
 * Returns an idempotent detach handle that removes exactly what this call
 * attached. THROWS LOUDLY when a function tool carries no `inputGuardrails`
 * array — that build's executor never consults guardrails, and a silent
 * no-op install would be a gate the caller believes in and does not have;
 * gate those tools with `obsvrGovernTool` instead (its refusal aborts the
 * run rather than returning a denial to the model).
 */
export function attachToolGate(
  agent: unknown,
  options: AttachToolGateOptions = {},
): () => void {
  const guardrail = makeToolGateGuardrail(options);
  const attached: Array<Record<string, unknown>> = [];
  const ungateable: string[] = [];
  if (!isAgentLike(agent)) {
    throw new Error(
      "[obsvr] attachToolGate expects an @openai/agents Agent (an object " +
        "carrying tools[] and handoffs[])",
    );
  }
  attachGateToAgent(
    agent,
    guardrail,
    attached,
    ungateable,
    new Set(),
    options.includeHandoffs !== false,
  );
  if (ungateable.length > 0) {
    // Refuse loudly AFTER undoing the partial attach: a half-armed gate that
    // throws reads as installed to the caller who catches.
    for (const tool of attached) {
      const arr = tool.inputGuardrails as unknown[];
      const at = arr.indexOf(guardrail as unknown);
      if (at >= 0) arr.splice(at, 1);
    }
    throw new Error(
      `[obsvr] this @openai/agents build carries no inputGuardrails array on ` +
        `tool(s) ${ungateable.join(", ")}, so its executor never consults ` +
        `tool input guardrails and the pre-execution gate cannot install. ` +
        `Gate the tools themselves instead: obsvrGovernTool`,
    );
  }
  let removed = false;
  return function detach(): void {
    if (removed) return;
    removed = true;
    for (const tool of attached) {
      const arr = tool.inputGuardrails as unknown[];
      const at = arr.indexOf(guardrail as unknown);
      if (at >= 0) arr.splice(at, 1);
    }
  };
}

/**
 * SpanProcessor-compatible processor for the OpenAI Agents SDK.
 *
 * Emits audit events for agent run lifecycle, tool calls, and LLM generations.
 * OBSERVES `agentPolicy`: a function span ends after its tool has returned,
 * and the processor hooks are dispatched fire-and-forget, so nothing here can
 * refuse anything. Refusal lives in {@link attachToolGate} (a denied tool
 * comes back to the model as a blocked-tool result) and `obsvrGovernTool`
 * (a denied tool aborts the run); this processor is the audit rail beneath
 * them.
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
    // Only the agent span derives anything from its START (run.start). The
    // function and generation branches used to run on both deliveries, which
    // emitted every tool call twice — two tool.call events, two
    // tool_not_evaluated events — and charged stepCount twice, tripping
    // maxSteps at half its budget. Their payload is complete at END, so that
    // is the one delivery they process.
    const spanData = (span.spanData ?? {}) as Record<string, unknown>;
    if (spanData.type !== "agent") return;
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
          // A name a real pre-execution gate speaks for (the guardrail from
          // attachToolGate, or an obsvrGovernTool wrapper) already carries
          // the gate's own verdict; stamping not_evaluated beside it would
          // contradict a true blocked record.
          if (!allowed && !isToolGoverned(toolName)) {
            emitIntegrationEvent({
              config,
              provider: "unknown",
              model: "unknown",
              operation: "openai_agents.agent.policy.tool_not_evaluated",
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
              // This surface CANNOT refuse, so it must not say it did. The
              // hooks are dispatched fire-and-forget and a function span does
              // not end until its tool has returned, so by the time the gate
              // sees a call there is nothing left to prevent. It previously
              // recorded `blocked` with TOOL_DENIED about calls that had
              // completed and returned their result to the caller.
              compliance: toolGateNotEvaluatedCompliance(
                "openai_agents.tool.call",
                "tool_gate",
                `tool policy would have refused this call (${reason}), but the ` +
                  `decision is reached after the tool has already returned and ` +
                  `cannot bind it; enforce with obsvrGovernTool instead`,
              ),
              options: this.opts,
            });
          }

          const stepAction = checkSteps(stepIndex, agentPolicy);
          if (state) {
            state.stepCount += 1;
            // Loop detection
            if (state.loopDetector) {
              // canHalt: false — nothing thrown from here reaches the run, so
              // the finding is recorded without claiming the halt happened.
              applyLoopDetection(state.loopDetector, config, {
                agentRunId: traceId,
                source: SOURCE,
                operation: "openai_agents.agent",
                canHalt: false,
              });
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
              compliance: toolGateNotEvaluatedCompliance(
                "openai_agents.agent.policy.step_limit",
                "step_limit",
                "the step budget is exhausted but this surface cannot halt the " +
                  "run; the limit is observed, not enforced",
              ),
              options: this.opts,
            });
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

        const genStored = governStored(promptText, responseText, config);

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
          prompt: genStored.prompt,
          response: genStored.response,
          compliance: genStored.compliance,
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
        const respStored = governStored(promptText, responseText, config);

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
          prompt: respStored.prompt,
          response: respStored.response,
          compliance: respStored.compliance,
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
