/**
 * Framework-agnostic tool governance.
 *
 * `obsvrGovernTool(tool)` wraps a tool definition from ANY agent framework —
 * Vercel AI (`execute`), LlamaIndex (`call`), LangChain (`func`/`invoke`) — so
 * that every invocation of that tool is governed at the point of execution:
 *
 *   1. allow/deny against `agentPolicy` (deniedTools / allowedTools) — a denied
 *      tool THROWS before its function runs, blocking it;
 *   2. built-in PII scan on the tool arguments (redacted in the signed record);
 *   3. a signed `tool.call` audit event (RFC-chained like every obsvr event).
 *
 * This works regardless of whether the framework surfaces tool calls through a
 * callback/hook (many don't, or change across versions) because it governs the
 * tool's own execute function directly. Wrap your tools once and pass the
 * wrapped versions to your agent.
 *
 *   import { obsvrGovernTool } from "@obsvr/sdk";
 *   const safeCalc = obsvrGovernTool(calculatorTool, { name: "calculator" });
 *
 * @packageDocumentation
 */
import {
  emitIntegrationEvent,
  redactForStorage,
  applyObservePolicy,
  tryGetConfig,
  setupExitHandlers,
  type IntegrationOptions,
  type ComplianceInfo,
} from "./core.js";
import {
  resolveSessionTaint,
  deriveSessionKey,
  evaluateSessionTaint,
  touchTaint,
  sessionTaintSize,
} from "../policy/session-taint.js";

const SOURCE = "obsvr_tool";

/** Verdict for a tool that was blocked by policy (so it reads as BLOCKED, not
 *  the default "allowed"/"llm_call"). */
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

export interface GovernToolOptions extends IntegrationOptions {
  /**
   * Explicit tool name. Needed for frameworks (e.g. Vercel AI) whose tool
   * objects carry no name — the name lives on the enclosing `tools` map key.
   * Falls back to `tool.name` then `tool.metadata.name`.
   */
  name?: string;
}

type AnyTool = Record<string, unknown>;

/** Which property holds the tool's execute function, across frameworks. */
function resolveExecKey(t: AnyTool): string | null {
  for (const key of ["execute", "call", "func", "invoke"]) {
    if (typeof t[key] === "function") return key;
  }
  return null;
}

function resolveToolName(t: AnyTool, opts: GovernToolOptions): string {
  const meta = t.metadata as { name?: unknown } | undefined;
  return (
    opts.name ??
    (typeof t.name === "string" ? t.name : undefined) ??
    (typeof meta?.name === "string" ? meta.name : undefined) ??
    "unknown_tool"
  );
}

function safeJson(v: unknown): string {
  if (typeof v === "string") return v;
  try {
    return JSON.stringify(v ?? {});
  } catch {
    return String(v);
  }
}

/**
 * Wrap a framework tool so its execution is governed by obsvr. Returns a
 * proxy that behaves exactly like the original tool but gates its execute
 * function. If the tool shape isn't recognized, the original is returned
 * unchanged (never breaks the caller).
 */
export function obsvrGovernTool<T>(tool: T, options: GovernToolOptions = {}): T {
  const t = tool as unknown as AnyTool;
  const execKey = resolveExecKey(t);
  if (!execKey) return tool;

  const toolName = resolveToolName(t, options);
  const original = t[execKey] as (...args: unknown[]) => unknown;

  const cfgAtWrap = tryGetConfig();
  if (cfgAtWrap) setupExitHandlers(cfgAtWrap);

  const gated = function (this: unknown, ...args: unknown[]): unknown {
    const config = tryGetConfig();
    if (config) {
      // Tool input position differs by framework: Vercel `execute(input, opts)`,
      // LlamaIndex `call(input)`, LangChain `func(input)` all put it at arg 0;
      // OpenAI Agents `invoke(runContext, input)` puts it at arg 1 (arg 0 is the
      // run context). Pick arg 1 for the invoke shape, else arg 0.
      const input = execKey === "invoke" && args.length >= 2 ? args[1] : args[0];
      const inputText = safeJson(input);

      // 1) allow/deny — BLOCK a denied tool before it runs.
      const policy = config.agentPolicy;
      if (policy) {
        const denied = (policy.deniedTools ?? []).includes(toolName);
        const notAllowed =
          policy.allowedTools !== undefined && !policy.allowedTools.includes(toolName);
        if (denied || notAllowed) {
          emitIntegrationEvent({
            config,
            provider: "unknown",
            model: "unknown",
            operation: "tool.policy.tool_blocked",
            source: SOURCE,
            prompt: "",
            response: "",
            success: false,
            metadata: {
              tool_name: toolName,
              reason: denied ? "tool_denied" : "tool_not_in_allowlist",
            },
            compliance: BLOCKED_COMPLIANCE,
            options,
          });
          throw new Error(`[obsvr] Tool blocked by agent policy: ${toolName}`);
        }
      }

      // 1.5) Session taint latch: tool execution is a real, side-effecting
      // egress — the MOST dangerous one — so a session compromised on an
      // earlier turn has its tool calls escalated. Keyed on options.metadata
      // identity (same derivation as every other egress). block mode refuses
      // the tool before it runs; flag mode records it on the event.
      const taintCfg = resolveSessionTaint(config);
      let toolTaintFlag: string | undefined;
      if (taintCfg && sessionTaintSize() > 0) {
        const taintKey = deriveSessionKey(
          (options.metadata ?? {}) as Record<string, unknown>,
        );
        const verdict = evaluateSessionTaint(taintKey, taintCfg);
        if (verdict.enforcement !== "none") {
          touchTaint(taintKey, Date.now());
          if (verdict.enforcement === "block") {
            emitIntegrationEvent({
              config,
              provider: "unknown",
              model: "unknown",
              operation: "tool.call",
              source: SOURCE,
              prompt: "",
              response: "",
              success: false,
              statusCode: 403,
              metadata: { tool_name: toolName },
              compliance: {
                ...BLOCKED_COMPLIANCE,
                rule_id: "sdk:session_tainted",
                policy_reason: `Session previously compromised (${verdict.reason}); tool call escalated`,
              },
              options,
            });
            throw new Error(`[obsvr] Tool blocked: session tainted (${verdict.reason})`);
          }
          toolTaintFlag = verdict.reason; // flag mode: annotate below
        }
      }

      // 2) PII scan on the arguments; redact in the stored record. A
      // view-only hit (storedRedactionVia) has no locatable span, so the
      // stored copy becomes a whole-text placeholder via redactForStorage.
      const { shouldRedactStored, storedRedactionVia } = applyObservePolicy(inputText, config);
      const recordedArgs = shouldRedactStored
        ? redactForStorage(inputText, storedRedactionVia)
        : inputText;

      // 3) signed tool.call audit event.
      emitIntegrationEvent({
        config,
        provider: "unknown",
        model: "unknown",
        operation: "tool.call",
        source: SOURCE,
        prompt: recordedArgs,
        response: "",
        metadata: { tool_name: toolName },
        compliance: toolTaintFlag !== undefined
          ? {
              ...TOOL_CALL_COMPLIANCE,
              event_type: "policy_flag",
              action_reason: "policy_violation",
              rule_id: "sdk:session_tainted",
              policy_reason: `Session previously compromised (${toolTaintFlag}); tool call flagged`,
            }
          : TOOL_CALL_COMPLIANCE,
        options,
      });
    }
    // Always invoke the real tool bound to the real target.
    return original.apply(t, args);
  };

  return new Proxy(t, {
    get(target, prop, receiver) {
      if (prop === execKey) return gated;
      const value = Reflect.get(target, prop, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  }) as unknown as T;
}

/** Wrap several tools at once. Names are read from each tool (or pass a map). */
export function obsvrGovernTools<T extends unknown[]>(
  tools: [...T],
  options: GovernToolOptions = {},
): [...T] {
  return tools.map((tl) => obsvrGovernTool(tl, options)) as [...T];
}
