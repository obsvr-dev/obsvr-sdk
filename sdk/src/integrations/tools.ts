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
  evaluateToolTaintGate,
  touchTaint,
  sessionTaintSize,
} from "../policy/session-taint.js";
import {
  safeToolContentHash,
  toolContentMetadata,
  type ToolContentDescriptor,
} from "../policy/tool-content-hash.js";
import { describeError, recordDetectorFailure } from "../policy/detector-guard.js";
import { ReasonCode } from "../governance/reason-codes.js";

const SOURCE = "obsvr_tool";

/** A refusal that must reach the caller: either the taint latch's own block or
 *  a detector failure that resolved closed. Carried out of the guard as a value
 *  so the guard cannot swallow the enforcement it exists to protect. */
interface ToolBlock {
  rule_id: string;
  policy_reason: string;
  message: string;
  /** Registry code for the classification; absent derives at event build. */
  reason_code?: string;
}

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

/**
 * The tool's descriptor, under the evidence contract's MCP wire names. The
 * input-schema property is spelled differently per framework (Vercel
 * `inputSchema`/`parameters`, LangChain `schema`), so all three are accepted;
 * a tool carrying none contributes no schema rather than a guessed one.
 */
function toolContentDescriptorOf(t: AnyTool): ToolContentDescriptor {
  const schema = t.inputSchema ?? t.parameters ?? t.schema;
  return {
    name: typeof t.name === "string" ? t.name : undefined,
    description: typeof t.description === "string" ? t.description : undefined,
    inputSchema: schema === undefined || typeof schema === "function" ? undefined : schema,
  };
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

      // Sealed evidence of WHICH tool content and arguments this call saw. The
      // tool object IS the descriptor here, so the digest covers both halves.
      // Computed once and stamped on every event this call emits - including
      // the blocked ones, where "what was refused" is the point of the record.
      const toolContentMeta = toolContentMetadata(
        safeToolContentHash({
          toolName,
          descriptor: toolContentDescriptorOf(t),
          args: input,
        }),
      );

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
              ...toolContentMeta,
            },
            // TOOL_DENIED covers both refusal shapes: an explicit deny list
            // hit and absence from a configured allowlist are the same
            // classification — this tool may not run.
            compliance: { ...BLOCKED_COMPLIANCE, reason_code: ReasonCode.TOOL_DENIED },
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
      //
      // Guarded: a defect in the taint layer resolves here instead of
      // escaping into the host's own tool call. The INTENDED block travels
      // back out of the try as a descriptor rather than a throw — a guard
      // that swallowed its own enforcement would be worse than no guard.
      let toolTaintFlag: string | undefined;
      let toolBlock: ToolBlock | undefined;
      try {
        const taintCfg = resolveSessionTaint(config);
        if (taintCfg && sessionTaintSize() > 0) {
          const taintKey = deriveSessionKey(
            (options.metadata ?? {}) as Record<string, unknown>,
          );
          // Tool-aware: a tainted session in flag mode still loses its
          // DESTRUCTIVE capabilities (sessionTaint.destructiveTools) — the
          // composition that stops indirect injection without bricking the
          // session. One set-membership test.
          const verdict = evaluateToolTaintGate(taintKey, taintCfg, toolName);
          if (verdict.enforcement !== "none") {
            touchTaint(taintKey, Date.now());
            if (verdict.enforcement === "block") {
              toolBlock = {
                rule_id: "sdk:session_tainted",
                policy_reason: verdict.destructive
                  ? `Session previously compromised (${verdict.reason}); destructive capability '${toolName}' denied`
                  : `Session previously compromised (${verdict.reason}); tool call escalated`,
                message: verdict.destructive
                  ? `[obsvr] Tool blocked: destructive capability denied for tainted session (${verdict.reason})`
                  : `[obsvr] Tool blocked: session tainted (${verdict.reason})`,
                // A taint-gated refusal of outbound egress (a tool call is the
                // most side-effecting transmission there is).
                reason_code: ReasonCode.TRANSMISSION_BLOCKED,
              };
            } else {
              toolTaintFlag = verdict.reason; // flag mode: annotate below
            }
          }
        }
      } catch (err) {
        // session_taint is a scanning layer, so failMode decides: open lets
        // the tool run with this layer's enforcement lost, closed refuses it.
        if (recordDetectorFailure("session_taint", err, config)) {
          toolBlock = {
            rule_id: "sdk:detector_error",
            policy_reason:
              `Detector layer 'session_taint' raised ${describeError(err)}; resolved closed (failMode)`.slice(
                0,
                256,
              ),
            message: "[obsvr] Tool blocked: session_taint detector failed (failMode=closed)",
          };
        }
      }

      if (toolBlock) {
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
          metadata: { tool_name: toolName, ...toolContentMeta },
          compliance: {
            ...BLOCKED_COMPLIANCE,
            rule_id: toolBlock.rule_id,
            policy_reason: toolBlock.policy_reason,
            ...(toolBlock.reason_code !== undefined
              ? { reason_code: toolBlock.reason_code }
              : {}),
          },
          options,
        });
        throw new Error(toolBlock.message);
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
        metadata: { tool_name: toolName, ...toolContentMeta },
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
