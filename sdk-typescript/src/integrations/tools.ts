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
  toolGateNotEvaluatedCompliance,
  tryGetConfig,
  setupExitHandlers,
  destructiveSourceLabel,
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
import { declaresDestructive } from "../policy/capability-hints.js";
import { getCurrentSubject } from "../proxy/subject.js";
import { describeError, recordDetectorFailure } from "../policy/detector-guard.js";
import { ReasonCode } from "../governance/reason-codes.js";

const SOURCE = "obsvr_tool";

/**
 * Answered `true` by the Proxy every governed tool IS, and checked before
 * wrapping, so governing twice yields one gate: without it a second wrap
 * re-gates the first proxy's gated function and every invocation is
 * evaluated and audited twice. The marker is served by the proxy's `get`
 * trap only — it is never written onto the caller's original object, and a
 * tool whose shape resolved no execute key is returned unchanged and
 * unmarked, so a later legitimate attempt still runs rather than being
 * refused by a claim no gate backs. `Symbol.for` so two copies of the SDK
 * in one process still recognize each other's proxies.
 */
const GOVERNED_TOOL_MARKER = Symbol.for("obsvr.governedTool");

/**
 * Names of every tool a pre-execution gate speaks for — the wrapper below, or
 * an integration-owned gate registered through {@link registerGovernedToolName}
 * (openai-agents' tool input guardrails). Audit rails that would otherwise
 * re-judge a governed call after the fact consult this so they never stamp
 * `not_evaluated` beside a real gate's own verdict. Process-lifetime by
 * design — a governed name stays the gate's to speak for. Twin of the Python
 * `_GOVERNED_TOOL_NAMES` registry.
 */
const GOVERNED_TOOL_NAMES = new Set<string>();

/** Whether a tool of this name is governed by a pre-execution gate. */
export function isToolGoverned(toolName: string): boolean {
  return GOVERNED_TOOL_NAMES.has(toolName);
}

/** Record that a pre-execution gate outside this module speaks for a name. */
export function registerGovernedToolName(toolName: string): void {
  GOVERNED_TOOL_NAMES.add(toolName);
}

/** Test hook. The registry is process-lifetime everywhere else. */
export function _resetGovernedToolNames(): void {
  GOVERNED_TOOL_NAMES.clear();
}

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

/**
 * Verdict for an allowed tool call that NO pre-call policy layer judged —
 * the fallback used only when nothing the shared pipeline enforces was
 * configured, so there was no evaluation to evidence.
 *
 * `action_source` is "unknown" rather than "policy_rules" for exactly that
 * reason: this permit is not the rules engine's, and naming that layer here
 * credited a verdict it had never issued. The layers this file enforces on its
 * own (the allow/deny gate, requirePrincipal, the taint latch) speak through
 * their own compliance records when they refuse.
 */
const TOOL_CALL_COMPLIANCE: ComplianceInfo = {
  event_type: "tool_call",
  policy_version: "none",
  action_taken: "allowed",
  action_reason: "none",
  action_source: "unknown",
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

/**
 * Which property holds the tool's execute function, across frameworks.
 *
 * ORDER IS THE CONTRACT, AND THE LAST THREE WERE APPENDED RATHER THAN INSERTED.
 * The first four are framework tool objects and resolve exactly as before, so no
 * tool that is gated today is gated differently. The last three are the shapes a
 * PROVIDER TOOL RUNNER dispatches. Until they were here this function returned
 * null for all of them, and line 147 then returned the tool unchanged — no gate,
 * no error, no event. So the mitigation both READMEs point a caller toward for
 * the one surface obsvr was not on was itself a silent no-op on that surface.
 *
 *   run        a runner tool entry the runner invokes as `tool.run(input)`.
 *   function   the INNER half of `{ type: "function", function: {...} }`. The
 *              outer entry carries only `type` and that object, so there is
 *              nothing gateable on it; the runner dispatches the inner object's
 *              own `function` property.
 *   $callback  a tool built by a provider schema helper. The runner normalises
 *              it into the shape above by reading this property, so replacing it
 *              is what reaches execution.
 */
function resolveExecKey(t: AnyTool): string | null {
  for (const key of ["execute", "call", "func", "invoke", "run", "function", "$callback"]) {
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
  // Governing an already-governed proxy is a no-op returning it unchanged:
  // re-gating the first proxy's gated function would evaluate and audit
  // every invocation twice.
  if ((t as Record<PropertyKey, unknown>)[GOVERNED_TOOL_MARKER] === true) return tool;
  const execKey = resolveExecKey(t);
  if (!execKey) return tool;

  const toolName = resolveToolName(t, options);
  const original = t[execKey] as (...args: unknown[]) => unknown;
  GOVERNED_TOOL_NAMES.add(toolName);

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

      // 1.15) The enforcing identity view, resolved ONCE for every gate below.
      //
      // A principal reaches this boundary by three channels — per-call
      // metadata, the wrap-time option, the ambient useSubject() scope — and
      // each gate below has to enforce on the same one. Resolving per gate is
      // how they drift: the require-principal gate read all three while the
      // taint key read the raw metadata object alone, so a caller who
      // attributed through either of the other two satisfied the gate and was
      // then keyed to the 'global' taint bucket. core.ts SETS the taint under
      // the resolved principal, so SET and ENFORCE disagreed and the latch
      // never fired for that caller — on the most side-effecting egress the
      // SDK governs.
      //
      // Precedence is this surface's existing contract (per-call metadata,
      // then the wrap-time option, then the ambient subject), matching the
      // signed principal in buildAuditEvent so the view that ENFORCES and the
      // view that is RECORDED name the same caller. Twin of Python's
      // `_identity_meta`, which folded these three the same way.
      //
      // A FUNCTION, not a value, because the two consumers below need
      // different postures toward a metadata object that throws when read —
      // and a hostile object is a real vector here, not a hypothetical. The
      // require-principal gate calls it defensively (unreadable counts as
      // absent, matching core.ts's pre-guard read); the taint layer calls it
      // inside its own guard so the same defect is recorded as a detector
      // failure and resolved by failMode. One resolution, two dispositions.
      const enforcingIdentity = (): Record<string, unknown> => {
        const ambient = getCurrentSubject();
        const view: Record<string, unknown> = {
          ...((options.metadata ?? {}) as Record<string, unknown>),
        };
        const userId = view.user_id ?? options.user_id ?? ambient?.user_id;
        const serviceName = view.service_name ?? options.service_name ?? ambient?.service_name;
        const tenantId = view.tenant_id ?? ambient?.tenant_id;
        if (userId !== undefined) view.user_id = userId;
        if (serviceName !== undefined) view.service_name = serviceName;
        if (tenantId !== undefined) view.tenant_id = tenantId;
        return view;
      };

      // 1.2) Required principal (opt-in): an unattributed tool call is
      // refused before any scanning layer runs — the refusal is about
      // attribution, not content. An empty string is a supplied principal;
      // only an absent one refuses (Python parity: the same gate inside the
      // shared pre-call pipeline). A metadata object that throws on read is
      // an ABSENT principal, not a readable one: this gate runs ahead of the
      // detector guard, and refusing an unattributed call is the safe answer
      // when the attribution cannot be read at all.
      if (config.requirePrincipal === true) {
        let principal: unknown;
        try {
          principal = enforcingIdentity().user_id;
        } catch {
          principal = undefined;
        }
        if (principal == null) {
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
              reason: "principal_required",
              ...toolContentMeta,
            },
            compliance: {
              ...BLOCKED_COMPLIANCE,
              reason_code: ReasonCode.PRINCIPAL_REQUIRED,
              rule_id: "sdk:principal_required",
              policy_reason:
                "requirePrincipal is set and the call carries no user_id on the enforcing channel",
            },
            options,
          });
          throw new Error(
            `[obsvr] Tool blocked: no caller principal supplied (requirePrincipal): ${toolName}`,
          );
        }
      }

      // 1.5) Session taint latch: tool execution is a real, side-effecting
      // egress — the MOST dangerous one — so a session compromised on an
      // earlier turn has its tool calls escalated. Keyed on the resolved
      // identity above, which is the derivation core.ts uses to SET the taint;
      // deriveSessionKey's contract is that SET and ENFORCE agree. block mode
      // refuses the tool before it runs; flag mode records it on the event.
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
          const taintKey = deriveSessionKey(enforcingIdentity());
          // Tool-aware: a tainted session in flag mode still loses its
          // DESTRUCTIVE capabilities — the composition that stops indirect
          // injection without bricking the session. One set-membership test
          // against the operator's list, unioned with the tool object's own
          // destructiveHint. A framework tool adapted from MCP usually carries
          // its original annotations, so the hint is worth reading here too;
          // one that carries none is simply not hinted.
          const verdict = evaluateToolTaintGate(
            taintKey,
            taintCfg,
            toolName,
            declaresDestructive(t),
          );
          if (verdict.enforcement !== "none") {
            touchTaint(taintKey, Date.now());
            if (verdict.enforcement === "block") {
              toolBlock = {
                rule_id: "sdk:session_tainted",
                policy_reason: verdict.destructive
                  ? `Session previously compromised (${verdict.reason}); destructive capability '${toolName}' denied (${destructiveSourceLabel(verdict.destructiveSource)})`
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

      // 1.8) Which configured pre-call layers this synchronous gate could NOT
      // consult, so the record says so instead of claiming a permit for them.
      //
      // The shared pre-call pipeline — the PII policy, the customer rule set,
      // the anti-tamper floor, the pre-call hook — is `async` in TypeScript
      // (the hook and the external backend are awaited), and this gate cannot
      // be: it wraps sync tool functions as well as async ones, so awaiting
      // here would hand every sync caller a Promise and change the tool's
      // contract. Python's pipeline is synchronous, which is why `_gate` there
      // consults it and this does not.
      //
      // That is a coverage gap, and it stays one. What it must not be is a
      // false record: a call these layers never saw recorded `allowed` under
      // `action_source: "policy_rules"`, crediting the rules engine with a
      // permit it was never asked for. So when one of those layers is
      // CONFIGURED, this reports the absence and names it — the same
      // `not_evaluated` shape the tool-runner path and Python's tool gate use.
      // Nothing configured means nothing was skipped, and the call records a
      // plain permit naming no deciding layer.
      const unconsulted: string[] = [];
      if (config.policyFloor && config.policyFloor.length > 0) unconsulted.push("policy_floor");
      if (config.policyRules && config.policyRules.length > 0) unconsulted.push("policy_rules");
      if (config.pii_policy) unconsulted.push("pii_policy");
      if (config.on_pre_call) unconsulted.push("customer_hook");

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
        // A configured layer this gate could not consult makes the honest
        // verdict `not_evaluated`, not `allowed` — see 1.8. The taint flag
        // still rides on top when the latch flagged the call, because that
        // latch DID run: the two say different things about different layers
        // and both belong on the record.
        compliance: toolTaintFlag !== undefined
          ? {
              ...(unconsulted.length
                ? toolGateNotEvaluatedCompliance(
                    "obsvr_tool",
                    unconsulted.join("+"),
                    `${unconsulted.join(", ")} configured, but the synchronous tool gate cannot await the pre-call pipeline`,
                  )
                : TOOL_CALL_COMPLIANCE),
              event_type: "policy_flag",
              action_reason: "policy_violation",
              rule_id: "sdk:session_tainted",
              policy_reason: `Session previously compromised (${toolTaintFlag}); tool call flagged`,
            }
          : unconsulted.length
            ? toolGateNotEvaluatedCompliance(
                "obsvr_tool",
                unconsulted.join("+"),
                `${unconsulted.join(", ")} configured, but the synchronous tool gate cannot await the pre-call pipeline`,
              )
            : TOOL_CALL_COMPLIANCE,
        options,
      });
    }
    // Always invoke the real tool bound to the real target.
    return original.apply(t, args);
  };

  return new Proxy(t, {
    get(target, prop, receiver) {
      // The idempotence marker: answered by the trap, never written onto the
      // caller's object — the proxy IS the installed gate, so its existence
      // is the verification the marker claims.
      if (prop === GOVERNED_TOOL_MARKER) return true;
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
