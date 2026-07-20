/**
 * MCP (Model Context Protocol) Integration
 *
 * Patches `@modelcontextprotocol/sdk` Client.prototype.callTool to intercept
 * tool invocations for auditing. Applies PII scanning on tool arguments and
 * enforces `mcpToolPolicy` (allowedTools / deniedTools).
 *
 * @example
 * ```ts
 * import { obsvr } from "@obsvr/sdk";
 *
 * obsvr.init({
 *   apiKey: "...",
 *   providers: ["mcp"],
 *   mcpToolPolicy: { deniedTools: ["dangerous_tool"] },
 * });
 *
 * // Any MCP Client.callTool() calls are now auto-audited.
 * ```
 *
 * @packageDocumentation
 */

import type { ResolvedConfig } from "../proxy/types.js";
import {
  applyPreCallPolicy,
  emitIntegrationEvent,
  setupExitHandlers,
  tryGetConfig,
  type ComplianceInfo,
  type IntegrationOptions,
} from "./core.js";
import { extractMcpPrompt, extractMcpResponse } from "../proxy/extractors/mcp.js";
import { derivePolicyVersion } from "../policy/rules.js";
import { scanMcpToolResult, sanitizeMcpResult, type McpPrincipal } from "../policy/response-scan.js";
import { isPolicyEnforcementDegraded } from "../proxy/config.js";
import { normalizeForMatching } from "../policy/normalize.js";
import { canaryRegistrySize } from "../policy/canary.js";
import { sessionTaintSize } from "../policy/session-taint.js";
import {
  createToolPinStore,
  evaluateToolPin,
  resolveToolPinning,
  toolDescriptorHash,
  type McpToolDescriptor,
  type ToolPinStore,
  type ToolPinVerdict,
} from "../policy/tool-pinning.js";
import { debugLog } from "../utils/logger.js";

// Re-exported so operators can precompute config pins from a known-good
// descriptor (additive public surface on the mcp subpath).
export { toolDescriptorHash, canonicalToolDescriptor } from "../policy/tool-pinning.js";
export type { McpToolDescriptor, ToolPinningConfig } from "../policy/tool-pinning.js";

const SOURCE = "mcp_sdk";
const PATCHED_SYMBOL = Symbol("obsvr-mcp-patched");

/** Cap on per-tool hashes carried in inventory-event metadata. */
const MAX_TOOL_HASHES_ON_EVENT = 50;

/**
 * Tool name for keying/events. Uses `?? "unknown"` (a present empty string
 * "" is kept, matching the Python twin's `name if name is not None`), and
 * tolerates a null/garbage tool entry without throwing.
 */
function mcpToolName(tool: unknown): string {
  const n = (tool as { name?: unknown } | null | undefined)?.name;
  return typeof n === "string" ? n : n == null ? "unknown" : String(n);
}

/**
 * Read an OWN string property of a config-pins map. Guards against a
 * server-controlled tool name colliding with an `Object.prototype` member
 * (`constructor`, `hasOwnProperty`, `toString`, `__proto__`), which a plain
 * index would resolve to an inherited function/object and then crash the
 * hex-compare. Non-own or non-string values read as absent.
 */
function ownStringProp(
  map: Record<string, string> | undefined,
  key: string,
): string | undefined {
  if (!map || !Object.prototype.hasOwnProperty.call(map, key)) return undefined;
  const v = (map as Record<string, unknown>)[key];
  return typeof v === "string" ? v : undefined;
}

/**
 * Per-client pin stores for the prototype-patch path: the patched methods are
 * shared on the prototype, so per-INSTANCE stores must be keyed off `this`
 * (a WeakMap so governed clients are never leaked).
 */
const patchPathPinStores = new WeakMap<object, ToolPinStore>();

function pinStoreForPatchedInstance(instance: unknown): ToolPinStore | undefined {
  if (instance === null || typeof instance !== "object") return undefined;
  let store = patchPathPinStores.get(instance);
  if (!store) {
    store = createToolPinStore();
    patchPathPinStores.set(instance, store);
  }
  return store;
}

/** One-time deprecation warning gate for patchMCP (reset only for tests). */
let patchMCPDeprecationWarned = false;

/** @internal test-only: re-arm the one-time patchMCP deprecation warning. */
export function _resetPatchMCPDeprecationWarning(): void {
  patchMCPDeprecationWarned = false;
}

/**
 * Check whether a tool name is permitted by the MCP tool policy.
 */
function checkMcpToolPolicy(
  toolName: string,
  policy: { allowedTools?: string[]; deniedTools?: string[] },
): { allowed: boolean; reason: string } {
  const denied = policy.deniedTools ?? [];
  const allowed = policy.allowedTools;
  if (denied.includes(toolName)) return { allowed: false, reason: "tool_denied" };
  if (allowed !== undefined && !allowed.includes(toolName)) {
    return { allowed: false, reason: "tool_not_in_allowlist" };
  }
  return { allowed: true, reason: "" };
}

/**
 * Patch the MCP SDK Client prototype to intercept `callTool` invocations.
 *
 * @param config - Resolved SDK configuration
 * @param opts - Per-integration options (source, region, etc.)
 */
/**
 * Patch a provided MCP Client class directly. Use this in ESM environments
 * where require() is unavailable and auto-instrumentation cannot patch via
 * the CJS require path.
 *
 * @example
 * ```ts
 * import { Client } from '@modelcontextprotocol/sdk/client/index.js';
 * import { obsvrGovernMCP } from '@obsvr/sdk/integrations/mcp';
 * obsvrGovernMCP(Client, resolvedConfig);
 * ```
 */
/**
 * Govern an MCP Client — NON-MUTATING (no monkey-patching).
 *
 * Pass the Client CLASS to get back a governed class (a construct-trap Proxy):
 * every `new GovernedClient()` is governed, the real Client prototype is never
 * touched, and it coexists with anything else. USE THE RETURNED CLASS:
 *
 *   const GovernedClient = obsvrGovernMCP(Client, getConfig());
 *   const client = new GovernedClient({ name, version }, { capabilities: {} });
 *
 * Or pass a Client INSTANCE to get back a governed instance:
 *
 *   const client = obsvrGovernMCP(new Client(...), getConfig());
 */
export function obsvrGovernMCP<T>(
  ClientClassOrInstance: T,
  config: ResolvedConfig,
  opts: IntegrationOptions = {},
): T {
  const target = ClientClassOrInstance as unknown;

  // A CLASS → construct-trap Proxy: wrap every instance it constructs.
  if (typeof target === "function" && (target as { prototype?: unknown }).prototype) {
    setupExitHandlers(config);
    return new Proxy(target as object, {
      construct(TargetClass, argumentsList) {
        const instance = Reflect.construct(TargetClass as new (...a: unknown[]) => object, argumentsList);
        return governClientInstance(instance, config, opts);
      },
    }) as T;
  }

  // An INSTANCE → wrap it directly.
  if (target && typeof (target as { callTool?: unknown }).callTool === "function") {
    setupExitHandlers(config);
    return governClientInstance(target as object, config, opts) as T;
  }

  debugLog(config, "info", "[obsvrGovernMCP] expected an MCP Client class or instance - returning unchanged");
  return ClientClassOrInstance;
}

/**
 * @deprecated Legacy prototype-mutating path — will be removed in the next
 * major release. Use {@link obsvrGovernMCP} instead: it is non-mutating and
 * coexists with other instrumentation.
 */
export function patchMCP(
  config: ResolvedConfig,
  opts: IntegrationOptions = {},
): void {
  if (!patchMCPDeprecationWarned) {
    patchMCPDeprecationWarned = true;
    console.warn(
      "[obsvr] patchMCP() is deprecated and will be removed in the next major release. " +
        "Use obsvrGovernMCP(Client, getConfig()) instead - it is non-mutating (no prototype patching).",
    );
  }
  // Resolve require - MCP SDK is an optional peer dependency
  let mod: any;
  if (typeof require === "undefined") {
    debugLog(config, "info", "[auto] MCP auto-patch requires CJS require - skipping");
    return;
  }
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    mod = require("@modelcontextprotocol/sdk/client/index.js");
  } catch {
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      mod = require("@modelcontextprotocol/sdk");
    } catch {
      debugLog(config, "info", "[auto] @modelcontextprotocol/sdk not installed - skipping");
      return;
    }
  }

  const ClientClass = mod?.Client ?? mod?.default?.Client ?? mod?.default;
  if (!ClientClass?.prototype) {
    debugLog(config, "info", "[auto] MCP Client class not found - skipping");
    return;
  }

  _applyMCPPatch(ClientClass, config, opts);
}

/**
 * Tool-poisoning detection patterns (defense for the MCP discovery phase).
 *
 * A malicious MCP server can embed instructions in tool *descriptions* that
 * the model reads during tools/list - before any tool is ever called. These
 * patterns flag instruction-shaped content where only capability descriptions
 * belong. Deterministic regex; no LLM in the decision path.
 */
const TOOL_POISONING_PATTERNS: Array<{ reason: string; re: RegExp }> = [
  { reason: "embedded_instruction_override", re: /(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|other|above)\s+(instructions?|tools?|rules?)/i },
  { reason: "embedded_directive_to_model", re: /\b(IMPORTANT|SYSTEM|NOTE)\s*(NOTE|MESSAGE)?\s*:\s*(before|first|always|you must|do not tell)/i },
  { reason: "cross_tool_invocation", re: /\b(first|before)\s+(calling|using)\s+(any\s+other|any|other|this)\s+tools?,?\s+(call|use|invoke)\b/i },
  { reason: "exfiltration_directive", re: /\b(send|post|forward|upload|transmit)\s+(all\s+)?((conversation|context|chat|user)\s+)?(history|messages?|data|contents?|context)\s+(to|at)\b/i },
  { reason: "concealment_directive", re: /\b(do\s+not|don'?t|never)\s+(tell|show|reveal|mention|inform)\s+(the\s+)?(user|human)\b/i },
];

/**
 * Scan a tool definition (name + description) for poisoning patterns.
 * Returns the matched reasons (empty array = clean).
 */
export function scanToolDescription(tool: { name?: string; description?: string }): string[] {
  // Normalize before matching (NFKC + confusable-fold + zero-width/bidi strip),
  // exactly like the PII/rules scanners. A malicious server can otherwise hide a
  // poisoning directive behind homoglyphs / zero-width chars and evade every
  // pattern below.
  const text = normalizeForMatching(`${tool?.name ?? ""} ${tool?.description ?? ""}`);
  const reasons: string[] = [];
  for (const { reason, re } of TOOL_POISONING_PATTERNS) {
    if (re.test(text)) reasons.push(reason);
  }
  return reasons;
}

/**
 * Scan + record a listTools result: emit the `mcp.tools.list` inventory event
 * (every discovery, clean or flagged) and optionally strip poisoned tools.
 * Shared by the non-mutating Proxy path and the legacy prototype patch.
 */
function processListToolsResult(
  result: unknown,
  currentConfig: ResolvedConfig,
  opts: IntegrationOptions,
  pinStore?: ToolPinStore,
  listArgs?: unknown[],
): unknown {
  const tools: Array<McpToolDescriptor> =
    (result as { tools?: Array<McpToolDescriptor> })?.tools ?? [];

  const flagged: Array<{ name: string; reasons: string[] }> = [];
  for (const tool of tools) {
    const reasons = scanToolDescription(tool);
    if (reasons.length > 0) {
      flagged.push({ name: mcpToolName(tool), reasons });
    }
  }

  // ── Descriptor content-hash pinning (rug-pull defense) ──────────────────
  // Hash every listed descriptor, compare against config pins (authoritative)
  // then the per-client TOFU store, record first sightings, and cache the
  // verdict for the call-time gate. All metadata below is added ONLY when
  // pinning is enabled, so existing events stay byte-identical.
  const pinning = resolveToolPinning(currentConfig.mcpToolPolicy);
  const pinViolations: Array<{
    name: string;
    reason: string;
    expected?: string;
    observed?: string;
  }> = [];
  // Null-prototype accumulator so a tool named "__proto__"/"constructor"/etc.
  // is recorded as a plain key (and JSON-serializes) instead of mutating the
  // prototype or being silently dropped.
  const toolHashes: Record<string, string> = Object.create(null);
  let toolHashesTruncated = false;
  let missingPinned: string[] | undefined;
  const pinBlockedNames = new Set<string>();
  if (pinning && pinStore) {
    for (const tool of tools) {
      // Fail closed per-tool: a null/garbage entry must not abort the whole
      // discovery (which would lose the inventory event and leave later tools
      // with stale verdicts). Treat an unhashable/nameless entry as a
      // hash_error verdict under its resolved name.
      const name = mcpToolName(tool);
      let observed: string | undefined;
      try {
        observed = toolDescriptorHash(tool ?? undefined);
      } catch {
        observed = undefined; // evaluateToolPin fails closed on hash_error
      }
      if (observed !== undefined) {
        if (Object.keys(toolHashes).length < MAX_TOOL_HASHES_ON_EVENT) {
          toolHashes[name] = observed;
        } else {
          toolHashesTruncated = true;
        }
      }
      // hasOwnProperty guard: a server-controlled name of "constructor" /
      // "hasOwnProperty" / "toString" must not read an inherited prototype
      // member as if it were a config pin (that value is not a hex string).
      const configPin = ownStringProp(pinning.pins, name);
      // Strict mode disables TOFU entirely (see evaluateToolPin); do not even
      // read the TOFU pin so it cannot influence the verdict.
      const tofuPin = pinning.requirePin ? undefined : pinStore.getTofuPin(name);
      const verdict = evaluateToolPin({
        configPin,
        tofuPin,
        observedHash: observed,
        mode: pinning.mode,
        requirePin: pinning.requirePin,
      });
      // Record TOFU only for a genuinely unpinned tool that PASSED — never
      // under requirePin (a pin_required violation must not ratify its own
      // hash for the next listing).
      if (
        !pinning.requirePin &&
        configPin === undefined &&
        tofuPin === undefined &&
        observed !== undefined
      ) {
        pinStore.recordTofuPin(name, observed); // first sighting, never re-pinned
      }
      pinStore.setVerdict(name, verdict);
      if (verdict.enforcement !== "none") {
        pinViolations.push({
          name,
          reason: verdict.reason ?? verdict.status,
          ...(verdict.expected !== undefined ? { expected: verdict.expected } : {}),
          ...(verdict.observed !== undefined ? { observed: verdict.observed } : {}),
        });
        if (verdict.enforcement === "block") pinBlockedNames.add(name);
      }
    }
    // Removal detection: a tool THIS SESSION recorded a TOFU pin for, now gone
    // from a full (unpaginated) listing — a dropped validator/guard signal.
    // Scoped to TOFU-seen names (not the global config-pin set, which would
    // spuriously flag pins meant for other servers on every listing). A
    // non-null pagination cursor means the listing is a page, so absence is
    // not removal; null/undefined cursor = full listing.
    const resultCursor = (result as { nextCursor?: unknown })?.nextCursor;
    const argCursor = (listArgs?.[0] as { cursor?: unknown } | undefined)?.cursor;
    const paged = (resultCursor !== undefined && resultCursor !== null) ||
      (argCursor !== undefined && argCursor !== null);
    if (!paged) {
      const listedNames = new Set(tools.map((t) => mcpToolName(t)));
      const missing = pinStore.pinnedNames().filter((n) => !listedNames.has(n));
      if (missing.length > 0) missingPinned = missing.sort();
    }
  }

  const reasonParts: string[] = [];
  if (flagged.length > 0) {
    reasonParts.push(
      `tool_poisoning_detected: ${flagged
        .map((f) => `${f.name} (${f.reasons.join(",")})`)
        .join("; ")}`,
    );
  }
  if (pinViolations.length > 0) {
    reasonParts.push(
      `tool_pin_violation: ${pinViolations
        .map((v) => `${v.name} (${v.reason})`)
        .join("; ")}`,
    );
  }

  const compliance: ComplianceInfo =
    reasonParts.length > 0
      ? {
          event_type: "policy_flag",
          policy_version: derivePolicyVersion(currentConfig.policyRules ?? []),
          action_taken: "allowed",
          action_reason: "policy_violation",
          action_source: "builtin",
          redacted_types: [],
          blocked_types: [],
          policy_reason: reasonParts.join("; "),
        }
      : {
          event_type: "tool_call",
          policy_version: derivePolicyVersion(currentConfig.policyRules ?? []),
          action_taken: "allowed",
          action_reason: "none",
          action_source: "builtin",
          redacted_types: [],
          blocked_types: [],
        };

  emitIntegrationEvent({
    config: currentConfig,
    provider: "mcp",
    model: "mcp",
    operation: "mcp.tools.list",
    source: SOURCE,
    prompt: JSON.stringify(tools).slice(0, 4000),
    response: "",
    success: true,
    metadata: {
      flagged_tools: flagged.map((f) => f.name),
      ...opts.metadata,
      // Pinning surface (only under pinning): per-tool descriptor hashes ride
      // the signed inventory event — the operator copies an observed hash
      // into config pins, and the record proves which definitions were live.
      // After opts.metadata: sealed pin evidence wins over key collisions.
      ...(pinning && pinStore
        ? {
            tool_hashes: toolHashes,
            ...(toolHashesTruncated ? { tool_hashes_truncated: true } : {}),
            ...(pinViolations.length > 0 ? { pin_violations: pinViolations } : {}),
            ...(missingPinned ? { missing_pinned_tools: missingPinned } : {}),
            ...(pinStore.saturated() ? { pin_store_saturated: true } : {}),
          }
        : {}),
    },
    options: opts,
    compliance,
  });

  if (flagged.length > 0) {
    debugLog(
      currentConfig,
      "warn",
      `[obsvr] MCP tool-poisoning patterns detected in tool descriptions: ${flagged
        .map((f) => f.name)
        .join(", ")}`,
    );
  }
  if (pinViolations.length > 0) {
    debugLog(
      currentConfig,
      "warn",
      `[obsvr] MCP tool descriptor pin violations: ${pinViolations
        .map((v) => `${v.name} (${v.reason})`)
        .join(", ")}`,
    );
  }

  const stripNames = new Set<string>();
  const blockPoisoned = (currentConfig.mcpToolPolicy as { blockPoisonedTools?: boolean } | undefined)
    ?.blockPoisonedTools;
  if (flagged.length > 0 && blockPoisoned) {
    for (const f of flagged) stripNames.add(f.name);
  }
  for (const n of pinBlockedNames) stripNames.add(n); // pinning mode "block"
  if (stripNames.size > 0) {
    return {
      ...(result as Record<string, unknown>),
      tools: tools.filter((t) => !stripNames.has(mcpToolName(t))),
    };
  }

  return result;
}

/** Governed listTools: run the original, then scan + record. `listOriginal`
 *  is the real method already bound to the client instance. */
async function runGovernedListTools(
  config: ResolvedConfig,
  opts: IntegrationOptions,
  listOriginal: (...args: unknown[]) => Promise<unknown>,
  args: unknown[],
  pinStore?: ToolPinStore,
): Promise<unknown> {
  const currentConfig = tryGetConfig() ?? config;
  const result = await listOriginal(...args);
  return processListToolsResult(result, currentConfig, opts, pinStore, args);
}

/** Governed callTool: enforce policy + PII, run the original, record the
 *  signed tool.call event. `callOriginal` is the real method bound to the
 *  client instance. Throws `[obsvr] ...` to BLOCK. */
async function runGovernedCallTool(
  config: ResolvedConfig,
  opts: IntegrationOptions,
  callOriginal: (params: unknown, ...rest: unknown[]) => Promise<unknown>,
  params: { name: string; arguments?: Record<string, unknown> },
  rest: unknown[],
  pinStore?: ToolPinStore,
): Promise<unknown> {
    const currentConfig = tryGetConfig() ?? config;
    const toolName = params?.name ?? "unknown";
    const toolArgs = params?.arguments;

    const promptText = extractMcpPrompt(toolName, toolArgs);
    const startTime = performance.now();

    // Caller identity (Phase-1A quota residual + ADR-6 audit principal): the
    // client-patch path has no authenticated principal, but the integration's
    // options carry the caller's user/service/tenant, so thread them so
    // user-scoped quota rules meter the right bucket and the audit attributes
    // the decision to the caller.
    const principal: McpPrincipal = {
      user_id: opts.user_id,
      service_name: opts.service_name,
      tenant_id:
        typeof (opts.metadata as { tenant_id?: unknown } | undefined)?.tenant_id === "string"
          ? ((opts.metadata as { tenant_id: string }).tenant_id)
          : undefined,
    };

    // 0. Enforcement-integrity gate: kill switch / stale policy with failMode=closed
    const degraded = isPolicyEnforcementDegraded(currentConfig);
    if (degraded.degraded) {
      const gateReason =
        degraded.reason === "project_paused_or_key_revoked"
          ? "Project paused or API key revoked (SDK kill switch)"
          : `Policy sync unavailable with failMode=closed (${degraded.reason})`;
      emitIntegrationEvent({
        config: currentConfig,
        provider: "mcp",
        model: "mcp",
        operation: "mcp.tool.call",
        source: SOURCE,
        prompt: promptText,
        response: "",
        success: false,
        metadata: { tool_name: toolName, ...opts.metadata },
        options: opts,
        compliance: {
          event_type: "blocked_call",
          policy_version: derivePolicyVersion(currentConfig.policyRules ?? []),
          action_taken: "blocked",
          action_reason: "policy_violation",
          action_source: "policy_rules",
          redacted_types: [],
          blocked_types: [],
          rule_id: `sdk:${degraded.reason}`,
          policy_reason: gateReason,
        },
      });
      throw new Error(`[obsvr] MCP tool call blocked: ${gateReason}`);
    }

    // 0.5 Descriptor content-hash pin gate (rug-pull defense). The descriptor
    //     is not on the wire at call time, so this consults the verdict cached
    //     at the most recent tools/list. Runs after the integrity gate (a
    //     paused project blocks first — EV-3 precedence) and before allow/deny
    //     and any argument scanning: a swapped tool is refused on IDENTITY.
    const pinning = resolveToolPinning(currentConfig.mcpToolPolicy);
    let pinVerdict: ToolPinVerdict | undefined;
    if (pinning && pinStore) {
      pinVerdict = pinStore.getVerdict(toolName);
      const flagFor = pinning.mode === "block" ? "block" : "flag";
      if (pinVerdict === undefined && pinning.requirePin) {
        // Called without ever being listed: nothing was verified. Strict mode
        // treats that as a violation; lenient mode passes it as unverified.
        pinVerdict = { status: "unpinned", enforcement: flagFor, reason: "tool_not_discovered" };
      } else if (pinVerdict === undefined && pinStore.saturated()) {
        // The verdict store hit its cap during discovery (attacker can flood a
        // listing to push a tool past it), so this tool was never verified.
        // Fail CLOSED: a missing verdict under saturation is a violation, not a
        // pass — otherwise a block-mode config-pin mismatch becomes callable.
        pinVerdict = { status: "unpinned", enforcement: flagFor, reason: "pin_unverified_store_saturated" };
      } else if (pinVerdict !== undefined && pinVerdict.enforcement !== "none") {
        // A cached VIOLATION (mismatch, or a strict-mode pin_required): its
        // status is mode-independent, but its enforcement level tracks the
        // mode. Re-derive against the CURRENT mode so an operator flipping
        // warn→block (or block→warn) at runtime takes effect immediately, not
        // only after the next re-list. A lenient pass (enforcement "none")
        // is untouched.
        pinVerdict = { ...pinVerdict, enforcement: flagFor };
      }
      if (pinVerdict?.enforcement === "block") {
        const reasonText = `tool_descriptor_pin_violation: ${toolName} (${pinVerdict.reason ?? pinVerdict.status})`;
        emitIntegrationEvent({
          config: currentConfig,
          provider: "mcp",
          model: "mcp",
          operation: "mcp.tool.call",
          source: SOURCE,
          prompt: promptText,
          response: "",
          success: false,
          statusCode: 403,
          metadata: {
            tool_name: toolName,
            ...opts.metadata,
            // After opts.metadata: sealed pin evidence wins over caller
            // key collisions (wrapper precedence).
            tool_pin_status: pinVerdict.status,
            ...(pinVerdict.expected !== undefined ? { tool_pin_expected: pinVerdict.expected } : {}),
            ...(pinVerdict.observed !== undefined ? { tool_descriptor_hash: pinVerdict.observed } : {}),
          },
          options: opts,
          compliance: {
            event_type: "blocked_call",
            policy_version: derivePolicyVersion(currentConfig.policyRules ?? []),
            action_taken: "blocked",
            action_reason: "policy_violation",
            action_source: "builtin",
            redacted_types: [],
            blocked_types: [],
            rule_id: "sdk:mcp_tool_pin",
            policy_reason: reasonText,
          },
        });
        throw new Error(`[obsvr] MCP tool call blocked: ${reasonText}`);
      }
    }

    // 1. Tool policy enforcement
    if (currentConfig.mcpToolPolicy) {
      const { allowed, reason } = checkMcpToolPolicy(toolName, currentConfig.mcpToolPolicy);
      if (!allowed) {
        const blockedCompliance: ComplianceInfo = {
          event_type: "blocked_call",
          policy_version: derivePolicyVersion(currentConfig.policyRules ?? []),
          action_taken: "blocked",
          action_reason: "policy_violation",
          action_source: "builtin",
          redacted_types: [],
          blocked_types: [],
          policy_reason: reason,
        };
        emitIntegrationEvent({
          config: currentConfig,
          provider: "mcp",
          model: "mcp",
          operation: "mcp.tool.call",
          source: SOURCE,
          prompt: promptText,
          response: "",
          success: false,
          metadata: { tool_name: toolName, ...opts.metadata },
          options: opts,
          compliance: blockedCompliance,
        });
        throw new Error(`[obsvr] MCP tool blocked by policy: ${toolName} (${reason})`);
      }
    }

    // 2. PII pre-call policy on tool args
    let compliance: ComplianceInfo | undefined;
    let finalPrompt = promptText;

    // Also run the pre-call policy when a canary is minted: a canary in tool
    // ARGUMENTS is a CRITICAL exfil surface, and the canary scan lives inside
    // applyPreCallPolicy — without this, args are unscanned when neither
    // pii_policy nor a hook is configured.
    if (
      currentConfig.pii_policy ||
      currentConfig.on_pre_call ||
      canaryRegistrySize() > 0 ||
      sessionTaintSize() > 0
    ) {
      try {
        const policyResult = await applyPreCallPolicy(promptText, {
          config: currentConfig,
          provider: "mcp",
          operation: "mcp.tool.call",
          userId: principal.user_id,
          serviceName: principal.service_name,
          tenantId: principal.tenant_id,
          metadata: opts.metadata,
        });

        compliance = policyResult.compliance;
        finalPrompt = policyResult.redactedPrompt;

        if (policyResult.decision === "block") {
          emitIntegrationEvent({
            config: currentConfig,
            provider: "mcp",
            model: "mcp",
            operation: "mcp.tool.call",
            source: SOURCE,
            prompt: finalPrompt,
            response: "",
            success: false,
            metadata: {
              tool_name: toolName,
              ...opts.metadata,
              // Server-side normalizer mirror: which view defeated the obfuscation. After
              // opts.metadata so the sealed provenance always wins over a
              // caller key collision (same precedence as the proxy wrapper).
              ...(policyResult.securityNormalized !== undefined
                ? { security_normalized: policyResult.securityNormalized }
                : {}),
              // CRITICAL canary leak + anti-tamper floor evidence ride the
              // reserved telemetry channel (merged so both survive).
              ...(policyResult.canaryTelemetry !== undefined || policyResult.floorTelemetry !== undefined
                ? {
                    obsvr_telemetry: {
                      ...(policyResult.canaryTelemetry ?? {}),
                      ...(policyResult.floorTelemetry ?? {}),
                    },
                  }
                : {}),
            },
            options: opts,
            compliance,
          });
          throw new Error(
            policyResult.canaryTelemetry !== undefined
              ? "[obsvr] MCP tool call blocked by policy (canary leak)"
              : "[obsvr] MCP tool call blocked by policy (PII detected)",
          );
        }
      } catch (err) {
        if (err instanceof Error && err.message.startsWith("[obsvr]")) throw err;
        if (currentConfig.failMode === "closed") {
          // fail_closed: a policy engine that cannot render a verdict must not
          // be treated as approval - block the tool call.
          throw new Error(
            `[obsvr] MCP tool call blocked: policy evaluation failed and failMode=closed (${err instanceof Error ? err.message : String(err)})`,
          );
        }
        // fail_open (default): policy evaluation errors do not block the tool call
      }
    }

    // 3. Execute the original callTool
    const defaultToolCompliance = (): ComplianceInfo => ({
      event_type: "tool_call",
      policy_version: derivePolicyVersion(currentConfig.policyRules ?? []),
      action_taken: "allowed",
      action_reason: "none",
      action_source: "unknown",
      redacted_types: [],
      blocked_types: [],
    });

    let result: unknown;
    try {
      result = await callOriginal(params, ...rest);
    } catch (callError) {
      const latencyMs = Math.round(performance.now() - startTime);
      const eventCompliance = compliance ?? defaultToolCompliance();
      if (eventCompliance.event_type === "llm_call") eventCompliance.event_type = "tool_call";
      emitIntegrationEvent({
        config: currentConfig,
        provider: "mcp",
        model: "mcp",
        operation: "mcp.tool.call",
        source: SOURCE,
        prompt: finalPrompt,
        response: extractMcpResponse(callError),
        latencyMs,
        success: false,
        error: callError,
        metadata: { tool_name: toolName, ...opts.metadata },
        options: opts,
        compliance: eventCompliance,
      });
      throw callError;
    }

    // 4. Response-side scan (ADR-6): the tool RESULT is the exfil/poisoning
    //    channel. Scan it for PII/secrets/injection and BLOCK / SANITIZE / LOG
    //    before it reaches the caller — mirrors the request-side scanner, with
    //    the caller principal threaded into the decision + audit.
    const respScan = scanMcpToolResult(extractMcpResponse(result), currentConfig, principal);
    const latencyMs = Math.round(performance.now() - startTime);

    if (respScan.action === "block") {
      emitIntegrationEvent({
        config: currentConfig,
        provider: "mcp",
        model: "mcp",
        operation: "mcp.tool.call",
        source: SOURCE,
        prompt: finalPrompt,
        response: "",
        latencyMs,
        success: false,
        statusCode: 403,
        metadata: {
          tool_name: toolName,
          response_blocked: true,
          ...opts.metadata,
          // Server-side normalizer mirror: which view defeated the obfuscation. After
          // opts.metadata so the sealed provenance always wins (wrapper parity).
          ...(respScan.via !== undefined ? { security_normalized: respScan.via } : {}),
          // CRITICAL canary leak evidence (tool result) rides the telemetry channel.
          ...(respScan.canaryTelemetry !== undefined
            ? { obsvr_telemetry: respScan.canaryTelemetry }
            : {}),
        },
        options: opts,
        compliance: {
          event_type: "blocked_call",
          policy_version: respScan.policy_version,
          action_taken: "blocked",
          action_reason: respScan.action_reason === "none" ? "policy_violation" : respScan.action_reason,
          action_source: respScan.action_source === "unknown" ? "policy_rules" : respScan.action_source,
          redacted_types: respScan.redacted_types,
          blocked_types: respScan.blocked_types,
          rule_id: respScan.rule_id,
          policy_reason: respScan.policy_reason ?? "tool result blocked by policy",
        },
      });
      throw new Error(
        `[obsvr] MCP tool result blocked by policy: ${toolName} (${respScan.policy_reason ?? "policy violation"})`,
      );
    }

    // SANITIZE: redact the offending spans from the result before returning.
    const finalResult = respScan.action === "sanitize" ? sanitizeMcpResult(result) : result;
    const responseText = extractMcpResponse(finalResult);

    // Merge the request-side compliance (PII in args) with the response-side
    // outcome; the stronger action wins for the audited event.
    const eventCompliance = compliance ?? defaultToolCompliance();
    if (eventCompliance.event_type === "llm_call") eventCompliance.event_type = "tool_call";
    if (respScan.action === "sanitize" && eventCompliance.action_taken !== "blocked") {
      eventCompliance.action_taken = "redacted";
      if (eventCompliance.action_reason === "none") eventCompliance.action_reason = respScan.action_reason;
      if (eventCompliance.action_source === "unknown") eventCompliance.action_source = respScan.action_source;
      eventCompliance.redacted_types = [
        ...new Set([...eventCompliance.redacted_types, ...respScan.redacted_types]),
      ];
      if (!eventCompliance.rule_id) eventCompliance.rule_id = respScan.rule_id;
      if (!eventCompliance.policy_reason) eventCompliance.policy_reason = respScan.policy_reason;
    }

    emitIntegrationEvent({
      config: currentConfig,
      provider: "mcp",
      model: "mcp",
      operation: "mcp.tool.call",
      source: SOURCE,
      prompt: finalPrompt,
      response: responseText,
      latencyMs,
      success: true,
      metadata: {
        tool_name: toolName,
        ...(respScan.detected_types.length > 0 ? { response_detected_types: respScan.detected_types } : {}),
        ...opts.metadata,
        // Server-side normalizer mirror: a detect-only view hit is still sealed evidence.
        // After opts.metadata so the sealed provenance always wins (wrapper parity).
        ...(respScan.via !== undefined ? { security_normalized: respScan.via } : {}),
        // Pin surface: the descriptor hash that governed this call rides the
        // signed event (sealing), plus the pin status (ok/unpinned/flagged).
        // Also after opts.metadata: sealed pin evidence wins over collisions.
        ...(pinning && pinStore
          ? {
              tool_pin_status: pinVerdict?.status ?? "unverified",
              ...(pinVerdict?.observed !== undefined
                ? { tool_descriptor_hash: pinVerdict.observed }
                : {}),
              ...(pinVerdict !== undefined && pinVerdict.enforcement === "flag"
                ? { pin_violation: pinVerdict.reason ?? pinVerdict.status }
                : {}),
            }
          : {}),
      },
      options: opts,
      compliance: eventCompliance,
    });

    return finalResult;
}

/**
 * Non-mutating governance for a single MCP Client INSTANCE. Returns a Proxy
 * that intercepts callTool + listTools via the get trap — the client's
 * prototype is never touched, so it coexists with anything else and other
 * Client instances are unaffected. instanceof is preserved (the Proxy target
 * is the real instance).
 */
function governClientInstance<T extends object>(
  client: T,
  config: ResolvedConfig,
  opts: IntegrationOptions,
): T {
  const c = client as unknown as Record<string, unknown>;
  const origCall =
    typeof c.callTool === "function"
      ? (c.callTool as (...a: unknown[]) => Promise<unknown>).bind(client)
      : undefined;
  const origList =
    typeof c.listTools === "function"
      ? (c.listTools as (...a: unknown[]) => Promise<unknown>).bind(client)
      : undefined;

  // One pin store per governed client: tool names are only unique per server,
  // so TOFU pins must not be shared across clients (name collisions would
  // cross-contaminate two servers' descriptors).
  const pinStore = createToolPinStore();

  const governedCall = origCall
    ? (params: { name: string; arguments?: Record<string, unknown> }, ...rest: unknown[]) =>
        runGovernedCallTool(config, opts, origCall, params, rest, pinStore)
    : undefined;
  const governedList = origList
    ? (...args: unknown[]) => runGovernedListTools(config, opts, origList, args, pinStore)
    : undefined;

  return new Proxy(client, {
    get(target, prop, receiver) {
      if (prop === "callTool" && governedCall) return governedCall;
      if (prop === "listTools" && governedList) return governedList;
      // Bind other methods to the REAL target so private-field (#) access works
      // through the Proxy.
      const value = Reflect.get(target, prop, target);
      return typeof value === "function" ? (value as Function).bind(target) : value;
    },
  }) as T;
}

/**
 * Legacy prototype-patch path (used only by patchMCP). Mutates
 * Client.prototype — prefer obsvrGovernMCP() which is non-mutating.
 */
function _applyMCPPatch(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  ClientClass: any,
  config: ResolvedConfig,
  opts: IntegrationOptions,
): void {
  const proto = ClientClass.prototype as Record<string | symbol, unknown>;
  if (proto[PATCHED_SYMBOL]) {
    debugLog(config, "info", "[auto] MCP already patched");
    return;
  }
  const originalCallTool = proto["callTool"] as Function | undefined;
  if (typeof originalCallTool !== "function") {
    debugLog(config, "info", "[auto] MCP Client.prototype.callTool not found - skipping");
    return;
  }
  const originalListTools = proto["listTools"] as Function | undefined;
  if (typeof originalListTools === "function") {
    proto["listTools"] = async function patchedListTools(this: unknown, ...args: unknown[]) {
      return runGovernedListTools(
        config, opts,
        (...a) => (originalListTools as Function).apply(this, a),
        args,
        pinStoreForPatchedInstance(this),
      );
    };
  }
  proto["callTool"] = async function patchedCallTool(
    this: unknown,
    params: { name: string; arguments?: Record<string, unknown> },
    ...rest: unknown[]
  ) {
    return runGovernedCallTool(
      config, opts,
      (p, ...r) => (originalCallTool as Function).call(this, p, ...r),
      params, rest,
      pinStoreForPatchedInstance(this),
    );
  };
  proto[PATCHED_SYMBOL] = true;
  setupExitHandlers(config);
  debugLog(config, "info", "[auto] MCP patched (prototype)");
}
