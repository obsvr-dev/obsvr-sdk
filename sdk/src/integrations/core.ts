/**
 * Integrations Core
 *
 * Shared glue used by all framework and infrastructure integrations:
 * sampling → PII scan/resolve → `on_pre_call` hook → build AuditEvent
 * (same field mapping as the proxy wrapper) → fire-and-forget send.
 *
 * This module only *imports* from the existing proxy/policy/sender code -
 * it never modifies their behavior.
 *
 * @packageDocumentation
 */

import type { AuditEvent, ResolvedConfig } from "../proxy/types.js";
import {
  type CallTelemetry,
  withTelemetryMetadata,
} from "../proxy/extractors/telemetry.js";
import { spanEnvelopeFor, withSpanMetadata } from "../proxy/span.js";
import { withRunMetadata } from "../proxy/agent-run.js";
import { getCurrentSubject } from "../proxy/subject.js";
import { getConfig, isInitialized, getTenantConfig, isPolicyEnforcementDegraded } from "../proxy/config.js";
import {
  evaluatePolicyHook,
  redactBuiltinPii,
  resolvePiiPolicy,
  runBuiltinPiiScan,
} from "../policy/hook.js";
import {
  runConfiguredPiiScan,
  escalateViewOnlyAction,
  redactForStorage,
} from "../policy/deobfuscate.js";
import type { DeobfuscationView } from "../policy/deobfuscate.js";
import {
  scanForCanary,
  canaryRegistrySize,
  canaryLeakTelemetry,
  CANARY_REDACTION_PLACEHOLDER,
} from "../policy/canary.js";
import type { CanaryHit } from "../policy/canary.js";
import {
  resolveSessionTaint,
  deriveSessionKey,
  evaluateSessionTaint,
  markTainted,
  touchTaint,
  sessionTaintSize,
} from "../policy/session-taint.js";
import { presidioScan, presidioRedactText } from "../policy/presidio.js";
import { scoreTurn } from "../policy/injection-session.js";
import type { PolicyDecisionResult, PostCallDecisionResult } from "../policy/hook.js";
import { normalizePostCallDecision } from "../policy/hook.js";
import { evaluatePolicyRules, derivePolicyVersion, evaluateFloor, deriveFloorVersion } from "../policy/rules.js";
import type { PolicyEvalContext } from "../policy/rules.js";
import {
  ENGINE_VERSION,
  buildDecisionInput,
  computeDecisionInputHash,
  sha256Hex,
} from "../policy/decision-record.js";
import type { HookDisposition } from "../policy/decision-record.js";
import {
  buildBackendInput,
  runExternalBackendStep,
} from "../policy/external-backend.js";
import type { ExternalBackendRecord } from "../policy/external-backend.js";
import {
  sendAuditAsync,
  shouldSample,
  setupExitHandlers,
} from "../proxy/sender/index.js";
import { truncate } from "../utils/truncate.js";
import { debugLog } from "../utils/logger.js";
import { generateUUID } from "../client.js";

import { LoopDetector, createLoopDetector } from "../policy/industry/devops.js";
import { DelegationTracker, createDelegationTracker } from "../policy/industry/agentic.js";
import type { DelegationViolation } from "../policy/industry/agentic.js";

// Re-exports so integration modules need a single import point
export { shouldSample, sendAuditAsync, setupExitHandlers, getConfig, debugLog };
export { redactBuiltinPii };
export { redactForStorage };
export type { DeobfuscationView };

/**
 * Whole-text placeholder for a stored response the policy FLOOR redacted. A
 * floor rule match (keyword/regex/topic) has no locatable span, so the stored
 * copy is replaced wholesale rather than span-redacted (which would leave the
 * matched content intact). Kept byte-identical to the Python twin
 * (policy.FLOOR_REDACTION_PLACEHOLDER) so cross-SDK stored copies agree.
 */
export const FLOOR_REDACTION_PLACEHOLDER = '[REDACTED:policy_floor]';
export { LoopDetector, createLoopDetector, DelegationTracker, createDelegationTracker };
export type { DelegationViolation };

/** Provider values accepted by the audit event schema */
export type IntegrationProvider = AuditEvent["provider"];

/** Per-integration options (mirrors WrapOptions semantics) */
export interface IntegrationOptions {
  source?: string;
  region?: string;
  service_name?: string;
  user_id?: string;
  metadata?: Record<string, unknown>;
}

/** Compliance context stamped on every emitted event */
export interface ComplianceInfo {
  event_type: "llm_call" | "blocked_call" | "policy_flag" | "tool_call" | "hard_delete" | "delegation" | "loop_detected" | "approval_required";
  policy_version: string;
  action_taken: "allowed" | "blocked" | "redacted" | "hook_error" | "hook_timeout";
  action_reason:
    | "pii_detected"
    | "policy_violation"
    | "customer_override"
    | "none";
  action_source: "builtin" | "builtin+presidio" | "customer_hook" | "policy_rules" | "external_backend" | "unknown";
  redacted_types: string[];
  blocked_types: string[];
  rule_id?: string;
  policy_reason?: string;
  /** SHA-256 of the canonical decision-input document (ADR-2); additive. */
  decision_input_hash?: string;
  /** Rules-engine semantics version the decision ran under ("obsvr-rules/<N>"). */
  engine_version?: string;
  /** Inbound external policy backend provenance (ADR-4); additive. */
  external_backend?: ExternalBackendRecord;
}

/** Default compliance context (mirrors proxy wrapper defaults) */
export const DEFAULT_COMPLIANCE: ComplianceInfo = {
  event_type: "llm_call",
  policy_version: "v1",
  action_taken: "allowed",
  action_reason: "none",
  action_source: "unknown",
  redacted_types: [],
  blocked_types: [],
};

/**
 * Get the resolved config, or null when the SDK is uninitialized or
 * disabled. Observe-only handlers use this so they never throw inside
 * a framework callback.
 */
export function tryGetConfig(): ResolvedConfig | null {
  if (!isInitialized()) return null;
  const config = getConfig();
  if (config.disabled) return null;
  return config;
}

/**
 * Classify an error into the audit error taxonomy.
 * (Same logic as the proxy wrapper, which does not export it.)
 */
export function classifyError(error: unknown): AuditEvent["error_type"] {
  if (!(error instanceof Error)) return "api_error";

  const message = error.message.toLowerCase();
  const name = error.name.toLowerCase();

  if (
    message.includes("rate limit") ||
    message.includes("429") ||
    name.includes("ratelimit")
  ) {
    return "rate_limit";
  }
  if (
    message.includes("timeout") ||
    name.includes("timeout") ||
    message.includes("timed out")
  ) {
    return "timeout";
  }
  if (
    message.includes("auth") ||
    message.includes("401") ||
    message.includes("403") ||
    message.includes("unauthorized")
  ) {
    return "auth_error";
  }
  return "api_error";
}

// ============================================================================
// Prompt-text helpers (OpenAI messages / Anthropic system / Gemini contents)
// ============================================================================

/**
 * Extract all visible prompt text from a request object for PII scanning.
 */
export function extractAllPromptText(args: unknown): string {
  if (typeof args === "string") return args;
  if (!args || typeof args !== "object") return "";
  const req = args as Record<string, unknown>;
  const parts: string[] = [];

  if (typeof req.system === "string") {
    parts.push(req.system);
  }

  if (Array.isArray(req.messages)) {
    for (const msg of req.messages as Record<string, unknown>[]) {
      if (typeof msg.content === "string") {
        parts.push(msg.content);
      } else if (Array.isArray(msg.content)) {
        for (const part of msg.content as Record<string, unknown>[]) {
          if (typeof part.text === "string") parts.push(part.text);
        }
      }
    }
  }

  if (Array.isArray(req.contents)) {
    for (const c of req.contents as Record<string, unknown>[]) {
      if (Array.isArray(c.parts)) {
        for (const part of c.parts as Record<string, unknown>[]) {
          if (typeof part.text === "string") parts.push(part.text);
        }
      }
    }
  }

  return parts.join(" ");
}

/**
 * Extract only the last user message for PII policy decisions.
 */
export function extractLastUserText(args: unknown): string {
  if (typeof args === "string") return args;
  if (!args || typeof args !== "object") return "";
  const req = args as Record<string, unknown>;

  if (Array.isArray(req.messages)) {
    for (let i = (req.messages as unknown[]).length - 1; i >= 0; i--) {
      const msg = (req.messages as Record<string, unknown>[])[i];
      if (msg.role === "user") {
        if (typeof msg.content === "string") return msg.content;
        if (Array.isArray(msg.content)) {
          return (msg.content as Record<string, unknown>[])
            .map((p) => (typeof p.text === "string" ? p.text : ""))
            .join(" ");
        }
      }
    }
  }

  if (Array.isArray(req.contents)) {
    for (let i = (req.contents as unknown[]).length - 1; i >= 0; i--) {
      const c = (req.contents as Record<string, unknown>[])[i];
      if (c.role === "user" && Array.isArray(c.parts)) {
        return (c.parts as Record<string, unknown>[])
          .map((p) => (typeof p.text === "string" ? p.text : ""))
          .join(" ");
      }
    }
  }

  return extractAllPromptText(args);
}

/**
 * Redact PII in-place across message/prompt content fields, preserving
 * structure (OpenAI messages, Anthropic system, Gemini contents).
 */
export function redactRequestMessagesInPlace(args: unknown): void {
  if (!args || typeof args !== "object") return;
  const req = args as Record<string, unknown>;

  if (typeof req.system === "string") {
    req.system = redactBuiltinPii(req.system);
  }

  if (Array.isArray(req.messages)) {
    for (const msg of req.messages as Record<string, unknown>[]) {
      if (typeof msg.content === "string") {
        msg.content = redactBuiltinPii(msg.content);
      } else if (Array.isArray(msg.content)) {
        for (const part of msg.content as Record<string, unknown>[]) {
          if (typeof part.text === "string") {
            part.text = redactBuiltinPii(part.text);
          }
        }
      }
    }
  }

  if (Array.isArray(req.contents)) {
    for (const c of req.contents as Record<string, unknown>[]) {
      if (Array.isArray(c.parts)) {
        for (const part of c.parts as Record<string, unknown>[]) {
          if (typeof part.text === "string") {
            part.text = redactBuiltinPii(part.text);
          }
        }
      }
    }
  }
}

// ============================================================================
// Pre-call policy
// ============================================================================

export interface PreCallPolicyResult {
  decision: "allow" | "block" | "redact";
  compliance: ComplianceInfo;
  /** Prompt text with PII replaced by typed placeholders */
  redactedPrompt: string;
  /**
   * Which de-obfuscation view surfaced the PII/injection hit (the server-side normalizer
   * `security_normalized` mirror). Absent for an overt raw-text match and
   * whenever `config.deobfuscation` is disabled. Present ⟹ the raw text is
   * clean ⟹ `redactedPrompt` is a whole-text placeholder, and a redact-mode
   * verdict was escalated to block (spans are unlocatable).
   */
  securityNormalized?: DeobfuscationView["method"];
  /**
   * Canary-leak evidence bundle (`{ canary_leak: { surface, ids,
   * hash_prefixes, via } }`) when a planted honeytoken leaked in the request.
   * Never contains the raw token; the caller merges it into
   * `metadata.obsvr_telemetry`. Present ⟹ the call was blocked unsuppressibly.
   */
  canaryTelemetry?: Record<string, unknown>;
  /**
   * Anti-tamper floor evidence: `floor_version` (the sealed floor-definition
   * hash) when a floor is configured, and `floor_override_ignored` ({ rule_id,
   * attempted }) when the customer hook tried to un-block/downgrade a floor
   * rule and was refused. The caller merges it into `metadata.obsvr_telemetry`.
   */
  floorTelemetry?: Record<string, unknown>;
}

/**
 * Apply the compliance boundary (built-in PII scan + customer hook) to a
 * prompt before the LLM call. Mirrors the proxy wrapper semantics exactly:
 *  - builtin scan resolves per-type block/redact/detect_only
 *  - the customer hook ALWAYS runs and may escalate or override
 */
export async function applyPreCallPolicy(
  promptText: string,
  ctx: {
    config: ResolvedConfig;
    provider: IntegrationProvider;
    operation: string;
    tenantId?: string;
    /**
     * Caller identity (Phase-1A quota residual). Framework integrations must
     * thread the user/service so USER-SCOPED (and service/tenant-scoped) quota
     * rules meter the RIGHT bucket on the integration path — without this, they
     * silently metered the 'default' bucket (the wrap() path was already fixed).
     * Absent values fall back to the ambient useSubject() subject, mirroring
     * buildIntegrationEvent's identity precedence.
     */
    userId?: string;
    serviceName?: string;
    /**
     * The request model, when the integration knows it. Threaded into the
     * anti-tamper FLOOR eval context so a floor `model_gate` rule enforces on
     * the integration path too (parity with the proxy wrapper and Python) —
     * without it, a floor model allow/deny-list was silently inert here.
     */
    model?: string;
    /** Extra rule-evaluation context (e.g. tenant_id, session_id). */
    metadata?: Record<string, unknown>;
  },
): Promise<PreCallPolicyResult> {
  const { provider, operation, tenantId } = ctx;
  const config = tenantId ? getTenantConfig(tenantId) : ctx.config;

  // Resolve the caller identity for scoped-quota bucketing: explicit options
  // win, else the ambient useSubject() subject (same precedence the audit
  // event uses). Threaded into the rules eval context below.
  const ambientSubject = getCurrentSubject();
  const identityUserId = ctx.userId ?? ambientSubject?.user_id;
  const identityServiceName = ctx.serviceName ?? ambientSubject?.service_name;
  const identityTenantId = tenantId ?? ambientSubject?.tenant_id;

  let actionTaken: ComplianceInfo["action_taken"] = "allowed";
  let actionReason: ComplianceInfo["action_reason"] = "none";
  let actionSource: ComplianceInfo["action_source"] = "unknown";
  let redactedTypes: string[] = [];
  let blockedTypes: string[] = [];
  let gateRuleId: string | undefined;
  let gatePolicyReason: string | undefined;

  // 0. Enforcement-integrity gate (EV-3): blocks when the project is paused /
  //    the key is revoked (kill switch) or fail-closed staleness. A gate block
  //    is NOT customer-overridable (the hook is skipped below when degraded).
  //    Mirrors the proxy wrapper so infra integrations (Bedrock / Vertex /
  //    Vercel AI / Cloudflare / Azure OpenAI / Together / MCP) get the same
  //    kill-switch coverage as wrap().
  const degraded = isPolicyEnforcementDegraded(config);
  if (degraded.degraded) {
    actionTaken = "blocked";
    actionReason = "policy_violation";
    actionSource = "policy_rules";
    gateRuleId = `sdk:${degraded.reason}`;
    gatePolicyReason =
      degraded.reason === "project_paused_or_key_revoked"
        ? "Project paused or API key revoked (SDK kill switch)"
        : `Policy sync unavailable with failMode=closed (${degraded.reason})`;
    debugLog(config, "warn", `Call blocked: ${gatePolicyReason}`);
  }

  // 0.5 Session taint latch. The session key matches the multi-turn / event
  //     derivation exactly so SET (below, on a detection) and ENFORCE (here)
  //     agree. ENFORCE runs on PRIOR taint (from earlier turns), so the turn
  //     that first taints the session is handled by its own gate, and only
  //     SUBSEQUENT egress in the session is escalated. Only when enabled.
  const taintCfg = resolveSessionTaint(config);
  const taintKey = deriveSessionKey({
    ...(ctx.metadata ?? {}),
    ...(identityUserId !== undefined ? { user_id: identityUserId } : {}),
    ...(identityTenantId !== undefined ? { tenant_id: identityTenantId } : {}),
  });
  let taintRuleId: string | undefined;
  let taintPolicyReason: string | undefined;
  if (taintCfg && sessionTaintSize() > 0 && actionTaken !== "blocked") {
    const verdict = evaluateSessionTaint(taintKey, taintCfg);
    if (verdict.enforcement !== "none") {
      touchTaint(taintKey, Date.now()); // LRU: keep an enforced victim alive
      taintRuleId = "sdk:session_tainted";
      taintPolicyReason = `Session previously compromised (${verdict.reason}); egress escalated`;
      if (verdict.enforcement === "block") {
        actionTaken = "blocked";
        actionReason = "policy_violation";
        actionSource = "policy_rules";
        debugLog(config, "warn", `Call blocked: ${taintPolicyReason}`);
      } else if (actionReason === "none") {
        actionReason = "policy_violation";
        actionSource = "policy_rules";
      }
    }
  }

  // 0.75 Canary-leak scan (unsuppressible). A planted honeytoken appearing in
  //     the OUTBOUND text (tool-call arguments, or a user turn echoing a
  //     leaked token) is a CRITICAL exfiltration signal — block it before it
  //     reaches the provider/tool, and DO NOT let the customer hook downgrade
  //     it (canaryFloor below). Scans the same user/tool-args text as the PII
  //     step (never the app's planted system prompt), and only when a canary
  //     has actually been minted (zero cost otherwise).
  let canaryFloor = false;
  let canaryTelemetry: Record<string, unknown> | undefined;
  let canaryRuleId: string | undefined;
  let canaryPolicyReason: string | undefined;
  if (canaryRegistrySize() > 0 && actionTaken !== "blocked") {
    const leak = scanForCanary(promptText);
    if (leak.leaked) {
      actionTaken = "blocked";
      actionReason = "policy_violation";
      actionSource = "builtin";
      canaryFloor = true;
      canaryRuleId = "sdk:canary_leak";
      canaryPolicyReason = `Canary token leaked in request (${leak.hits.map((h) => h.id).join(", ")})`;
      canaryTelemetry = canaryLeakTelemetry(leak.hits, "request");
      debugLog(config, "warn", `Call blocked: ${canaryPolicyReason}`);
      if (taintCfg) markTainted(taintKey, "canary_leak", Date.now());
    }
  }

  // 1. Built-in PII scan (runs before customer hook; skipped when the
  //    integrity gate already blocked the call). The regex scan always runs;
  //    Presidio NLP results merge in when configured — same contract as the
  //    proxy wrapper and the Python shared pre-call, so the integrations path
  //    no longer silently ignores presidio_analyzer_url.
  let piiScanVia: DeobfuscationView["method"] | undefined;
  if (config.pii_policy && actionTaken !== "blocked") {
    // With deobfuscation enabled the scanner also sees decoded/stripped views
    // (server-side normalizer mirror); `via` records which view surfaced a hidden hit.
    const piiScan = runConfiguredPiiScan(promptText, config.deobfuscation);
    const regexTypes = piiScan.detected_types;
    piiScanVia = piiScan.via;
    let allTypes = regexTypes;
    if (config.presidio_analyzer_url) {
      const { detected_types: nlpTypes } = await presidioScan(
        promptText, config.presidio_analyzer_url,
      );
      allTypes = [...new Set([...regexTypes, ...nlpTypes])];
    }
    if (allTypes.length > 0) {
      actionReason = "pii_detected";
      actionSource = config.presidio_analyzer_url ? "builtin+presidio" : "builtin";
      // A detected prompt-injection taints the session (later egress escalated).
      if (taintCfg && allTypes.includes("prompt_injection")) {
        markTainted(taintKey, "prompt_injection", Date.now());
      }
      const resolved = resolvePiiPolicy(allTypes, config.pii_policy);
      // A view-only hit has no locatable span in the raw text, so "redact"
      // would no-op while the record claims "redacted" — escalate to block.
      const piiAction = escalateViewOnlyAction(resolved.action, piiScanVia);
      if (piiAction === "block") {
        actionTaken = "blocked";
        blockedTypes = resolved.blockedTypes;
        redactedTypes = resolved.redactedTypes;
      } else if (piiAction === "redact") {
        actionTaken = "redacted";
        redactedTypes = resolved.redactedTypes;
      }
      // detect_only: reason/source set; action stays "allowed"
    }
  }

  // Caller identity merged over ctx.metadata: the view the rules eval runs
  // with (scoped quota rules meter the right bucket, never 'default'); also
  // keys multi-turn injection sessions below.
  const evalMetadata: Record<string, unknown> = { ...(ctx.metadata ?? {}) };
  if (identityUserId !== undefined) evalMetadata.user_id = identityUserId;
  if (identityServiceName !== undefined) evalMetadata.service_name = identityServiceName;
  if (identityTenantId !== undefined) evalMetadata.tenant_id = identityTenantId;

  // 1.2. Multi-turn injection scoring — catches injection payloads split
  //      across turns that no single message would trip. Mirrors the proxy
  //      wrapper's step 1.2 and the Python shared pre-call, so the
  //      integrations/MCP path no longer silently ignores
  //      config.multiTurnInjection. `promptText` on this path is the current
  //      turn's text at every call site, which is what the wrapper's
  //      deliberate per-turn-delta scoring requires (never the joined
  //      history — that would re-count early turns on every call).
  let mtRuleId: string | undefined;
  let mtPolicyReason: string | undefined;
  if (config.multiTurnInjection?.enabled && actionTaken !== "blocked") {
    const sessionKey = String(
      evalMetadata.user_id ?? evalMetadata.session_id ?? evalMetadata.tenant_id ?? "global",
    );
    // RAW scan only — deliberately NOT the deobfuscation-aware scan (see the
    // proxy wrapper's step 1.2 comment: a view-aware full match would
    // suppress the accumulation gate below with no single-turn enforcement
    // replacing it when pii_policy is absent).
    const hadFullMatch = runBuiltinPiiScan(promptText).detected_types.includes("prompt_injection");
    const mt = scoreTurn(sessionKey, promptText, hadFullMatch, {
      threshold: config.multiTurnInjection.threshold ?? 1.0,
      halfLifeMs: config.multiTurnInjection.halfLifeMs ?? 600_000,
    });
    // A full match is already handled by the single-turn scan above; the
    // multi-turn gate exists for the accumulation case.
    if (mt.tripped && !hadFullMatch) {
      const mtAction = config.multiTurnInjection.action ?? "block";
      mtRuleId = "sdk:multi_turn_injection";
      mtPolicyReason = `Multi-turn injection score ${mt.score.toFixed(2)} reached threshold over ${mt.turns} turn(s); this turn's signals: ${mt.signals.join(", ") || "none"}`;
      // Accumulated injection taints the session (later egress escalated).
      if (taintCfg) markTainted(taintKey, "multi_turn_injection", Date.now());
      if (mtAction === "block") {
        actionTaken = "blocked";
        actionReason = "policy_violation";
        actionSource = "policy_rules";
        debugLog(config, "warn", `Call blocked: ${mtPolicyReason}`);
      } else {
        if (actionReason === "none") actionReason = "policy_violation";
        actionSource = "policy_rules";
        debugLog(config, "warn", `Call flagged: ${mtPolicyReason}`);
      }
    }
  }

  // 1.4. Anti-tamper policy FLOOR (runs BEFORE customer rules so a customer
  //      topic_allow cannot pre-empt a floor block; floor rules always enforce
  //      regardless of their declared enabled/mode). A floor block is
  //      non-overridable: floorBlock excludes it from the hook-override
  //      branches below, and the floor lives in its own config field so a
  //      remote sync can never delete it.
  let floorBlock = false;
  let floorRuleId: string | undefined;
  let floorPolicyReason: string | undefined;
  let floorOverrideIgnored: { rule_id?: string; attempted: "allow" | "redact" } | undefined;
  const floorActive = !!(config.policyFloor && config.policyFloor.length > 0);
  if (config.policyFloor && config.policyFloor.length > 0 && actionTaken !== "blocked") {
    // The floor is evaluated with the RICHEST available context (model +
    // environment as top-level fields the rules engine reads for model_gate /
    // environment_gate), so an operator floor that gates on model or
    // environment enforces on the integration path too — matching the proxy
    // wrapper and Python. The floor is the hardened baseline: it deliberately
    // gets a context at least as strong as the customer rules below.
    const floorResult = evaluateFloor(config.policyFloor, promptText, "prompt", {
      currentEnvironment: config.environment,
      model: ctx.model ?? "",
      provider,
      metadata: evalMetadata,
    });
    if (floorResult.decision === "block" || floorResult.decision === "redact") {
      // A floor 'redact' FAILS CLOSED to a block: the redaction paths here
      // (presidio anonymizer / redactForStorage) only cover PII spans, not an
      // arbitrary floor-rule match, so a floor redact could otherwise forward
      // the matched content verbatim under a false "redacted" record. The
      // floor is the non-overridable baseline — block rather than leak.
      // Uniform across the proxy wrapper, this path, Python, and governance.
      floorBlock = true;
      floorRuleId = floorResult.rule_id;
      floorPolicyReason = floorResult.reason ?? "Blocked by policy floor";
      actionTaken = "blocked";
      actionReason = "policy_violation";
      actionSource = "policy_rules";
      debugLog(config, "warn", `Floor block (${floorResult.decision} → block): ${floorPolicyReason}`);
    }
  }

  // 1.5. Structured policy rules (runs after builtin PII scan, before customer
  //      hook). Rule ids start from the multi-turn gate's override and are
  //      overwritten when rules actually run — the same precedence the proxy
  //      wrapper and the Python shared pre-call use.
  let rulesRuleId: string | undefined = floorRuleId ?? mtRuleId;
  let rulesPolicyReason: string | undefined = floorPolicyReason ?? mtPolicyReason;
  if (config.policyRules && config.policyRules.length > 0 && actionTaken !== "blocked") {
    const rulesResult = evaluatePolicyRules(config.policyRules, promptText, "prompt", {
      provider,
      metadata: evalMetadata,
    });
    if (rulesResult.decision === 'block') {
      actionTaken = 'blocked';
      actionReason = 'policy_violation';
      actionSource = 'policy_rules';
    } else if (rulesResult.decision === 'redact' && actionTaken !== 'redacted') {
      actionTaken = 'redacted';
      actionReason = 'policy_violation';
      actionSource = 'policy_rules';
    }
    rulesRuleId = rulesResult.rule_id;
    rulesPolicyReason = rulesResult.reason;
  }

  // 2. Customer hook - fires according to hookTrigger config (M-2).
  let hookRuleId: string | undefined;
  let hookPolicyReason: string | undefined;
  // Hook disposition for the decision record (ADR-2): configured-but-not-run
  // is "skipped"; outcomes overwrite it below.
  let hookDisposition: HookDisposition = config.on_pre_call ? 'skipped' : 'not_configured';
  const hookTrigger = config.hookTrigger ?? 'always';
  const shouldRunHook =
    config.on_pre_call &&
    !degraded.degraded && // integrity-gate blocks are not customer-overridable (EV-3)
    (hookTrigger === 'always' ||
      (hookTrigger === 'on_pii' && actionReason === 'pii_detected') ||
      (hookTrigger === 'on_block' && actionTaken === 'blocked'));
  if (shouldRunHook) {
    const preEvent: Partial<AuditEvent> = {
      provider,
      operation,
      environment: config.environment,
      prompt: promptText,
    };
    let hookDecision: string;
    let hookResultObj: PolicyDecisionResult | null = null;
    try {
      const hookTimeoutMs: number = config.hookTimeoutMs ?? 2000;
      const hookResult = await evaluatePolicyHook(config.on_pre_call!, preEvent, hookTimeoutMs);
      if (hookResult === 'hook_timeout') {
        hookDisposition = "timeout";
        // fail_closed: a hook that cannot render a verdict is not approval
        hookDecision = config.failMode === "closed" ? "block" : "allow";
        if (config.failMode === "closed") {
          hookPolicyReason = "hook_timeout (fail_closed)";
        }
        // Never downgrade a block that builtin PII / rules already decided — a
        // hook that can't render a verdict is not an approval. Fail-open applies
        // to the hook's OWN contribution, not to overriding other enforcement.
        if (actionTaken !== "blocked") {
          actionTaken = "hook_timeout";
          actionSource = "customer_hook";
        }
      } else {
        hookResultObj = hookResult;
        hookDecision = hookResult.decision;
        hookDisposition =
          hookDecision === "block" || hookDecision === "redact" ? hookDecision : "allow";
      }
    } catch (hookErr) {
      debugLog(
        config,
        "error",
        `onPreCall hook threw, ${config.failMode === "closed" ? "failMode=closed - blocking" : "defaulting to allow"}:`,
        hookErr instanceof Error ? hookErr.message : String(hookErr),
      );
      hookDisposition = "error";
      hookDecision = config.failMode === "closed" ? "block" : "allow";
      if (config.failMode === "closed") {
        hookPolicyReason = "hook_error (fail_closed)";
      }
      // Same as timeout: a hook error must not un-block a builtin/rules block.
      if (actionTaken !== "blocked") {
        actionTaken = "hook_error";
        actionSource = "customer_hook";
      }
    }
    if (hookResultObj) {
      hookRuleId = hookResultObj.rule_id;
      hookPolicyReason = hookResultObj.reason;
    }
    if (hookDecision === "block") {
      actionTaken = "blocked";
      actionReason = "policy_violation";
      actionSource = "customer_hook";
    } else if (
      hookDecision === "allow" &&
      hookDisposition === "allow" &&
      actionTaken === "blocked" &&
      !canaryFloor
    ) {
      if (floorBlock) {
        // The hook tried to un-block a FLOOR rule. Refused — and recorded on
        // the tamper-evident audit event (the differentiator over a swallowed
        // stderr line). The block stands.
        floorOverrideIgnored = { rule_id: floorRuleId, attempted: "allow" };
      } else {
        // Only an EXPLICIT hook allow overrides a builtin block (logged
        // transparently). A fail-open timeout/error default must NOT — its
        // disposition is "timeout"/"error", not "allow". A canary-leak block is
        // unsuppressible: the hook can never un-block it (canaryFloor).
        actionTaken = "allowed";
        actionReason = "customer_override";
        actionSource = "customer_hook";
      }
    } else if (
      hookDecision === "redact" &&
      actionTaken !== "redacted" &&
      !canaryFloor &&
      floorBlock
    ) {
      // The hook tried to downgrade a FLOOR block to redact. Refused + recorded.
      floorOverrideIgnored = { rule_id: floorRuleId, attempted: "redact" };
    } else if (hookDecision === "redact" && actionTaken !== "redacted" && !canaryFloor) {
      if (piiScanVia !== undefined) {
        // View-only detection: no locatable span, so a "redacted" outcome
        // would be a false record (and would downgrade the escalated builtin
        // block). Same clamp as escalateViewOnlyAction: block instead.
        actionTaken = "blocked";
        actionReason = "policy_violation";
        actionSource = "customer_hook";
      } else {
        actionTaken = "redacted";
        actionReason = "policy_violation";
        actionSource = "customer_hook";
        redactedTypes = ["all"]; // customer-driven; exact types unknown
      }
    }
  }

  // Canonical decision record (ADR-2): commit exactly what this decision ran
  // over. `promptText` is the text as presented to the pipeline (pre-redaction).
  const rulesHash = derivePolicyVersion(config.policyRules ?? []);

  // Inbound external policy backend (ADR-4): consult the customer's OPA/Cedar
  // engine and merge DENY-WINS with the local decision. Only when not already
  // blocked (a block cannot be downgraded). Error/timeout is a DENY unless the
  // backend is in observe-only shadow mode. Same seam the proxy wrapper uses.
  let externalBackend: ExternalBackendRecord | undefined;
  let backendRuleId: string | undefined;
  let backendPolicyReason: string | undefined;
  if (config.external_policy_backend && actionTaken !== "blocked") {
    const localDecision = actionTaken === "redacted" ? "redact" : "allow";
    try {
      const step = await runExternalBackendStep(
        config.external_policy_backend,
        localDecision,
        buildBackendInput({
          operation,
          provider,
          model: "",
          environment: config.environment,
          tenantId,
          localDecision,
          rulesHash,
          promptSha256: sha256Hex(promptText),
        }),
      );
      externalBackend = step.record;
      if (step.blocked_by_backend) {
        actionTaken = "blocked";
        actionReason = "policy_violation";
        actionSource = "external_backend";
        backendRuleId = `backend:${step.record.type}`;
        backendPolicyReason =
          step.record.reasons && step.record.reasons.length > 0
            ? step.record.reasons.join("; ")
            : `Denied by external ${step.record.type} policy backend`;
      }
    } catch {
      if (!config.external_policy_backend.shadow) {
        actionTaken = "blocked";
        actionReason = "policy_violation";
        actionSource = "external_backend";
        backendRuleId = `backend:${config.external_policy_backend.type}`;
        backendPolicyReason = `Denied by external ${config.external_policy_backend.type} policy backend (evaluation error, fail-closed)`;
      }
    }
  }

  const decisionInput = buildDecisionInput({
    rulesHash,
    degraded: degraded.degraded,
    degradedReason: degraded.reason,
    target: "request",
    evaluatedText: promptText,
    tenantId,
    hook: hookDisposition,
  });

  const compliance: ComplianceInfo = {
    event_type: actionTaken === "blocked" ? "blocked_call" : "llm_call",
    policy_version: rulesHash,
    action_taken: actionTaken,
    action_reason: actionReason,
    action_source: actionSource,
    redacted_types: redactedTypes,
    blocked_types: blockedTypes,
    // Canary wins (unsuppressible), then the integrity gate, then the rest;
    // taint is the escalation reason when nothing more specific fired.
    rule_id: canaryRuleId ?? backendRuleId ?? hookRuleId ?? rulesRuleId ?? taintRuleId ?? gateRuleId,
    policy_reason: canaryPolicyReason ?? backendPolicyReason ?? hookPolicyReason ?? rulesPolicyReason ?? taintPolicyReason ?? gatePolicyReason,
    decision_input_hash: computeDecisionInputHash(decisionInput),
    engine_version: ENGINE_VERSION,
    external_backend: externalBackend,
  };

  // Presidio anonymizer produces the redacted copy when configured (typed
  // placeholders for NLP entities); regex redaction is the fallback. Only an
  // actually-redacted decision pays the anonymizer round-trip — mirrors the
  // Python shared pre-call and the wrapper's redact branch.
  let redactedViaAnonymizer: string | null = null;
  if (
    actionTaken === "redacted" &&
    config.presidio_analyzer_url &&
    config.presidio_anonymizer_url
  ) {
    redactedViaAnonymizer = await presidioRedactText(
      promptText,
      config.presidio_analyzer_url,
      config.presidio_anonymizer_url,
    );
  }

  return {
    decision:
      actionTaken === "blocked"
        ? "block"
        : actionTaken === "redacted"
          ? "redact"
          : "allow",
    compliance,
    // A canary leak stores a whole-text placeholder (the surface carries the
    // raw token and maybe an encoded copy — never persist the secret).
    // Otherwise: view-only detections have no locatable span, so the stored
    // copy becomes a whole-text placeholder (redactForStorage); with via
    // absent this is exactly the prior redactBuiltinPii output.
    redactedPrompt: canaryFloor
      ? CANARY_REDACTION_PLACEHOLDER
      : redactedViaAnonymizer ?? redactForStorage(promptText, piiScanVia),
    ...(piiScanVia !== undefined ? { securityNormalized: piiScanVia } : {}),
    ...(canaryTelemetry !== undefined ? { canaryTelemetry } : {}),
    ...(floorActive
      ? {
          floorTelemetry: {
            floor_version: deriveFloorVersion(config.policyFloor),
            ...(floorOverrideIgnored !== undefined
              ? { floor_override_ignored: floorOverrideIgnored }
              : {}),
          },
        }
      : {}),
  };
}

// ============================================================================
// Post-call policy
// ============================================================================

export interface PostCallPolicyResult {
  decision: 'pass' | 'flag' | 'redact_response';
  redactedResponse?: string;
  compliance: Partial<ComplianceInfo>;
  /**
   * Built-in response-side PII verdict (distinct from the prompt-side scan).
   * The request already reached the provider, so "block" cannot un-send it:
   * block/redact per-type actions both surface as action "redacted" on the
   * STORED copy; detect_only records the finding. Rides the M1 telemetry
   * metadata channel as response_pii_* so the signed wire schema is untouched.
   */
  responsePii?: {
    detected: boolean;
    types: string[];
    action: 'redacted' | 'detected_only';
    /**
     * Which de-obfuscation view surfaced the hit (server-side normalizer mirror); absent
     * for an overt raw-text match or with deobfuscation disabled. Present ⟹
     * spans are unlocatable ⟹ a redacted STORED copy is a whole-text
     * placeholder rather than span redaction.
     */
    via?: DeobfuscationView['method'];
  };
  /**
   * Canary-leak evidence when a planted honeytoken surfaced in the RESPONSE
   * (system-prompt/context leakage). The response was already produced, so
   * this is evidential: it forces `redact_response` (stored copy → placeholder)
   * and rides `metadata.obsvr_telemetry.canary_leak`. Never the raw token.
   */
  canaryTelemetry?: Record<string, unknown>;
}

export async function applyPostCallPolicy(
  responseText: string,
  event: Partial<AuditEvent>,
  config: ResolvedConfig,
): Promise<PostCallPolicyResult> {
  let decision: 'pass' | 'flag' | 'redact_response' = 'pass';
  let ruleId: string | undefined;
  let reason: string | undefined;

  // 0. Anti-tamper policy FLOOR on the RESPONSE (applies_to 'response'|'both').
  //    Evaluated first and re-asserted at the very end (below) so it is
  //    unsuppressible: neither the customer rules, the onPostCall hook (which
  //    can otherwise downgrade redact_response → flag), nor anything else may
  //    weaken it. The response already came back and cannot be un-sent, so a
  //    floor match fails closed to redact_response (the STORED copy is
  //    redacted). Twin: apply_post_call_policy in Python policy.py.
  let floorResponseLock = false;
  let floorResponseRuleId: string | undefined;
  let floorResponseReason: string | undefined;
  if (config.policyFloor && config.policyFloor.length > 0) {
    const floorCtx: PolicyEvalContext = {
      metadata: {
        ...((event.metadata as Record<string, unknown>) ?? {}),
        ...(event.user_id ? { user_id: event.user_id } : {}),
        ...(event.service_name ? { service_name: event.service_name } : {}),
        ...(event.tenant_id ? { tenant_id: event.tenant_id } : {}),
      },
    };
    const floorResult = evaluateFloor(config.policyFloor, responseText, 'response', floorCtx);
    if (floorResult.decision === 'block' || floorResult.decision === 'redact') {
      decision = 'redact_response';
      ruleId = floorResult.rule_id;
      reason = floorResult.reason;
      floorResponseLock = true;
      floorResponseRuleId = floorResult.rule_id;
      floorResponseReason = floorResult.reason;
    }
  }

  // 1. Evaluate rules against response. Identity context (user/service/
  // tenant) rides along so response-scoped quota rules meter the SAME
  // bucket the request phase used — never a silent 'default' fallback.
  if (config.policyRules && config.policyRules.length > 0) {
    const evalContext: PolicyEvalContext = {
      metadata: {
        ...((event.metadata as Record<string, unknown>) ?? {}),
        ...(event.user_id ? { user_id: event.user_id } : {}),
        ...(event.service_name ? { service_name: event.service_name } : {}),
        ...(event.tenant_id ? { tenant_id: event.tenant_id } : {}),
      },
    };
    const rulesResult = evaluatePolicyRules(config.policyRules, responseText, 'response', evalContext);
    if (rulesResult.decision === 'block') {
      decision = 'redact_response';
    } else if (rulesResult.decision === 'redact') {
      decision = 'redact_response';
    }
    ruleId = rulesResult.rule_id;
    reason = rulesResult.reason;
  }

  // 2. onPostCall hook (timeout + error handling same as onPreCall)
  if (config.on_post_call) {
    let hookResult: PostCallDecisionResult | 'hook_timeout';
    try {
      const timeoutMs = config.postCallTimeoutMs ?? 2000;
      const raw = await (timeoutMs > 0
        ? Promise.race([
            config.on_post_call(responseText, event),
            new Promise<'hook_timeout'>((res) => setTimeout(() => res('hook_timeout'), timeoutMs)),
          ])
        : config.on_post_call(responseText, event));
      hookResult = raw === 'hook_timeout' ? 'hook_timeout' : normalizePostCallDecision(raw as PostCallDecisionResult);
    } catch {
      hookResult = { decision: 'pass' };
    }
    if (hookResult !== 'hook_timeout') {
      const hd = (hookResult as PostCallDecisionResult).decision;
      if (hd === 'redact_response' || hd === 'flag') {
        decision = hd;
        ruleId = (hookResult as PostCallDecisionResult).rule_id ?? ruleId;
        reason = (hookResult as PostCallDecisionResult).reason ?? reason;
      }
    }
  }

  // 3. Built-in response-side PII scan (the response twin of the pre-call
  // Step 1 scan). Only when a pii_policy is configured, matching pre-call
  // behavior. Per-type resolution reuses resolvePiiPolicy; on the response
  // side a "block" verdict cannot un-send the request, so block and redact
  // both redact the STORED copy, and detect_only records the finding.
  let responsePii: PostCallPolicyResult['responsePii'];
  let storedRedactionVia: DeobfuscationView['method'] | undefined;
  if (config.pii_policy && responseText) {
    const scan = runConfiguredPiiScan(responseText, config.deobfuscation);
    if (scan.pii_detected) {
      const resolved = resolvePiiPolicy(scan.detected_types, config.pii_policy);
      const mustRedact = resolved.action === 'block' || resolved.action === 'redact';
      responsePii = {
        detected: true,
        types: scan.detected_types,
        action: mustRedact ? 'redacted' : 'detected_only',
        ...(scan.via !== undefined ? { via: scan.via } : {}),
      };
      if (mustRedact) {
        decision = 'redact_response';
        if (!reason) reason = 'pii_detected_in_response';
        // View-only hit: the stored copy must become a whole-text placeholder
        // (span redaction cannot locate an encoded payload).
        storedRedactionVia = scan.via;
      }
    }
  }

  // Canary-leak scan on the RESPONSE (the primary leak surface: a planted
  // system-prompt/context token surfacing in the model's output). Evidential —
  // the response already came back, so this forces redact_response and stores
  // a placeholder (never the raw token), and stamps CRITICAL telemetry. Only
  // when a canary has been minted (zero cost otherwise).
  let canaryTelemetry: Record<string, unknown> | undefined;
  let canaryLeaked = false;
  if (canaryRegistrySize() > 0 && responseText) {
    const leak = scanForCanary(responseText);
    if (leak.leaked) {
      canaryLeaked = true;
      decision = 'redact_response';
      canaryTelemetry = canaryLeakTelemetry(leak.hits, 'response');
      if (!ruleId) ruleId = 'sdk:canary_leak';
      reason = `Canary token leaked in response (${leak.hits.map((h) => h.id).join(', ')})`;
    }
  }

  // Re-assert the floor (unsuppressible): nothing above may downgrade a
  // floor-forced response redaction. Keep the floor's attribution unless a
  // canary also leaked (canary is likewise critical and carries its own
  // telemetry, so its rule_id/reason stay).
  if (floorResponseLock) {
    decision = 'redact_response';
    if (!canaryLeaked) {
      ruleId = floorResponseRuleId;
      reason = floorResponseReason;
    }
  }

  const compliance: Partial<ComplianceInfo> = {};
  if (decision === 'flag') {
    compliance.event_type = 'policy_flag';
  }
  if (ruleId) compliance.rule_id = ruleId;
  if (reason) compliance.policy_reason = reason;

  return {
    decision,
    // A canary leak replaces the whole stored response (the surface carries the
    // raw token / an encoded copy). A floor match likewise replaces the whole
    // stored response: a floor rule match (keyword/regex/topic) has no locatable
    // span the PII redactor could target, so span-redaction would leave the
    // matched content intact — the floor must store a placeholder, never a
    // silently-intact "redacted" record. Otherwise the PII redaction path.
    redactedResponse: decision === 'redact_response'
      ? (canaryLeaked
          ? CANARY_REDACTION_PLACEHOLDER
          : floorResponseLock
            ? FLOOR_REDACTION_PLACEHOLDER
            : redactForStorage(responseText, storedRedactionVia))
      : undefined,
    compliance,
    ...(responsePii ? { responsePii } : {}),
    ...(canaryTelemetry !== undefined ? { canaryTelemetry } : {}),
  };
}

/**
 * Merge a post-call outcome onto a built audit event, mirroring the Python
 * wrapper exactly (wrap.py): the STORED response is replaced by the redacted
 * copy, compliance keys overlay the event, and the response-side PII verdict
 * rides metadata.obsvr_telemetry (M1 channel) as response_pii_* fields.
 * The response returned to the caller is never modified here.
 */
export function mergePostCallOutcome(
  event: AuditEvent,
  post: PostCallPolicyResult,
): void {
  if (post.decision === 'redact_response' && post.redactedResponse !== undefined) {
    event.response = post.redactedResponse;
  }
  if (post.compliance.event_type) event.event_type = post.compliance.event_type;
  if (post.compliance.rule_id) event.rule_id = post.compliance.rule_id;
  if (post.compliance.policy_reason) event.policy_reason = post.compliance.policy_reason;

  if (post.responsePii) {
    const metadata = (event.metadata ?? {}) as Record<string, unknown>;
    const telemetry = {
      ...((metadata.obsvr_telemetry as Record<string, unknown>) ?? {}),
      response_pii_detected: post.responsePii.detected,
      response_pii_types: post.responsePii.types,
      response_pii_action: post.responsePii.action,
      // Server-side normalizer mirror: which view defeated the obfuscation (absent for
      // overt matches — key not written, keeping existing events byte-stable).
      ...(post.responsePii.via !== undefined
        ? { response_pii_via: post.responsePii.via }
        : {}),
    };
    metadata.obsvr_telemetry = telemetry;
    event.metadata = metadata;
  }

  if (post.canaryTelemetry) {
    // CRITICAL canary evidence rides the reserved obsvr_telemetry channel so
    // it survives metadata trimming; only ids + hash prefixes, never a token.
    const metadata = (event.metadata ?? {}) as Record<string, unknown>;
    metadata.obsvr_telemetry = {
      ...((metadata.obsvr_telemetry as Record<string, unknown>) ?? {}),
      ...post.canaryTelemetry,
    };
    event.metadata = metadata;
  }
}

/**
 * The prompt stored on a blocked-call forensic event: redacted form when
 * PII triggered the block, otherwise a policy placeholder.
 */
export function blockedPromptForStorage(
  promptText: string,
  compliance: ComplianceInfo,
  /**
   * `securityNormalized` from the PreCallPolicyResult, when the caller has
   * one: a view-only detection has no locatable span, so the stored prompt
   * becomes a whole-text placeholder instead of a silently-intact "redacted"
   * copy. Additive — omitting it preserves the prior behavior exactly.
   */
  via?: DeobfuscationView["method"],
): string {
  return compliance.action_reason === "pii_detected"
    ? redactForStorage(promptText, via)
    : "[BLOCKED_BY_POLICY]";
}

/**
 * The `user_input` stored on a blocked pre-call event. On a canary-leak block
 * the raw token must NEVER persist (redactForStorage → redactBuiltinPii does
 * not know the canary format), so the stored copy is the canary placeholder;
 * otherwise the view-aware redaction. Used by every infra integration's
 * blocked event so none of them leak a leaked token into the audit trail.
 */
export function blockedUserInputForStorage(
  userText: string,
  policy: Pick<PreCallPolicyResult, "canaryTelemetry" | "securityNormalized">,
): string {
  return policy.canaryTelemetry !== undefined
    ? CANARY_REDACTION_PLACEHOLDER
    : redactForStorage(userText, policy.securityNormalized);
}

/**
 * Observe-only policy for framework callbacks: the request was already
 * sent to the LLM, so PII policy applies to the *stored* copy.
 * "block" is downgraded to redact-in-event with action_reason pii_detected.
 */
/**
 * DEFAULT_COMPLIANCE copy with the REAL policy_version (derived rules hash)
 * stamped: even observe-only paths must pin the exact policy state they ran
 * under, so the sealed policy_version (v6 leaf) is accurate for framework events
 * too — never a placeholder. Mirrors the Python SDK's `_observe_compliance`.
 */
function observeCompliance(config: ResolvedConfig): ComplianceInfo {
  return {
    ...DEFAULT_COMPLIANCE,
    policy_version: derivePolicyVersion(config.policyRules ?? []),
  };
}

export function applyObservePolicy(
  promptText: string,
  config: ResolvedConfig,
): {
  shouldRedactStored: boolean;
  compliance: ComplianceInfo;
  /**
   * Which de-obfuscation view surfaced the hit (absent for overt matches or
   * with deobfuscation disabled). When present alongside
   * `shouldRedactStored`, callers MUST redact stored copies with
   * `redactForStorage(text, storedRedactionVia)` — span redaction cannot
   * locate an encoded payload.
   */
  storedRedactionVia?: DeobfuscationView["method"];
} {
  if (!config.pii_policy) {
    return { shouldRedactStored: false, compliance: observeCompliance(config) };
  }
  const scan = runConfiguredPiiScan(promptText, config.deobfuscation);
  const { pii_detected, detected_types } = scan;
  if (!pii_detected) {
    return { shouldRedactStored: false, compliance: observeCompliance(config) };
  }
  const resolved = resolvePiiPolicy(detected_types, config.pii_policy);
  if (resolved.action === "detect_only") {
    return {
      shouldRedactStored: false,
      compliance: {
        ...observeCompliance(config),
        action_reason: "pii_detected",
        action_source: "builtin",
      },
      ...(scan.via !== undefined ? { storedRedactionVia: scan.via } : {}),
    };
  }
  // redact OR block (downgraded): redact the stored copy
  return {
    shouldRedactStored: true,
    compliance: {
      ...observeCompliance(config),
      action_taken: "redacted",
      action_reason: "pii_detected",
      action_source: "builtin",
      redacted_types: [...resolved.redactedTypes, ...resolved.blockedTypes],
      blocked_types: [],
    },
    ...(scan.via !== undefined ? { storedRedactionVia: scan.via } : {}),
  };
}

// ============================================================================
// Event building + emission
// ============================================================================

export interface IntegrationEventParams {
  config: ResolvedConfig;
  provider: IntegrationProvider;
  model: string;
  /** Provider-resolved model snapshot from the response body, when captured. */
  model_resolved?: string;
  /** Trust tier for `model_resolved`, set by the integration at its capture
   * site: `provider_response` (native provider client) or `framework_reported`
   * (third-party framework abstraction). Present iff `model_resolved` is. */
  provenance_source?: "provider_response" | "framework_reported" | "client_declared";
  operation: string;
  /** Integration default source label (e.g. "langchain_js") */
  source: string;
  prompt: string;
  response?: string;
  userInput?: string;
  inputTokens?: number;
  outputTokens?: number;
  totalTokens?: number;
  latencyMs?: number;
  timeToFirstTokenMs?: number;
  success?: boolean;
  statusCode?: number;
  error?: unknown;
  requestId?: string;
  metadata?: Record<string, unknown>;
  options?: IntegrationOptions;
  compliance?: ComplianceInfo;
  /** Optional curated call telemetry (DASHBOARD_TELEMETRY.md M1). Merged
   * into metadata under the reserved key when supplied by an integration. */
  telemetry?: CallTelemetry;
  /** Canary-leak evidence for a PRE-CALL block (whose stored prompt is already
   * a placeholder, so the event-layer scrub cannot re-derive it). Merged into
   * metadata.obsvr_telemetry.canary_leak. Never the raw token. */
  canaryTelemetry?: Record<string, unknown>;
  /** Anti-tamper floor evidence (floor_version / floor_override_ignored),
   * merged into metadata.obsvr_telemetry. */
  floorTelemetry?: Record<string, unknown>;
}

/**
 * Build an AuditEvent with the same field mapping as the proxy wrapper's
 * buildAuditEvent (precedence: per-call > options > config defaults).
 */
export function buildIntegrationEvent(
  params: IntegrationEventParams,
): AuditEvent {
  const { config } = params;
  const options = params.options ?? {};
  const ambientSubject = getCurrentSubject();
  const compliance = params.compliance ?? DEFAULT_COMPLIANCE;
  const success = params.success ?? true;

  // Final canary safety net: NO emitted event may carry a raw canary token in
  // its content, on ANY path. The model echoing a planted token into its
  // OUTPUT is the primary leak surface, and the infra integrations have no
  // post-call scan — so this event-construction chokepoint scans
  // prompt/response/user_input, replaces a leaked field with the placeholder,
  // and stamps the evidence (ids/hash-prefixes, never the token). Zero cost
  // until a canary is minted.
  let scrubbedPrompt = params.prompt;
  let scrubbedResponse = params.response ?? "";
  let scrubbedUserInput = params.userInput;
  let canaryEventTelemetry: Record<string, unknown> | undefined;
  if (canaryRegistrySize() > 0) {
    const hits: CanaryHit[] = [];
    let leakSurface: string | undefined;
    const scrub = (v: string, surface: string): string => {
      const leak = scanForCanary(v);
      if (leak.leaked) {
        hits.push(...leak.hits);
        if (leakSurface === undefined) leakSurface = surface;
        return CANARY_REDACTION_PLACEHOLDER;
      }
      return v;
    };
    scrubbedPrompt = scrub(scrubbedPrompt, "prompt");
    scrubbedResponse = scrub(scrubbedResponse, "response");
    if (scrubbedUserInput !== undefined) scrubbedUserInput = scrub(scrubbedUserInput, "user_input");
    if (hits.length > 0) canaryEventTelemetry = canaryLeakTelemetry(hits, leakSurface ?? "response");
  }

  const errorMessage = (() => {
    const m =
      params.error instanceof Error
        ? params.error.message
        : params.error
          ? String(params.error)
          : undefined;
    return m && m.length > 500 ? m.slice(0, 500) : m;
  })();

  const event: AuditEvent = {
    // Core fields
    request_id: params.requestId || generateUUID(),

    // Environment fields
    environment: config.environment,
    service_name:
      options.service_name || ambientSubject?.service_name || config.default_service_name || undefined,
    region: options.region || config.default_region || "unknown",

    // Provider-resolved model snapshot (temporal provenance), when captured.
    model_resolved: params.model_resolved ?? undefined,
    // Trust tier for the capture above; threaded through from the integration.
    provenance_source: params.provenance_source ?? undefined,

    // Identity fields — explicit options win, else the ambient useSubject() subject
    user_id: options.user_id || ambientSubject?.user_id || undefined,

    // Network fields
    client_ip: undefined,
    user_agent: undefined,

    // LLM Call fields
    provider: params.provider,
    model: params.model || "unknown",
    operation: params.operation,
    source: options.source || params.source || config.default_source || "integration",

    // Content fields (canary-scrubbed — a leaked token never reaches storage)
    prompt: truncate(scrubbedPrompt, config.max_payload_chars),
    response: truncate(scrubbedResponse, config.max_payload_chars),
    user_input:
      scrubbedUserInput !== undefined
        ? truncate(scrubbedUserInput, config.max_payload_chars)
        : undefined,

    // Usage fields
    input_tokens: params.inputTokens,
    output_tokens: params.outputTokens,
    total_tokens: params.totalTokens,

    // Performance fields
    latency_ms: params.latencyMs,
    time_to_first_token_ms: params.timeToFirstTokenMs,

    // Success/Status fields
    success,
    status_code: params.statusCode ?? (success ? 200 : 500),
    error_type: params.error ? classifyError(params.error) : null,
    error_message: errorMessage,

    // Metadata (call telemetry + span envelope merged under reserved keys).
    // For tool events, surface the tool name as the standard span attribute
    // `gen_ai.tool.name` so the ingest projection promotes it to a first-class
    // `tool_name` (routes.ts), letting the dashboard show the tool instead of
    // an empty model.
    // Ambient agent-run stamping (withRunMetadata) makes every governed action
    // inside an `agentRun(...)` scope — tool calls, framework handler events —
    // carry the run's agent_run_id, so they group into one run. A caller that
    // set agent_run_id itself (LangChain, OpenAI-Agents) always wins; outside a
    // run scope the metadata is byte-identical to before.
    metadata: withRunMetadata(
      withSpanMetadata(
        withTelemetryMetadata(
          // ingest coerces provider "mcp" → "unknown"; stamp the identity
          // in metadata.provider_detail so provider-level analytics can recover it.
          params.provider === "mcp"
            ? { ...(params.metadata ?? options.metadata ?? {}), provider_detail: "mcp" }
            : params.metadata ?? options.metadata,
          params.telemetry ?? {},
        ),
        spanEnvelopeFor(
          "llm_call",
          params.operation,
          typeof (params.metadata as { tool_name?: unknown } | undefined)?.tool_name === "string"
            ? { "gen_ai.tool.name": (params.metadata as { tool_name: string }).tool_name }
            : undefined,
        ),
      ),
    ),

    // Compliance fields
    event_type: compliance.event_type,
    policy_version: compliance.policy_version,
    action_taken: compliance.action_taken,
    action_reason: compliance.action_reason,
    action_source: compliance.action_source,
    redacted_types: compliance.redacted_types,
    blocked_types: compliance.blocked_types,
    rule_id: compliance.rule_id,
    policy_reason: compliance.policy_reason,
    // Canonical decision record (ADR-2, additive — not in the chain preimage)
    decision_input_hash: compliance.decision_input_hash,
    engine_version: compliance.engine_version,
    // External policy backend provenance (ADR-4, additive)
    external_backend: compliance.external_backend,
  };

  // Stamp canary + floor evidence on the reserved obsvr_telemetry channel:
  // canary from the caller (pre-call block) and/or the event-layer scrub;
  // floor from config + caller. floor_version is a pure function of
  // config.policyFloor, so it is derived HERE for EVERY event under an active
  // floor — matching the proxy wrapper (which stamps it on all events, not
  // just blocks) so a change to the floor is auditable from the allowed-event
  // stream on every integration path. The call-specific floor_override_ignored
  // still rides params.floorTelemetry (only the block path carries it), and is
  // merged on top so it wins where present.
  const canaryTel = params.canaryTelemetry ?? canaryEventTelemetry;
  const floorActive = !!(config.policyFloor && config.policyFloor.length > 0);
  if (floorActive || params.floorTelemetry) {
    const metadata = (event.metadata ?? {}) as Record<string, unknown>;
    metadata.obsvr_telemetry = {
      ...((metadata.obsvr_telemetry as Record<string, unknown>) ?? {}),
      ...(floorActive ? { floor_version: deriveFloorVersion(config.policyFloor) } : {}),
      ...(params.floorTelemetry ?? {}),
    };
    event.metadata = metadata;
  }
  if (canaryTel) {
    const metadata = (event.metadata ?? {}) as Record<string, unknown>;
    metadata.obsvr_telemetry = {
      ...((metadata.obsvr_telemetry as Record<string, unknown>) ?? {}),
      ...canaryTel,
    };
    event.metadata = metadata;
    // A leak the event-layer scrub caught on an otherwise-clean event must not
    // read as "allowed" — surface it as a policy_flag with the canary rule id.
    if (canaryEventTelemetry && event.action_taken === "allowed") {
      event.event_type = "policy_flag";
      event.rule_id = event.rule_id ?? "sdk:canary_leak";
      event.policy_reason = event.policy_reason ?? "Canary token leaked in emitted content";
    }
  }

  return event;
}

/**
 * Build and fire-and-forget send an integration audit event.
 * Returns the built event (useful for tests), or null on build failure.
 * Never throws - audit failures must not affect the LLM call path.
 */
export function emitIntegrationEvent(
  params: IntegrationEventParams,
): AuditEvent | null {
  const { config } = params;
  if (config.disabled) return null;
  try {
    const event = buildIntegrationEvent(params);
    sendAuditAsync(config, event);
    debugLog(
      config,
      "info",
      `Audit event queued (integration:${params.source}): ${event.request_id}`,
    );
    return event;
  } catch (err) {
    debugLog(
      config,
      "error",
      "Failed to build integration audit event:",
      err instanceof Error ? err.message : String(err),
    );
    return null;
  }
}

/**
 * Standard blocked-call error thrown by infra integrations.
 */
export function blockedCallError(compliance: ComplianceInfo): Error {
  return new Error(
    `[obsvr] Request blocked by policy (${
      compliance.action_reason === "pii_detected"
        ? "PII detected"
        : "policy violation"
    })`,
  );
}

/**
 * Check if an object is an AsyncIterable (stream)
 */
export function isAsyncIterable(obj: unknown): obj is AsyncIterable<unknown> {
  return obj !== null && typeof obj === "object" && Symbol.asyncIterator in obj;
}

// ============================================================================
// Loop detection + delegation tracking helpers
// ============================================================================

/**
 * Apply loop detection and emit an audit event if the threshold is exceeded.
 * Returns the action to take ('block' | 'escalate') or null if within limits.
 */
export function applyLoopDetection(
  detector: LoopDetector,
  config: ResolvedConfig,
  meta: { agentRunId: string; source: string; operation: string },
): { action: 'block' | 'escalate'; iterationCount: number } | null {
  const result = detector.recordIteration();
  if (!result) return null;

  emitIntegrationEvent({
    config,
    provider: 'unknown',
    model: 'unknown',
    operation: `${meta.operation}.loop_detected`,
    source: meta.source,
    prompt: '',
    response: '',
    success: result.action === 'escalate',
    metadata: {
      agent_run_id: meta.agentRunId,
      loop_iteration_count: result.iterationCount,
      loop_action: result.action,
    },
    compliance: {
      ...DEFAULT_COMPLIANCE,
      event_type: 'loop_detected',
    },
  });

  return result;
}

/**
 * Apply delegation policy and emit an audit event on violation.
 * Returns the violation details or null if delegation is allowed.
 */
export function applyDelegationPolicy(
  tracker: DelegationTracker,
  fromAgent: string,
  toAgent: string,
  config: ResolvedConfig,
  meta: { agentRunId: string; source: string; operation: string },
): DelegationViolation | null {
  const violation = tracker.recordDelegation(fromAgent, toAgent);
  if (!violation) {
    // Emit delegation event (success)
    emitIntegrationEvent({
      config,
      provider: 'unknown',
      model: 'unknown',
      operation: `${meta.operation}.delegation`,
      source: meta.source,
      prompt: '',
      response: '',
      metadata: {
        agent_run_id: meta.agentRunId,
        from_agent: fromAgent,
        to_agent: toAgent,
        delegation_chain: tracker.getChain(),
        delegation_depth: tracker.getDepth(),
      },
      compliance: {
        ...DEFAULT_COMPLIANCE,
        event_type: 'delegation',
      },
    });
    return null;
  }

  // Emit violation event
  emitIntegrationEvent({
    config,
    provider: 'unknown',
    model: 'unknown',
    operation: `${meta.operation}.delegation_blocked`,
    source: meta.source,
    prompt: '',
    response: '',
    success: false,
    metadata: {
      agent_run_id: meta.agentRunId,
      from_agent: fromAgent,
      to_agent: toAgent,
      violation_type: violation.type,
      delegation_chain: violation.chain,
      delegation_depth: violation.depth,
    },
    compliance: {
      ...DEFAULT_COMPLIANCE,
      event_type: 'delegation',
      action_taken: 'blocked',
      action_reason: 'policy_violation',
      action_source: 'policy_rules',
      policy_reason: violation.message,
    },
  });

  return violation;
}

/**
 * Infer a provider label from an arbitrary identifier string
 * (LangChain serialized ids, Vercel AI model.provider, class names...).
 */
export function inferProviderFromString(id: string): IntegrationProvider {
  const s = id.toLowerCase();
  if (s.includes("azure")) return "azure_openai";
  if (s.includes("bedrock")) return "bedrock";
  if (s.includes("vertex")) return "vertex_ai";
  if (s.includes("together")) return "together";
  if (s.includes("cloudflare") || s.includes("workersai")) return "cloudflare";
  if (s.includes("openai")) return "openai";
  if (s.includes("anthropic") || s.includes("claude")) return "anthropic";
  if (s.includes("google") || s.includes("gemini") || s.includes("genai")) {
    return "google";
  }
  return "unknown";
}
