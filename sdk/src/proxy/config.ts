/**
 * Singleton Configuration Manager
 *
 * Manages global state for the LLM Audit proxy SDK.
 *
 * @packageDocumentation
 */

import type {
  AuditEvent,
  LLMAuditInitConfig,
  LLMAuditState,
  ObsvrConfig,
  ResolvedConfig,
} from "./types.js";
import { randomUUID } from "node:crypto";
import { debugLog } from "../utils/logger.js";
import { PROXY_TIMEOUT_MS, SDK_VERSION } from "../constants.js";

/**
 * Stable per-process id sent as `X-Obsvr-Instance-Id` on every /policies poll.
 * Fleet-quota escrow (ADR-7) allocates a share per instance; without a distinct
 * id, N replicas sharing one API key reconcile against ONE escrow record and
 * either over-block or collectively overspend the budget. One id per process is
 * exactly the granularity the allocator needs.
 */
const SDK_INSTANCE_ID = randomUUID();
import type { PolicyRule } from "../policy/rules.js";
import { derivePolicyVersion } from "../policy/rules.js";
import { snapshotPolicy, emitPolicyChangedEvent, sendPolicyEvent } from "../policy/policy-log.js";
import { validateRegexPattern } from "../utils/safe-regex.js";
import { updateApprovals, type ApprovalGrant } from "../policy/approvals.js";
import {
  applyEscrowResponse,
  snapshotConsumption,
  type EscrowShare,
} from "../governance/escrow.js";
import { verifyPolicySignature, type PolicySignature } from "./policy-verify.js";
import { assertBackendUrlStatic } from "../utils/ssrf.js";
import { _resetCanaries } from "../policy/canary.js";
import { _resetSessionTaint } from "../policy/session-taint.js";

/**
 * Global singleton state
 */
const state: LLMAuditState = {
  initialized: false,
  config: null,
  wrappedClients: new WeakSet(),
};

const tenantRegistry = new Map<string, { policyRules?: PolicyRule[] }>();

let policyPollIntervalId: ReturnType<typeof setInterval> | null = null;

/**
 * Convert public camelCase ObsvrConfig to internal snake_case LLMAuditInitConfig
 */
function fromObsvrConfig(config: ObsvrConfig): LLMAuditInitConfig {
  return {
    api_key: config.apiKey,
    ingest_url: config.ingestUrl,
    environment: config.environment,
    sample_rate: config.sampleRate,
    debug: config.debug,
    disabled: config.disabled,
    streaming_mode: config.streamingMode,
    on_pre_call: config.onPreCall,
    hook_timeout_ms: config.hookTimeoutMs,
    hook_trigger: config.hookTrigger,
    fail_mode: config.failMode,
    pii_policy: config.piiPolicy,
    policy_rules: config.policyRules,
    policyFloor: config.policyFloor,
    on_post_call: config.onPostCall,
    post_call_timeout_ms: config.postCallTimeoutMs,
    agent_policy: config.agentPolicy,
    providers: config.providers,
    policy_refresh_interval_ms: config.policyRefreshIntervalMs,
    policy_staleness_budget_ms: config.policyStalenessBudgetMs,
    policy_public_key: config.policyPublicKey,
    multi_turn_injection: config.multiTurnInjection,
    sessionTaint: config.sessionTaint,
    deobfuscation: config.deobfuscation,
    otel: config.otel,
    mcpToolPolicy: config.mcpToolPolicy,
    presidio_analyzer_url: config.presidioAnalyzerUrl,
    presidio_anonymizer_url: config.presidioAnonymizerUrl,
    hardDeletion: config.hardDeletion,
    environmentPolicies: config.environmentPolicies,
    external_policy_backend: config.externalPolicyBackend,
  };
}

/**
 * Detect whether a config object is in ObsvrConfig (camelCase) form.
 */
function isObsvrConfig(
  config: LLMAuditInitConfig | ObsvrConfig,
): config is ObsvrConfig {
  return "apiKey" in config;
}

/**
 * Validate and resolve configuration with defaults
 */
function resolveConfig(config: LLMAuditInitConfig): ResolvedConfig {
  // Validate required fields
  if (!config.api_key) {
    throw new Error("obsvr.init(): api_key is required");
  }

  if (typeof config.api_key !== "string" || config.api_key.trim() === "") {
    throw new Error("obsvr.init(): api_key must be a non-empty string");
  }

  // Validate ingest_url if provided
  if (config.ingest_url !== undefined) {
    try {
      new URL(config.ingest_url);
    } catch {
      throw new Error(
        `obsvr.init(): invalid ingest_url "${config.ingest_url}"`,
      );
    }
  }

  // Strict init validation (E14): reject clearly-invalid values with a
  // typed error AT INIT, never at first use. Silent misconfiguration of a
  // governance SDK is itself a governance failure. (This function receives
  // the snake_case LLMAuditInitConfig; camelCase ObsvrConfig keys were
  // mapped in fromObsvrConfig above.)
  if (config.fail_mode !== undefined && config.fail_mode !== "open" && config.fail_mode !== "closed") {
    throw new Error(
      `obsvr.init(): failMode must be "open" or "closed", got "${String(config.fail_mode)}"`,
    );
  }
  if (config.timeout !== undefined && (typeof config.timeout !== "number" || config.timeout <= 0)) {
    throw new Error(`obsvr.init(): timeout must be a positive number of ms, got ${String(config.timeout)}`);
  }
  const refreshMs = config.policy_refresh_interval_ms;
  if (refreshMs !== undefined && (typeof refreshMs !== "number" || refreshMs < 0)) {
    throw new Error(`obsvr.init(): policyRefreshIntervalMs must be >= 0, got ${String(refreshMs)}`);
  }
  const stalenessMs = config.policy_staleness_budget_ms;
  if (stalenessMs !== undefined && (typeof stalenessMs !== "number" || stalenessMs <= 0)) {
    throw new Error(`obsvr.init(): policyStalenessBudgetMs must be a positive number of ms, got ${String(stalenessMs)}`);
  }
  if (config.sample_rate !== undefined && typeof config.sample_rate !== "number") {
    throw new Error(`obsvr.init(): sample_rate must be a number in [0, 1], got ${String(config.sample_rate)}`);
  }

  // External policy backend (ADR-4): validate the shape and run the STATIC SSRF
  // guard (scheme + literal-IP range) so a clearly-unsafe backend URL fails at
  // init, never at first call. Hostname resolution is checked per-call.
  const backend = config.external_policy_backend;
  if (backend !== undefined) {
    if (!backend || typeof backend !== "object") {
      throw new Error("obsvr.init(): externalPolicyBackend must be an object");
    }
    if (backend.type !== "opa" && backend.type !== "cedar") {
      throw new Error(
        `obsvr.init(): externalPolicyBackend.type must be "opa" or "cedar", got "${String(backend.type)}"`,
      );
    }
    if (typeof backend.url !== "string" || backend.url.trim() === "") {
      throw new Error("obsvr.init(): externalPolicyBackend.url must be a non-empty string");
    }
    if (backend.timeoutMs !== undefined && (typeof backend.timeoutMs !== "number" || backend.timeoutMs <= 0)) {
      throw new Error(
        `obsvr.init(): externalPolicyBackend.timeoutMs must be a positive number of ms, got ${String(backend.timeoutMs)}`,
      );
    }
    // Throws SsrfError (an Error subtype) on a non-http(s) scheme or a literal
    // metadata/private IP (unless allowPrivateNetwork permits the private case).
    assertBackendUrlStatic(backend.url, { allowPrivateNetwork: backend.allowPrivateNetwork });
  }

  // Presidio analyzer/anonymizer endpoints receive the PROMPT/PII content to
  // scan, so a misconfigured or hijacked URL is both an SSRF primitive and a
  // data-exfiltration surface — the endpoint that sees the MOST sensitive data.
  // Run the STATIC SSRF guard at init on each configured endpoint (parity with
  // the external policy backend above). A presidio deployment is normally a
  // LOCAL sidecar (localhost / private host), so private/loopback are permitted
  // here — but the cloud-metadata / link-local endpoint (169.254.169.254 and
  // the IPv6 forms) is ALWAYS refused, no opt-out, closing the crown-jewel SSRF
  // vector. Twin: sdk-python/obsvr/config.py.
  for (const [name, purl] of [
    ["presidioAnalyzerUrl", config.presidio_analyzer_url],
    ["presidioAnonymizerUrl", config.presidio_anonymizer_url],
  ] as const) {
    if (purl !== undefined) {
      if (typeof purl !== "string" || purl.trim() === "") {
        throw new Error(`obsvr.init(): ${name} must be a non-empty string`);
      }
      try {
        assertBackendUrlStatic(purl, { allowPrivateNetwork: true });
      } catch (e) {
        throw new Error(
          `obsvr.init(): ${name} failed the SSRF guard: ${e instanceof Error ? e.message : String(e)}`,
        );
      }
    }
  }

  // Clamp sample_rate to [0, 1]
  let sampleRate = config.sample_rate ?? 1.0;
  if (sampleRate < 0) sampleRate = 0;
  if (sampleRate > 1) sampleRate = 1;

  const resolved: ResolvedConfig = {
    api_key: config.api_key.trim(),
    environment: config.environment ?? "development",
    ingest_url: (() => {
      if (!config.ingest_url) {
        console.warn(
          "[obsvr] WARNING: ingest_url is not configured. " +
            "Audit events will not be delivered until ingest_url is set in obsvr.init().",
        );
        return "";
      }
      const url = config.ingest_url.replace(/\/$/, "");
      // Enforce HTTPS for any non-localhost URL to protect audit data in transit
      if (
        url.startsWith("http://") &&
        !url.includes("localhost") &&
        !url.includes("127.0.0.1")
      ) {
        throw new Error(
          `obsvr.init(): ingest_url "${url}" uses plaintext HTTP for a non-localhost URL. ` +
            "Use HTTPS to protect audit events in transit.",
        );
      }
      return url;
    })(),
    sample_rate: sampleRate,
    max_payload_chars: config.max_payload_chars ?? 100000,
    disabled: config.disabled ?? false,
    debug: config.debug ?? false,
    timeout: config.timeout ?? PROXY_TIMEOUT_MS,
    streaming_mode: config.streaming_mode ?? "wrap",
    default_region: config.default_region,
    default_source: config.default_source,
    on_pre_call: config.on_pre_call,
    hookTimeoutMs: config.hook_timeout_ms,
    hookTrigger: config.hook_trigger,
    failMode: config.fail_mode ?? 'open',
    pii_policy: (() => {
      const p = config.pii_policy as any;
      if (!p) return undefined;
      // Backward compat: convert legacy { action: "block" } shape to new { default: "block" }
      if ("action" in p && !("default" in p) && !("rules" in p)) {
        return { default: p.action as "block" | "redact" | "detect_only" };
      }
      // W6: Warn about PII types that have no built-in detection patterns
      if (p.rules && typeof p.rules === "object") {
        const UNDETECTABLE_PII_TYPES = new Set([
          "name", "address", "person", "location", "medical", "national_id",
        ]);
        const undetectable = Object.keys(p.rules).filter((k) =>
          UNDETECTABLE_PII_TYPES.has(k),
        );
        if (undetectable.length > 0) {
          console.warn(
            `[obsvr] WARNING: pii_policy.rules contains types with no built-in detection patterns: ${undetectable.join(", ")}. ` +
              "These rules will never fire with regex-only scanning. " +
              "Use the Presidio integration for name/address/medical detection.",
          );
        }
      }
      return p;
    })(),
    policyRules: config.policy_rules,
    policyFloor: config.policyFloor,
    agentPolicy: config.agent_policy,
    on_post_call: config.on_post_call,
    postCallTimeoutMs: config.post_call_timeout_ms,
    providers: config.providers,
    policyRefreshIntervalMs: config.policy_refresh_interval_ms ?? 30_000,
    policyStalenessBudgetMs: config.policy_staleness_budget_ms,
    policyPublicKey: config.policy_public_key,
    multiTurnInjection: config.multi_turn_injection,
    sessionTaint: config.sessionTaint,
    deobfuscation: config.deobfuscation,
    otel: config.otel,
    mcpToolPolicy: config.mcpToolPolicy,
    presidio_analyzer_url: config.presidio_analyzer_url,
    presidio_anonymizer_url: config.presidio_anonymizer_url,
    hardDeletion: config.hardDeletion,
    environmentPolicies: config.environmentPolicies,
    external_policy_backend: config.external_policy_backend,
  };

  // Merge environment-specific policy overrides into the resolved config
  if (resolved.environmentPolicies && resolved.environment) {
    const envOverride = resolved.environmentPolicies[resolved.environment];
    if (envOverride) {
      if (envOverride.policyRules) {
        resolved.policyRules = [
          ...(resolved.policyRules ?? []),
          ...envOverride.policyRules,
        ];
      }
      if (envOverride.agentPolicy) {
        resolved.agentPolicy = {
          ...resolved.agentPolicy,
          ...envOverride.agentPolicy,
        };
      }
    }
  }

  return resolved;
}

/**
 * Initialize the LLM Audit proxy SDK
 *
 * Accepts either the new camelCase `ObsvrConfig` or the legacy
 * snake_case `LLMAuditInitConfig`. Must be called before wrap().
 * Can be called multiple times but will warn on re-initialization.
 */
export function init(config: LLMAuditInitConfig | ObsvrConfig): void {
  if (state.initialized) {
    debugLog(
      state.config!,
      "warn",
      "obsvr.init() called multiple times - using latest config",
    );
  }

  const internal = isObsvrConfig(config) ? fromObsvrConfig(config) : config;
  const resolved = resolveConfig(internal);
  state.config = resolved;
  state.initialized = true;

  // Governance bypass is permitted but never silent: disabling obsvr in a
  // production environment logs a prominent warning and emits a single
  // governance_disabled audit event so the bypass itself is on the record.
  if (resolved.disabled && resolved.environment === "production") {
    console.warn(
      "[obsvr] WARNING: governance is DISABLED (disabled: true) in a production environment. " +
        "All LLM and tool calls will proceed unaudited and unenforced. " +
        "This bypass has been recorded in the audit trail.",
    );
    emitGovernanceDisabledEvent(resolved);
  }

  // failMode="closed" expresses "never fail open", but the SDK kill switch
  // (project paused / key revoked) and staleness enforcement both require the
  // /policies poll to run. With polling disabled the degraded gate can never
  // trip, so the posture is effectively fail-OPEN — warn loudly so it is not a
  // silent contradiction of the operator's intent.
  if (
    resolved.failMode === "closed" &&
    (resolved.policyRefreshIntervalMs ?? 30_000) <= 0 &&
    !resolved.disabled
  ) {
    console.warn(
      "[obsvr] WARNING: failMode is 'closed' but policy polling is disabled " +
        "(policyRefreshIntervalMs <= 0). The SDK kill switch and staleness " +
        "enforcement require polling — with it off they cannot trip, so calls " +
        "will NOT fail closed on a paused project / revoked key / stale sync. " +
        "Enable polling for a working fail-closed posture.",
    );
  }

  if (resolved.policyRules && resolved.policyRules.length > 0) {
    snapshotPolicy(resolved.policyRules);
  }

  debugLog(
    resolved,
    "info",
    "obsvr initialized",
    `environment=${resolved.environment}, sample_rate=${resolved.sample_rate}`,
  );
}

/**
 * Emit a single governance_disabled audit event when the SDK is initialized
 * with `disabled: true` in production. Uses a dynamic import to avoid a
 * static config → sender → config cycle. Fire-and-forget: never blocks init.
 */
function emitGovernanceDisabledEvent(resolved: ResolvedConfig): void {
  import("./sender/index.js")
    .then(async ({ sendAuditAsync }) => {
      const { derivePolicyVersion } = await import("../policy/rules.js");
      const event: Partial<AuditEvent> = {
        request_id: `governance-disabled-${Date.now()}`,
        environment: resolved.environment,
        region: resolved.default_region ?? "unknown",
        provider: "unknown",
        model: "none",
        operation: "governance.disabled",
        source: "obsvr_sdk",
        prompt: "",
        response: "",
        success: true,
        latency_ms: 0,
        event_type: "policy_flag",
        policy_version: derivePolicyVersion(resolved.policyRules ?? []),
        action_taken: "allowed",
        action_reason: "customer_override",
        action_source: "customer_hook",
        redacted_types: [],
        blocked_types: [],
        metadata: {
          governance_event: "governance_disabled",
          note: "SDK initialized with disabled:true in production - all subsequent calls unaudited",
        },
      };
      sendAuditAsync(resolved, event as AuditEvent);
    })
    .catch(() => {
      // Never let audit emission break init
    });
}

/**
 * Get the current configuration
 *
 * @throws Error if init() hasn't been called
 */
export function getConfig(): ResolvedConfig {
  if (!state.initialized || !state.config) {
    throw new Error(
      "obsvr: Call init() before using wrap() or other methods",
    );
  }
  return state.config;
}

/**
 * Check if the SDK has been initialized
 */
export function isInitialized(): boolean {
  return state.initialized;
}

/**
 * Check if a client has already been wrapped
 */
export function isWrapped(client: object): boolean {
  return state.wrappedClients.has(client);
}

/**
 * Mark a client as wrapped
 */
export function markWrapped(client: object): void {
  state.wrappedClients.add(client);
}

export function setTenantPolicy(tenantId: string, rules: PolicyRule[], changedBy?: string): void {
  const existing = tenantRegistry.get(tenantId);
  const prevRules = existing?.policyRules ?? [];
  tenantRegistry.set(tenantId, { policyRules: rules });
  snapshotPolicy(rules, tenantId);
  const event = emitPolicyChangedEvent(prevRules, rules, tenantId, changedBy);
  // actually record the change in the audit trail (was built + dropped).
  const cfg = state.config;
  if (cfg?.ingest_url) {
    void sendPolicyEvent(event, cfg.ingest_url, cfg.api_key);
  }
}

export function getTenantConfig(tenantId: string): ResolvedConfig {
  const base = getConfig();
  const override = tenantRegistry.get(tenantId);
  if (!override) return base;
  return { ...base, policyRules: override.policyRules ?? base.policyRules };
}

/**
 * Mutate the in-memory policy rules and snapshot them for audit.
 */
export function updatePolicyRules(rules: PolicyRule[]): void {
  if (state.config) {
    state.config.policyRules = rules;
    snapshotPolicy(rules);
  }
}

const VALID_RULE_ACTIONS = new Set(["block", "redact", "flag"]);
// "pii" is intentionally valid (authored + hashed into policy_version) though it
// has no rules-engine branch — PII is enforced by the builtin scanner (policy/hook.ts).
// It is also referenced by the shared cross-language conformance fixtures; removing
// it would break rules_hash parity in both the TS and Python SDKs.
/** The rule types this SDK build can validate and enforce. Exported so the
 * reason-code staleness check can assert every enforceable type has an
 * explicit ReasonCode mapping (a new type with no code fails CI). */
export const VALID_RULE_TYPES = new Set([
  "keyword", "regex", "topic_deny", "topic_allow", "pii",
  "action_gate", "namespace_isolation", "cross_tenant_block",
  "destructive_op_gate", "source_grounding", "environment_gate",
  "quota", "model_gate",
]);

/**
 * Capability descriptor sent on every /policies poll: the rule types
 * this SDK build can enforce plus feature markers. The dashboard warns
 * when a saved rule's type is outside a connected client's capabilities,
 * which kills the silently-unenforced-rule bug class (a rule this SDK
 * cannot validate is discarded, and without this signal nobody knows).
 */
export const SDK_CAPABILITIES: string = [
  ...Array.from(VALID_RULE_TYPES).sort(),
  "shadow_mode",
  "approval_pinning",
  "rules_hash",
  // Signals the allocator that this instance honors escrow-share grants
  // (quota_escrow on /policies) so a fleet-wide quota can be enforced
  // without per-call network latency (ADR-7).
  "quota_escrow",
  // Signals this instance can consult an inbound external policy backend
  // (OPA/Cedar), merged DENY-WINS with local rules (ADR-4).
  "external_policy_backend",
].join(",");

/**
 * Validate that a server-fetched object has the minimum required PolicyRule fields.
 * Prevents malformed or pathological rules from being applied.
 * Regex rules additionally pass through the ReDoS pattern validator so a
 * catastrophic-backtracking pattern can never be installed from the server.
 */
export function isValidPolicyRule(rule: unknown): rule is PolicyRule {
  if (!rule || typeof rule !== "object") return false;
  const r = rule as Record<string, unknown>;
  const structureOk =
    typeof r.id === "string" &&
    r.id.length > 0 &&
    typeof r.name === "string" &&
    typeof r.enabled === "boolean" &&
    VALID_RULE_ACTIONS.has(r.action as string) &&
    VALID_RULE_TYPES.has(r.type as string) &&
    typeof r.conditions === "object" &&
    r.conditions !== null;
  if (!structureOk) return false;

  // mode is optional; when present it must be a known value. A typo'd
  // mode must invalidate the rule (EV-12), never silently ENFORCE a rule
  // the author meant to shadow.
  if (r.mode !== undefined && r.mode !== "enforce" && r.mode !== "shadow") return false;

  if (r.type === "regex") {
    const pattern = (r.conditions as Record<string, unknown>).pattern;
    if (typeof pattern !== "string") return false;
    const verdict = validateRegexPattern(pattern);
    if (!verdict.ok) return false;
  }
  return true;
}

// ── Remote policy sync health ────────────────────────────────────────────────
// Tracks whether the SDK's view of server-side policy is fresh. Powers two
// guarantees: failMode="closed" blocks calls when policy sync goes stale, and
// a revoked/paused API key (401/403 from /policies) blocks calls even before
// ingest rejects the events (SDK-side kill switch).
const policySync = {
  startedAt: null as number | null,
  lastSuccessAt: null as number | null,
  consecutiveFailures: 0,
  /** Set when /policies returns 401/403: key revoked or project paused. */
  remoteDisabled: false,
  /** Sorted ids of validator-rejected rules from the last poll; the
   * rejected-rule audit signal fires once per distinct set. */
  lastRejectedRulesSignature: "",
  /** B2: false when the last signed /policies response failed verification
   * (policyPublicKey pinned). The fetched policy was NOT applied; last-good
   * stays in force. The signature-failure audit signal fires once per set. */
  policySignatureValid: true,
  lastPolicySignatureFailure: "",
  /** issued_at of the last successfully-verified policy (anti-rollback). */
  lastAppliedPolicyIssuedAt: undefined as string | undefined,
};

/** @internal exposed for tests */
export function _getPolicySyncState(): typeof policySync {
  return policySync;
}

/**
 * Validate and narrow the `quota_escrow` field of a /policies response into a
 * `{ [rule_id]: { share, epoch } }` map (ADR-7). Entries whose share is not a
 * finite non-negative number, or whose epoch is not a finite number, are
 * dropped rather than trusted — the SDK never fabricates or over-trusts share
 * (the share is floored to an integer when the grant is applied). Returns
 * undefined when the field is absent or not an object, which clears escrow
 * (fall back to per-process).
 */
function parseEscrowMap(raw: unknown): Record<string, EscrowShare> | undefined {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const out: Record<string, EscrowShare> = {};
  for (const [ruleId, v] of Object.entries(raw as Record<string, unknown>)) {
    if (!v || typeof v !== "object") continue;
    const share = (v as { share?: unknown }).share;
    const epoch = (v as { epoch?: unknown }).epoch;
    if (
      typeof share === "number" && Number.isFinite(share) && share >= 0 &&
      typeof epoch === "number" && Number.isFinite(epoch)
    ) {
      out[ruleId] = { share, epoch };
    }
  }
  return out;
}

/**
 * Whether policy enforcement can currently be trusted.
 * - remoteDisabled (key revoked / project paused) always degrades, regardless
 *   of failMode: the server has withdrawn authorization.
 * - With failMode="closed" and polling enabled, a sync gap longer than the
 *   staleness budget (default 3x refresh interval, min 90s) degrades, because
 *   the SDK can no longer prove it is enforcing current policy.
 * With failMode="open" (default) stale sync never blocks calls.
 */
export function isPolicyEnforcementDegraded(
  config: ResolvedConfig,
): { degraded: boolean; reason?: string } {
  if (policySync.remoteDisabled) {
    return { degraded: true, reason: "project_paused_or_key_revoked" };
  }
  if (config.failMode !== "closed") return { degraded: false };
  const intervalMs = config.policyRefreshIntervalMs ?? 30_000;
  if (intervalMs <= 0) return { degraded: false }; // polling disabled: local rules only
  const budget = config.policyStalenessBudgetMs ?? Math.max(3 * intervalMs, 90_000);
  const now = Date.now();
  const reference = policySync.lastSuccessAt ?? policySync.startedAt;
  if (reference === null) return { degraded: false }; // polling not started yet
  if (now - reference > budget) {
    return {
      degraded: true,
      reason: policySync.lastSuccessAt === null ? "policy_sync_never_succeeded" : "policy_sync_stale",
    };
  }
  return { degraded: false };
}

/**
 * One policy refresh from the ingest service. Updates sync-health state:
 * success resets failures and clears remoteDisabled; 401/403 sets
 * remoteDisabled (kill switch); other failures count toward staleness.
 */
async function pollPoliciesOnce(config: ResolvedConfig): Promise<void> {
  // M-4: AbortController timeout prevents a hung endpoint from blocking indefinitely
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), config.timeout);
  if (typeof timeoutId === "object" && (timeoutId as any).unref) (timeoutId as any).unref();
  try {
    // Fleet status (E10/E11/E33): every poll self-reports what this client
    // IS (version, capabilities), what it is ENFORCING (applied rules hash,
    // degraded flag), and its delivery counters. Ingest coalesces these
    // into the per-key registry the fleet view and coverage report read.
    // Dynamic import: config -> sender must not be a static edge (cycle).
    const degradedNow = isPolicyEnforcementDegraded(config);
    let countersHeader = "";
    try {
      const { getSenderStats } = await import("./sender/index.js");
      const s = getSenderStats();
      const dropped = s.dropped_overflow + s.dropped_permanent + s.dropped_retry_exhausted;
      countersHeader = `enqueued=${s.enqueued},sent=${s.sent},retries=${s.retries},dropped=${dropped}`;
    } catch {
      // stats unavailable: send the poll anyway
    }
    // Escrow report (ADR-7): how much of each rule's granted share this
    // instance spent since the last grant, tagged with the epoch it was
    // granted under (a stale report against an old epoch is ignored by the
    // allocator). Snapshotted BEFORE applying this poll's response, because a
    // fresh grant resets the per-epoch consumption counter. Header only when
    // an escrow grant is in effect — backward compatible otherwise.
    let quotaConsumedHeader = "";
    try {
      const consumed = snapshotConsumption();
      if (Object.keys(consumed).length > 0) {
        quotaConsumedHeader = JSON.stringify(consumed);
      }
    } catch {
      // consumption unavailable: send the poll anyway
    }
    const resp = await fetch(`${config.ingest_url}/policies`, {
      headers: {
        "X-API-Key": config.api_key,
        "X-Obsvr-Sdk": `node/${SDK_VERSION}`,
        "X-Obsvr-Instance-Id": SDK_INSTANCE_ID,
        "X-Obsvr-Capabilities": SDK_CAPABILITIES,
        "X-Obsvr-Rules-Hash": derivePolicyVersion(config.policyRules ?? []),
        "X-Obsvr-Degraded": String(degradedNow.degraded),
        ...(countersHeader ? { "X-Obsvr-Counters": countersHeader } : {}),
        ...(quotaConsumedHeader ? { "X-Obsvr-Quota-Consumed": quotaConsumedHeader } : {}),
      },
      signal: controller.signal,
    });
    clearTimeout(timeoutId);
    if (resp.status === 401 || resp.status === 403) {
      if (!policySync.remoteDisabled) {
        debugLog(config, "warn", `Policy poll: ${resp.status} - API key revoked or project paused; blocking governed calls`);
      }
      policySync.remoteDisabled = true;
      policySync.consecutiveFailures += 1;
      return;
    }
    if (!resp.ok) {
      policySync.consecutiveFailures += 1;
      debugLog(config, "warn", `Policy poll failed: ${resp.status}`);
      return;
    }
    const data = (await resp.json()) as unknown;
    // M-4: Validate top-level response shape
    if (!data || typeof data !== "object" || !("rules" in data) || !Array.isArray((data as Record<string, unknown>).rules)) {
      policySync.consecutiveFailures += 1;
      debugLog(config, "warn", "Policy poll: unexpected response shape, skipping update");
      return;
    }
    const rulesArr = (data as { rules: unknown[] }).rules;
    const validRules = rulesArr.filter(isValidPolicyRule) as PolicyRule[];
    if (validRules.length !== rulesArr.length) {
      // Rejected-rule signal (EV-12): a rule the validator discards is
      // silently UNENFORCED, which is the worst failure mode a governance
      // SDK can have. Name the rule ids loudly and put one policy_flag
      // event on the audit record per distinct rejected set (not per
      // poll), so the dashboard shows it even if nobody reads logs.
      const rejectedIds = rulesArr
        .filter((r) => !isValidPolicyRule(r))
        .map((r) =>
          r && typeof r === "object" && typeof (r as { id?: unknown }).id === "string"
            ? ((r as { id: string }).id)
            : "(missing id)",
        );
      debugLog(
        config,
        "warn",
        `Policy poll: ${rejectedIds.length} rule(s) REJECTED by the validator and NOT enforced: ${rejectedIds.join(", ")}`,
      );
      const signature = [...rejectedIds].sort().join("|");
      if (signature !== policySync.lastRejectedRulesSignature) {
        policySync.lastRejectedRulesSignature = signature;
        void import("./sender/index.js")
          .then(({ sendAuditAsync }) => {
            sendAuditAsync(config, {
              request_id: `rule-rejected-${Date.now()}`,
              environment: config.environment,
              region: config.default_region ?? "unknown",
              provider: "unknown",
              model: "none",
              operation: "policy.rule_rejected",
              source: "obsvr_sdk",
              prompt: "",
              response: "",
              success: true,
              latency_ms: 0,
              event_type: "policy_flag",
              policy_version: derivePolicyVersion(validRules),
              action_taken: "allowed",
              action_reason: "policy_violation",
              action_source: "builtin",
              rule_id: "sdk:rule_rejected",
              policy_reason: `Rules rejected by SDK validator (not enforced): ${rejectedIds.join(", ")}`.slice(0, 256),
              redacted_types: [],
              blocked_types: [],
            } as never);
          })
          .catch(() => { /* signal is best-effort */ });
      }
    } else {
      policySync.lastRejectedRulesSignature = "";
    }
    // B2: when a policy public key is pinned, verify the signature over the RAW
    // payload the server sent before applying anything. Fail closed — a
    // tampered, forged, unsigned, or rolled-back policy is NOT applied and the
    // last-good policy (already in config.policyRules) stays in force.
    if (config.policyPublicKey) {
      const sig = (data as { signature?: PolicySignature }).signature;
      const approvalsRaw = ((data as { approvals?: unknown[] }).approvals ?? []) as unknown[];
      const verdict = verifyPolicySignature(
        rulesArr,
        approvalsRaw,
        sig,
        config.policyPublicKey,
        policySync.lastAppliedPolicyIssuedAt,
      );
      if (!verdict.ok) {
        policySync.policySignatureValid = false;
        policySync.consecutiveFailures += 1;
        debugLog(config, "warn", `Policy signature verification FAILED — keeping last-good policy: ${verdict.reason}`);
        const failReason = verdict.reason ?? "unknown";
        if (failReason !== policySync.lastPolicySignatureFailure) {
          policySync.lastPolicySignatureFailure = failReason;
          void import("./sender/index.js")
            .then(({ sendAuditAsync }) => {
              sendAuditAsync(config, {
                request_id: `policy-sig-invalid-${Date.now()}`,
                environment: config.environment,
                region: config.default_region ?? "unknown",
                provider: "unknown",
                model: "none",
                operation: "policy.signature_invalid",
                source: "obsvr_sdk",
                prompt: "",
                response: "",
                success: true,
                latency_ms: 0,
                event_type: "policy_flag",
                policy_version: derivePolicyVersion(config.policyRules ?? []),
                action_taken: "allowed",
                action_reason: "policy_violation",
                action_source: "builtin",
                rule_id: "sdk:policy_signature_invalid",
                policy_reason: `Policy signature verification failed; kept last-good policy: ${failReason}`.slice(0, 256),
                redacted_types: [],
                blocked_types: [],
              } as never);
            })
            .catch(() => { /* signal is best-effort */ });
        }
        return; // do NOT apply the unverified policy
      }
      policySync.policySignatureValid = true;
      policySync.lastPolicySignatureFailure = "";
      if (sig) policySync.lastAppliedPolicyIssuedAt = sig.issued_at;
    }
    updatePolicyRules(validRules);
    // Approval grants ride along with the rules on the same poll
    const approvalsArr = (data as { approvals?: unknown[] }).approvals;
    if (Array.isArray(approvalsArr)) {
      updateApprovals(
        approvalsArr.filter(
          (a): a is ApprovalGrant =>
            !!a && typeof a === "object" &&
            typeof (a as ApprovalGrant).rule_id === "string" &&
            typeof (a as ApprovalGrant).expires_at === "string",
        ),
      );
    }
    // Fleet-quota escrow grants (ADR-7) ride along on the same poll. Apply
    // AFTER the consumption snapshot above so the just-reported grant's
    // consumption is not reset before it is reported. An absent field / absent
    // rule clears escrow for that rule (falls back to the per-process meter).
    applyEscrowResponse(parseEscrowMap((data as { quota_escrow?: unknown }).quota_escrow));
    policySync.lastSuccessAt = Date.now();
    policySync.consecutiveFailures = 0;
    if (policySync.remoteDisabled) {
      debugLog(config, "info", "Policy poll: authorization restored, resuming governed calls");
      policySync.remoteDisabled = false;
    }
  } catch {
    clearTimeout(timeoutId);
    policySync.consecutiveFailures += 1;
    // Network errors count toward staleness; failMode decides the consequence
  }
}

/**
 * Start a background polling loop that refreshes policy rules from the ingest service.
 * Fires an immediate first refresh (so failMode="closed" gets fresh policy at
 * startup, not one interval later), then repeats on an unref'd setInterval so
 * it does not prevent process exit.
 */
export function startPolicyPolling(config: ResolvedConfig): void {
  if (policyPollIntervalId !== null) {
    clearInterval(policyPollIntervalId);
  }
  const intervalMs = config.policyRefreshIntervalMs ?? 30_000;
  policySync.startedAt = Date.now();
  void pollPoliciesOnce(config);
  const id = setInterval(() => {
    void pollPoliciesOnce(config);
  }, intervalMs);
  if (typeof (id as any).unref === "function") {
    (id as any).unref();
  }
  policyPollIntervalId = id;
}

/**
 * Stop the policy polling loop (call in test teardown or graceful shutdown).
 */
export function stopPolicyPolling(): void {
  if (policyPollIntervalId !== null) {
    clearInterval(policyPollIntervalId);
    policyPollIntervalId = null;
  }
}

/**
 * Reset state (for testing only)
 * @internal
 */
export function _reset(): void {
  stopPolicyPolling();
  state.initialized = false;
  state.config = null;
  state.wrappedClients = new WeakSet();
  tenantRegistry.clear();
  policySync.startedAt = null;
  policySync.lastSuccessAt = null;
  policySync.consecutiveFailures = 0;
  policySync.remoteDisabled = false;
  applyEscrowResponse(undefined); // clear any fleet-quota escrow grants
  // Clear the process-global canary registry (parity with the Python
  // config._reset, which calls _reset_canaries) so a minted canary never
  // leaks across test boundaries and re-init starts clean.
  _resetCanaries();
  _resetSessionTaint();
}
