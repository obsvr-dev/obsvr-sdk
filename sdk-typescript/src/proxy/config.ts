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
import { derivePolicyVersion, ensureRuleResolution } from "../policy/rules.js";
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
 * The public camelCase key beside the internal name it maps to.
 *
 * ONE table, because the converter below and the mixed-spelling warning both
 * read it. Two hand-maintained lists would drift, and the failure mode of that
 * drift is a key silently dropped — the exact defect the warning exists to make
 * visible. Where a name is identical in both shapes it appears on both sides.
 */
const CONFIG_KEY_MAP: Record<string, string> = {
  apiKey: "api_key",
  ingestUrl: "ingest_url",
  environment: "environment",
  sampleRate: "sample_rate",
  debug: "debug",
  disabled: "disabled",
  streamingMode: "streaming_mode",
  onPreCall: "on_pre_call",
  hookTimeoutMs: "hook_timeout_ms",
  hookTrigger: "hook_trigger",
  failMode: "fail_mode",
  approvalWaitMs: "approval_wait_ms",
  approvalPollMs: "approval_poll_ms",
  enforcementMode: "enforcement_mode",
  requirePrincipal: "require_principal",
  ruleResolution: "rule_resolution",
  piiPolicy: "pii_policy",
  policyRules: "policy_rules",
  policyFloor: "policyFloor",
  onPostCall: "on_post_call",
  postCallTimeoutMs: "post_call_timeout_ms",
  agentPolicy: "agent_policy",
  providers: "providers",
  policyRefreshIntervalMs: "policy_refresh_interval_ms",
  policyStalenessBudgetMs: "policy_staleness_budget_ms",
  policyPublicKey: "policy_public_key",
  multiTurnInjection: "multi_turn_injection",
  sessionTaint: "sessionTaint",
  costPolicy: "costPolicy",
  deobfuscation: "deobfuscation",
  otel: "otel",
  meterIntegrationEvents: "meterIntegrationEvents",
  mcpToolPolicy: "mcpToolPolicy",
  presidioAnalyzerUrl: "presidio_analyzer_url",
  presidioAnonymizerUrl: "presidio_anonymizer_url",
  hardDeletion: "hardDeletion",
  environmentPolicies: "environmentPolicies",
  externalPolicyBackend: "external_policy_backend",
};

const CAMEL_KEYS = new Set(Object.keys(CONFIG_KEY_MAP));
const SNAKE_KEYS = new Set(Object.values(CONFIG_KEY_MAP));
/** Internal name -> public name, for naming the spelling a caller should use. */
const SNAKE_TO_CAMEL: Record<string, string> = Object.fromEntries(
  Object.entries(CONFIG_KEY_MAP).map(([camel, snake]) => [snake, camel]),
);

/**
 * Convert public camelCase ObsvrConfig to internal snake_case LLMAuditInitConfig
 */
function fromObsvrConfig(config: ObsvrConfig): LLMAuditInitConfig {
  const out: Record<string, unknown> = {};
  for (const [camel, snake] of Object.entries(CONFIG_KEY_MAP)) {
    out[snake] = (config as unknown as Record<string, unknown>)[camel];
  }
  // The table above IS the mapping, so the shape is correct by construction;
  // the compiler cannot see that through a keyed build. `api_key` is required
  // on the target and is asserted at resolveConfig, which validates it.
  return out as unknown as LLMAuditInitConfig;
}

/**
 * Detect whether a config object is in ObsvrConfig (camelCase) form.
 *
 * ONE key decides the convention for the WHOLE object, which is why the warning
 * below exists: a caller who writes `api_key` beside `piiPolicy` gets the
 * snake_case path, and `piiPolicy` is never read. Nothing failed, nothing was
 * logged, and the PII policy simply did not exist.
 */
function isObsvrConfig(
  config: LLMAuditInitConfig | ObsvrConfig,
): config is ObsvrConfig {
  return "apiKey" in config;
}

/**
 * Warn about keys the chosen naming convention will not read.
 *
 * Warn rather than reject, and warn rather than accept both spellings. Rejecting
 * turns a typo into an outage for a caller who was passing a harmless extra
 * field. Accepting both hides the mistake and leaves two conventions live
 * forever. Warning is visible, non-breaking, and names the key — and for a
 * misspelled key it names the spelling that WOULD have been read, because
 * "unknown key" tells a caller nothing they can act on.
 *
 * Deliberately not silent for a value of `undefined`: a key present and
 * explicitly undefined still signals intent, and the caller still wants to know
 * their spelling was ignored.
 */
function warnOnUnreadableConfigKeys(config: Record<string, unknown>, isCamel: boolean): void {
  const style = isCamel ? "camelCase" : "snake_case";
  const readable = isCamel ? CAMEL_KEYS : SNAKE_KEYS;
  const otherConvention = isCamel ? SNAKE_KEYS : CAMEL_KEYS;

  const wrongStyle: string[] = [];
  const unrecognised: string[] = [];
  for (const key of Object.keys(config)) {
    if (readable.has(key)) continue;
    if (otherConvention.has(key)) wrongStyle.push(key);
    else unrecognised.push(key);
  }

  if (wrongStyle.length > 0) {
    const fixes = wrongStyle
      .map((k) => `${k} -> ${isCamel ? SNAKE_TO_CAMEL[k] : CONFIG_KEY_MAP[k]}`)
      .join(", ");
    console.warn(
      `[obsvr] WARNING: init() read this config as ${style}, because ` +
        `${isCamel ? "`apiKey` is present" : "`apiKey` is absent"}. ` +
        `One key decides the convention for the whole object, so these keys ` +
        `were IGNORED and their settings are NOT in force: ${wrongStyle.join(", ")}. ` +
        `Rename them to match: ${fixes}. ` +
        `A policy passed under the unread spelling does not exist — a pii_policy ` +
        `dropped this way means no PII scanning at all, silently.`,
    );
  }
  if (unrecognised.length > 0) {
    console.warn(
      `[obsvr] WARNING: init() does not recognise these config keys and ignored ` +
        `them: ${unrecognised.join(", ")}. Check for a typo — obsvr reads ` +
        `${style} for this call.`,
    );
  }
}

/**
 * Loopback hosts exempt from the HTTPS requirement and from the private-range
 * half of the SSRF guard, for local development. Compared against the PARSED
 * hostname, never against a substring of the URL. Twin: `_LOCAL_HOSTNAMES` in
 * sdk-python/obsvr/config.py.
 */
const LOCAL_INGEST_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

/**
 * Validate `ingest_url` and return it with any trailing slash removed.
 *
 * This endpoint receives every prompt, every response and the `X-API-Key`
 * header, so it is the largest egress surface the SDK has — larger than the
 * external policy backend or the Presidio endpoints, both of which already run
 * this guard while this one ran none of it.
 *
 * Two checks, in order:
 *
 *  1. **The static SSRF guard**, at the same posture as the Presidio endpoints.
 *     The scheme must be http(s), so `file:`, `gopher:`, `ftp:` and everything
 *     else are refused rather than accepted — previously any non-`http` scheme
 *     was waved through, `file:///etc/passwd` included. A literal-IP host must
 *     not be a cloud-metadata / link-local address (ALWAYS refused, no opt-out,
 *     in all four IPv6 spellings) and must not be a private/reserved range
 *     unless the host is loopback.
 *  2. **TLS posture**: plaintext `http` off-loopback is refused.
 *
 * Loopback keeps working so local development and a local collector are
 * unaffected; the metadata address is refused there too, because it is refused
 * everywhere.
 *
 * Two limits, stated rather than implied. This is the STATIC guard, so a
 * HOSTNAME that resolves to a private or metadata address is not refused —
 * `init()` is synchronous and the resolving guard needs DNS, which is the same
 * limit the Presidio endpoints carry. And unlike the Python twin there is no
 * `OBSVR_ALLOW_HTTP` escape hatch here: this SDK reads no environment variable
 * anywhere in `src/`, and relaxing a transport check should not be the first
 * one. `SECURITY.md` scopes that opt-out to Python for this reason.
 *
 * Twin: `_validate_ingest_url` in sdk-python/obsvr/config.py.
 */
function validateIngestUrl(raw: string): string {
  const url = raw.replace(/\/$/, "");
  // Parse for the host first so the loopback exemption and the guard agree on
  // what the host is. An unparseable URL leaves it empty and the guard reports
  // it, rather than this throwing a second, worse-worded error for the same URL.
  let host = "";
  try {
    host = new URL(url).hostname.replace(/^\[|\]$/g, "").toLowerCase();
  } catch {
    /* reported by assertBackendUrlStatic below */
  }
  const isLocal = LOCAL_INGEST_HOSTS.has(host);

  let parsed: URL;
  try {
    parsed = assertBackendUrlStatic(url, { allowPrivateNetwork: isLocal });
  } catch (e) {
    throw new Error(
      `obsvr.init(): ingest_url failed the SSRF guard: ${e instanceof Error ? e.message : String(e)}`,
    );
  }

  if (parsed.protocol === "http:" && !isLocal) {
    throw new Error(
      `obsvr.init(): ingest_url "${url}" uses plaintext HTTP for a non-localhost URL. ` +
        "Use HTTPS to protect audit events in transit.",
    );
  }
  return url;
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
  if (
    config.approval_wait_ms !== undefined &&
    (typeof config.approval_wait_ms !== "number" || !Number.isFinite(config.approval_wait_ms) || config.approval_wait_ms < 0)
  ) {
    throw new Error(
      `obsvr.init(): approvalWaitMs must be a number of ms >= 0, got ${String(config.approval_wait_ms)}`,
    );
  }
  if (
    config.approval_poll_ms !== undefined &&
    (typeof config.approval_poll_ms !== "number" || !Number.isFinite(config.approval_poll_ms) || config.approval_poll_ms <= 0)
  ) {
    throw new Error(
      `obsvr.init(): approvalPollMs must be a positive number of ms, got ${String(config.approval_poll_ms)}`,
    );
  }
  // A typo'd mode must never silently monitor a deployment the operator
  // meant to enforce — the same reasoning the rule validator applies to a
  // rule-level mode.
  if (
    config.enforcement_mode !== undefined &&
    config.enforcement_mode !== "enforce" &&
    config.enforcement_mode !== "monitor"
  ) {
    throw new Error(
      `obsvr.init(): enforcementMode must be "enforce" or "monitor", got "${String(config.enforcement_mode)}"`,
    );
  }
  // A governance flag must be a real boolean: a truthy string like "false"
  // silently enabling (or a falsy 0 silently disabling) an attribution
  // requirement is exactly the misconfiguration strict init exists to catch.
  if (config.require_principal !== undefined && typeof config.require_principal !== "boolean") {
    throw new Error(
      `obsvr.init(): requirePrincipal must be a boolean, got ${String(config.require_principal)}`,
    );
  }
  if (config.rule_resolution !== undefined) {
    // The rules engine's own validator: an unknown declaration must refuse
    // loudly at init, never silently evaluate under semantics the author did
    // not choose.
    try {
      ensureRuleResolution(config.rule_resolution as string);
    } catch (err) {
      throw new Error(`obsvr.init(): ${(err as Error).message}`);
    }
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
  // here — but the cloud-metadata / link-local endpoint is ALWAYS refused, no
  // opt-out, closing the crown-jewel SSRF vector. "The IPv6 forms" is now four
  // forms rather than one: IPv4-mapped (`::ffff:`), IPv4-COMPATIBLE (`::`),
  // NAT64 (`64:ff9b::`) and 6to4 (`2002:`). Only the first was folded, so
  // `http://[::169.254.169.254]/` was ACCEPTED here and stored verbatim while
  // the `::ffff:` spelling of the same address was refused — the absolute held
  // for one spelling of it. Twin: sdk-python/obsvr/config.py.
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
      return validateIngestUrl(config.ingest_url);
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
    // Strictly opt-in: the default 0 keeps the fire-and-forget approval path.
    approvalWaitMs: config.approval_wait_ms ?? 0,
    approvalPollMs: config.approval_poll_ms ?? 5000,
    enforcementMode: config.enforcement_mode ?? 'enforce',
    requirePrincipal: config.require_principal === true,
    ruleResolution: config.rule_resolution as 'first_match' | 'deny_wins' | undefined,
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
    costPolicy: config.costPolicy,
    deobfuscation: config.deobfuscation,
    otel: config.otel,
    meterIntegrationEvents: config.meterIntegrationEvents,
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

  const isCamel = isObsvrConfig(config);
  warnOnUnreadableConfigKeys(config as unknown as Record<string, unknown>, isCamel);
  const internal = isCamel ? fromObsvrConfig(config) : config;
  const resolved = resolveConfig(internal);
  state.config = resolved;
  state.initialized = true;
  // What the caller declared in code, kept apart from what a poll delivers.
  // See LOCALLY-DECLARED RULES on updatePolicyRules.
  localPolicyRules = [...(resolved.policyRules ?? [])];

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
    snapshotPolicy(resolved.policyRules, undefined, resolved.ruleResolution);
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
        policy_version: derivePolicyVersion(resolved.policyRules ?? [], resolved.ruleResolution),
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
  snapshotPolicy(rules, tenantId, state.config?.ruleResolution);
  const event = emitPolicyChangedEvent(
    prevRules, rules, tenantId, changedBy, state.config?.ruleResolution,
  );
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
 * Rules the caller declared in code, captured at `init()`. Replaced only by
 * another `init()`; a poll can never remove one.
 */
let localPolicyRules: PolicyRule[] | null = null;
/** Rules from the last successful poll. Replaced wholesale, empty included. */
let serverPolicyRules: PolicyRule[] | null = null;

/**
 * Mutate the in-memory policy rules and snapshot them for audit.
 *
 * LOCALLY-DECLARED RULES SURVIVE A POLL. The two sources have separate
 * lifetimes: a poll owns the server set and may legitimately empty it, but it
 * never deletes a rule the caller passed to `init({ policyRules })`.
 *
 * Why, given that the wholesale replacement looks like the simpler contract: a
 * `200` carrying `{"rules":[]}` used to erase locally declared rules AND stamp
 * the sync as successful, so `failMode: "closed"` never tripped — a deployment
 * was silently disarmed by a response nobody ever sees, with nothing on the
 * record saying its rules had gone. `policyFloor` already survived a poll, so
 * local rules were the one tier a network response could delete, and making
 * the three tiers consistent is the smaller change: the floor always survives,
 * local survives a poll, the server set is the poll's to manage.
 *
 * A server rule carrying the id of a local one does NOT replace it — that is
 * the same disarming edit wearing a matching id, and letting it through would
 * reopen the hole for any deployment that has not pinned a policy key. The
 * collision is logged rather than absorbed silently.
 */
export function updatePolicyRules(rules: PolicyRule[]): void {
  if (!state.config) return;
  serverPolicyRules = rules;
  const local = localPolicyRules ?? [];
  const localIds = new Set(local.map((r) => r.id));
  const shadowed = rules.filter((r) => localIds.has(r.id));
  if (shadowed.length > 0) {
    debugLog(
      state.config,
      "warn",
      `Policy poll returned ${shadowed.length} rule(s) whose id is declared locally ` +
        `(${shadowed.map((r) => r.id).join(", ")}); the local declaration stands.`,
    );
  }
  const effective = [...local, ...rules.filter((r) => !localIds.has(r.id))];
  state.config.policyRules = effective;
  snapshotPolicy(effective, undefined, state.config.ruleResolution);
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
  "quota", "model_gate", "protocol_facet",
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
 * Rule-id namespaces the SDK mints for its OWN verdicts — `sdk:` for the
 * built-in governance layers (sdk:canary_leak, sdk:session_tainted,
 * sdk:multi_turn_injection, ...) and `backend:` for external-policy-backend
 * verdicts. Reserved: an operator- or server-supplied rule claiming either
 * prefix is invalid, because a forged `sdk:*` rule would be indistinguishable
 * from the SDK's own governance verdicts on the audit record. Pinned by the
 * `reserved_rule_id_rejected` case in conformance/fixtures/eval_semantics.json.
 */
export const RESERVED_RULE_ID_PREFIXES = ["sdk:", "backend:"] as const;

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

  // A rule cannot claim the SDK's own verdict namespace (see
  // RESERVED_RULE_ID_PREFIXES above).
  if (RESERVED_RULE_ID_PREFIXES.some((p) => (r.id as string).startsWith(p))) return false;

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
 *
 * Exported for the blocking approval wait (policy/approvals.ts
 * `awaitApproval`), which re-drives this same refresh so a pinned
 * deployment's signature verification and the grant-shape validation both
 * still stand between the network and the grant store during a wait.
 */
export async function pollPoliciesOnce(config: ResolvedConfig): Promise<void> {
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
      // `dropped` aggregates the never-delivered buckets; server-refused
      // events ride their own key so the fleet view can tell "we never got
      // it" apart from "we got it and said no".
      const dropped = s.dropped_overflow + s.dropped_permanent + s.dropped_retry_exhausted;
      const { getDetectorErrorCount } = await import("../policy/detector-guard.js");
      countersHeader =
        `enqueued=${s.enqueued},sent=${s.sent},retries=${s.retries},dropped=${dropped}` +
        `,dropped_rejected=${s.dropped_rejected}` +
        // Enforcement loss, not delivery loss: a detector layer that raised
        // and was resolved by the guard. Its own key for the same reason
        // dropped_rejected has one - these are different operational stories,
        // and folding them together would report a lost control as a lost
        // event. Same key name and order as the Python poll.
        `,detector_errors=${getDetectorErrorCount()}`;
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
        "X-Obsvr-Rules-Hash": derivePolicyVersion(config.policyRules ?? [], config.ruleResolution),
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
              policy_version: derivePolicyVersion(validRules, config.ruleResolution),
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
                policy_version: derivePolicyVersion(config.policyRules ?? [], config.ruleResolution),
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
            typeof (a as ApprovalGrant).expires_at === "string" &&
            // A string is not a date. Accepting one that `Date.parse` cannot
            // read let any /policies response mint a grant that never expires —
            // and nothing authenticates that response at all unless a policy
            // key is pinned. Refused at the door as well as at the gate.
            Number.isFinite(Date.parse((a as ApprovalGrant).expires_at)),
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
  localPolicyRules = null;
  serverPolicyRules = null;
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
