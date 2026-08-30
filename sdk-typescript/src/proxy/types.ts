/**
 * Proxy SDK Types
 *
 * Types for the transparent proxy wrapper that intercepts LLM API calls.
 *
 * @packageDocumentation
 */

import type { PolicyHook, PostCallHook } from '../policy/hook.js';
import type { PolicyRule } from '../policy/rules.js';
import type { ExternalPolicyBackendConfig, ExternalBackendRecord } from '../policy/external-backend.js';
import type { CostPolicyConfig } from '../governance/cost.js';
import type { StrictProviderBoundaryV21Capability } from '../governance/strict-provider-boundary-v2-1.js';

// Re-export PolicyHook so callers only need one import
export type { PolicyHook, PolicyDecision, PostCallHook } from '../policy/hook.js';
export type { PolicyRule } from '../policy/rules.js';
export type { ExternalPolicyBackendConfig, ExternalBackendRecord } from '../policy/external-backend.js';

/**
 * Run-level agent policy enforced across an entire agentic execution.
 * Applied on top of call-level policies - existing per-call policies are unchanged.
 */
export interface AgentPolicy {
  /** Tools this agent is allowed to call. Omit to allow all. */
  allowedTools?: string[];
  /** Tools this agent is explicitly denied from calling. */
  deniedTools?: string[];
  /** If false, block the run when PII is detected in any step. @default true */
  allowPiiAccess?: boolean;
  /** Maximum number of tool calls before block or escalation. Omit for unlimited. */
  maxSteps?: number;
  /** Action when step limit is reached. @default "block" */
  stepLimitAction?: "block" | "escalate";
  /** Restrictions on the final run output. */
  outputPolicy?: { deniedTopics?: string[] };
  /** Loop detection: block or escalate when an agent iterates excessively. */
  loopDetection?: { maxIterations: number; windowMs: number; action: 'block' | 'escalate' };
  /** Delegation policy: restrict agent-to-agent delegation depth and circularity. */
  delegationPolicy?: { maxDepth: number; allowedDelegates?: string[]; blockCircular: boolean };
  /** Namespace for cross-tenant isolation (e.g. "tenant-a"). */
  namespace?: string;
}

/**
 * Public customer-facing configuration (camelCase).
 *
 * Use with `defineConfig()` in your `obsvr.config.ts`:
 * ```ts
 * import { defineConfig } from '@obsvr/sdk';
 * export default defineConfig({
 *   apiKey:    process.env.OBSVR_API_KEY!,
 *   ingestUrl: 'https://ingest.obsvr.co',
 *   providers: ['openai', 'anthropic'],
 * });
 * ```
 */
export interface ObsvrConfig {
  /** API key for authentication with the audit service. */
  apiKey: string;

  /** URL of the ingest service. @default DEFAULT_INGEST_URL */
  ingestUrl?: string;

  /**
   * Optional disk-backed audit outbox. Each signed event is atomically stored
   * before enqueue returns, replayed on restart, and removed only after ingest
   * confirms delivery. Use a directory private to one application deployment.
   */
  durableDelivery?: {
    directory: string;
    /** Maximum bytes retained across pending and dead-letter records. @default 67108864 */
    maxBytes?: number;
    /** fsync event files and directory renames before returning. @default true */
    fsync?: boolean;
    /** Throw when durability cannot be established; otherwise warn and use memory delivery. @default "error" */
    failureMode?: 'error' | 'warn';
  };

  /** Environment identifier. @default "development" */
  environment?: 'development' | 'staging' | 'production';

  /**
   * Narrows which providers the module interceptor governs when the app is
   * started with `node --import @obsvr/sdk/register`. Omit or leave empty to
   * govern all supported providers. Has no effect without the interceptor;
   * init() never patches provider SDKs.
   */
  providers?: ('openai' | 'anthropic' | 'google')[];

  /**
   * Emission rate for ALLOWED-call audit events (0–1). Enforcement is NOT
   * sampled — PII/policy/hook/kill-switch checks run on every call regardless,
   * and blocked/redacted/error events are always emitted. Lowering this reduces
   * ingest volume, not the per-call enforcement cost. @default 1.0
   */
  sampleRate?: number;

  /** Enable debug logging. @default false */
  debug?: boolean;

  /** Disable auditing entirely (passthrough mode). @default false */
  disabled?: boolean;

  /** How to handle streaming responses. @default "wrap" */
  streamingMode?: 'wrap' | 'skip';

  /**
   * Pre-call policy hook.
   * Called before every LLM call with a partial audit event.
   * Return 'block' to throw, 'redact' to strip content, 'allow' to proceed.
   */
  onPreCall?: PolicyHook;

  /** Timeout (ms) for onPreCall hook. @default 2000 */
  hookTimeoutMs?: number;

  /** When the pre-call hook should fire: always, only on PII, or only on block. @default 'always' */
  hookTrigger?: 'always' | 'on_pii' | 'on_block';

  /**
   * Enforcement fail mode when the pre-call hook times out or throws.
   * - 'open'   : proceed with the call (default - audit-friendly, never breaks the app)
   * - 'closed' : block the call (governance-friendly - a hook that can't render a
   *              verdict must not be treated as approval)
   * Use 'closed' for policies that must genuinely gate execution.
   * @default 'open'
   */
  failMode?: 'open' | 'closed';

  /**
   * Blocking human approval. When > 0, a require_approval block HOLDS the
   * governed call for up to this many milliseconds while the grant channel
   * is polled, and proceeds only if a covering grant lands and is still live
   * when the call goes out. 0 (default) keeps the fire-and-forget behavior:
   * the call is refused, an approval request is filed, and a retry passes
   * once granted. Strictly opt-in — a library that starts blocking for
   * minutes on upgrade is a production incident.
   * @default 0
   */
  approvalWaitMs?: number;

  /**
   * Grant-channel poll cadence (ms) while an approval wait is in progress.
   * Each poll re-drives the /policies refresh (signature verification and
   * grant-shape validation included), so keep it coarse: this is a
   * human-timescale wait, not a busy loop.
   * @default 5000
   */
  approvalPollMs?: number;

  /**
   * Global enforcement mode. "enforce" (default) applies blocks. "monitor"
   * evaluates every layer, emits every event, and converts a final block
   * into an allow whose `shadow_outcome` carries the would-be verdict — one
   * flip for a staged rollout or rollback that keeps the evidence stream
   * intact. The enforcement-integrity gate (kill switch / fail-closed
   * staleness) is never converted: monitor mode must not become a way to
   * defeat a revoked key.
   * @default "enforce"
   */
  enforcementMode?: 'enforce' | 'monitor';

  /**
   * Refuse an unattributed call (opt-in). When true, a governed call whose
   * enforcing channel carries no non-blank user_id is blocked with
   * PRINCIPAL_REQUIRED before any scanning layer runs. Empty and whitespace-
   * only strings are unattributed. Default false: a
   * single-tenant deployment that legitimately passes no user_id must not
   * start refusing on upgrade.
   * @default false
   */
  requirePrincipal?: boolean;

  /**
   * Refuse a `wrap()` that governs nothing (opt-in). When true, wrapping a
   * client on which no auditable method path resolves throws instead of
   * returning a proxy that will never emit an event. Default false, and the
   * default still WARNS — see {@link wrap}. A deployment that treats coverage
   * as a deploy-time invariant sets this so the process refuses to start
   * rather than running ungoverned.
   * @default false
   */
  requireGovernedSurface?: boolean;

  /**
   * Declared conflict-resolution mode for the policy rules. Undefined (the
   * default) is undeclared: the original first-match contract AND the
   * original policy_version bytes are kept. Declaring a mode opts the
   * deployment into that mode's evaluation semantics and the
   * order-committed policy_version that makes them auditable; an unknown
   * value is refused at init.
   */
  ruleResolution?: 'first_match' | 'deny_wins';

  /**
   * Optional client-held device signing identity (Ed25519): path to an
   * operator-generated private key (PKCS8 PEM, or a raw 32-byte seed as
   * hex/base64). When set, every signed event ALSO carries `device_sig` /
   * `device_key_id` over the same payload the HMAC signs — non-repudiation
   * against everyone who does not hold this key, with the HMAC chain
   * untouched. The SDK NEVER generates this key; a configured key that
   * cannot sign refuses at init. See proxy/device-identity.ts.
   */
  deviceSigningKeyFile?: string;

  /**
   * Built-in PII scan policy (opt-in).
   * Runs before the LLM call using the built-in pattern set (PII,
   * secrets, and prompt-injection detectors; see policy/hook.ts).
   * - default: fallback action for types not listed in rules
   * - rules: per-type overrides (e.g. { ssn: "block", email: "redact" })
   * If omitted entirely, no PII scan runs.
   * If provided with no rules/default, built-in severity defaults apply
   * (see BUILTIN_SEVERITY in policy/pii-types.ts): secrets, ssn,
   * credit_card, ip_address, and prompt_injection block; email/phone
   * redact; uuid detect_only.
   */
  piiPolicy?: {
    default?: "block" | "redact" | "detect_only";
    rules?: Partial<Record<string, "block" | "redact" | "detect_only">>;
  };

  /** Structured policy rules evaluated before the customer hook */
  policyRules?: PolicyRule[];

  /**
   * Anti-tamper policy FLOOR: rules that cannot be silently disabled or
   * downgraded. A floor rule always enforces (shadow/enabled:false on it is
   * ignored), the customer hook can never un-block it, and because the floor
   * lives in its OWN field a remote /policies sync (which replaces only
   * policyRules) can never delete it. When the hook attempts to override a
   * floor block, the audit event records `floor_override_ignored`. Off by
   * default (empty).
   */
  policyFloor?: PolicyRule[];

  /** Post-call hook for response scanning */
  onPostCall?: PostCallHook;

  /** Timeout (ms) for onPostCall hook. @default 2000 */
  postCallTimeoutMs?: number;

  /** Interval (ms) to poll `/policies` endpoint for rule updates. @default 30000 */
  policyRefreshIntervalMs?: number;

  /**
   * With failMode "closed": maximum age (ms) of the last successful policy
   * sync before governed calls are blocked. @default max(3x refresh, 90000)
   */
  policyStalenessBudgetMs?: number;

  /**
   * Base64 raw 32-byte Ed25519 public key to pin for policy-signature
   * verification. When set, the SDK REQUIRES a valid signature on every
   * /policies response and fails closed (keeps last-good policy) otherwise.
   */
  policyPublicKey?: string;

  /**
   * Multi-turn injection scoring: accumulates weak injection signals per
   * end-user session with temporal decay, catching payloads split across
   * turns. Off by default.
   */
  multiTurnInjection?: {
    enabled?: boolean;
    /** Decayed score that trips the gate. @default 1.0 */
    threshold?: number;
    /** Score half-life in ms. @default 600000 */
    halfLifeMs?: number;
    /** @default "block" */
    action?: "block" | "flag";
  };

  /**
   * Session taint latch: once a prompt-injection or canary leak is detected in
   * a session, the session's subsequent EGRESS (tool calls, tool args, MCP
   * calls) is escalated. Keyed on `metadata.user_id ?? session_id ??
   * tenant_id` (thread a session id or everything shares one "global" bucket).
   * `action` defaults to "flag" (annotate, don't block) so one detection never
   * bricks a session; "block" refuses tainted egress. Off by default.
   */
  sessionTaint?: {
    enabled?: boolean;
    /** @default "flag" */
    action?: "block" | "flag";
    /** Destructive-capability set: EXACT tool names a TAINTED session may
     * never invoke, even under the default "flag" action. Unioned with the
     * tools whose own MCP descriptor declares `destructiveHint: true`, so a
     * deployment that configures nothing still gets a capability gate. */
    destructiveTools?: string[];
    /** Whether a tool descriptor's own `destructiveHint` may add that tool to
     * the destructive set. The hint can only ever ADD - a server can never
     * remove a tool from the set by describing itself as harmless - so turning
     * this off never tightens anything; it restricts the set to
     * `destructiveTools` alone. @default true */
    honorDestructiveHints?: boolean;
  };

  /**
   * Layered call cost. Three layers, each overriding the one before it and all
   * three RETAINED on the record: what the caller said a call would cost, what
   * you declare it costs (which overrides the caller, since the caller is the
   * party being governed), and what it actually cost — provider-reported usage
   * priced at YOUR rates. The gap between the estimate and the metered figure
   * is the auditable quantity: an estimator that is persistently wrong is only
   * visible if both numbers survive.
   *
   * No provider price list ships in this package. Prices change on the
   * vendor's schedule, and a stale rate baked into a release produces a SEALED
   * wrong number, which is worse than none because sealed evidence cannot be
   * reissued. Declare your own rates here.
   *
   * Every amount is an INTEGER count of millionths of a currency unit, because
   * money in binary floating point does not agree between two runtimes at the
   * edges. Off by default; resolving costs nothing when unset.
   */
  costPolicy?: CostPolicyConfig;

  /**
   * De-obfuscation scan views (server-side normalizer mirror): when enabled, the builtin
   * scanners also see base64/hex/percent-decoded and invisible-stripped /
   * confusable-folded / HTML-comment-stripped views of the text, so encoded
   * or hidden payloads cannot dodge detection. Detection-only (views never
   * feed span redaction); bounded (64 KiB input, ≤6 views, decode depth 1).
   *
   * Enforcement semantics for a hit found ONLY in a view (`via` present —
   * the raw text is clean, so there is no locatable span to redact):
   * - pre-delivery paths escalate a `redact` resolution to `block` rather
   *   than emit a false "redacted" record while the payload flows through;
   * - stored copies (blocked-event prompt, post-call stored response) become
   *   a whole-text `[REDACTED:obfuscated]` placeholder;
   * - events carry the view that defeated the obfuscation
   *   (`security_normalized` / `response_pii_via`).
   *
   * Off by default: enabling can turn previously-allowed calls into blocks
   * under a block- or redact-mode policy.
   */
  deobfuscation?: { enabled?: boolean };

  /**
   * Mirror audit events as OpenTelemetry spans (requires @opentelemetry/api,
   * an optional peer - never a hard dependency). Off by default.
   */
  otel?: { enabled?: boolean; tracerName?: string };
  /**
   * Meter framework-integration events for cost and token quota. Default
   * **false**.
   *
   * Framework-integration events (LangChain, LlamaIndex, Vercel AI, the agent
   * frameworks) are **UNMETERED UNLESS THIS IS SET**: they carry no cost
   * fragment and never increment a token-unit quota. Only the `wrap()`
   * client-proxy path is metered by default, and it is metered either way —
   * this flag does not affect it.
   *
   * The default is off because turning it on is not a neutral correction. A
   * `quota_unit: "tokens"` budget that has never bound on framework traffic
   * begins binding, and calls that previously succeeded start being blocked
   * once the budget is reached. For someone already running a token quota that
   * is an outage, not a fix, so it has to be a deliberate choice.
   *
   * One flag covers BOTH cost and quota rather than two, because the two only
   * make sense together: metering what a call cost without counting it against
   * the budget it belongs to produces an audit record that disagrees with
   * itself, and a governance record that contradicts itself is worse than one
   * that is silent.
   *
   * With no `costPolicy` and no token-unit quota rule configured, enabling this
   * changes nothing — both halves are independently configured and the flag
   * only removes the path-level block.
   */
  meterIntegrationEvents?: boolean;

  /** Run-level agent policy for agentic frameworks (CrewAI, AutoGen, LangChain agents). */
  agentPolicy?: AgentPolicy;

  /**
   * MCP tool-level policy: allowlist/denylist of tool names, poisoned-tool
   * stripping, and descriptor content-hash pinning (rug-pull defense).
   * `pinning`: hash each tool descriptor at tools/list (canonical projection,
   * full SHA-256); `pins` are operator-declared name->hash pins (authoritative,
   * survive restarts), otherwise first-seen hashes are TOFU-recorded for the
   * governed client's lifetime and NEVER silently re-pinned. On a mismatch:
   * mode "warn" (default) flags the violation on signed events; mode "block"
   * strips the tool at discovery and refuses calls to it. `requirePin` treats
   * tools without any pin as violations. Off by default.
   */
  mcpToolPolicy?: {
    allowedTools?: string[];
    deniedTools?: string[];
    blockPoisonedTools?: boolean;
    pinning?: {
      enabled?: boolean;
      mode?: "warn" | "block";
      pins?: Record<string, string>;
      requirePin?: boolean;
    };
  };

  /** Presidio Analyzer URL (e.g. http://localhost:5002). Enables NLP PII detection. */
  presidioAnalyzerUrl?: string;
  /** Presidio Anonymizer URL (e.g. http://localhost:5001). Required when presidioAnalyzerUrl is set. */
  presidioAnonymizerUrl?: string;

  /** Hard deletion config: issue DELETE to ingest endpoint on demand. */
  hardDeletion?: { enabled: boolean; endpoint?: string };
  /** Per-environment policy overrides merged into the active config at resolution time. */
  environmentPolicies?: Record<string, { policyRules?: PolicyRule[]; agentPolicy?: AgentPolicy }>;

  /**
   * Inbound external policy backend (OPA or Cedar). When configured, the
   * backend's verdict participates in every pre-call decision, merged
   * DENY-WINS with the local rules (a deny from either side blocks). A backend
   * error or timeout is treated as DENY (fail-closed); set `shadow: true` for
   * an observe-only rollout that never blocks. The backend URL is SSRF-guarded.
   * Omit for the zero-config default (no backend, unchanged behavior).
   */
  externalPolicyBackend?: ExternalPolicyBackendConfig;
}

/**
 * Legacy snake_case init config.
 * @deprecated Use the camelCase {@link ObsvrConfig} shape instead. Still
 * accepted by `obsvr.init()` for backward compatibility.
 */
export interface LLMAuditInitConfig {
  /**
   * API key for authentication with the audit service
   * Required - obtain from your LLM Audit dashboard
   */
  api_key: string;

  /**
   * Environment identifier
   * @default "development"
   */
  environment?: "development" | "staging" | "production";

  /**
   * URL of the ingest service
   * @default DEFAULT_INGEST_URL
   */
  ingest_url?: string;

  /** Disk-backed delivery outbox (snake_case alias). */
  durable_delivery?: {
    directory: string;
    maxBytes?: number;
    fsync?: boolean;
    failureMode?: 'error' | 'warn';
  };

  /**
   * Emission rate for ALLOWED-call audit events (0-1). This gates audit
   * EMISSION only, never enforcement: 0 = no allowed-call events are sent, but
   * PII/policy/hook/kill-switch checks still run on every call and
   * blocked/redacted/error events are always emitted. Lowering it reduces ingest
   * volume, not the per-call enforcement cost.
   * @default 1.0
   */
  sample_rate?: number;

  /**
   * Maximum characters for prompt/response payloads
   * Larger payloads will be truncated with "[TRUNCATED]" marker
   * @default 100000
   */
  max_payload_chars?: number;

  /**
   * Disable auditing entirely (passthrough mode)
   * When true, wrap() returns the original client unchanged
   * @default false
   */
  disabled?: boolean;

  /**
   * Enable debug logging to console
   * @default false
   */
  debug?: boolean;

  /**
   * Timeout for audit HTTP calls in milliseconds
   * @default 5000
   */
  timeout?: number;

  /**
   * How to handle streaming responses
   * - "skip": Don't audit streaming requests (default)
   * - "wrap": Wrap AsyncIterable, audit on completion
   * @default "skip"
   */
  streaming_mode?: "skip" | "wrap";

  /**
   * Default region for all audit events
   * Can be overridden per-wrap or per-request
   */
  default_region?: string;

  /**
   * Default source identifier for all audit events
   * Can be overridden per-wrap or per-request
   */
  default_source?: string;

  /**
   * Default service name for all audit events (V2)
   * Can be overridden per-wrap or per-request
   */
  default_service_name?: string;

  /**
   * Narrows which providers the module interceptor governs (see the
   * camelCase `providers` field). Omit to govern all supported providers.
   */
  providers?: ('openai' | 'anthropic' | 'google')[];

  /**
   * Pre-call policy hook (internal snake_case alias)
   */
  on_pre_call?: PolicyHook;

  /** Timeout (ms) for on_pre_call hook. @default 2000 */
  hook_timeout_ms?: number;

  /** When the pre-call hook should fire. @default 'always' */
  hook_trigger?: 'always' | 'on_pii' | 'on_block';

  /** Enforcement fail mode when the pre-call hook times out or throws. @default 'open' */
  fail_mode?: 'open' | 'closed';

  /** Blocking approval hold budget in ms (see ObsvrConfig.approvalWaitMs). @default 0 */
  approval_wait_ms?: number;

  /** Grant-channel poll cadence (ms) during an approval wait. @default 5000 */
  approval_poll_ms?: number;

  /** Global enforcement mode (see ObsvrConfig.enforcementMode). @default "enforce" */
  enforcement_mode?: 'enforce' | 'monitor';

  /** Refuse an unattributed call (see ObsvrConfig.requirePrincipal). @default false */
  require_principal?: boolean;

  /** Refuse a wrap() that governs nothing (see ObsvrConfig.requireGovernedSurface). @default false */
  require_governed_surface?: boolean;

  /** Declared rule conflict-resolution mode (see ObsvrConfig.ruleResolution). */
  rule_resolution?: 'first_match' | 'deny_wins';

  /** Device signing key path (see ObsvrConfig.deviceSigningKeyFile). */
  device_signing_key_file?: string;

  /**
   * Built-in PII scan policy (opt-in, snake_case alias)
   */
  pii_policy?: {
    default?: "block" | "redact" | "detect_only";
    rules?: Partial<Record<string, "block" | "redact" | "detect_only">>;
  };

  /** Structured policy rules evaluated before the customer hook */
  policy_rules?: PolicyRule[];

  /** Anti-tamper policy floor (see ObsvrConfig.policyFloor). */
  policyFloor?: PolicyRule[];

  /** Run-level agent policy (tool allowlists, step limits, loop detection). */
  agent_policy?: AgentPolicy;

  /** Post-call hook for response scanning */
  on_post_call?: PostCallHook;

  /** Timeout (ms) for on_post_call hook. @default 2000 */
  post_call_timeout_ms?: number;

  /** Interval (ms) to poll `/policies` endpoint for rule updates. @default 30000 */
  policy_refresh_interval_ms?: number;

  /** With fail_mode "closed": max age (ms) of last policy sync before calls block. */
  policy_staleness_budget_ms?: number;

  /** Base64 raw Ed25519 public key pinned for policy-signature verification. */
  policy_public_key?: string;

  /** Multi-turn injection scoring config (see ObsvrConfig.multiTurnInjection). */
  multi_turn_injection?: {
    enabled?: boolean;
    threshold?: number;
    halfLifeMs?: number;
    action?: "block" | "flag";
  };

  /** Session taint latch (see ObsvrConfig.sessionTaint). */
  sessionTaint?: {
    enabled?: boolean;
    action?: "block" | "flag";
    destructiveTools?: string[];
    /** See ObsvrConfig.sessionTaint.honorDestructiveHints. @default true */
    honorDestructiveHints?: boolean;
  };

  /** Layered call cost (see ObsvrConfig.costPolicy). */
  costPolicy?: CostPolicyConfig;

  /** De-obfuscation scan views (see ObsvrConfig.deobfuscation). */
  deobfuscation?: { enabled?: boolean };

  /** Mirror audit events as OTel spans (see ObsvrConfig.otel). */
  otel?: { enabled?: boolean; tracerName?: string };
  /** Meter framework-integration events (see ObsvrConfig.meterIntegrationEvents). */
  meterIntegrationEvents?: boolean;

  /**
   * MCP tool-level policy: allowlist/denylist of tool names, poisoned-tool
   * stripping, and descriptor content-hash pinning (rug-pull defense).
   * `pinning`: hash each tool descriptor at tools/list (canonical projection,
   * full SHA-256); `pins` are operator-declared name->hash pins (authoritative,
   * survive restarts), otherwise first-seen hashes are TOFU-recorded for the
   * governed client's lifetime and NEVER silently re-pinned. On a mismatch:
   * mode "warn" (default) flags the violation on signed events; mode "block"
   * strips the tool at discovery and refuses calls to it. `requirePin` treats
   * tools without any pin as violations. Off by default.
   */
  mcpToolPolicy?: {
    allowedTools?: string[];
    deniedTools?: string[];
    blockPoisonedTools?: boolean;
    pinning?: {
      enabled?: boolean;
      mode?: "warn" | "block";
      pins?: Record<string, string>;
      requirePin?: boolean;
    };
  };

  /** Presidio Analyzer URL (e.g. http://localhost:5002). Enables NLP PII detection. */
  presidio_analyzer_url?: string;
  /** Presidio Anonymizer URL (e.g. http://localhost:5001). Required when presidio_analyzer_url is set. */
  presidio_anonymizer_url?: string;

  /** Hard deletion config. */
  hardDeletion?: { enabled: boolean; endpoint?: string };
  /** Per-environment policy overrides. */
  environmentPolicies?: Record<string, { policyRules?: PolicyRule[]; agentPolicy?: AgentPolicy }>;

  /** Inbound external policy backend (OPA/Cedar); see ObsvrConfig.externalPolicyBackend. */
  external_policy_backend?: ExternalPolicyBackendConfig;
}

/**
 * Options for wrapping a specific client
 */
export interface WrapOptions {
  /**
   * Factory-created strict profile-2.1 execution capability. When present,
   * ordinary non-streaming provider calls require signed receipt admission
   * and durable checkpoints before the provider can be contacted.
   */
  strict_receipt_v2_1?: StrictProviderBoundaryV21Capability;

  /**
   * Replace governed methods on the exact raw instance passed to `wrap()` with
   * refusal stubs. The returned governed proxy retains the original callables.
   * Other instances and method references copied before wrapping are unchanged.
   * @default false
   */
  sealRaw?: boolean;

  /**
   * Customer ID to associate with this client's events
   */
  customer_id?: string;

  /**
   * Override region for this client
   */
  region?: string;

  /**
   * Override source for this client
   */
  source?: string;

  /**
   * User ID to associate with this client's events (V2)
   */
  user_id?: string;

  /**
   * Service name for this client (V2)
   */
  service_name?: string;

  /** Metadata merged into every event from this wrapped client. */
  metadata?: Record<string, unknown>;
}

/**
 * Internal state for the singleton configuration
 */
export interface LLMAuditState {
  initialized: boolean;
  config: ResolvedConfig | null;
  wrappedClients: WeakSet<object>;
}

/**
 * Resolved configuration with defaults applied
 */
export interface ResolvedConfig {
  api_key: string;
  environment: "development" | "staging" | "production";
  ingest_url: string;
  durable_delivery?: {
    directory: string;
    maxBytes: number;
    fsync: boolean;
    failureMode: 'error' | 'warn';
  };
  sample_rate: number;
  max_payload_chars: number;
  disabled: boolean;
  debug: boolean;
  timeout: number;
  streaming_mode: "skip" | "wrap";
  default_region?: string;
  default_source?: string;
  default_service_name?: string;
  /** Which provider SDKs are enabled for auto-instrumentation */
  providers?: ('openai' | 'anthropic' | 'google')[];
  /** Pre-call policy hook (optional) */
  on_pre_call?: PolicyHook;
  /** Timeout (ms) for on_pre_call hook. @default 2000 */
  hookTimeoutMs?: number;
  /** Built-in PII scan policy (opt-in) */
  pii_policy?: {
    default?: "block" | "redact" | "detect_only";
    rules?: Partial<Record<string, "block" | "redact" | "detect_only">>;
  };
  /** Structured policy rules evaluated before the customer hook */
  policyRules?: PolicyRule[];

  /** Anti-tamper policy floor (see ObsvrConfig.policyFloor). */
  policyFloor?: PolicyRule[];
  /** Post-call hook for response scanning */
  on_post_call?: PostCallHook;
  /** Timeout (ms) for on_post_call hook. @default 2000 */
  postCallTimeoutMs?: number;
  /** Polling interval (ms) for fetching updated policy rules. */
  policyRefreshIntervalMs?: number;
  /** With failMode "closed": max age (ms) of last policy sync before calls block. */
  policyStalenessBudgetMs?: number;
  /** Base64 raw Ed25519 public key pinned for policy-signature verification (B2). */
  policyPublicKey?: string;
  /** Multi-turn injection scoring (session-accumulated, decaying). */
  multiTurnInjection?: {
    enabled?: boolean;
    threshold?: number;
    halfLifeMs?: number;
    action?: "block" | "flag";
  };
  /** Session taint latch (see ObsvrConfig.sessionTaint). */
  sessionTaint?: {
    enabled?: boolean;
    action?: "block" | "flag";
    destructiveTools?: string[];
    /** See ObsvrConfig.sessionTaint.honorDestructiveHints. @default true */
    honorDestructiveHints?: boolean;
  };
  /** Layered call cost (see ObsvrConfig.costPolicy). */
  costPolicy?: CostPolicyConfig;
  /** De-obfuscation scan views (server-side normalizer mirror), detection-only. */
  deobfuscation?: { enabled?: boolean };
  /** Mirror audit events as OTel spans (optional @opentelemetry/api peer). */
  otel?: { enabled?: boolean; tracerName?: string };
  /** Meter framework-integration events (see ObsvrConfig.meterIntegrationEvents). */
  meterIntegrationEvents?: boolean;

  /** Run-level agent policy for agentic frameworks. */
  agentPolicy?: AgentPolicy;

  /** When the pre-call hook should fire: always, only on PII, or only on block. @default 'always' */
  hookTrigger?: 'always' | 'on_pii' | 'on_block';

  /** Enforcement fail mode when the pre-call hook times out or throws. @default 'open' */
  failMode?: 'open' | 'closed';

  /** Blocking approval hold budget in ms (see ObsvrConfig.approvalWaitMs). @default 0 */
  approvalWaitMs?: number;

  /** Grant-channel poll cadence (ms) during an approval wait. @default 5000 */
  approvalPollMs?: number;

  /** Global enforcement mode (see ObsvrConfig.enforcementMode). @default "enforce" */
  enforcementMode?: 'enforce' | 'monitor';

  /** Refuse an unattributed call (see ObsvrConfig.requirePrincipal). @default false */
  requirePrincipal?: boolean;

  /** Refuse a wrap() that governs nothing (see ObsvrConfig.requireGovernedSurface). @default false */
  requireGovernedSurface?: boolean;

  /** Declared rule conflict-resolution mode (see ObsvrConfig.ruleResolution). */
  ruleResolution?: 'first_match' | 'deny_wins';

  /** Device signing key path (see ObsvrConfig.deviceSigningKeyFile). */
  deviceSigningKeyFile?: string;

  /**
   * MCP tool-level policy: allowlist/denylist of tool names, poisoned-tool
   * stripping, and descriptor content-hash pinning (rug-pull defense).
   * `pinning`: hash each tool descriptor at tools/list (canonical projection,
   * full SHA-256); `pins` are operator-declared name->hash pins (authoritative,
   * survive restarts), otherwise first-seen hashes are TOFU-recorded for the
   * governed client's lifetime and NEVER silently re-pinned. On a mismatch:
   * mode "warn" (default) flags the violation on signed events; mode "block"
   * strips the tool at discovery and refuses calls to it. `requirePin` treats
   * tools without any pin as violations. Off by default.
   */
  mcpToolPolicy?: {
    allowedTools?: string[];
    deniedTools?: string[];
    blockPoisonedTools?: boolean;
    pinning?: {
      enabled?: boolean;
      mode?: "warn" | "block";
      pins?: Record<string, string>;
      requirePin?: boolean;
    };
  };

  /** Presidio Analyzer URL (e.g. http://localhost:5002). Enables NLP PII detection. */
  presidio_analyzer_url?: string;
  /** Presidio Anonymizer URL (e.g. http://localhost:5001). Required when presidio_analyzer_url is set. */
  presidio_anonymizer_url?: string;

  /** Hard deletion config: issue DELETE to ingest endpoint on demand. */
  hardDeletion?: { enabled: boolean; endpoint?: string };
  /** Per-environment policy overrides merged into the active config at resolution time. */
  environmentPolicies?: Record<string, { policyRules?: PolicyRule[]; agentPolicy?: AgentPolicy }>;

  /** Inbound external policy backend (OPA/Cedar); merged DENY-WINS with local rules. */
  external_policy_backend?: ExternalPolicyBackendConfig;
}

/**
 * Fields extracted from request args for audit purposes
 * These fields are stripped before sending to the LLM
 */
export interface AuditFields {
  request_id?: string;
  region?: string;
  source?: string;
  metadata?: Record<string, unknown>;

  // V2 fields - customer-provided. Pass them alongside the provider's own
  // parameters; the SDK strips them from the request and puts them on the
  // event. Non-string values are dropped rather than forwarded, as for the
  // fields above.
  user_id?: string;
  /**
   * Masking is the ingest service's job, not this SDK's: the value rides the
   * event exactly as given. Said plainly because this line used to read "will
   * be masked server-side" beside a field the SDK never captured at all.
   */
  client_ip?: string;
  user_agent?: string;
  service_name?: string;
}

/**
 * Result of filtering request arguments
 */
export interface FilterResult {
  /**
   * Cleaned args with audit fields removed (send to LLM)
   */
  cleaned_args: unknown[];

  /**
   * Extracted audit fields (send to audit backend)
   */
  audit_fields: AuditFields;
}

/**
 * Extracted data from an LLM request/response
 */
export interface ExtractedData {
  prompt: string;
  response: string;
  model: string;
  latency_ms: number;

  // V2 token usage fields
  input_tokens?: number;
  output_tokens?: number;
  total_tokens?: number;
}

/**
 * Complete audit event to send to the backend (V2 Schema)
 */
export interface AuditEvent {
  // Core fields
  request_id: string;

  // Environment fields
  environment?: "development" | "staging" | "production";
  service_name?: string;
  region: string;

  // Identity fields (customer_id derived from API key on server)
  user_id?: string;

  // Network fields (customer-provided, optional)
  client_ip?: string;  // Will be masked server-side
  user_agent?: string;

  // LLM Call fields
  provider:
    | "openai"
    | "anthropic"
    | "google"
    | "azure_openai"
    | "bedrock"
    | "vertex_ai"
    | "together"
    | "cloudflare"
    // the ingest canonical provider enum has NO "mcp", so ingest
    // stores this as "unknown". MCP identity stays recoverable from `source`
    // ("mcp-*"), `operation` ("mcp.*"), and `metadata.provider_detail` (stamped
    // in buildIntegrationEvent). Coordinate a backend enum addition to promote
    // MCP to a first-class provider in provider-level dashboards.
    | "mcp"
    | "unknown";
  model: string;
  /** Provider-resolved model snapshot (e.g. "gpt-4o-2024-08-06") from the
   * response body, when available — vs `model` which is the request alias.
   * Load-bearing for temporal provenance ("which exact model decided"). */
  model_resolved?: string;
  /** How `model_resolved` was captured — present IF AND ONLY IF `model_resolved`
   * is present. `provider_response` = read directly from a native provider
   * client's response (highest trust); `framework_reported` = read from a
   * third-party framework's response abstraction; `client_declared` = supplied
   * by an API-direct/older caller with no source attribution (lowest trust). */
  provenance_source?: "provider_response" | "framework_reported" | "client_declared";
  operation: string;  // e.g., "chat.completion", "embedding"
  source: string;
  /** Where INSIDE the payload this event's content came from — `source` names
   * the integration that emitted the event, this names the position the text
   * occupied within the call. `detected_types` says WHAT was found; this says
   * WHERE it entered. `user_turn` = typed by the end user; `system` = the
   * system prompt; `retrieved` = a document a retriever returned;
   * `tool_result` = text a tool returned; `memory` = a prior-turn store
   * replayed into this call; `unknown` = the emitter looked and could not tell.
   *
   * The distinction is an incident-triage one: a `prompt_injection` found in a
   * `user_turn` is someone probing your bot, and the identical finding in
   * `retrieved` or `tool_result` means an upstream data source is already
   * compromised. Those are different incidents with different first responses.
   *
   * Set ONLY where an integration genuinely knows, and ABSENT everywhere else —
   * never inferred from the operation name or the shape of the payload. An
   * absent field is honest; a guessed one gets read as evidence in exactly the
   * incident where being wrong costs the most.
   *
   * AUDIT-RECORD COMPLETENESS ONLY — deliberately not a policy input. Nothing
   * in detection, scoring, or gating reads it. obsvr bets on session-taint
   * reachability (`policy/session-taint.ts`) rather than on classifying how far
   * to trust a source, and wiring this into a decision would quietly adopt the
   * trust taxonomy that bet rejects.
   *
   * NOT SEALED, and that is load-bearing for how much weight it can carry. The
   * ledger's Merkle leaf is a closed list of named fields (currently v8) and
   * this is not one of them; neither the `sdk_sig` preimage
   * (`proxy/chain-format.ts` — format, session, seq, timestamp, a hash of
   * prompt+response, prev_sig) nor the canonical decision-input document
   * (`policy/decision-record.ts`) covers it either. So it sits OUTSIDE the
   * integrity proof: it can be altered after the fact without breaking chain
   * verification or the anchored root. For a field whose whole purpose is
   * asserting "this text arrived from a compromised upstream source," treat it
   * as a triage hint rather than as evidence. Sealing it would be a leaf
   * version bump, which is a deliberate decision and not this field's to make.
   *
   * Carriage: ingest has no column for this name yet and strips unknown
   * top-level fields, so the sender also mirrors it onto reserved
   * `metadata.obsvr_content_provenance` — the route `obsvr_external_backend`
   * and `obsvr_tool_content_hash` already take, and one the metadata trimmer
   * preserves. Read it from metadata until ingest declares the column. */
  content_provenance?:
    | "user_turn"
    | "system"
    | "retrieved"
    | "tool_result"
    | "memory"
    | "unknown";

  // Content fields
  prompt: string;
  response: string;
  /** Latest user message only - used by ingest for PII detection (not full history). */
  user_input?: string;

  // Usage fields (from provider response.usage)
  input_tokens?: number;
  output_tokens?: number;
  total_tokens?: number;

  // Performance fields
  latency_ms?: number;
  time_to_first_token_ms?: number;  // null for v2 (streaming not implemented)

  // Success/Status fields
  success: boolean;
  status_code?: number;
  error_type?: "rate_limit" | "timeout" | "api_error" | "auth_error" | null;
  error_message?: string;

  // Metadata
  metadata?: Record<string, unknown>;

  // Compliance fields - always set by the SDK before sending
  event_type: "llm_call" | "blocked_call" | "policy_flag" | "tool_call" | "hard_delete" | "delegation" | "loop_detected" | "approval_required" | "span";
  /**
   * Evidence tier (M3B): "governance" events lead the audit feed; "execution_span"
   * nodes are signed evidence too but are viewed through traces, not the main
   * feed. Absent means "governance" (backwards compatible).
   */
  event_class?: "governance" | "execution_span";
  policy_version: string;
  /**
   * The policy verdict. `not_evaluated` means NO GATE RAN for this event's
   * subject — it is the absence of a decision, not a permissive one, and it
   * must never be read as `allowed`. See `PolicyNotEvaluated`.
   */
  action_taken: "allowed" | "blocked" | "redacted" | "hook_error" | "hook_timeout" | "not_evaluated";
  action_reason: "pii_detected" | "policy_violation" | "customer_override" | "none";
  /** Registry reason code (governance/reason-codes.ts) for the classification
   * this decision rests on: the deciding layer's fine-grained code (e.g. the
   * rules engine's KEYWORD_BLOCKED), never re-collapsed to a coarse category.
   * PERMITTED on a clean allow; on a flagged-but-allowed call it carries the
   * classifying code. Matches the reason_code on the thrown ObsvrPolicyError
   * for the same decision. */
  reason_code?: string;
  action_source: "builtin" | "builtin+presidio" | "customer_hook" | "policy_rules" | "external_backend" | "unknown";
  redacted_types: string[];
  blocked_types?: string[];
  rule_id?: string;
  policy_reason?: string;
  tenant_id?: string;
  /** What shadow-mode rules would have done (EV-21), or the would-be verdict
   * of a monitor-mode conversion; informational only. `reason_code` carries
   * the registry classification when the producing layer resolved one. */
  shadow_outcome?: {
    rule_id: string;
    would: "block" | "redact" | "flag";
    reason_code?: string;
    reason: string;
  };
  /** SHA-256 hex of the canonical decision-input document the rules engine
   * evaluated (ADR-2 tier-1). ADDITIVE — never part of the HMAC chain
   * preimage; sealed by the ledger's v7 Merkle leaf. */
  decision_input_hash?: string;
  /** Rules-engine semantics version the decision ran under ("obsvr-rules/<N>").
   * Bumped only when evaluation semantics change (see decision-record.ts). */
  engine_version?: string;
  /** Provenance of the inbound external policy backend (OPA/Cedar) when one is
   * configured: which backend decided, its outcome, and the effective-policy
   * hash. ADDITIVE — never part of the HMAC chain preimage. */
  external_backend?: ExternalBackendRecord;

  // Industry-specific fields
  action_name?: string;
  delegation_chain?: string[];
  delegation_depth?: number;
  /** Scope/permissions delegated to the child agent (C2, recorded for traceability). */
  delegated_scope?: string[];
  source_grounding_score?: number;
  loop_iteration_count?: number;

  // SDK integrity fields - stamped by fire-and-forget.ts at queue entry
  sdk_session_id?: string;  // UUID stable for this process lifetime, groups the sequence
  seq_no?: number;           // monotonic counter, 1-based, resets on SDK re-init
  timestamp_sdk?: number;    // Date.now() at capture, before queue entry
  sdk_version?: string;      // "node/<semver>", which SDK build produced this event
  /** Signing format this event verifies under (see proxy/chain-format.ts).
   * Absent = 1, the legacy concatenation preimage; the current SDK stamps 3
   * (CHAIN_FORMAT_CURRENT), whose preimage also covers the decision fields;
   * 2 is the content-framed format signed before the verdict entered the
   * preimage. Routing only — the format number is also inside the signed
   * payload. */
  chain_format?: number;
  sdk_sig?: string;          // HMAC-SHA256 hex signature, 64 chars (Phase 2)
  /** Optional device seal: Ed25519 over the same payload sdk_sig covers,
   *  hex (128 chars). Additive — absent unless a device key is configured. */
  device_sig?: string;
  /** sha256(raw device public key) hex, first 16 chars. A selection hint;
   *  verification trusts only keys pinned out of band. */
  device_key_id?: string;
  prev_sig?: string;         // sdk_sig of the previous event in this session (Phase 3)
}

/**
 * Token usage extracted from LLM response
 */
export interface TokenUsage {
  input_tokens: number;
  output_tokens: number;
  total_tokens: number;
}

/**
 * Provider type detection
 */
export type ProviderType = "openai" | "anthropic" | "unknown";

/**
 * Auditable method configuration
 */
export interface AuditableMethod {
  /**
   * Path to the method (e.g., ["chat", "completions", "create"])
   */
  path: string[];

  /**
   * Whether this method supports streaming
   */
  supports_streaming: boolean;

  /**
   * Extractor function name to use
   */
  extractor: string;
}

/**
 * Queue item for fire-and-forget sending
 */
export interface QueueItem {
  event: AuditEvent;
  timestamp: number;
  retries: number;
  /** Durable outbox record retained until terminal delivery classification. */
  outboxId?: string;
}

/**
 * Backoff state for rate limiting
 */
export interface BackoffState {
  until: number;
  multiplier: number;
}
