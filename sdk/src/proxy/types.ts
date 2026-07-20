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
  };

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
  };

  /** De-obfuscation scan views (see ObsvrConfig.deobfuscation). */
  deobfuscation?: { enabled?: boolean };

  /** Mirror audit events as OTel spans (see ObsvrConfig.otel). */
  otel?: { enabled?: boolean; tracerName?: string };

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
  };
  /** De-obfuscation scan views (server-side normalizer mirror), detection-only. */
  deobfuscation?: { enabled?: boolean };
  /** Mirror audit events as OTel spans (optional @opentelemetry/api peer). */
  otel?: { enabled?: boolean; tracerName?: string };

  /** Run-level agent policy for agentic frameworks. */
  agentPolicy?: AgentPolicy;

  /** When the pre-call hook should fire: always, only on PII, or only on block. @default 'always' */
  hookTrigger?: 'always' | 'on_pii' | 'on_block';

  /** Enforcement fail mode when the pre-call hook times out or throws. @default 'open' */
  failMode?: 'open' | 'closed';

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

  // V2 fields - customer-provided
  user_id?: string;
  client_ip?: string;  // Will be masked server-side
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
  action_taken: "allowed" | "blocked" | "redacted" | "hook_error" | "hook_timeout";
  action_reason: "pii_detected" | "policy_violation" | "customer_override" | "none";
  action_source: "builtin" | "builtin+presidio" | "customer_hook" | "policy_rules" | "external_backend" | "unknown";
  redacted_types: string[];
  blocked_types?: string[];
  rule_id?: string;
  policy_reason?: string;
  tenant_id?: string;
  /** What shadow-mode rules would have done (EV-21); informational only. */
  shadow_outcome?: { rule_id: string; would: "block" | "redact" | "flag"; reason: string };
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
  sdk_sig?: string;          // HMAC-SHA256 hex signature, 64 chars (Phase 2)
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
}

/**
 * Backoff state for rate limiting
 */
export interface BackoffState {
  until: number;
  multiplier: number;
}
