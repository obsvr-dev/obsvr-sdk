import type { ReasonCode } from './reason-codes.js';

/** Standardized governance decision */
export type GovernanceDecision = 'PERMITTED' | 'BLOCKED';

/** Standardized governance response */
export interface GovernanceResponse {
  decision: GovernanceDecision;
  reason_code: ReasonCode;
  reason?: string;
  rule_id?: string;
  timestamp: number;
  nonce?: string;
}

/** Request to evaluate an action */
export interface EvaluateRequest {
  action_type: string;
  payload: Record<string, unknown>;
  tenant_id?: string;
  user_id?: string;
  service_name?: string;
  metadata?: Record<string, unknown>;
}

/** Response from evaluate endpoint - extends GovernanceResponse with optional JWT */
export interface EvaluateResponse extends GovernanceResponse {
  execution_token?: string;
}

/** Payload embedded in JWT execution tokens */
export interface PolicyEvaluationToken {
  action: string;
  decision: GovernanceDecision;
  rule_id?: string;
  timestamp: number;
  nonce: string;
  exp: number;
}

/** Quota configuration for rate limiting */
export interface QuotaConfig {
  scope: 'user_id' | 'service_name' | 'tenant_id';
  scope_value: string;
  max_calls: number;
  window_ms: number;
}

/** Result of audit chain verification */
export interface ChainVerificationResult {
  valid: boolean;
  brokenAt?: number;
  reason?: string;
  eventsVerified: number;
}

/** Configuration for standalone HTTP governance server */
export interface GovernanceServerConfig {
  apiKey: string;
  port?: number;
  /**
   * Bind host. Defaults to `127.0.0.1` (loopback only) — the server issues
   * signed execution tokens and lets callers probe policy, so it must not be
   * network-reachable by default. Binding a NON-loopback host (e.g. `0.0.0.0`)
   * REQUIRES `authToken` to be set, or `start()` refuses to listen.
   */
  host?: string;
  /**
   * Bearer token required on every `/v2/*` endpoint (constant-time compared
   * against `Authorization: Bearer <token>`). `/health` stays open. Strongly
   * recommended for any deployment; mandatory to bind a non-loopback host.
   */
  authToken?: string;
  /**
   * CORS policy. `false` (default) sends no CORS headers. An `{ origins }`
   * allowlist echoes the request Origin only when it matches. `true` is the
   * legacy wildcard (`Access-Control-Allow-Origin: *`) and logs an insecurity
   * warning — prefer an allowlist.
   */
  cors?: boolean | { origins: string[] };
  policyRules?: import('../policy/rules.js').PolicyRule[];
  piiPolicy?: import('../proxy/types.js').ResolvedConfig['pii_policy'];
  onPreCall?: import('../policy/hook.js').PolicyHook;
  environment?: 'development' | 'staging' | 'production';
  ingestUrl?: string;
  agentPolicy?: import('../proxy/types.js').AgentPolicy;
}

/** Quota tracking entry (internal) */
export interface QuotaEntry {
  count: number;
  windowStart: number;
}
