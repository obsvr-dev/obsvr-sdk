/**
 * Inbound external policy backend (ADR-4): OPA or Cedar.
 *
 * Today Obsvr only EXPORTS to Rego one-way (rego-export.ts). This module adds
 * the INBOUND seam: a customer points the SDK at their existing policy-as-code
 * engine — an OPA HTTP endpoint or a Cedar authorization endpoint — and that
 * engine's verdict participates in the pre-call decision.
 *
 * Four guarantees (all pinned cross-language; twin: sdk-python/obsvr/external_backend.py):
 *   1. DENY-WINS merge with the local rules — a deny from EITHER side blocks.
 *      The backend can only ADD restriction; a backend "allow" never downgrades
 *      a local block. Pinned by conformance/fixtures/external_backend.json.
 *   2. Fail-closed: a backend error OR timeout counts as DENY (enforce mode),
 *      because a policy engine that cannot render a verdict must not be treated
 *      as approval. A configurable shadow mode makes the backend observe-only
 *      (records what it WOULD have done, never blocks) for safe rollout.
 *   3. SSRF guard on the backend URL (see utils/ssrf.ts): non-http(s) schemes and
 *      private/loopback/link-local/metadata addresses are refused, resolving
 *      every address once and pinning the socket to that approved snapshot. Any
 *      guard failure is an error outcome -> fail-closed. "Metadata addresses" means
 *      every IPv6 form that carries the v4 address, not only the mapped one:
 *      until this was measured, `http://[::169.254.169.254]/` reached `fetch`
 *      while `::ffff:169.254.169.254` was refused.
 *   4. Provenance: the emitted event records which backend decided (identity +
 *      a hash of the effective backend policy) via the ExternalBackendRecord.
 *
 * Zero-config default is NO backend (unchanged behavior).
 *
 * @packageDocumentation
 */

import { createHash } from 'node:crypto';
import { createPinnedLookup, postPinnedBytes } from '../utils/pinned-http.js';
import {
  resolveBackendUrlAllowed,
  type AllowedBackendTarget,
  type Resolver,
  type SsrfOptions,
} from '../utils/ssrf.js';

/** Which policy-as-code engine the backend speaks. */
export type ExternalBackendType = 'opa' | 'cedar';

/**
 * Raw outcome of consulting the backend, before the shadow/fail-closed policy
 * is applied. `error` and `timeout` are the fail-closed cases (treated as deny
 * in enforce mode); they are kept distinct from a genuine `deny` for provenance.
 */
export type BackendOutcome = 'allow' | 'deny' | 'error' | 'timeout';

/** Local decision reached by the rest of the pre-call pipeline. */
export type LocalDecision = 'allow' | 'redact' | 'block';

/** Customer configuration for the inbound external policy backend. */
export interface ExternalPolicyBackendConfig {
  /** 'opa' (POST {input}, read result.allow/bool) or 'cedar' (read decision Allow/Deny). */
  type: ExternalBackendType;
  /**
   * Full decision endpoint URL. For OPA this is the data document, e.g.
   * `https://opa.example.com/v1/data/obsvr/allow`. Must be http(s); SSRF-guarded.
   */
  url: string;
  /** Observe-only: record the verdict but never block. Default false (enforce). */
  shadow?: boolean;
  /** Per-call budget (ms). Error/timeout => deny in enforce mode. Default 2000. */
  timeoutMs?: number;
  /** Extra request headers (auth tokens, etc.). */
  headers?: Record<string, string>;
  /** Human label recorded on events (provenance). Default `${type}:${host}`. */
  name?: string;
  /**
   * The effective backend policy text/identity (e.g. the Rego module, the Cedar
   * policy set, or a bundle revision id). Hashed into the event's policy hash so
   * the audit record ties to a specific backend policy version. When omitted,
   * the hash is derived from the endpoint identity instead.
   */
  policy?: string;
  /** Permit a loopback/private-network backend (never metadata/link-local). Default false. */
  allowPrivateNetwork?: boolean;
}

/** Non-content decision input POSTed to the backend (digests, not raw prompts). */
export interface BackendDecisionInput {
  operation: string;
  provider: string;
  model: string;
  environment?: string;
  /** Principal/subject identifiers visible at the boundary (only non-empty ones). */
  principal: { user_id?: string; service_name?: string; tenant_id?: string };
  /** The local pipeline's decision before the backend was consulted. */
  local_decision: LocalDecision;
  /** Canonical rules hash (policy_version) the local decision ran under. */
  rules_hash: string;
  /** SHA-256 of the evaluated prompt text (digest — the raw prompt is never sent). */
  prompt_sha256: string;
}

/**
 * Provenance record stamped on the emitted audit event: WHICH backend decided,
 * and what it said. Additive (never part of the HMAC chain preimage).
 */
export interface ExternalBackendRecord {
  /** Human identity of the backend (config.name or `${type}:${host}`). */
  identity: string;
  /** 16-hex SHA-256 prefix of the effective backend policy (or endpoint identity). */
  policy_hash: string;
  type: ExternalBackendType;
  /** Raw outcome before shadow/fail-closed. */
  outcome: BackendOutcome;
  /** True when observe-only (the outcome did not affect the decision). */
  shadow: boolean;
  /** Reasons returned by the backend, when any. */
  reasons?: string[];
}

/** Result of the deny-wins merge between the local decision and the backend. */
export interface BackendMergeResult {
  decision: LocalDecision;
  /** True iff the backend's denial is what produced the block. */
  blocked_by_backend: boolean;
}

/**
 * DENY-WINS merge — the load-bearing, conformance-pinned function.
 *
 * A denial from EITHER side blocks; a backend "allow" never downgrades a local
 * decision. `error`/`timeout` are denials in enforce mode (fail-closed). In
 * shadow mode the backend NEVER changes the decision (observe-only), though the
 * raw outcome is still recorded on the event for rollout visibility.
 */
export function mergeExternalBackendDecision(
  local: LocalDecision,
  outcome: BackendOutcome,
  shadow: boolean,
): BackendMergeResult {
  const backendDenies = outcome !== 'allow'; // deny | error | timeout
  if (shadow) {
    return { decision: local, blocked_by_backend: false };
  }
  if (backendDenies) {
    return { decision: 'block', blocked_by_backend: local !== 'block' };
  }
  return { decision: local, blocked_by_backend: false };
}

/** Host portion of a URL for identity, or the raw url on parse failure. */
function urlHost(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

/**
 * Backend identity + effective-policy hash for provenance. The hash is a
 * 16-hex SHA-256 prefix of the configured policy text when present, else of the
 * endpoint identity (`type|url`). Deterministic and cross-language-identical.
 */
export function backendProvenance(cfg: ExternalPolicyBackendConfig): {
  identity: string;
  policy_hash: string;
} {
  const identity = cfg.name && cfg.name.length > 0 ? cfg.name : `${cfg.type}:${urlHost(cfg.url)}`;
  const material =
    cfg.policy && cfg.policy.length > 0 ? cfg.policy : `${cfg.type}|${cfg.url}`;
  const policy_hash = createHash('sha256').update(material, 'utf8').digest('hex').slice(0, 16);
  return { identity, policy_hash };
}

/** Build the non-content decision-input document POSTed to the backend. */
export function buildBackendInput(params: {
  operation: string;
  provider: string;
  model: string;
  environment?: string;
  userId?: string;
  serviceName?: string;
  tenantId?: string;
  localDecision: LocalDecision;
  rulesHash: string;
  promptSha256: string;
}): BackendDecisionInput {
  const principal: BackendDecisionInput['principal'] = {};
  if (params.userId) principal.user_id = params.userId;
  if (params.serviceName) principal.service_name = params.serviceName;
  if (params.tenantId) principal.tenant_id = params.tenantId;
  return {
    operation: params.operation,
    provider: params.provider,
    model: params.model,
    ...(params.environment ? { environment: params.environment } : {}),
    principal,
    local_decision: params.localDecision,
    rules_hash: params.rulesHash,
    prompt_sha256: params.promptSha256,
  };
}

/** Normalize an OPA `result` value into allow + reasons. */
function normalizeOpa(body: unknown): { allow: boolean; reasons: string[] } | null {
  if (!body || typeof body !== 'object') return null;
  if (!('result' in body)) return null; // OPA with an undefined document omits `result`
  const result = (body as { result: unknown }).result;
  if (typeof result === 'boolean') return { allow: result, reasons: [] };
  if (result && typeof result === 'object') {
    const r = result as Record<string, unknown>;
    const reasons = Array.isArray(r.reasons)
      ? (r.reasons.filter((x) => typeof x === 'string') as string[])
      : [];
    if (typeof r.allow === 'boolean') return { allow: r.allow, reasons };
    if (typeof r.deny === 'boolean') return { allow: !r.deny, reasons };
    if (Array.isArray(r.deny)) {
      const denyReasons = r.deny.filter((x) => typeof x === 'string') as string[];
      return { allow: r.deny.length === 0, reasons: denyReasons.length ? denyReasons : reasons };
    }
  }
  return null; // unrecognized shape -> caller treats as error (fail-closed)
}

/** Normalize a Cedar/AVP-style response into allow + reasons. */
function normalizeCedar(body: unknown): { allow: boolean; reasons: string[] } | null {
  if (!body || typeof body !== 'object') return null;
  const b = body as Record<string, unknown>;
  const decision = b.decision;
  if (typeof decision === 'string') {
    const allow = decision.toLowerCase() === 'allow';
    const reasons: string[] = [];
    const errors = b.errors ?? (b.diagnostics as Record<string, unknown> | undefined)?.errors;
    if (Array.isArray(errors)) {
      for (const e of errors) {
        if (typeof e === 'string') reasons.push(e);
        else if (e && typeof e === 'object' && typeof (e as { errorDescription?: unknown }).errorDescription === 'string') {
          reasons.push((e as { errorDescription: string }).errorDescription);
        }
      }
    }
    return { allow, reasons };
  }
  return null;
}

/** Dependencies injectable for tests. */
export interface EvaluateDeps {
  /**
   * Explicit transport seam for tests/embedders. The production path does not
   * use fetch: it pins the socket to the address snapshot returned by the SSRF
   * guard. A supplied fetch implementation is trusted to provide equivalent
   * destination pinning and must not be used with an untrusted URL.
   */
  fetchImpl?: typeof fetch;
  resolver?: Resolver;
}

interface BackendHttpResponse {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
  type?: string;
}

export const createPinnedBackendLookup = createPinnedLookup;

/**
 * POST through Node's native HTTP stack with a pinned lookup. Passing the
 * original URL preserves its Host header. For HTTPS, `servername` is kept as
 * the configured hostname, so certificate validation remains hostname-based
 * even though the socket connects to the approved numeric address.
 */
async function postPinnedJson(
  target: AllowedBackendTarget,
  body: string,
  headers: Record<string, string>,
  signal: AbortSignal,
): Promise<BackendHttpResponse> {
  const response = await postPinnedBytes(target, body, headers, signal, 1_048_576);
  return {
    ok: response.status >= 200 && response.status < 300,
    status: response.status,
    json: async () => JSON.parse(Buffer.from(response.body ?? []).toString('utf8')),
  };
}

/**
 * Consult the backend. NEVER throws — every failure mode (SSRF block, network
 * error, non-2xx, unparseable body, timeout) maps to an `error`/`timeout`
 * outcome so the caller's fail-closed merge stays in control.
 */
export async function evaluateExternalBackend(
  cfg: ExternalPolicyBackendConfig,
  input: BackendDecisionInput,
  deps: EvaluateDeps = {},
): Promise<{ outcome: BackendOutcome; reasons: string[] }> {
  const ssrfOpts: SsrfOptions = { allowPrivateNetwork: cfg.allowPrivateNetwork };
  let target: AllowedBackendTarget;
  try {
    target = await resolveBackendUrlAllowed(cfg.url, ssrfOpts, deps.resolver);
  } catch {
    return { outcome: 'error', reasons: ['ssrf_guard_blocked_backend_url'] };
  }

  const timeoutMs = cfg.timeoutMs ?? 2000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  if (typeof (timer as unknown as { unref?: () => void }).unref === 'function') {
    (timer as unknown as { unref: () => void }).unref();
  }

  // OPA reads the decision under `input`; Cedar receives the document directly.
  const payload = cfg.type === 'opa' ? { input } : input;
  const requestBody = JSON.stringify(payload);
  const requestHeaders = { 'content-type': 'application/json', ...(cfg.headers ?? {}) };

  try {
    const resp: BackendHttpResponse = deps.fetchImpl
      ? await deps.fetchImpl(cfg.url, {
          method: 'POST',
          headers: requestHeaders,
          body: requestBody,
          signal: controller.signal,
          redirect: 'manual',
        })
      : await postPinnedJson(target, requestBody, requestHeaders, controller.signal);
    if (!resp.ok || (resp as { type?: string }).type === 'opaqueredirect') {
      return { outcome: 'error', reasons: [`backend_http_${resp.status}`] };
    }
    let body: unknown;
    try {
      body = await resp.json();
    } catch {
      return { outcome: 'error', reasons: ['backend_response_not_json'] };
    }
    const normalized = cfg.type === 'opa' ? normalizeOpa(body) : normalizeCedar(body);
    if (!normalized) {
      return { outcome: 'error', reasons: ['backend_response_unrecognized'] };
    }
    return { outcome: normalized.allow ? 'allow' : 'deny', reasons: normalized.reasons };
  } catch (err) {
    const isAbort = err instanceof Error && (err.name === 'AbortError' || err.name === 'TimeoutError');
    return { outcome: isAbort ? 'timeout' : 'error', reasons: [isAbort ? 'backend_timeout' : 'backend_error'] };
  } finally {
    clearTimeout(timer);
  }
}

/** Outcome of the single external-backend step: merged decision + provenance. */
export interface ExternalBackendStepResult {
  decision: LocalDecision;
  blocked_by_backend: boolean;
  record: ExternalBackendRecord;
}

/**
 * One-call integration step used by the wrapper and integration pre-call paths:
 * evaluate the backend, merge deny-wins, and assemble the provenance record.
 * The caller invokes this only when the local decision is not already a block
 * (a block cannot be downgraded, so consulting the backend would be pure
 * overhead — and the deny-wins outcome is already decided).
 */
export async function runExternalBackendStep(
  cfg: ExternalPolicyBackendConfig,
  localDecision: LocalDecision,
  input: BackendDecisionInput,
  deps: EvaluateDeps = {},
): Promise<ExternalBackendStepResult> {
  const shadow = cfg.shadow === true;
  const { outcome, reasons } = await evaluateExternalBackend(cfg, input, deps);
  const prov = backendProvenance(cfg);
  const merge = mergeExternalBackendDecision(localDecision, outcome, shadow);
  const record: ExternalBackendRecord = {
    identity: prov.identity,
    policy_hash: prov.policy_hash,
    type: cfg.type,
    outcome,
    shadow,
    ...(reasons.length ? { reasons } : {}),
  };
  return { decision: merge.decision, blocked_by_backend: merge.blocked_by_backend, record };
}
