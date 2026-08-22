import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import { postPinnedBytes, type PinnedHttpResponse } from '../utils/pinned-http.js';
import {
  assertBackendUrlStatic, resolveBackendUrlAllowed,
  type AllowedBackendTarget, type Resolver,
} from '../utils/ssrf.js';
import type { PreparedDecisionV21 } from './strict-receipt-coordinator-v2-1-types.js';
import { DEFINITIVE_NO_STORE } from './strict-receipt-prepared-state.js';
import { verifyStrictReceiptV21 } from './strict-receipt-v2-1-verify.js';

export const STRICT_RECEIPT_V21_INGEST_SCHEMA = 'obsvr-strict-receipt-ingest-v2-1' as const;
export const STRICT_RECEIPT_V21_ADMISSION_SCHEMA = 'obsvr-strict-receipt-admission-v2-1' as const;
export const STRICT_RECEIPT_V21_ENDPOINT = '/ingest/strict-receipts/v2-1' as const;
export const STRICT_RECEIPT_V21_MAX_REQUEST_BYTES = 262_144 as const;

const HEX64 = /^[0-9a-f]{64}$/;
const NO_STORE = new Set([400, 401, 403, 413]);
const RETRYABLE = new Set([408, 429]);
const LOCAL = new Set(['localhost', '127.0.0.1', '::1']);
const MAX_RESPONSE_BYTES = 1_048_576;

export type StrictAdmissionV21PinnedTransport = (
  target: AllowedBackendTarget, body: string,
  headers: Readonly<Record<string, string>>, signal: AbortSignal,
  maxResponseBytes: number,
) => Promise<PinnedHttpResponse>;

export interface StrictAdmissionV21Coordinator {
  inspectState(): {
    tenant_id: string; session_id: string; frozen: boolean;
    prepared?: { token: string; receipt_hash: string; kind: 'decision' | 'resolution' | 'timeout' };
  };
  commitPrepared(token: string, receiptHash: string): unknown;
  abortPrepared(token: string, receiptHash: string, capability: typeof DEFINITIVE_NO_STORE): void;
  freezePrepared(token: string, receiptHash: string, reason?: string): void;
}

export interface StrictAdmissionV21Options {
  ingest_url: string;
  api_key: string;
  timeout_ms?: number;
  retry_deadline_ms?: number;
  max_attempts?: number;
  max_response_bytes?: number;
  retry_base_ms?: number;
  retry_max_ms?: number;
  resolver?: Resolver;
  /** Explicitly trusted test seam; production defaults to the DNS-pinned transport. */
  trusted_pinned_transport?: StrictAdmissionV21PinnedTransport;
  clock_ms?: () => number;
  sleep?: (delayMs: number) => Promise<void>;
  jitter?: () => number;
}

interface ResultBase {
  schema: typeof STRICT_RECEIPT_V21_ADMISSION_SCHEMA;
  tenant_id: string;
  session_id: string;
  receipt_hash: string;
  attempts: number;
}
export type StrictAdmissionV21Result =
  | (ResultBase & { disposition: 'accepted'; status: 'accepted' | 'already_accepted' })
  | (ResultBase & { disposition: 'definitive_no_store'; http_status: 400 | 401 | 403 | 413 })
  | (ResultBase & { disposition: 'uncertain'; reason: 'redirect' | 'conflict' | 'invalid_response' | 'retry_exhausted' | 'local_commit_failed' });

export class StrictAdmissionV21ValidationError extends Error {
  constructor(message: string) { super(message); this.name = 'StrictAdmissionV21ValidationError'; }
}

function positive(value: number | undefined, fallback: number, max: number, field: string): number {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result <= 0 || result > max) {
    throw new StrictAdmissionV21ValidationError(`${field} is outside its supported positive range`);
  }
  return result;
}
function text(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new StrictAdmissionV21ValidationError(`${field} must be nonblank`);
  }
  return value;
}
function endpoint(rawValue: string): { url: string; loopback: boolean } {
  const raw = text(rawValue, 'ingest_url'); let host = '';
  try { host = new URL(raw).hostname.replace(/^\[|\]$/g, '').toLowerCase(); } catch { /* static guard below */ }
  const loopback = LOCAL.has(host); let parsed: URL;
  try { parsed = assertBackendUrlStatic(raw, { allowPrivateNetwork: loopback }); } catch {
    throw new StrictAdmissionV21ValidationError('ingest_url failed static security validation');
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new StrictAdmissionV21ValidationError('ingest_url cannot contain credentials, query, or fragment');
  }
  if (parsed.protocol === 'http:' && !loopback) {
    throw new StrictAdmissionV21ValidationError('ingest_url must use HTTPS unless it targets loopback');
  }
  parsed.pathname = `${parsed.pathname.replace(/\/+$/, '')}${STRICT_RECEIPT_V21_ENDPOINT}`;
  return { url: parsed.toString(), loopback };
}
function identity(
  coordinator: StrictAdmissionV21Coordinator, prepared: PreparedDecisionV21,
): ResultBase {
  const state = coordinator.inspectState();
  if (state.frozen || !state.prepared || state.prepared.kind !== 'decision'
    || prepared.kind !== 'decision' || prepared.token !== state.prepared.token
    || prepared.receipt_hash !== state.prepared.receipt_hash) {
    throw new StrictAdmissionV21ValidationError('receipt is not the coordinator current prepared decision');
  }
  const receipt = prepared.value?.receipt; const body = receipt?.body;
  const verified = verifyStrictReceiptV21(receipt, {
    trusted_agent_keys: [], allowed_evaluator_manifest_hashes: [],
  });
  if (!verified.integrity_valid || body?.record_type !== 'decision'
    || body.profile_version !== '2.1' || !HEX64.test(receipt.receipt_hash)
    || receipt.receipt_hash !== prepared.receipt_hash
    || body.tenant_id !== state.tenant_id || body.session_id !== state.session_id) {
    throw new StrictAdmissionV21ValidationError('prepared receipt must be an intact strict profile-2.1 decision');
  }
  return { schema: STRICT_RECEIPT_V21_ADMISSION_SCHEMA,
    tenant_id: text(body.tenant_id, 'tenant_id'), session_id: text(body.session_id, 'session_id'),
    receipt_hash: receipt.receipt_hash, attempts: 0 };
}
function parse(bytes: Uint8Array | undefined, limit: number): Record<string, unknown> | undefined {
  if (!bytes?.byteLength || bytes.byteLength > limit) return undefined;
  try {
    const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown;
    return value !== null && typeof value === 'object' && !Array.isArray(value)
      ? value as Record<string, unknown> : undefined;
  } catch { return undefined; }
}
function accepted(value: Record<string, unknown> | undefined, hash: string): 'accepted' | 'already_accepted' | undefined {
  if (!value || Object.keys(value).sort().join(',') !== 'accepted_at_ms,ok,receipt_hash,schema,status'
    || value.schema !== STRICT_RECEIPT_V21_ADMISSION_SCHEMA || value.ok !== true
    || value.receipt_hash !== hash || !['accepted', 'already_accepted'].includes(value.status as string)
    || !Number.isSafeInteger(value.accepted_at_ms) || (value.accepted_at_ms as number) < 0) return undefined;
  return value.status as 'accepted' | 'already_accepted';
}
function noStore(value: Record<string, unknown> | undefined, hash: string): boolean {
  return !!value && Object.keys(value).sort().join(',') === 'code,ok,receipt_hash,schema,status,stored'
    && value.schema === STRICT_RECEIPT_V21_ADMISSION_SCHEMA && value.ok === false
    && value.status === 'rejected' && value.stored === false && value.receipt_hash === hash
    && typeof value.code === 'string' && value.code.length > 0;
}
function conflict(value: Record<string, unknown> | undefined, hash: string): boolean {
  return !!value && Object.keys(value).sort().join(',') === 'code,ok,receipt_hash,schema,status'
    && value.schema === STRICT_RECEIPT_V21_ADMISSION_SCHEMA && value.ok === false
    && value.status === 'conflict' && value.receipt_hash === hash
    && typeof value.code === 'string' && value.code.length > 0;
}
export function assertStrictAdmissionV21RequestBytes(body: string): void {
  if (Buffer.byteLength(body, 'utf8') > STRICT_RECEIPT_V21_MAX_REQUEST_BYTES) {
    throw new StrictAdmissionV21ValidationError('receipt ingest request exceeds its supported size');
  }
}
function finish(
  coordinator: StrictAdmissionV21Coordinator, prepared: PreparedDecisionV21,
  result: StrictAdmissionV21Result,
): StrictAdmissionV21Result {
  if (result.disposition === 'accepted') {
    try { coordinator.commitPrepared(prepared.token, prepared.receipt_hash); return result; } catch {
      coordinator.freezePrepared(prepared.token, prepared.receipt_hash, 'accepted_but_local_commit_failed');
      return { ...result, disposition: 'uncertain', reason: 'local_commit_failed' };
    }
  }
  if (result.disposition === 'definitive_no_store') {
    coordinator.abortPrepared(prepared.token, prepared.receipt_hash, DEFINITIVE_NO_STORE);
  } else coordinator.freezePrepared(prepared.token, prepared.receipt_hash, result.reason);
  return result;
}

/** @internal Transport only. The caller must reconcile the prepared coordinator state. */
export async function transportPreparedStrictReceiptV21(
  coordinator: StrictAdmissionV21Coordinator, prepared: PreparedDecisionV21,
  options: StrictAdmissionV21Options,
): Promise<StrictAdmissionV21Result> {
  const base = identity(coordinator, prepared); const location = endpoint(options.ingest_url);
  const apiKey = text(options.api_key, 'api_key');
  const timeout = positive(options.timeout_ms, 2_000, 60_000, 'timeout_ms');
  const deadline = positive(options.retry_deadline_ms, 10_000, 300_000, 'retry_deadline_ms');
  const maximum = positive(options.max_attempts, 3, 20, 'max_attempts');
  const responseLimit = positive(options.max_response_bytes, 65_536, MAX_RESPONSE_BYTES, 'max_response_bytes');
  const retryBase = positive(options.retry_base_ms, 100, 60_000, 'retry_base_ms');
  const retryMax = positive(options.retry_max_ms, 2_000, 60_000, 'retry_max_ms');
  const now = options.clock_ms ?? (() => performance.now());
  const sleep = options.sleep ?? ((ms: number) => new Promise((resolve) => setTimeout(resolve, ms)));
  const jitter = options.jitter ?? Math.random;
  const receipt = structuredClone(prepared.value.receipt);
  const body = canonicalJsonForHash({ schema: STRICT_RECEIPT_V21_INGEST_SCHEMA,
    tenant_id: base.tenant_id, session_id: base.session_id, receipt });
  assertStrictAdmissionV21RequestBytes(body);
  const headers = { 'Content-Type': 'application/json', 'X-API-Key': apiKey,
    'Idempotency-Key': base.receipt_hash };
  const started = now(); let attempts = 0;
  while (attempts < maximum && now() - started < deadline) {
    attempts += 1; const remaining = deadline - (now() - started);
    const controller = new AbortController(); let timer: ReturnType<typeof setTimeout> | undefined;
    const attempt = Promise.resolve().then(async () => {
      const target = await resolveBackendUrlAllowed(
        location.url, { allowPrivateNetwork: location.loopback }, options.resolver,
      );
      return (options.trusted_pinned_transport ?? postPinnedBytes)(
        target, body, headers, controller.signal, responseLimit,
      );
    }).catch(() => undefined);
    const expired = new Promise<undefined>((resolve) => {
      timer = setTimeout(() => { controller.abort(); resolve(undefined); }, Math.max(1, Math.min(timeout, remaining)));
    });
    const response = await Promise.race([attempt, expired]); if (timer) clearTimeout(timer);
    if (response) {
      if (response.status >= 300 && response.status < 400) {
        return { ...base, attempts, disposition: 'uncertain', reason: 'redirect' };
      }
      const retryable = RETRYABLE.has(response.status) || response.status >= 500;
      if (!retryable) {
        const value = parse(response.body, responseLimit);
        if (response.status >= 200 && response.status < 300) {
          const status = accepted(value, base.receipt_hash);
          return status
            ? { ...base, attempts, disposition: 'accepted', status }
            : { ...base, attempts, disposition: 'uncertain', reason: 'invalid_response' };
        }
        if (NO_STORE.has(response.status) && noStore(value, base.receipt_hash)) {
          return { ...base, attempts, disposition: 'definitive_no_store',
            http_status: response.status as 400 | 401 | 403 | 413 };
        }
        if (response.status === 409 && conflict(value, base.receipt_hash)) {
          return { ...base, attempts, disposition: 'uncertain', reason: 'conflict' };
        }
        return { ...base, attempts, disposition: 'uncertain', reason: 'invalid_response' };
      }
    }
    if (attempts >= maximum || now() - started >= deadline) break;
    const delay = Math.min(retryMax, retryBase * (2 ** (attempts - 1)));
    await sleep(Math.min(deadline - (now() - started), Math.floor(delay * jitter())));
  }
  return { ...base, attempts, disposition: 'uncertain', reason: 'retry_exhausted' };
}

export async function admitPreparedStrictReceiptV21(
  coordinator: StrictAdmissionV21Coordinator, prepared: PreparedDecisionV21,
  options: StrictAdmissionV21Options,
): Promise<StrictAdmissionV21Result> {
  return finish(
    coordinator, prepared,
    await transportPreparedStrictReceiptV21(coordinator, prepared, options),
  );
}
