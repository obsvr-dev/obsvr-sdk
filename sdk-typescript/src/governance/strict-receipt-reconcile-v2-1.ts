import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import { postPinnedBytes } from '../utils/pinned-http.js';
import { assertBackendUrlStatic, resolveBackendUrlAllowed } from '../utils/ssrf.js';
import type { StrictAdmissionV21Options } from './strict-admission-v2-1.js';
import {
  STRICT_RECEIPT_V21_INGEST_SCHEMA, STRICT_RECEIPT_V21_MAX_REQUEST_BYTES,
} from './strict-admission-v2-1.js';
import type { StrictReceiptV21Envelope } from './strict-receipt-v2-1.js';
import { verifyStrictReceiptV21 } from './strict-receipt-v2-1-verify.js';

export const STRICT_RECONCILIATION_V21_SCHEMA = 'obsvr-strict-receipt-reconciliation-v2-1' as const;
export const STRICT_RECONCILIATION_V21_ENDPOINT = '/ingest/strict-receipts/v2-1/reconcile' as const;
const acceptedProofs = new WeakSet<object>(); const LOCAL = new Set(['localhost', '127.0.0.1', '::1']);
const MAX_RESPONSE_BYTES = 1_048_576;

export type StrictReconciliationV21Result =
  | { schema: typeof STRICT_RECONCILIATION_V21_SCHEMA; status: 'accepted'; tenant_id: string;
    session_id: string; receipt_hash: string; accepted_at_ms: number; attempts: number }
  | { schema: typeof STRICT_RECONCILIATION_V21_SCHEMA; status: 'absent' | 'conflict' | 'unknown';
    tenant_id: string; session_id: string; receipt_hash: string; attempts: number; reason?: string };

function endpoint(raw: string): { url: string; loopback: boolean } {
  let host = ''; try { host = new URL(raw).hostname.replace(/^\[|\]$/g, '').toLowerCase(); } catch { /* guard */ }
  const loopback = LOCAL.has(host); const parsed = assertBackendUrlStatic(raw, { allowPrivateNetwork: loopback });
  if (parsed.username || parsed.password || parsed.search || parsed.hash || (parsed.protocol === 'http:' && !loopback)) {
    throw new Error('invalid reconciliation URL');
  }
  parsed.pathname = `${parsed.pathname.replace(/\/+$/, '')}${STRICT_RECONCILIATION_V21_ENDPOINT}`;
  return { url: parsed.toString(), loopback };
}
function parse(bytes: Uint8Array | undefined, limit: number): Record<string, unknown> | undefined {
  if (!bytes?.length || bytes.length > limit) return undefined;
  try { const value = JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(bytes)) as unknown;
    return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
  } catch { return undefined; }
}
function positive(value: number | undefined, fallback: number, max: number, field: string): number {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result <= 0 || result > max) throw new Error(`${field} is outside its supported positive range`);
  return result;
}
function observation(receipt: StrictReceiptV21Envelope, attempts: number,
  status: 'absent' | 'conflict' | 'unknown', reason?: string): StrictReconciliationV21Result {
  return { schema: STRICT_RECONCILIATION_V21_SCHEMA, status,
    tenant_id: receipt.body.tenant_id, session_id: receipt.body.session_id,
    receipt_hash: receipt.receipt_hash, attempts, ...(reason ? { reason } : {}) };
}
function validateReceipt(receipt: StrictReceiptV21Envelope): void {
  const verified = verifyStrictReceiptV21(receipt, { trusted_agent_keys: [], allowed_evaluator_manifest_hashes: [] });
  if (!verified.integrity_valid || !['decision', 'resolution'].includes(receipt.body.record_type)
    || receipt.body.profile_version !== '2.1') throw new Error('receipt must be an intact profile-2.1 decision');
}

export async function reconcileStrictReceiptV21(
  receipt: StrictReceiptV21Envelope, options: StrictAdmissionV21Options,
): Promise<StrictReconciliationV21Result> {
  validateReceipt(receipt); const location = endpoint(options.ingest_url);
  if (typeof options.api_key !== 'string' || !options.api_key.trim()) throw new Error('api_key must be nonblank');
  const body = canonicalJsonForHash({ schema: STRICT_RECEIPT_V21_INGEST_SCHEMA,
    tenant_id: receipt.body.tenant_id, session_id: receipt.body.session_id, receipt });
  if (Buffer.byteLength(body, 'utf8') > STRICT_RECEIPT_V21_MAX_REQUEST_BYTES) throw new Error('reconciliation request exceeds its supported size');
  const maximum = positive(options.max_attempts, 3, 20, 'max_attempts');
  const timeout = positive(options.timeout_ms, 2_000, 60_000, 'timeout_ms');
  const responseLimit = positive(options.max_response_bytes, 65_536, MAX_RESPONSE_BYTES, 'max_response_bytes');
  const headers = { 'Content-Type': 'application/json', 'X-API-Key': options.api_key,
    'Idempotency-Key': receipt.receipt_hash };
  for (let attempts = 1; attempts <= maximum; attempts += 1) {
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), timeout);
    try {
      const target = await resolveBackendUrlAllowed(location.url,
        { allowPrivateNetwork: location.loopback }, options.resolver);
      const response = await (options.trusted_pinned_transport ?? postPinnedBytes)(
        target, body, headers, controller.signal, responseLimit,
      );
      const value = parse(response.body, responseLimit); const keys = value ? Object.keys(value).sort().join(',') : '';
      if (response.status === 200 && keys === 'accepted_at_ms,ok,receipt_hash,schema,session_id,status'
        && value?.schema === STRICT_RECONCILIATION_V21_SCHEMA && value.ok === true
        && value.status === 'accepted' && value.receipt_hash === receipt.receipt_hash
        && value.session_id === receipt.body.session_id && Number.isSafeInteger(value.accepted_at_ms)
        && (value.accepted_at_ms as number) >= 0) {
        const accepted: StrictReconciliationV21Result = { schema: STRICT_RECONCILIATION_V21_SCHEMA,
          status: 'accepted', tenant_id: receipt.body.tenant_id, session_id: receipt.body.session_id,
          receipt_hash: receipt.receipt_hash, accepted_at_ms: value.accepted_at_ms as number, attempts };
        acceptedProofs.add(accepted); return accepted;
      }
      if (response.status === 404 && keys === 'ok,receipt_hash,schema,session_id,status'
        && value?.schema === STRICT_RECONCILIATION_V21_SCHEMA && value.ok === true
        && value.status === 'absent' && value.receipt_hash === receipt.receipt_hash
        && value.session_id === receipt.body.session_id) return observation(receipt, attempts, 'absent');
      if (response.status === 409) return observation(receipt, attempts, 'conflict');
      if (response.status < 500 && response.status !== 408 && response.status !== 429) {
        return observation(receipt, attempts, 'unknown', 'invalid_response');
      }
    } catch { /* an ambiguous attempt is retryable */ } finally { clearTimeout(timer); }
    if (attempts < maximum) await (options.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms))))(0);
  }
  return observation(receipt, maximum, 'unknown', 'retry_exhausted');
}

export function assertAcceptedStrictReconciliationV21(
  value: StrictReconciliationV21Result, receipt: StrictReceiptV21Envelope,
): void {
  if (!acceptedProofs.has(value) || value.status !== 'accepted'
    || value.tenant_id !== receipt.body.tenant_id || value.session_id !== receipt.body.session_id
    || value.receipt_hash !== receipt.receipt_hash) throw new Error('trusted accepted profile-2.1 reconciliation is required');
}
