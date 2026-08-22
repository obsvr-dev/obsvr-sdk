import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import { postPinnedBytes } from '../utils/pinned-http.js';
import { assertBackendUrlStatic, resolveBackendUrlAllowed } from '../utils/ssrf.js';
import type { StrictAdmissionV2Options } from './strict-admission-v2.js';
import type { StrictReceiptV2Envelope } from './strict-receipt-v2.js';

export const STRICT_RECONCILIATION_V2_SCHEMA = 'obsvr-strict-receipt-reconciliation-v2' as const;
export const STRICT_RECONCILIATION_V2_ENDPOINT = '/ingest/strict-receipts/v2/reconcile' as const;
const acceptedProofs = new WeakSet<object>();
const LOCAL = new Set(['localhost', '127.0.0.1', '::1']);
const HEX64 = /^[0-9a-f]{64}$/;
const MAX_REQUEST_BYTES = 1_048_576;
const MAX_RESPONSE_BYTES = 1_048_576;

export type StrictReconciliationV2Result =
  | { schema: typeof STRICT_RECONCILIATION_V2_SCHEMA; status: 'accepted';
    tenant_id: string; session_id: string; receipt_hash: string; accepted_at_ms: number; attempts: number }
  | { schema: typeof STRICT_RECONCILIATION_V2_SCHEMA; status: 'absent' | 'conflict' | 'unknown';
    tenant_id: string; session_id: string; receipt_hash: string; attempts: number; reason?: string };

function endpoint(raw: string): { url: string; loopback: boolean } {
  let host = '';
  try { host = new URL(raw).hostname.replace(/^\[|\]$/g, '').toLowerCase(); } catch { /* static guard */ }
  const loopback = LOCAL.has(host);
  const parsed = assertBackendUrlStatic(raw, { allowPrivateNetwork: loopback });
  if (parsed.username || parsed.password || parsed.search || parsed.hash
    || (parsed.protocol === 'http:' && !loopback)) throw new Error('invalid reconciliation URL');
  parsed.pathname = `${parsed.pathname.replace(/\/+$/, '')}${STRICT_RECONCILIATION_V2_ENDPOINT}`;
  return { url: parsed.toString(), loopback };
}
function parse(raw: Uint8Array | undefined): Record<string, unknown> | undefined {
  if (!raw?.length) return undefined;
  try {
    const value = JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(raw)) as unknown;
    return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
  } catch { return undefined; }
}
function result(receipt: StrictReceiptV2Envelope, attempts: number,
  status: 'absent' | 'conflict' | 'unknown', reason?: string): StrictReconciliationV2Result {
  return { schema: STRICT_RECONCILIATION_V2_SCHEMA, status,
    tenant_id: receipt.body.tenant_id, session_id: receipt.body.session_id,
    receipt_hash: receipt.receipt_hash, attempts, ...(reason ? { reason } : {}) };
}
function positive(value: number | undefined, fallback: number, maximum: number, field: string): number {
  const normalized = value ?? fallback;
  if (!Number.isSafeInteger(normalized) || normalized <= 0 || normalized > maximum) {
    throw new Error(`${field} is outside its supported positive range`);
  }
  return normalized;
}
function validateReceipt(receipt: StrictReceiptV2Envelope): void {
  if (receipt?.schema !== 'obsvr-strict-receipt-envelope-v2'
    || receipt.body?.schema !== 'obsvr-strict-receipt-v2'
    || typeof receipt.body.tenant_id !== 'string' || !receipt.body.tenant_id.trim()
    || typeof receipt.body.session_id !== 'string' || !receipt.body.session_id.trim()
    || !HEX64.test(receipt.receipt_hash)) throw new Error('receipt must be a valid strict v2 envelope');
}

export async function reconcileStrictReceiptV2(
  receipt: StrictReceiptV2Envelope, options: StrictAdmissionV2Options,
): Promise<StrictReconciliationV2Result> {
  validateReceipt(receipt);
  const location = endpoint(options.ingest_url);
  if (typeof options.api_key !== 'string' || !options.api_key.trim()) throw new Error('api_key must be nonblank');
  const body = canonicalJsonForHash({ schema: 'obsvr-strict-receipt-ingest-v2',
    tenant_id: receipt.body.tenant_id, session_id: receipt.body.session_id, receipt });
  if (Buffer.byteLength(body, 'utf8') > MAX_REQUEST_BYTES) throw new Error('reconciliation request exceeds its supported size');
  const attemptsMax = positive(options.max_attempts, 3, 20, 'max_attempts');
  const timeoutMs = positive(options.timeout_ms, 2_000, 60_000, 'timeout_ms');
  const responseBytes = positive(options.max_response_bytes, 65_536,
    MAX_RESPONSE_BYTES, 'max_response_bytes');
  const headers = { 'Content-Type': 'application/json', 'X-API-Key': options.api_key,
    'Idempotency-Key': receipt.receipt_hash };
  for (let attempts = 1; attempts <= attemptsMax; attempts += 1) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const target = await resolveBackendUrlAllowed(
        location.url, { allowPrivateNetwork: location.loopback }, options.resolver,
      );
      const transport = options.trusted_pinned_transport ?? postPinnedBytes;
      const response = await transport(target, body, headers, controller.signal,
        responseBytes);
      const value = parse(response.body);
      if (response.status === 200 && value
        && Object.keys(value).sort().join(',') === 'accepted_at_ms,ok,receipt_hash,schema,session_id,status'
        && value.schema === STRICT_RECONCILIATION_V2_SCHEMA && value.ok === true
        && value.status === 'accepted'
        && value.receipt_hash === receipt.receipt_hash && value.session_id === receipt.body.session_id
        && Number.isSafeInteger(value.accepted_at_ms) && (value.accepted_at_ms as number) >= 0) {
        const accepted: StrictReconciliationV2Result = { schema: STRICT_RECONCILIATION_V2_SCHEMA,
          status: 'accepted', tenant_id: receipt.body.tenant_id, session_id: receipt.body.session_id,
          receipt_hash: receipt.receipt_hash, accepted_at_ms: value.accepted_at_ms as number, attempts };
        acceptedProofs.add(accepted); return accepted;
      }
      if (response.status === 404 && value
        && Object.keys(value).sort().join(',') === 'ok,receipt_hash,schema,session_id,status'
        && value.schema === STRICT_RECONCILIATION_V2_SCHEMA && value.ok === true
        && value.receipt_hash === receipt.receipt_hash
        && value.session_id === receipt.body.session_id && value.status === 'absent') return result(receipt, attempts, 'absent');
      if (response.status === 409) return result(receipt, attempts, 'conflict');
      if (response.status < 500 && response.status !== 408 && response.status !== 429) return result(receipt, attempts, 'unknown', 'invalid_response');
    } catch { /* ambiguous attempt remains retryable */ } finally { clearTimeout(timer); }
    if (attempts < attemptsMax) await (options.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms))))(0);
  }
  return result(receipt, attemptsMax, 'unknown', 'retry_exhausted');
}

export function assertAcceptedStrictReconciliationV2(
  value: StrictReconciliationV2Result, receipt: StrictReceiptV2Envelope,
): void {
  if (!acceptedProofs.has(value) || value.status !== 'accepted'
    || value.tenant_id !== receipt.body.tenant_id || value.session_id !== receipt.body.session_id
    || value.receipt_hash !== receipt.receipt_hash) throw new Error('trusted accepted reconciliation is required');
}
