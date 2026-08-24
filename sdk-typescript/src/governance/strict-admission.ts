import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import { postPinnedBytes, type PinnedHttpResponse } from '../utils/pinned-http.js';
import {
  assertBackendUrlStatic,
  resolveBackendUrlAllowed,
  type AllowedBackendTarget,
  type Resolver,
} from '../utils/ssrf.js';
import type { StrictReceiptEnvelope } from './strict-receipt.js';

export const STRICT_RECEIPT_INGEST_SCHEMA = 'obsvr-strict-receipt-ingest-v1' as const;
export const STRICT_RECEIPT_ADMISSION_SCHEMA = 'obsvr-strict-receipt-admission-v1' as const;

const HASH_RE = /^[0-9a-f]{64}$/;
const DEFINITIVE_NO_STORE = new Set([400, 401, 403, 413]);
const RETRYABLE = new Set([408, 429]);
const MAX_TIMEOUT_MS = 60_000;
const MAX_RETRY_DEADLINE_MS = 300_000;
const MAX_ATTEMPTS = 20;
const MAX_REQUEST_BYTES = 1_048_576;
const MAX_RESPONSE_BYTES = 1_048_576;
const MAX_RETRY_DELAY_MS = 60_000;
const LOCAL_INGEST_HOSTS = new Set(['localhost', '127.0.0.1', '::1']);

export interface StrictAdmissionOptions {
  ingest_url: string;
  api_key: string;
  timeout_ms?: number;
  retry_deadline_ms?: number;
  max_attempts?: number;
  max_response_bytes?: number;
  retry_base_ms?: number;
  retry_max_ms?: number;
  /** Explicitly trusted test seam. Production never falls back to global fetch. */
  trusted_fetch?: typeof fetch;
  /** Explicitly trusted test seam that still receives an approved DNS snapshot. */
  trusted_pinned_transport?: StrictAdmissionPinnedTransport;
  resolver?: Resolver;
  clock_ms?: () => number;
  sleep?: (delay_ms: number) => Promise<void>;
  jitter?: () => number;
}

export type StrictAdmissionPinnedTransport = (
  target: AllowedBackendTarget,
  body: string,
  headers: Readonly<Record<string, string>>,
  signal: AbortSignal,
  maxResponseBytes: number,
) => Promise<PinnedHttpResponse>;

export type StrictAdmissionResult =
  | {
      disposition: 'accepted';
      receipt_hash: string;
      status: 'accepted' | 'already_accepted';
      attempts: number;
    }
  | {
      disposition: 'definitive_no_store';
      receipt_hash: string;
      http_status: 400 | 401 | 403 | 413;
      attempts: number;
    }
  | {
      disposition: 'uncertain';
      receipt_hash: string;
      reason: 'redirect' | 'conflict' | 'invalid_response' | 'retry_exhausted';
      attempts: number;
    };

export class StrictAdmissionValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StrictAdmissionValidationError';
  }
}

function positiveInteger(
  value: number | undefined,
  fallback: number,
  maximum: number,
  field: string,
): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved <= 0 || resolved > maximum) {
    throw new StrictAdmissionValidationError(`${field} is outside its supported positive range`);
  }
  return resolved;
}

function nonblank(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new StrictAdmissionValidationError(`${field} must be a nonblank string`);
  }
  return value;
}

function endpoint(value: string): string {
  const raw = nonblank(value, 'ingest_url');
  let host = '';
  try {
    host = new URL(raw).hostname.replace(/^\[|\]$/g, '').toLowerCase();
  } catch {
    // The shared static guard below reports malformed URLs.
  }
  const isLocal = LOCAL_INGEST_HOSTS.has(host);
  let parsed: URL;
  try {
    parsed = assertBackendUrlStatic(raw, { allowPrivateNetwork: isLocal });
  } catch {
    throw new StrictAdmissionValidationError('ingest_url failed static security validation');
  }
  if (parsed.username !== '' || parsed.password !== ''
    || parsed.search !== '' || parsed.hash !== '') {
    throw new StrictAdmissionValidationError('ingest_url must be an absolute HTTP(S) URL without credentials, query, or fragment');
  }
  if (parsed.protocol === 'http:' && !isLocal) {
    throw new StrictAdmissionValidationError('ingest_url must use HTTPS unless it targets loopback');
  }
  parsed.pathname = `${parsed.pathname.replace(/\/+$/, '')}/ingest/strict-receipts`;
  return parsed.toString();
}

function receiptHash(receipt: StrictReceiptEnvelope): string {
  if (receipt === null || typeof receipt !== 'object'
    || receipt.schema !== 'obsvr-strict-receipt-envelope-v1'
    || typeof receipt.receipt_hash !== 'string' || !HASH_RE.test(receipt.receipt_hash)) {
    throw new StrictAdmissionValidationError('receipt must be a strict receipt envelope with a valid receipt_hash');
  }
  return receipt.receipt_hash;
}

async function readBounded(response: Response, limit: number): Promise<Uint8Array | undefined> {
  const declared = response.headers.get('content-length');
  if (declared !== null && (/^[0-9]+$/.test(declared) === false || Number(declared) > limit)) {
    return undefined;
  }
  if (response.body === null) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      try { await reader.cancel(); } catch { /* bounded result remains invalid */ }
      return undefined;
    }
    chunks.push(value);
  }
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

function parsedResult(bytes: Uint8Array | undefined): Record<string, unknown> | undefined {
  if (bytes === undefined || bytes.byteLength === 0) return undefined;
  try {
    const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown;
    return value !== null && typeof value === 'object' && !Array.isArray(value)
      ? value as Record<string, unknown>
      : undefined;
  } catch {
    return undefined;
  }
}

function acceptedResponse(
  response: Record<string, unknown> | undefined,
  expectedHash: string,
): 'accepted' | 'already_accepted' | undefined {
  if (response === undefined
    || Object.keys(response).sort().join(',') !== 'accepted_at_ms,ok,receipt_hash,schema,status'
    || response.schema !== STRICT_RECEIPT_ADMISSION_SCHEMA
    || response.ok !== true
    || response.receipt_hash !== expectedHash
    || (response.status !== 'accepted' && response.status !== 'already_accepted')
    || typeof response.accepted_at_ms !== 'number'
    || !Number.isSafeInteger(response.accepted_at_ms)
    || response.accepted_at_ms < 0) {
    return undefined;
  }
  return response.status;
}

function explicitNoStore(response: Record<string, unknown> | undefined, expectedHash: string): boolean {
  return response !== undefined
    && Object.keys(response).sort().join(',') === 'code,ok,receipt_hash,schema,status,stored'
    && response.schema === STRICT_RECEIPT_ADMISSION_SCHEMA
    && response.ok === false
    && response.receipt_hash === expectedHash
    && response.status === 'rejected'
    && typeof response.code === 'string'
    && response.code.length > 0
    && response.stored === false;
}

function explicitConflict(response: Record<string, unknown> | undefined, expectedHash: string): boolean {
  return response !== undefined
    && Object.keys(response).sort().join(',') === 'code,ok,receipt_hash,schema,status'
    && response.schema === STRICT_RECEIPT_ADMISSION_SCHEMA
    && response.ok === false
    && response.receipt_hash === expectedHash
    && response.status === 'conflict'
    && typeof response.code === 'string'
    && response.code.length > 0;
}

export async function admitStrictReceipt(
  receipt: StrictReceiptEnvelope,
  options: StrictAdmissionOptions,
): Promise<StrictAdmissionResult> {
  const hash = receiptHash(receipt);
  const url = endpoint(options.ingest_url);
  const apiKey = nonblank(options.api_key, 'api_key');
  const timeoutMs = positiveInteger(options.timeout_ms, 2_000, MAX_TIMEOUT_MS, 'timeout_ms');
  const deadlineMs = positiveInteger(
    options.retry_deadline_ms, 10_000, MAX_RETRY_DEADLINE_MS, 'retry_deadline_ms',
  );
  const maxAttempts = positiveInteger(options.max_attempts, 3, MAX_ATTEMPTS, 'max_attempts');
  const maxResponseBytes = positiveInteger(
    options.max_response_bytes, 65_536, MAX_RESPONSE_BYTES, 'max_response_bytes',
  );
  const retryBaseMs = positiveInteger(
    options.retry_base_ms, 100, MAX_RETRY_DELAY_MS, 'retry_base_ms',
  );
  const retryMaxMs = positiveInteger(
    options.retry_max_ms, 2_000, MAX_RETRY_DELAY_MS, 'retry_max_ms',
  );
  if (options.trusted_fetch !== undefined && typeof options.trusted_fetch !== 'function') {
    throw new StrictAdmissionValidationError('trusted_fetch must be a function');
  }
  if (options.trusted_pinned_transport !== undefined
    && typeof options.trusted_pinned_transport !== 'function') {
    throw new StrictAdmissionValidationError('trusted_pinned_transport must be a function');
  }
  const clock = options.clock_ms ?? (() => performance.now());
  const sleep = options.sleep ?? ((delay: number) => new Promise((resolve) => setTimeout(resolve, delay)));
  const jitter = options.jitter ?? Math.random;
  let body: string;
  try {
    body = canonicalJsonForHash({ schema: STRICT_RECEIPT_INGEST_SCHEMA, receipt });
  } catch {
    throw new StrictAdmissionValidationError('receipt cannot be serialized canonically');
  }
  if (Buffer.byteLength(body) > MAX_REQUEST_BYTES) {
    throw new StrictAdmissionValidationError('receipt ingest request exceeds its supported size');
  }
  const start = clock();
  let attempts = 0;
  const allowLoopback = LOCAL_INGEST_HOSTS.has(
    new URL(url).hostname.replace(/^\[|\]$/g, '').toLowerCase(),
  );
  const headers = {
    'Content-Type': 'application/json',
    'X-API-Key': apiKey,
    'Idempotency-Key': hash,
  };

  while (attempts < maxAttempts && clock() - start < deadlineMs) {
    attempts += 1;
    const remaining = deadlineMs - (clock() - start);
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const requestAttempt = Promise.resolve().then(async (): Promise<PinnedHttpResponse> => {
      if (options.trusted_fetch !== undefined) {
        const response = await options.trusted_fetch(url, {
          method: 'POST', redirect: 'manual', headers, body, signal: controller.signal,
        });
        return {
          status: response.status,
          body: await readBounded(response, maxResponseBytes),
        };
      }
      const target = await resolveBackendUrlAllowed(
        url, { allowPrivateNetwork: allowLoopback }, options.resolver,
      );
      const transport = options.trusted_pinned_transport ?? postPinnedBytes;
      return transport(target, body, headers, controller.signal, maxResponseBytes);
    }).catch(() => undefined);
    const timeoutAttempt = new Promise<undefined>((resolve) => {
      timer = setTimeout(() => {
        controller.abort();
        resolve(undefined);
      }, Math.max(1, Math.min(timeoutMs, remaining)));
    });
    const response = await Promise.race([requestAttempt, timeoutAttempt]);
    if (timer !== undefined) clearTimeout(timer);

    if (response !== undefined) {
      if (response.status >= 300 && response.status < 400) {
        return { disposition: 'uncertain', receipt_hash: hash, reason: 'redirect', attempts };
      }
      const retryable = RETRYABLE.has(response.status) || response.status >= 500;
      if (!retryable) {
        let parsed: Record<string, unknown> | undefined;
        try {
          parsed = parsedResult(response.body);
        } catch {
          return { disposition: 'uncertain', receipt_hash: hash, reason: 'invalid_response', attempts };
        }
        if (response.status >= 200 && response.status < 300) {
          const status = acceptedResponse(parsed, hash);
          return status === undefined
            ? { disposition: 'uncertain', receipt_hash: hash, reason: 'invalid_response', attempts }
            : { disposition: 'accepted', receipt_hash: hash, status, attempts };
        }
        if (DEFINITIVE_NO_STORE.has(response.status) && explicitNoStore(parsed, hash)) {
          return {
            disposition: 'definitive_no_store', receipt_hash: hash,
            http_status: response.status as 400 | 401 | 403 | 413, attempts,
          };
        }
        if (response.status === 409) {
          return {
            disposition: 'uncertain', receipt_hash: hash,
            reason: explicitConflict(parsed, hash) ? 'conflict' : 'invalid_response', attempts,
          };
        }
        if (!RETRYABLE.has(response.status) && response.status < 500) {
          return { disposition: 'uncertain', receipt_hash: hash, reason: 'invalid_response', attempts };
        }
      }
    }

    if (attempts >= maxAttempts || clock() - start >= deadlineMs) break;
    const rawJitter = jitter();
    if (!Number.isFinite(rawJitter) || rawJitter < 0 || rawJitter > 1) {
      throw new StrictAdmissionValidationError('jitter must return a number from 0 through 1');
    }
    const ceiling = Math.min(retryMaxMs, retryBaseMs * (2 ** (attempts - 1)));
    const delay = Math.floor(ceiling * (0.5 + rawJitter / 2));
    const budget = deadlineMs - (clock() - start);
    if (budget <= 0) break;
    await sleep(Math.min(delay, budget));
  }
  return { disposition: 'uncertain', receipt_hash: hash, reason: 'retry_exhausted', attempts };
}
