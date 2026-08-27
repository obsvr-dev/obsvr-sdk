import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import { postPinnedBytes, type PinnedHttpResponse } from '../utils/pinned-http.js';
import {
  assertBackendUrlStatic, resolveBackendUrlAllowed,
  type AllowedBackendTarget, type Resolver,
} from '../utils/ssrf.js';
import {
  verifyStrictExecutionOutcomeV21,
  type StrictExecutionOutcomeV21Envelope,
} from './strict-execution-outcome-v2-1.js';
import type { StrictReceiptV21Envelope } from './strict-receipt-v2-1.js';
import type { StrictReceiptV21TrustOptions } from './strict-receipt-v2-1-verify.js';
import {
  reconcileStrictRuntimeExecutionV21,
} from './strict-runtime-recovery-v2-1.js';
import type { StrictRuntimeExecutionJournalV21 } from './strict-receipt-runtime-v2-1-types.js';

export const STRICT_EXECUTION_OUTCOME_V21_INGEST_SCHEMA =
  'obsvr-strict-execution-outcome-ingest-v2-1' as const;
export const STRICT_EXECUTION_OUTCOME_V21_ADMISSION_SCHEMA =
  'obsvr-strict-execution-outcome-admission-v2-1' as const;
export const STRICT_EXECUTION_OUTCOME_V21_ENDPOINT =
  '/ingest/strict-execution-outcomes/v2-1' as const;
export const STRICT_EXECUTION_OUTCOME_V21_MAX_REQUEST_BYTES = 262_144 as const;

const NO_STORE = new Set([400, 401, 403, 413]);
const RETRYABLE = new Set([408, 429]);
const LOCAL = new Set(['localhost', '127.0.0.1', '::1']);
const MAX_RESPONSE_BYTES = 1_048_576;

export type StrictExecutionOutcomeV21PinnedTransport = (
  target: AllowedBackendTarget,
  body: string,
  headers: Readonly<Record<string, string>>,
  signal: AbortSignal,
  maxResponseBytes: number,
) => Promise<PinnedHttpResponse>;

export interface StrictExecutionOutcomeV21TransportOptions {
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
  trusted_pinned_transport?: StrictExecutionOutcomeV21PinnedTransport;
  clock_ms?: () => number;
  sleep?: (delayMs: number) => Promise<void>;
  jitter?: () => number;
}

interface ResultBase {
  schema: typeof STRICT_EXECUTION_OUTCOME_V21_ADMISSION_SCHEMA;
  tenant_id: string;
  session_id: string;
  outcome_hash: string;
  attempts: number;
}

export type StrictExecutionOutcomeV21TransportResult =
  | (ResultBase & { disposition: 'accepted'; status: 'accepted' | 'already_accepted' })
  | (ResultBase & { disposition: 'definitive_no_store'; http_status: 400 | 401 | 403 | 413 })
  | (ResultBase & {
      disposition: 'uncertain';
      reason: 'redirect' | 'conflict' | 'invalid_response' | 'retry_exhausted';
    });

export class StrictExecutionOutcomeV21TransportError extends Error {
  constructor(message: string) {
    super(message); this.name = 'StrictExecutionOutcomeV21TransportError';
  }
}

function positive(value: number | undefined, fallback: number, max: number, field: string): number {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result <= 0 || result > max) {
    throw new StrictExecutionOutcomeV21TransportError(`${field} is outside its supported positive range`);
  }
  return result;
}

function text(value: unknown, field: string): string {
  if (typeof value !== 'string' || !value.trim()) {
    throw new StrictExecutionOutcomeV21TransportError(`${field} must be nonblank`);
  }
  return value;
}

function endpoint(rawValue: string): { url: string; loopback: boolean } {
  const raw = text(rawValue, 'ingest_url'); let host = '';
  try { host = new URL(raw).hostname.replace(/^\[|\]$/g, '').toLowerCase(); } catch { /* guard below */ }
  const loopback = LOCAL.has(host); let parsed: URL;
  try { parsed = assertBackendUrlStatic(raw, { allowPrivateNetwork: loopback }); } catch {
    throw new StrictExecutionOutcomeV21TransportError('ingest_url failed static security validation');
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new StrictExecutionOutcomeV21TransportError(
      'ingest_url cannot contain credentials, query, or fragment',
    );
  }
  if (parsed.protocol === 'http:' && !loopback) {
    throw new StrictExecutionOutcomeV21TransportError(
      'ingest_url must use HTTPS unless it targets loopback',
    );
  }
  parsed.pathname = `${parsed.pathname.replace(/\/+$/, '')}${STRICT_EXECUTION_OUTCOME_V21_ENDPOINT}`;
  return { url: parsed.toString(), loopback };
}

function parse(bytes: Uint8Array | undefined, limit: number): Record<string, unknown> | undefined {
  if (!bytes?.byteLength || bytes.byteLength > limit) return undefined;
  try {
    const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown;
    return value !== null && typeof value === 'object' && !Array.isArray(value)
      ? value as Record<string, unknown> : undefined;
  } catch { return undefined; }
}

function accepted(
  value: Record<string, unknown> | undefined,
  outcomeHash: string,
): 'accepted' | 'already_accepted' | undefined {
  if (!value || Object.keys(value).sort().join(',') !== 'accepted_at_ms,ok,outcome_hash,schema,status'
    || value.schema !== STRICT_EXECUTION_OUTCOME_V21_ADMISSION_SCHEMA || value.ok !== true
    || value.outcome_hash !== outcomeHash
    || !['accepted', 'already_accepted'].includes(value.status as string)
    || !Number.isSafeInteger(value.accepted_at_ms) || (value.accepted_at_ms as number) < 0) return undefined;
  return value.status as 'accepted' | 'already_accepted';
}

function rejected(
  value: Record<string, unknown> | undefined,
  outcomeHash: string,
  status: 'rejected' | 'conflict',
): boolean {
  return !!value
    && Object.keys(value).sort().join(',') === 'code,ok,outcome_hash,schema,status'
    && value.schema === STRICT_EXECUTION_OUTCOME_V21_ADMISSION_SCHEMA
    && value.ok === false && value.status === status && value.outcome_hash === outcomeHash
    && typeof value.code === 'string' && value.code.length > 0;
}

export function assertStrictExecutionOutcomeV21RequestBytes(body: string): void {
  if (Buffer.byteLength(body, 'utf8') > STRICT_EXECUTION_OUTCOME_V21_MAX_REQUEST_BYTES) {
    throw new StrictExecutionOutcomeV21TransportError(
      'execution outcome ingest request exceeds its supported size',
    );
  }
}

export async function submitStrictExecutionOutcomeV21(
  outcome: StrictExecutionOutcomeV21Envelope,
  decision: StrictReceiptV21Envelope,
  options: StrictExecutionOutcomeV21TransportOptions,
  trust: StrictReceiptV21TrustOptions = {
    trusted_agent_keys: [], allowed_evaluator_manifest_hashes: [],
  },
): Promise<StrictExecutionOutcomeV21TransportResult> {
  const verification = verifyStrictExecutionOutcomeV21(outcome, decision, trust);
  if (!verification.integrity_valid) {
    throw new StrictExecutionOutcomeV21TransportError(
      'execution outcome must be intact and bound to its decision receipt',
    );
  }
  const base: ResultBase = {
    schema: STRICT_EXECUTION_OUTCOME_V21_ADMISSION_SCHEMA,
    tenant_id: text(outcome.body.tenant_id, 'tenant_id'),
    session_id: text(outcome.body.session_id, 'session_id'),
    outcome_hash: outcome.outcome_hash,
    attempts: 0,
  };
  const location = endpoint(options.ingest_url);
  const apiKey = text(options.api_key, 'api_key');
  const timeout = positive(options.timeout_ms, 2_000, 60_000, 'timeout_ms');
  const deadline = positive(options.retry_deadline_ms, 10_000, 300_000, 'retry_deadline_ms');
  const maximum = positive(options.max_attempts, 3, 20, 'max_attempts');
  const responseLimit = positive(options.max_response_bytes, 65_536, MAX_RESPONSE_BYTES,
    'max_response_bytes');
  const retryBase = positive(options.retry_base_ms, 100, 60_000, 'retry_base_ms');
  const retryMax = positive(options.retry_max_ms, 2_000, 60_000, 'retry_max_ms');
  const now = options.clock_ms ?? (() => performance.now());
  const sleep = options.sleep ?? ((ms: number) => new Promise((resolve) => setTimeout(resolve, ms)));
  const jitter = options.jitter ?? Math.random;
  const body = canonicalJsonForHash({
    schema: STRICT_EXECUTION_OUTCOME_V21_INGEST_SCHEMA,
    tenant_id: base.tenant_id,
    session_id: base.session_id,
    outcome: structuredClone(outcome),
  });
  assertStrictExecutionOutcomeV21RequestBytes(body);
  const headers = {
    'Content-Type': 'application/json', 'X-API-Key': apiKey,
    'Idempotency-Key': base.outcome_hash,
  };
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
      timer = setTimeout(() => { controller.abort(); resolve(undefined); },
        Math.max(1, Math.min(timeout, remaining)));
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
          const status = accepted(value, base.outcome_hash);
          return status
            ? { ...base, attempts, disposition: 'accepted', status }
            : { ...base, attempts, disposition: 'uncertain', reason: 'invalid_response' };
        }
        if (NO_STORE.has(response.status) && rejected(value, base.outcome_hash, 'rejected')) {
          return { ...base, attempts, disposition: 'definitive_no_store',
            http_status: response.status as 400 | 401 | 403 | 413 };
        }
        if (response.status === 409 && rejected(value, base.outcome_hash, 'conflict')) {
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

export async function submitStrictRuntimeTerminalJournalV21(
  journal: StrictRuntimeExecutionJournalV21,
  options: StrictExecutionOutcomeV21TransportOptions,
  trust: StrictReceiptV21TrustOptions = {
    trusted_agent_keys: [], allowed_evaluator_manifest_hashes: [],
  },
): Promise<StrictExecutionOutcomeV21TransportResult> {
  const recovered = reconcileStrictRuntimeExecutionV21(journal, undefined, trust);
  if (recovered.status !== 'resolved' || !recovered.journal.execution_outcome) {
    throw new StrictExecutionOutcomeV21TransportError(
      'runtime journal does not contain a signed terminal execution outcome',
    );
  }
  return submitStrictExecutionOutcomeV21(
    recovered.journal.execution_outcome, recovered.journal.receipt, options, trust,
  );
}
