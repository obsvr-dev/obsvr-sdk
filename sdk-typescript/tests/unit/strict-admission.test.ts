import { jest } from '@jest/globals';
import type { StrictReceiptEnvelope } from '../../src/governance/strict-receipt';
import { canonicalJsonForHash } from '../../src/policy/tool-pinning';
import {
  STRICT_RECEIPT_ADMISSION_SCHEMA,
  STRICT_RECEIPT_INGEST_SCHEMA,
  StrictAdmissionValidationError,
  admitStrictReceipt,
} from '../../src/governance/strict-admission';

const RECEIPT_HASH = 'a'.repeat(64);
const receipt = {
  schema: 'obsvr-strict-receipt-envelope-v1',
  body: { receipt_id: 'session:1' },
  receipt_hash: RECEIPT_HASH,
  signature: { algorithm: 'Ed25519', key_id: `sha256:${'b'.repeat(64)}`, value: 'c'.repeat(128) },
} as unknown as StrictReceiptEnvelope;

function admission(
  status: 'accepted' | 'already_accepted' = 'accepted',
  hash = RECEIPT_HASH,
): Record<string, unknown> {
  return {
    schema: STRICT_RECEIPT_ADMISSION_SCHEMA, ok: true, status,
    receipt_hash: hash, accepted_at_ms: 1_700_000_000_000,
  };
}

function rejection(hash = RECEIPT_HASH): Record<string, unknown> {
  return {
    schema: STRICT_RECEIPT_ADMISSION_SCHEMA, ok: false, status: 'rejected',
    code: 'not_authorized', stored: false, receipt_hash: hash,
  };
}

function response(status: number, value: unknown, headers?: Record<string, string>): Response {
  return new Response(typeof value === 'string' ? value : JSON.stringify(value), { status, headers });
}

function deterministic(fetchFn: typeof fetch, overrides: Record<string, unknown> = {}) {
  let now = 0;
  return {
    ingest_url: 'https://ingest.example.test/base/',
    api_key: 'top-secret-test-key',
    fetch: fetchFn,
    clock_ms: () => now,
    sleep: async (delay: number) => { now += delay; },
    jitter: () => 0,
    retry_base_ms: 2,
    retry_deadline_ms: 100,
    timeout_ms: 10,
    ...overrides,
  };
}

describe('strict receipt admission transport', () => {
  it('retries byte-identically with one idempotency key', async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const fetchFn = jest.fn(async (url: string | URL | Request, init?: RequestInit) => {
      calls.push({ url: String(url), init: init as RequestInit });
      return calls.length === 1
        ? response(503, { unavailable: true })
        : response(200, admission());
    }) as unknown as typeof fetch;

    const result = await admitStrictReceipt(receipt, deterministic(fetchFn));

    expect(result).toEqual({
      disposition: 'accepted', receipt_hash: RECEIPT_HASH, status: 'accepted', attempts: 2,
    });
    expect(calls.map((call) => call.init.body)).toEqual([calls[0].init.body, calls[0].init.body]);
    expect(calls[0].init.body).toBe(canonicalJsonForHash({
      schema: STRICT_RECEIPT_INGEST_SCHEMA, receipt,
    }));
    expect(calls.map((call) => (call.init.headers as Record<string, string>)['Idempotency-Key']))
      .toEqual([RECEIPT_HASH, RECEIPT_HASH]);
    expect(calls[0].url).toBe('https://ingest.example.test/base/ingest/strict-receipts');
    expect(calls[0].init.redirect).toBe('manual');
  });

  it('treats a duplicate ACK after a lost ACK as accepted', async () => {
    let count = 0;
    const fetchFn = jest.fn(async () => {
      count += 1;
      if (count === 1) throw new Error('connection lost after write');
      return response(200, admission('already_accepted'));
    }) as unknown as typeof fetch;
    await expect(admitStrictReceipt(receipt, deterministic(fetchFn))).resolves.toEqual({
      disposition: 'accepted', receipt_hash: RECEIPT_HASH,
      status: 'already_accepted', attempts: 2,
    });
  });

  it('allows loopback HTTP and preserves the normalized base path', async () => {
    const urls: string[] = [];
    const fetchFn = jest.fn(async (url: string | URL | Request) => {
      urls.push(String(url));
      return response(200, admission());
    }) as unknown as typeof fetch;
    await expect(admitStrictReceipt(receipt, deterministic(fetchFn, {
      ingest_url: 'http://localhost:8787/base/',
    }))).resolves.toMatchObject({ disposition: 'accepted' });
    expect(urls).toEqual(['http://localhost:8787/base/ingest/strict-receipts']);
  });

  it('refuses plaintext HTTP off loopback without exposing URL material', async () => {
    const fetchFn = jest.fn() as unknown as typeof fetch;
    const sentinel = 'sentinel-url-secret';
    try {
      await admitStrictReceipt(receipt, deterministic(fetchFn, {
        ingest_url: `http://ingest.example.test/${sentinel}`,
      }));
      throw new Error('expected validation to fail');
    } catch (error) {
      expect(error).toBeInstanceOf(StrictAdmissionValidationError);
      expect(String(error)).not.toContain(sentinel);
    }
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it.each([
    'http://169.254.169.254/latest/meta-data',
    'https://169.254.1.2/collector',
    'https://10.0.0.5/collector',
  ])('refuses a statically unsafe literal target: %s', async (ingestUrl) => {
    const fetchFn = jest.fn() as unknown as typeof fetch;
    await expect(admitStrictReceipt(receipt, deterministic(fetchFn, {
      ingest_url: ingestUrl,
    }))).rejects.toBeInstanceOf(StrictAdmissionValidationError);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('freezes on a mismatched success hash', async () => {
    const fetchFn = jest.fn(async () => response(200, admission('accepted', 'd'.repeat(64)))) as unknown as typeof fetch;
    await expect(admitStrictReceipt(receipt, deterministic(fetchFn))).resolves.toEqual({
      disposition: 'uncertain', receipt_hash: RECEIPT_HASH, reason: 'invalid_response', attempts: 1,
    });
  });

  it.each([
    ['malformed', response(200, '{')],
    ['oversized', response(200, admission(), { 'Content-Length': '1000' })],
    ['additive field', response(200, { ...admission(), extra: true })],
  ])('freezes on a %s response', async (_name, returned) => {
    const fetchFn = jest.fn(async () => returned) as unknown as typeof fetch;
    await expect(admitStrictReceipt(receipt, deterministic(fetchFn, { max_response_bytes: 100 })))
      .resolves.toMatchObject({ disposition: 'uncertain', reason: 'invalid_response', attempts: 1 });
  });

  it('refuses redirects', async () => {
    const fetchFn = jest.fn(async () => response(302, '', { Location: 'https://elsewhere.test' })) as unknown as typeof fetch;
    await expect(admitStrictReceipt(receipt, deterministic(fetchFn))).resolves.toMatchObject({
      disposition: 'uncertain', reason: 'redirect', attempts: 1,
    });
  });

  it('accepts only an explicit matching no-store rejection as definitive', async () => {
    const fetchFn = jest.fn(async () => response(401, rejection())) as unknown as typeof fetch;
    await expect(admitStrictReceipt(receipt, deterministic(fetchFn))).resolves.toEqual({
      disposition: 'definitive_no_store', receipt_hash: RECEIPT_HASH, http_status: 401, attempts: 1,
    });
    const mismatch = jest.fn(async () => response(401, rejection('d'.repeat(64)))) as unknown as typeof fetch;
    await expect(admitStrictReceipt(receipt, deterministic(mismatch))).resolves.toMatchObject({
      disposition: 'uncertain', reason: 'invalid_response', attempts: 1,
    });
  });

  it('classifies a schema-valid 409 as uncertain conflict', async () => {
    const conflict = {
      schema: STRICT_RECEIPT_ADMISSION_SCHEMA, ok: false, status: 'conflict',
      code: 'idempotency_conflict', receipt_hash: RECEIPT_HASH,
    };
    const fetchFn = jest.fn(async () => response(409, conflict)) as unknown as typeof fetch;
    await expect(admitStrictReceipt(receipt, deterministic(fetchFn))).resolves.toEqual({
      disposition: 'uncertain', receipt_hash: RECEIPT_HASH, reason: 'conflict', attempts: 1,
    });
  });

  it.each(['transport ambiguity', 'timeout', 'retryable HTTP'])('bounds %s retries', async (kind) => {
    const fetchFn = jest.fn(async () => {
      if (kind !== 'retryable HTTP') {
        const error = new Error(kind === 'timeout' ? 'timed out' : 'top-secret-test-key');
        if (kind === 'timeout') error.name = 'AbortError';
        throw error;
      }
      return response(503, { unavailable: true });
    }) as unknown as typeof fetch;
    const result = await admitStrictReceipt(receipt, deterministic(fetchFn, { max_attempts: 3 }));
    expect(result).toEqual({
      disposition: 'uncertain', receipt_hash: RECEIPT_HASH, reason: 'retry_exhausted', attempts: 3,
    });
    expect(JSON.stringify(result)).not.toContain('top-secret-test-key');
  });

  it('returns uncertain when an injected fetch ignores abort', async () => {
    const fetchFn = jest.fn(async () => new Promise<Response>(() => undefined)) as unknown as typeof fetch;
    await expect(admitStrictReceipt(receipt, deterministic(fetchFn, {
      max_attempts: 1, timeout_ms: 1,
    }))).resolves.toEqual({
      disposition: 'uncertain', receipt_hash: RECEIPT_HASH,
      reason: 'retry_exhausted', attempts: 1,
    });
  });

  it('does not expose an API key in validation errors', async () => {
    try {
      await admitStrictReceipt(receipt, deterministic(jest.fn() as unknown as typeof fetch, {
        ingest_url: 'not-a-url', api_key: 'top-secret-test-key',
      }));
      throw new Error('expected validation to fail');
    } catch (error) {
      expect(error).toBeInstanceOf(StrictAdmissionValidationError);
      expect(String(error)).not.toContain('top-secret-test-key');
    }
  });
});
