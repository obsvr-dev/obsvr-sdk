import {
  admitStrictReceiptV2, STRICT_RECEIPT_V2_ADMISSION_SCHEMA,
  STRICT_RECEIPT_V2_ENDPOINT, STRICT_RECEIPT_V2_INGEST_SCHEMA,
} from '../../src/governance/strict-admission-v2.js';
import type { StrictReceiptV2Envelope } from '../../src/governance/strict-receipt-v2.js';

const HASH = 'a'.repeat(64);
const receipt = {
  schema: 'obsvr-strict-receipt-envelope-v2', receipt_hash: HASH,
  body: { schema: 'obsvr-strict-receipt-v2', tenant_id: 'tenant-1', session_id: 'session-1' },
} as unknown as StrictReceiptV2Envelope;
const bytes = (value: unknown): Uint8Array => Buffer.from(JSON.stringify(value));

describe('strict admission v2', () => {
  test('uses the exact v2 endpoint/wrapper through an approved address snapshot', async () => {
    let target: any; let body = ''; let headers: any;
    const result = await admitStrictReceiptV2(receipt, {
      ingest_url: 'https://example.com/base/', api_key: 'key',
      resolver: async () => ['8.8.8.8'], max_attempts: 1,
      trusted_pinned_transport: async (approved, requestBody, requestHeaders) => {
        target = approved; body = requestBody; headers = requestHeaders;
        return { status: 200, body: bytes({ schema: STRICT_RECEIPT_V2_ADMISSION_SCHEMA,
          ok: true, status: 'accepted', receipt_hash: HASH, accepted_at_ms: 10 }) };
      },
    });
    expect(target.url.pathname).toBe(`/base${STRICT_RECEIPT_V2_ENDPOINT}`);
    expect(target.addresses).toEqual([{ address: '8.8.8.8', family: 4 }]);
    expect(headers).toMatchObject({ 'Idempotency-Key': HASH, 'X-API-Key': 'key' });
    expect(JSON.parse(body)).toEqual({ schema: STRICT_RECEIPT_V2_INGEST_SCHEMA,
      tenant_id: 'tenant-1', session_id: 'session-1', receipt });
    expect(result).toMatchObject({ schema: STRICT_RECEIPT_V2_ADMISSION_SCHEMA,
      tenant_id: 'tenant-1', session_id: 'session-1', disposition: 'accepted' });
  });

  test('re-resolves per retry but preserves exact bytes and idempotency key', async () => {
    const bodies: string[] = []; const snapshots: string[][] = []; let resolves = 0;
    const result = await admitStrictReceiptV2(receipt, {
      ingest_url: 'https://example.com', api_key: 'key', max_attempts: 2,
      resolver: async () => [resolves++ === 0 ? '8.8.8.8' : '1.1.1.1'],
      sleep: async () => {}, jitter: () => 0,
      trusted_pinned_transport: async (target, body, headers) => {
        bodies.push(body); snapshots.push(target.addresses.map((item) => item.address));
        expect(headers['Idempotency-Key']).toBe(HASH);
        return bodies.length === 1 ? { status: 500, body: new Uint8Array() }
          : { status: 200, body: bytes({ schema: STRICT_RECEIPT_V2_ADMISSION_SCHEMA,
            ok: true, status: 'already_accepted', receipt_hash: HASH, accepted_at_ms: 11 }) };
      },
    });
    expect(bodies).toHaveLength(2); expect(bodies[0]).toBe(bodies[1]);
    expect(snapshots).toEqual([['8.8.8.8'], ['1.1.1.1']]);
    expect(result).toMatchObject({ disposition: 'accepted', status: 'already_accepted', attempts: 2 });
  });

  test('mixed public/private answers never reach the socket transport', async () => {
    let transports = 0;
    const result = await admitStrictReceiptV2(receipt, {
      ingest_url: 'https://example.com', api_key: 'key', max_attempts: 1,
      resolver: async () => ['8.8.8.8', '127.0.0.1'],
      trusted_pinned_transport: async () => { transports += 1; throw new Error('unreachable'); },
    });
    expect(transports).toBe(0);
    expect(result).toMatchObject({ disposition: 'uncertain', reason: 'retry_exhausted' });
  });

  test('accepts explicit v2 no-store without redundant tenant/session response fields', async () => {
    const result = await admitStrictReceiptV2(receipt, {
      ingest_url: 'http://127.0.0.1:8000', api_key: 'key', max_attempts: 1,
      resolver: async () => ['127.0.0.1'],
      trusted_pinned_transport: async () => ({ status: 400,
        body: bytes({ schema: STRICT_RECEIPT_V2_ADMISSION_SCHEMA, ok: false,
          status: 'rejected', code: 'invalid', stored: false, receipt_hash: HASH }) }),
    });
    expect(result).toMatchObject({ disposition: 'definitive_no_store',
      tenant_id: 'tenant-1', session_id: 'session-1', http_status: 400 });
  });

  test('rejects a v1 or malformed response as uncertain', async () => {
    const result = await admitStrictReceiptV2(receipt, {
      ingest_url: 'https://example.com', api_key: 'key', max_attempts: 1,
      resolver: async () => ['8.8.8.8'],
      trusted_pinned_transport: async () => ({ status: 200,
        body: bytes({ schema: 'obsvr-strict-receipt-admission-v1', ok: true,
          status: 'accepted', receipt_hash: HASH, accepted_at_ms: 10 }) }),
    });
    expect(result).toMatchObject({ disposition: 'uncertain', reason: 'invalid_response' });
  });
});
