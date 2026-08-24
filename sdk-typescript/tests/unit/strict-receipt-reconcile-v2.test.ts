import { reconcileStrictReceiptV2, STRICT_RECONCILIATION_V2_ENDPOINT } from '../../src/governance/strict-receipt-reconcile-v2';
import type { StrictReceiptV2Envelope } from '../../src/governance/strict-receipt-v2';

const HASH = 'a'.repeat(64);
const receipt = { schema: 'obsvr-strict-receipt-envelope-v2', receipt_hash: HASH,
  body: { schema: 'obsvr-strict-receipt-v2', tenant_id: 'tenant-1',
    session_id: 'session-1' } } as StrictReceiptV2Envelope;

describe('strict receipt v2 reconciliation transport', () => {
  test('uses exact wrapper, pinned snapshot, and stable idempotency bytes', async () => {
    const bodies: string[] = []; const addresses: string[][] = []; let lookups = 0;
    const result = await reconcileStrictReceiptV2(receipt, { ingest_url: 'https://example.com/base/',
      api_key: 'key', max_attempts: 2, resolver: async () => [lookups++ ? '1.1.1.1' : '8.8.8.8'],
      sleep: async () => {}, trusted_pinned_transport: async (target, body, headers) => {
        bodies.push(body); addresses.push(target.addresses.map((item) => item.address));
        expect(target.url.pathname).toBe(`/base${STRICT_RECONCILIATION_V2_ENDPOINT}`);
        expect(headers['Idempotency-Key']).toBe(HASH);
        return bodies.length === 1 ? { status: 500, body: new Uint8Array() } : { status: 200,
          body: Buffer.from(JSON.stringify({ schema: 'obsvr-strict-receipt-reconciliation-v2',
            ok: true, status: 'accepted', session_id: 'session-1', receipt_hash: HASH,
            accepted_at_ms: 10 })) };
      } });
    expect(bodies[0]).toBe(bodies[1]); expect(addresses).toEqual([['8.8.8.8'], ['1.1.1.1']]);
    expect(JSON.parse(bodies[0]!)).toEqual({ schema: 'obsvr-strict-receipt-ingest-v2',
      tenant_id: 'tenant-1', session_id: 'session-1', receipt });
    expect(result).toMatchObject({ status: 'accepted', attempts: 2 });
  });

  test('mixed DNS answers and malformed echoes remain unresolved', async () => {
    let called = false;
    const mixed = await reconcileStrictReceiptV2(receipt, { ingest_url: 'https://example.com',
      api_key: 'key', max_attempts: 1, resolver: async () => ['8.8.8.8', '127.0.0.1'],
      trusted_pinned_transport: async () => { called = true; throw new Error('unreachable'); } });
    expect(called).toBe(false); expect(mixed).toMatchObject({ status: 'unknown' });
    const wrong = await reconcileStrictReceiptV2(receipt, { ingest_url: 'https://example.com',
      api_key: 'key', max_attempts: 1, resolver: async () => ['8.8.8.8'],
      trusted_pinned_transport: async () => ({ status: 200, body: Buffer.from(JSON.stringify({
        schema: 'obsvr-strict-receipt-reconciliation-v2', ok: true, status: 'accepted',
        session_id: 'other', receipt_hash: HASH, accepted_at_ms: 10 })) }) });
    expect(wrong).toMatchObject({ status: 'unknown' });
    const absent = await reconcileStrictReceiptV2(receipt, { ingest_url: 'https://example.com',
      api_key: 'key', max_attempts: 1, resolver: async () => ['8.8.8.8'],
      trusted_pinned_transport: async () => ({ status: 404, body: Buffer.from(JSON.stringify({
        schema: 'obsvr-strict-receipt-reconciliation-v2', ok: true, status: 'absent',
        session_id: 'session-1', receipt_hash: HASH })) }) });
    expect(absent).toMatchObject({ status: 'absent' });
  });

  test('rejects invalid transport bounds before lookup', async () => {
    await expect(reconcileStrictReceiptV2(receipt, { ingest_url: 'https://example.com',
      api_key: 'key', max_attempts: 0 })).rejects.toThrow('max_attempts');
  });
});
