import { jest } from '@jest/globals';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { StrictReceiptEnvelope } from '../../src/governance/strict-receipt';
import {
  STRICT_RECEIPT_ADMISSION_SCHEMA,
  admitStrictReceipt,
  type StrictAdmissionPinnedTransport,
} from '../../src/governance/strict-admission';
import { pinnedRequestOptions } from '../../src/utils/pinned-http';
import type { Resolver } from '../../src/utils/ssrf';

const RECEIPT_HASH = 'a'.repeat(64);
const receipt = {
  schema: 'obsvr-strict-receipt-envelope-v1',
  body: { receipt_id: 'session:1' },
  receipt_hash: RECEIPT_HASH,
  signature: {
    algorithm: 'Ed25519', key_id: `sha256:${'b'.repeat(64)}`, value: 'c'.repeat(128),
  },
} as unknown as StrictReceiptEnvelope;

function body(status: 'accepted' | 'already_accepted' = 'accepted'): Uint8Array {
  return Buffer.from(JSON.stringify({
    schema: STRICT_RECEIPT_ADMISSION_SCHEMA, ok: true, status,
    receipt_hash: RECEIPT_HASH, accepted_at_ms: 1_700_000_000_000,
  }));
}

function options(
  resolver: Resolver,
  transport: StrictAdmissionPinnedTransport,
  overrides: Record<string, unknown> = {},
) {
  let now = 0;
  return {
    ingest_url: 'https://ingest.example.test:8443/base', api_key: 'test-key',
    resolver, trusted_pinned_transport: transport,
    clock_ms: () => now, sleep: async (delay: number) => { now += delay; },
    jitter: () => 0, retry_base_ms: 2, retry_deadline_ms: 100, timeout_ms: 10,
    ...overrides,
  };
}

describe('strict admission DNS pinning', () => {
  it('uses the pinned production transport by default', async () => {
    const captured: { host?: string; connection?: string; body?: string } = {};
    const server = createServer((request, response) => {
      const chunks: Buffer[] = [];
      request.on('data', (chunk: Buffer) => chunks.push(chunk));
      request.on('end', () => {
        captured.host = request.headers.host;
        captured.connection = request.headers.connection;
        captured.body = Buffer.concat(chunks).toString('utf8');
        response.writeHead(200, { 'content-type': 'application/json' });
        response.end(body());
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    try {
      const port = (server.address() as AddressInfo).port;
      let now = 0;
      const result = await admitStrictReceipt(receipt, {
        ingest_url: `http://localhost:${port}/base`, api_key: 'test-key',
        resolver: async () => ['127.0.0.1'], max_attempts: 1,
        clock_ms: () => now, sleep: async (delay) => { now += delay; },
      });
      expect(result).toMatchObject({ disposition: 'accepted' });
      expect(captured.host).toBe(`localhost:${port}`);
      expect(captured.connection).toBe('close');
      expect(captured.body).toContain(`"receipt_hash":"${RECEIPT_HASH}"`);
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    }
  });

  it.each([
    ['private answer', ['10.1.2.3']],
    ['mixed public/private answers', ['8.8.8.8', '10.1.2.3']],
    ['metadata answer', ['169.254.169.254']],
  ])('rejects every unsafe snapshot: %s', async (_name, answers) => {
    const resolver = jest.fn(async () => answers);
    const transport = jest.fn<StrictAdmissionPinnedTransport>();
    await expect(admitStrictReceipt(receipt, options(resolver, transport, {
      max_attempts: 2,
    }))).resolves.toEqual({
      disposition: 'uncertain', receipt_hash: RECEIPT_HASH,
      reason: 'retry_exhausted', attempts: 2,
    });
    expect(resolver).toHaveBeenCalledTimes(2);
    expect(transport).not.toHaveBeenCalled();
  });

  it('pins both approved IPv4 and IPv6 answers and preserves Host plus SNI', async () => {
    const resolver = jest.fn(async () => ['8.8.8.8', '2606:4700:4700::1111']);
    const snapshots: Array<Parameters<StrictAdmissionPinnedTransport>[0]> = [];
    const transport: StrictAdmissionPinnedTransport = async (target) => {
      snapshots.push(target);
      return { status: 200, body: body() };
    };
    await expect(admitStrictReceipt(receipt, options(resolver, transport)))
      .resolves.toMatchObject({ disposition: 'accepted' });

    expect(snapshots[0].addresses).toEqual([
      { address: '8.8.8.8', family: 4 },
      { address: '2606:4700:4700::1111', family: 6 },
    ]);
    const request = pinnedRequestOptions(
      snapshots[0], { host: '169.254.169.254', connection: 'keep-alive' }, 17,
      new AbortController().signal,
    );
    expect(request).toMatchObject({ agent: false, servername: 'ingest.example.test' });
    expect(request.headers).toMatchObject({
      host: 'ingest.example.test:8443', connection: 'close', 'content-length': '17',
    });
    const lookup = request.lookup;
    expect(lookup).toBeDefined();
    const addresses = await new Promise<unknown>((resolve, reject) => {
      lookup?.('ignored.invalid', { all: true, family: 0, hints: 0 }, (error, value) => {
        if (error) reject(error); else resolve(value);
      });
    });
    expect(addresses).toEqual(snapshots[0].addresses);
    expect(resolver).toHaveBeenCalledTimes(1);
  });

  it('does not re-resolve between the guard and the pinned transport', async () => {
    const answers = [['8.8.8.8'], ['127.0.0.1']];
    const resolver = jest.fn(async () => answers.shift() ?? ['127.0.0.1']);
    const seen: string[][] = [];
    const transport: StrictAdmissionPinnedTransport = async (target) => {
      seen.push(target.addresses.map(({ address }) => address));
      return { status: 200, body: body() };
    };
    await expect(admitStrictReceipt(receipt, options(resolver, transport, {
      max_attempts: 1,
    }))).resolves.toMatchObject({ disposition: 'accepted' });
    expect(seen).toEqual([['8.8.8.8']]);
    expect(resolver).toHaveBeenCalledTimes(1);
  });

  it('takes a fresh immutable address snapshot for every retry', async () => {
    const answers = [['8.8.8.8'], ['1.1.1.1']];
    const resolver = jest.fn(async () => answers.shift() ?? []);
    const snapshots: string[][] = [];
    const bodies: string[] = [];
    const keys: string[] = [];
    const transport: StrictAdmissionPinnedTransport = async (target, requestBody, headers) => {
      snapshots.push(target.addresses.map(({ address }) => address));
      bodies.push(requestBody);
      keys.push(headers['Idempotency-Key']);
      return snapshots.length === 1
        ? { status: 503, body: Buffer.from('{}') }
        : { status: 200, body: body('already_accepted') };
    };
    await expect(admitStrictReceipt(receipt, options(resolver, transport)))
      .resolves.toMatchObject({ disposition: 'accepted', status: 'already_accepted', attempts: 2 });
    expect(snapshots).toEqual([['8.8.8.8'], ['1.1.1.1']]);
    expect(bodies[1]).toBe(bodies[0]);
    expect(keys).toEqual([RECEIPT_HASH, RECEIPT_HASH]);
  });

  it('maps resolver failure to uncertainty without reaching transport', async () => {
    const resolver = jest.fn(async () => { throw new Error('resolver unavailable'); });
    const transport = jest.fn<StrictAdmissionPinnedTransport>();
    await expect(admitStrictReceipt(receipt, options(resolver, transport, {
      max_attempts: 1,
    }))).resolves.toEqual({
      disposition: 'uncertain', receipt_hash: RECEIPT_HASH,
      reason: 'retry_exhausted', attempts: 1,
    });
    expect(transport).not.toHaveBeenCalled();
  });

  it('allows literal loopback HTTP but still refuses metadata from localhost DNS', async () => {
    const transport: StrictAdmissionPinnedTransport = async (target) => ({
      status: 200, body: body(),
    });
    await expect(admitStrictReceipt(receipt, options(
      async () => { throw new Error('literal loopback must not resolve'); }, transport,
      { ingest_url: 'http://127.0.0.1:8787/base', max_attempts: 1 },
    ))).resolves.toMatchObject({ disposition: 'accepted' });

    const blocked = jest.fn<StrictAdmissionPinnedTransport>();
    await expect(admitStrictReceipt(receipt, options(
      async () => ['127.0.0.1', '169.254.169.254'], blocked,
      { ingest_url: 'http://localhost:8787/base', max_attempts: 1 },
    ))).resolves.toMatchObject({ disposition: 'uncertain' });
    expect(blocked).not.toHaveBeenCalled();
  });
});
