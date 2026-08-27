import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  admitPreparedStrictReceiptV21,
  assertStrictAdmissionV21RequestBytes,
  STRICT_RECEIPT_V21_ADMISSION_SCHEMA,
  STRICT_RECEIPT_V21_ENDPOINT,
  STRICT_RECEIPT_V21_INGEST_SCHEMA,
  STRICT_RECEIPT_V21_MAX_REQUEST_BYTES,
  type StrictAdmissionV21Coordinator,
} from '../../src/governance/strict-admission-v2-1.js';
import type {
  PreparedApprovalResolutionV21, PreparedDecisionV21,
} from '../../src/governance/strict-receipt-coordinator-v2-1-types.js';
import { DEFINITIVE_NO_STORE } from '../../src/governance/strict-receipt-prepared-state.js';
import { signStrictReceiptV21 } from '../../src/governance/strict-receipt-v2-1.js';
import { loadDeviceSigner } from '../../src/proxy/device-identity.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const FIXTURE = JSON.parse(readFileSync(
  join(ROOT, 'conformance/fixtures/strict_receipts_v2_1.json'), 'utf8',
));
const receipt = {
  schema: 'obsvr-strict-receipt-envelope-v2-1',
  body: FIXTURE.vector.body,
  receipt_hash: FIXTURE.vector.receipt_hash,
  signature: {
    algorithm: 'Ed25519', key_id: FIXTURE.public_test_key.key_id,
    value: FIXTURE.vector.signature,
  },
  public_key_b64: FIXTURE.public_test_key.public_key_b64,
};
const HASH = receipt.receipt_hash as string;
const WRAPPER_SHA256 = '270dd3f997c5fb729e41d935dd840ebe4e6fbabd5a7af6fa4810352bc13aa83c';
const bytes = (value: unknown): Uint8Array => Buffer.from(JSON.stringify(value));

function prepared(overrides: Record<string, unknown> = {}): PreparedDecisionV21 {
  return {
    token: 'token-21', receipt_hash: HASH, kind: 'decision',
    value: { receipt, action_context: {}, intent_evaluation: {}, evaluation_evidence: {} },
    ...overrides,
  } as unknown as PreparedDecisionV21;
}
function preparedResolution(): PreparedApprovalResolutionV21 {
  const path = join(mkdtempSync(join(tmpdir(), 'obsvr-v21-admission-')), 'seed.key');
  writeFileSync(path, FIXTURE.public_test_key.seed_hex, 'ascii');
  const body = structuredClone(FIXTURE.vector.body);
  body.record_type = 'resolution'; body.receipt_id = `${body.session_id}:2`;
  body.sequence = 2; body.timestamp_ms += 1; body.previous_receipt_hash = HASH;
  body.evaluation.requested_outcome = 'ALLOW'; body.evaluation.outcome = 'ALLOW';
  body.outcome = 'ALLOW'; body.execution_authorized = true; delete body.suspension;
  body.resolution = { resolves_receipt_hash: HASH, suspension_id: 'approval-21',
    method: 'approval_granted', resolver_ref_hash: 'a'.repeat(64),
    resolved_at_ms: body.timestamp_ms, approval_evidence_hash: 'b'.repeat(64) };
  const signed = signStrictReceiptV21(body, loadDeviceSigner(path));
  return { token: 'resolution-token', receipt_hash: signed.receipt_hash,
    kind: 'resolution', value: signed };
}

class Coordinator implements StrictAdmissionV21Coordinator {
  readonly tenant = receipt.body.tenant_id as string;
  readonly session = receipt.body.session_id as string;
  current: { token: string; receipt_hash: string; kind: 'decision' | 'resolution' } | undefined = {
    token: 'token-21', receipt_hash: HASH, kind: 'decision',
  };
  frozen = false; commits = 0; aborts = 0; freezes: string[] = [];
  commitFailure = false;

  inspectState() {
    return { tenant_id: this.tenant, session_id: this.session, frozen: this.frozen,
      ...(this.current ? { prepared: this.current } : {}) };
  }
  commitPrepared(token: string, hash: string): unknown {
    this.match(token, hash); this.commits += 1;
    if (this.commitFailure) throw new Error('commit failed');
    this.current = undefined as never; return {};
  }
  abortPrepared(token: string, hash: string, capability: typeof DEFINITIVE_NO_STORE): void {
    this.match(token, hash); expect(capability).toBe(DEFINITIVE_NO_STORE);
    this.aborts += 1; this.current = undefined as never;
  }
  freezePrepared(token: string, hash: string, reason = 'transport_ambiguous'): void {
    this.match(token, hash); this.frozen = true; this.freezes.push(reason);
  }
  private match(token: string, hash: string): void {
    expect(token).toBe(this.current?.token); expect(hash).toBe(this.current?.receipt_hash);
  }
}

function accepted(
  status: 'accepted' | 'already_accepted' = 'accepted', receiptHash = HASH,
) {
  return bytes({ schema: STRICT_RECEIPT_V21_ADMISSION_SCHEMA, ok: true, status,
    receipt_hash: receiptHash, accepted_at_ms: 10 });
}
function options(transport: NonNullable<Parameters<typeof admitPreparedStrictReceiptV21>[2]['trusted_pinned_transport']>) {
  return { ingest_url: 'https://example.com/base/', api_key: 'key', max_attempts: 1,
    resolver: async () => ['8.8.8.8'], trusted_pinned_transport: transport };
}

describe('strict profile 2.1 prepared decision admission', () => {
  test('enforces the backend request cap locally before transport', () => {
    expect(() => assertStrictAdmissionV21RequestBytes(
      'x'.repeat(STRICT_RECEIPT_V21_MAX_REQUEST_BYTES),
    )).not.toThrow();
    expect(() => assertStrictAdmissionV21RequestBytes(
      'x'.repeat(STRICT_RECEIPT_V21_MAX_REQUEST_BYTES + 1),
    )).toThrow('receipt ingest request exceeds its supported size');
  });

  test('sends exact canonical wrapper through a pinned snapshot and commits accepted', async () => {
    const coordinator = new Coordinator(); let captured: any;
    const result = await admitPreparedStrictReceiptV21(coordinator, prepared(), options(
      async (target, body, headers) => {
        captured = { target, body, headers };
        return { status: 200, body: accepted() };
      },
    ));
    expect(captured.target.url.pathname).toBe(`/base${STRICT_RECEIPT_V21_ENDPOINT}`);
    expect(captured.target.addresses).toEqual([{ address: '8.8.8.8', family: 4 }]);
    expect(captured.headers).toMatchObject({ 'Idempotency-Key': HASH, 'X-API-Key': 'key' });
    expect(JSON.parse(captured.body)).toEqual({ schema: STRICT_RECEIPT_V21_INGEST_SCHEMA,
      tenant_id: receipt.body.tenant_id, session_id: receipt.body.session_id, receipt });
    expect(createHash('sha256').update(captured.body).digest('hex')).toBe(WRAPPER_SHA256);
    expect(result).toMatchObject({ disposition: 'accepted', status: 'accepted', attempts: 1 });
    expect(coordinator.commits).toBe(1); expect(coordinator.freezes).toEqual([]);
  });

  test('commits an exact already_accepted response without changing request identity', async () => {
    const coordinator = new Coordinator();
    const result = await admitPreparedStrictReceiptV21(coordinator, prepared(), options(
      async () => ({ status: 200, body: accepted('already_accepted') }),
    ));
    expect(result).toMatchObject({ disposition: 'accepted', status: 'already_accepted' });
    expect(coordinator.commits).toBe(1);
  });

  test('admits and commits an intact prepared resolution', async () => {
    const coordinator = new Coordinator(); const resolution = preparedResolution(); let captured: any;
    coordinator.current = { token: resolution.token, receipt_hash: resolution.receipt_hash,
      kind: 'resolution' };
    const result = await admitPreparedStrictReceiptV21(coordinator, resolution, options(
      async (_target, body) => {
        captured = JSON.parse(body); return { status: 200,
          body: accepted('accepted', resolution.receipt_hash) };
      },
    ));
    expect(captured.receipt).toEqual(resolution.value);
    expect(result).toMatchObject({ disposition: 'accepted', receipt_hash: resolution.receipt_hash });
    expect(coordinator.commits).toBe(1);
  });

  test('aborts only for an exact definitive no-store rejection', async () => {
    const coordinator = new Coordinator();
    const result = await admitPreparedStrictReceiptV21(coordinator, prepared(), options(
      async () => ({ status: 400, body: bytes({ schema: STRICT_RECEIPT_V21_ADMISSION_SCHEMA,
        ok: false, status: 'rejected', code: 'invalid_receipt', stored: false,
        receipt_hash: HASH }) }),
    ));
    expect(result).toMatchObject({ disposition: 'definitive_no_store', http_status: 400 });
    expect(coordinator.aborts).toBe(1); expect(coordinator.freezes).toEqual([]);
  });

  test('freezes on conflict and retry exhaustion', async () => {
    const conflictCoordinator = new Coordinator();
    const conflict = await admitPreparedStrictReceiptV21(
      conflictCoordinator, prepared(), options(async () => ({ status: 409,
        body: bytes({ schema: STRICT_RECEIPT_V21_ADMISSION_SCHEMA, ok: false,
          status: 'conflict', code: 'receipt_conflict', receipt_hash: HASH }) })),
    );
    expect(conflict).toMatchObject({ disposition: 'uncertain', reason: 'conflict' });
    expect(conflictCoordinator.freezes).toEqual(['conflict']);

    const retryCoordinator = new Coordinator();
    const retry = await admitPreparedStrictReceiptV21(
      retryCoordinator, prepared(), options(async () => ({ status: 503, body: bytes({}) })),
    );
    expect(retry).toMatchObject({ disposition: 'uncertain', reason: 'retry_exhausted' });
    expect(retryCoordinator.freezes).toEqual(['retry_exhausted']);
  });

  test.each([
    ['malformed', bytes({ nope: true })],
    ['wrong-hash', bytes({ schema: STRICT_RECEIPT_V21_ADMISSION_SCHEMA, ok: true,
      status: 'accepted', receipt_hash: 'b'.repeat(64), accepted_at_ms: 10 })],
    ['truncated', Buffer.from('{"schema":')],
    ['oversized', Buffer.alloc(65_537, 32)],
  ])('freezes a %s success response', async (_name, responseBody) => {
    const coordinator = new Coordinator();
    const result = await admitPreparedStrictReceiptV21(coordinator, prepared(), options(
      async () => ({ status: 200, body: responseBody }),
    ));
    expect(result).toMatchObject({ disposition: 'uncertain', reason: 'invalid_response' });
    expect(coordinator.freezes).toEqual(['invalid_response']);
  });

  test('freezes on redirects, DNS rejection, and pinned transport failure', async () => {
    const redirectCoordinator = new Coordinator();
    const redirect = await admitPreparedStrictReceiptV21(
      redirectCoordinator, prepared(), options(async () => ({ status: 302, body: new Uint8Array() })),
    );
    expect(redirect).toMatchObject({ reason: 'redirect' });

    const dnsCoordinator = new Coordinator(); let calls = 0;
    const dns = await admitPreparedStrictReceiptV21(dnsCoordinator, prepared(), {
      ...options(async () => { calls += 1; throw new Error('must not connect'); }),
      resolver: async () => ['8.8.8.8', '127.0.0.1'],
    });
    expect(calls).toBe(0); expect(dns).toMatchObject({ reason: 'retry_exhausted' });

    const pinCoordinator = new Coordinator();
    const pin = await admitPreparedStrictReceiptV21(pinCoordinator, prepared(), options(
      async () => { throw new Error('pinned socket failed'); },
    ));
    expect(pin).toMatchObject({ reason: 'retry_exhausted' });
    expect([redirectCoordinator, dnsCoordinator, pinCoordinator]
      .every((item) => item.frozen)).toBe(true);
  });

  test('rejects record-kind or state-drifted prepared values before transport', async () => {
    const coordinator = new Coordinator(); let calls = 0;
    coordinator.current = { token: 'token-21', receipt_hash: HASH, kind: 'resolution' };
    await expect(admitPreparedStrictReceiptV21(coordinator, prepared({ kind: 'resolution' }), options(
      async () => { calls += 1; return { status: 200, body: accepted() }; },
    ))).rejects.toThrow('intact strict profile-2.1 record');
    expect(calls).toBe(0); expect(coordinator.commits).toBe(0);
  });

  test('freezes if remote acceptance cannot be committed locally', async () => {
    const coordinator = new Coordinator(); coordinator.commitFailure = true;
    const result = await admitPreparedStrictReceiptV21(coordinator, prepared(), options(
      async () => ({ status: 200, body: accepted() }),
    ));
    expect(result).toMatchObject({ disposition: 'uncertain', reason: 'local_commit_failed' });
    expect(coordinator.freezes).toEqual(['accepted_but_local_commit_failed']);
  });
});
