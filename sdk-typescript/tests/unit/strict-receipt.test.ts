import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import * as path from 'node:path';
import {
  StrictReceiptValidationError,
  buildStrictReceiptBody,
  canonicalizeStrictReceiptBody,
  signStrictReceipt,
  strictReceiptHash,
  strictReceiptKeyId,
  type StrictReceiptBody,
  type StrictReceiptEnvelope,
} from '../../src/governance/strict-receipt';
import { verifyStrictReceipt, verifyStrictReceiptChain } from '../../src/governance/strict-receipt-verify';
import { loadDeviceSigner } from '../../src/proxy/device-identity';

function findFixture(rel: string): string {
  let dir = process.cwd();
  for (let i = 0; i < 6; i++) {
    const candidate = path.join(dir, rel);
    try { readFileSync(candidate); return candidate; } catch { dir = dirname(dir); }
  }
  throw new Error(`fixture not found upward from ${process.cwd()}: ${rel}`);
}

interface Vector {
  id: string;
  input_rule_ids: string[];
  input_required_fields?: string[];
  body: StrictReceiptBody;
  canonical: string;
  receipt_hash: string;
  signature: string;
}

const FIXTURE = JSON.parse(readFileSync(
  findFixture('conformance/fixtures/strict_receipts.json'), 'utf8',
)) as {
  description: string;
  claimable: boolean;
  public_test_key: { seed_hex: string; public_key_b64: string; key_id: string };
  vectors: Vector[];
  negative_case_ids: string[];
};

const seedDir = mkdtempSync(join(tmpdir(), 'obsvr-strict-receipt-'));
const seedPath = join(seedDir, 'public-test-seed.key');
writeFileSync(seedPath, FIXTURE.public_test_key.seed_hex);
const signer = loadDeviceSigner(seedPath);

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function envelopes(includePublicKey = true): StrictReceiptEnvelope[] {
  return FIXTURE.vectors.map((vector) => signStrictReceipt(inputBody(vector), signer, includePublicKey));
}

function inputBody(vector: Vector): StrictReceiptBody {
  const body = clone(vector.body);
  body.evaluation.rule_ids = vector.input_rule_ids;
  if (vector.input_required_fields && body.suspension) {
    body.suspension.required_fields = vector.input_required_fields;
  }
  return body;
}

function resign(chain: StrictReceiptEnvelope[], index: number, mutate: (body: StrictReceiptBody) => void): void {
  const body = clone(chain[index].body);
  mutate(body);
  chain[index] = signStrictReceipt(body, signer, true);
}

describe('Obsvr-authored strict receipt fixtures', () => {
  it('is explicitly local and uses a full strict public-key identity', () => {
    expect(FIXTURE.claimable).toBe(false);
    expect(FIXTURE.description).toContain('not official AARM conformance vectors');
    expect(strictReceiptKeyId(signer.rawPublicKey)).toBe(FIXTURE.public_test_key.key_id);
  });

  for (const vector of FIXTURE.vectors) {
    it(`pins canonical bytes, body hash, and signature: ${vector.id}`, () => {
      const body = inputBody(vector);
      const envelope = signStrictReceipt(body, signer, true);
      expect(Buffer.from(canonicalizeStrictReceiptBody(body), 'utf8'))
        .toEqual(Buffer.from(vector.canonical, 'utf8'));
      expect(strictReceiptHash(body)).toBe(vector.receipt_hash);
      expect(envelope.receipt_hash).toBe(vector.receipt_hash);
      expect(envelope.signature).toEqual({
        algorithm: 'Ed25519', key_id: FIXTURE.public_test_key.key_id, value: vector.signature,
      });
      expect(envelope.body).toEqual(JSON.parse(vector.canonical));
    });
  }

  it('covers outcomes, suspensions, resolutions, clock clamping, and optional thread', () => {
    expect(new Set(FIXTURE.vectors.map((vector) => vector.body.evaluation.outcome)))
      .toEqual(new Set(['ALLOW', 'DENY', 'MODIFY', 'STEP_UP', 'DEFER']));
    expect(FIXTURE.vectors[0].body.context.thread_id).toBeUndefined();
    expect(FIXTURE.vectors[1].body.clock_regression_clamped).toBe(true);
    expect(FIXTURE.vectors[3].body.suspension?.approval_action_hash).toBe('5'.repeat(64));
    expect(FIXTURE.vectors[5].body.suspension?.required_fields)
      .toEqual(['missing_上下文', 'tool_result']);
    expect(FIXTURE.vectors.filter((vector) => vector.body.record_type === 'resolution')).toHaveLength(2);
  });
});

describe('strict offline verification axes', () => {
  it('distinguishes self-asserted, pinned, and unknown keys', () => {
    expect(verifyStrictReceipt(envelopes()[0])).toEqual({
      schema_valid: true, hash_valid: true, signature_valid: true,
      semantic_valid: true, identity_binding_valid: true, key_trust: 'self_asserted',
    });
    const withoutHint = envelopes(false)[0];
    expect(verifyStrictReceipt(withoutHint, {
      pinned_public_key_b64: FIXTURE.public_test_key.public_key_b64,
    })).toEqual({
      schema_valid: true, hash_valid: true, signature_valid: true,
      semantic_valid: true, identity_binding_valid: true, key_trust: 'pinned',
    });
    expect(verifyStrictReceipt(withoutHint)).toMatchObject({
      signature_valid: false, identity_binding_valid: false, key_trust: 'unknown',
    });
  });

  it('separates body, hash, signature, and three-way key binding tampering', () => {
    const original = envelopes()[0];
    const bodyTamper = clone(original);
    bodyTamper.body.action.name = 'tampered';
    expect(verifyStrictReceipt(bodyTamper)).toMatchObject({ hash_valid: false, signature_valid: true });
    const hashTamper = clone(original);
    hashTamper.receipt_hash = `0${hashTamper.receipt_hash.slice(1)}`;
    expect(verifyStrictReceipt(hashTamper)).toMatchObject({ hash_valid: false, signature_valid: false });
    const signatureTamper = clone(original);
    signatureTamper.signature.value = `0${signatureTamper.signature.value.slice(1)}`;
    expect(verifyStrictReceipt(signatureTamper)).toMatchObject({ hash_valid: true, signature_valid: false });
    const signatureKeyTamper = clone(original);
    signatureKeyTamper.signature.key_id = `sha256:${'0'.repeat(64)}`;
    expect(verifyStrictReceipt(signatureKeyTamper)).toMatchObject({ signature_valid: false, identity_binding_valid: false });
    expect(verifyStrictReceipt(original, {
      pinned_public_key_b64: Buffer.alloc(32).toString('base64'),
    })).toMatchObject({ signature_valid: false, identity_binding_valid: false, key_trust: 'pinned' });
    expect(verifyStrictReceipt(original, { pinned_public_key_b64: 'not-base64' }))
      .toMatchObject({ signature_valid: false, identity_binding_valid: false, key_trust: 'pinned' });
  });
});

describe('strict receipt semantic refusals', () => {
  const cases: Array<[string, number, (body: StrictReceiptBody) => void]> = [
    ['unknown_body_key', 0, (body) => { (body as unknown as Record<string, unknown>).extra = true; }],
    ['clock_flag_missing', 0, (body) => { delete (body as Partial<StrictReceiptBody>).clock_regression_clamped; }],
    ['clock_flag_wrong_type', 0, (body) => { (body as unknown as Record<string, unknown>).clock_regression_clamped = 1; }],
    ['invalid_sequence', 0, (body) => { body.sequence = 0; body.receipt_id = `${body.session_id}:0`; }],
    ['invalid_timestamp', 0, (body) => { body.timestamp_ms = Number.MAX_SAFE_INTEGER + 1; }],
    ['receipt_id_mismatch', 0, (body) => { body.receipt_id = 'wrong'; }],
    ['genesis_previous_hash', 0, (body) => { body.previous_receipt_hash = '0'.repeat(64); }],
    ['modify_missing_effective_hash', 2, (body) => { delete body.action.effective_arguments_hash; }],
    ['non_modify_effective_hash', 0, (body) => { body.action.effective_arguments_hash = 'b'.repeat(64); }],
    ['authorization_mismatch', 0, (body) => { body.execution_authorized = false; }],
    ['step_up_missing_suspension', 3, (body) => { delete body.suspension; }],
    ['step_up_required_fields', 3, (body) => { body.suspension!.required_fields = ['x']; }],
    ['approval_hash_missing', 3, (body) => { delete body.suspension!.approval_action_hash; }],
    ['approval_hash_malformed', 3, (body) => { body.suspension!.approval_action_hash = 'bad'; }],
    ['suspension_expired_before_receipt', 3, (body) => { body.suspension!.expires_at_ms = body.timestamp_ms - 1; }],
    ['defer_empty_required_fields', 5, (body) => { body.suspension!.required_fields = []; }],
    ['defer_approval_fields', 5, (body) => { body.suspension!.approval_request_id = 'bad'; }],
    ['resolution_nonfinal', 4, (body) => { body.evaluation.outcome = 'STEP_UP'; body.execution_authorized = false; }],
    ['resolution_missing', 4, (body) => { delete body.resolution; }],
    ['resolution_method_outcome', 4, (body) => { body.resolution!.method = 'approval_denied'; }],
    ['resolution_timestamp_after_receipt', 4, (body) => { body.resolution!.resolved_at_ms = body.timestamp_ms + 1; }],
  ];
  for (const [id, index, mutate] of cases) {
    it(`rejects ${id}`, () => {
      expect(FIXTURE.negative_case_ids).toContain(id);
      const body = clone(FIXTURE.vectors[index].body);
      mutate(body);
      expect(() => buildStrictReceiptBody(body)).toThrow(StrictReceiptValidationError);
    });
  }
});

describe('strict receipt chain verification', () => {
  it('rejects empty and malformed chains without throwing', () => {
    expect(verifyStrictReceiptChain([])).toEqual({ valid: false, errors: ['empty_chain'] });
    const malformed: unknown[] = [null, {}, { schema: 'obsvr-strict-receipt-envelope-v1' }];
    expect(() => verifyStrictReceiptChain(malformed)).not.toThrow();
    const result = verifyStrictReceiptChain(malformed);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('receipt_schema_invalid:index-0');
    expect(result.errors).toContain('receipt_semantic_invalid:index-1');
  });

  it('accepts self-asserted or pinned valid chains in provided order', () => {
    const valid = envelopes();
    expect(verifyStrictReceiptChain(valid)).toEqual({ valid: true, errors: [] });
    expect(verifyStrictReceiptChain(valid, {
      pinned_public_key_b64: FIXTURE.public_test_key.public_key_b64,
    })).toEqual({ valid: true, errors: [] });
  });

  it('does not sort away reordered receipts and rejects tampering inside the chain', () => {
    const reordered = envelopes();
    [reordered[1], reordered[2]] = [reordered[2], reordered[1]];
    expect(verifyStrictReceiptChain(reordered).errors.some((error) => error.startsWith('sequence_order_invalid'))).toBe(true);
    const tampered = envelopes();
    tampered[1].body.action.name = 'tampered';
    expect(verifyStrictReceiptChain(tampered).errors).toContain(`receipt_hash_invalid:${tampered[1].body.receipt_id}`);
    const approvalBinding = envelopes();
    approvalBinding[3].body.suspension!.approval_action_hash = '8'.repeat(64);
    expect(verifyStrictReceiptChain(approvalBinding).errors)
      .toContain(`receipt_hash_invalid:${approvalBinding[3].body.receipt_id}`);
  });

  it('checks sequence links, time, session, and resolution continuity', () => {
    const tests: Array<[string, (chain: StrictReceiptEnvelope[]) => void, string]> = [
      ['previous_hash_mismatch', (chain) => resign(chain, 1, (body) => { body.previous_receipt_hash = '0'.repeat(64); }), 'previous_hash_mismatch'],
      ['timestamp_regression', (chain) => resign(chain, 1, (body) => { body.timestamp_ms = chain[0].body.timestamp_ms - 1; }), 'timestamp_regression'],
      ['session_mismatch', (chain) => resign(chain, 1, (body) => { body.session_id = 'other'; body.receipt_id = 'other:2'; }), 'session_mismatch'],
      ['resolution_reference_invalid', (chain) => resign(chain, 4, (body) => { body.resolution!.resolves_receipt_hash = '0'.repeat(64); }), 'resolution_reference_invalid'],
      ['resolution_suspension_mismatch', (chain) => resign(chain, 4, (body) => { body.resolution!.suspension_id = 'other'; }), 'resolution_suspension_mismatch'],
      ['resolution_method_mismatch', (chain) => resign(chain, 4, (body) => { body.resolution!.method = 'context_supplied'; }), 'resolution_method_mismatch'],
      ['resolution_time_invalid', (chain) => resign(chain, 4, (body) => { body.resolution!.resolved_at_ms = chain[3].body.timestamp_ms - 1; }), 'resolution_time_invalid'],
      ['resolution_after_expiry', (chain) => resign(chain, 4, (body) => { body.resolution!.resolved_at_ms = chain[3].body.suspension!.expires_at_ms + 1; body.timestamp_ms = body.resolution!.resolved_at_ms; }), 'resolution_after_expiry'],
      ['resolution_action_mismatch', (chain) => resign(chain, 4, (body) => { body.action.action_id = 'other'; }), 'resolution_action_mismatch'],
      ['resolution_initiator_mismatch', (chain) => resign(chain, 4, (body) => { body.initiator.agent_id = 'other'; }), 'resolution_initiator_mismatch'],
      ['resolution_prior_not_suspended', (chain) => resign(chain, 4, (body) => { body.resolution!.resolves_receipt_hash = chain[0].receipt_hash; body.resolution!.suspension_id = 'other'; body.action = clone(chain[0].body.action); }), 'resolution_prior_not_suspended'],
    ];
    for (const [id, mutate, expected] of tests) {
      expect(FIXTURE.negative_case_ids).toContain(id);
      const chain = envelopes();
      mutate(chain);
      expect(verifyStrictReceiptChain(chain).errors.some((error) => error.startsWith(expected))).toBe(true);
    }
  });
});
