import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadDeviceSigner, type DeviceSigner } from '../../src/proxy/device-identity.js';
import {
  StrictReceiptV2ValidationError,
  buildStrictReceiptV2Body,
  canonicalizeStrictReceiptV2Body,
  signStrictReceiptV2,
  strictReceiptV2Hash,
  strictReceiptV2KeyId,
  type StrictReceiptV2Body,
  type StrictReceiptV2Envelope,
} from '../../src/governance/strict-receipt-v2.js';
import {
  verifyStrictReceiptV2,
  verifyStrictReceiptV2Chain,
} from '../../src/governance/strict-receipt-v2-verify.js';
import { signStrictReceipt, type StrictReceiptBody } from '../../src/governance/strict-receipt.js';
import { verifyStrictReceipt } from '../../src/governance/strict-receipt-verify.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const FIXTURE = JSON.parse(readFileSync(
  join(ROOT, 'conformance/fixtures/strict_receipts_v2.json'), 'utf8',
));
const V1_FIXTURE = JSON.parse(readFileSync(
  join(ROOT, 'conformance/fixtures/strict_receipts.json'), 'utf8',
));

function clone<T>(value: T): T { return structuredClone(value); }
function signer(seedHex = FIXTURE.public_test_key.seed_hex): DeviceSigner {
  const directory = mkdtempSync(join(tmpdir(), 'obsvr-strict-v2-'));
  const path = join(directory, 'public-test-seed.key');
  writeFileSync(path, seedHex, 'ascii');
  return loadDeviceSigner(path);
}
function inputBody(vector: typeof FIXTURE.vectors[number]): StrictReceiptV2Body {
  const body = clone(vector.body) as StrictReceiptV2Body;
  body.evaluation.rule_ids = clone(vector.input_rule_ids);
  return body;
}
function envelopes(device = signer()): StrictReceiptV2Envelope[] {
  return FIXTURE.vectors.map((vector: typeof FIXTURE.vectors[number]) =>
    signStrictReceiptV2(inputBody(vector), device, true));
}

describe('strict receipt v2 canonical fixture', () => {
  it('pins full key identity and non-conformance status', () => {
    const device = signer();
    expect(FIXTURE.claimable).toBe(false);
    expect(FIXTURE.description).toContain('not official AARM conformance vectors');
    expect(strictReceiptV2KeyId(device.rawPublicKey)).toBe(FIXTURE.public_test_key.key_id);
  });

  for (const vector of FIXTURE.vectors) {
    it(`matches canonical bytes, hash, and signature: ${vector.id}`, () => {
      const body = inputBody(vector);
      const envelope = signStrictReceiptV2(body, signer(), true);
      expect(canonicalizeStrictReceiptV2Body(body)).toBe(vector.canonical);
      expect(strictReceiptV2Hash(body)).toBe(vector.receipt_hash);
      expect(envelope.receipt_hash).toBe(vector.receipt_hash);
      expect(envelope.signature.value).toBe(vector.signature);
      expect(envelope.body).toEqual(JSON.parse(vector.canonical));
      expect('target' in envelope.body.action).toBe(false);
      expect(envelope.body.action.target_hash).toMatch(/^[0-9a-f]{64}$/);
      expect(envelope.body.tenant_id).toBe('tenant-北');
    });
  }
});

describe('strict receipt v2 validation and isolation', () => {
  it('preserves embedded-key integrity axes but trusts only a valid pin', () => {
    const chain = envelopes();
    const embeddedOnly = verifyStrictReceiptV2Chain(chain);
    expect(embeddedOnly.valid).toBe(false);
    expect(embeddedOnly.errors).toEqual(chain.map(
      (receipt) => `receipt_key_untrusted:${receipt.body.receipt_id}`,
    ));
    expect(verifyStrictReceiptV2Chain(chain, {
      pinned_public_key_b64: FIXTURE.public_test_key.public_key_b64,
    })).toEqual({ valid: true, errors: [] });
    expect(verifyStrictReceiptV2(chain[0])).toEqual({
      schema_valid: true, hash_valid: true, signature_valid: true,
      semantic_valid: true, identity_binding_valid: true, key_trust: 'self_asserted',
    });
    const invalidPin = verifyStrictReceiptV2(chain[0], { pinned_public_key_b64: 'bad' });
    expect(invalidPin.key_trust).toBe('unknown');
    expect(invalidPin.signature_valid).toBe(false);
    expect(invalidPin.identity_binding_valid).toBe(false);

    const attacker = signer('11'.repeat(32));
    const attackerBody = inputBody(FIXTURE.vectors[0]);
    attackerBody.initiator.key_id = strictReceiptV2KeyId(attacker.rawPublicKey);
    const attackerReceipt = signStrictReceiptV2(attackerBody, attacker, true);
    expect(verifyStrictReceiptV2(attackerReceipt).signature_valid).toBe(true);
    expect(verifyStrictReceiptV2Chain([attackerReceipt]).errors)
      .toContain(`receipt_key_untrusted:${attackerBody.receipt_id}`);
  });

  it('binds the tenant into canonical bytes, hash, signature, and chain', () => {
    const device = signer();
    const original = signStrictReceiptV2(inputBody(FIXTURE.vectors[0]), device, true);
    const otherBody = inputBody(FIXTURE.vectors[0]);
    otherBody.tenant_id = 'tenant-other';
    const other = signStrictReceiptV2(otherBody, device, true);
    expect(other.receipt_hash).not.toBe(original.receipt_hash);
    expect(other.signature.value).not.toBe(original.signature.value);
    const tampered = clone(original);
    tampered.body.tenant_id = 'tenant-other';
    expect(verifyStrictReceiptV2(tampered).hash_valid).toBe(false);

    const chain = envelopes(device);
    const second = inputBody(FIXTURE.vectors[1]);
    second.tenant_id = 'tenant-other';
    chain[1] = signStrictReceiptV2(second, device, true);
    expect(verifyStrictReceiptV2Chain(chain).errors)
      .toContain(`tenant_mismatch:${second.receipt_id}`);
  });

  it('enforces exact keys, target privacy, bounds, and scalar validity', () => {
    const body = inputBody(FIXTURE.vectors[0]);
    (body.action as unknown as Record<string, unknown>).target = 'raw-target';
    expect(() => buildStrictReceiptV2Body(body)).toThrow(StrictReceiptV2ValidationError);
    const unknown = inputBody(FIXTURE.vectors[0]) as unknown as Record<string, unknown>;
    unknown.extra = true;
    expect(() => buildStrictReceiptV2Body(unknown as unknown as StrictReceiptV2Body)).toThrow();
    const wrongEngine = inputBody(FIXTURE.vectors[0]);
    wrongEngine.evaluation.engine_version = 'obsvr-intent/1';
    expect(() => buildStrictReceiptV2Body(wrongEngine)).toThrow(/engine_version/);
    const noncanonical = envelopes()[0];
    noncanonical.body.evaluation.rule_ids = ['rule-z', 'rule-a'];
    expect(verifyStrictReceiptV2(noncanonical).semantic_valid).toBe(false);
    const oversizedSet = inputBody(FIXTURE.vectors[0]);
    oversizedSet.evaluation.rule_ids = Array(65).fill('duplicate');
    expect(() => buildStrictReceiptV2Body(oversizedSet)).toThrow(/exceeds 64 items/);
    for (const tenant of ['x'.repeat(256), '🚀'.repeat(64)]) {
      const bounded = inputBody(FIXTURE.vectors[0]); bounded.tenant_id = tenant;
      expect(buildStrictReceiptV2Body(bounded).tenant_id).toBe(tenant);
    }
    for (const tenant of ['x'.repeat(257), '🚀'.repeat(65), '\ud800']) {
      const rejected = inputBody(FIXTURE.vectors[0]); rejected.tenant_id = tenant;
      expect(() => buildStrictReceiptV2Body(rejected)).toThrow(StrictReceiptV2ValidationError);
    }
  });

  it('keeps v1 and v2 domains and verifiers isolated', () => {
    const device = signer();
    const v2 = signStrictReceiptV2(inputBody(FIXTURE.vectors[0]), device, true);
    const rawV1 = clone(V1_FIXTURE.vectors[0].body) as StrictReceiptBody;
    rawV1.evaluation.rule_ids = clone(V1_FIXTURE.vectors[0].input_rule_ids);
    const v1 = signStrictReceipt(rawV1, device, true);
    expect(verifyStrictReceipt(v1).schema_valid).toBe(true);
    expect(verifyStrictReceipt(v2).schema_valid).toBe(false);
    expect(verifyStrictReceiptV2(v1).schema_valid).toBe(false);
    expect(v1.receipt_hash).not.toBe(v2.receipt_hash);
  });

  it('refuses malformed, wrong-key, and public-key-mismatched signers', () => {
    const device = signer();
    const body = inputBody(FIXTURE.vectors[0]);
    const malformed = { ...device, signBytes: () => 'bad' };
    expect(() => signStrictReceiptV2(body, malformed)).toThrow(/invalid Ed25519/);
    const wrong = signer('11'.repeat(32));
    const wrongSignature = { ...device, signBytes: (bytes: Uint8Array) => wrong.signBytes(bytes) };
    expect(() => signStrictReceiptV2(body, wrongSignature)).toThrow(/self-verification/);
    const publicMismatch = { ...device, publicKeyB64: wrong.publicKeyB64 };
    expect(() => signStrictReceiptV2(body, publicMismatch)).toThrow(/does not match/);
  });
});

describe('strict receipt v2 chain adversarial cases', () => {
  it('does not sort reordered receipts or ignore tampering', () => {
    const reordered = envelopes();
    [reordered[0], reordered[1]] = [reordered[1], reordered[0]];
    expect(verifyStrictReceiptV2Chain(reordered).errors.some(
      (error) => error.startsWith('sequence_order_invalid'),
    )).toBe(true);
    const tampered = envelopes();
    tampered[1].body.action.name = 'tampered';
    expect(verifyStrictReceiptV2Chain(tampered).errors)
      .toContain(`receipt_hash_invalid:${tampered[1].body.receipt_id}`);
  });

  it('rejects duplicate receipts and cross-key or cross-agent splicing', () => {
    const device = signer();
    const duplicate = envelopes(device);
    duplicate.splice(1, 0, clone(duplicate[0]));
    expect(verifyStrictReceiptV2Chain(duplicate).errors)
      .toContain(`duplicate_receipt:${duplicate[1].body.receipt_id}`);

    const spliced = envelopes(device);
    const secondBody = inputBody(FIXTURE.vectors[1]);
    secondBody.initiator.agent_id = 'other-agent';
    spliced[1] = signStrictReceiptV2(secondBody, device, true);
    expect(verifyStrictReceiptV2Chain(spliced).errors)
      .toContain(`initiator_mismatch:${secondBody.receipt_id}`);

    const other = signer('11'.repeat(32));
    secondBody.initiator.agent_id = spliced[0].body.initiator.agent_id;
    secondBody.initiator.key_id = strictReceiptV2KeyId(other.rawPublicKey);
    spliced[1] = signStrictReceiptV2(secondBody, other, true);
    expect(verifyStrictReceiptV2Chain(spliced).errors)
      .toContain(`signer_key_mismatch:${secondBody.receipt_id}`);
  });

  it('rejects a second resolution for the same suspension', () => {
    const device = signer();
    const chain = envelopes(device);
    const duplicate = clone(chain[2].body);
    duplicate.sequence = 4;
    duplicate.receipt_id = `${duplicate.session_id}:4`;
    duplicate.timestamp_ms += 100;
    duplicate.previous_receipt_hash = chain[2].receipt_hash;
    chain.push(signStrictReceiptV2(duplicate, device, true));
    expect(verifyStrictReceiptV2Chain(chain).errors)
      .toContain(`duplicate_resolution:${duplicate.receipt_id}`);
  });

  it('enforces exact expiry boundaries against both signed timestamps', () => {
    const device = signer();
    const pin = { pinned_public_key_b64: FIXTURE.public_test_key.public_key_b64 };
    const atExpiry = envelopes(device);
    const expiry = atExpiry[1].body.suspension!.expires_at_ms;
    const exact = clone(atExpiry[2].body);
    exact.resolution!.resolved_at_ms = expiry;
    exact.timestamp_ms = expiry;
    atExpiry[2] = signStrictReceiptV2(exact, device, true);
    expect(verifyStrictReceiptV2Chain(atExpiry, pin).errors)
      .toContain(`resolution_after_expiry:${exact.receipt_id}`);

    const forgedTimestamp = envelopes(device);
    const forged = clone(forgedTimestamp[2].body);
    forged.resolution!.resolved_at_ms = expiry - 1;
    forged.timestamp_ms = expiry;
    forgedTimestamp[2] = signStrictReceiptV2(forged, device, true);
    expect(verifyStrictReceiptV2Chain(forgedTimestamp, pin).errors)
      .toContain(`resolution_after_expiry:${forged.receipt_id}`);

    const expired = envelopes(device);
    const expiredBody = clone(expired[2].body);
    expiredBody.resolution!.method = 'expired';
    expiredBody.resolution!.resolved_at_ms = expiry;
    expiredBody.timestamp_ms = expiry;
    expiredBody.evaluation.outcome = 'DENY';
    expiredBody.evaluation.reason_code = 'approval_expired';
    expiredBody.execution_authorized = false;
    expired[2] = signStrictReceiptV2(expiredBody, device, true);
    expect(verifyStrictReceiptV2Chain(expired, pin)).toEqual({ valid: true, errors: [] });

    const early = envelopes(device);
    const earlyBody = clone(expiredBody);
    earlyBody.resolution!.resolved_at_ms = expiry - 1;
    early[2] = signStrictReceiptV2(earlyBody, device, true);
    expect(verifyStrictReceiptV2Chain(early, pin).errors)
      .toContain(`resolution_before_expiry:${earlyBody.receipt_id}`);
  });

  it('enforces referenced time and resolution method-to-outcome semantics', () => {
    const device = signer();
    const pin = { pinned_public_key_b64: FIXTURE.public_test_key.public_key_b64 };
    const wrongOutcome = envelopes(device);
    const deniedGrant = clone(wrongOutcome[2].body);
    deniedGrant.evaluation.outcome = 'DENY';
    deniedGrant.execution_authorized = false;
    wrongOutcome[2] = signStrictReceiptV2(deniedGrant, device, true);
    expect(verifyStrictReceiptV2Chain(wrongOutcome, pin).errors)
      .toContain(`resolution_outcome_mismatch:${deniedGrant.receipt_id}`);

    const beforePrior = envelopes(device);
    const before = clone(beforePrior[2].body);
    before.timestamp_ms = beforePrior[1].body.timestamp_ms - 1;
    before.resolution!.resolved_at_ms = before.timestamp_ms;
    beforePrior[2] = signStrictReceiptV2(before, device, true);
    expect(verifyStrictReceiptV2Chain(beforePrior, pin).errors)
      .toContain(`resolution_time_invalid:${before.receipt_id}`);

    const nonfinalContext = clone(beforePrior[2].body);
    nonfinalContext.resolution!.method = 'context_supplied';
    nonfinalContext.evaluation.outcome = 'STEP_UP';
    nonfinalContext.execution_authorized = false;
    expect(() => buildStrictReceiptV2Body(nonfinalContext)).toThrow(/outcome must be final/);
    const allowedExpiry = clone(beforePrior[2].body);
    allowedExpiry.resolution!.method = 'expired';
    allowedExpiry.evaluation.outcome = 'ALLOW';
    allowedExpiry.execution_authorized = true;
    expect(() => buildStrictReceiptV2Body(allowedExpiry)).toThrow(/requires DENY/);
  });
});
