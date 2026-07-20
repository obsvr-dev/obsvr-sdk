import { generateKeyPairSync, createPublicKey, sign as edSign, createHash, type KeyObject } from 'node:crypto';
import { verifyPolicySignature, type PolicySignature } from '../../src/proxy/policy-verify';
import { stableStringify } from '../../src/policy/rules';

/**
 * B2 SDK-side policy-signature verification. A signature block is constructed
 * exactly as ingest/lib/policy-signing.ts would, then verifyPolicySignature is
 * exercised for the accept case and every fail-closed reject case.
 */

function rawPub(pub: KeyObject): Buffer {
  const der = pub.export({ type: 'spki', format: 'der' }) as Buffer;
  return der.subarray(der.length - 32);
}
function payloadHash(v: unknown): string {
  return createHash('sha256').update(stableStringify(v), 'utf8').digest('hex');
}
function keyId(rawB64: string): string {
  return createHash('sha256').update(Buffer.from(rawB64, 'base64')).digest('hex').slice(0, 16);
}

const RULES = [{ id: 'r1', name: 'block secret', enabled: true, action: 'block', type: 'keyword', conditions: { keywords: ['secret'] } }];
const APPROVALS: unknown[] = [];

function makeSignature(opts: { issuedAt?: string; key?: KeyObject; rules?: unknown[] } = {}): { sig: PolicySignature; pubB64: string } {
  const { privateKey, publicKey } = opts.key
    ? { privateKey: opts.key, publicKey: createPublicKey(opts.key) }
    : generateKeyPairSync('ed25519');
  const pubB64 = rawPub(publicKey).toString('base64');
  const issued_at = opts.issuedAt ?? '2026-07-12T00:00:00.000Z';
  const rules_sha256 = payloadHash(opts.rules ?? RULES);
  const approvals_sha256 = payloadHash(APPROVALS);
  const message = `obsvr-policy-v1|${issued_at}|${rules_sha256}|${approvals_sha256}`;
  const value = edSign(null, Buffer.from(message, 'utf8'), privateKey).toString('base64');
  return { sig: { alg: 'ed25519', key_id: keyId(pubB64), public_key: pubB64, issued_at, rules_sha256, approvals_sha256, value }, pubB64 };
}

describe('verifyPolicySignature', () => {
  it('accepts a valid signature over the received payload', () => {
    const { sig, pubB64 } = makeSignature();
    expect(verifyPolicySignature(RULES, APPROVALS, sig, pubB64)).toEqual({ ok: true });
  });

  it('rejects when the rules were altered in transit (hash mismatch)', () => {
    const { sig, pubB64 } = makeSignature();
    const tampered = [{ ...RULES[0], conditions: { keywords: ['nothing'] } }];
    const r = verifyPolicySignature(tampered, APPROVALS, sig, pubB64);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/rules hash/);
  });

  it('rejects a signature from a different key than pinned', () => {
    const { sig } = makeSignature();
    const { pubB64: otherKey } = makeSignature();
    const r = verifyPolicySignature(RULES, APPROVALS, sig, otherKey);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/public_key does not match/);
  });

  it('rejects a rolled-back policy (issued_at older than last applied)', () => {
    const { sig, pubB64 } = makeSignature({ issuedAt: '2026-07-10T00:00:00.000Z' });
    const r = verifyPolicySignature(RULES, APPROVALS, sig, pubB64, '2026-07-11T00:00:00.000Z');
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/rollback/);
  });

  it('rejects an unsigned response when a key is pinned (fail-closed)', () => {
    const { pubB64 } = makeSignature();
    const r = verifyPolicySignature(RULES, APPROVALS, undefined, pubB64);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/unsigned/);
  });

  it('rejects a forged signature value', () => {
    const { sig, pubB64 } = makeSignature();
    const r = verifyPolicySignature(RULES, APPROVALS, { ...sig, value: Buffer.alloc(64).toString('base64') }, pubB64);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/verification failed/);
  });

  it('accepts an equal-or-newer issued_at (not a rollback)', () => {
    const { sig, pubB64 } = makeSignature({ issuedAt: '2026-07-12T00:00:00.000Z' });
    expect(verifyPolicySignature(RULES, APPROVALS, sig, pubB64, '2026-07-11T00:00:00.000Z').ok).toBe(true);
  });
});
