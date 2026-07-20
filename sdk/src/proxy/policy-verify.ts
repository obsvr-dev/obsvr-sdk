/**
 * SDK-side verification of the Ed25519-signed policy payload (B2).
 *
 * When obsvr.init is given a pinned `policyPublicKey`, the SDK REQUIRES a valid
 * signature on every /policies response before applying it. A tamperer on the
 * delivery path cannot modify the rules (the signed hash breaks) or forge a
 * signature (no private key), and cannot roll the policy back to an older signed
 * version (issued_at monotonicity). On any verification failure the SDK fails
 * closed: it does NOT apply the fetched rules and keeps its last-good policy.
 *
 * Dependency-free (node:crypto). The canonical hash uses the SAME stableStringify
 * as the rules engine, so the hash the SDK recomputes matches the one ingest
 * signed byte-for-byte (ingest/lib/policy-signing.ts).
 */

import { createHash, createPublicKey, verify as edVerify } from 'node:crypto';
import { stableStringify } from '../policy/rules.js';

/** The signature block ingest attaches to a /policies response. */
export interface PolicySignature {
  alg: 'ed25519';
  key_id: string;
  public_key: string;
  issued_at: string;
  rules_sha256: string;
  approvals_sha256: string;
  value: string;
}

const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function payloadHash(value: unknown): string {
  return createHash('sha256').update(stableStringify(value), 'utf8').digest('hex');
}

function canonicalPolicyMessage(s: Pick<PolicySignature, 'issued_at' | 'rules_sha256' | 'approvals_sha256'>): string {
  return `obsvr-policy-v1|${s.issued_at}|${s.rules_sha256}|${s.approvals_sha256}`;
}

function keyIdOf(rawB64: string): string {
  return createHash('sha256').update(Buffer.from(rawB64, 'base64')).digest('hex').slice(0, 16);
}

export interface PolicyVerifyResult {
  ok: boolean;
  reason?: string;
}

/**
 * Verify a signed policy payload against the pinned public key.
 * @param rules      the raw rules array as received (pre-validation)
 * @param approvals  the raw approvals array as received
 * @param signature  the response's signature block (or undefined if unsigned)
 * @param pinnedPublicKeyB64  base64 raw 32-byte Ed25519 key from obsvr.init
 * @param lastAppliedIssuedAt  issued_at of the last applied signed policy (anti-rollback), or undefined
 */
export function verifyPolicySignature(
  rules: unknown[],
  approvals: unknown[],
  signature: PolicySignature | undefined,
  pinnedPublicKeyB64: string,
  lastAppliedIssuedAt?: string,
): PolicyVerifyResult {
  if (!signature) return { ok: false, reason: 'policy signature required (policyPublicKey pinned) but response was unsigned' };
  if (signature.alg !== 'ed25519') return { ok: false, reason: `unsupported signature alg: ${signature.alg}` };

  // The inline key must be the pinned key (defends against a swapped key_id).
  if (signature.public_key !== pinnedPublicKeyB64) {
    return { ok: false, reason: 'signature public_key does not match the pinned policyPublicKey' };
  }
  if (signature.key_id !== keyIdOf(pinnedPublicKeyB64)) {
    return { ok: false, reason: 'signature key_id does not match its public key' };
  }

  // The signed hashes must match the rules/approvals actually received.
  if (payloadHash(rules) !== signature.rules_sha256) {
    return { ok: false, reason: 'rules hash does not match the signed rules_sha256 (rules were altered in transit)' };
  }
  if (payloadHash(approvals) !== signature.approvals_sha256) {
    return { ok: false, reason: 'approvals hash does not match the signed approvals_sha256' };
  }

  // Anti-rollback: never accept a signed policy older than the last applied one.
  if (lastAppliedIssuedAt && signature.issued_at < lastAppliedIssuedAt) {
    return { ok: false, reason: `signed policy issued_at ${signature.issued_at} is older than the last applied ${lastAppliedIssuedAt} (rollback)` };
  }

  // Ed25519 verification over the canonical message.
  try {
    const raw = Buffer.from(pinnedPublicKeyB64, 'base64');
    if (raw.length !== 32) return { ok: false, reason: 'pinned policyPublicKey is not a 32-byte Ed25519 key' };
    const pub = createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
    const message = Buffer.from(canonicalPolicyMessage(signature), 'utf8');
    const ok = edVerify(null, message, pub, Buffer.from(signature.value, 'base64'));
    return ok ? { ok: true } : { ok: false, reason: 'Ed25519 signature verification failed' };
  } catch (err) {
    return { ok: false, reason: `signature verification error: ${(err as Error).message}` };
  }
}
