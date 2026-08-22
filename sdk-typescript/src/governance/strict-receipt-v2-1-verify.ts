import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import {
  STRICT_RECEIPT_V21_BODY_DOMAIN,
  STRICT_RECEIPT_V21_ENVELOPE_SCHEMA,
  StrictReceiptV21ValidationError,
  buildStrictReceiptV21Body,
  strictReceiptV21KeyId,
  strictReceiptV21SignaturePreimage,
  type StrictReceiptV21Body,
  type StrictReceiptV21Envelope,
} from './strict-receipt-v2-1.js';

const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const KEY_ID = /^sha256:[0-9a-f]{64}$/;
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export interface TrustedAgentKeyV21 {
  tenant_id: string;
  agent_ref_hash: string;
  key_id: string;
  public_key_b64: string;
  status: 'active' | 'revoked';
}
export interface StrictReceiptV21TrustOptions {
  trusted_agent_keys: readonly TrustedAgentKeyV21[];
  allowed_evaluator_manifest_hashes: readonly string[];
}
export type StrictReceiptV21KeyTrust = 'trusted' | 'unknown' | 'revoked' | 'mismatch' | 'malformed';
export type StrictReceiptV21EvaluatorTrust = 'allowlisted' | 'unknown' | 'malformed';
export interface StrictReceiptV21Verification {
  schema_valid: boolean;
  semantic_valid: boolean;
  hash_valid: boolean;
  signature_valid: boolean;
  identity_binding_valid: boolean;
  integrity_valid: boolean;
  key_trust: StrictReceiptV21KeyTrust;
  evaluator_trust: StrictReceiptV21EvaluatorTrust;
  trusted: boolean;
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown> : undefined;
}
function exact(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every((key) => Object.prototype.hasOwnProperty.call(value, key));
}
function u64(value: number): Buffer { const bytes = Buffer.alloc(8); bytes.writeBigUInt64BE(BigInt(value)); return bytes; }
function decodePublicKey(value: unknown): Buffer | undefined {
  if (typeof value !== 'string') return undefined;
  try { const raw = Buffer.from(value, 'base64'); return raw.length === 32 && raw.toString('base64') === value ? raw : undefined; } catch { return undefined; }
}
function registryTrust(
  body: Record<string, unknown> | undefined,
  rawKey: Buffer | undefined,
  options: StrictReceiptV21TrustOptions,
): StrictReceiptV21KeyTrust {
  const identity = record(body?.identity); const initiator = record(identity?.initiator);
  const tenant = body?.tenant_id; const agent = initiator?.agent_ref_hash; const keyId = initiator?.key_id;
  if (typeof tenant !== 'string' || typeof agent !== 'string' || typeof keyId !== 'string' || !rawKey) return 'malformed';
  const matches = options.trusted_agent_keys.filter((entry) => (
    entry.tenant_id === tenant && entry.agent_ref_hash === agent && entry.key_id === keyId
  ));
  if (matches.length === 0) return 'unknown';
  if (matches.length !== 1) return 'malformed';
  const entryKey = decodePublicKey(matches[0].public_key_b64);
  if (!entryKey || strictReceiptV21KeyId(entryKey) !== matches[0].key_id) return 'malformed';
  if (!entryKey.equals(rawKey)) return 'mismatch';
  return matches[0].status === 'active' ? 'trusted' : 'revoked';
}
function evaluatorTrust(body: Record<string, unknown> | undefined, options: StrictReceiptV21TrustOptions): StrictReceiptV21EvaluatorTrust {
  const evaluation = record(body?.evaluation); const manifest = evaluation?.evaluator_manifest_hash;
  if (typeof manifest !== 'string' || !HEX64.test(manifest)) return 'malformed';
  const validAllowlist = options.allowed_evaluator_manifest_hashes.every((value) => HEX64.test(value));
  if (!validAllowlist) return 'malformed';
  return options.allowed_evaluator_manifest_hashes.includes(manifest) ? 'allowlisted' : 'unknown';
}

export function verifyStrictReceiptV21(value: unknown, options: StrictReceiptV21TrustOptions): StrictReceiptV21Verification {
  const envelope = record(value); const body = record(envelope?.body); const signature = record(envelope?.signature);
  const schemaValid = Boolean(
    envelope && exact(envelope, ['schema', 'body', 'receipt_hash', 'signature', 'public_key_b64'])
    && envelope.schema === STRICT_RECEIPT_V21_ENVELOPE_SCHEMA && body
    && typeof envelope.receipt_hash === 'string' && HEX64.test(envelope.receipt_hash)
    && signature && exact(signature, ['algorithm', 'key_id', 'value'])
    && signature.algorithm === 'Ed25519' && typeof signature.key_id === 'string' && KEY_ID.test(signature.key_id)
    && typeof signature.value === 'string' && HEX128.test(signature.value)
    && typeof envelope.public_key_b64 === 'string'
  );
  let semanticValid = false;
  if (body) {
    try { semanticValid = canonicalJsonForHash(buildStrictReceiptV21Body(body as unknown as StrictReceiptV21Body)) === canonicalJsonForHash(body); }
    catch (error) { if (!(error instanceof StrictReceiptV21ValidationError)) semanticValid = false; }
  }
  let hashValid = false;
  if (body && typeof envelope?.receipt_hash === 'string') {
    try {
      const canonical = Buffer.from(canonicalJsonForHash(body), 'utf8');
      const actual = createHash('sha256').update(Buffer.concat([
        Buffer.from(STRICT_RECEIPT_V21_BODY_DOMAIN), Buffer.from([0]), u64(canonical.length), canonical,
      ])).digest('hex');
      hashValid = actual === envelope.receipt_hash;
    } catch { hashValid = false; }
  }
  const rawKey = decodePublicKey(envelope?.public_key_b64);
  const identity = record(body?.identity); const initiator = record(identity?.initiator);
  const bodyKeyId = initiator?.key_id; const signatureKeyId = signature?.key_id;
  let fingerprint: string | undefined;
  try { if (rawKey) fingerprint = strictReceiptV21KeyId(rawKey); } catch { fingerprint = undefined; }
  const identityBindingValid = typeof bodyKeyId === 'string' && bodyKeyId === signatureKeyId && bodyKeyId === fingerprint;
  let signatureValid = false;
  if (rawKey && typeof signatureKeyId === 'string' && typeof envelope?.receipt_hash === 'string' && typeof signature?.value === 'string') {
    try {
      const publicKey = createPublicKey({ key: Buffer.concat([SPKI_PREFIX, rawKey]), format: 'der', type: 'spki' });
      signatureValid = cryptoVerify(null, strictReceiptV21SignaturePreimage(signatureKeyId, envelope.receipt_hash), publicKey, Buffer.from(signature.value, 'hex'));
    } catch { signatureValid = false; }
  }
  const keyTrust = registryTrust(body, rawKey, options); const manifestTrust = evaluatorTrust(body, options);
  const integrityValid = schemaValid && semanticValid && hashValid && signatureValid && identityBindingValid;
  return {
    schema_valid: schemaValid, semantic_valid: semanticValid, hash_valid: hashValid,
    signature_valid: signatureValid, identity_binding_valid: identityBindingValid,
    integrity_valid: integrityValid, key_trust: keyTrust, evaluator_trust: manifestTrust,
    trusted: integrityValid && keyTrust === 'trusted' && manifestTrust === 'allowlisted',
  };
}

function sameAction(left: StrictReceiptV21Body['action'], right: StrictReceiptV21Body['action']): boolean {
  return ['action_id', 'kind', 'name', 'arguments_hash', 'target_hash'].every(
    (field) => left[field as keyof typeof left] === right[field as keyof typeof right],
  );
}
function resolutionMethodMatches(type: 'approval' | 'context', method: string): boolean {
  return type === 'approval'
    ? ['approval_granted', 'approval_denied', 'expired', 'cancelled'].includes(method)
    : ['context_supplied', 'expired', 'cancelled'].includes(method);
}

export function verifyStrictReceiptV21Chain(
  values: readonly unknown[], options: StrictReceiptV21TrustOptions,
): { valid: boolean; errors: string[] } {
  if (values.length === 0) return { valid: false, errors: ['empty_chain'] };
  const errors: string[] = []; const byHash = new Map<string, StrictReceiptV21Envelope>();
  const resolved = new Set<string>(); let tenant: string | undefined; let session: string | undefined;
  let previous: StrictReceiptV21Envelope | undefined;
  values.forEach((candidate, index) => {
    const envelope = record(candidate); const rawBody = record(envelope?.body);
    const id = typeof rawBody?.receipt_id === 'string' ? rawBody.receipt_id : `index-${index}`;
    const result = verifyStrictReceiptV21(candidate, options);
    for (const [field, code] of [
      ['schema_valid', 'receipt_schema_invalid'], ['semantic_valid', 'receipt_semantic_invalid'],
      ['hash_valid', 'receipt_hash_invalid'], ['signature_valid', 'receipt_signature_invalid'],
      ['identity_binding_valid', 'receipt_identity_invalid'],
    ] as const) if (!result[field]) errors.push(`${code}:${id}`);
    if (result.key_trust !== 'trusted') errors.push(`receipt_key_untrusted:${id}`);
    if (result.evaluator_trust !== 'allowlisted') errors.push(`receipt_evaluator_untrusted:${id}`);
    if (!result.integrity_valid || !envelope || !rawBody) return;
    const current = { ...envelope, body: buildStrictReceiptV21Body(rawBody as unknown as StrictReceiptV21Body) } as unknown as StrictReceiptV21Envelope;
    const body = current.body;
    tenant ??= body.tenant_id; session ??= body.session_id;
    if (body.tenant_id !== tenant) errors.push(`tenant_mismatch:${id}`);
    if (body.session_id !== session) errors.push(`session_mismatch:${id}`);
    if (body.sequence !== index + 1) errors.push(`sequence_order_invalid:${id}`);
    if ((previous?.receipt_hash ?? null) !== body.previous_receipt_hash) errors.push(`previous_hash_mismatch:${id}`);
    if (previous && body.timestamp_ms < previous.body.timestamp_ms) errors.push(`timestamp_regression:${id}`);
    if (byHash.has(current.receipt_hash)) errors.push(`duplicate_receipt:${id}`);
    if (body.record_type === 'resolution' && body.resolution) {
      const target = byHash.get(body.resolution.resolves_receipt_hash); const targetId = body.resolution.resolves_receipt_hash;
      if (!target || target.body.record_type !== 'decision' || !target.body.suspension) errors.push(`resolution_target_invalid:${id}`);
      else {
        if (resolved.has(targetId)) errors.push(`duplicate_resolution:${id}`); else resolved.add(targetId);
        if (canonicalJsonForHash(body.identity) !== canonicalJsonForHash(target.body.identity)) errors.push(`resolution_identity_mismatch:${id}`);
        if (!sameAction(body.action, target.body.action) || body.context_hash !== target.body.context_hash) errors.push(`resolution_action_mismatch:${id}`);
        if (body.resolution.suspension_id !== target.body.suspension.suspension_id) errors.push(`resolution_suspension_mismatch:${id}`);
        if (!resolutionMethodMatches(target.body.suspension.type, body.resolution.method)) errors.push(`resolution_method_mismatch:${id}`);
        if (body.timestamp_ms < target.body.timestamp_ms) errors.push(`resolution_before_decision:${id}`);
        if (['approval_granted', 'context_supplied'].includes(body.resolution.method)
          && body.timestamp_ms >= target.body.suspension.expires_at_ms) errors.push(`resolution_after_expiry:${id}`);
      }
    }
    byHash.set(current.receipt_hash, current); previous = current;
  });
  return { valid: errors.length === 0, errors };
}
