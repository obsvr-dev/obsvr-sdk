import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import {
  STRICT_RECEIPT_BODY_DOMAIN,
  STRICT_RECEIPT_ENVELOPE_SCHEMA,
  buildStrictReceiptBody,
  strictReceiptKeyId,
  strictReceiptSignaturePreimage,
  type StrictReceiptBody,
  type StrictReceiptEnvelope,
} from './strict-receipt.js';

const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const KEY_ID = /^sha256:[0-9a-f]{64}$/;
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export type StrictKeyTrust = 'pinned' | 'registered' | 'revoked' | 'self_asserted' | 'unknown';

export interface StrictReceiptVerification {
  schema_valid: boolean;
  hash_valid: boolean;
  signature_valid: boolean;
  semantic_valid: boolean;
  identity_binding_valid: boolean;
  key_trust: StrictKeyTrust;
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function exact(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  const keys = new Set(allowed);
  return Object.keys(value).every((key) => keys.has(key));
}

function u64(value: number): Buffer {
  const output = Buffer.alloc(8);
  output.writeBigUInt64BE(BigInt(value));
  return output;
}

function decodePublicKey(value: unknown): Buffer | undefined {
  if (typeof value !== 'string') return undefined;
  try {
    const raw = Buffer.from(value, 'base64');
    return raw.length === 32 && raw.toString('base64') === value ? raw : undefined;
  } catch { return undefined; }
}

export function verifyStrictReceipt(
  value: unknown,
  options: { pinned_public_key_b64?: string } = {},
): StrictReceiptVerification {
  const envelope = record(value);
  const body = record(envelope?.body);
  const signature = record(envelope?.signature);
  const schemaValid = envelope !== undefined
    && exact(envelope, ['schema', 'body', 'receipt_hash', 'signature', 'public_key_b64'])
    && envelope.schema === STRICT_RECEIPT_ENVELOPE_SCHEMA
    && body !== undefined
    && typeof envelope.receipt_hash === 'string' && HEX64.test(envelope.receipt_hash)
    && signature !== undefined
    && exact(signature, ['algorithm', 'key_id', 'value'])
    && signature.algorithm === 'Ed25519'
    && typeof signature.key_id === 'string' && KEY_ID.test(signature.key_id)
    && typeof signature.value === 'string' && HEX128.test(signature.value)
    && (!Object.prototype.hasOwnProperty.call(envelope, 'public_key_b64')
      || typeof envelope.public_key_b64 === 'string');

  let semanticValid = false;
  if (body) {
    try { buildStrictReceiptBody(body as unknown as StrictReceiptBody); semanticValid = true; } catch { /* false */ }
  }

  let hashValid = false;
  if (body && envelope && typeof envelope.receipt_hash === 'string') {
    try {
      const bytes = Buffer.from(canonicalJsonForHash(body), 'utf8');
      hashValid = createHash('sha256').update(Buffer.concat([
        Buffer.from(STRICT_RECEIPT_BODY_DOMAIN, 'utf8'), Buffer.from([0]),
        u64(bytes.length), bytes,
      ])).digest('hex') === envelope.receipt_hash;
    } catch { /* false */ }
  }

  const pinSupplied = Object.prototype.hasOwnProperty.call(options, 'pinned_public_key_b64');
  const pinned = decodePublicKey(options.pinned_public_key_b64);
  const embedded = decodePublicKey(envelope?.public_key_b64);
  const rawKey = pinSupplied ? pinned : embedded;
  const keyTrust: StrictKeyTrust = pinSupplied ? 'pinned' : embedded ? 'self_asserted' : 'unknown';
  const initiator = record(body?.initiator);
  const bodyKeyId = initiator?.key_id;
  const signatureKeyId = signature?.key_id;
  const fingerprint = rawKey ? strictReceiptKeyId(rawKey) : undefined;
  const identityValid = typeof bodyKeyId === 'string'
    && typeof signatureKeyId === 'string'
    && fingerprint !== undefined
    && bodyKeyId === signatureKeyId
    && signatureKeyId === fingerprint;

  let signatureValid = false;
  if (rawKey && typeof signatureKeyId === 'string' && envelope
    && typeof envelope.receipt_hash === 'string' && typeof signature?.value === 'string') {
    try {
      const key = createPublicKey({
        key: Buffer.concat([SPKI_PREFIX, rawKey]), format: 'der', type: 'spki',
      });
      signatureValid = cryptoVerify(
        null,
        strictReceiptSignaturePreimage(signatureKeyId, envelope.receipt_hash),
        key,
        Buffer.from(signature.value, 'hex'),
      );
    } catch { /* false */ }
  }

  return {
    schema_valid: schemaValid,
    hash_valid: hashValid,
    signature_valid: signatureValid,
    semantic_valid: semanticValid,
    identity_binding_valid: identityValid,
    key_trust: keyTrust,
  };
}

function sameAction(left: StrictReceiptBody['action'], right: StrictReceiptBody['action']): boolean {
  return left.action_id === right.action_id
    && left.kind === right.kind
    && left.name === right.name
    && left.arguments_hash === right.arguments_hash
    && left.target === right.target;
}

function compatibleResolution(
  suspension: NonNullable<StrictReceiptBody['suspension']>,
  method: NonNullable<StrictReceiptBody['resolution']>['method'],
): boolean {
  if (suspension.type === 'approval') {
    return ['approval_granted', 'approval_denied', 'expired', 'cancelled'].includes(method);
  }
  return ['context_supplied', 'expired', 'cancelled'].includes(method);
}

export function verifyStrictReceiptChain(
  envelopes: readonly unknown[],
  options: { pinned_public_key_b64?: string } = {},
): { valid: boolean; errors: string[] } {
  if (envelopes.length === 0) return { valid: false, errors: ['empty_chain'] };
  const errors: string[] = [];
  const byHash = new Map<string, StrictReceiptEnvelope>();
  const resolved = new Set<string>();
  let session: string | undefined;
  let previous: StrictReceiptEnvelope | undefined;
  for (let index = 0; index < envelopes.length; index++) {
    const candidate = envelopes[index];
    const rawEnvelope = record(candidate);
    const rawBody = record(rawEnvelope?.body);
    const rawId = rawBody?.receipt_id;
    const id = typeof rawId === 'string' ? rawId : `index-${index}`;
    const axes = verifyStrictReceipt(candidate, options);
    if (!axes.schema_valid) errors.push(`receipt_schema_invalid:${id}`);
    if (!axes.semantic_valid) errors.push(`receipt_semantic_invalid:${id}`);
    if (!axes.hash_valid) errors.push(`receipt_hash_invalid:${id}`);
    if (!axes.signature_valid) errors.push(`receipt_signature_invalid:${id}`);
    if (!axes.identity_binding_valid) errors.push(`receipt_identity_invalid:${id}`);
    if (!axes.schema_valid || !axes.semantic_valid || !axes.hash_valid
      || !axes.signature_valid || !axes.identity_binding_valid || !rawEnvelope || !rawBody) {
      continue;
    }
    const current = {
      ...rawEnvelope,
      body: buildStrictReceiptBody(rawBody as unknown as StrictReceiptBody),
    } as unknown as StrictReceiptEnvelope;
    if (session === undefined) session = current.body.session_id;

    if (current.body.sequence !== index + 1) errors.push(`sequence_order_invalid:${id}`);
    if (current.body.session_id !== session) errors.push(`session_mismatch:${id}`);
    if (previous) {
      if (current.body.previous_receipt_hash !== previous.receipt_hash) errors.push(`previous_hash_mismatch:${id}`);
      if (current.body.timestamp_ms < previous.body.timestamp_ms) errors.push(`timestamp_regression:${id}`);
    }

    const resolution = current.body.resolution;
    if (current.body.record_type === 'resolution' && resolution) {
      if (resolved.has(resolution.resolves_receipt_hash)) {
        errors.push(`duplicate_resolution:${id}`);
      } else {
        resolved.add(resolution.resolves_receipt_hash);
      }
      const prior = byHash.get(resolution.resolves_receipt_hash);
      if (!prior) {
        errors.push(`resolution_reference_invalid:${id}`);
      } else {
        const suspension = prior.body.suspension;
        if (prior.body.record_type !== 'decision' || !suspension) {
          errors.push(`resolution_prior_not_suspended:${id}`);
        } else {
          if (suspension.suspension_id !== resolution.suspension_id) errors.push(`resolution_suspension_mismatch:${id}`);
          if (!compatibleResolution(suspension, resolution.method)) errors.push(`resolution_method_mismatch:${id}`);
          if (resolution.resolved_at_ms < prior.body.timestamp_ms) errors.push(`resolution_time_invalid:${id}`);
          if ((resolution.method === 'approval_granted' || resolution.method === 'context_supplied')
            && resolution.resolved_at_ms > suspension.expires_at_ms) {
            errors.push(`resolution_after_expiry:${id}`);
          }
        }
        if (!sameAction(prior.body.action, current.body.action)) errors.push(`resolution_action_mismatch:${id}`);
        if (prior.body.initiator.agent_id !== current.body.initiator.agent_id
          || prior.body.initiator.key_id !== current.body.initiator.key_id) {
          errors.push(`resolution_initiator_mismatch:${id}`);
        }
      }
    }
    byHash.set(current.receipt_hash, current);
    previous = current;
  }
  return { valid: errors.length === 0, errors };
}
