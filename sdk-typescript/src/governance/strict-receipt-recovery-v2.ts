import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import type { IntentAlignmentV2Result, IntentV2BaseResult } from '../policy/intent-alignment-v2.js';
import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import type { DeviceSigner } from '../proxy/device-identity.js';
import type { ActionContextV2Document, PriorActionV2Input } from './action-context-v2.js';
import type { StrictReceiptV2Envelope } from './strict-receipt-v2.js';
import { strictReceiptV2KeyId } from './strict-receipt-v2.js';

export const STRICT_RECOVERY_V2_SCHEMA = 'obsvr-strict-receipt-recovery-v2' as const;
export const STRICT_RECOVERY_V2_ENVELOPE_SCHEMA = 'obsvr-strict-receipt-recovery-envelope-v2' as const;
const DOMAIN = Buffer.from('obsvr-strict-receipt-recovery/2\0', 'utf8');
const SPKI = Buffer.from('302a300506032b6570032100', 'hex');
const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;

export interface RecoveryPendingV2 {
  kind: 'decision' | 'resolution' | 'timeout';
  receipt: StrictReceiptV2Envelope;
  context?: ActionContextV2Document;
  base_result?: IntentV2BaseResult;
  evaluation?: IntentAlignmentV2Result;
  suspended_receipt_hash?: string;
}
export interface RecoveryCommittedV2 {
  sequence: number;
  head_receipt_hash: string | null;
  last_timestamp_ms: number | null;
  prior_actions: PriorActionV2Input[];
  suspended: Array<{ receipt_hash: string; receipt: StrictReceiptV2Envelope;
    context: ActionContextV2Document; base_result: IntentV2BaseResult }>;
  resolved_receipt_hashes: string[];
  action_ids: string[];
  approval_requests: Array<{ request_id: string; receipt_hash: string }>;
}
export interface StrictRecoveryV2Document {
  schema: typeof STRICT_RECOVERY_V2_SCHEMA;
  profile_version: '2.0';
  tenant_id: string;
  session_id: string;
  sdk_language: 'typescript';
  sdk_version: string;
  origin_pid: number;
  committed: RecoveryCommittedV2;
  prepared?: RecoveryPendingV2;
}
export interface StrictRecoveryV2Envelope {
  schema: typeof STRICT_RECOVERY_V2_ENVELOPE_SCHEMA;
  document: StrictRecoveryV2Document;
  checkpoint_hash: string;
  signature: { algorithm: 'Ed25519'; key_id: string; value: string };
}

export class StrictRecoveryV2Error extends Error {
  constructor(message: string) { super(message); this.name = 'StrictRecoveryV2Error'; }
}
function fail(message: string): never { throw new StrictRecoveryV2Error(message); }
function text(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) return fail(`${field} must be nonblank`);
  return value;
}
function integer(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) return fail(`${field} must be a nonnegative safe integer`);
  return value;
}
function checkpointHash(document: StrictRecoveryV2Document): string {
  return createHash('sha256').update(canonicalJsonForHash(document)).digest('hex');
}
function preimage(hash: string): Buffer { return Buffer.concat([DOMAIN, Buffer.from(hash, 'hex')]); }
function verifySignature(envelope: StrictRecoveryV2Envelope, rawPublicKey: Uint8Array): boolean {
  const key = createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(rawPublicKey)]), format: 'der', type: 'spki' });
  return cryptoVerify(null, preimage(envelope.checkpoint_hash), key, Buffer.from(envelope.signature.value, 'hex'));
}

export function signStrictRecoveryV2(
  document: StrictRecoveryV2Document, signer: DeviceSigner,
): StrictRecoveryV2Envelope {
  validateStrictRecoveryV2Document(document);
  const checkpoint_hash = checkpointHash(document);
  const keyId = strictReceiptV2KeyId(signer.rawPublicKey);
  const value = signer.signBytes(preimage(checkpoint_hash));
  if (!HEX128.test(value)) fail('checkpoint signer returned an invalid signature');
  const envelope: StrictRecoveryV2Envelope = { schema: STRICT_RECOVERY_V2_ENVELOPE_SCHEMA,
    document: JSON.parse(JSON.stringify(document)) as StrictRecoveryV2Document,
    checkpoint_hash, signature: { algorithm: 'Ed25519', key_id: keyId, value } };
  if (!verifySignature(envelope, signer.rawPublicKey)) fail('checkpoint signature failed self-verification');
  return envelope;
}

export function verifyStrictRecoveryV2(
  value: unknown, signer: DeviceSigner,
): StrictRecoveryV2Document {
  if (!value || typeof value !== 'object') return fail('checkpoint must be an object');
  const envelope = value as StrictRecoveryV2Envelope;
  if (envelope.schema !== STRICT_RECOVERY_V2_ENVELOPE_SCHEMA
    || !HEX64.test(envelope.checkpoint_hash)
    || envelope.signature?.algorithm !== 'Ed25519'
    || envelope.signature.key_id !== strictReceiptV2KeyId(signer.rawPublicKey)
    || !HEX128.test(envelope.signature.value)) return fail('invalid checkpoint envelope');
  validateStrictRecoveryV2Document(envelope.document);
  if (checkpointHash(envelope.document) !== envelope.checkpoint_hash) return fail('checkpoint hash mismatch');
  if (!verifySignature(envelope, signer.rawPublicKey)) return fail('checkpoint signature invalid');
  return JSON.parse(JSON.stringify(envelope.document)) as StrictRecoveryV2Document;
}

export function validateStrictRecoveryV2Document(document: StrictRecoveryV2Document): void {
  if (!document || typeof document !== 'object' || document.schema !== STRICT_RECOVERY_V2_SCHEMA
    || document.profile_version !== '2.0' || document.sdk_language !== 'typescript') return fail('invalid checkpoint document');
  text(document.tenant_id, 'tenant_id'); text(document.session_id, 'session_id'); text(document.sdk_version, 'sdk_version');
  integer(document.origin_pid, 'origin_pid'); integer(document.committed?.sequence, 'committed.sequence');
  if ((document.committed.head_receipt_hash === null) !== (document.committed.sequence === 0)) return fail('checkpoint head/sequence mismatch');
  if (document.committed.head_receipt_hash !== null && !HEX64.test(document.committed.head_receipt_hash)) return fail('invalid checkpoint head hash');
  if (document.committed.last_timestamp_ms !== null) integer(document.committed.last_timestamp_ms, 'last_timestamp_ms');
  if (!Array.isArray(document.committed.prior_actions) || !Array.isArray(document.committed.suspended)
    || !Array.isArray(document.committed.resolved_receipt_hashes) || !Array.isArray(document.committed.action_ids)
    || !Array.isArray(document.committed.approval_requests)) return fail('checkpoint collections must be arrays');
  const last = document.committed.prior_actions.at(-1);
  if (document.committed.sequence > 0 && (!last || last.sequence !== document.committed.sequence
    || last.receipt_hash !== document.committed.head_receipt_hash)) return fail('checkpoint head does not match prior actions');
  if (document.prepared) {
    if (!['decision', 'resolution', 'timeout'].includes(document.prepared.kind)
      || document.prepared.receipt.body.tenant_id !== document.tenant_id
      || document.prepared.receipt.body.session_id !== document.session_id
      || document.prepared.receipt.body.profile_version !== '2.0'
      || document.prepared.receipt.body.sequence !== document.committed.sequence + 1
      || document.prepared.receipt.body.previous_receipt_hash !== document.committed.head_receipt_hash) return fail('prepared receipt does not continue checkpoint head');
  }
}
