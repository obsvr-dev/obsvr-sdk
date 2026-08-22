import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import type { DeviceSigner } from '../proxy/device-identity.js';
import type { PriorActionV2Input } from './action-context-v2.js';
import { normalizeDecisionActionV21 } from './strict-receipt-coordinator-v2-1-support.js';
import type {
  StrictDecisionActionV21Input, StrictDecisionV21Result,
} from './strict-receipt-coordinator-v2-1-types.js';
import { strictReceiptV21KeyId } from './strict-receipt-v2-1.js';
import { verifyStrictReceiptV21 } from './strict-receipt-v2-1-verify.js';

export const STRICT_RECOVERY_V21_SCHEMA = 'obsvr-strict-receipt-recovery-v2-1' as const;
export const STRICT_RECOVERY_V21_ENVELOPE_SCHEMA = 'obsvr-strict-receipt-recovery-envelope-v2-1' as const;
const DOMAIN = Buffer.from('obsvr-strict-receipt-recovery/2.1\0', 'utf8');
const SPKI = Buffer.from('302a300506032b6570032100', 'hex');
const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;

export interface RecoveryPreparedV21 {
  kind: 'decision';
  input: StrictDecisionActionV21Input;
  result: StrictDecisionV21Result;
}
export interface RecoveryCommittedV21 {
  sequence: number;
  head_receipt_hash: string | null;
  last_timestamp_ms: number | null;
  prior_actions: PriorActionV2Input[];
  action_ids: string[];
  pending_approval_ids: string[];
}
export interface StrictRecoveryV21Document {
  schema: typeof STRICT_RECOVERY_V21_SCHEMA;
  profile_version: '2.1';
  tenant_id: string;
  session_id: string;
  sdk_language: 'typescript';
  sdk_version: string;
  origin_pid: number;
  committed: RecoveryCommittedV21;
  prepared?: RecoveryPreparedV21;
}
export interface StrictRecoveryV21Envelope {
  schema: typeof STRICT_RECOVERY_V21_ENVELOPE_SCHEMA;
  document: StrictRecoveryV21Document;
  checkpoint_hash: string;
  signature: { algorithm: 'Ed25519'; key_id: string; value: string };
}

export class StrictRecoveryV21Error extends Error {
  constructor(message: string) { super(message); this.name = 'StrictRecoveryV21Error'; }
}
function fail(message: string): never { throw new StrictRecoveryV21Error(message); }
function record(value: unknown, field: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${field} must be an object`);
  return value as Record<string, unknown>;
}
function exact(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): void {
  const keys = Object.keys(value).sort(); const allowed = [...required, ...optional].sort();
  if (keys.join(',') !== allowed.filter((key) => Object.hasOwn(value, key)).sort().join(',')
    || required.some((key) => !Object.hasOwn(value, key))) fail('checkpoint contains missing or unsupported fields');
}
function text(value: unknown, field: string): string {
  if (typeof value !== 'string' || !value.trim()) fail(`${field} must be nonblank`); return value;
}
function integer(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) fail(`${field} must be a nonnegative safe integer`);
  return value;
}
function sortedUnique(values: unknown, field: string): string[] {
  if (!Array.isArray(values) || values.some((item) => typeof item !== 'string' || !item.trim())) fail(`${field} must be a string array`);
  const normalized = [...new Set(values as string[])].sort();
  if (canonicalJsonForHash(values) !== canonicalJsonForHash(normalized)) fail(`${field} must be sorted and unique`);
  return normalized;
}
function checkpointHash(document: StrictRecoveryV21Document): string {
  return createHash('sha256').update(canonicalJsonForHash(document)).digest('hex');
}
function preimage(hash: string): Buffer { return Buffer.concat([DOMAIN, Buffer.from(hash, 'hex')]); }
function verifySignature(value: StrictRecoveryV21Envelope, rawKey: Uint8Array): boolean {
  try {
    const key = createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(rawKey)]), format: 'der', type: 'spki' });
    return cryptoVerify(null, preimage(value.checkpoint_hash), key, Buffer.from(value.signature.value, 'hex'));
  } catch { return false; }
}

export function signStrictRecoveryV21(
  document: StrictRecoveryV21Document, signer: DeviceSigner,
): StrictRecoveryV21Envelope {
  validateStrictRecoveryV21Document(document);
  const checkpoint_hash = checkpointHash(document); const keyId = strictReceiptV21KeyId(signer.rawPublicKey);
  const signature = signer.signBytes(preimage(checkpoint_hash));
  if (!HEX128.test(signature)) fail('checkpoint signer returned an invalid signature');
  const envelope: StrictRecoveryV21Envelope = {
    schema: STRICT_RECOVERY_V21_ENVELOPE_SCHEMA,
    document: structuredClone(document), checkpoint_hash,
    signature: { algorithm: 'Ed25519', key_id: keyId, value: signature },
  };
  if (!verifySignature(envelope, signer.rawPublicKey)) fail('checkpoint signature failed self-verification');
  return envelope;
}

export function verifyStrictRecoveryV21(value: unknown, signer: DeviceSigner): StrictRecoveryV21Document {
  const root = record(value, 'checkpoint');
  exact(root, ['schema', 'document', 'checkpoint_hash', 'signature']);
  const signature = record(root.signature, 'checkpoint.signature');
  exact(signature, ['algorithm', 'key_id', 'value']);
  if (root.schema !== STRICT_RECOVERY_V21_ENVELOPE_SCHEMA || !HEX64.test(root.checkpoint_hash as string)
    || signature.algorithm !== 'Ed25519' || signature.key_id !== strictReceiptV21KeyId(signer.rawPublicKey)
    || !HEX128.test(signature.value as string)) fail('invalid checkpoint envelope');
  const document = root.document as StrictRecoveryV21Document;
  validateStrictRecoveryV21Document(document);
  const envelope = root as unknown as StrictRecoveryV21Envelope;
  if (checkpointHash(document) !== envelope.checkpoint_hash) fail('checkpoint hash mismatch');
  if (!verifySignature(envelope, signer.rawPublicKey)) fail('checkpoint signature invalid');
  return structuredClone(document);
}

export function validateStrictRecoveryV21Document(document: StrictRecoveryV21Document): void {
  const root = record(document, 'checkpoint.document');
  exact(root, ['schema', 'profile_version', 'tenant_id', 'session_id', 'sdk_language',
    'sdk_version', 'origin_pid', 'committed'], ['prepared']);
  if (document.schema !== STRICT_RECOVERY_V21_SCHEMA || document.profile_version !== '2.1'
    || document.sdk_language !== 'typescript') fail('invalid checkpoint document');
  text(document.tenant_id, 'tenant_id'); text(document.session_id, 'session_id');
  text(document.sdk_version, 'sdk_version'); integer(document.origin_pid, 'origin_pid');
  const committed = record(document.committed, 'committed');
  exact(committed, ['sequence', 'head_receipt_hash', 'last_timestamp_ms', 'prior_actions',
    'action_ids', 'pending_approval_ids']);
  integer(document.committed.sequence, 'committed.sequence');
  if ((document.committed.head_receipt_hash === null) !== (document.committed.sequence === 0)) fail('checkpoint head/sequence mismatch');
  if (document.committed.head_receipt_hash !== null && !HEX64.test(document.committed.head_receipt_hash)) fail('invalid checkpoint head hash');
  if ((document.committed.last_timestamp_ms === null) !== (document.committed.sequence === 0)) fail('checkpoint timestamp/sequence mismatch');
  if (document.committed.last_timestamp_ms !== null) integer(document.committed.last_timestamp_ms, 'last_timestamp_ms');
  if (!Array.isArray(document.committed.prior_actions)) fail('prior_actions must be an array');
  sortedUnique(document.committed.action_ids, 'action_ids'); sortedUnique(document.committed.pending_approval_ids, 'pending_approval_ids');
  const last = document.committed.prior_actions.at(-1);
  if (document.committed.sequence !== document.committed.prior_actions.length
    || (last && (last.sequence !== document.committed.sequence || last.receipt_hash !== document.committed.head_receipt_hash))) {
    fail('committed history does not match checkpoint head');
  }
  if (!document.prepared) return;
  const prepared = record(document.prepared, 'prepared'); exact(prepared, ['kind', 'input', 'result']);
  if (document.prepared.kind !== 'decision') fail('profile 2.1 recovery accepts decisions only');
  const resultRecord = record(document.prepared.result, 'prepared.result');
  exact(resultRecord, ['action_context', 'intent_evaluation', 'evaluation_evidence', 'receipt']);
  const intentRecord = record(document.prepared.result.intent_evaluation, 'prepared.intent_evaluation');
  exact(intentRecord, ['outcome', 'reason_code', 'context_hash', 'policy_hash']);
  const contextRecord = record(document.prepared.result.action_context, 'prepared.action_context');
  exact(contextRecord, ['schema', 'agent', 'action', 'run_id', 'prior_actions'], ['session_id', 'thread_id']);
  exact(record(contextRecord.agent, 'prepared.action_context.agent'),
    ['agent_id', 'active_intents'], ['role', 'privilege_scope']);
  exact(record(contextRecord.action, 'prepared.action_context.action'),
    ['kind', 'name', 'arguments_hash', 'data_classifications', 'requested_scopes'], ['target_hash']);
  try {
    if (canonicalJsonForHash(normalizeDecisionActionV21(document.prepared.input))
      !== canonicalJsonForHash(document.prepared.input)) fail('prepared state is not canonical');
  } catch { fail('prepared state is not canonical'); }
  const receipt = document.prepared.result?.receipt;
  const verified = verifyStrictReceiptV21(receipt, { trusted_agent_keys: [], allowed_evaluator_manifest_hashes: [] });
  const result = document.prepared.result;
  const contextHash = createHash('sha256')
    .update(canonicalJsonForHash(result?.action_context)).digest('hex');
  const intent = result?.intent_evaluation;
  const evidence = result?.evaluation_evidence;
  if (!verified.integrity_valid || receipt.body.record_type !== 'decision'
    || receipt.body.profile_version !== '2.1' || receipt.body.tenant_id !== document.tenant_id
    || receipt.body.session_id !== document.session_id || receipt.body.sequence !== document.committed.sequence + 1
    || receipt.body.previous_receipt_hash !== document.committed.head_receipt_hash
    || receipt.body.action.action_id !== document.prepared.input.action_id
    || receipt.body.action.arguments_hash !== document.prepared.input.current_action.arguments_hash
    || receipt.body.action.target_hash !== document.prepared.input.current_action.target_hash
    || contextHash !== receipt.body.context_hash
    || canonicalJsonForHash(result.action_context.action) !== canonicalJsonForHash(document.prepared.input.current_action)
    || canonicalJsonForHash(result.action_context.prior_actions) !== canonicalJsonForHash(document.committed.prior_actions)
    || intent.context_hash !== receipt.body.context_hash || intent.outcome !== receipt.body.outcome
    || intent.policy_hash !== receipt.body.evaluation.effective_policy.artifact_hash
    || canonicalJsonForHash([intent.reason_code]) !== canonicalJsonForHash(receipt.body.evaluation.decision_reason_codes)
    || canonicalJsonForHash(evidence) !== canonicalJsonForHash(receipt.body.evaluation)) {
    fail('prepared decision does not continue the exact checkpoint head');
  }
}
