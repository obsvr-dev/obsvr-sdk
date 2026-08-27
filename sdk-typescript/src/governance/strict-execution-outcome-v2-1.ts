import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import type { DeviceSigner } from '../proxy/device-identity.js';
import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import {
  STRICT_IDENTIFIER_MAX_BYTES,
  boundedCanonicalText,
  compareCodePoints,
} from './strict-canonical.js';
import {
  strictReceiptV21KeyId,
  type StrictReceiptV21Envelope,
} from './strict-receipt-v2-1.js';
import {
  verifyStrictReceiptV21,
  type StrictReceiptV21TrustOptions,
} from './strict-receipt-v2-1-verify.js';

export const STRICT_EXECUTION_OUTCOME_V21_SCHEMA = 'obsvr-strict-execution-outcome-v2-1' as const;
export const STRICT_EXECUTION_OUTCOME_V21_ENVELOPE_SCHEMA = 'obsvr-strict-execution-outcome-envelope-v2-1' as const;
export const STRICT_EXECUTION_OUTCOME_V21_BODY_DOMAIN = 'obsvr-strict-execution-outcome/body/2.1' as const;
export const STRICT_EXECUTION_OUTCOME_V21_SIGNATURE_DOMAIN = 'obsvr-strict-execution-outcome/signature/2.1' as const;
export const STRICT_EXECUTION_START_V21_DOMAIN = 'obsvr-strict-execution-start/2.1' as const;
export const STRICT_EXECUTION_RESULT_V21_DOMAIN = 'obsvr-strict-execution-result/2.1' as const;

const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const KEY_ID = /^sha256:[0-9a-f]{64}$/;
const ERROR_CODE = /^[a-z][a-z0-9_]{0,63}$/;
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const MAX_CANONICAL_BYTES = 262_144;

export type StrictExecutionOutcomeV21Status = 'succeeded' | 'failed' | 'uncertain';

export interface StrictExecutionStartV21 {
  tenant_id: string;
  session_id: string;
  action_id: string;
  decision_receipt_hash: string;
  operation_fingerprint: string;
  attempt: 1;
  started_at_ms: number;
}

export interface StrictExecutionOutcomeV21Body extends StrictExecutionStartV21 {
  schema: typeof STRICT_EXECUTION_OUTCOME_V21_SCHEMA;
  profile_version: '2.1';
  record_type: 'execution_outcome';
  outcome_id: string;
  decision_sequence: number;
  execution_start_hash: string;
  completed_at_ms: number;
  status: StrictExecutionOutcomeV21Status;
  result_hash?: string;
  error_code?: string;
}

export interface StrictExecutionOutcomeV21Envelope {
  schema: typeof STRICT_EXECUTION_OUTCOME_V21_ENVELOPE_SCHEMA;
  body: StrictExecutionOutcomeV21Body;
  outcome_hash: string;
  signature: { algorithm: 'Ed25519'; key_id: string; value: string };
  public_key_b64: string;
}

export interface StrictExecutionOutcomeV21Verification {
  schema_valid: boolean;
  semantic_valid: boolean;
  hash_valid: boolean;
  signature_valid: boolean;
  decision_integrity_valid: boolean;
  decision_binding_valid: boolean;
  signer_binding_valid: boolean;
  integrity_valid: boolean;
  decision_trusted: boolean;
  trusted: boolean;
}

export class StrictExecutionOutcomeV21ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StrictExecutionOutcomeV21ValidationError';
  }
}

function fail(message: string): never { throw new StrictExecutionOutcomeV21ValidationError(message); }
function record(value: unknown, field: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(`${field} must be an object`);
  return value as Record<string, unknown>;
}
function exactOptional(
  value: Record<string, unknown>, required: readonly string[], optional: readonly string[], field: string,
): void {
  const accepted = new Set([...required, ...optional]);
  const unknown = Object.keys(value).filter((key) => !accepted.has(key)).sort(compareCodePoints);
  if (unknown.length) fail(`${field} contains unsupported field: ${unknown[0]}`);
  const missing = required.filter((key) => !Object.prototype.hasOwnProperty.call(value, key));
  if (missing.length) fail(`${field} is missing required field: ${missing[0]}`);
}
function text(value: unknown, field: string): string {
  return boundedCanonicalText(value, field, STRICT_IDENTIFIER_MAX_BYTES, fail);
}
function hash(value: unknown, field: string): string {
  if (typeof value !== 'string' || !HEX64.test(value)) fail(`${field} must be 64 lowercase hex characters`);
  return value;
}
function integer(value: unknown, field: string, minimum = 0): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum) {
    fail(`${field} must be a safe integer >= ${minimum}`);
  }
  return value;
}
function u64(value: number): Buffer {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(BigInt(value));
  return bytes;
}
function domainHash(domain: string, canonical: string): string {
  const body = Buffer.from(canonical, 'utf8');
  return createHash('sha256').update(Buffer.concat([
    Buffer.from(domain), Buffer.from([0]), u64(body.length), body,
  ])).digest('hex');
}
function decodePublicKey(value: unknown): Buffer | undefined {
  if (typeof value !== 'string') return undefined;
  try {
    const raw = Buffer.from(value, 'base64');
    return raw.length === 32 && raw.toString('base64') === value ? raw : undefined;
  } catch { return undefined; }
}

export function strictExecutionStartV21Hash(input: StrictExecutionStartV21): string {
  const root = record(input, 'execution start');
  exactOptional(root, [
    'tenant_id', 'session_id', 'action_id', 'decision_receipt_hash',
    'operation_fingerprint', 'attempt', 'started_at_ms',
  ], [], 'execution start');
  text(root.tenant_id, 'tenant_id');
  text(root.session_id, 'session_id');
  text(root.action_id, 'action_id');
  hash(root.decision_receipt_hash, 'decision_receipt_hash');
  hash(root.operation_fingerprint, 'operation_fingerprint');
  if (root.attempt !== 1) fail('attempt must be 1');
  integer(root.started_at_ms, 'started_at_ms');
  return domainHash(STRICT_EXECUTION_START_V21_DOMAIN, canonicalJsonForHash(root));
}

export function strictExecutionResultV21Hash(value: unknown): string {
  const canonical = canonicalJsonForHash(value);
  if (Buffer.byteLength(canonical, 'utf8') > MAX_CANONICAL_BYTES) {
    fail(`canonical result exceeds ${MAX_CANONICAL_BYTES} UTF-8 bytes`);
  }
  return domainHash(STRICT_EXECUTION_RESULT_V21_DOMAIN, canonical);
}

export function buildStrictExecutionOutcomeV21Body(
  input: StrictExecutionOutcomeV21Body,
): StrictExecutionOutcomeV21Body {
  const root = record(input, 'execution outcome');
  exactOptional(root, [
    'schema', 'profile_version', 'record_type', 'outcome_id', 'tenant_id',
    'session_id', 'action_id', 'decision_receipt_hash', 'decision_sequence',
    'operation_fingerprint', 'attempt', 'started_at_ms', 'execution_start_hash',
    'completed_at_ms', 'status',
  ], ['result_hash', 'error_code'], 'execution outcome');
  if (root.schema !== STRICT_EXECUTION_OUTCOME_V21_SCHEMA || root.profile_version !== '2.1') {
    fail('invalid execution outcome profile');
  }
  if (root.record_type !== 'execution_outcome') fail('invalid record_type');
  text(root.outcome_id, 'outcome_id');
  text(root.tenant_id, 'tenant_id');
  text(root.session_id, 'session_id');
  text(root.action_id, 'action_id');
  hash(root.decision_receipt_hash, 'decision_receipt_hash');
  integer(root.decision_sequence, 'decision_sequence', 1);
  hash(root.operation_fingerprint, 'operation_fingerprint');
  if (root.attempt !== 1) fail('attempt must be 1');
  const startedAt = integer(root.started_at_ms, 'started_at_ms');
  const completedAt = integer(root.completed_at_ms, 'completed_at_ms');
  if (completedAt < startedAt) fail('completed_at_ms cannot precede started_at_ms');
  const expectedStartHash = strictExecutionStartV21Hash({
    tenant_id: root.tenant_id as string,
    session_id: root.session_id as string,
    action_id: root.action_id as string,
    decision_receipt_hash: root.decision_receipt_hash as string,
    operation_fingerprint: root.operation_fingerprint as string,
    attempt: 1,
    started_at_ms: startedAt,
  });
  if (hash(root.execution_start_hash, 'execution_start_hash') !== expectedStartHash) {
    fail('execution_start_hash does not match the execution start');
  }
  if (!['succeeded', 'failed', 'uncertain'].includes(String(root.status))) fail('invalid execution outcome status');
  if (root.status === 'succeeded') {
    hash(root.result_hash, 'result_hash');
    if ('error_code' in root) fail('succeeded outcome cannot contain error_code');
  } else {
    if (typeof root.error_code !== 'string' || !ERROR_CODE.test(root.error_code)) fail('invalid error_code');
    if ('result_hash' in root) fail('failed or uncertain outcome cannot contain result_hash');
  }
  const canonical = canonicalJsonForHash(root);
  if (Buffer.byteLength(canonical, 'utf8') > MAX_CANONICAL_BYTES) {
    fail(`canonical execution outcome exceeds ${MAX_CANONICAL_BYTES} UTF-8 bytes`);
  }
  return JSON.parse(canonical) as StrictExecutionOutcomeV21Body;
}

export function canonicalizeStrictExecutionOutcomeV21Body(
  input: StrictExecutionOutcomeV21Body,
): string {
  return canonicalJsonForHash(buildStrictExecutionOutcomeV21Body(input));
}

export function strictExecutionOutcomeV21Hash(input: StrictExecutionOutcomeV21Body): string {
  return domainHash(
    STRICT_EXECUTION_OUTCOME_V21_BODY_DOMAIN,
    canonicalizeStrictExecutionOutcomeV21Body(input),
  );
}

export function strictExecutionOutcomeV21SignaturePreimage(
  keyId: string, outcomeHash: string,
): Buffer {
  if (!KEY_ID.test(keyId)) fail('invalid strict key id');
  const key = Buffer.from(keyId, 'utf8');
  return Buffer.concat([
    Buffer.from(STRICT_EXECUTION_OUTCOME_V21_SIGNATURE_DOMAIN), Buffer.from([0]),
    u64(key.length), key, Buffer.from(hash(outcomeHash, 'outcome_hash'), 'hex'),
  ]);
}

function decisionIntegrity(decision: StrictReceiptV21Envelope): boolean {
  try {
    const initiator = decision.body.identity.initiator;
    return verifyStrictReceiptV21(decision, {
      trusted_agent_keys: [{
        tenant_id: decision.body.tenant_id,
        agent_ref_hash: initiator.agent_ref_hash,
        key_id: initiator.key_id,
        public_key_b64: decision.public_key_b64,
        status: 'active',
      }],
      allowed_evaluator_manifest_hashes: [decision.body.evaluation.evaluator_manifest_hash],
    }).integrity_valid;
  } catch { return false; }
}

function bindsDecision(body: StrictExecutionOutcomeV21Body, decision: StrictReceiptV21Envelope): boolean {
  return decisionIntegrity(decision)
    && decision.body.execution_authorized
    && body.decision_receipt_hash === decision.receipt_hash
    && body.decision_sequence === decision.body.sequence
    && body.tenant_id === decision.body.tenant_id
    && body.session_id === decision.body.session_id
    && body.action_id === decision.body.action.action_id
    && body.started_at_ms >= decision.body.timestamp_ms;
}

export function signStrictExecutionOutcomeV21(
  input: StrictExecutionOutcomeV21Body,
  signer: DeviceSigner,
  decision: StrictReceiptV21Envelope,
): StrictExecutionOutcomeV21Envelope {
  const body = buildStrictExecutionOutcomeV21Body(input);
  if (!bindsDecision(body, decision)) fail('execution outcome does not bind an authorized decision receipt');
  const keyId = strictReceiptV21KeyId(signer.rawPublicKey);
  if (keyId !== decision.signature.key_id || keyId !== decision.body.identity.initiator.key_id) {
    fail('outcome signer does not match the decision signer');
  }
  const outcomeHash = strictExecutionOutcomeV21Hash(body);
  const preimage = strictExecutionOutcomeV21SignaturePreimage(keyId, outcomeHash);
  const signature = signer.signBytes(preimage);
  if (!HEX128.test(signature)) fail('signer returned an invalid Ed25519 signature');
  const raw = Buffer.from(signer.rawPublicKey);
  const publicKeyB64 = raw.toString('base64');
  if (signer.publicKeyB64 !== publicKeyB64) fail('signer publicKeyB64 does not match rawPublicKey');
  const publicKey = createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, raw]), format: 'der', type: 'spki',
  });
  if (!cryptoVerify(null, preimage, publicKey, Buffer.from(signature, 'hex'))) {
    fail('signer signature failed self-verification');
  }
  return {
    schema: STRICT_EXECUTION_OUTCOME_V21_ENVELOPE_SCHEMA,
    body,
    outcome_hash: outcomeHash,
    signature: { algorithm: 'Ed25519', key_id: keyId, value: signature },
    public_key_b64: publicKeyB64,
  };
}

export function verifyStrictExecutionOutcomeV21(
  value: unknown,
  decision: StrictReceiptV21Envelope,
  options: StrictReceiptV21TrustOptions,
): StrictExecutionOutcomeV21Verification {
  const envelope = value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown> : undefined;
  const body = envelope?.body !== null && typeof envelope?.body === 'object' && !Array.isArray(envelope.body)
    ? envelope.body as Record<string, unknown> : undefined;
  const signature = envelope?.signature !== null && typeof envelope?.signature === 'object' && !Array.isArray(envelope.signature)
    ? envelope.signature as Record<string, unknown> : undefined;
  const schemaValid = Boolean(
    envelope && Object.keys(envelope).length === 5
    && ['schema', 'body', 'outcome_hash', 'signature', 'public_key_b64'].every((key) => Object.prototype.hasOwnProperty.call(envelope, key))
    && envelope.schema === STRICT_EXECUTION_OUTCOME_V21_ENVELOPE_SCHEMA
    && body && typeof envelope.outcome_hash === 'string' && HEX64.test(envelope.outcome_hash)
    && signature && Object.keys(signature).length === 3
    && signature.algorithm === 'Ed25519'
    && typeof signature.key_id === 'string' && KEY_ID.test(signature.key_id)
    && typeof signature.value === 'string' && HEX128.test(signature.value)
    && typeof envelope.public_key_b64 === 'string'
  );
  let normalized: StrictExecutionOutcomeV21Body | undefined;
  let semanticValid = false;
  if (body) {
    try {
      normalized = buildStrictExecutionOutcomeV21Body(body as unknown as StrictExecutionOutcomeV21Body);
      semanticValid = canonicalJsonForHash(normalized) === canonicalJsonForHash(body);
    } catch { semanticValid = false; }
  }
  let hashValid = false;
  if (normalized && typeof envelope?.outcome_hash === 'string') {
    try { hashValid = strictExecutionOutcomeV21Hash(normalized) === envelope.outcome_hash; } catch { hashValid = false; }
  }
  const rawKey = decodePublicKey(envelope?.public_key_b64);
  let signatureValid = false;
  if (rawKey && signature && typeof signature.key_id === 'string'
    && typeof signature.value === 'string' && typeof envelope?.outcome_hash === 'string') {
    try {
      const publicKey = createPublicKey({
        key: Buffer.concat([SPKI_PREFIX, rawKey]), format: 'der', type: 'spki',
      });
      signatureValid = cryptoVerify(
        null,
        strictExecutionOutcomeV21SignaturePreimage(signature.key_id, envelope.outcome_hash),
        publicKey,
        Buffer.from(signature.value, 'hex'),
      );
    } catch { signatureValid = false; }
  }
  const decisionVerification = verifyStrictReceiptV21(decision, options);
  const decisionBindingValid = Boolean(normalized && bindsDecision(normalized, decision));
  let rawKeyId: string | undefined;
  try { if (rawKey) rawKeyId = strictReceiptV21KeyId(rawKey); } catch { rawKeyId = undefined; }
  const signerBindingValid = Boolean(
    rawKeyId && signature?.key_id === rawKeyId
    && rawKeyId === decision.signature.key_id
    && envelope?.public_key_b64 === decision.public_key_b64,
  );
  const integrityValid = schemaValid && semanticValid && hashValid && signatureValid
    && decisionVerification.integrity_valid && decisionBindingValid && signerBindingValid;
  return {
    schema_valid: schemaValid,
    semantic_valid: semanticValid,
    hash_valid: hashValid,
    signature_valid: signatureValid,
    decision_integrity_valid: decisionVerification.integrity_valid,
    decision_binding_valid: decisionBindingValid,
    signer_binding_valid: signerBindingValid,
    integrity_valid: integrityValid,
    decision_trusted: decisionVerification.trusted,
    trusted: integrityValid && decisionVerification.trusted,
  };
}
