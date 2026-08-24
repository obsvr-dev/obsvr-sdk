import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import type { DeviceSigner } from '../proxy/device-identity.js';
import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import type { AarmOutcome } from './aarm-outcome.js';
import {
  buildStrictIdentityEvidenceV21,
  type StrictIdentityEvidenceV21Document,
} from './strict-identity-evidence-v2-1.js';
import type { StrictEvaluationEvidenceV21 } from './strict-evaluation-evidence-v2-1.js';
import {
  STRICT_IDENTIFIER_MAX_BYTES,
  STRICT_SET_MAX_ITEMS,
  boundedCanonicalText,
  compareCodePoints,
} from './strict-canonical.js';

export const STRICT_RECEIPT_V21_SCHEMA = 'obsvr-strict-receipt-v2-1' as const;
export const STRICT_RECEIPT_V21_PROFILE_VERSION = '2.1' as const;
export const STRICT_RECEIPT_V21_ENVELOPE_SCHEMA = 'obsvr-strict-receipt-envelope-v2-1' as const;
export const STRICT_RECEIPT_V21_BODY_DOMAIN = 'obsvr-strict-receipt/body/2.1' as const;
export const STRICT_RECEIPT_V21_SIGNATURE_DOMAIN = 'obsvr-strict-receipt/signature/2.1' as const;
const STRICT_EVALUATION_EVIDENCE_V21_SCHEMA = 'obsvr-strict-evaluation-evidence-v2-1' as const;

const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const KEY_ID = /^sha256:[0-9a-f]{64}$/;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const FAILURE_CODE = /^[a-z][a-z0-9_]{0,63}$/;
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const MAX_CANONICAL_BYTES = 262_144;
const DETECTOR_SET_DOMAIN = 'obsvr-strict-detector-set/2.1';

export interface StrictReceiptV21Body {
  schema: typeof STRICT_RECEIPT_V21_SCHEMA;
  profile_version: typeof STRICT_RECEIPT_V21_PROFILE_VERSION;
  record_type: 'decision' | 'resolution';
  receipt_id: string;
  tenant_id: string;
  session_id: string;
  sequence: number;
  timestamp_ms: number;
  previous_receipt_hash: string | null;
  action: { action_id: string; kind: string; name: string; arguments_hash: string; target_hash: string; effective_arguments_hash?: string };
  context_hash: string;
  identity: StrictIdentityEvidenceV21Document;
  evaluation: StrictEvaluationEvidenceV21;
  outcome: AarmOutcome;
  reason_code: string;
  execution_authorized: boolean;
  suspension?: {
    suspension_id: string;
    type: 'approval' | 'context';
    expires_at_ms: number;
  };
  resolution?: {
    resolves_receipt_hash: string;
    suspension_id: string;
    method: 'approval_granted' | 'approval_denied' | 'context_supplied' | 'expired' | 'cancelled';
    resolver_ref_hash: string;
    resolved_at_ms: number;
  };
}

export interface StrictReceiptV21Envelope {
  schema: typeof STRICT_RECEIPT_V21_ENVELOPE_SCHEMA;
  body: StrictReceiptV21Body;
  receipt_hash: string;
  signature: { algorithm: 'Ed25519'; key_id: string; value: string };
  public_key_b64: string;
}

export class StrictReceiptV21ValidationError extends Error {
  constructor(message: string) { super(message); this.name = 'StrictReceiptV21ValidationError'; }
}

function fail(message: string): never { throw new StrictReceiptV21ValidationError(message); }
function record(value: unknown, field: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(`${field} must be an object`);
  return value as Record<string, unknown>;
}
function exact(value: Record<string, unknown>, allowed: readonly string[], field: string): void {
  const accepted = new Set(allowed);
  const unknown = Object.keys(value).filter((key) => !accepted.has(key)).sort(compareCodePoints);
  if (unknown.length) fail(`${field} contains unsupported field: ${unknown[0]}`);
  const missing = allowed.filter((key) => !Object.prototype.hasOwnProperty.call(value, key));
  if (missing.length) fail(`${field} is missing required field: ${missing[0]}`);
}
function exactOptional(value: Record<string, unknown>, required: readonly string[], optional: readonly string[], field: string): void {
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
function canonicalSet(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || value.length > STRICT_SET_MAX_ITEMS) fail(`${field} must contain at most ${STRICT_SET_MAX_ITEMS} items`);
  const items = value.map((item, index) => text(item, `${field}[${index}]`));
  const normalized = [...new Set(items)].sort(compareCodePoints);
  if (canonicalJsonForHash(items) !== canonicalJsonForHash(normalized)) fail(`${field} must be sorted and unique`);
  return items;
}
function u64(value: number): Buffer {
  const bytes = Buffer.alloc(8); bytes.writeBigUInt64BE(BigInt(value)); return bytes;
}
function safeId(value: unknown, field: string): string {
  if (typeof value !== 'string' || !SAFE_ID.test(value)) fail(`${field} must be a bounded ASCII identifier`);
  return value;
}
function domainHash(domain: string, canonical: string): string {
  const bytes = Buffer.from(canonical, 'utf8');
  return createHash('sha256').update(Buffer.concat([Buffer.from(domain), Buffer.from([0]), u64(bytes.length), bytes])).digest('hex');
}

function validateIdentity(value: unknown): StrictIdentityEvidenceV21Document {
  try {
    return buildStrictIdentityEvidenceV21(value as StrictIdentityEvidenceV21Document);
  } catch (error) {
    return fail(error instanceof Error ? error.message : 'invalid identity evidence');
  }
}

function validateEvaluation(value: unknown): StrictEvaluationEvidenceV21 {
  const evaluation = record(value, 'evaluation');
  if (evaluation.schema !== STRICT_EVALUATION_EVIDENCE_V21_SCHEMA) fail('invalid evaluation.schema');
  if (evaluation.profile_version !== STRICT_RECEIPT_V21_PROFILE_VERSION) fail('invalid evaluation.profile_version');
  exact(evaluation, ['schema', 'profile_version', 'effective_policy', 'evaluator_manifest_hash', 'detectors', 'detector_set_hash', 'requested_outcome', 'outcome', 'decision_reason_codes', 'reason_code'], 'evaluation');
  const policy = record(evaluation.effective_policy, 'evaluation.effective_policy');
  exact(policy, ['version', 'artifact_hash', 'matched_rule_ids'], 'evaluation.effective_policy');
  safeId(policy.version, 'evaluation.effective_policy.version'); hash(policy.artifact_hash, 'evaluation.effective_policy.artifact_hash');
  const ruleIds = canonicalSet(policy.matched_rule_ids, 'evaluation.effective_policy.matched_rule_ids');
  ruleIds.forEach((rule, index) => safeId(rule, `evaluation.effective_policy.matched_rule_ids[${index}]`));
  hash(evaluation.evaluator_manifest_hash, 'evaluation.evaluator_manifest_hash');
  hash(evaluation.detector_set_hash, 'evaluation.detector_set_hash');
  if (!Array.isArray(evaluation.detectors) || evaluation.detectors.length > STRICT_SET_MAX_ITEMS) fail(`evaluation.detectors must contain at most ${STRICT_SET_MAX_ITEMS} items`);
  let previousId: string | undefined;
  evaluation.detectors.forEach((candidate, index) => {
    const detector = record(candidate, `evaluation.detectors[${index}]`);
    exactOptional(detector, ['detector_id', 'detector_manifest_hash', 'required', 'purpose', 'status'], ['result_hash', 'failure_code'], `evaluation.detectors[${index}]`);
    const id = safeId(detector.detector_id, `evaluation.detectors[${index}].detector_id`);
    if (previousId !== undefined && compareCodePoints(previousId, id) >= 0) fail('evaluation.detectors must be sorted by unique detector_id');
    previousId = id; hash(detector.detector_manifest_hash, `evaluation.detectors[${index}].detector_manifest_hash`);
    if (typeof detector.required !== 'boolean' || !['evaluation', 'transform'].includes(String(detector.purpose))) fail('invalid detector requirement');
    if (!['ok', 'unavailable', 'degraded'].includes(String(detector.status))) fail('invalid detector status');
    if (detector.status === 'ok') {
      hash(detector.result_hash, `evaluation.detectors[${index}].result_hash`);
      if ('failure_code' in detector) fail('evaluated detector cannot have failure_code');
    } else {
      if (typeof detector.failure_code !== 'string' || !FAILURE_CODE.test(detector.failure_code)) fail('invalid detector failure_code');
      if ('result_hash' in detector) fail('failed detector cannot have result_hash');
    }
  });
  if (!['ALLOW', 'DENY', 'MODIFY', 'STEP_UP', 'DEFER'].includes(String(evaluation.requested_outcome))) fail('invalid evaluation.requested_outcome');
  if (!['ALLOW', 'DENY', 'MODIFY', 'STEP_UP', 'DEFER'].includes(String(evaluation.outcome))) fail('invalid evaluation.outcome');
  if (!Array.isArray(evaluation.decision_reason_codes)
    || evaluation.decision_reason_codes.length === 0
    || evaluation.decision_reason_codes.length > 32) {
    fail('evaluation.decision_reason_codes must contain 1 to 32 items');
  }
  const decisionReasons = canonicalSet(evaluation.decision_reason_codes, 'evaluation.decision_reason_codes');
  decisionReasons.forEach((reason, index) => safeId(reason, `evaluation.decision_reason_codes[${index}]`));
  if (!['evaluation_complete', 'required_detector_uncertain', 'required_transform_unavailable'].includes(String(evaluation.reason_code))) fail('invalid evaluation.reason_code');
  const unhealthy = (evaluation.detectors as Array<Record<string, unknown>>)
    .filter((detector) => detector.required === true && detector.status !== 'ok');
  let expectedOutcome = evaluation.requested_outcome; let expectedReason = 'evaluation_complete';
  if (['ALLOW', 'MODIFY'].includes(String(evaluation.requested_outcome))
    && unhealthy.some((detector) => detector.purpose === 'transform')) {
    expectedOutcome = 'DENY'; expectedReason = 'required_transform_unavailable';
  } else if (['ALLOW', 'MODIFY'].includes(String(evaluation.requested_outcome)) && unhealthy.length) {
    expectedOutcome = 'DEFER'; expectedReason = 'required_detector_uncertain';
  }
  if (evaluation.outcome !== expectedOutcome || evaluation.reason_code !== expectedReason) {
    fail('evaluation outcome and reason are inconsistent with detector evidence');
  }
  const expectedDetectorSetHash = domainHash(DETECTOR_SET_DOMAIN, canonicalJsonForHash({
    schema: 'obsvr-strict-detector-set-v2-1', detectors: evaluation.detectors,
  }));
  if (evaluation.detector_set_hash !== expectedDetectorSetHash) fail('evaluation.detector_set_hash does not match detectors');
  return JSON.parse(canonicalJsonForHash(evaluation)) as StrictEvaluationEvidenceV21;
}

export function buildStrictReceiptV21Body(input: StrictReceiptV21Body): StrictReceiptV21Body {
  const root = record(input, 'receipt body');
  exactOptional(root, ['schema', 'profile_version', 'record_type', 'receipt_id', 'tenant_id', 'session_id', 'sequence', 'timestamp_ms', 'previous_receipt_hash', 'action', 'context_hash', 'identity', 'evaluation', 'outcome', 'reason_code', 'execution_authorized'], ['suspension', 'resolution'], 'receipt body');
  if (root.schema !== STRICT_RECEIPT_V21_SCHEMA || root.profile_version !== STRICT_RECEIPT_V21_PROFILE_VERSION) fail('invalid receipt profile');
  if (root.record_type !== 'decision' && root.record_type !== 'resolution') fail('invalid record_type');
  text(root.receipt_id, 'receipt_id'); text(root.tenant_id, 'tenant_id'); text(root.session_id, 'session_id');
  integer(root.sequence, 'sequence', 1); integer(root.timestamp_ms, 'timestamp_ms');
  if (root.previous_receipt_hash !== null) hash(root.previous_receipt_hash, 'previous_receipt_hash');
  if ((root.sequence === 1) !== (root.previous_receipt_hash === null)) fail('genesis and previous_receipt_hash are inconsistent');
  const action = record(root.action, 'action');
  exactOptional(action, ['action_id', 'kind', 'name', 'arguments_hash', 'target_hash'], ['effective_arguments_hash'], 'action');
  text(action.action_id, 'action.action_id'); text(action.kind, 'action.kind'); text(action.name, 'action.name');
  hash(action.arguments_hash, 'action.arguments_hash'); hash(action.target_hash, 'action.target_hash'); hash(root.context_hash, 'context_hash');
  const identity = validateIdentity(root.identity); const evaluation = validateEvaluation(root.evaluation);
  if (root.record_type === 'decision' && identity.receipt_time_ms !== root.timestamp_ms) {
    fail('decision identity.receipt_time_ms must equal timestamp_ms');
  }
  if (root.record_type === 'resolution' && identity.receipt_time_ms > Number(root.timestamp_ms)) {
    fail('resolution identity.receipt_time_ms cannot follow timestamp_ms');
  }
  if (!['ALLOW', 'DENY', 'MODIFY', 'STEP_UP', 'DEFER'].includes(String(root.outcome))) fail('invalid outcome');
  if (root.outcome === 'MODIFY') {
    const effective = hash(action.effective_arguments_hash, 'action.effective_arguments_hash');
    if (effective === action.arguments_hash) fail('MODIFY effective_arguments_hash must differ from arguments_hash');
  } else if ('effective_arguments_hash' in action) fail('effective_arguments_hash is valid only for MODIFY');
  text(root.reason_code, 'reason_code'); if (typeof root.execution_authorized !== 'boolean') fail('execution_authorized must be boolean');
  if (root.outcome !== evaluation.outcome || root.reason_code !== evaluation.reason_code) fail('receipt outcome and reason must match evaluation evidence');
  const shouldAuthorize = root.outcome === 'ALLOW' || root.outcome === 'MODIFY';
  if (root.execution_authorized !== shouldAuthorize) fail('execution_authorized is inconsistent with outcome');
  if ('suspension' in root) {
    const suspension = record(root.suspension, 'suspension'); exact(suspension, ['suspension_id', 'type', 'expires_at_ms'], 'suspension');
    text(suspension.suspension_id, 'suspension.suspension_id');
    if (suspension.type !== 'approval' && suspension.type !== 'context') fail('invalid suspension.type');
    if (integer(suspension.expires_at_ms, 'suspension.expires_at_ms') <= Number(root.timestamp_ms)) fail('suspension expiry must follow receipt timestamp');
  }
  if ('resolution' in root) {
    const resolution = record(root.resolution, 'resolution'); exact(resolution, ['resolves_receipt_hash', 'suspension_id', 'method', 'resolver_ref_hash', 'resolved_at_ms'], 'resolution');
    hash(resolution.resolves_receipt_hash, 'resolution.resolves_receipt_hash'); text(resolution.suspension_id, 'resolution.suspension_id');
    if (!['approval_granted', 'approval_denied', 'context_supplied', 'expired', 'cancelled'].includes(String(resolution.method))) fail('invalid resolution.method');
    hash(resolution.resolver_ref_hash, 'resolution.resolver_ref_hash');
    if (integer(resolution.resolved_at_ms, 'resolution.resolved_at_ms') !== root.timestamp_ms) fail('resolution time must equal receipt timestamp');
  }
  if (root.record_type === 'decision' && 'resolution' in root) fail('decision cannot contain resolution');
  if (root.record_type === 'resolution' && (!('resolution' in root) || 'suspension' in root)) fail('resolution record has invalid suspension fields');
  if ((root.outcome === 'STEP_UP' || root.outcome === 'DEFER') !== ('suspension' in root)) fail('suspension is inconsistent with outcome');
  const canonical = canonicalJsonForHash({ ...root, identity, evaluation });
  if (Buffer.byteLength(canonical, 'utf8') > MAX_CANONICAL_BYTES) fail(`canonical receipt exceeds ${MAX_CANONICAL_BYTES} UTF-8 bytes`);
  return JSON.parse(canonical) as StrictReceiptV21Body;
}

export function canonicalizeStrictReceiptV21Body(input: StrictReceiptV21Body): string { return canonicalJsonForHash(buildStrictReceiptV21Body(input)); }
export function strictReceiptV21Hash(input: StrictReceiptV21Body): string {
  const body = Buffer.from(canonicalizeStrictReceiptV21Body(input), 'utf8');
  return createHash('sha256').update(Buffer.concat([Buffer.from(STRICT_RECEIPT_V21_BODY_DOMAIN), Buffer.from([0]), u64(body.length), body])).digest('hex');
}
export function strictReceiptV21KeyId(rawPublicKey: Uint8Array): string {
  const raw = Buffer.from(rawPublicKey); if (raw.length !== 32) fail('public key must be 32 raw bytes');
  return `sha256:${createHash('sha256').update(raw).digest('hex')}`;
}
export function strictReceiptV21SignaturePreimage(keyId: string, receiptHash: string): Buffer {
  if (!KEY_ID.test(keyId)) fail('invalid strict key id'); const key = Buffer.from(keyId);
  return Buffer.concat([Buffer.from(STRICT_RECEIPT_V21_SIGNATURE_DOMAIN), Buffer.from([0]), u64(key.length), key, Buffer.from(hash(receiptHash, 'receipt_hash'), 'hex')]);
}
export function signStrictReceiptV21(input: StrictReceiptV21Body, signer: DeviceSigner): StrictReceiptV21Envelope {
  const body = buildStrictReceiptV21Body(input); const keyId = strictReceiptV21KeyId(signer.rawPublicKey);
  if (body.identity.initiator.key_id !== keyId) fail('signer does not match identity.initiator.key_id');
  const receiptHash = strictReceiptV21Hash(body); const preimage = strictReceiptV21SignaturePreimage(keyId, receiptHash);
  const signature = signer.signBytes(preimage); if (!HEX128.test(signature)) fail('signer returned an invalid Ed25519 signature');
  const raw = Buffer.from(signer.rawPublicKey); const publicKeyB64 = raw.toString('base64');
  if (signer.publicKeyB64 !== publicKeyB64) fail('signer publicKeyB64 does not match rawPublicKey');
  const publicKey = createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
  if (!cryptoVerify(null, preimage, publicKey, Buffer.from(signature, 'hex'))) fail('signer signature failed self-verification');
  return { schema: STRICT_RECEIPT_V21_ENVELOPE_SCHEMA, body, receipt_hash: receiptHash, signature: { algorithm: 'Ed25519', key_id: keyId, value: signature }, public_key_b64: publicKeyB64 };
}
