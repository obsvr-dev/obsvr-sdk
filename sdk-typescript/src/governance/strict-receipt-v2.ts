import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import type { DeviceSigner } from '../proxy/device-identity.js';
import { INTENT_V2_ENGINE_VERSION } from '../policy/intent-alignment-v2.js';
import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import type { AarmOutcome } from './aarm-outcome.js';
import {
  STRICT_IDENTIFIER_MAX_BYTES,
  STRICT_SET_MAX_ITEMS,
  boundedCanonicalText,
} from './strict-canonical.js';
import {
  STRICT_RECEIPT_PROFILE_VERSION,
  STRICT_RECEIPT_SCHEMA,
  buildStrictReceiptBody,
  type StrictReceiptBody,
} from './strict-receipt.js';

export const STRICT_RECEIPT_V2_SCHEMA = 'obsvr-strict-receipt-v2' as const;
export const STRICT_RECEIPT_V2_PROFILE_VERSION = '2.0' as const;
export const STRICT_RECEIPT_V2_ENVELOPE_SCHEMA = 'obsvr-strict-receipt-envelope-v2' as const;
export const STRICT_RECEIPT_V2_BODY_DOMAIN = 'obsvr-strict-receipt/body/2' as const;
export const STRICT_RECEIPT_V2_SIGNATURE_DOMAIN = 'obsvr-strict-receipt/signature/2' as const;

const HEX64 = /^[0-9a-f]{64}$/;
const KEY_ID = /^sha256:[0-9a-f]{64}$/;
const SIGNATURE_HEX = /^[0-9a-f]{128}$/;
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export interface StrictReceiptV2Body {
  schema: typeof STRICT_RECEIPT_V2_SCHEMA;
  profile_version: typeof STRICT_RECEIPT_V2_PROFILE_VERSION;
  record_type: 'decision' | 'resolution';
  receipt_id: string;
  tenant_id: string;
  session_id: string;
  sequence: number;
  timestamp_ms: number;
  clock_regression_clamped: boolean;
  previous_receipt_hash: string | null;
  sdk: StrictReceiptBody['sdk'];
  initiator: StrictReceiptBody['initiator'];
  action: Omit<StrictReceiptBody['action'], 'target'> & { target_hash?: string };
  context: Omit<StrictReceiptBody['context'], 'schema'> & {
    schema: 'obsvr-action-context-v2';
  };
  evaluation: Omit<StrictReceiptBody['evaluation'], 'outcome'> & { outcome: AarmOutcome };
  execution_authorized: boolean;
  suspension?: StrictReceiptBody['suspension'];
  resolution?: StrictReceiptBody['resolution'];
}

export interface StrictReceiptV2Envelope {
  schema: typeof STRICT_RECEIPT_V2_ENVELOPE_SCHEMA;
  body: StrictReceiptV2Body;
  receipt_hash: string;
  signature: { algorithm: 'Ed25519'; key_id: string; value: string };
  public_key_b64?: string;
}

export class StrictReceiptV2ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StrictReceiptV2ValidationError';
  }
}

function fail(message: string): never { throw new StrictReceiptV2ValidationError(message); }
function record(value: unknown, field: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return fail(`${field} must be an object`);
  }
  return value as Record<string, unknown>;
}
function exact(value: Record<string, unknown>, allowed: readonly string[], field: string): void {
  const keys = new Set(allowed);
  const unknown = Object.keys(value).filter((key) => !keys.has(key)).sort();
  if (unknown.length) fail(`${field} contains unsupported field: ${unknown[0]}`);
}
function text(value: unknown, field: string): string {
  return boundedCanonicalText(value, field, STRICT_IDENTIFIER_MAX_BYTES, fail);
}
function hash(value: unknown, field: string): string {
  if (typeof value !== 'string' || !HEX64.test(value)) {
    return fail(`${field} must be 64 lowercase hex characters`);
  }
  return value;
}
function optionalHash(
  source: Record<string, unknown>, key: string, field: string,
): string | undefined {
  return Object.prototype.hasOwnProperty.call(source, key) ? hash(source[key], field) : undefined;
}
function boundedTexts(values: readonly string[] | undefined, field: string): void {
  if (values === undefined) return;
  if (values.length > STRICT_SET_MAX_ITEMS) fail(`${field} exceeds ${STRICT_SET_MAX_ITEMS} items`);
  values.forEach((value, index) => text(value, `${field}[${index}]`));
}
function boundedInputTexts(value: unknown, field: string): void {
  if (!Array.isArray(value)) fail(`${field} must be an array`);
  if (value.length > STRICT_SET_MAX_ITEMS) fail(`${field} exceeds ${STRICT_SET_MAX_ITEMS} items`);
  value.forEach((item, index) => text(item, `${field}[${index}]`));
}
function u64(value: number): Buffer {
  const output = Buffer.alloc(8);
  output.writeBigUInt64BE(BigInt(value));
  return output;
}

export function strictReceiptV2KeyId(rawPublicKey: Uint8Array): string {
  const raw = Buffer.from(rawPublicKey);
  if (raw.length !== 32) fail('public key must be 32 raw bytes');
  return `sha256:${createHash('sha256').update(raw).digest('hex')}`;
}

function validateV2TextBounds(body: StrictReceiptV2Body): void {
  [
    [body.receipt_id, 'receipt_id'], [body.session_id, 'session_id'],
    [body.sdk.version, 'sdk.version'], [body.initiator.agent_id, 'initiator.agent_id'],
    [body.action.action_id, 'action.action_id'], [body.action.kind, 'action.kind'],
    [body.action.name, 'action.name'], [body.context.run_id, 'context.run_id'],
    [body.evaluation.engine_version, 'evaluation.engine_version'],
    [body.evaluation.policy_version, 'evaluation.policy_version'],
    [body.evaluation.reason_code, 'evaluation.reason_code'],
  ].forEach(([value, field]) => text(value, field));
  if (body.context.thread_id !== undefined) text(body.context.thread_id, 'context.thread_id');
  boundedTexts(body.evaluation.rule_ids, 'evaluation.rule_ids');
  if (body.suspension) {
    text(body.suspension.suspension_id, 'suspension.suspension_id');
    boundedTexts(body.suspension.required_fields, 'suspension.required_fields');
    if (body.suspension.approval_request_id !== undefined) {
      text(body.suspension.approval_request_id, 'suspension.approval_request_id');
    }
  }
  if (body.resolution) {
    text(body.resolution.suspension_id, 'resolution.suspension_id');
    text(body.resolution.resolver_principal_id, 'resolution.resolver_principal_id');
  }
}

export function buildStrictReceiptV2Body(input: StrictReceiptV2Body): StrictReceiptV2Body {
  const root = record(input, 'receipt body');
  exact(root, [
    'schema', 'profile_version', 'record_type', 'receipt_id', 'tenant_id', 'session_id',
    'sequence', 'timestamp_ms', 'clock_regression_clamped', 'previous_receipt_hash',
    'sdk', 'initiator', 'action', 'context', 'evaluation', 'execution_authorized',
    'suspension', 'resolution',
  ], 'receipt body');
  if (root.schema !== STRICT_RECEIPT_V2_SCHEMA) fail('invalid receipt schema');
  if (root.profile_version !== STRICT_RECEIPT_V2_PROFILE_VERSION) {
    fail('invalid receipt profile_version');
  }
  const tenantId = text(root.tenant_id, 'tenant_id');
  const rawAction = record(root.action, 'action');
  exact(rawAction, ['action_id', 'kind', 'name', 'arguments_hash', 'target_hash',
    'effective_arguments_hash'], 'action');
  const targetHash = optionalHash(rawAction, 'target_hash', 'action.target_hash');
  const rawContext = record(root.context, 'context');
  exact(rawContext, ['schema', 'context_hash', 'run_id', 'thread_id'], 'context');
  if (rawContext.schema !== 'obsvr-action-context-v2') fail('invalid context.schema');
  const rawEvaluation = record(root.evaluation, 'evaluation');
  boundedInputTexts(rawEvaluation.rule_ids, 'evaluation.rule_ids');
  if (Object.prototype.hasOwnProperty.call(root, 'suspension')) {
    const rawSuspension = record(root.suspension, 'suspension');
    boundedInputTexts(rawSuspension.required_fields, 'suspension.required_fields');
  }

  const legacyAction = { ...rawAction };
  delete legacyAction.target_hash;
  if (targetHash !== undefined) legacyAction.target = targetHash;
  const legacyInput: Record<string, unknown> = {
    ...root,
    schema: STRICT_RECEIPT_SCHEMA,
    profile_version: STRICT_RECEIPT_PROFILE_VERSION,
    action: legacyAction,
    context: { ...rawContext, schema: 'obsvr-action-context-v1' },
  };
  delete legacyInput.tenant_id;
  const legacy = buildStrictReceiptBody(legacyInput as unknown as StrictReceiptBody);
  const normalizedAction: StrictReceiptV2Body['action'] = { ...legacy.action };
  delete (normalizedAction as Record<string, unknown>).target;
  if (legacy.action.target !== undefined) normalizedAction.target_hash = legacy.action.target;
  const body: StrictReceiptV2Body = {
    ...legacy,
    schema: STRICT_RECEIPT_V2_SCHEMA,
    profile_version: STRICT_RECEIPT_V2_PROFILE_VERSION,
    tenant_id: tenantId,
    action: normalizedAction,
    context: { ...legacy.context, schema: 'obsvr-action-context-v2' },
  };
  validateV2TextBounds(body);
  if (body.evaluation.engine_version !== INTENT_V2_ENGINE_VERSION) {
    fail(`evaluation.engine_version must be ${INTENT_V2_ENGINE_VERSION}`);
  }
  return body;
}

export function canonicalizeStrictReceiptV2Body(input: StrictReceiptV2Body): string {
  return canonicalJsonForHash(buildStrictReceiptV2Body(input));
}
export function strictReceiptV2Hash(input: StrictReceiptV2Body): string {
  const body = Buffer.from(canonicalizeStrictReceiptV2Body(input), 'utf8');
  return createHash('sha256').update(Buffer.concat([
    Buffer.from(STRICT_RECEIPT_V2_BODY_DOMAIN, 'utf8'), Buffer.from([0]),
    u64(body.length), body,
  ])).digest('hex');
}
export function strictReceiptV2SignaturePreimage(keyId: string, receiptHash: string): Buffer {
  if (!KEY_ID.test(keyId)) fail('invalid strict key id');
  const key = Buffer.from(keyId, 'utf8');
  return Buffer.concat([
    Buffer.from(STRICT_RECEIPT_V2_SIGNATURE_DOMAIN, 'utf8'), Buffer.from([0]),
    u64(key.length), key, Buffer.from(hash(receiptHash, 'receipt_hash'), 'hex'),
  ]);
}

export function signStrictReceiptV2(
  input: StrictReceiptV2Body,
  signer: DeviceSigner,
  includePublicKey = false,
): StrictReceiptV2Envelope {
  const body = buildStrictReceiptV2Body(input);
  const keyId = strictReceiptV2KeyId(signer.rawPublicKey);
  if (body.initiator.key_id !== keyId) fail('signer does not match initiator.key_id');
  const receiptHash = strictReceiptV2Hash(body);
  const preimage = strictReceiptV2SignaturePreimage(keyId, receiptHash);
  const signature = signer.signBytes(preimage);
  if (!SIGNATURE_HEX.test(signature)) fail('signer returned an invalid Ed25519 signature');
  const publicKeyB64 = Buffer.from(signer.rawPublicKey).toString('base64');
  if (signer.publicKeyB64 !== publicKeyB64) fail('signer publicKeyB64 does not match rawPublicKey');
  const publicKey = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(signer.rawPublicKey)]),
    format: 'der', type: 'spki',
  });
  if (!cryptoVerify(null, preimage, publicKey, Buffer.from(signature, 'hex'))) {
    fail('signer signature failed self-verification');
  }
  const envelope: StrictReceiptV2Envelope = {
    schema: STRICT_RECEIPT_V2_ENVELOPE_SCHEMA,
    body,
    receipt_hash: receiptHash,
    signature: { algorithm: 'Ed25519', key_id: keyId, value: signature },
  };
  if (includePublicKey) envelope.public_key_b64 = publicKeyB64;
  return envelope;
}
