import { createHash } from 'node:crypto';
import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import type { DeviceSigner } from '../proxy/device-identity.js';
import { AARM_OUTCOMES, type AarmOutcome } from './aarm-outcome.js';

export const STRICT_RECEIPT_SCHEMA = 'obsvr-strict-receipt-v1' as const;
export const STRICT_RECEIPT_PROFILE_VERSION = '1.0' as const;
export const STRICT_RECEIPT_ENVELOPE_SCHEMA = 'obsvr-strict-receipt-envelope-v1' as const;
export const STRICT_RECEIPT_BODY_DOMAIN = 'obsvr-strict-receipt/body/1' as const;
export const STRICT_RECEIPT_SIGNATURE_DOMAIN = 'obsvr-strict-receipt/signature/1' as const;

const HEX64 = /^[0-9a-f]{64}$/;
const KEY_ID = /^sha256:[0-9a-f]{64}$/;
const OUTCOMES = new Set<string>(AARM_OUTCOMES);

export interface StrictReceiptBody {
  schema: typeof STRICT_RECEIPT_SCHEMA;
  profile_version: typeof STRICT_RECEIPT_PROFILE_VERSION;
  record_type: 'decision' | 'resolution';
  receipt_id: string;
  session_id: string;
  sequence: number;
  timestamp_ms: number;
  clock_regression_clamped: boolean;
  previous_receipt_hash: string | null;
  sdk: { language: 'typescript' | 'python'; version: string };
  initiator: { agent_id: string; key_id: string };
  action: {
    action_id: string;
    kind: string;
    name: string;
    arguments_hash: string;
    target?: string;
    effective_arguments_hash?: string;
  };
  context: {
    schema: 'obsvr-action-context-v1';
    context_hash: string;
    run_id: string;
    thread_id?: string;
  };
  evaluation: {
    input_hash: string;
    policy_hash: string;
    evaluator_hash: string;
    engine_version: string;
    policy_version: string;
    outcome: AarmOutcome;
    reason_code: string;
    rule_ids: string[];
  };
  execution_authorized: boolean;
  suspension?: {
    suspension_id: string;
    type: 'approval' | 'context';
    status: 'pending';
    required_fields: string[];
    expires_at_ms: number;
    approval_request_id?: string;
    approval_action_hash?: string;
  };
  resolution?: {
    resolves_receipt_hash: string;
    suspension_id: string;
    method: 'approval_granted' | 'approval_denied' | 'context_supplied' | 'expired' | 'cancelled';
    resolver_principal_id: string;
    resolution_source_hash: string;
    resolved_at_ms: number;
  };
}

export interface StrictReceiptEnvelope {
  schema: typeof STRICT_RECEIPT_ENVELOPE_SCHEMA;
  body: StrictReceiptBody;
  receipt_hash: string;
  signature: { algorithm: 'Ed25519'; key_id: string; value: string };
  public_key_b64?: string;
}

export class StrictReceiptValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StrictReceiptValidationError';
  }
}

function record(value: unknown, field: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new StrictReceiptValidationError(`${field} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exact(value: Record<string, unknown>, allowed: readonly string[], field: string): void {
  const set = new Set(allowed);
  const unknown = Object.keys(value).filter((key) => !set.has(key)).sort();
  if (unknown.length) {
    throw new StrictReceiptValidationError(`${field} contains unsupported field: ${unknown[0]}`);
  }
}

function text(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new StrictReceiptValidationError(`${field} must be a nonblank string`);
  }
  return value;
}

function hash(value: unknown, field: string): string {
  if (typeof value !== 'string' || !HEX64.test(value)) {
    throw new StrictReceiptValidationError(`${field} must be 64 lowercase hex characters`);
  }
  return value;
}

function safeInteger(value: unknown, field: string, positive = false): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < (positive ? 1 : 0)) {
    throw new StrictReceiptValidationError(`${field} must be a ${positive ? 'positive' : 'nonnegative'} safe integer`);
  }
  return value;
}

function optionalText(source: Record<string, unknown>, key: string, field: string): string | undefined {
  if (!Object.prototype.hasOwnProperty.call(source, key)) return undefined;
  return text(source[key], field);
}

function compareScalars(left: string, right: string): number {
  const a = Array.from(left, (char) => char.codePointAt(0) as number);
  const b = Array.from(right, (char) => char.codePointAt(0) as number);
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

function stringSet(value: unknown, field: string): string[] {
  if (!Array.isArray(value)) throw new StrictReceiptValidationError(`${field} must be an array`);
  const values = value.map((item, index) => text(item, `${field}[${index}]`));
  values.sort(compareScalars);
  return values.filter((item, index) => index === 0 || item !== values[index - 1]);
}

function u64(value: number): Buffer {
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(BigInt(value));
  return out;
}

export function strictReceiptKeyId(rawPublicKey: Uint8Array): string {
  const raw = Buffer.from(rawPublicKey);
  if (raw.length !== 32) throw new StrictReceiptValidationError('public key must be 32 raw bytes');
  return `sha256:${createHash('sha256').update(raw).digest('hex')}`;
}

export function buildStrictReceiptBody(input: StrictReceiptBody): StrictReceiptBody {
  const root = record(input, 'receipt body');
  exact(root, [
    'schema', 'profile_version', 'record_type', 'receipt_id', 'session_id', 'sequence',
    'timestamp_ms', 'clock_regression_clamped', 'previous_receipt_hash', 'sdk', 'initiator', 'action', 'context',
    'evaluation', 'execution_authorized', 'suspension', 'resolution',
  ], 'receipt body');
  if (root.schema !== STRICT_RECEIPT_SCHEMA) throw new StrictReceiptValidationError('invalid receipt schema');
  if (root.profile_version !== STRICT_RECEIPT_PROFILE_VERSION) throw new StrictReceiptValidationError('invalid receipt profile_version');
  if (root.record_type !== 'decision' && root.record_type !== 'resolution') throw new StrictReceiptValidationError('invalid record_type');
  const sessionId = text(root.session_id, 'session_id');
  const sequence = safeInteger(root.sequence, 'sequence', true);
  if (root.receipt_id !== `${sessionId}:${sequence}`) throw new StrictReceiptValidationError('receipt_id must equal session_id:sequence');
  const timestamp = safeInteger(root.timestamp_ms, 'timestamp_ms');
  if (typeof root.clock_regression_clamped !== 'boolean') {
    throw new StrictReceiptValidationError('clock_regression_clamped must be a boolean');
  }
  let previous: string | null;
  if (sequence === 1) {
    if (root.previous_receipt_hash !== null) throw new StrictReceiptValidationError('genesis previous_receipt_hash must be null');
    previous = null;
  } else {
    previous = hash(root.previous_receipt_hash, 'previous_receipt_hash');
  }

  const sdk = record(root.sdk, 'sdk');
  exact(sdk, ['language', 'version'], 'sdk');
  if (sdk.language !== 'typescript' && sdk.language !== 'python') throw new StrictReceiptValidationError('invalid sdk.language');
  const initiator = record(root.initiator, 'initiator');
  exact(initiator, ['agent_id', 'key_id'], 'initiator');
  const keyId = text(initiator.key_id, 'initiator.key_id');
  if (!KEY_ID.test(keyId)) throw new StrictReceiptValidationError('initiator.key_id must be sha256:<64 lowercase hex>');

  const action = record(root.action, 'action');
  exact(action, ['action_id', 'kind', 'name', 'arguments_hash', 'target', 'effective_arguments_hash'], 'action');
  const normalizedAction: StrictReceiptBody['action'] = {
    action_id: text(action.action_id, 'action.action_id'),
    kind: text(action.kind, 'action.kind'),
    name: text(action.name, 'action.name'),
    arguments_hash: hash(action.arguments_hash, 'action.arguments_hash'),
  };
  const target = optionalText(action, 'target', 'action.target');
  if (target !== undefined) normalizedAction.target = target;

  const context = record(root.context, 'context');
  exact(context, ['schema', 'context_hash', 'run_id', 'thread_id'], 'context');
  if (context.schema !== 'obsvr-action-context-v1') throw new StrictReceiptValidationError('invalid context.schema');
  const normalizedContext: StrictReceiptBody['context'] = {
    schema: 'obsvr-action-context-v1',
    context_hash: hash(context.context_hash, 'context.context_hash'),
    run_id: text(context.run_id, 'context.run_id'),
  };
  const threadId = optionalText(context, 'thread_id', 'context.thread_id');
  if (threadId !== undefined) normalizedContext.thread_id = threadId;

  const evaluation = record(root.evaluation, 'evaluation');
  exact(evaluation, [
    'input_hash', 'policy_hash', 'evaluator_hash', 'engine_version', 'policy_version',
    'outcome', 'reason_code', 'rule_ids',
  ], 'evaluation');
  if (typeof evaluation.outcome !== 'string' || !OUTCOMES.has(evaluation.outcome)) throw new StrictReceiptValidationError('invalid evaluation.outcome');
  const outcome = evaluation.outcome as AarmOutcome;
  const normalizedEvaluation: StrictReceiptBody['evaluation'] = {
    input_hash: hash(evaluation.input_hash, 'evaluation.input_hash'),
    policy_hash: hash(evaluation.policy_hash, 'evaluation.policy_hash'),
    evaluator_hash: hash(evaluation.evaluator_hash, 'evaluation.evaluator_hash'),
    engine_version: text(evaluation.engine_version, 'evaluation.engine_version'),
    policy_version: text(evaluation.policy_version, 'evaluation.policy_version'),
    outcome,
    reason_code: text(evaluation.reason_code, 'evaluation.reason_code'),
    rule_ids: stringSet(evaluation.rule_ids, 'evaluation.rule_ids'),
  };
  const authorized = outcome === 'ALLOW' || outcome === 'MODIFY';
  if (root.execution_authorized !== authorized) throw new StrictReceiptValidationError('execution_authorized disagrees with outcome');
  if (outcome === 'MODIFY') {
    const effective = hash(action.effective_arguments_hash, 'action.effective_arguments_hash');
    if (effective === normalizedAction.arguments_hash) throw new StrictReceiptValidationError('MODIFY effective hash must differ');
    normalizedAction.effective_arguments_hash = effective;
  } else if (Object.prototype.hasOwnProperty.call(action, 'effective_arguments_hash')) {
    throw new StrictReceiptValidationError('effective_arguments_hash requires MODIFY');
  }

  let suspension: StrictReceiptBody['suspension'];
  if (root.record_type === 'decision' && (outcome === 'STEP_UP' || outcome === 'DEFER')) {
    const raw = record(root.suspension, 'suspension');
    exact(raw, [
      'suspension_id', 'type', 'status', 'required_fields', 'expires_at_ms',
      'approval_request_id', 'approval_action_hash',
    ], 'suspension');
    const type = outcome === 'STEP_UP' ? 'approval' : 'context';
    if (raw.type !== type) throw new StrictReceiptValidationError(`suspension.type must be ${type}`);
    if (raw.status !== 'pending') throw new StrictReceiptValidationError('suspension.status must be pending');
    const requiredFields = stringSet(raw.required_fields, 'suspension.required_fields');
    const expiresAt = safeInteger(raw.expires_at_ms, 'suspension.expires_at_ms');
    if (expiresAt < timestamp) throw new StrictReceiptValidationError('suspension.expires_at_ms precedes timestamp_ms');
    suspension = {
      suspension_id: text(raw.suspension_id, 'suspension.suspension_id'),
      type,
      status: 'pending',
      required_fields: requiredFields,
      expires_at_ms: expiresAt,
    };
    if (outcome === 'STEP_UP') {
      if (requiredFields.length !== 0) throw new StrictReceiptValidationError('STEP_UP required_fields must be empty');
      suspension.approval_request_id = text(raw.approval_request_id, 'suspension.approval_request_id');
      suspension.approval_action_hash = hash(raw.approval_action_hash, 'suspension.approval_action_hash');
    } else {
      if (requiredFields.length === 0) throw new StrictReceiptValidationError('DEFER required_fields must be nonempty');
      if (Object.prototype.hasOwnProperty.call(raw, 'approval_request_id')
        || Object.prototype.hasOwnProperty.call(raw, 'approval_action_hash')) {
        throw new StrictReceiptValidationError('DEFER cannot carry approval fields');
      }
    }
  } else if (Object.prototype.hasOwnProperty.call(root, 'suspension')) {
    throw new StrictReceiptValidationError('suspension requires a STEP_UP or DEFER decision');
  }

  let resolution: StrictReceiptBody['resolution'];
  if (root.record_type === 'resolution') {
    if (!['ALLOW', 'DENY', 'MODIFY'].includes(outcome)) throw new StrictReceiptValidationError('resolution outcome must be final');
    const raw = record(root.resolution, 'resolution');
    exact(raw, [
      'resolves_receipt_hash', 'suspension_id', 'method', 'resolver_principal_id',
      'resolution_source_hash', 'resolved_at_ms',
    ], 'resolution');
    const method = raw.method;
    if (!['approval_granted', 'approval_denied', 'context_supplied', 'expired', 'cancelled'].includes(String(method))) {
      throw new StrictReceiptValidationError('invalid resolution.method');
    }
    if (['approval_denied', 'expired', 'cancelled'].includes(String(method)) && outcome !== 'DENY') {
      throw new StrictReceiptValidationError('resolution method requires DENY');
    }
    const resolvedAt = safeInteger(raw.resolved_at_ms, 'resolution.resolved_at_ms');
    if (resolvedAt > timestamp) throw new StrictReceiptValidationError('resolution.resolved_at_ms exceeds timestamp_ms');
    resolution = {
      resolves_receipt_hash: hash(raw.resolves_receipt_hash, 'resolution.resolves_receipt_hash'),
      suspension_id: text(raw.suspension_id, 'resolution.suspension_id'),
      method: method as NonNullable<StrictReceiptBody['resolution']>['method'],
      resolver_principal_id: text(raw.resolver_principal_id, 'resolution.resolver_principal_id'),
      resolution_source_hash: hash(raw.resolution_source_hash, 'resolution.resolution_source_hash'),
      resolved_at_ms: resolvedAt,
    };
  } else if (Object.prototype.hasOwnProperty.call(root, 'resolution')) {
    throw new StrictReceiptValidationError('decision cannot carry resolution');
  }

  const body: StrictReceiptBody = {
    schema: STRICT_RECEIPT_SCHEMA,
    profile_version: STRICT_RECEIPT_PROFILE_VERSION,
    record_type: root.record_type,
    receipt_id: `${sessionId}:${sequence}`,
    session_id: sessionId,
    sequence,
    timestamp_ms: timestamp,
    clock_regression_clamped: root.clock_regression_clamped,
    previous_receipt_hash: previous,
    sdk: { language: sdk.language, version: text(sdk.version, 'sdk.version') },
    initiator: { agent_id: text(initiator.agent_id, 'initiator.agent_id'), key_id: keyId },
    action: normalizedAction,
    context: normalizedContext,
    evaluation: normalizedEvaluation,
    execution_authorized: authorized,
  };
  if (suspension) body.suspension = suspension;
  if (resolution) body.resolution = resolution;
  return body;
}

export function canonicalizeStrictReceiptBody(input: StrictReceiptBody): string {
  return canonicalJsonForHash(buildStrictReceiptBody(input));
}

export function strictReceiptHash(input: StrictReceiptBody): string {
  const body = Buffer.from(canonicalizeStrictReceiptBody(input), 'utf8');
  return createHash('sha256').update(Buffer.concat([
    Buffer.from(STRICT_RECEIPT_BODY_DOMAIN, 'utf8'), Buffer.from([0]), u64(body.length), body,
  ])).digest('hex');
}

export function strictReceiptSignaturePreimage(keyId: string, receiptHash: string): Buffer {
  if (!KEY_ID.test(keyId)) throw new StrictReceiptValidationError('invalid strict key id');
  const key = Buffer.from(keyId, 'utf8');
  const digest = Buffer.from(hash(receiptHash, 'receipt_hash'), 'hex');
  return Buffer.concat([
    Buffer.from(STRICT_RECEIPT_SIGNATURE_DOMAIN, 'utf8'), Buffer.from([0]),
    u64(key.length), key, digest,
  ]);
}

export function signStrictReceipt(
  input: StrictReceiptBody,
  signer: DeviceSigner,
  includePublicKey = false,
): StrictReceiptEnvelope {
  const body = buildStrictReceiptBody(input);
  const keyId = strictReceiptKeyId(signer.rawPublicKey);
  if (body.initiator.key_id !== keyId) throw new StrictReceiptValidationError('signer does not match initiator.key_id');
  const receiptHash = strictReceiptHash(body);
  const envelope: StrictReceiptEnvelope = {
    schema: STRICT_RECEIPT_ENVELOPE_SCHEMA,
    body,
    receipt_hash: receiptHash,
    signature: {
      algorithm: 'Ed25519',
      key_id: keyId,
      value: signer.signBytes(strictReceiptSignaturePreimage(keyId, receiptHash)),
    },
  };
  if (includePublicKey) envelope.public_key_b64 = signer.publicKeyB64;
  return envelope;
}
