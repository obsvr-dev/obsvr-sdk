import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import { sha256Hex } from '../policy/decision-record.js';
import type { IntentBaseResult } from '../policy/intent-alignment.js';
import type { IntentAlignmentResult } from '../policy/intent-alignment.js';
import type { DeviceSigner } from '../proxy/device-identity.js';
import {
  buildActionContext,
  type ActionContextDocument,
  type ActionContextInput,
  type PriorActionInput,
} from './action-context.js';
import {
  STRICT_RECEIPT_PROFILE_VERSION,
  STRICT_RECEIPT_SCHEMA,
  signStrictReceipt,
  strictReceiptKeyId,
  type StrictReceiptBody,
  type StrictReceiptEnvelope,
} from './strict-receipt.js';

const HEX64 = /^[0-9a-f]{64}$/;

export interface StrictApprovalExpectation {
  request_id: string;
  action_hash: string;
  decision: 'granted' | 'denied';
  current_time_ms: number;
}

export interface TrustedApprovalResult {
  request_id: string;
  action_hash: string;
  principal_id: string;
  /** Pseudonymous stable identity used for separation-of-duties checks. */
  principal_ref_hash?: string;
  decision: 'granted' | 'denied';
  source_hash: string;
  expires_at_ms: number;
}

export type StrictApprovalVerifier = (
  evidence: unknown, expected: StrictApprovalExpectation,
) => TrustedApprovalResult;

export function coordinatorText(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`${field} must be a nonblank string`);
  }
  return value;
}

export function coordinatorHash(value: unknown, field: string): string {
  if (typeof value !== 'string' || !HEX64.test(value)) {
    throw new Error(`${field} must be 64 lowercase hex characters`);
  }
  return value;
}

export function coordinatorSafeInteger(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${field} must be a nonnegative safe integer`);
  }
  return value;
}

export function cloneCoordinatorValue<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function compareScalars(left: string, right: string): number {
  const a = Array.from(left, (char) => char.codePointAt(0) as number);
  const b = Array.from(right, (char) => char.codePointAt(0) as number);
  for (let index = 0; index < Math.min(a.length, b.length); index++) {
    if (a[index] !== b[index]) return a[index] - b[index];
  }
  return a.length - b.length;
}

export function normalizedStrings(value: unknown, field: string): string[] {
  if (!Array.isArray(value)) throw new Error(`${field} must be an array`);
  const values = value.map((item, index) => coordinatorText(item, `${field}[${index}]`));
  values.sort(compareScalars);
  return values.filter((item, index) => index === 0 || item !== values[index - 1]);
}

export function canonicalHash(value: unknown): string {
  return sha256Hex(canonicalJsonForHash(value));
}

export function contextInputFromDocument(
  context: ActionContextDocument,
): Omit<ActionContextInput, 'prior_actions' | 'session_id'> {
  return {
    agent_id: context.agent.agent_id,
    active_intents: [...context.agent.active_intents],
    ...(context.agent.role === undefined ? {} : { agent_role: context.agent.role }),
    ...(context.agent.privilege_scope === undefined
      ? {} : { privilege_scope: [...context.agent.privilege_scope] }),
    current_action: { ...context.action },
    run_id: context.run_id,
    ...(context.thread_id === undefined ? {} : { thread_id: context.thread_id }),
  };
}

export function buildCoordinatorContext(
  input: Omit<ActionContextInput, 'prior_actions' | 'session_id'>,
  sessionId: string,
  priorActions: PriorActionInput[],
): ActionContextDocument {
  const raw = input as unknown as Record<string, unknown>;
  if (Object.prototype.hasOwnProperty.call(raw, 'prior_actions')) {
    throw new Error('caller prior_actions are not accepted');
  }
  if (Object.prototype.hasOwnProperty.call(raw, 'session_id')) {
    throw new Error('caller session_id is not accepted');
  }
  return buildActionContext({
    ...input,
    session_id: sessionId,
    prior_actions: priorActions.map((item) => ({
      ...item, data_classifications: [...item.data_classifications],
    })),
  });
}

export function addSafeIntegers(left: number, right: number): number {
  const result = left + right;
  if (!Number.isSafeInteger(result)) throw new Error('value exceeds safe integer range');
  return result;
}

export function signCoordinatorResolution(params: {
  prior: StrictReceiptEnvelope;
  evaluation: IntentAlignmentResult;
  context: ActionContextDocument;
  base_result: IntentBaseResult;
  policy_version: string;
  rule_ids: string[];
  method: NonNullable<StrictReceiptBody['resolution']>['method'];
  principal_id: string;
  source_hash: string;
  timestamp: number;
  clamped: boolean;
  sequence: number;
  session_id: string;
  previous_hash: string | null;
  sdk_version: string;
  signer: DeviceSigner;
  include_public_key: boolean;
}): StrictReceiptEnvelope {
  const action: StrictReceiptBody['action'] = {
    action_id: params.prior.body.action.action_id,
    kind: params.context.action.kind,
    name: params.context.action.name,
    arguments_hash: params.context.action.arguments_hash,
  };
  if (params.context.action.target !== undefined) action.target = params.context.action.target;
  if (params.evaluation.outcome === 'MODIFY') {
    action.effective_arguments_hash = params.base_result.modified_arguments_hash;
  }
  const body: StrictReceiptBody = {
    schema: STRICT_RECEIPT_SCHEMA,
    profile_version: STRICT_RECEIPT_PROFILE_VERSION,
    record_type: 'resolution',
    receipt_id: `${params.session_id}:${params.sequence}`,
    session_id: params.session_id,
    sequence: params.sequence,
    timestamp_ms: params.timestamp,
    clock_regression_clamped: params.clamped,
    previous_receipt_hash: params.previous_hash,
    sdk: { language: 'typescript', version: params.sdk_version },
    initiator: { ...params.prior.body.initiator },
    action,
    context: {
      schema: 'obsvr-action-context-v1',
      context_hash: params.evaluation.context_hash,
      run_id: params.context.run_id,
      ...(params.context.thread_id === undefined ? {} : { thread_id: params.context.thread_id }),
    },
    evaluation: {
      input_hash: params.evaluation.input_hash,
      policy_hash: params.evaluation.policy_hash,
      evaluator_hash: params.evaluation.evaluator_hash,
      engine_version: params.evaluation.engine_version,
      policy_version: params.policy_version,
      outcome: params.evaluation.outcome,
      reason_code: `resolution_${params.method}`,
      rule_ids: params.rule_ids,
    },
    execution_authorized: params.evaluation.outcome === 'ALLOW'
      || params.evaluation.outcome === 'MODIFY',
    resolution: {
      resolves_receipt_hash: params.prior.receipt_hash,
      suspension_id: params.prior.body.suspension!.suspension_id,
      method: params.method,
      resolver_principal_id: params.principal_id,
      resolution_source_hash: params.source_hash,
      resolved_at_ms: params.timestamp,
    },
  };
  return signStrictReceipt(body, params.signer, params.include_public_key);
}

export function signCoordinatorDecision(params: {
  action_id: string; context: ActionContextDocument;
  base_result: IntentBaseResult; evaluation: IntentAlignmentResult;
  policy_version: string; rule_ids: string[]; timestamp: number; clamped: boolean;
  sequence: number; session_id: string; previous_hash: string | null;
  sdk_version: string; signer: DeviceSigner; include_public_key: boolean;
  defer_ttl_ms: number; approval_request_pending: (requestId: string) => boolean;
}): StrictReceiptEnvelope {
  const body: StrictReceiptBody = {
    schema: STRICT_RECEIPT_SCHEMA,
    profile_version: STRICT_RECEIPT_PROFILE_VERSION,
    record_type: 'decision',
    receipt_id: `${params.session_id}:${params.sequence}`,
    session_id: params.session_id,
    sequence: params.sequence,
    timestamp_ms: params.timestamp,
    clock_regression_clamped: params.clamped,
    previous_receipt_hash: params.previous_hash,
    sdk: { language: 'typescript', version: params.sdk_version },
    initiator: {
      agent_id: params.context.agent.agent_id,
      key_id: strictReceiptKeyId(params.signer.rawPublicKey),
    },
    action: {
      action_id: params.action_id, kind: params.context.action.kind,
      name: params.context.action.name,
      arguments_hash: params.context.action.arguments_hash,
    },
    context: {
      schema: 'obsvr-action-context-v1', context_hash: params.evaluation.context_hash,
      run_id: params.context.run_id,
    },
    evaluation: {
      input_hash: params.evaluation.input_hash,
      policy_hash: params.evaluation.policy_hash,
      evaluator_hash: params.evaluation.evaluator_hash,
      engine_version: params.evaluation.engine_version,
      policy_version: params.policy_version,
      outcome: params.evaluation.outcome,
      reason_code: params.evaluation.reason_code,
      rule_ids: params.rule_ids,
    },
    execution_authorized: params.evaluation.outcome === 'ALLOW'
      || params.evaluation.outcome === 'MODIFY',
  };
  if (params.context.action.target !== undefined) {
    body.action.target = params.context.action.target;
  }
  if (params.context.thread_id !== undefined) body.context.thread_id = params.context.thread_id;
  if (params.evaluation.outcome === 'MODIFY') {
    body.action.effective_arguments_hash = params.base_result.modified_arguments_hash;
  }
  if (params.evaluation.outcome === 'STEP_UP') {
    const requestId = params.base_result.approval_request_id as string;
    if (params.approval_request_pending(requestId)) {
      throw new Error('approval_request_id is already pending');
    }
    body.suspension = {
      suspension_id: requestId, type: 'approval', status: 'pending', required_fields: [],
      expires_at_ms: params.base_result.approval_expires_at_ms as number,
      approval_request_id: requestId,
      approval_action_hash: params.base_result.approval_action_hash,
    };
    if (body.suspension.expires_at_ms <= params.timestamp) {
      throw new Error('approval expiry must follow decision timestamp');
    }
  } else if (params.evaluation.outcome === 'DEFER') {
    body.suspension = {
      suspension_id: `defer:${params.session_id}:${params.sequence}`,
      type: 'context', status: 'pending',
      required_fields: params.evaluation.required_fields as string[],
      expires_at_ms: addSafeIntegers(params.timestamp, params.defer_ttl_ms),
    };
  }
  return signStrictReceipt(body, params.signer, params.include_public_key);
}

export function requestFingerprint(params: {
  context: Omit<ActionContextInput, 'prior_actions' | 'session_id'>;
  base_result: IntentBaseResult;
  policy_version: string;
  rule_ids: string[];
  session_id: string;
  action_id: string;
}): string {
  const context = buildActionContext({
    ...params.context,
    session_id: params.session_id,
    prior_actions: [],
  });
  return sha256Hex(canonicalJsonForHash({
    schema: 'obsvr-strict-decision-request-v1',
    action_id: coordinatorText(params.action_id, 'action_id'),
    context,
    base_result: { ...params.base_result },
    policy_version: coordinatorText(params.policy_version, 'policy_version'),
    rule_ids: normalizedStrings(params.rule_ids, 'rule_ids'),
  }));
}

export function trustedApprovalResult(
  value: unknown,
  expected: StrictApprovalExpectation,
  suspensionExpiry: number,
): {
  requestId: string;
  actionHash: string;
  principalId: string;
  principalRefHash?: string;
  sourceHash: string;
} {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('approval verifier returned an invalid result');
  }
  const raw = value as Record<string, unknown>;
  const required = new Set([
    'request_id', 'action_hash', 'principal_id', 'decision',
    'source_hash', 'expires_at_ms',
  ]);
  const allowed = new Set([...required, 'principal_ref_hash']);
  const unknown = Object.keys(raw).filter((key) => !allowed.has(key));
  const missing = [...required].filter((key) => !Object.prototype.hasOwnProperty.call(raw, key));
  if (unknown.length > 0 || missing.length > 0) {
    throw new Error('approval verifier returned an invalid result');
  }
  const requestId = coordinatorText(raw.request_id, 'trusted approval request_id');
  const actionHash = coordinatorHash(raw.action_hash, 'trusted approval action_hash');
  const principalId = coordinatorText(raw.principal_id, 'trusted approval principal_id');
  const principalRefHash = raw.principal_ref_hash === undefined
    ? undefined
    : coordinatorHash(raw.principal_ref_hash, 'trusted approval principal_ref_hash');
  const sourceHash = coordinatorHash(raw.source_hash, 'trusted approval source_hash');
  const expiresAt = coordinatorSafeInteger(raw.expires_at_ms, 'trusted approval expires_at_ms');
  if (requestId !== expected.request_id || actionHash !== expected.action_hash
    || raw.decision !== expected.decision) {
    throw new Error('approval verifier result does not match expected binding');
  }
  if (expiresAt > suspensionExpiry) {
    throw new Error('approval verifier expiry exceeds suspension expiry');
  }
  if (expected.decision === 'granted'
    && (expected.current_time_ms >= expiresAt
      || expected.current_time_ms >= suspensionExpiry)) {
    throw new Error('trusted approval is expired');
  }
  return {
    requestId, actionHash, principalId,
    ...(principalRefHash === undefined ? {} : { principalRefHash }),
    sourceHash,
  };
}

function projection(context: ActionContextDocument): Record<string, unknown> {
  return {
    agent_id: context.agent.agent_id,
    role: context.agent.role,
    privilege_scope: context.agent.privilege_scope,
    active_intents: context.agent.active_intents,
    action: context.action,
    run_id: context.run_id,
    session_id: context.session_id,
    thread_id: context.thread_id,
  };
}

export function validateDeferredChanges(params: {
  original_context: ActionContextDocument;
  current_context: ActionContextDocument;
  original_base: IntentBaseResult;
  current_base: IntentBaseResult;
  required_fields: string[];
}): void {
  const required = new Set(params.required_fields);
  const original = projection(params.original_context);
  const current = projection(params.current_context);
  const originalAction = { ...(original.action as Record<string, unknown>) };
  const currentAction = { ...(current.action as Record<string, unknown>) };
  if (required.has('action.target')) {
    delete originalAction.target;
    delete currentAction.target;
  }
  original.action = originalAction;
  current.action = currentAction;
  if (required.has('active_intents')) {
    delete original.active_intents;
    delete current.active_intents;
  }
  if (canonicalJsonForHash(original) !== canonicalJsonForHash(current)) {
    throw new Error('DEFER resolution changed fields outside required_fields');
  }
  if (required.has('policy_evaluation')) return;
  const allowedBase = new Set<string>();
  if (required.has('modified_arguments_hash')) allowedBase.add('modified_arguments_hash');
  for (const field of params.required_fields) {
    if (field.startsWith('approval_')) allowedBase.add(field);
  }
  const before = { ...params.original_base } as Record<string, unknown>;
  const after = { ...params.current_base } as Record<string, unknown>;
  for (const field of allowedBase) {
    delete before[field];
    delete after[field];
  }
  if (canonicalJsonForHash(before) !== canonicalJsonForHash(after)) {
    throw new Error('DEFER resolution changed base result outside required_fields');
  }
}
