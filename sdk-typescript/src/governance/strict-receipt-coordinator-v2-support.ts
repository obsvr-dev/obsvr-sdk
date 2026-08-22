import { sha256Hex } from '../policy/decision-record.js';
import {
  buildIntentPolicyV2, evaluateIntentAlignmentV2,
  type IntentAlignmentV2Result, type IntentPolicyV2Document, type IntentV2BaseResult,
} from '../policy/intent-alignment-v2.js';
import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import type { DeviceSigner } from '../proxy/device-identity.js';
import {
  buildActionContextV2, type ActionContextV2Document,
  type ActionContextV2Input, type PriorActionV2Input,
} from './action-context-v2.js';
import {
  STRICT_IDENTIFIER_MAX_BYTES, STRICT_SET_MAX_ITEMS,
  boundedCanonicalText, normalizedBoundedSet,
} from './strict-canonical.js';
import {
  STRICT_RECEIPT_V2_PROFILE_VERSION, STRICT_RECEIPT_V2_SCHEMA,
  signStrictReceiptV2, strictReceiptV2KeyId,
  type StrictReceiptV2Body, type StrictReceiptV2Envelope,
} from './strict-receipt-v2.js';
import { verifyStrictReceiptV2 } from './strict-receipt-v2-verify.js';
import type {
  StrictCoordinatorV2ContextInput, StrictDecisionV2Input,
  StrictResolutionV2Input, StrictTimeoutV2Input,
} from './strict-receipt-coordinator-v2-types.js';

const HEX64 = /^[0-9a-f]{64}$/;
function fail(message: string): never { throw new Error(message); }
export function v2Text(value: unknown, field: string): string {
  return boundedCanonicalText(value, field, STRICT_IDENTIFIER_MAX_BYTES, fail);
}
export function v2Hash(value: unknown, field: string): string {
  if (typeof value !== 'string' || !HEX64.test(value)) fail(`${field} must be 64 lowercase hex characters`);
  return value;
}
export function v2Integer(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    fail(`${field} must be a nonnegative safe integer`);
  }
  return value;
}
export function v2Strings(value: unknown, field: string): string[] {
  return normalizedBoundedSet(value, field, STRICT_SET_MAX_ITEMS, STRICT_IDENTIFIER_MAX_BYTES, fail);
}
export function v2Clone<T>(value: T): T { return JSON.parse(JSON.stringify(value)) as T; }
export function v2CanonicalHash(value: unknown): string {
  return sha256Hex(canonicalJsonForHash(value));
}
export function v2SafeAdd(left: number, right: number): number {
  const result = left + right;
  if (!Number.isSafeInteger(result)) fail('value exceeds safe integer range');
  return result;
}

export function buildCoordinatorContextV2(
  input: StrictCoordinatorV2ContextInput, sessionId: string, prior: PriorActionV2Input[],
): ActionContextV2Document {
  const raw = input as unknown as Record<string, unknown>;
  if (Object.prototype.hasOwnProperty.call(raw, 'prior_actions')) fail('caller prior_actions are not accepted');
  if (Object.prototype.hasOwnProperty.call(raw, 'session_id')) fail('caller session_id is not accepted');
  return buildActionContextV2({
    ...input, session_id: sessionId,
    prior_actions: prior.map((item) => ({ ...item, data_classifications: [...item.data_classifications] })),
  });
}

export function contextInputFromV2Document(
  context: ActionContextV2Document,
): StrictCoordinatorV2ContextInput {
  return {
    agent_id: context.agent.agent_id,
    active_intents: [...context.agent.active_intents],
    ...(context.agent.role === undefined ? {} : { agent_role: context.agent.role }),
    ...(context.agent.privilege_scope === undefined ? {} : { privilege_scope: [...context.agent.privilege_scope] }),
    current_action: { ...context.action }, run_id: context.run_id,
    ...(context.thread_id === undefined ? {} : { thread_id: context.thread_id }),
  };
}

function normalizedContext(input: StrictCoordinatorV2ContextInput, sessionId: string): ActionContextV2Document {
  return buildActionContextV2({ ...input, session_id: sessionId, prior_actions: [] });
}
export function decisionV2Fingerprint(input: StrictDecisionV2Input, tenantId: string, sessionId: string): string {
  return v2CanonicalHash({
    schema: 'obsvr-strict-decision-request-v2', tenant_id: tenantId, session_id: sessionId,
    action_id: v2Text(input.action_id, 'action_id'), context: normalizedContext(input.context, sessionId),
    base_result: { ...input.base_result }, policy_version: v2Text(input.policy_version, 'policy_version'),
    rule_ids: v2Strings(input.rule_ids, 'rule_ids'),
  });
}
export function resolutionV2Fingerprint(input: StrictResolutionV2Input, tenantId: string, sessionId: string): string {
  return v2CanonicalHash({
    schema: 'obsvr-strict-resolution-request-v2', tenant_id: tenantId, session_id: sessionId,
    suspended_receipt_hash: input.suspended_receipt_hash, method: input.method,
    context: normalizedContext(input.context, sessionId), base_result: { ...input.base_result },
    policy_version: input.policy_version, rule_ids: v2Strings(input.rule_ids, 'rule_ids'),
    resolver_principal_id: input.resolver_principal_id ?? null,
    resolution_source_hash: input.resolution_source_hash ?? null,
    approval_evidence_hash: input.approval_evidence === undefined ? null : v2CanonicalHash(input.approval_evidence),
  });
}
export function timeoutV2Fingerprint(input: StrictTimeoutV2Input, tenantId: string, sessionId: string): string {
  return v2CanonicalHash({ schema: 'obsvr-strict-timeout-request-v2', tenant_id: tenantId,
    session_id: sessionId, suspended_receipt_hash: input.suspended_receipt_hash,
    policy_version: input.policy_version, rule_ids: v2Strings(input.rule_ids, 'rule_ids') });
}

export function evaluateV2(
  context: ActionContextV2Document, base: IntentV2BaseResult, policy: IntentPolicyV2Document,
): IntentAlignmentV2Result {
  return evaluateIntentAlignmentV2({ context, base_result: base, policy });
}
export { buildIntentPolicyV2 };

function checkedSign(body: StrictReceiptV2Body, signer: DeviceSigner, includeKey: boolean): StrictReceiptV2Envelope {
  const receipt = signStrictReceiptV2(body, signer, includeKey);
  const axes = verifyStrictReceiptV2(receipt, { pinned_public_key_b64: signer.publicKeyB64 });
  if (!axes.schema_valid || !axes.hash_valid || !axes.signature_valid || !axes.semantic_valid
    || !axes.identity_binding_valid || axes.key_trust !== 'pinned') fail('signed v2 receipt failed self-verification');
  return receipt;
}

interface CommonSignV2 {
  tenant_id: string; session_id: string; sequence: number; timestamp: number; clamped: boolean;
  previous_hash: string | null; sdk_version: string; signer: DeviceSigner; include_public_key: boolean;
  context: ActionContextV2Document; base_result: IntentV2BaseResult;
  evaluation: IntentAlignmentV2Result; policy_version: string; rule_ids: string[];
}
function commonBody(params: CommonSignV2, actionId: string): Omit<StrictReceiptV2Body, 'record_type' | 'resolution'> {
  const action: StrictReceiptV2Body['action'] = {
    action_id: actionId, kind: params.context.action.kind, name: params.context.action.name,
    arguments_hash: params.context.action.arguments_hash,
    ...(params.context.action.target_hash === undefined ? {} : { target_hash: params.context.action.target_hash }),
  };
  if (params.evaluation.outcome === 'MODIFY') action.effective_arguments_hash = v2Hash(params.base_result.modified_arguments_hash, 'modified_arguments_hash');
  return {
    schema: STRICT_RECEIPT_V2_SCHEMA, profile_version: STRICT_RECEIPT_V2_PROFILE_VERSION,
    receipt_id: `${params.session_id}:${params.sequence}`, tenant_id: params.tenant_id,
    session_id: params.session_id, sequence: params.sequence, timestamp_ms: params.timestamp,
    clock_regression_clamped: params.clamped, previous_receipt_hash: params.previous_hash,
    sdk: { language: 'typescript', version: params.sdk_version },
    initiator: { agent_id: params.context.agent.agent_id, key_id: strictReceiptV2KeyId(params.signer.rawPublicKey) },
    action, context: { schema: 'obsvr-action-context-v2', context_hash: params.evaluation.context_hash,
      run_id: params.context.run_id, ...(params.context.thread_id === undefined ? {} : { thread_id: params.context.thread_id }) },
    evaluation: { input_hash: params.evaluation.input_hash, policy_hash: params.evaluation.policy_hash,
      evaluator_hash: params.evaluation.evaluator_hash, engine_version: params.evaluation.engine_version,
      policy_version: v2Text(params.policy_version, 'policy_version'), outcome: params.evaluation.outcome,
      reason_code: params.evaluation.reason_code, rule_ids: v2Strings(params.rule_ids, 'rule_ids') },
    execution_authorized: params.evaluation.outcome === 'ALLOW' || params.evaluation.outcome === 'MODIFY',
  };
}

export function signDecisionV2(params: CommonSignV2 & { action_id: string; defer_ttl_ms: number }): StrictReceiptV2Envelope {
  const body: StrictReceiptV2Body = { ...commonBody(params, params.action_id), record_type: 'decision' };
  if (params.evaluation.outcome === 'STEP_UP') {
    const requestId = v2Text(params.base_result.approval_request_id, 'approval_request_id');
    body.suspension = { suspension_id: requestId, type: 'approval', status: 'pending', required_fields: [],
      expires_at_ms: v2Integer(params.base_result.approval_expires_at_ms, 'approval_expires_at_ms'),
      approval_request_id: requestId, approval_action_hash: v2Hash(params.base_result.approval_action_hash, 'approval_action_hash') };
  } else if (params.evaluation.outcome === 'DEFER') {
    body.suspension = { suspension_id: `defer:${params.session_id}:${params.sequence}`, type: 'context', status: 'pending',
      required_fields: [...(params.evaluation.required_fields ?? [])], expires_at_ms: v2SafeAdd(params.timestamp, params.defer_ttl_ms) };
  }
  if (body.suspension && body.suspension.expires_at_ms <= params.timestamp) fail('suspension expiry must follow decision timestamp');
  return checkedSign(body, params.signer, params.include_public_key);
}

export function signResolutionV2(params: CommonSignV2 & {
  prior: StrictReceiptV2Envelope; method: NonNullable<StrictReceiptV2Body['resolution']>['method'];
  principal_id: string; source_hash: string;
}): StrictReceiptV2Envelope {
  const body: StrictReceiptV2Body = {
    ...commonBody(params, params.prior.body.action.action_id), record_type: 'resolution',
    initiator: { ...params.prior.body.initiator }, evaluation: {
      ...commonBody(params, params.prior.body.action.action_id).evaluation,
      reason_code: `resolution_${params.method}`,
    }, resolution: { resolves_receipt_hash: params.prior.receipt_hash,
      suspension_id: params.prior.body.suspension!.suspension_id, method: params.method,
      resolver_principal_id: v2Text(params.principal_id, 'resolver_principal_id'),
      resolution_source_hash: v2Hash(params.source_hash, 'resolution_source_hash'), resolved_at_ms: params.timestamp },
  };
  return checkedSign(body, params.signer, params.include_public_key);
}

export function validateDeferredChangesV2(params: {
  original_context: ActionContextV2Document; current_context: ActionContextV2Document;
  original_base: IntentV2BaseResult; current_base: IntentV2BaseResult; required_fields: string[];
}): void {
  const project = (context: ActionContextV2Document): Record<string, unknown> => ({
    agent_id: context.agent.agent_id, role: context.agent.role, privilege_scope: context.agent.privilege_scope,
    active_intents: context.agent.active_intents, action: { ...context.action }, run_id: context.run_id,
    session_id: context.session_id, thread_id: context.thread_id,
  });
  const before = project(params.original_context); const after = project(params.current_context);
  const required = new Set(params.required_fields);
  if (required.has('action.target')) {
    delete (before.action as Record<string, unknown>).target_hash;
    delete (after.action as Record<string, unknown>).target_hash;
  }
  if (required.has('active_intents')) { delete before.active_intents; delete after.active_intents; }
  if (canonicalJsonForHash(before) !== canonicalJsonForHash(after)) fail('DEFER resolution changed fields outside required_fields');
  if (required.has('policy_evaluation')) return;
  const oldBase = { ...params.original_base } as Record<string, unknown>;
  const newBase = { ...params.current_base } as Record<string, unknown>;
  for (const field of params.required_fields) if (field === 'modified_arguments_hash' || field.startsWith('approval_')) {
    delete oldBase[field]; delete newBase[field];
  }
  if (canonicalJsonForHash(oldBase) !== canonicalJsonForHash(newBase)) fail('DEFER resolution changed base result outside required_fields');
}
