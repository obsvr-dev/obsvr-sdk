import { createHash } from 'node:crypto';
import {
  buildIntentPolicyV2,
  evaluateIntentAlignmentV2,
  type IntentAlignmentV2Result,
  type IntentPolicyV2Document,
  type IntentV2BaseResult,
} from '../policy/intent-alignment-v2.js';
import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import {
  buildActionContextV2,
  type ActionContextV2Document,
  type PriorActionV2Input,
} from './action-context-v2.js';
import {
  STRICT_IDENTIFIER_MAX_BYTES,
  STRICT_SET_MAX_ITEMS,
  boundedCanonicalText,
  compareCodePoints,
  normalizedBoundedSet,
} from './strict-canonical.js';
import {
  buildStrictEvaluationEvidenceV21,
  createTrustedDecisionReasonCodesV21,
  type StrictEvaluationEvidenceV21,
  type TrustedEvaluationEvidenceProviderV21,
} from './strict-evaluation-evidence-v2-1.js';
import {
  type StrictIdentityEvidenceV21Document,
  trustedStrictIdentityEvidenceV21Document,
} from './strict-identity-evidence-v2-1.js';
import type {
  StrictReceiptCoordinatorV21Options,
  StrictDecisionActionV21Input,
  TrustedIntentDecisionProviderV21,
} from './strict-receipt-coordinator-v2-1-types.js';
import {
  STRICT_RECEIPT_V21_PROFILE_VERSION,
  STRICT_RECEIPT_V21_SCHEMA,
  signStrictReceiptV21,
  type StrictReceiptV21Body,
  type StrictReceiptV21Envelope,
} from './strict-receipt-v2-1.js';

const HASH = /^[0-9a-f]{64}$/;
const TRUSTED_DECISIONS = new WeakSet<object>();

export class StrictReceiptCoordinatorV21Error extends Error {
  constructor(message: string) { super(message); this.name = 'StrictReceiptCoordinatorV21Error'; }
}
function fail(message: string): never { throw new StrictReceiptCoordinatorV21Error(message); }
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
export function v21Text(value: unknown, field: string): string {
  return boundedCanonicalText(value, field, STRICT_IDENTIFIER_MAX_BYTES, fail);
}
export function v21Hash(value: unknown, field: string): string {
  if (typeof value !== 'string' || !HASH.test(value)) fail(`${field} must be 64 lowercase hex characters`);
  return value;
}
export function v21Integer(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    fail(`${field} must be a nonnegative safe integer`);
  }
  return value;
}
function v21Set(value: unknown, field: string): string[] {
  return normalizedBoundedSet(value, field, STRICT_SET_MAX_ITEMS, STRICT_IDENTIFIER_MAX_BYTES, fail);
}
export function v21Clone<T>(value: T): T { return structuredClone(value); }
function canonicalHash(value: unknown): string {
  return createHash('sha256').update(canonicalJsonForHash(value)).digest('hex');
}
function safeAdd(left: number, right: number): number {
  const result = left + right;
  if (!Number.isSafeInteger(result)) fail('value exceeds safe integer range');
  return result;
}

export function createTrustedIntentDecisionProviderV21(
  evaluate: (context: ActionContextV2Document) => IntentV2BaseResult,
): TrustedIntentDecisionProviderV21 {
  if (typeof evaluate !== 'function') fail('trusted intent decision provider must be callable');
  const provider = Object.freeze({ evaluate });
  TRUSTED_DECISIONS.add(provider);
  return provider;
}

export function assertTrustedIntentDecisionProviderV21(
  provider: TrustedIntentDecisionProviderV21,
): void {
  if (!TRUSTED_DECISIONS.has(provider as object)) fail('trusted intent decision provider is required');
}

export function normalizeDecisionActionV21(input: StrictDecisionActionV21Input): StrictDecisionActionV21Input {
  const root = record(input, 'decision request');
  const allowed = ['action_id', 'active_intents', 'current_action', 'run_id'];
  if (Object.prototype.hasOwnProperty.call(root, 'thread_id')) allowed.push('thread_id');
  exact(root, allowed, 'decision request');
  const action = record(root.current_action, 'current_action');
  exact(action, ['kind', 'name', 'arguments_hash', 'target_hash',
    'data_classifications', 'requested_scopes'], 'current_action');
  const normalized: StrictDecisionActionV21Input = {
    action_id: v21Text(root.action_id, 'action_id'),
    active_intents: v21Set(root.active_intents, 'active_intents'),
    current_action: {
      kind: v21Text(action.kind, 'current_action.kind'),
      name: v21Text(action.name, 'current_action.name'),
      arguments_hash: v21Hash(action.arguments_hash, 'current_action.arguments_hash'),
      target_hash: v21Hash(action.target_hash, 'current_action.target_hash'),
      data_classifications: v21Set(action.data_classifications, 'current_action.data_classifications'),
      requested_scopes: v21Set(action.requested_scopes, 'current_action.requested_scopes'),
    },
    run_id: v21Text(root.run_id, 'run_id'),
  };
  if (Object.prototype.hasOwnProperty.call(root, 'thread_id')) {
    normalized.thread_id = v21Text(root.thread_id, 'thread_id');
  }
  return normalized;
}

export function decisionV21Fingerprint(
  input: StrictDecisionActionV21Input,
  tenantId: string,
  sessionId: string,
  policy: IntentPolicyV2Document,
): string {
  return canonicalHash({ schema: 'obsvr-strict-decision-request-v2-1',
    tenant_id: tenantId, session_id: sessionId, policy_hash: canonicalHash(policy), input });
}

export function captureIdentityV21(
  options: StrictReceiptCoordinatorV21Options,
  timestamp: number,
): StrictIdentityEvidenceV21Document {
  let input;
  try { input = options.identity_snapshot(timestamp); } catch { return fail('trusted identity snapshot failed'); }
  let trusted;
  try { trusted = options.identity_authority.issue(input); } catch { return fail('trusted identity issuance failed'); }
  try { return trustedStrictIdentityEvidenceV21Document(trusted); } catch { return fail('trusted identity evidence is invalid'); }
}

export function buildCoordinatorContextV21(
  input: StrictDecisionActionV21Input,
  identity: StrictIdentityEvidenceV21Document,
  sessionId: string,
  priorActions: PriorActionV2Input[],
): ActionContextV2Document {
  return buildActionContextV2({
    agent_id: identity.initiator.agent_ref_hash,
    active_intents: input.active_intents,
    ...(identity.initiator.role_ids.length === 0 ? {} : {
      agent_role: identity.initiator.role_ids[0],
    }),
    privilege_scope: identity.initiator.privilege_scopes,
    current_action: input.current_action,
    run_id: input.run_id,
    session_id: sessionId,
    ...(input.thread_id === undefined ? {} : { thread_id: input.thread_id }),
    prior_actions: priorActions,
  });
}

export function evaluateDecisionV21(
  context: ActionContextV2Document,
  policy: IntentPolicyV2Document,
  intentProvider: TrustedIntentDecisionProviderV21,
  evidenceProvider: TrustedEvaluationEvidenceProviderV21,
): { base_result: IntentV2BaseResult; intent: IntentAlignmentV2Result;
  evidence: StrictEvaluationEvidenceV21 } {
  assertTrustedIntentDecisionProviderV21(intentProvider);
  let baseResult;
  try { baseResult = intentProvider.evaluate(v21Clone(context)); } catch { return fail('trusted intent decision failed'); }
  const intent = evaluateIntentAlignmentV2({ context, base_result: baseResult, policy });
  const trustedReasons = createTrustedDecisionReasonCodesV21([intent.reason_code]);
  const built = buildStrictEvaluationEvidenceV21(evidenceProvider, intent.outcome, trustedReasons);
  const evidence = built.evidence;
  if (evidence.effective_policy.artifact_hash !== intent.policy_hash) {
    fail('effective policy artifact_hash does not match evaluated policy');
  }
  const active = new Set(context.agent.active_intents);
  const expectedRules = policy.intent_scopes.map((scope) => scope.intent_id)
    .filter((intentId) => active.has(intentId)).sort(compareCodePoints);
  if (canonicalJsonForHash(evidence.effective_policy.matched_rule_ids)
    !== canonicalJsonForHash(expectedRules)) {
    fail('matched_rule_ids do not match active policy intents');
  }
  if (canonicalJsonForHash(evidence.decision_reason_codes)
    !== canonicalJsonForHash([intent.reason_code])) {
    fail('decision_reason_codes do not match intent evaluation');
  }
  return { base_result: v21Clone(baseResult), intent, evidence };
}

export function signDecisionV21(params: {
  input: StrictDecisionActionV21Input;
  identity: StrictIdentityEvidenceV21Document;
  context: ActionContextV2Document;
  evaluation: StrictEvaluationEvidenceV21;
  base_result: IntentV2BaseResult;
  tenant_id: string;
  session_id: string;
  sequence: number;
  timestamp: number;
  previous_hash: string | null;
  defer_ttl_ms: number;
  signer: StrictReceiptCoordinatorV21Options['signer'];
}): StrictReceiptV21Envelope {
  const action: StrictReceiptV21Body['action'] = {
    action_id: params.input.action_id,
    kind: params.input.current_action.kind,
    name: params.input.current_action.name,
    arguments_hash: params.input.current_action.arguments_hash,
    target_hash: params.input.current_action.target_hash,
  };
  if (params.evaluation.outcome === 'MODIFY') {
    action.effective_arguments_hash = v21Hash(
      params.base_result.modified_arguments_hash, 'modified_arguments_hash',
    );
  }
  const body: StrictReceiptV21Body = {
    schema: STRICT_RECEIPT_V21_SCHEMA,
    profile_version: STRICT_RECEIPT_V21_PROFILE_VERSION,
    record_type: 'decision',
    receipt_id: `${params.session_id}:${params.sequence}`,
    tenant_id: params.tenant_id,
    session_id: params.session_id,
    sequence: params.sequence,
    timestamp_ms: params.timestamp,
    previous_receipt_hash: params.previous_hash,
    action,
    context_hash: evaluateContextHash(params.context),
    identity: params.identity,
    evaluation: params.evaluation,
    outcome: params.evaluation.outcome,
    reason_code: params.evaluation.reason_code,
    execution_authorized: params.evaluation.outcome === 'ALLOW'
      || params.evaluation.outcome === 'MODIFY',
  };
  if (params.evaluation.outcome === 'STEP_UP') {
    body.suspension = {
      suspension_id: v21Text(params.base_result.approval_request_id, 'approval_request_id'),
      type: 'approval',
      expires_at_ms: v21Integer(params.base_result.approval_expires_at_ms, 'approval_expires_at_ms'),
    };
  } else if (params.evaluation.outcome === 'DEFER') {
    body.suspension = {
      suspension_id: `defer:${canonicalHash({ session_id: params.session_id,
        sequence: params.sequence, context_hash: body.context_hash })}`,
      type: 'context',
      expires_at_ms: safeAdd(params.timestamp, params.defer_ttl_ms),
    };
  }
  return signStrictReceiptV21(body, params.signer);
}

function evaluateContextHash(context: ActionContextV2Document): string {
  return createHash('sha256').update(canonicalJsonForHash(context)).digest('hex');
}

export { buildIntentPolicyV2 };
