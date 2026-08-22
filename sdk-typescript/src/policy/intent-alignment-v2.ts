import { sha256Hex } from './decision-record.js';
import { canonicalJsonForHash } from './tool-pinning.js';
import {
  ACTION_CONTEXT_V2_SCHEMA,
  actionTargetHash,
  buildActionContextV2,
  type ActionContextV2Document,
  type ActionContextV2Input,
} from '../governance/action-context-v2.js';
import { AARM_OUTCOMES, type AarmOutcome } from '../governance/aarm-outcome.js';
import type { ActionTaken } from '../governance/action-taken.js';
import {
  STRICT_IDENTIFIER_MAX_BYTES,
  STRICT_SET_MAX_ITEMS,
  STRICT_TARGET_MAX_BYTES,
  boundedCanonicalText,
  compareCodePoints,
  normalizedBoundedSet,
} from '../governance/strict-canonical.js';

export const INTENT_POLICY_V2_SCHEMA = 'obsvr-intent-policy-v2' as const;
export const INTENT_POLICY_V2_PROFILE_VERSION = '2.0' as const;
export const INTENT_V2_ENGINE_VERSION = 'obsvr-intent/2' as const;
export const INTENT_V2_EVALUATION_INPUT_SCHEMA = 'obsvr-intent-evaluation-input-v2' as const;

const HASH_RE = /^[0-9a-f]{64}$/;
const OUTCOMES = new Set<string>(AARM_OUTCOMES);
const ACTION_TAKEN = new Set<string>([
  'allowed', 'blocked', 'redacted', 'not_evaluated', 'hook_error', 'hook_timeout',
]);
const APPROVAL_FIELDS = ['approval_request_id', 'approval_action_hash',
  'approval_expires_at_ms'] as const;

export interface IntentActionV2Pair { kind: string; name: string }
export interface IntentScopeV2Input {
  intent_id: string;
  allowed_actions: IntentActionV2Pair[];
  allowed_targets: string[];
  allowed_requested_scopes: string[];
  allowed_data_classifications: string[];
  deny_after_outcomes?: AarmOutcome[];
  max_prior_actions?: number;
}
export interface IntentPolicyV2Input {
  schema: typeof INTENT_POLICY_V2_SCHEMA;
  profile_version: typeof INTENT_POLICY_V2_PROFILE_VERSION;
  intent_scopes: IntentScopeV2Input[];
}
export interface IntentScopeV2Document extends Omit<IntentScopeV2Input, 'allowed_targets'> {
  allowed_target_hashes: string[];
}
export interface IntentPolicyV2Document {
  schema: typeof INTENT_POLICY_V2_SCHEMA;
  profile_version: typeof INTENT_POLICY_V2_PROFILE_VERSION;
  intent_scopes: IntentScopeV2Document[];
}
export interface IntentV2BaseResult {
  action_taken: ActionTaken;
  approval_required?: boolean;
  approval_request_id?: string;
  approval_action_hash?: string;
  approval_expires_at_ms?: number;
  modified_arguments_hash?: string;
}
export interface IntentAlignmentV2Result {
  outcome: AarmOutcome;
  reason_code: string;
  prevents_original_action: boolean;
  engine_version: typeof INTENT_V2_ENGINE_VERSION;
  context_hash: string;
  policy_hash: string;
  input_hash: string;
  evaluator_hash: string;
  required_fields?: string[];
}

export class IntentAlignmentV2ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'IntentAlignmentV2ValidationError';
  }
}

function fail(message: string): never { throw new IntentAlignmentV2ValidationError(message); }
function record(value: unknown, field: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return fail(`${field} must be an object`);
  }
  return value as Record<string, unknown>;
}
function exactKeys(value: Record<string, unknown>, allowed: readonly string[], field: string): void {
  const known = new Set(allowed);
  const unknown = Object.keys(value).filter((key) => !known.has(key)).sort(compareCodePoints);
  if (unknown.length) fail(`${field} contains unsupported field: ${unknown[0]}`);
}
function text(value: unknown, field: string): string {
  return boundedCanonicalText(value, field, STRICT_IDENTIFIER_MAX_BYTES, fail);
}
function hash(value: unknown, field: string): string {
  if (typeof value !== 'string' || !HASH_RE.test(value)) {
    return fail(`${field} must be 64 lowercase hex characters`);
  }
  return value;
}
function stringSet(value: unknown, field: string): string[] {
  return normalizedBoundedSet(
    value, field, STRICT_SET_MAX_ITEMS, STRICT_IDENTIFIER_MAX_BYTES, fail,
  );
}
function hashSet(value: unknown, field: string): string[] {
  if (!Array.isArray(value)) return fail(`${field} must be an array`);
  if (value.length > STRICT_SET_MAX_ITEMS) return fail(`${field} exceeds ${STRICT_SET_MAX_ITEMS} items`);
  return [...new Set(value.map((item, index) => hash(item, `${field}[${index}]`)))].sort();
}
function outcomeSet(value: unknown, field: string): AarmOutcome[] {
  const values = stringSet(value, field);
  if (values.some((item) => !OUTCOMES.has(item))) fail(`${field} contains unsupported outcome`);
  return values as AarmOutcome[];
}
function actionPair(value: unknown, field: string): IntentActionV2Pair {
  const pair = record(value, field);
  exactKeys(pair, ['kind', 'name'], field);
  return { kind: text(pair.kind, `${field}.kind`), name: text(pair.name, `${field}.name`) };
}
function actionSet(value: unknown, field: string): IntentActionV2Pair[] {
  if (!Array.isArray(value)) return fail(`${field} must be an array`);
  if (value.length > STRICT_SET_MAX_ITEMS) return fail(`${field} exceeds ${STRICT_SET_MAX_ITEMS} items`);
  const pairs = value.map((item, index) => actionPair(item, `${field}[${index}]`));
  pairs.sort((left, right) => compareCodePoints(left.kind, right.kind)
    || compareCodePoints(left.name, right.name));
  return pairs.filter((pair, index) => index === 0
    || pair.kind !== pairs[index - 1].kind || pair.name !== pairs[index - 1].name);
}

function intentScope(value: unknown, index: number): IntentScopeV2Document {
  const field = `intent_scopes[${index}]`;
  const item = record(value, field);
  exactKeys(item, ['intent_id', 'allowed_actions', 'allowed_targets', 'allowed_target_hashes',
    'allowed_requested_scopes', 'allowed_data_classifications', 'deny_after_outcomes',
    'max_prior_actions'], field);
  const rawTargets = Object.prototype.hasOwnProperty.call(item, 'allowed_targets');
  const hashedTargets = Object.prototype.hasOwnProperty.call(item, 'allowed_target_hashes');
  if (rawTargets === hashedTargets) {
    return fail(`${field} must contain exactly one target representation`);
  }
  let allowedTargetHashes: string[];
  if (rawTargets) {
    if (!Array.isArray(item.allowed_targets)) return fail(`${field}.allowed_targets must be an array`);
    if (item.allowed_targets.length > STRICT_SET_MAX_ITEMS) {
      return fail(`${field}.allowed_targets exceeds ${STRICT_SET_MAX_ITEMS} items`);
    }
    allowedTargetHashes = [...new Set(item.allowed_targets.map(
      (target, targetIndex) => actionTargetHash(
        boundedCanonicalText(
          target,
          `${field}.allowed_targets[${targetIndex}]`,
          STRICT_TARGET_MAX_BYTES,
          fail,
        ),
      ),
    ))].sort();
  } else {
    allowedTargetHashes = hashSet(item.allowed_target_hashes, `${field}.allowed_target_hashes`);
  }
  const scope: IntentScopeV2Document = {
    intent_id: text(item.intent_id, `${field}.intent_id`),
    allowed_actions: actionSet(item.allowed_actions, `${field}.allowed_actions`),
    allowed_target_hashes: allowedTargetHashes,
    allowed_requested_scopes: stringSet(
      item.allowed_requested_scopes, `${field}.allowed_requested_scopes`,
    ),
    allowed_data_classifications: stringSet(
      item.allowed_data_classifications, `${field}.allowed_data_classifications`,
    ),
  };
  if (Object.prototype.hasOwnProperty.call(item, 'deny_after_outcomes')) {
    scope.deny_after_outcomes = outcomeSet(item.deny_after_outcomes, `${field}.deny_after_outcomes`);
  }
  if (Object.prototype.hasOwnProperty.call(item, 'max_prior_actions')) {
    const maximum = item.max_prior_actions;
    if (typeof maximum !== 'number' || !Number.isSafeInteger(maximum) || maximum < 0) {
      return fail(`${field}.max_prior_actions must be a nonnegative safe integer`);
    }
    scope.max_prior_actions = maximum;
  }
  return scope;
}

export function buildIntentPolicyV2(
  input: IntentPolicyV2Input | IntentPolicyV2Document,
): IntentPolicyV2Document {
  const root = record(input, 'intent policy');
  exactKeys(root, ['schema', 'profile_version', 'intent_scopes'], 'intent policy');
  if (root.schema !== INTENT_POLICY_V2_SCHEMA) fail(`schema must be ${INTENT_POLICY_V2_SCHEMA}`);
  if (root.profile_version !== INTENT_POLICY_V2_PROFILE_VERSION) {
    fail(`profile_version must be ${INTENT_POLICY_V2_PROFILE_VERSION}`);
  }
  if (!Array.isArray(root.intent_scopes)) fail('intent_scopes must be an array');
  if (root.intent_scopes.length > STRICT_SET_MAX_ITEMS) {
    fail(`intent_scopes exceeds ${STRICT_SET_MAX_ITEMS} items`);
  }
  const scopes = root.intent_scopes.map(intentScope);
  const seen = new Set<string>();
  for (const scope of scopes) {
    if (seen.has(scope.intent_id)) fail(`duplicate intent_id: ${scope.intent_id}`);
    seen.add(scope.intent_id);
  }
  scopes.sort((left, right) => compareCodePoints(left.intent_id, right.intent_id));
  return {
    schema: INTENT_POLICY_V2_SCHEMA,
    profile_version: INTENT_POLICY_V2_PROFILE_VERSION,
    intent_scopes: scopes,
  };
}

export function canonicalizeIntentPolicyV2(input: IntentPolicyV2Input): string {
  return canonicalJsonForHash(buildIntentPolicyV2(input));
}
export function intentPolicyV2Hash(input: IntentPolicyV2Input): string {
  return sha256Hex(canonicalizeIntentPolicyV2(input));
}

function contextInput(value: ActionContextV2Document): ActionContextV2Input {
  return {
    agent_id: value.agent.agent_id,
    active_intents: value.agent.active_intents,
    ...(value.agent.role === undefined ? {} : { agent_role: value.agent.role }),
    ...(value.agent.privilege_scope === undefined ? {} : {
      privilege_scope: value.agent.privilege_scope,
    }),
    current_action: value.action,
    run_id: value.run_id,
    ...(value.session_id === undefined ? {} : { session_id: value.session_id }),
    ...(value.thread_id === undefined ? {} : { thread_id: value.thread_id }),
    prior_actions: value.prior_actions,
  };
}
function normalizedContext(
  value: ActionContextV2Input | ActionContextV2Document,
): ActionContextV2Document {
  const raw = record(value, 'action context');
  if (Object.prototype.hasOwnProperty.call(raw, 'schema')) {
    if (raw.schema !== ACTION_CONTEXT_V2_SCHEMA) fail(`context schema must be ${ACTION_CONTEXT_V2_SCHEMA}`);
    return buildActionContextV2(contextInput(value as ActionContextV2Document));
  }
  return buildActionContextV2(value as ActionContextV2Input);
}

function normalizedBase(value: IntentV2BaseResult): IntentV2BaseResult {
  const base = record(value, 'base result');
  exactKeys(base, ['action_taken', 'approval_required', 'approval_request_id',
    'approval_action_hash', 'approval_expires_at_ms', 'modified_arguments_hash'], 'base result');
  if (typeof base.action_taken !== 'string' || !ACTION_TAKEN.has(base.action_taken)) {
    return fail('base result action_taken is unsupported');
  }
  if (Object.prototype.hasOwnProperty.call(base, 'approval_required')
    && typeof base.approval_required !== 'boolean') fail('approval_required must be a boolean');
  if (base.approval_required === true && base.action_taken !== 'blocked') {
    fail('approval_required is valid only when blocked');
  }
  if (APPROVAL_FIELDS.some((field) => Object.prototype.hasOwnProperty.call(base, field))
    && (base.action_taken !== 'blocked' || base.approval_required !== true)) {
    fail('approval binding fields are valid only when blocked with approval_required');
  }
  if (Object.prototype.hasOwnProperty.call(base, 'approval_request_id')) {
    text(base.approval_request_id, 'approval_request_id');
  }
  if (Object.prototype.hasOwnProperty.call(base, 'approval_action_hash')) {
    hash(base.approval_action_hash, 'approval_action_hash');
  }
  if (Object.prototype.hasOwnProperty.call(base, 'approval_expires_at_ms')
    && (typeof base.approval_expires_at_ms !== 'number'
      || !Number.isSafeInteger(base.approval_expires_at_ms)
      || base.approval_expires_at_ms < 0)) {
    fail('approval_expires_at_ms must be a nonnegative safe integer');
  }
  if (Object.prototype.hasOwnProperty.call(base, 'modified_arguments_hash')
    && typeof base.modified_arguments_hash !== 'string') fail('modified_arguments_hash must be a string');
  if (Object.prototype.hasOwnProperty.call(base, 'modified_arguments_hash')
    && base.action_taken !== 'redacted') fail('modified_arguments_hash is valid only when redacted');
  const output: IntentV2BaseResult = { action_taken: base.action_taken as ActionTaken };
  if (base.approval_required === true) output.approval_required = true;
  if (typeof base.approval_request_id === 'string') output.approval_request_id = base.approval_request_id;
  if (typeof base.approval_action_hash === 'string') output.approval_action_hash = base.approval_action_hash;
  if (typeof base.approval_expires_at_ms === 'number') output.approval_expires_at_ms = base.approval_expires_at_ms;
  if (typeof base.modified_arguments_hash === 'string') output.modified_arguments_hash = base.modified_arguments_hash;
  return output;
}

function subset(values: readonly string[], allowed: readonly string[]): boolean {
  const allowedSet = new Set(allowed);
  return values.every((value) => allowedSet.has(value));
}
function result(
  outcome: AarmOutcome,
  reasonCode: string,
  hashes: Omit<IntentAlignmentV2Result, 'outcome' | 'reason_code' | 'prevents_original_action'>,
  requiredFields?: string[],
): IntentAlignmentV2Result {
  const output: IntentAlignmentV2Result = {
    outcome, reason_code: reasonCode, prevents_original_action: outcome !== 'ALLOW', ...hashes,
  };
  if (outcome === 'DEFER') {
    if (!requiredFields?.length) fail('DEFER requires required_fields');
    output.required_fields = [...new Set(requiredFields)].sort(compareCodePoints);
  }
  return output;
}

export function evaluateIntentAlignmentV2(params: {
  context: ActionContextV2Input | ActionContextV2Document;
  base_result: IntentV2BaseResult;
  policy: IntentPolicyV2Input | IntentPolicyV2Document;
}): IntentAlignmentV2Result {
  const context = normalizedContext(params.context);
  const policy = buildIntentPolicyV2(params.policy);
  const base = normalizedBase(params.base_result);
  const contextHash = sha256Hex(canonicalJsonForHash(context));
  const policyHash = sha256Hex(canonicalJsonForHash(policy));
  const inputHash = sha256Hex(canonicalJsonForHash({
    schema: INTENT_V2_EVALUATION_INPUT_SCHEMA,
    base_result: base,
    context_hash: contextHash,
    policy_hash: policyHash,
  }));
  const evaluatorHash = sha256Hex(canonicalJsonForHash({
    engine_version: INTENT_V2_ENGINE_VERSION, policy_hash: policyHash,
  }));
  const hashes = {
    engine_version: INTENT_V2_ENGINE_VERSION,
    context_hash: contextHash, policy_hash: policyHash,
    input_hash: inputHash, evaluator_hash: evaluatorHash,
  };

  if (base.action_taken === 'blocked' && base.approval_required !== true) return result('DENY', 'base_blocked', hashes);
  if (base.action_taken === 'hook_error') return result('DEFER', 'base_hook_error', hashes, ['policy_evaluation']);
  if (base.action_taken === 'hook_timeout') return result('DEFER', 'base_hook_timeout', hashes, ['policy_evaluation']);
  if (base.action_taken === 'not_evaluated') return result('DEFER', 'base_not_evaluated', hashes, ['policy_evaluation']);
  if (context.agent.active_intents.length > 1) return result('DEFER', 'multiple_active_intents', hashes, ['active_intents']);
  const scope = policy.intent_scopes.find(
    (candidate) => candidate.intent_id === context.agent.active_intents[0],
  );
  if (!scope) return result('DEFER', 'intent_not_declared', hashes, ['intent_policy']);
  if (!scope.allowed_actions.some(
    (action) => action.kind === context.action.kind && action.name === context.action.name,
  )) return result('DENY', 'action_not_allowed', hashes);
  if (context.action.target_hash === undefined && scope.allowed_target_hashes.length > 0) {
    return result('DEFER', 'target_missing', hashes, ['action.target']);
  }
  if (context.action.target_hash !== undefined
    && !scope.allowed_target_hashes.includes(context.action.target_hash)) {
    return result('DENY', 'target_not_allowed', hashes);
  }
  if (!subset(context.action.requested_scopes, scope.allowed_requested_scopes)) return result('DENY', 'requested_scope_not_allowed', hashes);
  if (!subset(context.action.data_classifications, scope.allowed_data_classifications)) return result('DENY', 'data_classification_not_allowed', hashes);
  if (!subset(context.action.requested_scopes, context.agent.privilege_scope ?? [])) return result('DENY', 'requested_scope_not_privileged', hashes);
  const deniedPrior = new Set(scope.deny_after_outcomes ?? []);
  if (context.prior_actions.some((action) => deniedPrior.has(action.outcome))) return result('DENY', 'prior_outcome_denied', hashes);
  if (scope.max_prior_actions !== undefined
    && context.prior_actions.length > scope.max_prior_actions) return result('DENY', 'prior_action_limit_exceeded', hashes);
  if (base.action_taken === 'blocked' && base.approval_required === true) {
    const missing = APPROVAL_FIELDS.filter(
      (field) => !Object.prototype.hasOwnProperty.call(base, field),
    );
    return missing.length
      ? result('DEFER', 'approval_binding_missing', hashes, [...missing])
      : result('STEP_UP', 'approval_required', hashes);
  }
  if (base.action_taken === 'redacted') {
    const modified = base.modified_arguments_hash;
    if (typeof modified !== 'string' || !HASH_RE.test(modified)
      || modified === context.action.arguments_hash) {
      return result('DEFER', 'modified_arguments_hash_unproven', hashes, ['modified_arguments_hash']);
    }
    return result('MODIFY', 'arguments_modified', hashes);
  }
  return result('ALLOW', 'intent_aligned', hashes);
}
