import { sha256Hex } from './decision-record.js';
import { canonicalJsonForHash } from './tool-pinning.js';
import {
  ACTION_CONTEXT_SCHEMA,
  buildActionContext,
  type ActionContextDocument,
  type ActionContextInput,
} from '../governance/action-context.js';
import { AARM_OUTCOMES, type AarmOutcome } from '../governance/aarm-outcome.js';
import type { ActionTaken } from '../governance/action-taken.js';

export const INTENT_POLICY_SCHEMA = 'obsvr-intent-policy-v1' as const;
export const INTENT_POLICY_PROFILE_VERSION = '1.0' as const;
export const INTENT_ENGINE_VERSION = 'obsvr-intent/1' as const;
export const INTENT_EVALUATION_INPUT_SCHEMA = 'obsvr-intent-evaluation-input-v1' as const;

const HASH_RE = /^[0-9a-f]{64}$/;
const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;
const APPROVAL_FIELDS = ['approval_request_id', 'approval_action_hash',
  'approval_expires_at_ms'] as const;
const OUTCOMES = new Set<string>(AARM_OUTCOMES);
const ACTION_TAKEN = new Set<string>([
  'allowed',
  'blocked',
  'redacted',
  'not_evaluated',
  'hook_error',
  'hook_timeout',
]);

export interface IntentActionPair {
  kind: string;
  name: string;
}

export interface IntentScopeInput {
  intent_id: string;
  allowed_actions: IntentActionPair[];
  allowed_targets: string[];
  allowed_requested_scopes: string[];
  allowed_data_classifications: string[];
  deny_after_outcomes?: AarmOutcome[];
  max_prior_actions?: number;
}

export interface IntentPolicyInput {
  schema: typeof INTENT_POLICY_SCHEMA;
  profile_version: typeof INTENT_POLICY_PROFILE_VERSION;
  intent_scopes: IntentScopeInput[];
}

export interface IntentPolicyDocument extends IntentPolicyInput {}
export interface IntentBaseResult {
  action_taken: ActionTaken;
  approval_required?: boolean;
  approval_request_id?: string;
  approval_action_hash?: string;
  approval_expires_at_ms?: number;
  modified_arguments_hash?: string;
}

export interface IntentAlignmentResult {
  outcome: AarmOutcome;
  reason_code: string;
  prevents_original_action: boolean;
  engine_version: typeof INTENT_ENGINE_VERSION;
  context_hash: string;
  policy_hash: string;
  input_hash: string;
  evaluator_hash: string;
  required_fields?: string[];
}

export class IntentAlignmentValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'IntentAlignmentValidationError';
  }
}

function record(value: unknown, field: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new IntentAlignmentValidationError(`${field} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
  field: string,
): void {
  const allowedSet = new Set(allowed);
  const unknown = Object.keys(value).filter((key) => !allowedSet.has(key)).sort();
  if (unknown.length > 0) {
    throw new IntentAlignmentValidationError(
      `${field} contains unsupported field: ${unknown[0]}`,
    );
  }
}

function nonblank(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new IntentAlignmentValidationError(`${field} must be a nonblank string`);
  }
  return value;
}

function compareUnicodeScalars(left: string, right: string): number {
  const a = Array.from(left, (char) => char.codePointAt(0) as number);
  const b = Array.from(right, (char) => char.codePointAt(0) as number);
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

function normalizedSet(value: unknown, field: string): string[] {
  if (!Array.isArray(value)) {
    throw new IntentAlignmentValidationError(`${field} must be an array`);
  }
  const values = value.map((item, index) => nonblank(item, `${field}[${index}]`));
  values.sort(compareUnicodeScalars);
  return values.filter((item, index) => index === 0 || item !== values[index - 1]);
}

function normalizedOutcomes(value: unknown, field: string): AarmOutcome[] {
  const values = normalizedSet(value, field);
  for (const value_ of values) {
    if (!OUTCOMES.has(value_)) {
      throw new IntentAlignmentValidationError(`${field} contains unsupported outcome`);
    }
  }
  return values as AarmOutcome[];
}

function actionPair(value: unknown, field: string): IntentActionPair {
  const item = record(value, field);
  exactKeys(item, ['kind', 'name'], field);
  return {
    kind: nonblank(item.kind, `${field}.kind`),
    name: nonblank(item.name, `${field}.name`),
  };
}

function normalizedActions(value: unknown, field: string): IntentActionPair[] {
  if (!Array.isArray(value)) {
    throw new IntentAlignmentValidationError(`${field} must be an array`);
  }
  const pairs = value.map((item, index) => actionPair(item, `${field}[${index}]`));
  pairs.sort((left, right) => {
    const kind = compareUnicodeScalars(left.kind, right.kind);
    return kind === 0 ? compareUnicodeScalars(left.name, right.name) : kind;
  });
  return pairs.filter(
    (item, index) => index === 0
      || item.kind !== pairs[index - 1].kind
      || item.name !== pairs[index - 1].name,
  );
}

function intentScope(value: unknown, index: number): IntentScopeInput {
  const field = `intent_scopes[${index}]`;
  const item = record(value, field);
  exactKeys(
    item,
    [
      'intent_id',
      'allowed_actions',
      'allowed_targets',
      'allowed_requested_scopes',
      'allowed_data_classifications',
      'deny_after_outcomes',
      'max_prior_actions',
    ],
    field,
  );
  const scope: IntentScopeInput = {
    intent_id: nonblank(item.intent_id, `${field}.intent_id`),
    allowed_actions: normalizedActions(item.allowed_actions, `${field}.allowed_actions`),
    allowed_targets: normalizedSet(item.allowed_targets, `${field}.allowed_targets`),
    allowed_requested_scopes: normalizedSet(
      item.allowed_requested_scopes,
      `${field}.allowed_requested_scopes`,
    ),
    allowed_data_classifications: normalizedSet(
      item.allowed_data_classifications,
      `${field}.allowed_data_classifications`,
    ),
  };
  if (Object.prototype.hasOwnProperty.call(item, 'deny_after_outcomes')) {
    scope.deny_after_outcomes = normalizedOutcomes(
      item.deny_after_outcomes,
      `${field}.deny_after_outcomes`,
    );
  }
  if (Object.prototype.hasOwnProperty.call(item, 'max_prior_actions')) {
    const max = item.max_prior_actions;
    if (typeof max !== 'number' || !Number.isSafeInteger(max) || max < 0) {
      throw new IntentAlignmentValidationError(
        `${field}.max_prior_actions must be a nonnegative safe integer`,
      );
    }
    scope.max_prior_actions = max;
  }
  return scope;
}

export function buildIntentPolicy(input: IntentPolicyInput): IntentPolicyDocument {
  const root = record(input, 'intent policy');
  exactKeys(root, ['schema', 'profile_version', 'intent_scopes'], 'intent policy');
  if (root.schema !== INTENT_POLICY_SCHEMA) {
    throw new IntentAlignmentValidationError(`schema must be ${INTENT_POLICY_SCHEMA}`);
  }
  if (root.profile_version !== INTENT_POLICY_PROFILE_VERSION) {
    throw new IntentAlignmentValidationError(
      `profile_version must be ${INTENT_POLICY_PROFILE_VERSION}`,
    );
  }
  if (!Array.isArray(root.intent_scopes)) {
    throw new IntentAlignmentValidationError('intent_scopes must be an array');
  }
  const scopes = root.intent_scopes.map(intentScope);
  const seen = new Set<string>();
  for (const scope of scopes) {
    if (seen.has(scope.intent_id)) {
      throw new IntentAlignmentValidationError(`duplicate intent_id: ${scope.intent_id}`);
    }
    seen.add(scope.intent_id);
  }
  scopes.sort((left, right) => compareUnicodeScalars(left.intent_id, right.intent_id));
  return {
    schema: INTENT_POLICY_SCHEMA,
    profile_version: INTENT_POLICY_PROFILE_VERSION,
    intent_scopes: scopes,
  };
}

export function canonicalizeIntentPolicy(input: IntentPolicyInput): string {
  return canonicalJsonForHash(buildIntentPolicy(input));
}

export function intentPolicyHash(input: IntentPolicyInput): string {
  return sha256Hex(canonicalizeIntentPolicy(input));
}

function inputFromDocument(value: unknown): ActionContextInput {
  const root = record(value, 'action context document');
  exactKeys(
    root,
    ['schema', 'agent', 'action', 'run_id', 'session_id', 'thread_id', 'prior_actions'],
    'action context document',
  );
  if (root.schema !== ACTION_CONTEXT_SCHEMA) {
    throw new IntentAlignmentValidationError(`context schema must be ${ACTION_CONTEXT_SCHEMA}`);
  }
  const agent = record(root.agent, 'action context document.agent');
  exactKeys(
    agent,
    ['agent_id', 'active_intents', 'role', 'privilege_scope'],
    'action context document.agent',
  );
  const action = record(root.action, 'action context document.action');
  exactKeys(
    action,
    [
      'kind',
      'name',
      'arguments_hash',
      'target',
      'data_classifications',
      'requested_scopes',
    ],
    'action context document.action',
  );
  const input: Record<string, unknown> = {
    agent_id: agent.agent_id,
    active_intents: agent.active_intents,
    current_action: action,
    run_id: root.run_id,
    prior_actions: root.prior_actions,
  };
  if (Object.prototype.hasOwnProperty.call(agent, 'role')) input.agent_role = agent.role;
  if (Object.prototype.hasOwnProperty.call(agent, 'privilege_scope')) {
    input.privilege_scope = agent.privilege_scope;
  }
  if (Object.prototype.hasOwnProperty.call(root, 'session_id')) input.session_id = root.session_id;
  if (Object.prototype.hasOwnProperty.call(root, 'thread_id')) input.thread_id = root.thread_id;
  return input as unknown as ActionContextInput;
}

function normalizedContext(value: ActionContextInput | ActionContextDocument): ActionContextDocument {
  const raw = record(value, 'action context');
  return buildActionContext(
    Object.prototype.hasOwnProperty.call(raw, 'schema')
      ? inputFromDocument(raw)
      : value as ActionContextInput,
  );
}

function normalizedBaseResult(value: IntentBaseResult): IntentBaseResult {
  const base = record(value, 'base result');
  exactKeys(
    base,
    [
      'action_taken', 'approval_required', 'approval_request_id',
      'approval_action_hash', 'approval_expires_at_ms', 'modified_arguments_hash',
    ],
    'base result',
  );
  if (typeof base.action_taken !== 'string' || !ACTION_TAKEN.has(base.action_taken)) {
    throw new IntentAlignmentValidationError('base result action_taken is unsupported');
  }
  if (
    Object.prototype.hasOwnProperty.call(base, 'approval_required')
    && typeof base.approval_required !== 'boolean'
  ) {
    throw new IntentAlignmentValidationError('approval_required must be a boolean');
  }
  if (base.approval_required === true && base.action_taken !== 'blocked') {
    throw new IntentAlignmentValidationError('approval_required is valid only when blocked');
  }
  if (APPROVAL_FIELDS.some((field) => Object.prototype.hasOwnProperty.call(base, field))
    && (base.action_taken !== 'blocked' || base.approval_required !== true)) {
    throw new IntentAlignmentValidationError(
      'approval binding fields are valid only when blocked with approval_required',
    );
  }
  if (Object.prototype.hasOwnProperty.call(base, 'approval_request_id')) {
    nonblank(base.approval_request_id, 'approval_request_id');
  }
  if (Object.prototype.hasOwnProperty.call(base, 'approval_action_hash')
    && (typeof base.approval_action_hash !== 'string'
      || !HASH_RE.test(base.approval_action_hash))) {
    throw new IntentAlignmentValidationError(
      'approval_action_hash must be 64 lowercase hex characters',
    );
  }
  if (Object.prototype.hasOwnProperty.call(base, 'approval_expires_at_ms')
    && (typeof base.approval_expires_at_ms !== 'number'
      || !Number.isSafeInteger(base.approval_expires_at_ms)
      || base.approval_expires_at_ms < 0)) {
    throw new IntentAlignmentValidationError(
      'approval_expires_at_ms must be a nonnegative safe integer',
    );
  }
  if (
    Object.prototype.hasOwnProperty.call(base, 'modified_arguments_hash')
    && typeof base.modified_arguments_hash !== 'string'
  ) {
    throw new IntentAlignmentValidationError('modified_arguments_hash must be a string');
  }
  if (
    Object.prototype.hasOwnProperty.call(base, 'modified_arguments_hash')
    && base.action_taken !== 'redacted'
  ) {
    throw new IntentAlignmentValidationError(
      'modified_arguments_hash is valid only when redacted',
    );
  }
  const result: IntentBaseResult = { action_taken: base.action_taken as ActionTaken };
  if (base.approval_required === true) result.approval_required = true;
  if (typeof base.approval_request_id === 'string') {
    result.approval_request_id = base.approval_request_id;
  }
  if (typeof base.approval_action_hash === 'string') {
    result.approval_action_hash = base.approval_action_hash;
  }
  if (typeof base.approval_expires_at_ms === 'number') {
    result.approval_expires_at_ms = base.approval_expires_at_ms;
  }
  if (typeof base.modified_arguments_hash === 'string') {
    result.modified_arguments_hash = base.modified_arguments_hash;
  }
  return result;
}

function subset(values: readonly string[], allowed: readonly string[]): boolean {
  const allowedSet = new Set(allowed);
  return values.every((value) => allowedSet.has(value));
}

function result(
  outcome: AarmOutcome,
  reasonCode: string,
  hashes: Omit<IntentAlignmentResult, 'outcome' | 'reason_code' | 'prevents_original_action'>,
  requiredFields?: string[],
): IntentAlignmentResult {
  const output: IntentAlignmentResult = {
    outcome,
    reason_code: reasonCode,
    prevents_original_action: outcome !== 'ALLOW',
    ...hashes,
  };
  if (outcome === 'DEFER') {
    if (!requiredFields || requiredFields.length === 0) {
      throw new IntentAlignmentValidationError('DEFER requires required_fields');
    }
    output.required_fields = [...requiredFields].sort(compareUnicodeScalars);
  }
  return output;
}

export function evaluateIntentAlignment(params: {
  context: ActionContextInput | ActionContextDocument;
  base_result: IntentBaseResult;
  policy: IntentPolicyInput;
}): IntentAlignmentResult {
  const context = normalizedContext(params.context);
  const policy = buildIntentPolicy(params.policy);
  const base = normalizedBaseResult(params.base_result);
  const contextHash = sha256Hex(canonicalJsonForHash(context));
  const policyHash = sha256Hex(canonicalJsonForHash(policy));
  const evaluationInput = {
    schema: INTENT_EVALUATION_INPUT_SCHEMA,
    base_result: base,
    context_hash: contextHash,
    policy_hash: policyHash,
  };
  const inputHash = sha256Hex(canonicalJsonForHash(evaluationInput));
  const evaluatorHash = sha256Hex(canonicalJsonForHash({
    engine_version: INTENT_ENGINE_VERSION,
    policy_hash: policyHash,
  }));
  const hashes = {
    engine_version: INTENT_ENGINE_VERSION,
    context_hash: contextHash,
    policy_hash: policyHash,
    input_hash: inputHash,
    evaluator_hash: evaluatorHash,
  };

  if (base.action_taken === 'blocked' && base.approval_required !== true) {
    return result('DENY', 'base_blocked', hashes);
  }
  if (base.action_taken === 'hook_error') return result('DEFER', 'base_hook_error', hashes, ['policy_evaluation']);
  if (base.action_taken === 'hook_timeout') return result('DEFER', 'base_hook_timeout', hashes, ['policy_evaluation']);
  if (base.action_taken === 'not_evaluated') {
    return result('DEFER', 'base_not_evaluated', hashes, ['policy_evaluation']);
  }
  if (context.agent.active_intents.length > 1) {
    return result('DEFER', 'multiple_active_intents', hashes, ['active_intents']);
  }
  const scope = policy.intent_scopes.find(
    (candidate) => candidate.intent_id === context.agent.active_intents[0],
  );
  if (scope === undefined) return result('DEFER', 'intent_not_declared', hashes, ['intent_policy']);
  if (!scope.allowed_actions.some(
    (action) => action.kind === context.action.kind && action.name === context.action.name,
  )) {
    return result('DENY', 'action_not_allowed', hashes);
  }
  if (context.action.target === undefined && scope.allowed_targets.length > 0) {
    return result('DEFER', 'target_missing', hashes, ['action.target']);
  }
  if (context.action.target !== undefined && !scope.allowed_targets.includes(context.action.target)) {
    return result('DENY', 'target_not_allowed', hashes);
  }
  if (!subset(context.action.requested_scopes, scope.allowed_requested_scopes)) {
    return result('DENY', 'requested_scope_not_allowed', hashes);
  }
  if (!subset(context.action.data_classifications, scope.allowed_data_classifications)) {
    return result('DENY', 'data_classification_not_allowed', hashes);
  }
  if (!subset(context.action.requested_scopes, context.agent.privilege_scope ?? [])) {
    return result('DENY', 'requested_scope_not_privileged', hashes);
  }
  const deniedPrior = new Set(scope.deny_after_outcomes ?? []);
  if (context.prior_actions.some((action) => deniedPrior.has(action.outcome))) {
    return result('DENY', 'prior_outcome_denied', hashes);
  }
  if (
    scope.max_prior_actions !== undefined
    && context.prior_actions.length > scope.max_prior_actions
  ) {
    return result('DENY', 'prior_action_limit_exceeded', hashes);
  }
  if (base.action_taken === 'blocked' && base.approval_required === true) {
    const missing = APPROVAL_FIELDS.filter(
      (field) => !Object.prototype.hasOwnProperty.call(base, field),
    );
    if (missing.length > 0) {
      return result('DEFER', 'approval_binding_missing', hashes, missing);
    }
    return result('STEP_UP', 'approval_required', hashes);
  }
  if (base.action_taken === 'redacted') {
    const modified = base.modified_arguments_hash;
    if (
      modified === undefined
      || !HASH_RE.test(modified)
      || modified === context.action.arguments_hash
    ) {
      return result('DEFER', 'modified_arguments_hash_unproven', hashes, ['modified_arguments_hash']);
    }
    return result('MODIFY', 'arguments_modified', hashes);
  }
  return result('ALLOW', 'intent_aligned', hashes);
}
