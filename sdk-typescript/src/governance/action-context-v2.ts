import { sha256Hex } from '../policy/decision-record.js';
import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import { AARM_OUTCOMES, type AarmOutcome } from './aarm-outcome.js';
import {
  STRICT_CONTEXT_MAX_BYTES,
  STRICT_IDENTIFIER_MAX_BYTES,
  STRICT_PRIOR_ACTIONS_MAX_ITEMS,
  STRICT_SET_MAX_ITEMS,
  STRICT_TARGET_MAX_BYTES,
  boundedCanonicalText,
  compareCodePoints,
  normalizedBoundedSet,
} from './strict-canonical.js';

export const ACTION_CONTEXT_V2_SCHEMA = 'obsvr-action-context-v2' as const;
export const ACTION_TARGET_HASH_DOMAIN = 'obsvr-action-target/1' as const;

const HASH_RE = /^[0-9a-f]{64}$/;
const OUTCOMES = new Set<string>(AARM_OUTCOMES);
const PRINCIPAL_KINDS = new Set(['human', 'service', 'agent', 'unknown']);
const AUTONOMY_LEVELS = new Set(['assistive', 'supervised', 'autonomous']);
const CONSEQUENCE_LEVELS = new Set([
  'none', 'read', 'internal_write', 'external_write', 'destructive',
]);
const APPROVAL_STATES = new Set([
  'not_required', 'required', 'approved', 'denied', 'expired',
]);
const QUOTA_STATES = new Set(['within_limit', 'near_limit', 'exceeded', 'unknown']);

export interface PriorActionV2Input {
  sequence: number;
  kind: string;
  name: string;
  outcome: AarmOutcome;
  receipt_hash: string;
  data_classifications: string[];
}

export interface ActionContextV2Input {
  agent_id: string;
  active_intents: string[];
  agent_role?: string;
  privilege_scope?: string[];
  current_action: {
    kind: string;
    name: string;
    arguments_hash: string;
    target?: string;
    target_hash?: string;
    attempt_id?: string;
    parent_attempt_id?: string;
    remediation_retry_hash?: string;
    data_classifications: string[];
    requested_scopes: string[];
  };
  run_id: string;
  session_id?: string;
  thread_id?: string;
  prior_actions: PriorActionV2Input[];
  principal?: {
    principal_id: string;
    kind: 'human' | 'service' | 'agent' | 'unknown';
    tenant_hash?: string;
    roles: string[];
  };
  execution?: {
    environment: string;
    autonomy_level: 'assistive' | 'supervised' | 'autonomous';
    consequence_level: 'none' | 'read' | 'internal_write' | 'external_write' | 'destructive';
  };
  governance?: {
    integration_id: string;
    integration_version?: string;
    coverage_claim_hash?: string;
    active_pack_hashes: string[];
    approval_state: 'not_required' | 'required' | 'approved' | 'denied' | 'expired';
    quota_state: 'within_limit' | 'near_limit' | 'exceeded' | 'unknown';
  };
}

export interface ActionContextV2Document {
  schema: typeof ACTION_CONTEXT_V2_SCHEMA;
  agent: {
    agent_id: string;
    active_intents: string[];
    role?: string;
    privilege_scope?: string[];
  };
  action: {
    kind: string;
    name: string;
    arguments_hash: string;
    target_hash?: string;
    attempt_id?: string;
    parent_attempt_id?: string;
    remediation_retry_hash?: string;
    data_classifications: string[];
    requested_scopes: string[];
  };
  run_id: string;
  session_id?: string;
  thread_id?: string;
  prior_actions: PriorActionV2Input[];
  principal?: NonNullable<ActionContextV2Input['principal']>;
  execution?: NonNullable<ActionContextV2Input['execution']>;
  governance?: NonNullable<ActionContextV2Input['governance']>;
}

export class ActionContextV2ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ActionContextV2ValidationError';
  }
}

function fail(message: string): never {
  throw new ActionContextV2ValidationError(message);
}

function record(value: unknown, field: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return fail(`${field} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, allowed: readonly string[], field: string): void {
  const allowedSet = new Set(allowed);
  const unknown = Object.keys(value).filter((key) => !allowedSet.has(key));
  if (unknown.length > 0) {
    fail(`${field} contains unsupported field: ${unknown.sort(compareCodePoints)[0]}`);
  }
}

function text(value: unknown, field: string): string {
  return boundedCanonicalText(value, field, STRICT_IDENTIFIER_MAX_BYTES, fail);
}

function optionalText(value: Record<string, unknown>, key: string, field: string): string | undefined {
  return Object.prototype.hasOwnProperty.call(value, key) ? text(value[key], field) : undefined;
}

function hash(value: unknown, field: string): string {
  if (typeof value !== 'string' || !HASH_RE.test(value)) {
    return fail(`${field} must be exactly 64 lowercase hexadecimal characters`);
  }
  return value;
}

function stringSet(value: unknown, field: string): string[] {
  return normalizedBoundedSet(
    value, field, STRICT_SET_MAX_ITEMS, STRICT_IDENTIFIER_MAX_BYTES, fail,
  );
}

function enumeration(value: unknown, allowed: Set<string>, field: string): string {
  if (typeof value !== 'string' || !allowed.has(value)) fail(`${field} is unsupported`);
  return value;
}

function principalLayer(value: unknown): NonNullable<ActionContextV2Document['principal']> {
  const layer = record(value, 'principal');
  exactKeys(layer, ['principal_id', 'kind', 'tenant_hash', 'roles'], 'principal');
  const result: NonNullable<ActionContextV2Document['principal']> = {
    principal_id: text(layer.principal_id, 'principal.principal_id'),
    kind: enumeration(layer.kind, PRINCIPAL_KINDS, 'principal.kind') as NonNullable<
      ActionContextV2Document['principal']
    >['kind'],
    roles: stringSet(layer.roles, 'principal.roles'),
  };
  if (Object.prototype.hasOwnProperty.call(layer, 'tenant_hash')) {
    result.tenant_hash = hash(layer.tenant_hash, 'principal.tenant_hash');
  }
  return result;
}

function executionLayer(value: unknown): NonNullable<ActionContextV2Document['execution']> {
  const layer = record(value, 'execution');
  exactKeys(layer, ['environment', 'autonomy_level', 'consequence_level'], 'execution');
  return {
    environment: text(layer.environment, 'execution.environment'),
    autonomy_level: enumeration(
      layer.autonomy_level, AUTONOMY_LEVELS, 'execution.autonomy_level',
    ) as NonNullable<ActionContextV2Document['execution']>['autonomy_level'],
    consequence_level: enumeration(
      layer.consequence_level, CONSEQUENCE_LEVELS, 'execution.consequence_level',
    ) as NonNullable<ActionContextV2Document['execution']>['consequence_level'],
  };
}

function governanceLayer(value: unknown): NonNullable<ActionContextV2Document['governance']> {
  const layer = record(value, 'governance');
  exactKeys(layer, ['integration_id', 'integration_version', 'coverage_claim_hash',
    'active_pack_hashes', 'approval_state', 'quota_state'], 'governance');
  const result: NonNullable<ActionContextV2Document['governance']> = {
    integration_id: text(layer.integration_id, 'governance.integration_id'),
    active_pack_hashes: stringSet(layer.active_pack_hashes, 'governance.active_pack_hashes')
      .map((value) => hash(value, 'governance.active_pack_hashes')),
    approval_state: enumeration(
      layer.approval_state, APPROVAL_STATES, 'governance.approval_state',
    ) as NonNullable<ActionContextV2Document['governance']>['approval_state'],
    quota_state: enumeration(
      layer.quota_state, QUOTA_STATES, 'governance.quota_state',
    ) as NonNullable<ActionContextV2Document['governance']>['quota_state'],
  };
  const version = optionalText(layer, 'integration_version', 'governance.integration_version');
  if (version !== undefined) result.integration_version = version;
  if (Object.prototype.hasOwnProperty.call(layer, 'coverage_claim_hash')) {
    result.coverage_claim_hash = hash(
      layer.coverage_claim_hash, 'governance.coverage_claim_hash',
    );
  }
  return result;
}

export function actionTargetHash(value: unknown): string {
  const target = boundedCanonicalText(
    value, 'current_action.target', STRICT_TARGET_MAX_BYTES, fail,
  );
  return sha256Hex(`${ACTION_TARGET_HASH_DOMAIN}\0${target}`);
}

function priorAction(value: unknown, index: number): PriorActionV2Input {
  const field = `prior_actions[${index}]`;
  const item = record(value, field);
  exactKeys(item, ['sequence', 'kind', 'name', 'outcome', 'receipt_hash',
    'data_classifications'], field);
  if (typeof item.sequence !== 'number' || !Number.isSafeInteger(item.sequence)
    || item.sequence < 0) {
    return fail(`${field}.sequence must be a nonnegative safe integer`);
  }
  if (typeof item.outcome !== 'string' || !OUTCOMES.has(item.outcome)) {
    return fail(`${field}.outcome is unsupported`);
  }
  return {
    sequence: item.sequence,
    kind: text(item.kind, `${field}.kind`),
    name: text(item.name, `${field}.name`),
    outcome: item.outcome as AarmOutcome,
    receipt_hash: hash(item.receipt_hash, `${field}.receipt_hash`),
    data_classifications: stringSet(item.data_classifications, `${field}.data_classifications`),
  };
}

/** Build a bounded context whose canonical form never contains the raw target. */
export function buildActionContextV2(input: ActionContextV2Input): ActionContextV2Document {
  const root = record(input, 'action context');
  exactKeys(root, ['agent_id', 'active_intents', 'agent_role', 'privilege_scope',
    'current_action', 'run_id', 'session_id', 'thread_id', 'prior_actions',
    'principal', 'execution', 'governance'], 'action context');
  const current = record(root.current_action, 'current_action');
  exactKeys(current, ['kind', 'name', 'arguments_hash', 'target', 'target_hash',
    'attempt_id', 'parent_attempt_id', 'remediation_retry_hash',
    'data_classifications', 'requested_scopes'], 'current_action');

  const activeIntents = stringSet(root.active_intents, 'active_intents');
  if (activeIntents.length === 0) fail('active_intents must not be empty');
  const agent: ActionContextV2Document['agent'] = {
    agent_id: text(root.agent_id, 'agent_id'), active_intents: activeIntents,
  };
  const role = optionalText(root, 'agent_role', 'agent_role');
  if (role !== undefined) agent.role = role;
  if (Object.prototype.hasOwnProperty.call(root, 'privilege_scope')) {
    agent.privilege_scope = stringSet(root.privilege_scope, 'privilege_scope');
  }

  const action: ActionContextV2Document['action'] = {
    kind: text(current.kind, 'current_action.kind'),
    name: text(current.name, 'current_action.name'),
    arguments_hash: hash(current.arguments_hash, 'current_action.arguments_hash'),
    data_classifications: stringSet(
      current.data_classifications, 'current_action.data_classifications',
    ),
    requested_scopes: stringSet(current.requested_scopes, 'current_action.requested_scopes'),
  };
  if (Object.prototype.hasOwnProperty.call(current, 'target')
    && Object.prototype.hasOwnProperty.call(current, 'target_hash')) {
    fail('current_action cannot contain target and target_hash');
  }
  if (Object.prototype.hasOwnProperty.call(current, 'target')) {
    action.target_hash = actionTargetHash(current.target);
  } else if (Object.prototype.hasOwnProperty.call(current, 'target_hash')) {
    action.target_hash = hash(current.target_hash, 'current_action.target_hash');
  }
  const attemptId = optionalText(current, 'attempt_id', 'current_action.attempt_id');
  const parentAttemptId = optionalText(
    current, 'parent_attempt_id', 'current_action.parent_attempt_id',
  );
  const hasRetryHash = Object.prototype.hasOwnProperty.call(current, 'remediation_retry_hash');
  if ((parentAttemptId === undefined) !== !hasRetryHash) {
    fail('current_action parent_attempt_id and remediation_retry_hash must appear together');
  }
  if ((parentAttemptId !== undefined || hasRetryHash) && attemptId === undefined) {
    fail('current_action retry linkage requires attempt_id');
  }
  if (attemptId !== undefined) action.attempt_id = attemptId;
  if (parentAttemptId !== undefined) {
    if (parentAttemptId === attemptId) fail('current_action retry must use a new attempt_id');
    action.parent_attempt_id = parentAttemptId;
    action.remediation_retry_hash = hash(
      current.remediation_retry_hash, 'current_action.remediation_retry_hash',
    );
  }

  if (!Array.isArray(root.prior_actions)) fail('prior_actions must be an array');
  if (root.prior_actions.length > STRICT_PRIOR_ACTIONS_MAX_ITEMS) {
    fail(`prior_actions exceeds ${STRICT_PRIOR_ACTIONS_MAX_ITEMS} items`);
  }
  const priorActions = root.prior_actions.map(priorAction);
  for (let index = 1; index < priorActions.length; index += 1) {
    if (priorActions[index].sequence <= priorActions[index - 1].sequence) {
      fail('prior_actions sequences must be strictly increasing in input order');
    }
  }

  const doc: ActionContextV2Document = {
    schema: ACTION_CONTEXT_V2_SCHEMA,
    agent,
    action,
    run_id: text(root.run_id, 'run_id'),
    prior_actions: priorActions,
  };
  const sessionId = optionalText(root, 'session_id', 'session_id');
  if (sessionId !== undefined) doc.session_id = sessionId;
  const threadId = optionalText(root, 'thread_id', 'thread_id');
  if (threadId !== undefined) doc.thread_id = threadId;
  if (Object.prototype.hasOwnProperty.call(root, 'principal')) {
    doc.principal = principalLayer(root.principal);
  }
  if (Object.prototype.hasOwnProperty.call(root, 'execution')) {
    doc.execution = executionLayer(root.execution);
  }
  if (Object.prototype.hasOwnProperty.call(root, 'governance')) {
    doc.governance = governanceLayer(root.governance);
  }
  if (Buffer.byteLength(canonicalJsonForHash(doc), 'utf8') > STRICT_CONTEXT_MAX_BYTES) {
    fail(`canonical action context exceeds ${STRICT_CONTEXT_MAX_BYTES} UTF-8 bytes`);
  }
  return doc;
}

export function canonicalizeActionContextV2(input: ActionContextV2Input): string {
  return canonicalJsonForHash(buildActionContextV2(input));
}

export function actionContextV2Hash(input: ActionContextV2Input): string {
  return sha256Hex(canonicalizeActionContextV2(input));
}
