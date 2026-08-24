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
    data_classifications: string[];
    requested_scopes: string[];
  };
  run_id: string;
  session_id?: string;
  thread_id?: string;
  prior_actions: PriorActionV2Input[];
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
    data_classifications: string[];
    requested_scopes: string[];
  };
  run_id: string;
  session_id?: string;
  thread_id?: string;
  prior_actions: PriorActionV2Input[];
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
    'current_action', 'run_id', 'session_id', 'thread_id', 'prior_actions'], 'action context');
  const current = record(root.current_action, 'current_action');
  exactKeys(current, ['kind', 'name', 'arguments_hash', 'target', 'target_hash',
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
