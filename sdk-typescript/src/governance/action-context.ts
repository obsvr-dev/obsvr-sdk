import { sha256Hex } from '../policy/decision-record.js';
import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import { AARM_OUTCOMES, type AarmOutcome } from './aarm-outcome.js';

export const ACTION_CONTEXT_SCHEMA = 'obsvr-action-context-v1' as const;

const HASH_RE = /^[0-9a-f]{64}$/;
const OUTCOMES = new Set<string>(AARM_OUTCOMES);

export interface PriorActionInput {
  sequence: number;
  kind: string;
  name: string;
  outcome: AarmOutcome;
  receipt_hash: string;
  data_classifications: string[];
}

export interface ActionContextInput {
  agent_id: string;
  active_intents: string[];
  agent_role?: string;
  privilege_scope?: string[];
  current_action: {
    kind: string;
    name: string;
    arguments_hash: string;
    target?: string;
    data_classifications: string[];
    requested_scopes: string[];
  };
  run_id: string;
  session_id?: string;
  thread_id?: string;
  prior_actions: PriorActionInput[];
}

export interface ActionContextDocument {
  schema: typeof ACTION_CONTEXT_SCHEMA;
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
    target?: string;
    data_classifications: string[];
    requested_scopes: string[];
  };
  run_id: string;
  session_id?: string;
  thread_id?: string;
  prior_actions: PriorActionInput[];
}

export class ActionContextValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ActionContextValidationError';
  }
}

function record(value: unknown, field: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new ActionContextValidationError(`${field} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
  field: string,
): void {
  const allowedSet = new Set(allowed);
  const unknown = Object.keys(value).filter((key) => !allowedSet.has(key));
  if (unknown.length > 0) {
    throw new ActionContextValidationError(
      `${field} contains unsupported field: ${unknown.sort()[0]}`,
    );
  }
}

function nonblank(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new ActionContextValidationError(`${field} must be a nonblank string`);
  }
  return value;
}

function optionalNonblank(value: Record<string, unknown>, key: string, field: string): string | undefined {
  if (!Object.prototype.hasOwnProperty.call(value, key)) return undefined;
  return nonblank(value[key], field);
}

function hash(value: unknown, field: string): string {
  if (typeof value !== 'string' || !HASH_RE.test(value)) {
    throw new ActionContextValidationError(
      `${field} must be exactly 64 lowercase hexadecimal characters`,
    );
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
    throw new ActionContextValidationError(`${field} must be an array`);
  }
  const values = value.map((entry, index) => nonblank(entry, `${field}[${index}]`));
  values.sort(compareUnicodeScalars);
  return values.filter((entry, index) => index === 0 || entry !== values[index - 1]);
}

function priorAction(value: unknown, index: number): PriorActionInput {
  const item = record(value, `prior_actions[${index}]`);
  exactKeys(
    item,
    ['sequence', 'kind', 'name', 'outcome', 'receipt_hash', 'data_classifications'],
    `prior_actions[${index}]`,
  );
  if (
    typeof item.sequence !== 'number'
    || !Number.isSafeInteger(item.sequence)
    || item.sequence < 0
  ) {
    throw new ActionContextValidationError(
      `prior_actions[${index}].sequence must be a nonnegative safe integer`,
    );
  }
  if (typeof item.outcome !== 'string' || !OUTCOMES.has(item.outcome)) {
    throw new ActionContextValidationError(
      `prior_actions[${index}].outcome is unsupported`,
    );
  }
  return {
    sequence: item.sequence,
    kind: nonblank(item.kind, `prior_actions[${index}].kind`),
    name: nonblank(item.name, `prior_actions[${index}].name`),
    outcome: item.outcome as AarmOutcome,
    receipt_hash: hash(item.receipt_hash, `prior_actions[${index}].receipt_hash`),
    data_classifications: normalizedSet(
      item.data_classifications,
      `prior_actions[${index}].data_classifications`,
    ),
  };
}

/** Build the canonical context without admitting raw arguments or content. */
export function buildActionContext(input: ActionContextInput): ActionContextDocument {
  const root = record(input, 'action context');
  exactKeys(
    root,
    [
      'agent_id',
      'active_intents',
      'agent_role',
      'privilege_scope',
      'current_action',
      'run_id',
      'session_id',
      'thread_id',
      'prior_actions',
    ],
    'action context',
  );

  const current = record(root.current_action, 'current_action');
  exactKeys(
    current,
    [
      'kind',
      'name',
      'arguments_hash',
      'target',
      'data_classifications',
      'requested_scopes',
    ],
    'current_action',
  );

  const agent: ActionContextDocument['agent'] = {
    agent_id: nonblank(root.agent_id, 'agent_id'),
    active_intents: normalizedSet(root.active_intents, 'active_intents'),
  };
  if (agent.active_intents.length === 0) {
    throw new ActionContextValidationError('active_intents must not be empty');
  }
  const role = optionalNonblank(root, 'agent_role', 'agent_role');
  if (role !== undefined) agent.role = role;
  if (Object.prototype.hasOwnProperty.call(root, 'privilege_scope')) {
    agent.privilege_scope = normalizedSet(root.privilege_scope, 'privilege_scope');
  }

  const action: ActionContextDocument['action'] = {
    kind: nonblank(current.kind, 'current_action.kind'),
    name: nonblank(current.name, 'current_action.name'),
    arguments_hash: hash(current.arguments_hash, 'current_action.arguments_hash'),
    data_classifications: normalizedSet(
      current.data_classifications,
      'current_action.data_classifications',
    ),
    requested_scopes: normalizedSet(
      current.requested_scopes,
      'current_action.requested_scopes',
    ),
  };
  const target = optionalNonblank(current, 'target', 'current_action.target');
  if (target !== undefined) action.target = target;

  if (!Array.isArray(root.prior_actions)) {
    throw new ActionContextValidationError('prior_actions must be an array');
  }
  const priorActions = root.prior_actions.map(priorAction);
  for (let i = 1; i < priorActions.length; i++) {
    if (priorActions[i].sequence <= priorActions[i - 1].sequence) {
      throw new ActionContextValidationError(
        'prior_actions sequences must be strictly increasing in input order',
      );
    }
  }

  const doc: ActionContextDocument = {
    schema: ACTION_CONTEXT_SCHEMA,
    agent,
    action,
    run_id: nonblank(root.run_id, 'run_id'),
    prior_actions: priorActions,
  };
  const sessionId = optionalNonblank(root, 'session_id', 'session_id');
  if (sessionId !== undefined) doc.session_id = sessionId;
  const threadId = optionalNonblank(root, 'thread_id', 'thread_id');
  if (threadId !== undefined) doc.thread_id = threadId;
  return doc;
}

export function canonicalizeActionContext(input: ActionContextInput): string {
  return canonicalJsonForHash(buildActionContext(input));
}

export function actionContextHash(input: ActionContextInput): string {
  return sha256Hex(canonicalizeActionContext(input));
}
