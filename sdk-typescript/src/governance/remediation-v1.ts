import { sha256Hex } from '../policy/decision-record.js';
import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import {
  STRICT_IDENTIFIER_MAX_BYTES,
  STRICT_SET_MAX_ITEMS,
  boundedCanonicalText,
  compareCodePoints,
} from './strict-canonical.js';

export const REMEDIATION_PLAN_V1_SCHEMA = 'obsvr-remediation-plan-v1' as const;
export const REMEDIATION_RETRY_V1_SCHEMA = 'obsvr-remediation-retry-v1' as const;
export const REMEDIATION_PLAN_HASH_DOMAIN = 'obsvr-remediation-plan/1' as const;

const HASH_RE = /^[0-9a-f]{64}$/;
const OUTCOMES = new Set(['MODIFY', 'STEP_UP', 'DEFER']);
const REQUIREMENT_KINDS = new Set([
  'approval', 'context', 'modification', 'scope', 'tool', 'verification', 'wait_until',
]);

export interface RemediationRequirementV1Input {
  kind: 'approval' | 'context' | 'modification' | 'scope' | 'tool' | 'verification' | 'wait_until';
  code: string;
  evidence_key: string;
  expected_value_hash?: string;
  guidance?: string;
}

export interface RemediationPlanV1Input {
  plan_id: string;
  attempt_id: string;
  receipt_hash: string;
  outcome: 'MODIFY' | 'STEP_UP' | 'DEFER';
  reason_code: string;
  requirements: RemediationRequirementV1Input[];
  created_at_ms: number;
  expires_at_ms?: number;
}

export interface RemediationPlanV1Document extends RemediationPlanV1Input {
  schema: typeof REMEDIATION_PLAN_V1_SCHEMA;
}

export interface SatisfiedRemediationRequirementV1Input {
  code: string;
  evidence_hash: string;
}

export interface RemediationRetryV1Input {
  retry_attempt_id: string;
  plan: RemediationPlanV1Input | RemediationPlanV1Document;
  satisfied_requirements: SatisfiedRemediationRequirementV1Input[];
}

export interface RemediationRetryV1Document {
  schema: typeof REMEDIATION_RETRY_V1_SCHEMA;
  retry_attempt_id: string;
  parent_attempt_id: string;
  parent_receipt_hash: string;
  remediation_plan_hash: string;
  satisfied_requirements: SatisfiedRemediationRequirementV1Input[];
}

export class RemediationV1ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RemediationV1ValidationError';
  }
}

function fail(message: string): never {
  throw new RemediationV1ValidationError(message);
}

function record(value: unknown, field: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${field} must be an object`);
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, allowed: readonly string[], field: string): void {
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key)).sort(compareCodePoints);
  if (unknown.length > 0) fail(`${field} contains unsupported field: ${unknown[0]}`);
}

function text(value: unknown, field: string): string {
  return boundedCanonicalText(value, field, STRICT_IDENTIFIER_MAX_BYTES, fail);
}

function hash(value: unknown, field: string): string {
  if (typeof value !== 'string' || !HASH_RE.test(value)) {
    fail(`${field} must be exactly 64 lowercase hexadecimal characters`);
  }
  return value;
}

function integer(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    fail(`${field} must be a nonnegative safe integer`);
  }
  return value;
}

function requirement(value: unknown, index: number): RemediationRequirementV1Input {
  const field = `requirements[${index}]`;
  const item = record(value, field);
  exactKeys(item, ['kind', 'code', 'evidence_key', 'expected_value_hash', 'guidance'], field);
  if (typeof item.kind !== 'string' || !REQUIREMENT_KINDS.has(item.kind)) {
    fail(`${field}.kind is unsupported`);
  }
  const result: RemediationRequirementV1Input = {
    kind: item.kind as RemediationRequirementV1Input['kind'],
    code: text(item.code, `${field}.code`),
    evidence_key: text(item.evidence_key, `${field}.evidence_key`),
  };
  if (Object.prototype.hasOwnProperty.call(item, 'expected_value_hash')) {
    result.expected_value_hash = hash(item.expected_value_hash, `${field}.expected_value_hash`);
  }
  if (Object.prototype.hasOwnProperty.call(item, 'guidance')) {
    result.guidance = text(item.guidance, `${field}.guidance`);
  }
  return result;
}

export function buildRemediationPlanV1(input: RemediationPlanV1Input): RemediationPlanV1Document {
  const root = record(input, 'remediation plan');
  exactKeys(root, ['schema', 'plan_id', 'attempt_id', 'receipt_hash', 'outcome', 'reason_code',
    'requirements', 'created_at_ms', 'expires_at_ms'], 'remediation plan');
  if (Object.prototype.hasOwnProperty.call(root, 'schema')
    && root.schema !== REMEDIATION_PLAN_V1_SCHEMA) fail('remediation plan schema is invalid');
  if (typeof root.outcome !== 'string' || !OUTCOMES.has(root.outcome)) {
    fail('outcome must be MODIFY, STEP_UP, or DEFER');
  }
  if (!Array.isArray(root.requirements) || root.requirements.length === 0
    || root.requirements.length > STRICT_SET_MAX_ITEMS) {
    fail(`requirements must contain between 1 and ${STRICT_SET_MAX_ITEMS} items`);
  }
  const requirements = root.requirements.map(requirement).sort((left, right) => compareCodePoints(
    `${left.kind}\0${left.code}\0${left.evidence_key}`,
    `${right.kind}\0${right.code}\0${right.evidence_key}`,
  ));
  if (new Set(requirements.map((item) => item.code)).size !== requirements.length) {
    fail('requirement codes must be unique');
  }
  const created = integer(root.created_at_ms, 'created_at_ms');
  const document: RemediationPlanV1Document = {
    schema: REMEDIATION_PLAN_V1_SCHEMA,
    plan_id: text(root.plan_id, 'plan_id'),
    attempt_id: text(root.attempt_id, 'attempt_id'),
    receipt_hash: hash(root.receipt_hash, 'receipt_hash'),
    outcome: root.outcome as RemediationPlanV1Document['outcome'],
    reason_code: text(root.reason_code, 'reason_code'),
    requirements,
    created_at_ms: created,
  };
  if (Object.prototype.hasOwnProperty.call(root, 'expires_at_ms')) {
    const expires = integer(root.expires_at_ms, 'expires_at_ms');
    if (expires <= created) fail('expires_at_ms must be after created_at_ms');
    document.expires_at_ms = expires;
  }
  return document;
}

export function canonicalizeRemediationPlanV1(input: RemediationPlanV1Input): string {
  return canonicalJsonForHash(buildRemediationPlanV1(input));
}

export function remediationPlanV1Hash(input: RemediationPlanV1Input): string {
  return sha256Hex(`${REMEDIATION_PLAN_HASH_DOMAIN}\0${canonicalizeRemediationPlanV1(input)}`);
}

export function buildRemediationRetryV1(input: RemediationRetryV1Input): RemediationRetryV1Document {
  const root = record(input, 'remediation retry');
  exactKeys(root, ['retry_attempt_id', 'plan', 'satisfied_requirements'], 'remediation retry');
  const plan = buildRemediationPlanV1(root.plan as RemediationPlanV1Input);
  const retryAttemptId = text(root.retry_attempt_id, 'retry_attempt_id');
  if (retryAttemptId === plan.attempt_id) fail('retry_attempt_id must identify a new attempt');
  if (!Array.isArray(root.satisfied_requirements)
    || root.satisfied_requirements.length > STRICT_SET_MAX_ITEMS) {
    fail(`satisfied_requirements must contain at most ${STRICT_SET_MAX_ITEMS} items`);
  }
  const satisfied = root.satisfied_requirements.map((candidate, index) => {
    const field = `satisfied_requirements[${index}]`;
    const item = record(candidate, field);
    exactKeys(item, ['code', 'evidence_hash'], field);
    return { code: text(item.code, `${field}.code`), evidence_hash: hash(item.evidence_hash, `${field}.evidence_hash`) };
  }).sort((left, right) => compareCodePoints(left.code, right.code));
  if (new Set(satisfied.map((item) => item.code)).size !== satisfied.length) {
    fail('satisfied requirement codes must be unique');
  }
  const requiredCodes = plan.requirements.map((item) => item.code).sort(compareCodePoints);
  if (canonicalJsonForHash(satisfied.map((item) => item.code)) !== canonicalJsonForHash(requiredCodes)) {
    fail('satisfied_requirements must provide evidence for every plan requirement');
  }
  return {
    schema: REMEDIATION_RETRY_V1_SCHEMA,
    retry_attempt_id: retryAttemptId,
    parent_attempt_id: plan.attempt_id,
    parent_receipt_hash: plan.receipt_hash,
    remediation_plan_hash: remediationPlanV1Hash(plan),
    satisfied_requirements: satisfied,
  };
}

export function remediationRetryV1Hash(input: RemediationRetryV1Input): string {
  return sha256Hex(canonicalJsonForHash(buildRemediationRetryV1(input)));
}
