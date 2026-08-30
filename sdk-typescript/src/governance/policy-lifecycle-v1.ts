import { sha256Hex } from '../policy/decision-record.js';
import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import { compareCodePoints } from './strict-canonical.js';

export const POLICY_CANDIDATE_V1_SCHEMA = 'obsvr-policy-candidate-v1' as const;
export const POLICY_REPLAY_REPORT_V1_SCHEMA = 'obsvr-policy-replay-report-v1' as const;
export const POLICY_PROMOTION_V1_SCHEMA = 'obsvr-policy-promotion-v1' as const;
const HASH_RE = /^[0-9a-f]{64}$/;
const MAX_ITEMS = 10_000;

export type PolicyStageV1 = 'shadow' | 'canary' | 'active';
export type ReplayOutcomeV1 = 'ALLOW' | 'DENY' | 'MODIFY' | 'STEP_UP' | 'DEFER' | 'ERROR';

export interface PolicyCandidateV1Input {
  policy_id: string;
  version: string;
  artifact_hash: string;
  previous_active_hash?: string;
  stage: PolicyStageV1;
  rollout_bps: number;
  explanation_codes: string[];
}

export interface PolicyReplayCaseV1 {
  case_id: string;
  baseline_outcome: ReplayOutcomeV1;
  candidate_outcome: ReplayOutcomeV1;
  evidence_complete: boolean;
}

export interface PolicyPromotionThresholdsV1 {
  max_error_count: number;
  max_evidence_gap_count: number;
  max_changed_bps: number;
}

export class PolicyLifecycleV1ValidationError extends Error {
  constructor(message: string) { super(message); this.name = 'PolicyLifecycleV1ValidationError'; }
}

function fail(message: string): never { throw new PolicyLifecycleV1ValidationError(message); }
function text(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.trim() === '' || Buffer.byteLength(value.trim(), 'utf8') > 256) {
    fail(`${field} must be nonblank and at most 256 UTF-8 bytes`);
  }
  return value.trim();
}
function hash(value: unknown, field: string): string {
  if (typeof value !== 'string' || !HASH_RE.test(value)) fail(`${field} must be a lowercase SHA-256 hash`);
  return value;
}
function integer(value: unknown, field: string, max = Number.MAX_SAFE_INTEGER): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0 || value > max) {
    fail(`${field} must be a nonnegative safe integer no greater than ${max}`);
  }
  return value;
}
function exact(value: Record<string, unknown>, allowed: string[], field: string): void {
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key)).sort(compareCodePoints);
  if (unknown.length) fail(`${field} contains unsupported field: ${unknown[0]}`);
}

export function buildPolicyCandidateV1(input: PolicyCandidateV1Input): PolicyCandidateV1Input & { schema: typeof POLICY_CANDIDATE_V1_SCHEMA } {
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail('candidate must be an object');
  const raw = input as unknown as Record<string, unknown>;
  exact(raw, ['schema', 'policy_id', 'version', 'artifact_hash', 'previous_active_hash', 'stage', 'rollout_bps', 'explanation_codes'], 'candidate');
  if (raw.schema !== undefined && raw.schema !== POLICY_CANDIDATE_V1_SCHEMA) fail('candidate schema is invalid');
  if (!['shadow', 'canary', 'active'].includes(String(raw.stage))) fail('stage is invalid');
  const stage = raw.stage as PolicyStageV1;
  const rollout = integer(raw.rollout_bps, 'rollout_bps', 10_000);
  if ((stage === 'shadow' && rollout !== 0) || (stage === 'canary' && (rollout < 1 || rollout > 9_999)) || (stage === 'active' && rollout !== 10_000)) {
    fail('rollout_bps is inconsistent with stage');
  }
  if (!Array.isArray(raw.explanation_codes) || raw.explanation_codes.length === 0 || raw.explanation_codes.length > 256) {
    fail('explanation_codes must contain between 1 and 256 items');
  }
  const codes = [...new Set(raw.explanation_codes.map((item, i) => text(item, `explanation_codes[${i}]`)))].sort(compareCodePoints);
  const result: PolicyCandidateV1Input & { schema: typeof POLICY_CANDIDATE_V1_SCHEMA } = {
    schema: POLICY_CANDIDATE_V1_SCHEMA,
    policy_id: text(raw.policy_id, 'policy_id'), version: text(raw.version, 'version'),
    artifact_hash: hash(raw.artifact_hash, 'artifact_hash'), stage, rollout_bps: rollout,
    explanation_codes: codes,
  };
  if (raw.previous_active_hash !== undefined) result.previous_active_hash = hash(raw.previous_active_hash, 'previous_active_hash');
  if (stage !== 'shadow' && !result.previous_active_hash) fail('canary and active candidates require previous_active_hash for rollback');
  return result;
}

export function policyCandidateV1Hash(input: PolicyCandidateV1Input): string {
  return sha256Hex(`obsvr-policy-candidate/1\0${canonicalJsonForHash(buildPolicyCandidateV1(input))}`);
}

export function replayPolicyCandidateV1(candidateInput: PolicyCandidateV1Input, casesInput: PolicyReplayCaseV1[]) {
  const candidate = buildPolicyCandidateV1(candidateInput);
  if (!Array.isArray(casesInput) || casesInput.length === 0 || casesInput.length > MAX_ITEMS) fail(`cases must contain between 1 and ${MAX_ITEMS} items`);
  const allowed = new Set<ReplayOutcomeV1>(['ALLOW', 'DENY', 'MODIFY', 'STEP_UP', 'DEFER', 'ERROR']);
  const cases = casesInput.map((item, index) => {
    if (!item || typeof item !== 'object' || Array.isArray(item)) fail(`cases[${index}] must be an object`);
    exact(item as unknown as Record<string, unknown>, ['case_id', 'baseline_outcome', 'candidate_outcome', 'evidence_complete'], `cases[${index}]`);
    if (!allowed.has(item.baseline_outcome) || !allowed.has(item.candidate_outcome)) fail(`cases[${index}] outcome is invalid`);
    if (typeof item.evidence_complete !== 'boolean') fail(`cases[${index}].evidence_complete must be boolean`);
    return { ...item, case_id: text(item.case_id, `cases[${index}].case_id`) };
  }).sort((a, b) => compareCodePoints(a.case_id, b.case_id));
  if (new Set(cases.map((item) => item.case_id)).size !== cases.length) fail('case_id values must be unique');
  const counts: Record<ReplayOutcomeV1, number> = { ALLOW: 0, DENY: 0, MODIFY: 0, STEP_UP: 0, DEFER: 0, ERROR: 0 };
  for (const item of cases) counts[item.candidate_outcome] += 1;
  const changed = cases.filter((item) => item.baseline_outcome !== item.candidate_outcome).length;
  return {
    schema: POLICY_REPLAY_REPORT_V1_SCHEMA,
    candidate_hash: policyCandidateV1Hash(candidate), total_cases: cases.length,
    changed_cases: changed, changed_bps: Math.floor((changed * 10_000) / cases.length),
    error_count: counts.ERROR,
    evidence_gap_count: cases.filter((item) => !item.evidence_complete).length,
    outcome_counts: counts,
  };
}

export function decidePolicyPromotionV1(
  candidateInput: PolicyCandidateV1Input,
  report: ReturnType<typeof replayPolicyCandidateV1>,
  requestedStage: PolicyStageV1,
  requestedRolloutBps: number,
  thresholds: PolicyPromotionThresholdsV1,
) {
  const candidate = buildPolicyCandidateV1(candidateInput);
  if (report.schema !== POLICY_REPLAY_REPORT_V1_SCHEMA || report.candidate_hash !== policyCandidateV1Hash(candidate)) fail('replay report does not match candidate');
  const reasons: string[] = [];
  if (report.error_count > integer(thresholds.max_error_count, 'max_error_count')) reasons.push('policy.replay.errors_exceeded');
  if (report.evidence_gap_count > integer(thresholds.max_evidence_gap_count, 'max_evidence_gap_count')) reasons.push('policy.replay.evidence_gaps_exceeded');
  if (report.changed_bps > integer(thresholds.max_changed_bps, 'max_changed_bps', 10_000)) reasons.push('policy.replay.change_budget_exceeded');
  if (!['shadow', 'canary', 'active'].includes(requestedStage)) fail('requested_stage is invalid');
  const rollout = integer(requestedRolloutBps, 'requested_rollout_bps', 10_000);
  if ((requestedStage === 'shadow' && rollout !== 0) || (requestedStage === 'canary' && (rollout < 1 || rollout > 9_999)) || (requestedStage === 'active' && rollout !== 10_000)) fail('requested rollout is inconsistent with stage');
  if (requestedStage !== 'shadow' && !candidate.previous_active_hash) reasons.push('policy.rollback.target_missing');
  const approved = reasons.length === 0;
  return {
    schema: POLICY_PROMOTION_V1_SCHEMA,
    candidate_hash: policyCandidateV1Hash(candidate), approved,
    requested_stage: requestedStage, requested_rollout_bps: rollout,
    effective_stage: approved ? requestedStage : 'shadow',
    effective_rollout_bps: approved ? rollout : 0,
    rollback_artifact_hash: candidate.previous_active_hash ?? candidate.artifact_hash,
    reason_codes: approved ? ['policy.promotion.ready'] : reasons.sort(compareCodePoints),
  };
}

