import { createHash } from 'node:crypto';
import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import type { AarmOutcome } from './aarm-outcome.js';

export const STRICT_EVALUATION_EVIDENCE_V2_1_SCHEMA = 'obsvr-strict-evaluation-evidence-v2-1' as const;
const DETECTOR_SET_SCHEMA = 'obsvr-strict-detector-set-v2-1' as const;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const FAILURE = /^[a-z][a-z0-9_]{0,63}$/;
const HASH = /^[0-9a-f]{64}$/;
const OUTCOMES = new Set<AarmOutcome>(['ALLOW', 'DENY', 'MODIFY', 'STEP_UP', 'DEFER']);
const MAX_DETECTORS = 64; const MAX_RULES = 128;
const trustedProviders = new WeakSet<object>();
const trustedReasonCodes = new WeakMap<object, readonly string[]>();
const EVALUATOR_MANIFEST = { schema: 'obsvr-strict-evaluator-manifest-v2-1',
  profile_version: '2.1', engine: 'obsvr-strict-evaluation', semantics_version: '1' } as const;
export const STRICT_EVALUATOR_MANIFEST_HASH_V2_1 = sha(canonicalJsonForHash(EVALUATOR_MANIFEST));

export interface EffectivePolicyEvidenceV21 {
  version: string; artifact_hash: string; matched_rule_ids: string[];
}
export interface DetectorRequirementV21 {
  detector_id: string; detector_manifest_hash: string; required: boolean;
  purpose: 'evaluation' | 'transform';
}
export interface DetectorResultV21 {
  detector_id: string; status: 'ok' | 'unavailable' | 'degraded';
  result_hash?: string; failure_code?: string;
}
export interface TrustedEvaluationSnapshotV21 {
  effective_policy: EffectivePolicyEvidenceV21;
  detector_requirements: DetectorRequirementV21[];
  detector_results: DetectorResultV21[];
}
export interface TrustedEvaluationEvidenceProviderV21 {
  capture: () => TrustedEvaluationSnapshotV21;
}
export interface TrustedDecisionReasonCodesV21 { readonly trusted: 'decision_reason_codes_v2_1' }
export interface NormalizedDetectorEvidenceV21 extends DetectorRequirementV21 {
  status: DetectorResultV21['status']; result_hash?: string; failure_code?: string;
}
export interface StrictEvaluationEvidenceV21 {
  schema: typeof STRICT_EVALUATION_EVIDENCE_V2_1_SCHEMA; profile_version: '2.1';
  effective_policy: EffectivePolicyEvidenceV21; evaluator_manifest_hash: string;
  detectors: NormalizedDetectorEvidenceV21[]; detector_set_hash: string;
  requested_outcome: AarmOutcome; outcome: AarmOutcome;
  decision_reason_codes: string[];
  reason_code: 'evaluation_complete' | 'required_detector_uncertain' | 'required_transform_unavailable';
}

export class StrictEvaluationEvidenceV21Error extends Error {
  constructor(message: string) { super(message); this.name = 'StrictEvaluationEvidenceV21Error'; }
}
function fail(message: string): never { throw new StrictEvaluationEvidenceV21Error(message); }
function sha(value: string): string { return createHash('sha256').update(value).digest('hex'); }
function domainHash(domain: string, canonical: string): string {
  const body = Buffer.from(canonical, 'utf8'); const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(body.length));
  return createHash('sha256').update(Buffer.concat([
    Buffer.from(`${domain}\0`, 'utf8'), length, body,
  ])).digest('hex');
}
function exact(value: unknown, keys: readonly string[], field: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return fail(`${field} must be an object`);
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    return fail(`${field} has unknown or missing keys`);
  }
  return value as Record<string, unknown>;
}
function identifier(value: unknown, field: string): string {
  if (typeof value !== 'string' || !ID.test(value)) return fail(`${field} must be a bounded ASCII identifier`);
  return value;
}
function hash(value: unknown, field: string): string {
  if (typeof value !== 'string' || !HASH.test(value)) return fail(`${field} must be lowercase SHA-256`);
  return value;
}
function sortedUnique(values: unknown, field: string, cap: number): string[] {
  if (!Array.isArray(values) || values.length > cap) return fail(`${field} must be a bounded array`);
  const normalized = values.map((item, index) => identifier(item, `${field}[${index}]`));
  return [...new Set(normalized)].sort((left, right) => left < right ? -1 : left > right ? 1 : 0);
}
function policy(value: unknown): EffectivePolicyEvidenceV21 {
  const item = exact(value, ['version', 'artifact_hash', 'matched_rule_ids'], 'policy');
  return { version: identifier(item.version, 'policy.version'),
    artifact_hash: hash(item.artifact_hash, 'policy.artifact_hash'),
    matched_rule_ids: sortedUnique(item.matched_rule_ids, 'policy.matched_rule_ids', MAX_RULES) };
}
function requirements(value: unknown): DetectorRequirementV21[] {
  if (!Array.isArray(value) || value.length > MAX_DETECTORS) return fail('detector_requirements must be bounded');
  const seen = new Set<string>();
  const items = value.map((raw, index) => {
    const item = exact(raw, ['detector_id', 'detector_manifest_hash', 'required', 'purpose'], `requirement[${index}]`);
    const detector_id = identifier(item.detector_id, 'detector_id');
    if (seen.has(detector_id)) return fail('duplicate detector requirement'); seen.add(detector_id);
    if (typeof item.required !== 'boolean' || !['evaluation', 'transform'].includes(item.purpose as string)) {
      return fail('invalid detector requirement');
    }
    return { detector_id, detector_manifest_hash: hash(item.detector_manifest_hash, 'detector_manifest_hash'),
      required: item.required, purpose: item.purpose as DetectorRequirementV21['purpose'] };
  });
  return items.sort((left, right) => left.detector_id < right.detector_id ? -1 : 1);
}
function results(value: unknown, declared: DetectorRequirementV21[]): Map<string, DetectorResultV21> {
  if (!Array.isArray(value) || value.length > MAX_DETECTORS) return fail('detector_results must be bounded');
  const allowed = new Set(declared.map((item) => item.detector_id)); const found = new Map<string, DetectorResultV21>();
  value.forEach((raw, index) => {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return fail(`detector_result[${index}] must be an object`);
    const record = raw as Record<string, unknown>; const status = record.status;
    const keys = status === 'ok' ? ['detector_id', 'status', 'result_hash'] : ['detector_id', 'status', 'failure_code'];
    const item = exact(raw, keys, `detector_result[${index}]`);
    const detector_id = identifier(item.detector_id, 'detector_id');
    if (!allowed.has(detector_id) || found.has(detector_id)) return fail('unknown or duplicate detector result');
    if (!['ok', 'unavailable', 'degraded'].includes(status as string)) return fail('invalid detector status');
    found.set(detector_id, status === 'ok'
      ? { detector_id, status, result_hash: hash(item.result_hash, 'result_hash') } as DetectorResultV21
      : { detector_id, status: status as DetectorResultV21['status'],
        failure_code: typeof item.failure_code === 'string' && FAILURE.test(item.failure_code)
          ? item.failure_code : fail('invalid detector failure_code') });
  });
  return found;
}

/** Explicit trust boundary: adapters create this around their authenticated policy/detector snapshot. */
export function createTrustedEvaluationEvidenceProviderV21(
  capture: () => TrustedEvaluationSnapshotV21,
): TrustedEvaluationEvidenceProviderV21 {
  if (typeof capture !== 'function') return fail('trusted provider must be callable');
  const provider = Object.freeze({ capture }); trustedProviders.add(provider); return provider;
}
/** Explicit evaluator boundary; normalized codes are snapshotted and cannot be caller-mutated. */
export function createTrustedDecisionReasonCodesV21(
  codes: readonly string[],
): TrustedDecisionReasonCodesV21 {
  const normalized = sortedUnique(codes, 'decision_reason_codes', 32);
  if (!normalized.length) return fail('decision_reason_codes must be nonempty');
  const capability = Object.freeze({ trusted: 'decision_reason_codes_v2_1' as const });
  trustedReasonCodes.set(capability, Object.freeze(normalized)); return capability;
}
export function buildStrictEvaluationEvidenceV21(
  provider: TrustedEvaluationEvidenceProviderV21, requestedOutcome: AarmOutcome,
  trustedReasons: TrustedDecisionReasonCodesV21,
): { evidence: StrictEvaluationEvidenceV21; evidence_hash: string } {
  if (!trustedProviders.has(provider as object)) return fail('trusted evidence provider is required');
  if (!OUTCOMES.has(requestedOutcome)) return fail('unsupported requested outcome');
  const decision_reason_codes = trustedReasonCodes.get(trustedReasons as object);
  if (!decision_reason_codes) return fail('trusted decision_reason_codes are required');
  let captured: TrustedEvaluationSnapshotV21;
  try { captured = provider.capture(); } catch { return fail('trusted evidence capture failed'); }
  const snapshot = exact(captured, ['effective_policy', 'detector_requirements', 'detector_results'], 'snapshot');
  const normalizedPolicy = policy(snapshot.effective_policy);
  const declared = requirements(snapshot.detector_requirements);
  const actual = results(snapshot.detector_results, declared);
  const detectors = declared.map((requirement): NormalizedDetectorEvidenceV21 => {
    const record = actual.get(requirement.detector_id) ?? { detector_id: requirement.detector_id,
      status: 'unavailable' as const, failure_code: 'detector_missing' };
    return { ...requirement, status: record.status,
      ...(record.status === 'ok' ? { result_hash: record.result_hash! } : { failure_code: record.failure_code! }) };
  });
  const unhealthy = detectors.filter((item) => item.required && item.status !== 'ok');
  let outcome = requestedOutcome; let reason_code: StrictEvaluationEvidenceV21['reason_code'] = 'evaluation_complete';
  if (['ALLOW', 'MODIFY'].includes(requestedOutcome) && unhealthy.some((item) => item.purpose === 'transform')) {
    outcome = 'DENY'; reason_code = 'required_transform_unavailable';
  } else if (['ALLOW', 'MODIFY'].includes(requestedOutcome) && unhealthy.length) {
    outcome = 'DEFER'; reason_code = 'required_detector_uncertain';
  }
  const detector_set_hash = domainHash('obsvr-strict-detector-set/2.1',
    canonicalJsonForHash({ schema: DETECTOR_SET_SCHEMA, detectors }));
  const evidence: StrictEvaluationEvidenceV21 = { schema: STRICT_EVALUATION_EVIDENCE_V2_1_SCHEMA,
    profile_version: '2.1', effective_policy: normalizedPolicy,
    evaluator_manifest_hash: STRICT_EVALUATOR_MANIFEST_HASH_V2_1,
    detectors, detector_set_hash, requested_outcome: requestedOutcome, outcome,
    decision_reason_codes: [...decision_reason_codes], reason_code };
  return { evidence, evidence_hash: domainHash(
    'obsvr-strict-evaluation-evidence/2.1', canonicalJsonForHash(evidence),
  ) };
}
