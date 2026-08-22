import {
  buildStrictEvaluationEvidenceV21, createTrustedEvaluationEvidenceProviderV21,
  STRICT_EVALUATOR_MANIFEST_HASH_V2_1,
  type TrustedEvaluationSnapshotV21,
} from '../../src/governance/strict-evaluation-evidence-v2-1';

const A = 'a'.repeat(64); const B = 'b'.repeat(64); const C = 'c'.repeat(64);
const D = 'd'.repeat(64); const E = 'e'.repeat(64); const F = 'f'.repeat(64);
function snapshot(): TrustedEvaluationSnapshotV21 {
  return { effective_policy: { version: 'policy-7', artifact_hash: A,
    matched_rule_ids: ['rule-z', 'rule-a', 'rule-a'] }, detector_requirements: [
    { detector_id: 'redactor', detector_manifest_hash: C, required: true, purpose: 'transform' },
    { detector_id: 'telemetry', detector_manifest_hash: D, required: false, purpose: 'evaluation' },
    { detector_id: 'pii', detector_manifest_hash: B, required: true, purpose: 'evaluation' },
  ], detector_results: [
    { detector_id: 'telemetry', status: 'degraded', failure_code: 'optional_timeout' },
    { detector_id: 'redactor', status: 'ok', result_hash: F },
    { detector_id: 'pii', status: 'ok', result_hash: E },
  ] };
}
const build = (value: TrustedEvaluationSnapshotV21, outcome: 'ALLOW' | 'MODIFY' = 'ALLOW') =>
  buildStrictEvaluationEvidenceV21(createTrustedEvaluationEvidenceProviderV21(() => value), outcome);

describe('strict evaluation evidence profile 2.1', () => {
  test('pins exact normalized policy, detector evidence, and cross-language hashes', () => {
    const result = build(snapshot());
    expect(STRICT_EVALUATOR_MANIFEST_HASH_V2_1)
      .toBe('5e70e3fb6281921e614504b9dbcb41c8ca077698c525cd40b42d7bdb952689f7');
    expect(result.evidence_hash).toBe('ac433f5ae1d44147070d99b3f0ec3dda5aa113c5637e2248b750e9d3755f66f4');
    expect(result.evidence).toMatchObject({ profile_version: '2.1',
      effective_policy: { version: 'policy-7', artifact_hash: A, matched_rule_ids: ['rule-a', 'rule-z'] },
      evaluator_manifest_hash: STRICT_EVALUATOR_MANIFEST_HASH_V2_1,
      detector_set_hash: '74af29dbdae32a036e61000187726dc546520f795aebece4aedc0de22716be0c',
      requested_outcome: 'ALLOW', outcome: 'ALLOW', reason_code: 'evaluation_complete' });
    expect(result.evidence.detectors.map((item) => item.detector_id))
      .toEqual(['pii', 'redactor', 'telemetry']);
  });

  test('keeps evaluator identity fixed while policy evidence changes', () => {
    const first = build(snapshot()); const changed = snapshot();
    changed.effective_policy = { version: 'policy-8', artifact_hash: B, matched_rule_ids: ['rule-b'] };
    const second = build(changed);
    expect(second.evidence.evaluator_manifest_hash).toBe(first.evidence.evaluator_manifest_hash);
    expect(second.evidence.effective_policy).toEqual(changed.effective_policy);
    expect(second.evidence_hash).not.toBe(first.evidence_hash);
    expect(() => build({ ...snapshot(), effective_policy: { ...snapshot().effective_policy,
      matched_rule_ids: ['rule@forged'] } })).toThrow('ASCII identifier');
  });

  test('fails closed for every required detector outage', () => {
    const evaluation = snapshot();
    evaluation.detector_results = evaluation.detector_results.map((item) => item.detector_id === 'pii'
      ? { detector_id: 'pii', status: 'unavailable', failure_code: 'detector_timeout' } : item);
    expect(build(evaluation).evidence).toMatchObject({ outcome: 'DEFER',
      reason_code: 'required_detector_uncertain' });
    const missing = snapshot();
    missing.detector_results = missing.detector_results.filter((item) => item.detector_id !== 'pii');
    const deferred = build(missing);
    expect(deferred.evidence).toMatchObject({ outcome: 'DEFER',
      reason_code: 'required_detector_uncertain' });
    expect(deferred.evidence.detectors[0]).toMatchObject({ detector_id: 'pii',
      status: 'unavailable', failure_code: 'detector_missing' });
    const transform = snapshot(); transform.detector_results = transform.detector_results.map((item) =>
      item.detector_id === 'redactor'
        ? { detector_id: 'redactor', status: 'degraded', failure_code: 'transform_failed' } : item);
    expect(build(transform, 'MODIFY').evidence).toMatchObject({ outcome: 'DENY',
      reason_code: 'required_transform_unavailable' });
  });

  test('rejects forged capability, duplicate/unknown data, raw failures, and caps', () => {
    expect(() => buildStrictEvaluationEvidenceV21({ capture: snapshot } as never, 'ALLOW'))
      .toThrow('trusted evidence provider');
    expect(() => buildStrictEvaluationEvidenceV21(
      createTrustedEvaluationEvidenceProviderV21(() => { throw new Error('secret'); }), 'ALLOW'))
      .toThrow('trusted evidence capture failed');
    const duplicate = snapshot(); duplicate.detector_results.push({ ...duplicate.detector_results[0]! });
    expect(() => build(duplicate)).toThrow('duplicate detector result');
    const duplicateRequirement = snapshot();
    duplicateRequirement.detector_requirements.push({ ...duplicateRequirement.detector_requirements[0]! });
    expect(() => build(duplicateRequirement)).toThrow('duplicate detector requirement');
    const raw = snapshot(); raw.detector_results[0] = { ...raw.detector_results[0]!, raw_error: 'secret' } as never;
    expect(() => build(raw)).toThrow('unknown or missing keys');
    const over = snapshot(); over.effective_policy.matched_rule_ids = Array.from({ length: 129 }, (_, index) => `r${index}`);
    expect(() => build(over)).toThrow('bounded array');
    const detectorCap = snapshot(); detectorCap.detector_requirements = Array.from({ length: 65 }, (_, index) => ({
      detector_id: `d${index}`, detector_manifest_hash: B, required: false, purpose: 'evaluation' as const }));
    expect(() => build(detectorCap)).toThrow('detector_requirements must be bounded');
    const bad = snapshot(); bad.detector_requirements[0] = { ...bad.detector_requirements[0]!, detector_id: 'bad@id' };
    expect(() => build(bad)).toThrow('ASCII identifier');
  });
});
