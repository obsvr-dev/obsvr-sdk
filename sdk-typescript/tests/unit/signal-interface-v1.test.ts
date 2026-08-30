import { resolveSignalV1, signalResolutionToCedarContextV1, signalResolutionToOpaInputV1, signalResolutionToOtelAttributesV1 } from '../../src/governance/signal-interface-v1.js';

const declaration = { signal_id: 'customer-risk', version: '2', determinism: 'probabilistic' as const, locality: 'remote' as const, timeout_ms: 500, cache_ttl_ms: 1000, failure_disposition: 'defer' as const };
const observation = { signal_id: 'customer-risk', version: '2', input_hash: 'a'.repeat(64), status: 'matched' as const, labels: ['high-risk'], score_bps: 8700, provenance_hash: 'b'.repeat(64), evaluated_at_ms: 100, latency_ms: 30, cache_state: 'miss' as const };

describe('signal interface v1', () => {
  test('records probabilistic remote facts without granting authority', () => {
    const result = resolveSignalV1(declaration, observation);
    expect(result).toMatchObject({ fact: { matched: true, score_bps: 8700 }, required_outcome: null, authoritative_allow: false });
    expect(result.declaration.authoritative_allow).toBe(false);
    expect(result.resolution_hash).toBe('7fb165138893b6749a98511f198a759b59bc2ef017dcdd5155eb9037469fc610');
  });
  test('turns declared failures into a deterministic kernel constraint', () => {
    const result = resolveSignalV1(declaration, { ...observation, status: 'timeout', labels: [] });
    expect(result.required_outcome).toBe('DEFER');
    expect(result.authoritative_allow).toBe(false);
  });
  test('exports correlation and policy inputs without replacing evidence', () => {
    const result = resolveSignalV1(declaration, observation);
    expect(signalResolutionToOtelAttributesV1(result)['obsvr.signal.resolution_hash']).toBe(result.resolution_hash);
    expect(signalResolutionToOpaInputV1(result).obsvr_signal.authoritative_allow).toBe(false);
    expect(signalResolutionToCedarContextV1(result).obsvrSignalAuthoritativeAllow).toBe(false);
  });
});
