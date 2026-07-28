/**
 * Sampling Logic
 *
 * Decides whether to EMIT an allowed-call audit event. Sampling gates audit
 * *emission* only — it never gates enforcement: PII/policy/hook/kill-switch
 * checks run on every call regardless of sample_rate, and blocked/redacted/error
 * events are always emitted. Lowering sample_rate reduces ingest volume, not the
 * per-call enforcement cost.
 *
 * @packageDocumentation
 */

/**
 * Whether an allowed-call audit event should be emitted for this call. Does NOT
 * decide whether the call is governed — enforcement always runs.
 *
 * @param sampleRate - Rate between 0 and 1
 * @returns true if the allowed-call audit event should be emitted
 */
export function shouldSample(sampleRate: number): boolean {
  if (sampleRate <= 0) {
    return false;
  }

  if (sampleRate >= 1) {
    return true;
  }

  return Math.random() < sampleRate;
}
