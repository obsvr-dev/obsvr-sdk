/**
 * Audit chain integrity verifier.
 * Recomputes HMAC-SHA256 signatures and validates chain linking.
 *
 * @packageDocumentation
 */
import { createHmac, createHash } from 'crypto';
import type { AuditEvent } from '../proxy/types.js';
import { parseAuditGapPrompt } from '../proxy/audit-gap.js';

export interface ChainVerificationResult {
  valid: boolean;
  brokenAt?: number;
  reason?: string;
  eventsVerified: number;
  /**
   * Gap markers found in the verified prefix — events the SDK signed to say it
   * had dropped events before them (see proxy/audit-gap.ts).
   */
  gapMarkers: number;
  /**
   * Total events those markers declare lost. A chain can be perfectly valid
   * and still be missing this many events: `valid: true` means what is here is
   * genuine and in order, NOT that it is everything. Reporting them separately
   * is the point — a caller that ignores this reads a saturated burst as a
   * clean run.
   */
  eventsDeclaredLost: number;
}

const SIGNING_SALT = 'obsvr-sdk-signing-v1';

/** Derive signing key (same as fire-and-forget.ts) */
function deriveSigningKey(apiKey: string): Buffer {
  return createHmac('sha256', SIGNING_SALT).update(apiKey).digest();
}

/** Compute content hash (same as fire-and-forget.ts) */
function contentHash(prompt: string, response: string): string {
  return createHash('sha256')
    .update((prompt ?? '') + (response ?? ''))
    .digest('hex');
}

/** Compute expected signature for an event */
function computeSignature(
  signingKey: Buffer,
  sessionId: string,
  seqNo: number,
  timestampSdk: number,
  prompt: string,
  response: string,
  prevSig: string | null
): string {
  const hash = contentHash(prompt, response);
  const sigPayload = [sessionId, seqNo, timestampSdk, hash, prevSig ?? ''].join('|');
  return createHmac('sha256', signingKey).update(sigPayload).digest('hex');
}

/**
 * Verify the integrity of an audit event chain.
 *
 * Checks:
 * 1. All signatures are valid (recomputed HMAC matches)
 * 2. seq_no is monotonically increasing with no gaps
 * 3. prev_sig links correctly to the prior event's sdk_sig
 * 4. sdk_session_id is consistent across all events
 * 5. timestamps are non-decreasing
 *
 * It also TALLIES what the chain admits it is missing: gap markers the sender
 * signed to record events the bounded queue dropped before they could be
 * chained. Those events left no hole to detect - they never got a sequence
 * number - so the marker is the only evidence they existed, and a verifier
 * that returns `valid: true` without surfacing it reports a lossy run as a
 * complete one.
 */
export function verifyAuditChain(
  events: AuditEvent[],
  apiKey: string
): ChainVerificationResult {
  let gapMarkers = 0;
  let eventsDeclaredLost = 0;

  /** A break: the gap tally covers only the prefix that verified. */
  const broken = (i: number, reason: string): ChainVerificationResult => ({
    valid: false,
    brokenAt: i,
    reason,
    eventsVerified: i,
    gapMarkers,
    eventsDeclaredLost,
  });

  if (!events || events.length === 0) {
    return { valid: true, eventsVerified: 0, gapMarkers: 0, eventsDeclaredLost: 0 };
  }

  const signingKey = deriveSigningKey(apiKey);
  const sessionId = events[0].sdk_session_id;

  if (!sessionId) {
    return broken(0, 'First event missing sdk_session_id');
  }

  let lastSig: string | null = null;
  let lastSeq = 0;
  let lastTimestamp = 0;

  for (let i = 0; i < events.length; i++) {
    const event = events[i];

    // Check session consistency
    if (event.sdk_session_id !== sessionId) {
      return broken(i, `Session ID mismatch at event ${i}: expected ${sessionId}, got ${event.sdk_session_id}`);
    }

    // Check seq_no monotonicity
    if (event.seq_no === undefined || event.seq_no === null) {
      return broken(i, `Missing seq_no at event ${i}`);
    }
    if (i === 0) {
      if (event.seq_no < 1) {
        return broken(i, `Invalid initial seq_no: ${event.seq_no}`);
      }
    } else if (event.seq_no !== lastSeq + 1) {
      return broken(i, `seq_no gap at event ${i}: expected ${lastSeq + 1}, got ${event.seq_no}`);
    }
    lastSeq = event.seq_no;

    // Check timestamp non-decreasing
    if (event.timestamp_sdk !== undefined) {
      if (event.timestamp_sdk < lastTimestamp) {
        return broken(i, `Timestamp decreased at event ${i}: ${event.timestamp_sdk} < ${lastTimestamp}`);
      }
      lastTimestamp = event.timestamp_sdk;
    }

    // Check prev_sig chain link
    if (i > 0) {
      if (event.prev_sig !== lastSig) {
        return broken(i, `Chain break at event ${i}: prev_sig does not match prior event's sdk_sig`);
      }
    }

    // Recompute and verify signature
    const expectedSig = computeSignature(
      signingKey,
      event.sdk_session_id!,
      event.seq_no,
      event.timestamp_sdk ?? 0,
      event.prompt ?? '',
      event.response ?? '',
      event.prev_sig ?? null
    );

    if (event.sdk_sig !== expectedSig) {
      return broken(i, `Signature mismatch at event ${i}`);
    }

    lastSig = event.sdk_sig ?? null;

    // Counted only after the event's own signature verified: an unverified
    // marker's count is an unverified claim.
    const gap = parseAuditGapPrompt(event.prompt);
    if (gap) {
      gapMarkers++;
      eventsDeclaredLost += gap.dropped;
    }
  }

  return { valid: true, eventsVerified: events.length, gapMarkers, eventsDeclaredLost };
}
