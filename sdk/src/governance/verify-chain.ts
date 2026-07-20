/**
 * Audit chain integrity verifier.
 * Recomputes HMAC-SHA256 signatures and validates chain linking.
 *
 * @packageDocumentation
 */
import { createHmac, createHash } from 'crypto';
import type { AuditEvent } from '../proxy/types.js';

export interface ChainVerificationResult {
  valid: boolean;
  brokenAt?: number;
  reason?: string;
  eventsVerified: number;
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
 */
export function verifyAuditChain(
  events: AuditEvent[],
  apiKey: string
): ChainVerificationResult {
  if (!events || events.length === 0) {
    return { valid: true, eventsVerified: 0 };
  }

  const signingKey = deriveSigningKey(apiKey);
  const sessionId = events[0].sdk_session_id;

  if (!sessionId) {
    return { valid: false, brokenAt: 0, reason: 'First event missing sdk_session_id', eventsVerified: 0 };
  }

  let lastSig: string | null = null;
  let lastSeq = 0;
  let lastTimestamp = 0;

  for (let i = 0; i < events.length; i++) {
    const event = events[i];

    // Check session consistency
    if (event.sdk_session_id !== sessionId) {
      return {
        valid: false,
        brokenAt: i,
        reason: `Session ID mismatch at event ${i}: expected ${sessionId}, got ${event.sdk_session_id}`,
        eventsVerified: i,
      };
    }

    // Check seq_no monotonicity
    if (event.seq_no === undefined || event.seq_no === null) {
      return { valid: false, brokenAt: i, reason: `Missing seq_no at event ${i}`, eventsVerified: i };
    }
    if (i === 0) {
      if (event.seq_no < 1) {
        return { valid: false, brokenAt: i, reason: `Invalid initial seq_no: ${event.seq_no}`, eventsVerified: i };
      }
    } else if (event.seq_no !== lastSeq + 1) {
      return {
        valid: false,
        brokenAt: i,
        reason: `seq_no gap at event ${i}: expected ${lastSeq + 1}, got ${event.seq_no}`,
        eventsVerified: i,
      };
    }
    lastSeq = event.seq_no;

    // Check timestamp non-decreasing
    if (event.timestamp_sdk !== undefined) {
      if (event.timestamp_sdk < lastTimestamp) {
        return {
          valid: false,
          brokenAt: i,
          reason: `Timestamp decreased at event ${i}: ${event.timestamp_sdk} < ${lastTimestamp}`,
          eventsVerified: i,
        };
      }
      lastTimestamp = event.timestamp_sdk;
    }

    // Check prev_sig chain link
    if (i > 0) {
      if (event.prev_sig !== lastSig) {
        return {
          valid: false,
          brokenAt: i,
          reason: `Chain break at event ${i}: prev_sig does not match prior event's sdk_sig`,
          eventsVerified: i,
        };
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
      return {
        valid: false,
        brokenAt: i,
        reason: `Signature mismatch at event ${i}`,
        eventsVerified: i,
      };
    }

    lastSig = event.sdk_sig ?? null;
  }

  return { valid: true, eventsVerified: events.length };
}
