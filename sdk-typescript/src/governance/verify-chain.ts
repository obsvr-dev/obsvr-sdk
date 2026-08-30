/**
 * Audit chain integrity verifier.
 * Recomputes HMAC-SHA256 signatures and validates chain linking.
 *
 * @packageDocumentation
 */
import { createHmac, timingSafeEqual } from 'crypto';
import type { AuditEvent } from '../proxy/types.js';
import { readAuditGapClaim } from '../proxy/audit-gap.js';
import {
  CHAIN_FORMATS_SUPPORTED,
  CHAIN_FORMAT_LEGACY,
  decisionFieldsOf,
  signaturePayload,
  type DecisionFields,
} from '../proxy/chain-format.js';
import {
  deriveDeviceKeyId,
  loadDevicePublicKey,
  verifyDeviceSig,
} from '../proxy/device-identity.js';

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
  /**
   * Every break found in one pass, in event order. `brokenAt` / `reason`
   * remain the FIRST entry, so existing readers keep working; this list is
   * the full damage report — an auditor investigating a tampered export gets
   * every independent break in one run instead of one index per run. After a
   * break the verifier re-anchors on the breaking event's own claims
   * (seq_no, timestamp, stored sdk_sig), so one tampered event yields one
   * break rather than failing everything downstream of it.
   */
  breaks: Array<{ index: number; reason: string }>;
  /**
   * Signing format the chain was checked under (see proxy/chain-format.ts):
   * 3 for current chains, 2 for content-framed chains signed before the
   * verdict entered the preimage, and 1 for chains signed before
   * length-prefixed content framing existed. This list said "2 for current"
   * and stopped there, so a current chain reported a value the documented
   * vocabulary did not contain. Reported so a legacy chain never passes as
   * silently equivalent to a current one — format 1 does not bind the
   * prompt/response boundary, and a consumer weighing the evidence is
   * entitled to know that. Absent when verification broke before the format
   * could be established (empty chain, missing session id, unrecognized
   * format value).
   */
  chainFormat?: number;
  /**
   * Events carrying a `device_sig`, counted in the verified prefix whether
   * or not device keys were pinned — so a caller (and the CLI) can say
   * "seals present, not verified in this run" instead of silence.
   */
  deviceSignedEvents: number;
  /**
   * True when device public keys were pinned and the device tier ran. In
   * this SDK the Ed25519 backend is node:crypto, always present, so keys
   * pinned always means checked; the field exists for value parity with the
   * Python result, where a missing optional backend reports itself in
   * `deviceUnverifiedReason` instead of folding into valid or tampered.
   */
  deviceChecked: boolean;
  deviceUnverifiedReason?: string;
}

const SIGNING_SALT = 'obsvr-sdk-signing-v1';

/** Derive signing key (same as fire-and-forget.ts) */
function deriveSigningKey(apiKey: string): Buffer {
  return createHmac('sha256', SIGNING_SALT).update(apiKey).digest();
}

/**
 * The event's declared signing format. Absent means 1: legacy chains were
 * signed before the field existed. Anything outside CHAIN_FORMATS_SUPPORTED
 * returns null — an unrecognized format fails closed rather than being guessed
 * at, which is also what makes a chain from a NEWER SDK report unsupported
 * rather than silently mis-verifying under an older rule.
 */
function declaredFormat(event: AuditEvent): number | null {
  const raw = (event as { chain_format?: unknown }).chain_format;
  if (raw === undefined || raw === null) return CHAIN_FORMAT_LEGACY;
  if (typeof raw === "number" && (CHAIN_FORMATS_SUPPORTED as readonly number[]).includes(raw)) {
    return raw;
  }
  return null;
}

/**
 * Constant-time equality over the stored and the recomputed signature.
 *
 * `verifyAuditChain` is library surface, run against caller-supplied chains -
 * not only by the offline CLI - so the comparison must not leak how many
 * leading bytes matched. The length guard leaks only the lengths, which are
 * public: a well-formed sdk_sig is 64 hex characters, and the recomputed
 * digest always is. A non-string stored signature compares as empty and
 * fails. Twin reasoning: hmac.compare_digest in verify_chain.py.
 */
function signatureMatches(stored: unknown, expected: string): boolean {
  const storedBuf = Buffer.from(typeof stored === 'string' ? stored : '', 'utf8');
  const expectedBuf = Buffer.from(expected, 'utf8');
  if (storedBuf.length !== expectedBuf.length) return false;
  return timingSafeEqual(storedBuf, expectedBuf);
}

/**
 * Verify the integrity of an audit event chain.
 *
 * Checks:
 * 1. All signatures are valid (recomputed HMAC matches, under the chain's
 *    declared signing format — reported back as `chainFormat`)
 * 2. seq_no is monotonically increasing with no gaps
 * 3. prev_sig links correctly to the prior event's sdk_sig
 * 4. sdk_session_id is consistent across all events
 * 5. timestamps are non-decreasing
 * 6. every event declares the same chain format as the first
 *
 * It also TALLIES what the chain admits it is missing: gap markers the sender
 * signed to record events the bounded queue dropped before they could be
 * chained. Those events left no hole to detect - they never got a sequence
 * number - so the marker is the only evidence they existed, and a verifier
 * that returns `valid: true` without surfacing it reports a lossy run as a
 * complete one.
 *
 * One pass reports EVERY break (`breaks`), re-anchoring on each breaking
 * event's own claims so independent tampers surface as independent breaks;
 * `brokenAt` / `reason` remain the first of them.
 *
 * With `devicePublicKeys` pinned, the optional non-repudiation tier also
 * runs: every event must carry a `device_sig` by a pinned key that verifies
 * over the same payload (see proxy/device-identity.ts). An event signed by
 * an UNPINNED key is reported as foreign ("Device key unknown"), never
 * trusted on first use; a missing seal is a break, because pinning asserts
 * the expectation and a stripped seal must not read as clean. `apiKey` may
 * be null when device keys are pinned: the device seal covers the same
 * payload the HMAC covers, so content, order and the decision fields verify
 * under the public key alone — non-repudiation without sharing any secret.
 */
export function verifyAuditChain(
  events: AuditEvent[],
  apiKey: string | null,
  devicePublicKeys?: Array<Buffer | string> | null,
): ChainVerificationResult {
  const pinned = new Map<string, Buffer>();
  if (devicePublicKeys) {
    for (const supplied of devicePublicKeys) {
      const raw = Buffer.isBuffer(supplied) ? supplied : loadDevicePublicKey(String(supplied));
      pinned.set(deriveDeviceKeyId(raw), raw);
    }
  }
  const deviceChecked = pinned.size > 0;
  if (apiKey === null && !deviceChecked) {
    throw new Error(
      'verifyAuditChain needs an apiKey, pinned devicePublicKeys, or both',
    );
  }

  let gapMarkers = 0;
  let eventsDeclaredLost = 0;
  let deviceSignedEvents = 0;
  let chainFormat: number | undefined;
  const breaks: Array<{ index: number; reason: string }> = [];

  /**
   * A terminal break, before per-event scanning could even start: the gap
   * tally covers only the prefix that verified.
   */
  const broken = (i: number, reason: string): ChainVerificationResult => {
    breaks.push({ index: i, reason });
    return {
      valid: false,
      brokenAt: i,
      reason,
      eventsVerified: i,
      gapMarkers,
      eventsDeclaredLost,
      breaks,
      ...(chainFormat !== undefined ? { chainFormat } : {}),
      deviceSignedEvents,
      deviceChecked,
    };
  };

  if (!events || events.length === 0) {
    return {
      valid: true,
      eventsVerified: 0,
      gapMarkers: 0,
      eventsDeclaredLost: 0,
      breaks: [],
      deviceSignedEvents: 0,
      deviceChecked,
    };
  }

  const signingKey = apiKey !== null ? deriveSigningKey(apiKey) : null;
  const sessionId = events[0].sdk_session_id;

  if (!sessionId) {
    return broken(0, 'First event missing sdk_session_id');
  }

  // The first event fixes the chain's signing format. A chain is one session,
  // one process, one SDK build — no legitimate producer changes format
  // mid-chain, so a later event declaring a different format is a break, not
  // a negotiation. An unrecognized value fails closed: a newer format is not
  // guessed at by an older verifier.
  const firstFormat = declaredFormat(events[0]);
  if (firstFormat === null) {
    return broken(
      0,
      `Unsupported chain_format at event 0: ${String((events[0] as { chain_format?: unknown }).chain_format)}`
    );
  }
  chainFormat = firstFormat;

  let lastSig: string | null = null;
  // `null` means "unknown": after an event with no usable seq_no, the next
  // event's sequence is adopted as the new anchor rather than compared
  // against a stale value, so one missing field is one break, not two.
  let lastSeq: number | null = 0;
  let lastTimestamp = 0;

  /**
   * One break per event, then RE-ANCHOR on the event's own claims so scanning
   * continues: an auditor gets every independent break in one run, and a
   * single tampered event does not fail everything downstream of it. The
   * stored sdk_sig anchors the linkage check even when it did not verify —
   * the next event's prev_sig was minted against the stored value, so a
   * mismatch there is a further, real inconsistency.
   */
  const recordBreak = (i: number, reason: string, event: AuditEvent): void => {
    breaks.push({ index: i, reason });
    lastSeq = typeof event.seq_no === "number" ? event.seq_no : null;
    if (typeof event.timestamp_sdk === "number") {
      lastTimestamp = event.timestamp_sdk;
    }
    lastSig = typeof event.sdk_sig === "string" ? event.sdk_sig : null;
  };

  for (let i = 0; i < events.length; i++) {
    const event = events[i];

    // Check session consistency. A foreign event is not part of this chain:
    // it is reported and SKIPPED, neither anchoring nor advancing the state
    // the rest of the session verifies against.
    if (event.sdk_session_id !== sessionId) {
      breaks.push({
        index: i,
        reason: `Session ID mismatch at event ${i}: expected ${sessionId}, got ${event.sdk_session_id}`,
      });
      continue;
    }

    // Check format consistency
    const format = declaredFormat(event);
    if (format === null) {
      recordBreak(
        i,
        `Unsupported chain_format at event ${i}: ${String((event as { chain_format?: unknown }).chain_format)}`,
        event
      );
      continue;
    }
    if (format !== chainFormat) {
      recordBreak(i, `Chain format mismatch at event ${i}: expected ${chainFormat}, got ${format}`, event);
      continue;
    }

    // Check seq_no monotonicity
    if (event.seq_no === undefined || event.seq_no === null) {
      recordBreak(i, `Missing seq_no at event ${i}`, event);
      continue;
    }
    if (i === 0) {
      if (event.seq_no < 1) {
        recordBreak(i, `Invalid initial seq_no: ${event.seq_no}`, event);
        continue;
      }
    } else if (lastSeq !== null && event.seq_no !== lastSeq + 1) {
      recordBreak(i, `seq_no gap at event ${i}: expected ${lastSeq + 1}, got ${event.seq_no}`, event);
      continue;
    }
    lastSeq = event.seq_no;

    // Check timestamp non-decreasing
    if (event.timestamp_sdk !== undefined) {
      if (event.timestamp_sdk < lastTimestamp) {
        recordBreak(i, `Timestamp decreased at event ${i}: ${event.timestamp_sdk} < ${lastTimestamp}`, event);
        continue;
      }
      lastTimestamp = event.timestamp_sdk;
    }

    // Check prev_sig chain link
    if (i > 0) {
      if (event.prev_sig !== lastSig) {
        recordBreak(i, `Chain break at event ${i}: prev_sig does not match prior event's sdk_sig`, event);
        continue;
      }
    }

    // Recompute the shared payload; formats 1 and 2 ignore the decision
    // argument entirely, so one call site verifies every format. Read through
    // the SAME reader the signer used — two readers that disagree about an
    // absent field would make every event look tampered with.
    const sigPayload = signaturePayload(
      chainFormat,
      event.sdk_session_id!,
      event.seq_no,
      event.timestamp_sdk ?? 0,
      event.prompt ?? '',
      event.response ?? '',
      event.prev_sig ?? null,
      decisionFieldsOf(event as unknown as Record<string, unknown>, format)
    );

    if (signingKey !== null) {
      const expectedSig = createHmac('sha256', signingKey).update(sigPayload).digest('hex');
      if (!signatureMatches(event.sdk_sig, expectedSig)) {
        recordBreak(i, `Signature mismatch at event ${i}`, event);
        continue;
      }
    }

    lastSig = event.sdk_sig ?? null;

    const deviceSig = (event as { device_sig?: unknown }).device_sig;
    if (typeof deviceSig === 'string') {
      deviceSignedEvents++;
    }
    if (deviceChecked) {
      // The non-repudiation tier: the device seal must be present, by a
      // pinned key, and valid over the SAME payload. These breaks do not
      // re-anchor — the chain state above already advanced on the stored
      // fields.
      const keyId = (event as { device_key_id?: unknown }).device_key_id;
      if (typeof deviceSig !== 'string') {
        breaks.push({ index: i, reason: `Device signature missing at event ${i}` });
        continue;
      }
      if (typeof keyId !== 'string' || !pinned.has(keyId)) {
        const shown = typeof keyId === 'string' ? keyId : 'no usable device_key_id';
        breaks.push({
          index: i,
          reason: `Device key unknown at event ${i}: ${shown} is not among the pinned keys`,
        });
        continue;
      }
      if (verifyDeviceSig(pinned.get(keyId)!, keyId, sigPayload, deviceSig) !== true) {
        breaks.push({ index: i, reason: `Device signature mismatch at event ${i}` });
        continue;
      }
    }

    // Counted only after the event's own signature verified, and only in the
    // prefix before the first break — the tally a caller acts on must not
    // change because scanning now continues past a break. And read through
    // readAuditGapClaim, which requires the event to BE a marker — parsing the
    // prompt of every event let a user forge a loss declaration by typing one.
    if (breaks.length === 0) {
      const gap = readAuditGapClaim(event);
      if (gap) {
        gapMarkers++;
        eventsDeclaredLost += gap.dropped;
      }
    }
  }

  if (breaks.length > 0) {
    return {
      valid: false,
      brokenAt: breaks[0].index,
      reason: breaks[0].reason,
      eventsVerified: breaks[0].index,
      gapMarkers,
      eventsDeclaredLost,
      breaks,
      ...(chainFormat !== undefined ? { chainFormat } : {}),
      deviceSignedEvents,
      deviceChecked,
    };
  }

  return {
    valid: true,
    eventsVerified: events.length,
    gapMarkers,
    eventsDeclaredLost,
    breaks,
    chainFormat,
    deviceSignedEvents,
    deviceChecked,
  };
}
