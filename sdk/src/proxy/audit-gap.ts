/**
 * Audit gap markers — the signed record of events that never reached the chain.
 *
 * The bounded sender queue drops events when it is full. Those drops happen
 * BEFORE a sequence number is assigned, so the surviving chain is contiguous
 * and verifies clean: the record says nothing happened, when in a saturated
 * burst most of what happened is missing. Counters in `getSenderStats()` see
 * it, but counters live in the process that lost the events and are not
 * evidence — they are gone the moment it exits.
 *
 * A gap marker closes that: one real, signed, chain-linked event that states
 * how many events were lost immediately before it. It is emitted at the first
 * moment the queue has room again, so it occupies the chain position between
 * the last event that survived and the first event after the loss.
 *
 * WHY THE COUNT LIVES IN `prompt`: the HMAC preimage is
 * `session | seq | timestamp | sha256(prompt + response) | prev_sig`. Metadata
 * is deliberately NOT in it, so a count carried only in metadata could be
 * edited from 10,000 to 1 without breaking a single signature — a tamper-
 * evident record whose one load-bearing number is not tamper-evident. Putting
 * the canonical statement in the signed content preimage costs no chain-format
 * change and no verifier special case: the marker verifies exactly like any
 * other event, and its claim is covered by the same HMAC. The structured copy
 * in `metadata.obsvr_audit_gap` exists for querying; when the two disagree,
 * the signed `prompt` is the one that means anything.
 *
 * This module is dependency-free on purpose — both the sender (which writes
 * markers) and the verifier (which reads them) import it, and the verifier
 * must not pull in the sender's module-level state to read a string.
 *
 * @packageDocumentation
 */

/**
 * Preimage format version. Bumping it changes the signed bytes, so a reader
 * can tell a marker it fully understands from one written by a newer SDK.
 */
export const AUDIT_GAP_FORMAT = "obsvr:audit-gap/1";

/** Events dropped because the bounded sender queue was full. */
export const AUDIT_GAP_REASON_QUEUE_OVERFLOW = "queue_overflow";

/** Reserved metadata key carrying the structured (unsigned) copy of the claim. */
export const AUDIT_GAP_METADATA_KEY = "obsvr_audit_gap";

/** `metadata.governance_event` value, matching the `governance_disabled` precedent. */
export const AUDIT_GAP_GOVERNANCE_EVENT = "audit_gap";

/** `operation` stamped on a marker event. */
export const AUDIT_GAP_OPERATION = "audit.gap";

/** What a marker declares: how many events were lost, and to what. */
export interface AuditGapClaim {
  dropped: number;
  reason: string;
}

/**
 * The canonical signed statement of a gap.
 *
 * Byte-identical in both SDKs — it goes through SHA-256 into an HMAC, so a
 * single character of drift makes the two languages sign different markers.
 * Pinned by `conformance/fixtures/audit_gap.json`.
 */
export function formatAuditGapPrompt(
  dropped: number,
  reason: string = AUDIT_GAP_REASON_QUEUE_OVERFLOW
): string {
  return `${AUDIT_GAP_FORMAT} dropped=${dropped} reason=${reason}`;
}

/** Strict shape of a marker preimage; anything else is an ordinary event. */
const AUDIT_GAP_PROMPT_RE = new RegExp(
  `^${AUDIT_GAP_FORMAT.replace(/[/]/g, "\\/")} dropped=(\\d+) reason=([a-z0-9_]+)$`
);

/**
 * Read a marker's claim back out of its signed content, or null if this is not
 * a marker. Deliberately strict: a near-miss is treated as an ordinary event
 * rather than guessed at, because the alternative is inventing a loss count
 * from a string that was never a marker.
 */
export function parseAuditGapPrompt(prompt: unknown): AuditGapClaim | null {
  if (typeof prompt !== "string") return null;
  const match = AUDIT_GAP_PROMPT_RE.exec(prompt);
  if (!match) return null;
  return { dropped: Number(match[1]), reason: match[2] };
}
