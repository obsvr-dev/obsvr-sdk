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
 * WHY THE COUNT LIVES IN `prompt`: the HMAC preimage covers a content hash
 * of `prompt` and `response` (in every chain format — see chain-format.ts),
 * and metadata is deliberately NOT in it, so a count carried only in metadata
 * could be edited from 10,000 to 1 without breaking a single signature — a
 * tamper-evident record whose one load-bearing number is not tamper-evident. Putting
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

/** Events explicitly refused inside an otherwise terminal ingest response. */
export const AUDIT_GAP_REASON_INGEST_REJECTED = "ingest_rejected";

/** Events discarded after a non-retryable delivery failure. */
export const AUDIT_GAP_REASON_PERMANENT_FAILURE = "permanent_failure";

/** Events discarded after consuming their complete retry budget. */
export const AUDIT_GAP_REASON_RETRY_EXHAUSTED = "retry_exhausted";

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
 *
 * CONTENT ONLY — this does not decide whether the event IS a marker. Callers on
 * the verification path must use `readAuditGapClaim`, which also requires the
 * event to be one the SDK emitted as a marker. See that function for why.
 */
export function parseAuditGapPrompt(prompt: unknown): AuditGapClaim | null {
  if (typeof prompt !== "string") return null;
  const match = AUDIT_GAP_PROMPT_RE.exec(prompt);
  if (!match) return null;
  return { dropped: Number(match[1]), reason: match[2] };
}

/** `source` stamped on a marker event, alongside AUDIT_GAP_OPERATION. */
export const AUDIT_GAP_SOURCE = "obsvr_sdk";

/**
 * Is this event a gap marker, and if so what does it declare?
 *
 * THE DEFECT THIS CLOSES. The verifier used to call `parseAuditGapPrompt` on
 * the `prompt` of EVERY event it verified, with no discriminator at all. The
 * reasoning that put the count in the signed content was right — metadata is
 * unsigned, so a count carried only there could be edited from 10,000 to 1
 * without breaking a signature — but it placed a governance claim in the one
 * field a user fully controls, and then trusted any event that contained it.
 *
 * So a prompt reading exactly
 *
 *     obsvr:audit-gap/1 dropped=999999 reason=queue_overflow
 *
 * produced a legitimately-signed event that the verifier reported as
 * `{ valid: true, gapMarkers: 1, eventsDeclaredLost: 999999 }` — a user
 * fabricating a million lost events, with a valid chain, by typing a string.
 *
 * REACHABILITY, measured rather than assumed. MOST of the `wrap()` path is
 * immune by accident: the OpenAI/Anthropic extractors store `"user: <content>"`,
 * and the marker pattern is anchored, so a prompt through those can never
 * match. That is NOT true of the whole front door, and saying "the wrap() path
 * is immune" overstated it: `extractors/google.ts:115` returns a bare string
 * unchanged for the Gemini shorthand `generateContent('text')`, and
 * `wrapper.ts:698` routes provider `google` straight to it, so that prompt is
 * stored unprefixed and does parse as a marker. **The LangChain integration is
 * likewise not immune** — `handleLLMStart` stores `prompts.join("\n")`, a bare
 * user-controlled string.
 *
 * None of these are exploitable end-to-end, because the discriminator below
 * rejects them on `operation` — but the reachability reasoning was wrong, and a
 * later change that weakened the discriminator would have been reviewed against
 * a comment claiming an immunity the extractors do not provide.
 *
 * The discriminator is `operation`, which the sender stamps as `audit.gap` and
 * no user-facing call path produces.
 *
 * WHAT THIS DOES NOT CLOSE, stated because it is a real residual: `operation`
 * is NOT in the signature preimage, so a party who can edit a STORED event can
 * still set `operation` to `audit.gap` on an event whose prompt already parses
 * as a marker. That needs both capabilities at once, where before it needed
 * only the ability to type a prompt. Closing it entirely means signing
 * `operation`, which is a chain-format change and is not made here.
 */
export function readAuditGapClaim(event: unknown): AuditGapClaim | null {
  if (typeof event !== "object" || event === null) return null;
  const e = event as { operation?: unknown; prompt?: unknown };
  if (e.operation !== AUDIT_GAP_OPERATION) return null;
  return parseAuditGapPrompt(e.prompt);
}
