/**
 * Fire-and-Forget Audit Sender
 *
 * Non-blocking audit event sender with bounded queue and backoff.
 * Never blocks the main LLM response path.
 *
 * @packageDocumentation
 */

import { randomUUID, createHmac } from "node:crypto";
import {
  SOURCE_LINEAGE_METADATA_KEY,
  sourceLineageHashFromMetadata,
} from "../source-lineage.js";
import type { AuditEvent, QueueItem, BackoffState, ResolvedConfig } from "../types.js";
import { debugLog } from "../../utils/logger.js";
import { mirrorToOtel } from "../otel-mirror.js";
import {
  CHAIN_FORMAT_CURRENT,
  decisionFieldsOf,
  signaturePayload,
} from "../chain-format.js";
import {
  AUDIT_GAP_GOVERNANCE_EVENT,
  AUDIT_GAP_METADATA_KEY,
  AUDIT_GAP_OPERATION,
  AUDIT_GAP_REASON_INGEST_REJECTED,
  AUDIT_GAP_REASON_PERMANENT_FAILURE,
  AUDIT_GAP_REASON_QUEUE_OVERFLOW,
  AUDIT_GAP_REASON_RETRY_EXHAUSTED,
  formatAuditGapPrompt,
  readAuditGapClaim,
} from "../audit-gap.js";
import {
  MAX_QUEUE_SIZE,
  SEND_BATCH_SIZE,
  MAX_BATCH_BYTES,
  MAX_SEND_RETRIES,
  INITIAL_BACKOFF_MS,
  MAX_BACKOFF_MS,
  INGEST_PATH,
  INGEST_BATCH_PATH,
  API_KEY_HEADER,
  SDK_VERSION,
} from "../../constants.js";
import {
  acknowledgeDurableEvent,
  configureDurableOutbox,
  deadLetterDurableEvent,
  durableFailureMode,
  durableOutboxEnabled,
  getDurableOutboxStatus,
  markDurableRecordsReplayed,
  pendingDurableRecords,
  persistDurableEvent,
  resetDurableOutbox,
} from './durable-outbox.js';

/** Delivery verdict per request (failure taxonomy, E31): retrying a
 * permanent failure only burns quota and hides the bug. */
type SendVerdict = "ok" | "rejected" | "retryable" | "permanent";

/**
 * Structured delivery counters (E33): loss must be VISIBLE in the fleet
 * view, not just detectable at chain verification. Reported on the
 * /policies status poll via getSenderStats().
 */
const senderStats = {
  enqueued: 0,
  sent: 0,
  retries: 0,
  dropped_overflow: 0,
  dropped_permanent: 0,
  dropped_retry_exhausted: 0,
  /**
   * Events the server ACCEPTED the request for but REFUSED individually
   * (per-event rejects inside a 2xx batch response). Deliberately its own
   * bucket, not folded into the dropped_* aggregate above: a server-refused
   * event and a never-delivered event are different audit stories, and only
   * the first one means the server saw the event and said no.
   */
  dropped_rejected: 0,
  /** Signed gap markers emitted (see audit-gap.ts). */
  gap_markers: 0,
  /** Dropped events those markers have put on the record. */
  gap_events_declared: 0,
  durable_write_failures: 0,
  durable_deferred: 0,
};

/** Snapshot of delivery counters (enqueued/sent/retries/drops). */
export function getSenderStats(): typeof senderStats {
  return { ...senderStats };
}

/**
 * Classify an HTTP status (twin of the Python sender's _classify_status).
 *
 * ONLY A 2xx IS A DELIVERY. A 403 on the single-event path used to classify
 * "ok", on the reasoning that a server-side policy refusal is a final verdict
 * rather than something to retry. Final it is; delivered it is not, and "ok" is
 * the verdict that increments `sent`. The batch path had it right all along —
 * it reads the response body and books per-event refusals as `dropped_rejected`
 * — so the same 403 was counted as a delivery or as a loss depending only on
 * how many events happened to be queued behind it. Worse, the status is shared:
 * a server that answers 403 for `invalid_sdk_signature` produced a run where
 * the SDK reported 100% delivery and the sink had stored nothing.
 *
 * "rejected" is its own verdict rather than "permanent" because the server saw
 * the event and said no, which is a different audit story from never having
 * reached it — the same distinction `dropped_rejected` already draws.
 *
 * 3xx is permanent: `fetch` follows redirects by default and a 301/302/303 on a
 * POST is re-issued as a body-less GET, so the event is discarded in the client
 * and the redirect target's 200 is what this would otherwise see. The redirect
 * is refused at the call site instead (`redirect: "manual"`), and an ingest URL
 * that redirects is a misconfiguration to fix, not a condition to retry around.
 */
function classifyStatus(status: number, path: string): SendVerdict {
  if (status >= 200 && status < 300) return "ok";
  if (status === 403 && path === INGEST_PATH) return "rejected";
  if (status === 408 || status === 429 || status >= 500) return "retryable";
  if (status >= 300 && status < 500) return "permanent";
  return "retryable";
}

/** Seconds between loss warnings; the first loss speaks immediately. */
const LOSS_WARN_INTERVAL_MS = 60_000;
let lossWarnedAt = 0;

/**
 * Say out loud, at DEFAULT settings, that audit events were lost.
 *
 * Everything else on this path speaks only under `debug: true`, and that is how
 * a run that delivered nothing looked like a run that delivered everything: the
 * counters knew, the counters are not exported, and the process that held them
 * exited. The same principle the config module states for configuration —
 * silent misconfiguration of a governance SDK is itself a governance failure —
 * applies at least as strongly to silent loss of the evidence, so this one is a
 * warning nobody has to opt into. Rate-limited rather than once-per-process: a
 * second outage an hour later is news again, and a burst is not.
 */
function warnEventsLost(count: number, reason: string): void {
  const now = Date.now();
  if (lossWarnedAt && now - lossWarnedAt < LOSS_WARN_INTERVAL_MS) return;
  lossWarnedAt = now;
  console.warn(
    `[obsvr] ${count} audit event(s) were NOT recorded (${reason}). The audit ` +
      `trail for this process is incomplete; getSenderStats() has the counts, ` +
      `and debug: true logs each one.`,
  );
}

/** The reject code ingest returns for an event it has already recorded. */
const DUPLICATE_EVENT_ERROR = "duplicate_event";

/**
 * Whether a 409 body is ingest's duplicate response.
 *
 * A duplicate means a retry raced a lost 2xx: the event is ALREADY durably
 * recorded, so this is idempotent success. Counting it as a drop would
 * fabricate a coverage gap for evidence that exists - the worst direction for
 * an audit counter to be wrong in. Only this exact code is absorbed: a 409
 * `sequence_fork` means that chain position belongs to a DIFFERENT signature
 * and must stay a failure. (Twin of the platform emitter's isDuplicateConflict
 * and of the Python sender's _is_duplicate_conflict.)
 */
function isDuplicateConflict(body: unknown): boolean {
  return (
    typeof body === "object" &&
    body !== null &&
    (body as { error?: unknown }).error === DUPLICATE_EVENT_ERROR
  );
}

/** Read a 409 body and report whether it is the duplicate response. An
 * unreadable or non-JSON body is NOT a duplicate: absorbing an unparseable
 * conflict would silently turn real failures into phantom successes. */
async function isDuplicateResponse(response: { json(): Promise<unknown> }): Promise<boolean> {
  try {
    return isDuplicateConflict(await response.json());
  } catch {
    return false;
  }
}

/**
 * Backoff state
 */
const backoffState: BackoffState = {
  until: 0,
  multiplier: 1,
};

/**
 * Pending queue
 */
const pendingQueue: QueueItem[] = [];
/** Outbox records already represented in the in-memory queue. */
const queuedOutboxIds = new Set<string>();

/** Invalidates asynchronous queue work when test-only sender state is reset. */
let senderGeneration = 0;

/**
 * Currently processing flag
 */
let isProcessing = false;

/**
 * Number of events dropped due to a full queue
 */
let droppedCount = 0;

/**
 * Optional client-held device signing identity (proxy/device-identity.ts).
 * Installed by init() when deviceSigningKeyFile is configured; null means
 * exactly the pre-existing behaviour — HMAC only.
 */
let deviceSigner: import("../device-identity.js").DeviceSigner | null = null;

/** Install (or clear) the device signing identity for this process. */
export function setDeviceSigner(
  signer: import("../device-identity.js").DeviceSigner | null,
): void {
  deviceSigner = signer;
}

/**
 * Overflow drops that no gap marker has declared yet. Incremented at the drop
 * point, zeroed when a marker carrying them is signed into the chain.
 */
let gapPendingCount = 0;

/** Markers emitted this session — the ordinal in a marker's request_id. */
let gapMarkerOrdinal = 0;

// ─── SDK integrity state (Phase 1 + 2 + 3) ───────────────────────────────────

/** Current session UUID. Post-sign delivery loss starts a fresh chain. */
let sdkSessionId: string = randomUUID();

/** Monotonic event counter - 1-based, increments per enqueued event */
let seqNo = 0;

/** sdk_sig of the last enqueued event, used to chain-link consecutive events */
let lastSig: string | null = null;

/** Signing key cached after first derivation (derived from api_key) */
let signingKey: Buffer | null = null;
/** M-6: Track the API key used to derive the current signing key */
let signingKeySource: string | null = null;

/**
 * Derive (once) and cache the HMAC signing key from the API key.
 * HMAC-Extract step (RFC 5869 §2.2): PRK = HMAC-SHA256(salt, apiKey)
 * Note: only the extract phase is used; no expand phase is applied.
 */
function getOrDeriveSigningKey(apiKey: string): Buffer {
  // M-6: Re-derive when the API key changes (e.g. after re-init)
  if (!signingKey || signingKeySource !== apiKey) {
    signingKey = createHmac("sha256", "obsvr-sdk-signing-v1")
      .update(apiKey)
      .digest();
    signingKeySource = apiKey;
  }
  return signingKey;
}

/**
 * Check if we're in backoff period
 */
function isInBackoff(): boolean {
  return Date.now() < backoffState.until;
}

/**
 * Jittered exponential backoff (equal jitter): the deterministic half
 * guarantees spacing, the random half prevents many clients from retrying
 * in lockstep after a shared ingest outage (E32).
 */
function applyBackoff(): void {
  const base = Math.min(
    INITIAL_BACKOFF_MS * backoffState.multiplier,
    MAX_BACKOFF_MS
  );
  const backoffMs = base * (0.5 + Math.random() / 2);
  backoffState.until = Date.now() + backoffMs;
  backoffState.multiplier *= 2;
}

/**
 * Reset backoff on successful request
 */
function resetBackoff(): void {
  backoffState.until = 0;
  backoffState.multiplier = 1;
}

/**
 * Send a single audit event to the backend.
 *
 * Returns the per-event refusal count alongside the verdict, exactly as the
 * batch path does. This path used to read no response body at all, so a 200
 * carrying `{"rejected": [...]}` counted as a clean delivery of the event the
 * server had just refused in that very response.
 */
async function sendEvent(
  config: ResolvedConfig,
  event: AuditEvent,
  generation: number,
): Promise<{ verdict: SendVerdict; rejected: number }> {
  const url = `${config.ingest_url}${INGEST_PATH}`;

  let verdict: SendVerdict;
  let rejected = 0;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), config.timeout);
  try {
    if (typeof timeoutId === "object" && timeoutId.unref) timeoutId.unref();

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        [API_KEY_HEADER]: config.api_key,
      },
      // Intentional delivery of the signed audit record to the validated,
      // configured ingest endpoint. Durable records use this same path when
      // replayed; the backend verifies their signature before acceptance.
      body: JSON.stringify(event),
      signal: controller.signal,
      // Never let a redirect turn an audit POST into a body-less GET. See
      // classifyStatus: the 3xx surfaces here and classifies permanent.
      redirect: "manual",
    });

    verdict = classifyStatus(response.status, INGEST_PATH);
    if (response.status === 409 && (await isDuplicateResponse(response))) {
      verdict = "ok";
      debugLog(config, "info", `Audit event already recorded (duplicate): ${event.request_id}`);
    } else if (verdict === "ok") {
      rejected = await countRejects(config, response, [event]);
      debugLog(config, "info", `Audit event sent: ${event.request_id}`);
    } else {
      debugLog(config, "warn", `Audit request failed (${verdict}): ${response.status}`);
    }
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      debugLog(config, "warn", "Audit request timed out");
    } else {
      debugLog(
        config,
        "warn",
        "Audit request error:",
        error instanceof Error ? error.message : String(error)
      );
    }
    verdict = "retryable";
  } finally {
    clearTimeout(timeoutId);
  }
  // The server answered on both "ok" and "rejected". The transport is healthy
  // whichever way it ruled, so the backoff window is cleared for both.
  if (generation === senderGeneration) {
    if (verdict === "ok" || verdict === "rejected") resetBackoff();
    else if (verdict === "retryable") applyBackoff();
  }
  return { verdict, rejected };
}

/**
 * Per-event refusals inside an ACCEPTED response, for one event or a batch.
 *
 * The request succeeded; the server refused individual events (policy_blocked,
 * duplicate_event, ...). Those refusals are final — never retried — but they
 * are also not deliveries, so counting them as sent would overstate coverage.
 * Shape: `{count?, rejected?: [{index, error, message?}]}`. Twin of the Python
 * sender's `_count_rejects`.
 */
async function countRejects(
  config: ResolvedConfig,
  response: { json(): Promise<unknown> },
  events: AuditEvent[],
): Promise<number> {
  let body: { count?: number; rejected?: Array<{ index: number; error: string }> };
  try {
    body = (await response.json()) as typeof body;
  } catch {
    // Absent, truncated, or not JSON means no rejects were reported, never a
    // failed delivery.
    debugLog(config, "info", `Audit batch sent: ${events.length} events`);
    return 0;
  }
  let drops = 0;
  let duplicates = 0;
  for (const entry of body?.rejected ?? []) {
    const id = events[entry.index]?.request_id ?? `index ${entry.index}`;
    if (entry.error === DUPLICATE_EVENT_ERROR) {
      duplicates++;
      debugLog(config, "info", `Audit event already recorded (duplicate): ${id}`);
      continue;
    }
    drops++;
    debugLog(config, "warn", `Audit event rejected by server (${entry.error}) - dropping: ${id}`);
  }
  // RECONCILE AGAINST THE ACCEPTED COUNT. The response states how many it took;
  // a server that took fewer than it was sent has refused the rest whether or
  // not it enumerated them, and crediting the difference to `sent` would
  // overstate coverage on the strength of a field the sender read and then
  // ignored. A duplicate counts toward the delivered side, not the shortfall:
  // the server did not take it because it already had it.
  if (typeof body?.count === "number" && Number.isFinite(body.count)) {
    const shortfall = events.length - body.count - duplicates;
    if (shortfall > drops) {
      debugLog(
        config,
        "warn",
        `Ingest accepted ${body.count} of ${events.length} audit events and enumerated ` +
          `${drops} refusal(s); counting the ${shortfall - drops} unaccounted event(s) as dropped`,
      );
      drops = shortfall;
    }
  }
  debugLog(config, "info", `Audit batch sent: ${body?.count ?? events.length} accepted`);
  // Never exceed the batch, and never below zero: a malformed body cannot
  // inflate the counter or manufacture deliveries.
  return Math.max(0, Math.min(drops, events.length));
}

/**
 * Send multiple audit events in one request to /ingest/batch.
 * The server accepts/rejects per event, so a policy-blocked or duplicate
 * event in the batch never costs the others. Returns "retryable" only for
 * transport-level failures (429, network, 5xx) that warrant a retry, plus
 * the count of events the server refused individually so the caller can
 * account for them (they were delivered, and refused - not sent).
 */
async function sendEventBatch(
  config: ResolvedConfig,
  events: AuditEvent[],
  generation: number,
): Promise<{ verdict: SendVerdict; rejected: number }> {
  const url = `${config.ingest_url}${INGEST_BATCH_PATH}`;

  let verdict: SendVerdict;
  let rejected = 0;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), config.timeout);
  try {
    if (typeof timeoutId === "object" && timeoutId.unref) timeoutId.unref();

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        [API_KEY_HEADER]: config.api_key,
      },
      // Intentional batch delivery of signed audit records to the validated,
      // configured ingest endpoint, including records replayed from the
      // owner-only durable outbox.
      body: JSON.stringify(events),
      signal: controller.signal,
      // Same reason as the single-event path: a followed redirect re-issues
      // the POST as a body-less GET and the target's 200 reads as delivery.
      redirect: "manual",
    });

    verdict = classifyStatus(response.status, INGEST_BATCH_PATH);

    if (verdict === "ok") {
      // Per-event rejects (policy_blocked, duplicate_event, ...) are final -
      // count them, never retry them. Counted rather than only logged:
      // SECURITY.md promises every drop is visible in the per-client delivery
      // counters, and a reject that only reaches the debug log is an invisible
      // one.
      rejected = await countRejects(config, response, events);
    } else if (response.status === 409 && (await isDuplicateResponse(response))) {
      // A re-submitted batch is itself the duplicate: every event in it was
      // already recorded on the earlier attempt.
      verdict = "ok";
      debugLog(config, "info", `Audit batch already recorded (duplicate): ${events.length} events`);
    } else {
      debugLog(config, "warn", `Audit batch request failed (${verdict}): ${response.status}`);
    }
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      debugLog(config, "warn", "Audit batch request timed out");
    } else {
      debugLog(
        config,
        "warn",
        "Audit batch request error:",
        error instanceof Error ? error.message : String(error)
      );
    }
    verdict = "retryable";
  } finally {
    clearTimeout(timeoutId);
  }
  if (generation === senderGeneration) {
    if (verdict === "ok" || verdict === "rejected") resetBackoff();
    else if (verdict === "retryable") applyBackoff();
  }
  return { verdict, rejected };
}

/**
 * Requeue items at the front of the queue after a transport failure,
 * preserving order, up to MAX_SEND_RETRIES attempts per item. Items past
 * the retry budget are dropped and counted.
 */
function requeueFront(config: ResolvedConfig, items: QueueItem[]): QueueItem[] {
  const exhausted: QueueItem[] = [];
  for (let i = items.length - 1; i >= 0; i--) {
    const item = items[i];
    if (item.retries < MAX_SEND_RETRIES) {
      item.retries += 1;
      senderStats.retries++;
      pendingQueue.unshift(item);
    } else {
      exhausted.unshift(item);
      droppedCount++;
      senderStats.dropped_retry_exhausted++;
      debugLog(
        config,
        "warn",
        `Audit event dropped after ${item.retries} retries: ${item.event.request_id} (total dropped: ${droppedCount})`
      );
      warnEventsLost(1, "retry budget exhausted");
      if (item.outboxId) {
        deadLetterDurableEvent(item.outboxId, AUDIT_GAP_REASON_RETRY_EXHAUSTED);
        queuedOutboxIds.delete(item.outboxId);
      }
    }
  }
  return exhausted;
}

/**
 * Process the pending queue.
 * Drains up to SEND_BATCH_SIZE events per request via /ingest/batch, so a
 * burst of N calls costs ~N/25 requests instead of N - which is what keeps
 * a busy app inside the ingest request rate limit. Transport failures
 * requeue with a bounded retry budget instead of silently dropping.
 */
async function processQueue(config: ResolvedConfig): Promise<void> {
  if (isProcessing) {
    return;
  }

  isProcessing = true;
  const generation = senderGeneration;

  try {
    refillDurableQueue();
    while (pendingQueue.length > 0) {
      if (generation !== senderGeneration) return;
      if (isInBackoff()) {
        // Wait until backoff period ends
        const waitTime = backoffState.until - Date.now();
        debugLog(config, "info", `Waiting ${waitTime}ms for backoff`);
        await new Promise<void>((resolve) => {
          const t = setTimeout(resolve, waitTime);
          if (typeof t === "object" && t.unref) t.unref();
        });
        if (generation !== senderGeneration) return;
      }

      // Batch bounded by BOTH item count and serialized bytes (E13/E34):
      // large prompts split across requests instead of failing the batch.
      const items: QueueItem[] = [];
      let batchBytes = 0;
      while (items.length < SEND_BATCH_SIZE && pendingQueue.length > 0) {
        const next = pendingQueue[0];
        // Durable records use one request each so an accepted/rejected verdict
        // can acknowledge or dead-letter the exact on-disk record.
        if (items.length > 0 && (next.outboxId || items[0].outboxId)) break;
        const nextIsGapMarker = readAuditGapClaim(next.event) !== null;
        // A marker is its own delivery unit. That makes a refusal attributable
        // to the marker itself, which is what lets the terminal-loss guard stop
        // instead of recursively emitting replacement markers forever.
        if (items.length > 0 && nextIsGapMarker) break;
        const nextBytes = JSON.stringify(next.event).length;
        if (items.length > 0 && batchBytes + nextBytes > MAX_BATCH_BYTES) break;
        pendingQueue.shift();
        items.push(next);
        batchBytes += nextBytes;
        if (nextIsGapMarker) break;
      }
      if (items.length === 0) break;

      const { verdict, rejected } =
        items.length === 1
          ? await sendEvent(config, items[0].event, generation)
          : await sendEventBatch(config, items.map((i) => i.event), generation);

      // `_resetSender()` starts a new lifecycle. Results from an earlier one
      // must not requeue stale events, mutate fresh counters, or emit loss
      // warnings after the test/application lifecycle that owned them ended.
      if (generation !== senderGeneration) return;

      if (verdict === "ok") {
        // Events the server refused individually were delivered but not
        // accepted: they count as rejected, never as sent.
        senderStats.sent += items.length - rejected;
        if (rejected > 0) {
          senderStats.dropped_rejected += rejected;
          droppedCount += rejected;
          warnEventsLost(rejected, "refused by the ingest service");
          declareDeliveryGap(
            config,
            items,
            rejected,
            AUDIT_GAP_REASON_INGEST_REJECTED,
          );
        }
        for (const item of items) {
          if (!item.outboxId) continue;
          if (rejected > 0) {
            deadLetterDurableEvent(item.outboxId, AUDIT_GAP_REASON_INGEST_REJECTED);
          } else {
            acknowledgeDurableEvent(item.outboxId);
          }
          queuedOutboxIds.delete(item.outboxId);
        }
      } else if (verdict === "rejected") {
        // The server saw the request and refused it outright. Final, so never
        // retried — and never counted as sent, because nothing was stored at
        // the other end.
        droppedCount += items.length;
        senderStats.dropped_rejected += items.length;
        debugLog(
          config,
          "warn",
          `Audit request refused by the ingest service: ${items.length} event(s) (total dropped: ${droppedCount})`
        );
        warnEventsLost(items.length, "refused by the ingest service");
        declareDeliveryGap(
          config,
          items,
          items.length,
          AUDIT_GAP_REASON_INGEST_REJECTED,
        );
        deadLetterItems(items, AUDIT_GAP_REASON_INGEST_REJECTED);
      } else if (verdict === "permanent") {
        // The same bytes will always fail (bad key, malformed event, body
        // too large): discard and count now instead of burning retries.
        droppedCount += items.length;
        senderStats.dropped_permanent += items.length;
        debugLog(
          config,
          "warn",
          `Audit batch discarded after permanent failure: ${items.length} event(s) (total dropped: ${droppedCount})`
        );
        warnEventsLost(items.length, "permanently undeliverable to the ingest service");
        declareDeliveryGap(
          config,
          items,
          items.length,
          AUDIT_GAP_REASON_PERMANENT_FAILURE,
        );
        deadLetterItems(items, AUDIT_GAP_REASON_PERMANENT_FAILURE);
      } else {
        const exhausted = requeueFront(config, items);
        if (exhausted.length > 0) {
          declareDeliveryGap(
            config,
            exhausted,
            exhausted.length,
            AUDIT_GAP_REASON_RETRY_EXHAUSTED,
          );
        }
      }
      refillDurableQueue();
    }
  } finally {
    if (generation === senderGeneration) isProcessing = false;
  }
}

function deadLetterItems(items: QueueItem[], reason: string): void {
  for (const item of items) {
    if (!item.outboxId) continue;
    deadLetterDurableEvent(item.outboxId, reason);
    queuedOutboxIds.delete(item.outboxId);
  }
}

/** Fill free memory slots from atomically persisted records, oldest first. */
function refillDurableQueue(): void {
  if (!durableOutboxEnabled() || pendingQueue.length >= MAX_QUEUE_SIZE) return;
  let replayed = 0;
  for (const record of pendingDurableRecords()) {
    if (pendingQueue.length >= MAX_QUEUE_SIZE) break;
    if (queuedOutboxIds.has(record.id)) continue;
    pendingQueue.push({
      event: record.event,
      timestamp: record.created_at_ms,
      retries: 0,
      outboxId: record.id,
    });
    queuedOutboxIds.add(record.id);
    replayed++;
  }
  if (replayed > 0) markDurableRecordsReplayed(replayed);
}

/** Configure and immediately replay the optional durable outbox. */
export function configureDurableDelivery(config: ResolvedConfig): void {
  configureDurableOutbox(config.durable_delivery);
  refillDurableQueue();
  if (pendingQueue.length > 0) {
    void processQueue(config).catch((error) => {
      debugLog(config, 'error', 'Durable outbox replay failed:', error);
    });
  }
}

export function getDeliveryStatus(): ReturnType<typeof getSenderStats> & {
  outbox: ReturnType<typeof getDurableOutboxStatus>;
} {
  return { ...getSenderStats(), outbox: getDurableOutboxStatus() };
}

/**
 * Normalize the event to the shape the ingest schema actually stores, so no
 * emitted provenance is silently dropped (verified against the ingest Zod
 * schema). Additive and idempotent — the HMAC preimage is unaffected.
 *
 * - `external_backend` (ADR-4) has NO top-level ingest field and is
 *   stripped; mirror it onto the preserved `metadata.obsvr_external_backend`
 *   channel so the external-policy-backend provenance survives.
 * - `delegation_chain/depth/scope` (C2) ARE top-level ingest columns but
 *   the SDK emits them inside `metadata`; promote them so the columns populate.
 */
function normalizeWireShape(event: AuditEvent): void {
  if (event.external_backend) {
    event.metadata = {
      ...(event.metadata ?? {}),
      obsvr_external_backend: event.external_backend,
    };
  }
  // Same route, same reason: ingest has no `content_provenance` column and
  // strips unknown top-level fields, so the top-level name alone would lose the
  // value silently. Mirror it onto the reserved metadata key the trimmer
  // preserves; drop the mirror once ingest declares the column.
  if (event.content_provenance) {
    event.metadata = {
      ...(event.metadata ?? {}),
      [CONTENT_PROVENANCE_METADATA_KEY]: event.content_provenance,
    };
  }
  const m = event.metadata as Record<string, unknown> | undefined;
  if (m) {
    if (event.delegation_chain === undefined && Array.isArray(m.delegation_chain)) {
      event.delegation_chain = m.delegation_chain as string[];
    }
    if (event.delegation_depth === undefined && typeof m.delegation_depth === "number") {
      event.delegation_depth = m.delegation_depth;
    }
    if (event.delegated_scope === undefined && Array.isArray(m.delegated_scope)) {
      event.delegated_scope = m.delegated_scope as string[];
    }
  }
  trimMetadataToBudget(event);
}

/**
 * Reserved-metadata key `content_provenance` rides on until ingest has a column
 * for it, following the `obsvr_tool_content_hash` carriage plan verbatim:
 *   1. (now) the SDK stamps both the top-level field and this key; consumers
 *      read it from metadata;
 *   2. ingest declares a `content_provenance` column and backfills from here;
 *   3. the SDK keeps mirroring for one minor release, then stops.
 * Nothing downstream depends on the top-level name until step 2, so steps 1
 * and 3 are additive and need no coordinated release.
 */
export const CONTENT_PROVENANCE_METADATA_KEY = "obsvr_content_provenance";

/** Budget for metadata, kept under the ingest 10 KB canonical cap with headroom. */
const METADATA_BUDGET_CHARS = 9000;
/** Grouping / provenance keys that must survive trimming (or trace/run links break). */
const RESERVED_META_KEYS = [
  "trace_id",
  "agent_run_id",
  "agent_run_name",
  "obsvr_span",
  "obsvr_telemetry",
  "obsvr_external_backend",
  "obsvr_tool_content_hash",
  SOURCE_LINEAGE_METADATA_KEY,
  CONTENT_PROVENANCE_METADATA_KEY,
  AUDIT_GAP_METADATA_KEY,
];

/**
 * the ingest canonicalizer REPLACES metadata wholesale with
 * `{"_truncated":true}` once it exceeds 10 KB — destroying `trace_id` /
 * `agent_run_id` / the span envelope and orphaning the event from its run and
 * trace. Trim proactively here so the grouping/provenance keys always survive:
 * first shrink the open span-attribute bag, then drop non-reserved keys.
 */
function trimMetadataToBudget(event: AuditEvent): void {
  const md = event.metadata as Record<string, unknown> | undefined;
  if (!md) return;
  if (withinBudget(md)) return;

  // 1. The span attribute bag is the usual culprit — collapse it first.
  const span = md.obsvr_span as Record<string, unknown> | undefined;
  if (span && typeof span === "object" && "attributes" in span) {
    md.obsvr_span = { ...span, attributes: { _trimmed: true } };
    if (withinBudget(md)) {
      md._obsvr_metadata_trimmed = true;
      return;
    }
  }
  // 2. Still over: keep only the reserved grouping/provenance keys.
  const trimmed: Record<string, unknown> = { _obsvr_metadata_trimmed: true };
  for (const k of RESERVED_META_KEYS) {
    if (!(k in md)) continue;
    try {
      trimmed[k] = md[k];
    } catch {
      // The one read the measurement guard does not cover: a hostile getter on
      // a RESERVED key. A grouping value that cannot be read is not a grouping
      // value, so it is dropped — the same thing the trim already costs an
      // over-budget event for every non-reserved key.
    }
  }
  event.metadata = trimmed;
}

/**
 * Is the metadata bag inside the budget? An unmeasurable bag counts as OVER.
 *
 * `metadata` is CALLER-SUPPLIED, and four ordinary shapes make `JSON.stringify`
 * throw: a getter that raises, a `BigInt`, a circular reference, a `toJSON` that
 * throws. This runs on the synchronous enqueue path, so an unguarded throw came
 * back out of the sender into the application's own call — the single named
 * exception to "an exception inside any detector layer never reaches your
 * application". Python's twin (`_trim_metadata_to_budget` in obsvr/events.py)
 * uses the same rule.
 *
 * Answering "over budget" rather than inventing a posture is the point. A bag
 * this cannot measure is a bag ingest's canonicalizer cannot measure either, and
 * ingest REPLACES metadata wholesale with `{"_truncated":true}` past 10 KB —
 * destroying `trace_id` / `agent_run_id` and orphaning the event from its run.
 * Taking the existing trim keeps the grouping keys, which is exactly what that
 * branch exists to do.
 */
function withinBudget(md: Record<string, unknown>): boolean {
  try {
    const serialized = JSON.stringify(md);
    // A `toJSON` returning undefined serializes to undefined, not a string.
    if (typeof serialized !== "string") return false;
    return serialized.length <= METADATA_BUDGET_CHARS;
  } catch {
    return false;
  }
}

/**
 * Build the gap-marker event declaring `dropped` lost events.
 *
 * Shaped after the `governance_disabled` event: an SDK-authored `policy_flag`
 * carrying its identity in `metadata.governance_event`, since ingest's
 * `event_type` enum has no member for a delivery-layer record and inventing
 * one would get the marker rejected as malformed — losing the record of loss
 * to the same failure it exists to report.
 *
 * `policy_version` is "none" rather than the live ruleset hash: no policy
 * evaluated this event, and stamping a hash would assert that one did.
 */
function buildGapMarker(
  config: ResolvedConfig,
  dropped: number,
  reason: string = AUDIT_GAP_REASON_QUEUE_OVERFLOW,
): AuditEvent {
  return {
    request_id: `audit-gap-${sdkSessionId}-${++gapMarkerOrdinal}`,
    environment: config.environment,
    region: config.default_region ?? "unknown",
    provider: "unknown",
    model: "none",
    operation: AUDIT_GAP_OPERATION,
    source: "obsvr_sdk",
    // The claim itself, in the signed content preimage (see audit-gap.ts).
    prompt: formatAuditGapPrompt(dropped, reason),
    response: "",
    success: true,
    latency_ms: 0,
    event_type: "policy_flag",
    policy_version: "none",
    action_taken: "allowed",
    action_reason: "none",
    action_source: "builtin",
    redacted_types: [],
    blocked_types: [],
    metadata: {
      governance_event: AUDIT_GAP_GOVERNANCE_EVENT,
      // Structured copy for querying. Unsigned — `prompt` is authoritative.
      [AUDIT_GAP_METADATA_KEY]: {
        dropped,
        reason,
      },
    },
  };
}

/**
 * Record loss of events that were already signed into a session.
 *
 * The old chain cannot honestly continue through a missing signature, so the
 * marker begins a fresh session. Already-signed queued events stay ahead of it;
 * the JavaScript turn is otherwise atomic, so every event signed afterward
 * links to the marker. A failed marker is counted and warned about, but never
 * replaced: recursive markers cannot make an unavailable ingest available.
 */
function declareDeliveryGap(
  config: ResolvedConfig,
  lostItems: QueueItem[],
  dropped: number,
  reason: string,
): void {
  if (dropped <= 0 || lostItems.some((item) => readAuditGapClaim(item.event) !== null)) {
    return;
  }

  sdkSessionId = randomUUID();
  seqNo = 0;
  lastSig = null;
  gapMarkerOrdinal = 0;
  senderStats.gap_markers++;
  senderStats.gap_events_declared += dropped;
  debugLog(
    config,
    "warn",
    `Starting a new signed audit session after ${dropped} lost event(s): ${reason}`,
  );
  // Queue first on this path. The normal sender mirrors before queueing, but a
  // synchronous OTel exporter can re-enter the SDK; it must not sign a future
  // event behind the marker and enqueue that event ahead of the marker.
  signAndEnqueue(config, buildGapMarker(config, dropped, reason), true);
}

/**
 * Put any undeclared overflow drops on the record.
 *
 * Unforced, this needs room for the marker AND the event whose arrival proved
 * there was room: a marker that displaced that event would drop it, re-open
 * the gap, and emit one marker per event for as long as the burst lasted.
 *
 * `force` is for the flush path, and it is the case that matters most — a
 * shutdown after a saturated burst finds the queue FULL, which is precisely
 * when the capacity rule would refuse and the loss would die with the process.
 * Forcing overshoots the bound by exactly one item, on a queue that is already
 * draining, to keep the one event that says the others are gone.
 */
function declarePendingGap(config: ResolvedConfig, force: boolean): void {
  if (gapPendingCount === 0) return;
  if (!force && pendingQueue.length + 2 > MAX_QUEUE_SIZE) return;

  const dropped = gapPendingCount;
  gapPendingCount = 0;
  senderStats.gap_markers++;
  senderStats.gap_events_declared += dropped;
  debugLog(
    config,
    "warn",
    `Recording audit gap in the signed chain: ${dropped} dropped event(s)`
  );
  signAndEnqueue(config, buildGapMarker(config, dropped));
}

/**
 * Enqueue an audit event for fire-and-forget sending
 *
 * @param config - Resolved configuration
 * @param event - Audit event to send
 */
export function enqueueAuditEvent(
  config: ResolvedConfig,
  event: AuditEvent
): void {
  // Drop if queue is full (prevents memory growth). The drop is counted AND
  // remembered: the counter is process-local and dies with the process, so
  // until a marker carries it into the signed chain the loss is not on the
  // record (see audit-gap.ts).
  if (pendingQueue.length >= MAX_QUEUE_SIZE) {
    droppedCount++;
    senderStats.dropped_overflow++;
    gapPendingCount++;
    debugLog(config, "warn", `Audit queue full, dropping event (total dropped: ${droppedCount})`);
    return;
  }

  // The queue has room, so the gap that just ended can be declared. Emitted
  // BEFORE this event so the marker sits between the last event that survived
  // and the first one after the loss.
  declarePendingGap(config, false);

  signAndEnqueue(config, event);
}

/**
 * Stamp, sign, chain-link, and queue an event. The caller has already
 * established there is room for it.
 */
function signAndEnqueue(
  config: ResolvedConfig,
  event: AuditEvent,
  enqueueBeforeMirror: boolean = false,
): void {
  const previousSeq = seqNo;
  const previousSig = lastSig;
  // Reconcile the event's wire shape with the ingest schema before signing.
  normalizeWireShape(event);
  const lineageHash = sourceLineageHashFromMetadata(event.metadata);
  if (lineageHash !== undefined) {
    event.source_lineage_hash = lineageHash;
  } else {
    // The signed claim is derived from the validated metadata envelope. A
    // caller-supplied top-level hash without that envelope is not evidence.
    delete event.source_lineage_hash;
  }

  // ── Phase 1: Stamp sequence / session fields ──────────────────────────────
  event.sdk_session_id = sdkSessionId;
  event.seq_no = ++seqNo;
  event.timestamp_sdk = Date.now();
  // Forensics: the event alone should say which SDK build evaluated it,
  // without correlating against the fleet registry timeline. Not part of
  // the signature payload, so the chain format stays version-independent.
  event.sdk_version = `node/${SDK_VERSION}`;
  // Which signing format this event verifies under (see proxy/chain-format.ts).
  // The field itself only routes the verifier; the format number is also the
  // leading element of the signature payload, so stripping or rewriting this
  // field can only fail verification, never redirect it.
  event.chain_format = CHAIN_FORMAT_CURRENT;

  // ── Phase 3: Chain-link to previous event ────────────────────────────────
  if (lastSig !== null) {
    event.prev_sig = lastSig;
  }

  // ── Phase 2: Compute HMAC-SHA256 signature ────────────────────────────────
  const key = getOrDeriveSigningKey(config.api_key);
  const sigPayload = signaturePayload(
    CHAIN_FORMAT_CURRENT,
    event.sdk_session_id,
    event.seq_no,
    event.timestamp_sdk,
    event.prompt ?? "",
    event.response ?? "",
    event.prev_sig ?? null,
    // Format 3: the verdict and its attribution are inside the signature. Read
    // through the shared reader so the verifier cannot disagree about the field
    // set. Signed LAST in the build, after every layer that can still change a
    // verdict has run — signing an interim decision would seal a value the
    // event does not carry.
    decisionFieldsOf(event as unknown as Record<string, unknown>, CHAIN_FORMAT_CURRENT)
  );
  event.sdk_sig = createHmac("sha256", key)
    .update(sigPayload)
    .digest("hex");

  if (deviceSigner !== null) {
    // The optional second seal: the SAME payload, signed by the
    // operator-held Ed25519 key. Additive by construction — the HMAC
    // preimage above is byte-identical with or without it, so every
    // existing chain and verifier is untouched, while a verifier that pins
    // this key gets non-repudiation against every party that does not hold
    // it (an API-key holder included). The key id is inside the device
    // preimage, so neither it nor the version label can be swapped without
    // breaking the signature.
    event.device_key_id = deviceSigner.keyId;
    event.device_sig = deviceSigner.signPayload(sigPayload);
  }

  // Update chain state for the next event
  lastSig = event.sdk_sig;

  let outboxId: string | undefined;
  try {
    outboxId = persistDurableEvent(event);
  } catch (error) {
    senderStats.durable_write_failures++;
    if (durableFailureMode() === 'error') {
      seqNo = previousSeq;
      lastSig = previousSig;
      throw new Error(
        `[obsvr] durable audit persistence failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    console.warn(
      `[obsvr] durable audit persistence failed; using memory-only delivery: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  const queueSignedEvent = (): void => {
    if (outboxId && pendingQueue.length >= MAX_QUEUE_SIZE) {
      senderStats.durable_deferred++;
      void processQueue(config);
      return;
    }
    pendingQueue.push({
      event,
      timestamp: Date.now(),
      retries: 0,
      ...(outboxId ? { outboxId } : {}),
    });
    if (outboxId) queuedOutboxIds.add(outboxId);
    senderStats.enqueued++;
    processQueue(config).catch((error) => {
      debugLog(
        config,
        "error",
        "Queue processing error:",
        error instanceof Error ? error.message : String(error)
      );
    });
  };

  // Normal events preserve the historical mirror-before-queue ordering: the
  // mirror reads the event before delivery can consume it. A fresh-session gap
  // marker reverses those two operations so a re-entrant exporter cannot queue
  // a future event ahead of the marker that its signature follows.
  if (enqueueBeforeMirror) queueSignedEvent();
  mirrorToOtel(config, event);
  if (!enqueueBeforeMirror) queueSignedEvent();
}

/**
 * Send an audit event immediately (fire-and-forget)
 *
 * This is a convenience function that enqueues and processes.
 */
export function sendAuditAsync(
  config: ResolvedConfig,
  event: AuditEvent
): void {
  enqueueAuditEvent(config, event);
}

/**
 * Sign an event in place and advance the chain, WITHOUT enqueuing or
 * delivering it. Test-only: the delivery path samples and can drop, which
 * makes it the wrong tool for a test that needs to inspect the signed event
 * itself. Twin of the way sdk-python's tests call sender.sign_event.
 * @internal
 */
export function signAndEnqueueForTest(
  config: ResolvedConfig,
  event: AuditEvent,
): void {
  signAndEnqueue(config, event);
}

/**
 * Get current queue size (for testing/monitoring)
 */
export function getQueueSize(): number {
  return pendingQueue.length;
}

/**
 * Get the number of events dropped due to a full queue
 */
export function getDroppedCount(): number {
  return droppedCount;
}

/**
 * Overflow drops not yet declared by a gap marker. Non-zero only between a
 * drop and the next moment the queue had room; a flush drives it to zero.
 */
export function getPendingGapCount(): number {
  return gapPendingCount;
}

/**
 * Flush all pending events (for graceful shutdown)
 *
 * @param config - Resolved configuration
 * @param timeoutMs - Maximum time to wait for flush
 */
export async function flushQueue(
  config: ResolvedConfig,
  timeoutMs: number = 5000
): Promise<void> {
  const startTime = Date.now();

  // Declare any outstanding gap first, so a shutdown that follows a saturated
  // burst still leaves the loss on the record. Forced: the queue is about to
  // drain, and a marker that misses this flush may never be written at all.
  declarePendingGap(config, true);
  refillDurableQueue();

  // Deliberately REF'd timers: an explicit flush is a request to keep the
  // process alive until the queue drains (or the timeout hits). Unref'd
  // timers here let Node exit mid-flush with events still queued.
  while (
    (pendingQueue.length > 0 || isProcessing || getDurableOutboxStatus().pending > 0) &&
    Date.now() - startTime < timeoutMs
  ) {
    await processQueue(config);
    refillDurableQueue();
    if (pendingQueue.length > 0 || isProcessing) {
      await new Promise<void>((resolve) => setTimeout(resolve, 50));
    }
  }

  if (pendingQueue.length > 0 || getDurableOutboxStatus().pending > 0) {
    debugLog(
      config,
      "warn",
      `Flush timeout: ${Math.max(pendingQueue.length, getDurableOutboxStatus().pending)} events remaining`
    );
  }
}

// M-1: Idempotency guard - prevents duplicate signal handler registration
let handlersRegistered = false;
/** Guards against the beforeExit -> flush -> beforeExit loop. */
let exitFlushStarted = false;
let beforeExitHandler: (() => void) | null = null;
let sigtermHandler: (() => void) | null = null;
let sigintHandler: (() => void) | null = null;

/**
 * Setup exit handlers so queued audit events survive process shutdown.
 *
 * - beforeExit: the loop is about to go idle; an awaited flush (ref'd timers)
 *   keeps it alive until the queue drains or the budget elapses. Guarded so
 *   the flush itself does not retrigger beforeExit forever.
 * - SIGTERM/SIGINT: flush within a bounded budget, and exit ONLY when nothing
 *   else is listening for that signal. See the note on ownership below.
 *
 * WHO OWNS TERMINATION. Attaching a signal listener replaces the runtime's
 * default disposition for that signal, so a library that attaches one and does
 * not exit swallows the signal outright — which is why the exit is here at all.
 * But an unconditional exit is worse: it ends the process while the host's own
 * shutdown is still draining connections or committing a transaction, and
 * wrapping a client is not consent to that. Measured before this was changed: a
 * host committing over 600ms was terminated 4ms after the signal, with nothing
 * queued to flush; with events pending it was terminated at the 2s budget, so a
 * drain longer than that died too.
 *
 * So ownership is decided WHEN THE SIGNAL FIRES rather than when this handler
 * registered — a host may install its shutdown after wrapping a client — and it
 * goes to the host whenever the host has a listener of its own. Sole listener,
 * and the exit is ours to restore. Anything else, and the queue tail is the
 * cheaper thing to lose.
 */
export function setupExitHandlers(config: ResolvedConfig): void {
  if (handlersRegistered) return;

  if (typeof process !== "undefined" && process.on) {
    beforeExitHandler = () => {
      if (
        exitFlushStarted ||
        (pendingQueue.length === 0 && getDurableOutboxStatus().pending === 0)
      ) return;
      exitFlushStarted = true;
      flushQueue(config, 2000)
        .catch(() => { /* swallow errors during shutdown */ })
        .finally(() => {
          exitFlushStarted = false;
        });
    };

    const signalHandler = (signal: "SIGTERM" | "SIGINT") => {
      if (exitFlushStarted) return;
      exitFlushStarted = true;
      const code = signal === "SIGTERM" ? 143 : 130;
      // No listenerCount to consult means no way to tell whether the host has
      // its own shutdown, and a swallowed signal hangs the process forever
      // where a truncated one merely ends it early. Keep the exit.
      const soleListener =
        typeof process.listenerCount !== "function" ||
        process.listenerCount(signal) <= 1;
      const flushed = flushQueue(config, 2000).catch(() => {
        /* swallow errors during shutdown */
      });
      if (soleListener) {
        void flushed.finally(() => process.exit(code));
      } else {
        // The host is shutting itself down. Flush beside it and let it choose
        // when the process ends; reset the guard so a later beforeExit can
        // still drain anything enqueued while it drained.
        void flushed.finally(() => {
          exitFlushStarted = false;
        });
      }
    };
    sigtermHandler = () => signalHandler("SIGTERM");
    sigintHandler = () => signalHandler("SIGINT");
    process.on("beforeExit", beforeExitHandler);
    process.on("SIGTERM", sigtermHandler);
    process.on("SIGINT", sigintHandler);

    handlersRegistered = true;
    debugLog(config, "info", "Exit handlers registered");
  }
}

/**
 * Reset sender state (for testing only)
 * @internal
 */
export function _resetSender(): void {
  senderGeneration++;
  if (typeof process !== "undefined" && process.removeListener) {
    if (beforeExitHandler) process.removeListener("beforeExit", beforeExitHandler);
    if (sigtermHandler) process.removeListener("SIGTERM", sigtermHandler);
    if (sigintHandler) process.removeListener("SIGINT", sigintHandler);
  }
  beforeExitHandler = null;
  sigtermHandler = null;
  sigintHandler = null;
  pendingQueue.length = 0;
  queuedOutboxIds.clear();
  resetDurableOutbox();
  backoffState.until = 0;
  backoffState.multiplier = 1;
  isProcessing = false;
  droppedCount = 0;
  gapPendingCount = 0;
  gapMarkerOrdinal = 0;
  for (const k of Object.keys(senderStats) as Array<keyof typeof senderStats>) {
    senderStats[k] = 0;
  }
  seqNo = 0;
  lastSig = null;
  deviceSigner = null;
  signingKey = null;
  signingKeySource = null;
  handlersRegistered = false;
  exitFlushStarted = false;
}
