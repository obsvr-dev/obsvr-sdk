/**
 * Fire-and-Forget Audit Sender
 *
 * Non-blocking audit event sender with bounded queue and backoff.
 * Never blocks the main LLM response path.
 *
 * @packageDocumentation
 */

import { randomUUID, createHmac, createHash } from "node:crypto";
import type { AuditEvent, QueueItem, BackoffState, ResolvedConfig } from "../types.js";
import { debugLog } from "../../utils/logger.js";
import { mirrorToOtel } from "../otel-mirror.js";
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

/** Delivery verdict per request (failure taxonomy, E31): retrying a
 * permanent failure only burns quota and hides the bug. */
type SendVerdict = "ok" | "retryable" | "permanent";

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
};

/** Snapshot of delivery counters (enqueued/sent/retries/drops). */
export function getSenderStats(): typeof senderStats {
  return { ...senderStats };
}

/** Classify an HTTP status (twin of the Python sender's _classify_status). */
function classifyStatus(status: number, path: string): SendVerdict {
  if (status >= 200 && status < 300) return "ok";
  // Server-side policy block on the single-event path: final verdict.
  if (status === 403 && path === INGEST_PATH) return "ok";
  if (status === 408 || status === 429 || status >= 500) return "retryable";
  if (status >= 400 && status < 500) return "permanent";
  return "retryable";
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

/**
 * Currently processing flag
 */
let isProcessing = false;

/**
 * Number of events dropped due to a full queue
 */
let droppedCount = 0;

// ─── SDK integrity state (Phase 1 + 2 + 3) ───────────────────────────────────

/** Stable session UUID for this SDK process lifetime - groups the monotonic sequence */
const sdkSessionId: string = randomUUID();

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
 * Send a single audit event to the backend
 */
async function sendEvent(
  config: ResolvedConfig,
  event: AuditEvent
): Promise<SendVerdict> {
  const url = `${config.ingest_url}${INGEST_PATH}`;

  let verdict: SendVerdict;
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), config.timeout);
    if (typeof timeoutId === "object" && timeoutId.unref) timeoutId.unref();

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        [API_KEY_HEADER]: config.api_key,
      },
      body: JSON.stringify(event),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);
    verdict = classifyStatus(response.status, INGEST_PATH);
    if (verdict === "ok") {
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
  }
  if (verdict === "ok") resetBackoff();
  else if (verdict === "retryable") applyBackoff();
  return verdict;
}

/**
 * Send multiple audit events in one request to /ingest/batch.
 * The server accepts/rejects per event, so a policy-blocked or duplicate
 * event in the batch never costs the others. Returns false only for
 * transport-level failures (429, network, 5xx) that warrant a retry.
 */
async function sendEventBatch(
  config: ResolvedConfig,
  events: AuditEvent[]
): Promise<SendVerdict> {
  const url = `${config.ingest_url}${INGEST_BATCH_PATH}`;

  let verdict: SendVerdict;
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), config.timeout);
    if (typeof timeoutId === "object" && timeoutId.unref) timeoutId.unref();

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        [API_KEY_HEADER]: config.api_key,
      },
      body: JSON.stringify(events),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);
    verdict = classifyStatus(response.status, INGEST_BATCH_PATH);

    if (verdict === "ok") {
      // Per-event rejects (policy_blocked, duplicate_event, ...) are final -
      // log them, never retry them.
      try {
        const body = (await response.json()) as {
          count?: number;
          rejected?: Array<{ index: number; error: string; message?: string }>;
        };
        if (body.rejected && body.rejected.length > 0) {
          for (const r of body.rejected) {
            const ev = events[r.index];
            debugLog(
              config,
              "warn",
              `Audit event rejected by server (${r.error}) - dropping: ${ev?.request_id ?? `index ${r.index}`}`
            );
          }
        }
        debugLog(config, "info", `Audit batch sent: ${body.count ?? events.length} accepted`);
      } catch {
        debugLog(config, "info", `Audit batch sent: ${events.length} events`);
      }
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
  }
  if (verdict === "ok") resetBackoff();
  else if (verdict === "retryable") applyBackoff();
  return verdict;
}

/**
 * Requeue items at the front of the queue after a transport failure,
 * preserving order, up to MAX_SEND_RETRIES attempts per item. Items past
 * the retry budget are dropped and counted.
 */
function requeueFront(config: ResolvedConfig, items: QueueItem[]): void {
  for (let i = items.length - 1; i >= 0; i--) {
    const item = items[i];
    if (item.retries < MAX_SEND_RETRIES) {
      item.retries += 1;
      senderStats.retries++;
      pendingQueue.unshift(item);
    } else {
      droppedCount++;
      senderStats.dropped_retry_exhausted++;
      debugLog(
        config,
        "warn",
        `Audit event dropped after ${item.retries} retries: ${item.event.request_id} (total dropped: ${droppedCount})`
      );
    }
  }
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

  try {
    while (pendingQueue.length > 0) {
      if (isInBackoff()) {
        // Wait until backoff period ends
        const waitTime = backoffState.until - Date.now();
        debugLog(config, "info", `Waiting ${waitTime}ms for backoff`);
        await new Promise<void>((resolve) => {
          const t = setTimeout(resolve, waitTime);
          if (typeof t === "object" && t.unref) t.unref();
        });
      }

      // Batch bounded by BOTH item count and serialized bytes (E13/E34):
      // large prompts split across requests instead of failing the batch.
      const items: QueueItem[] = [];
      let batchBytes = 0;
      while (items.length < SEND_BATCH_SIZE && pendingQueue.length > 0) {
        const next = pendingQueue[0];
        const nextBytes = JSON.stringify(next.event).length;
        if (items.length > 0 && batchBytes + nextBytes > MAX_BATCH_BYTES) break;
        pendingQueue.shift();
        items.push(next);
        batchBytes += nextBytes;
      }
      if (items.length === 0) break;

      const verdict =
        items.length === 1
          ? await sendEvent(config, items[0].event)
          : await sendEventBatch(config, items.map((i) => i.event));

      if (verdict === "ok") {
        senderStats.sent += items.length;
      } else if (verdict === "permanent") {
        // The same bytes will always fail (bad key, malformed event, body
        // too large): dead-letter now, loudly, instead of burning retries.
        droppedCount += items.length;
        senderStats.dropped_permanent += items.length;
        debugLog(
          config,
          "warn",
          `Audit batch dead-lettered after permanent failure: ${items.length} event(s) (total dropped: ${droppedCount})`
        );
      } else {
        requeueFront(config, items);
      }
    }
  } finally {
    isProcessing = false;
  }
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
  if (JSON.stringify(md).length <= METADATA_BUDGET_CHARS) return;

  // 1. The span attribute bag is the usual culprit — collapse it first.
  const span = md.obsvr_span as Record<string, unknown> | undefined;
  if (span && typeof span === "object" && "attributes" in span) {
    md.obsvr_span = { ...span, attributes: { _trimmed: true } };
    if (JSON.stringify(md).length <= METADATA_BUDGET_CHARS) {
      md._obsvr_metadata_trimmed = true;
      return;
    }
  }
  // 2. Still over: keep only the reserved grouping/provenance keys.
  const trimmed: Record<string, unknown> = { _obsvr_metadata_trimmed: true };
  for (const k of RESERVED_META_KEYS) {
    if (k in md) trimmed[k] = md[k];
  }
  event.metadata = trimmed;
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
  // Drop if queue is full (prevents memory growth)
  if (pendingQueue.length >= MAX_QUEUE_SIZE) {
    droppedCount++;
    senderStats.dropped_overflow++;
    debugLog(config, "warn", `Audit queue full, dropping event (total dropped: ${droppedCount})`);
    return;
  }

  // Reconcile the event's wire shape with the ingest schema before signing.
  normalizeWireShape(event);

  // ── Phase 1: Stamp sequence / session fields ──────────────────────────────
  event.sdk_session_id = sdkSessionId;
  event.seq_no = ++seqNo;
  event.timestamp_sdk = Date.now();
  // Forensics: the event alone should say which SDK build evaluated it,
  // without correlating against the fleet registry timeline. Not part of
  // the signature payload, so the chain format stays version-independent.
  event.sdk_version = `node/${SDK_VERSION}`;

  // ── Phase 3: Chain-link to previous event ────────────────────────────────
  if (lastSig !== null) {
    event.prev_sig = lastSig;
  }

  // ── Phase 2: Compute HMAC-SHA256 signature ────────────────────────────────
  const key = getOrDeriveSigningKey(config.api_key);
  const contentHash = createHash("sha256")
    .update((event.prompt ?? "") + (event.response ?? ""))
    .digest("hex");
  const sigPayload = [
    event.sdk_session_id,
    String(event.seq_no),
    String(event.timestamp_sdk),
    contentHash,
    event.prev_sig ?? "",  // Phase 3: bind prev_sig into the signature
  ].join("|");
  event.sdk_sig = createHmac("sha256", key)
    .update(sigPayload)
    .digest("hex");

  // Update chain state for the next event
  lastSig = event.sdk_sig;

  // Optional OTel mirror - fire-and-forget, never affects the audit path
  mirrorToOtel(config, event);

  // Add to queue
  pendingQueue.push({
    event,
    timestamp: Date.now(),
    retries: 0,
  });
  senderStats.enqueued++;

  // Start processing asynchronously (fire-and-forget)
  processQueue(config).catch((error) => {
    debugLog(
      config,
      "error",
      "Queue processing error:",
      error instanceof Error ? error.message : String(error)
    );
  });
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

  // Deliberately REF'd timers: an explicit flush is a request to keep the
  // process alive until the queue drains (or the timeout hits). Unref'd
  // timers here let Node exit mid-flush with events still queued.
  while (
    (pendingQueue.length > 0 || isProcessing) &&
    Date.now() - startTime < timeoutMs
  ) {
    await processQueue(config);
    if (pendingQueue.length > 0 || isProcessing) {
      await new Promise<void>((resolve) => setTimeout(resolve, 50));
    }
  }

  if (pendingQueue.length > 0) {
    debugLog(
      config,
      "warn",
      `Flush timeout: ${pendingQueue.length} events remaining`
    );
  }
}

// M-1: Idempotency guard - prevents duplicate signal handler registration
let handlersRegistered = false;
/** Guards against the beforeExit -> flush -> beforeExit loop. */
let exitFlushStarted = false;

/**
 * Setup exit handlers so queued audit events survive process shutdown.
 *
 * - beforeExit: the loop is about to go idle; an awaited flush (ref'd timers)
 *   keeps it alive until the queue drains or the budget elapses. Guarded so
 *   the flush itself does not retrigger beforeExit forever.
 * - SIGTERM/SIGINT: flush within a bounded budget, then exit with the
 *   conventional signal exit code. Without the explicit exit, registering a
 *   handler would swallow the signal entirely.
 */
export function setupExitHandlers(config: ResolvedConfig): void {
  if (handlersRegistered) return;

  if (typeof process !== "undefined" && process.on) {
    process.on("beforeExit", () => {
      if (exitFlushStarted || pendingQueue.length === 0) return;
      exitFlushStarted = true;
      flushQueue(config, 2000)
        .catch(() => { /* swallow errors during shutdown */ })
        .finally(() => {
          exitFlushStarted = false;
        });
    });

    const signalHandler = (signal: "SIGTERM" | "SIGINT") => {
      if (exitFlushStarted) return;
      exitFlushStarted = true;
      const code = signal === "SIGTERM" ? 143 : 130;
      flushQueue(config, 2000)
        .catch(() => { /* swallow errors during shutdown */ })
        .finally(() => process.exit(code));
    };
    process.on("SIGTERM", () => signalHandler("SIGTERM"));
    process.on("SIGINT", () => signalHandler("SIGINT"));

    handlersRegistered = true;
    debugLog(config, "info", "Exit handlers registered");
  }
}

/**
 * Reset sender state (for testing only)
 * @internal
 */
export function _resetSender(): void {
  pendingQueue.length = 0;
  backoffState.until = 0;
  backoffState.multiplier = 1;
  isProcessing = false;
  droppedCount = 0;
  for (const k of Object.keys(senderStats) as Array<keyof typeof senderStats>) {
    senderStats[k] = 0;
  }
  seqNo = 0;
  lastSig = null;
  signingKey = null;
  signingKeySource = null;
  handlersRegistered = false;
  exitFlushStarted = false;
}
