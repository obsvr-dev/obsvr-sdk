/**
 * Fire-and-forget sender semantics — offline E2E.
 *
 * Drives the bounded-queue sender (proxy/sender/fire-and-forget.ts) two ways:
 *
 *   1) BATCH path: a burst > SEND_BATCH_SIZE (25) governed calls drains through
 *      /ingest/batch, so the number of ingest REQUESTS is far below the number
 *      of events; all events still arrive and the chain is gap-free.
 *   2) OVERFLOW drops: with ingest ACKs stalled, a burst well past
 *      MAX_QUEUE_SIZE (1000) fills the queue and overflow-drops the excess.
 *      Crucially, the drop happens in enqueueAuditEvent BEFORE seq_no is
 *      assigned, so the DELIVERED events stay a contiguous, gap-free chain.
 *      flushQueue returns honestly under a small timeout; getQueueSize stays
 *      bounded.
 *
 * Values source-verified from constants.ts: SEND_BATCH_SIZE=25, MAX_QUEUE_SIZE=1000.
 * Queue accessors are obsvr.getQueueSize() / obsvr.getDroppedCount() (getSenderStats
 * is internal / not exported).
 *
 *   node integrations/sender-semantics/test.mjs
 */
import { createServer } from "node:http";
import { obsvr } from "@obsvr/sdk";
import OpenAI from "openai";
import { startMockIngest } from "../../lib/mock-ingest.mjs";
import { check, done } from "../../lib/check.mjs";
import { assertSignedEvent, verifyCapturedChain } from "../../lib/assert-governance.mjs";

export const meta = { offline: true };

const API_KEY = process.env.OBSVR_API_KEY || "obsvr-test-key";
const SEND_BATCH_SIZE = 25; // source: sdk/src/constants.ts
const MAX_QUEUE_SIZE = 1000; // source: sdk/src/constants.ts

/** Offline OpenAI-shaped provider: 200 chat.completion to any POST. */
function startOpenAIStub() {
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          id: "chatcmpl-stub",
          object: "chat.completion",
          created: Math.floor(Date.now() / 1000),
          model: "gpt-4o",
          choices: [{ index: 0, message: { role: "assistant", content: "stubbed reply" }, finish_reason: "stop" }],
          usage: { prompt_tokens: 5, completion_tokens: 3, total_tokens: 8 },
        }),
      );
    });
  });
  return new Promise((resolve) =>
    server.listen(0, "127.0.0.1", () =>
      resolve({
        baseURL: `http://127.0.0.1:${server.address().port}/v1`,
        stop: () => new Promise((r) => server.close(r)),
      }),
    ),
  );
}

export async function run() {
  // ── Part 1: BATCH path (burst > 25 governed calls -> /ingest/batch) ────────
  const mock = await startMockIngest();
  const stub = await startOpenAIStub();
  obsvr.init({ apiKey: API_KEY, ingestUrl: mock.url, environment: "development", sampleRate: 1, policyRefreshIntervalMs: 0 });
  const client = obsvr.wrap(new OpenAI({ apiKey: "test", baseURL: stub.baseURL, maxRetries: 0 }));

  const N = 60; // > SEND_BATCH_SIZE so the sender must batch
  // Stall ingest ACKs while the burst enqueues: the in-flight send blocks the
  // drain loop, so all N events accumulate in the queue and then drain in
  // batches (rather than one-at-a-time). A generous stall keeps this
  // deterministic even under machine load. Cleared before flush so the drain is
  // fast.
  mock.setSlow(300);
  await Promise.all(
    Array.from({ length: N }, (_, i) =>
      client.chat.completions.create({ model: "gpt-4o", max_tokens: 8, messages: [{ role: "user", content: `batch call ${i}` }] }),
    ),
  );
  mock.setSlow(0);
  await obsvr.flush(15000);

  const batchEvents = mock.getEvents();
  check(`all ${N} governed calls were delivered`, batchEvents.length === N, `got ${batchEvents.length}`);
  check("batching happened: ingest requests < events delivered", mock.ingestRequestCount() < N, `requests=${mock.ingestRequestCount()} events=${batchEvents.length}`);
  check(`substantial batching (SEND_BATCH_SIZE=${SEND_BATCH_SIZE}): ${N} events drained in <= 10 ingest requests`, mock.ingestRequestCount() <= 10, `requests=${mock.ingestRequestCount()}`);
  check("every delivered event is a signed llm_call", batchEvents.every((e) => e.event_type === "llm_call" && /^[0-9a-f]{64}$/.test(String(e.sdk_sig))));
  if (batchEvents[0]) assertSignedEvent(batchEvents[0], "batched llm_call", { decisionRecord: true });
  verifyCapturedChain(batchEvents, API_KEY, "batch chain");

  await stub.stop();
  await mock.stop();

  // ── Part 2: OVERFLOW drops (fill past MAX_QUEUE_SIZE with stalled ingest) ───
  const droppedBefore = obsvr.getDroppedCount();
  const mock2 = await startMockIngest({ slowMs: 1000 }); // stall ACKs so the queue fills
  obsvr.init({ apiKey: API_KEY, ingestUrl: mock2.url, environment: "development", sampleRate: 1, policyRefreshIntervalMs: 0 });

  // Spans enqueue signed events synchronously with NO provider network, so a
  // tight loop fills the bounded queue deterministically (the event loop cannot
  // drain mid-loop). BURST > MAX_QUEUE_SIZE forces overflow drops.
  const BURST = 1300;
  for (let i = 0; i < BURST; i++) obsvr.span(`overflow-${i}`, "tool", () => i);

  const qSizeAfterBurst = obsvr.getQueueSize();
  const overflowDropped = obsvr.getDroppedCount() - droppedBefore;
  check("overflow drops occurred once the queue filled past MAX_QUEUE_SIZE", overflowDropped > 0, `dropped=${overflowDropped}`);
  check("queue stayed bounded and sane (0 < size <= MAX_QUEUE_SIZE)", qSizeAfterBurst > 0 && qSizeAfterBurst <= MAX_QUEUE_SIZE, `size=${qSizeAfterBurst}`);

  // flushQueue returns HONESTLY under a small timeout: it resolves promptly even
  // though the stalled ingest means the queue cannot fully drain yet.
  const t0 = Date.now();
  await obsvr.flush(100);
  const flushMs = Date.now() - t0;
  check("obsvr.flush(smallTimeout) resolves honestly within a bounded time", flushMs < 1500, `flush took ${flushMs}ms`);
  check("flush(smallTimeout) did not drain a still-stalled queue", obsvr.getQueueSize() > 0, `size=${obsvr.getQueueSize()}`);

  // Now let it drain fully and verify the DELIVERED events form a gap-free
  // chain: overflow drops happened BEFORE seq assignment, so no seq gaps.
  mock2.setSlow(0);
  await obsvr.flush(20000);
  const delivered = mock2.getEvents();
  const finalDropped = obsvr.getDroppedCount() - droppedBefore;
  // Account only for THIS burst. The queue is process-global and survives an
  // init() that repoints ingestUrl, so an event enqueued in part 1 that had not
  // drained yet is delivered here to mock2 and inflates the count by one — a
  // stray arrival, not a lost event, and the opposite failure from the one this
  // check exists to catch. Naming the strays keeps a future off-by-one legible
  // instead of a bare "1301 vs 1300".
  const isBurst = (e) => String(e?.metadata?.obsvr_span?.span_name ?? "").startsWith("overflow-");
  const strays = delivered.filter((e) => !isBurst(e));
  const burstDelivered = delivered.length - strays.length;
  check(
    "delivered + dropped account for the entire burst (no silent loss)",
    burstDelivered + finalDropped === BURST,
    `${burstDelivered} burst-delivered + ${finalDropped} dropped vs ${BURST}` +
      (strays.length
        ? ` (plus ${strays.length} stray pre-burst event(s): ${strays
            .map((e) => e?.metadata?.obsvr_span?.span_name ?? e.operation)
            .join(", ")})`
        : ""),
  );
  check("more events were delivered than dropped (queue absorbed most of the burst)", delivered.length >= MAX_QUEUE_SIZE);
  verifyCapturedChain(delivered, API_KEY, "overflow delivered chain (gap-free despite drops)");

  await obsvr.flush();
  await mock2.stop();
  return done.results();
}

if (import.meta.url === `file://${process.argv[1]}`) run();
