/**
 * Concurrent governed calls — offline E2E.
 *
 * Every other suite here drives ONE call at a time, so nothing has ever
 * exercised what happens when governed calls overlap. That matters because the
 * things the audit trail depends on are process-global mutable state: the
 * sequence counter, the previous-signature link, and the per-call state each
 * integration stashes between its pre-call and post-call hooks. Those are
 * exactly the structures that a single-call test cannot fail on.
 *
 * Four questions, none of which the existing suites can answer:
 *
 *   1) Does every concurrent call produce exactly one event? (No drops, no
 *      duplicates from shared state being overwritten mid-flight.)
 *   2) Is seq_no still a contiguous 1..N block with no repeats? A repeated
 *      seq_no is worse than a gap: the chain still verifies pairwise while two
 *      different calls claim the same position in it.
 *   3) Does prev_sig still form ONE unbroken chain, in seq order? Interleaved
 *      signing could produce a fork — two events pointing at the same parent —
 *      which verifyAuditChain walks without complaint if it only checks pairs.
 *   4) Does each event keep ITS OWN prompt and response? Per-call state keyed
 *      wrongly (or not keyed at all) shows up as call A's prompt filed against
 *      call B's response, which is the failure mode that silently corrupts
 *      attribution rather than losing it.
 *
 * The stub echoes a marker unique to each request, so a crossed prompt/response
 * pair is detectable rather than merely suspected.
 *
 *   node integrations/concurrency/test.mjs
 */
import { createServer } from "node:http";
import { obsvr } from "@obsvr/sdk";
import OpenAI from "openai";
import { startMockIngest } from "../../lib/mock-ingest.mjs";
import { check, done, showEvents } from "../../lib/check.mjs";
import { assertSignedEvent, verifyCapturedChain } from "../../lib/assert-governance.mjs";

export const meta = { offline: true };

const API_KEY = process.env.OBSVR_API_KEY || "obsvr-test-key";
const CALLS = 24;

/**
 * Offline OpenAI-shaped provider that echoes the caller's marker back and
 * responds with a randomised small delay, so the calls genuinely interleave
 * rather than completing in issue order.
 */
function startEchoStub() {
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      let parsed = {};
      try {
        parsed = JSON.parse(body);
      } catch {
        /* ignore */
      }
      const prompt = parsed?.messages?.[0]?.content ?? "";
      const marker = /marker-(\d+)/.exec(String(prompt))?.[1] ?? "none";
      // Deterministic but non-monotonic: later requests can finish first.
      const delayMs = (Number(marker) * 7919) % 40;
      setTimeout(() => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            id: `chatcmpl-${marker}`,
            object: "chat.completion",
            created: Math.floor(Date.now() / 1000),
            model: "gpt-4o",
            choices: [
              {
                index: 0,
                message: { role: "assistant", content: `reply-${marker}` },
                finish_reason: "stop",
              },
            ],
            usage: { prompt_tokens: 5, completion_tokens: 2, total_tokens: 7 },
          }),
        );
      }, delayMs);
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
  const mock = await startMockIngest();
  const stub = await startEchoStub();

  obsvr.init({
    apiKey: API_KEY,
    ingestUrl: mock.url,
    environment: "development",
    sampleRate: 1,
    policyRefreshIntervalMs: 0,
  });
  const client = obsvr.wrap(new OpenAI({ apiKey: "test", baseURL: stub.baseURL, maxRetries: 0 }));

  // Drain anything a prior suite left in the process-global queue, so the
  // strict counts below measure only this burst.
  await obsvr.flush();
  mock.reset();

  const replies = await Promise.all(
    Array.from({ length: CALLS }, (_, i) =>
      client.chat.completions.create({
        model: "gpt-4o",
        messages: [{ role: "user", content: `marker-${i}` }],
      }),
    ),
  );

  check(
    "every concurrent call returned its OWN reply to the caller",
    replies.every((r, i) => r?.choices?.[0]?.message?.content === `reply-${i}`),
    replies.map((r) => r?.choices?.[0]?.message?.content).join(","),
  );

  await obsvr.flush();
  const events = mock.getEvents();
  showEvents(events.slice(0, 3));

  // ── 1) one event per call ────────────────────────────────────────────────
  check(
    `${CALLS} concurrent calls produced exactly ${CALLS} audit events`,
    events.length === CALLS,
    `got ${events.length}`,
  );

  // ── 2) seq_no: contiguous, no repeats ────────────────────────────────────
  const seqs = events.map((e) => e.seq_no).sort((a, b) => a - b);
  const uniqueSeqs = new Set(seqs);
  check(
    "no seq_no was issued twice under concurrency",
    uniqueSeqs.size === seqs.length,
    `${seqs.length} events, ${uniqueSeqs.size} distinct seq_no`,
  );
  check(
    "seq_no is a contiguous block with no gaps",
    seqs.length > 0 && seqs[seqs.length - 1] - seqs[0] === seqs.length - 1,
    `range ${seqs[0]}..${seqs[seqs.length - 1]} over ${seqs.length} events`,
  );

  // ── 3) prev_sig: one unbroken chain, not a fork ──────────────────────────
  const bySeq = [...events].sort((a, b) => a.seq_no - b.seq_no);
  const parents = bySeq.slice(1).map((e) => e.prev_sig);
  check(
    "no two events claim the same parent (the chain did not fork)",
    new Set(parents).size === parents.length,
    `${parents.length} links, ${new Set(parents).size} distinct parents`,
  );
  check(
    "each event links to the signature of the one before it in seq order",
    bySeq.every((e, i) => i === 0 || e.prev_sig === bySeq[i - 1].sdk_sig),
    "a mismatch here means events were signed in a different order than they were numbered",
  );

  // ── 4) no cross-contamination of per-call content ────────────────────────
  const crossed = events.filter((e) => {
    const p = /marker-(\d+)/.exec(String(e.prompt ?? ""))?.[1];
    const r = /reply-(\d+)/.exec(String(e.response ?? ""))?.[1];
    return p === undefined || r === undefined || p !== r;
  });
  check(
    "every event kept its own prompt paired with its own response",
    crossed.length === 0,
    crossed.length
      ? `${crossed.length} crossed: ` +
        crossed
          .slice(0, 3)
          .map((e) => `${JSON.stringify(e.prompt)} -> ${JSON.stringify(e.response)}`)
          .join(" | ")
      : "",
  );

  check(
    "every event carries its own request_id",
    new Set(events.map((e) => e.request_id)).size === events.length,
    `${events.length} events, ${new Set(events.map((e) => e.request_id)).size} distinct request_id`,
  );

  check(
    "token counts survived concurrency intact on every event",
    events.every((e) => e.input_tokens === 5 && e.output_tokens === 2 && e.total_tokens === 7),
    events
      .filter((e) => e.input_tokens !== 5)
      .slice(0, 3)
      .map((e) => `${e.input_tokens}/${e.output_tokens}/${e.total_tokens}`)
      .join(","),
  );

  if (events[0]) assertSignedEvent(events[0], "concurrent llm_call", { decisionRecord: true });
  verifyCapturedChain(events, API_KEY, "concurrent capture");

  await stub.stop();
  await mock.stop();
  return done.results();
}

if (import.meta.url === `file://${process.argv[1]}`) run();
