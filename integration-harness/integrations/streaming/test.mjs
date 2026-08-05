/**
 * Streaming governance — offline E2E.
 *
 * The provider stub returns a real OpenAI SSE stream (chat.completion.chunk
 * objects). No key, no network — the wrap() proxy only talks to 127.0.0.1.
 *
 *   1) streamingMode "wrap" (default): the consumer sees every chunk unchanged,
 *      and exactly ONE llm_call audit event fires at stream END with the
 *      ACCUMULATED response text + token usage (wrapper.ts wrapStreamingIterator
 *      accumulates chunks in a finally block and emits a single event).
 *   2) streamingMode "skip": the stream passes through UNAUDITED (zero events).
 *
 * Ends with assertSignedEvent() on the single streaming event and
 * verifyCapturedChain() over the wrap-mode capture.
 *
 *   node integrations/streaming/test.mjs
 */
import { createServer } from "node:http";
import { obsvr } from "@obsvr/sdk";
import OpenAI from "openai";
import { startMockIngest } from "../../lib/mock-ingest.mjs";
import { check, done, showEvents } from "../../lib/check.mjs";
import { assertSignedEvent, verifyCapturedChain } from "../../lib/assert-governance.mjs";

export const meta = { offline: true };

const API_KEY = process.env.OBSVR_API_KEY || "obsvr-test-key";
const EXPECTED_TEXT = "Hello, world!";

/** Offline OpenAI-shaped provider that speaks SSE for streaming requests. The
 *  final usage chunk is always emitted so token accumulation is testable
 *  regardless of whether stream_options survived the request round-trip. */
function startStreamingStub() {
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
      if (parsed.stream === true) {
        res.writeHead(200, {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          Connection: "keep-alive",
        });
        const base = { id: "chatcmpl-stub", object: "chat.completion.chunk", created: Math.floor(Date.now() / 1000), model: "gpt-4o" };
        const chunks = [
          { ...base, choices: [{ index: 0, delta: { role: "assistant" }, finish_reason: null }] },
          { ...base, choices: [{ index: 0, delta: { content: "Hello" }, finish_reason: null }] },
          { ...base, choices: [{ index: 0, delta: { content: ", world" }, finish_reason: null }] },
          { ...base, choices: [{ index: 0, delta: { content: "!" }, finish_reason: null }] },
          { ...base, choices: [{ index: 0, delta: {}, finish_reason: "stop" }] },
          { ...base, choices: [], usage: { prompt_tokens: 7, completion_tokens: 3, total_tokens: 10 } },
        ];
        for (const c of chunks) res.write(`data: ${JSON.stringify(c)}\n\n`);
        res.write("data: [DONE]\n\n");
        res.end();
      } else {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            id: "chatcmpl-stub",
            object: "chat.completion",
            created: Math.floor(Date.now() / 1000),
            model: "gpt-4o",
            choices: [{ index: 0, message: { role: "assistant", content: EXPECTED_TEXT }, finish_reason: "stop" }],
            usage: { prompt_tokens: 7, completion_tokens: 3, total_tokens: 10 },
          }),
        );
      }
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
  const stub = await startStreamingStub();

  // ── 1) streamingMode "wrap" (default): consume fully, ONE event at stream end
  obsvr.init({ apiKey: API_KEY, ingestUrl: mock.url, environment: "development", sampleRate: 1, policyRefreshIntervalMs: 0 });
  const client = obsvr.wrap(new OpenAI({ apiKey: "test", baseURL: stub.baseURL, maxRetries: 0 }));

  // Drain any event a prior suite left in the process-global sender queue into
  // this mock, then clear it — so the strict "exactly one event" assertion below
  // measures only THIS stream, immune to upstream leakage.
  await obsvr.flush();
  mock.reset();

  const stream = await client.chat.completions.create({
    model: "gpt-4o",
    stream: true,
    stream_options: { include_usage: true },
    messages: [{ role: "user", content: "stream me a greeting" }],
  });

  let chunksSeen = 0;
  let consumerText = "";
  for await (const chunk of stream) {
    chunksSeen += 1;
    const delta = chunk?.choices?.[0]?.delta?.content;
    if (typeof delta === "string") consumerText += delta;
  }
  check("consumer received chunks unchanged and reassembled the text", chunksSeen >= 4 && consumerText === EXPECTED_TEXT, `chunks=${chunksSeen} text=${JSON.stringify(consumerText)}`);

  await obsvr.flush();
  const wrapEvents = mock.getEvents();
  showEvents(wrapEvents);

  check("streaming (wrap) fired EXACTLY ONE audit event", wrapEvents.length === 1, `got ${wrapEvents.length}`);
  const ev = wrapEvents[0];
  check("the single event is an llm_call", ev?.event_type === "llm_call");
  check("accumulated response text captured at stream end", ev?.response === EXPECTED_TEXT, JSON.stringify(ev?.response));
  check(
    "token usage accumulated from the final chunk (7 / 3 / 10)",
    ev?.input_tokens === 7 && ev?.output_tokens === 3 && ev?.total_tokens === 10,
    `${ev?.input_tokens}/${ev?.output_tokens}/${ev?.total_tokens}`,
  );
  if (ev) assertSignedEvent(ev, "streaming llm_call", { decisionRecord: true });
  verifyCapturedChain(wrapEvents, API_KEY, "streaming wrap chain");

  // ── 2) streamingMode "skip": passthrough, UNAUDITED (zero events) ──────────
  mock.reset();
  obsvr.init({ apiKey: API_KEY, ingestUrl: mock.url, environment: "development", sampleRate: 1, policyRefreshIntervalMs: 0, streamingMode: "skip" });
  const skipClient = obsvr.wrap(new OpenAI({ apiKey: "test", baseURL: stub.baseURL, maxRetries: 0 }));

  const skipStream = await skipClient.chat.completions.create({
    model: "gpt-4o",
    stream: true,
    stream_options: { include_usage: true },
    messages: [{ role: "user", content: "stream me again, unaudited" }],
  });
  let skipText = "";
  for await (const chunk of skipStream) {
    const delta = chunk?.choices?.[0]?.delta?.content;
    if (typeof delta === "string") skipText += delta;
  }
  check("streamingMode 'skip' still returns a working passthrough stream", skipText === EXPECTED_TEXT, JSON.stringify(skipText));

  await obsvr.flush();
  const skipEvents = mock.getEvents();
  check("streamingMode 'skip' emits ZERO audit events (passes through unaudited)", skipEvents.length === 0, `got ${skipEvents.length}`);

  await obsvr.flush();
  await mock.stop();
  await stub.stop();
  return done.results();
}

if (import.meta.url === `file://${process.argv[1]}`) run();
