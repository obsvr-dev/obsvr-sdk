/**
 * Execution spans + subject attribution — offline E2E.
 *
 * Exercises the span primitive (proxy/span.ts) and per-user subject attribution
 * (proxy/subject.ts) against an OFFLINE OpenAI-shaped HTTP stub (no key, no
 * network — the wrap() proxy talks only to 127.0.0.1):
 *
 *   1) generateSpanId() returns a UUID.
 *   2) obsvr.span(name, kind, fn) emits a SIGNED standalone execution-span event
 *      (event_type "span", event_class "execution_span", source "span"), and
 *      returns fn's result.
 *   3) A governed llm_call made inside obsvr.withSpan(...) links to the enclosing
 *      span as its deterministic parent (metadata.obsvr_span.parent_span_id).
 *   4) useSubject() fills user_id/service_name on the INTEGRATION path
 *      (obsvrGovernTool -> tool.call), combined with a withSpan parent — this is
 *      documented behavior (README), NOT the wrap() core-proxy path.
 *
 * Ends with assertSignedEvent() on each event class and verifyCapturedChain()
 * over the whole capture.
 *
 *   node integrations/spans/test.mjs
 */
import { createServer } from "node:http";
import {
  obsvr,
  currentSpanId,
  generateSpanId,
  useSubject,
  obsvrGovernTool,
  SPAN_ATTR,
} from "@obsvr/sdk";
import OpenAI from "openai";
import { startMockIngest } from "../../lib/mock-ingest.mjs";
import { check, done, showEvents } from "../../lib/check.mjs";
import { assertSignedEvent, verifyCapturedChain } from "../../lib/assert-governance.mjs";
import { loadFixture } from "../../lib/fixtures.mjs";

export const meta = { offline: true };

const API_KEY = process.env.OBSVR_API_KEY || "obsvr-test-key";
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Offline OpenAI-shaped provider: 200 chat.completion to any POST. No key, no
 *  real network — the wrap() proxy only ever talks to 127.0.0.1. */
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
  const mock = await startMockIngest();
  const stub = await startOpenAIStub();

  obsvr.init({
    apiKey: API_KEY,
    ingestUrl: mock.url,
    environment: "development",
    sampleRate: 1,
    policyRefreshIntervalMs: 0,
  });

  // ── 1) generateSpanId() -> UUID ────────────────────────────────────────────
  const sid = generateSpanId();
  check("generateSpanId() returns a UUID string", UUID_RE.test(sid), sid);
  check("generateSpanId() is unique per call", sid !== generateSpanId());

  // ── 2) obsvr.span() -> signed standalone execution-span event ──────────────
  const spanReturn = obsvr.span("vector_search", "tool", () => 42, {
    attributes: { [SPAN_ATTR.RETRIEVAL_DOCUMENT_COUNT]: 5 },
  });
  check("obsvr.span() returns the wrapped fn result (42)", spanReturn === 42);

  // ── 3) withSpan(): a governed llm_call links to the enclosing span parent ──
  const client = obsvr.wrap(new OpenAI({ apiKey: "test", baseURL: stub.baseURL, maxRetries: 0 }));
  const parentId = await obsvr.withSpan("plan_step", "agent", async () => {
    const pid = currentSpanId();
    check("currentSpanId() inside withSpan is a UUID", UUID_RE.test(String(pid)), String(pid));
    await client.chat.completions.create({
      model: "gpt-4o",
      max_tokens: 16,
      messages: [{ role: "user", content: "hello inside a span" }],
    });
    return pid;
  });

  // ── 4) useSubject + span on the INTEGRATION path (obsvrGovernTool) ─────────
  //    Documented behavior: buildIntegrationEvent reads getCurrentSubject(), so
  //    the ambient subject fills user_id/service_name here (it does NOT on the
  //    wrap() core-proxy path — see GROUND_TRUTH).
  const tool = { name: "t", execute: async (input) => ({ ok: true, echo: input }) };
  await obsvr.withSpan("agent_step", "agent", async () => {
    await useSubject("user:alice;service:svc", () =>
      obsvrGovernTool(tool, { name: "t" }).execute({ q: "lookup account status" }),
    );
  });

  await obsvr.flush();
  const events = mock.getEvents();
  showEvents(events);

  // ── standalone span event assertions ───────────────────────────────────────
  const spanEv = events.find((e) => e.event_type === "span");
  check("obsvr.span() emitted a standalone span event", !!spanEv);
  check("span event_class === execution_span", spanEv?.event_class === "execution_span");
  check("span source === 'span'", spanEv?.source === "span");
  check("span operation === name ('vector_search')", spanEv?.operation === "vector_search");
  check(
    "span metadata.obsvr_span carries span_kind/span_name",
    spanEv?.metadata?.obsvr_span?.span_kind === "tool" && spanEv?.metadata?.obsvr_span?.span_name === "vector_search",
  );
  check("span() auto-adds duration_ms (a number) to attributes", typeof spanEv?.metadata?.obsvr_span?.attributes?.duration_ms === "number");
  check(
    "custom SPAN_ATTR attribute stored in the span bag",
    spanEv?.metadata?.obsvr_span?.attributes?.[SPAN_ATTR.RETRIEVAL_DOCUMENT_COUNT] === 5,
  );
  if (spanEv) assertSignedEvent(spanEv, "span", { decisionRecord: false });

  // ── withSpan -> llm_call parent linkage ────────────────────────────────────
  const llm = events.find((e) => e.event_type === "llm_call");
  check("wrapped llm_call captured inside withSpan", !!llm);
  check("llm_call metadata.obsvr_span.parent_span_id === withSpan id", llm?.metadata?.obsvr_span?.parent_span_id === parentId);
  check("llm_call metadata.obsvr_span.span_kind === 'llm_call'", llm?.metadata?.obsvr_span?.span_kind === "llm_call");
  check("llm_call metadata.obsvr_span.span_name === operation", llm?.metadata?.obsvr_span?.span_name === llm?.operation);
  if (llm) assertSignedEvent(llm, "withSpan llm_call", { decisionRecord: true });

  // ── useSubject + span on the tool.call integration event ───────────────────
  const toolEv = events.find((e) => e.event_type === "tool_call" && e.operation === "tool.call");
  check("obsvrGovernTool emitted a signed tool.call event", !!toolEv);
  check("subject fills user_id=alice on the integration path", toolEv?.user_id === "alice");
  check("subject fills service_name=svc on the integration path", toolEv?.service_name === "svc");
  check("tool.call metadata.obsvr_span.parent_span_id set (withSpan parent)", UUID_RE.test(String(toolEv?.metadata?.obsvr_span?.parent_span_id)));
  check("tool.call metadata.tool_name === 't'", toolEv?.metadata?.tool_name === "t");
  if (toolEv) assertSignedEvent(toolEv, "tool.call", { decisionRecord: false });

  // ── SPAN_ATTR vs otel_attributes.json fixture ──────────────────────────────
  // Self-consistency on two source-verified SPAN_ATTR keys.
  check("SPAN_ATTR.TOOL_NAME === 'gen_ai.tool.name'", SPAN_ATTR.TOOL_NAME === "gen_ai.tool.name");
  check("SPAN_ATTR.DURATION_MS === 'duration_ms'", SPAN_ATTR.DURATION_MS === "duration_ms");
  // otel_attributes.json is the OTel-MIRROR attribute-key parity fixture (the
  // gen_ai.* request/usage + obsvr.* governance keys the OTel export emits). That
  // is a different vocabulary from proxy/span-attributes.ts SPAN_ATTR (the span
  // attribute bag). No SPAN_ATTR value appears in the mirror key set, so the
  // fixture does not MAP to SPAN_ATTR — consciously deferred, asserted here as a
  // disjointness invariant rather than forced into a false mapping.
  try {
    const fx = loadFixture("otel_attributes");
    const spanVals = new Set(Object.values(SPAN_ATTR));
    const overlap = (fx.attribute_keys || []).filter((k) => spanVals.has(k));
    check(
      "otel_attributes.json is the OTel-mirror key set, disjoint from SPAN_ATTR (deferred, not a mapping)",
      Array.isArray(fx.attribute_keys) && overlap.length === 0,
      `overlap=${JSON.stringify(overlap)}`,
    );
  } catch (e) {
    check("otel_attributes.json load for the SPAN_ATTR cross-check", false, `could not load fixture: ${e.message}`);
  }

  // ── full-chain verification ────────────────────────────────────────────────
  verifyCapturedChain(events, API_KEY, "spans chain");

  await obsvr.flush();
  await mock.stop();
  await stub.stop();
  return done.results();
}

if (import.meta.url === `file://${process.argv[1]}`) run();
