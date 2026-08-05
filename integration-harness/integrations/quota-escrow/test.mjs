/**
 * quota-escrow — fleet-quota escrow (ADR-7), end-to-end through /policies → wrap().
 *
 * The escrow client (governance/escrow.ts grant/spend/peek/report) is INTERNAL —
 * not exported — so its wire semantics are driven the only public way: the SDK
 * polls /policies, the mock serves `{ rules:[quotaRule], quota_escrow:{ id:{share,
 * epoch} } }`, and governed wrap() calls spend the granted share. (The fixture
 * quota_escrow.json pins the internal grant/spend/report step-cases; those exact
 * steps are consciously deferred here because the functions aren't public — the
 * observable decision behavior below matches the fixture's grant-spend-exhaust /
 * re-grant / stale-epoch cases.)
 *
 * Verifies: a granted share of N allows N calls then blocks the (N+1)th with a
 * QUOTA verdict (rule_id on the event); a strictly-newer epoch REFILLS the share
 * (call unblocks); a re-served (non-increasing) epoch does NOT refill, so after
 * the refilled share is spent the call blocks again (fail-closed, no fabricated
 * share).
 *
 * Run: node integrations/quota-escrow/test.mjs
 */
import { createServer } from "node:http";
import OpenAI from "openai";
import { obsvr } from "@obsvr/sdk";
import { startMockIngest } from "../../lib/mock-ingest.mjs";
import { check, done } from "../../lib/check.mjs";
import { verifyCapturedChain } from "../../lib/assert-governance.mjs";

export const meta = { offline: true };

const API_KEY = process.env.OBSVR_API_KEY || "obsvr-test-key";
const RULE_ID = "q-escrow-1";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const QUOTA_RULE = {
  id: RULE_ID,
  name: "escrow-metered",
  enabled: true,
  action: "block",
  type: "quota",
  // High limit so the per-process meter never blocks — the escrow SHARE is the
  // real cap. (When hasEscrow(rule.id), the share is spent, not this limit.)
  conditions: { quota_limit: 1000, quota_window_ms: 60_000, quota_scope: "project" },
};
const policiesWith = (share, epoch) => ({ rules: [QUOTA_RULE], quota_escrow: { [RULE_ID]: { share, epoch } } });

function startOpenAIStub() {
  let hits = 0;
  const server = createServer((req, res) => {
    let b = ""; req.on("data", (c) => (b += c));
    req.on("end", () => { hits += 1; res.writeHead(200, { "Content-Type": "application/json" }); res.end(JSON.stringify({ id: "c", object: "chat.completion", created: 0, model: "gpt-4o-mini", choices: [{ index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } })); });
  });
  return new Promise((r) => server.listen(0, "127.0.0.1", () => r({ port: server.address().port, hits: () => hits, stop: () => new Promise((res) => server.close(res)) })));
}

export async function run() {
  const stub = await startOpenAIStub();
  obsvr._reset(); // clear any escrow/policy-sync state from a prior suite

  const ingest = await startMockIngest({ policies: policiesWith(2, 1) });
  obsvr.init({ apiKey: API_KEY, ingestUrl: ingest.url, environment: "development", policyRefreshIntervalMs: 20 });
  const openai = obsvr.wrap(new OpenAI({ apiKey: "t", baseURL: `http://127.0.0.1:${stub.port}/v1` }));
  const say = () => openai.chat.completions.create({ model: "gpt-4o-mini", max_tokens: 8, messages: [{ role: "user", content: "metered call" }] });
  const tryCall = async () => { try { await say(); return "allowed"; } catch { return "blocked"; } };

  // Wait for the first poll to apply the grant (share 2, epoch 1).
  await ingest.waitForPoll(1, 2000);
  await sleep(150);

  // ── Grant share=2 ⇒ 2 allowed, 3rd blocked ─────────────────────────────────
  const r1 = await tryCall();
  const r2 = await tryCall();
  const r3 = await tryCall();
  check("escrow share=2: first two governed calls are allowed", r1 === "allowed" && r2 === "allowed", `${r1},${r2}`);
  check("escrow exhausted: the 3rd call is blocked (quota)", r3 === "blocked");

  await obsvr.flush();
  const qEv = ingest.getEvents().find((e) => e.event_type === "blocked_call" && e.rule_id === RULE_ID);
  check("quota block records the rule_id on a blocked_call event", !!qEv && qEv.action_source === "policy_rules", String(qEv?.rule_id));

  // ── Epoch bump (share=3, epoch=2) REFILLS ───────────────────────────────────
  ingest.setPolicies(policiesWith(3, 2));
  const before = ingest.policiesPollCount();
  await ingest.waitForPoll(before + 2, 2000); // a poll that started AFTER the change
  await sleep(120);
  const r4 = await tryCall();
  check("a strictly-newer epoch refills the share (call unblocks)", r4 === "allowed", r4);

  // ── Stale epoch does NOT refill: spend the refilled share, then block ───────
  // Still serving epoch 2 — re-applying epoch<=current is ignored, so no refill.
  const r5 = await tryCall(); // spends 2 of the refilled 3 (r4 spent 1)
  const r6 = await tryCall(); // spends the last, share -> 0
  const r7 = await tryCall(); // exhausted again, and stale epoch-2 polls never refilled
  check("re-served (non-increasing) epoch does NOT fabricate share", r7 === "blocked", `${r5},${r6},${r7}`);

  await obsvr.flush();
  const events = ingest.getEvents();
  verifyCapturedChain(events, API_KEY, "quota-escrow chain");

  obsvr._reset();
  await ingest.stop();
  await stub.stop();
  return done.results();
}

if (import.meta.url === `file://${process.argv[1]}`) run();
