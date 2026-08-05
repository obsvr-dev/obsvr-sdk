/**
 * degraded-mode — enforcement-integrity gate (kill switch + fail-closed staleness).
 *
 * Two triggers (source: proxy/config.ts isPolicyEnforcementDegraded):
 *   - KILL SWITCH: /policies returns 401/403 ⇒ remoteDisabled, regardless of
 *     failMode. Governed calls block with rule_id `sdk:project_paused_or_key_revoked`
 *     and the block is NOT customer-overridable (the pre-call hook is skipped).
 *   - STALE, fail-closed: failMode "closed" + polling on + last successful sync
 *     older than the staleness budget ⇒ block (reason policy_sync_never_succeeded).
 *     failMode "open" never blocks on staleness.
 *
 * Uses obsvr._reset() between phases so the process-global policy-sync state
 * cannot leak into other suites.
 *
 * Run: node integrations/degraded-mode/test.mjs
 */
import { createServer } from "node:http";
import OpenAI from "openai";
import { obsvr } from "@obsvr/sdk";
import { startMockIngest } from "../../lib/mock-ingest.mjs";
import { check, done } from "../../lib/check.mjs";
import { verifyCapturedChain } from "../../lib/assert-governance.mjs";

export const meta = { offline: true };

const API_KEY = process.env.OBSVR_API_KEY || "obsvr-test-key";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function startOpenAIStub() {
  let hits = 0;
  const server = createServer((req, res) => {
    let b = ""; req.on("data", (c) => (b += c));
    req.on("end", () => { hits += 1; res.writeHead(200, { "Content-Type": "application/json" }); res.end(JSON.stringify({ id: "c", object: "chat.completion", created: 0, model: "gpt-4o-mini", choices: [{ index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } })); });
  });
  return new Promise((r) => server.listen(0, "127.0.0.1", () => r({ port: server.address().port, hits: () => hits, stop: () => new Promise((res) => server.close(res)) })));
}
const say = (client) => client.chat.completions.create({ model: "gpt-4o-mini", max_tokens: 8, messages: [{ role: "user", content: "benign request" }] });

export async function run() {
  const stub = await startOpenAIStub();
  const mkClient = () => obsvr.wrap(new OpenAI({ apiKey: "t", baseURL: `http://127.0.0.1:${stub.port}/v1` }));

  // ── Phase 1: KILL SWITCH (/policies 403), non-overridable ───────────────────
  obsvr._reset();
  const killIngest = await startMockIngest({ policies: () => ({ status: 403, body: {} }) });
  obsvr.init({
    apiKey: API_KEY,
    ingestUrl: killIngest.url,
    environment: "development",
    policyRefreshIntervalMs: 25,
    // A hook that WOULD allow — proves the integrity gate is not overridable.
    onPreCall: async () => ({ decision: "allow" }),
  });
  await killIngest.waitForPoll(1, 2000);
  await sleep(120); // let the client process the 403 → remoteDisabled

  let killBlocked = false;
  try { await say(mkClient()); } catch { killBlocked = true; }
  check("SECURITY: /policies 403 kill switch blocks governed calls", killBlocked);
  check("kill-switch block is NOT overridable by an allow hook", killBlocked);

  await obsvr.flush();
  const killEvents = killIngest.getEvents();
  const killEv = killEvents.find((e) => e.event_type === "blocked_call");
  check("kill-switch block records rule_id sdk:project_paused_or_key_revoked", killEv?.rule_id === "sdk:project_paused_or_key_revoked", String(killEv?.rule_id));
  check("kill-switch block: action_taken blocked, action_source policy_rules, reason policy_violation", killEv?.action_taken === "blocked" && killEv?.action_source === "policy_rules" && killEv?.action_reason === "policy_violation");
  if (killEv) verifyCapturedChain(killEvents, API_KEY, "kill-switch chain");
  obsvr._reset();
  await killIngest.stop();

  // ── Phase 2: STALE sync — failMode closed blocks, open allows ───────────────
  // /policies always 500 ⇒ no successful sync; a tiny staleness budget trips the
  // fail-closed gate after a short wait.
  const staleIngest = await startMockIngest({ policies: () => ({ status: 500, body: {} }) });

  // failMode: "closed" ⇒ blocked after the budget elapses.
  obsvr.init({ apiKey: API_KEY, ingestUrl: staleIngest.url, environment: "development", failMode: "closed", policyRefreshIntervalMs: 20, policyStalenessBudgetMs: 30 });
  await sleep(150); // exceed the 30ms staleness budget with no successful poll
  let staleClosedBlocked = false;
  try { await say(mkClient()); } catch { staleClosedBlocked = true; }
  check("SECURITY: failMode=closed + stale sync blocks governed calls", staleClosedBlocked);

  await obsvr.flush();
  const staleEv = staleIngest.getEvents().find((e) => e.event_type === "blocked_call");
  check("stale fail-closed block reason is a policy_sync_* gate", typeof staleEv?.rule_id === "string" && staleEv.rule_id.startsWith("sdk:policy_sync"), String(staleEv?.rule_id));
  obsvr._reset();

  // failMode: "open" ⇒ same stale sync, but calls are ALLOWED.
  obsvr.init({ apiKey: API_KEY, ingestUrl: staleIngest.url, environment: "development", failMode: "open", policyRefreshIntervalMs: 20, policyStalenessBudgetMs: 30 });
  await sleep(150);
  const hitsBefore = stub.hits();
  let openAllowed = true;
  try { await say(mkClient()); } catch { openAllowed = false; }
  check("failMode=open never blocks on staleness (call allowed)", openAllowed && stub.hits() === hitsBefore + 1);

  // Drain this call's event before _reset — _reset clears policy/escrow state but
  // NOT the fire-and-forget queue, so an unflushed event would leak into the next
  // suite's capture (and its strict event-count assertions).
  await obsvr.flush();
  obsvr._reset();
  await staleIngest.stop();
  await stub.stop();
  return done.results();
}

if (import.meta.url === `file://${process.argv[1]}`) run();
