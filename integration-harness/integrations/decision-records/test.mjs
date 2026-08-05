/**
 * decision-records — the canonical decision-input document (ADR-2).
 *
 * Every governance event (allowed AND blocked) carries a 64-hex
 * decision_input_hash + engine_version. The hash is deterministic over the
 * decision inputs ONLY (rules_hash, degraded, target, evaluated-text digest,
 * scope ids, hook disposition) — identical input+config ⇒ identical hash.
 *
 * Three checks:
 *   1. Emitted events (real wrap() calls) carry the record; identical calls hash
 *      identically; different evaluated text hashes differently; blocked events
 *      carry it too.
 *   2. A real wrap() call reproduces the fixture case "request-no-optionals"
 *      byte-for-byte (exercises the SDK's own computeDecisionInputHash).
 *   3. Algorithm cross-check over EVERY decision_input.json case: the canonical
 *      serialization (RFC-8785-style stableStringify) and its SHA-256 match the
 *      pinned oracle for all targets/scopes/degraded/unicode cases.
 *
 * Run: node integrations/decision-records/test.mjs
 */
import { createServer } from "node:http";
import { createHash } from "node:crypto";
import OpenAI from "openai";
import { obsvr } from "@obsvr/sdk";
import { startMockIngest } from "../../lib/mock-ingest.mjs";
import { check, done } from "../../lib/check.mjs";
import { verifyCapturedChain } from "../../lib/assert-governance.mjs";
import { loadFixture } from "../../lib/fixtures.mjs";

export const meta = { offline: true };

const API_KEY = process.env.OBSVR_API_KEY || "obsvr-test-key";
const HEX64 = /^[0-9a-f]{64}$/;

/** SDK's canonicalizer (rules.ts stableStringify): sorted keys, omit undefined. */
function stableStringify(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map((x) => stableStringify(x === undefined ? null : x)).join(",") + "]";
  const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + stableStringify(v[k])).join(",") + "}";
}
const sha256Hex = (s) => createHash("sha256").update(s, "utf8").digest("hex");

function startOpenAIStub() {
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        id: "chatcmpl-x", object: "chat.completion", created: 0, model: "gpt-4o-mini",
        choices: [{ index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" }],
        usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
      }));
    });
  });
  return new Promise((r) => server.listen(0, "127.0.0.1", () => r({ port: server.address().port, stop: () => new Promise((res) => server.close(res)) })));
}

const say = (client, content) => client.chat.completions.create({ model: "gpt-4o-mini", max_tokens: 8, messages: [{ role: "user", content }] });

export async function run() {
  const ingest = await startMockIngest();
  const stub = await startOpenAIStub();

  // Phase A/B: no rules, no hook, no PII policy. rules_hash "none", hook
  // "not_configured" — the exact shape of the fixture's no-optionals case.
  obsvr.init({ apiKey: API_KEY, ingestUrl: ingest.url, environment: "development", policyRefreshIntervalMs: 0 });
  const openai = obsvr.wrap(new OpenAI({ apiKey: "t", baseURL: `http://127.0.0.1:${stub.port}/v1` }));

  await say(openai, ""); // empty last-user-message ⇒ evaluated_text "" ⇒ no-optionals case
  await say(openai, "determinism probe alpha");
  await say(openai, "determinism probe alpha"); // identical to the previous
  await say(openai, "determinism probe beta"); // different evaluated text

  // Phase C: a PII block still stamps a decision record on the blocked event.
  obsvr.init({ apiKey: API_KEY, ingestUrl: ingest.url, environment: "development", piiPolicy: {}, policyRefreshIntervalMs: 0 });
  const openaiPii = obsvr.wrap(new OpenAI({ apiKey: "t", baseURL: `http://127.0.0.1:${stub.port}/v1` }));
  let blocked = false;
  try { await say(openaiPii, "my ssn is 123-45-6789"); } catch { blocked = true; }

  await obsvr.flush();
  const events = ingest.getEvents();

  // ── 1. Presence + determinism on emitted events ─────────────────────────────
  const llm = events.filter((e) => e.event_type === "llm_call");
  check("every llm_call carries a 64-hex decision_input_hash", llm.length > 0 && llm.every((e) => HEX64.test(String(e.decision_input_hash))));
  check("every llm_call carries engine_version obsvr-rules/1", llm.every((e) => e.engine_version === "obsvr-rules/1"));

  // Match on user_input (the raw last-user-message); the stored `prompt` is the
  // formatted transcript ("user: <content>"), not the raw text.
  const alpha = llm.filter((e) => e.user_input === "determinism probe alpha");
  const beta = llm.find((e) => e.user_input === "determinism probe beta");
  check("two identical calls produce the SAME decision_input_hash", alpha.length === 2 && alpha[0].decision_input_hash === alpha[1].decision_input_hash);
  check("a different evaluated text produces a DIFFERENT decision_input_hash", !!beta && beta.decision_input_hash !== alpha[0]?.decision_input_hash);

  const blockedEv = events.find((e) => e.event_type === "blocked_call");
  check("SSN prompt was blocked", blocked && !!blockedEv);
  check("blocked_call event ALSO carries a 64-hex decision_input_hash", HEX64.test(String(blockedEv?.decision_input_hash)) && blockedEv?.engine_version === "obsvr-rules/1");

  // ── 2. Real wrap() call reproduces the no-optionals fixture case exactly ─────
  const fx = loadFixture("decision_input");
  const noOpt = fx.cases.find((c) => c.id === "request-no-optionals");
  const emptyEv = llm.find((e) => (e.user_input ?? "") === "");
  check(
    "real wrap() call reproduces fixture 'request-no-optionals' decision_input_hash",
    !!emptyEv && emptyEv.decision_input_hash === noOpt.expected.hash,
    emptyEv ? `event ${emptyEv.decision_input_hash} vs fixture ${noOpt.expected.hash}` : "empty-prompt event not found",
  );

  // ── 3. Algorithm cross-check over EVERY fixture case ────────────────────────
  let canonOk = true, hashOk = true, firstBad = null;
  for (const c of fx.cases) {
    const canonical = stableStringify(c.doc);
    if (canonical !== c.expected.canonical) { canonOk = false; firstBad = firstBad ?? c.id; }
    if (sha256Hex(c.expected.canonical) !== c.expected.hash) { hashOk = false; firstBad = firstBad ?? c.id; }
  }
  check(`canonical serialization matches the oracle for all ${fx.cases.length} cases`, canonOk, firstBad ? `first mismatch: ${firstBad}` : undefined);
  check("SHA-256 of the canonical bytes matches the oracle hash for all cases", hashOk);
  check("fixture engine_version pin matches SDK (obsvr-rules/1)", fx.engine_version === "obsvr-rules/1");

  // ── chain integrity of the whole capture ────────────────────────────────────
  verifyCapturedChain(events, API_KEY, "decision-records chain");

  await stub.stop();
  await ingest.stop();
  return done.results();
}

if (import.meta.url === `file://${process.argv[1]}`) run();
