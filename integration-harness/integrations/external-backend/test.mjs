/**
 * external-backend — the inbound OPA/Cedar policy backend (ADR-4).
 *
 * Layers:
 *   1. DENY-WINS truth table + provenance vs conformance/fixtures/external_backend.json,
 *      cross-checked against the SDK's exported pure functions
 *      (mergeExternalBackendDecision / backendProvenance) for every case.
 *   2. A local stub OPA server (127.0.0.1, allowPrivateNetwork) driven THROUGH
 *      obsvr.wrap(): deny → blocked (deny-wins), shadow:true → observed but not
 *      enforced, backend error → fail-closed block. external_backend provenance
 *      is recorded on the event.
 *   3. SSRF guard: a metadata (169.254.169.254) or private (10.x) backend URL is
 *      rejected AT init() — literal-IP guard is a static init-time throw
 *      (utils/ssrf.ts assertBackendUrlStatic, called from proxy/config.ts). 10.x
 *      is allowed only with allowPrivateNetwork; metadata is never allowed.
 *
 * Run: node integrations/external-backend/test.mjs
 */
import { createServer } from "node:http";
import OpenAI from "openai";
import { obsvr, mergeExternalBackendDecision, backendProvenance } from "@obsvr/sdk";
import { startMockIngest } from "../../lib/mock-ingest.mjs";
import { check, done } from "../../lib/check.mjs";
import { verifyCapturedChain } from "../../lib/assert-governance.mjs";
import { loadFixture } from "../../lib/fixtures.mjs";

export const meta = { offline: true };

const API_KEY = process.env.OBSVR_API_KEY || "obsvr-test-key";

function startOpenAIStub() {
  let hits = 0;
  const server = createServer((req, res) => {
    let b = ""; req.on("data", (c) => (b += c));
    req.on("end", () => { hits += 1; res.writeHead(200, { "Content-Type": "application/json" }); res.end(JSON.stringify({ id: "c", object: "chat.completion", created: 0, model: "gpt-4o-mini", choices: [{ index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } })); });
  });
  return new Promise((r) => server.listen(0, "127.0.0.1", () => r({ port: server.address().port, hits: () => hits, stop: () => new Promise((res) => server.close(res)) })));
}

/** Stub OPA data endpoint whose verdict is switchable per test. */
function startOpaStub() {
  let mode = "deny";
  const server = createServer((req, res) => {
    let b = ""; req.on("data", (c) => (b += c));
    req.on("end", () => {
      if (mode === "error") { res.writeHead(500); res.end("boom"); return; }
      const allow = mode === "allow";
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ result: { allow, reasons: allow ? [] : ["denied by test backend"] } }));
    });
  });
  return new Promise((r) => server.listen(0, "127.0.0.1", () => r({ port: server.address().port, setMode: (m) => { mode = m; }, stop: () => new Promise((res) => server.close(res)) })));
}

export async function run() {
  const fx = loadFixture("external_backend");

  // ── 1. Deny-wins truth table + provenance (pure exported functions) ─────────
  let mergeOk = true, mergeBad = null;
  for (const c of fx.merge_cases) {
    const r = mergeExternalBackendDecision(c.local, c.outcome, c.shadow);
    if (r.decision !== c.expect.decision || r.blocked_by_backend !== c.expect.blocked_by_backend) { mergeOk = false; mergeBad = mergeBad ?? c.id; }
  }
  check(`DENY-WINS merge matches the fixture for all ${fx.merge_cases.length} cases`, mergeOk, mergeBad ? `first mismatch: ${mergeBad}` : undefined);

  let provOk = true, provBad = null;
  for (const c of fx.provenance_cases) {
    const p = backendProvenance(c.backend);
    if (p.identity !== c.expect.identity || p.policy_hash !== c.expect.policy_hash) { provOk = false; provBad = provBad ?? c.id; }
  }
  check(`backend provenance (identity + policy_hash) matches the fixture for all ${fx.provenance_cases.length} cases`, provOk, provBad ? `first mismatch: ${provBad}` : undefined);

  // ── 2. Stub OPA through the wrapper ─────────────────────────────────────────
  const ingest = await startMockIngest();
  const stub = await startOpenAIStub();
  const opa = await startOpaStub();
  const opaUrl = `http://127.0.0.1:${opa.port}/v1/data/obsvr/allow`;
  const initBackend = (shadow) => obsvr.init({ apiKey: API_KEY, ingestUrl: ingest.url, environment: "development", policyRefreshIntervalMs: 0, externalPolicyBackend: { type: "opa", url: opaUrl, allowPrivateNetwork: true, shadow } });
  const wrapClient = () => obsvr.wrap(new OpenAI({ apiKey: "t", baseURL: `http://127.0.0.1:${stub.port}/v1` }));
  const say = (client) => client.chat.completions.create({ model: "gpt-4o-mini", max_tokens: 8, messages: [{ role: "user", content: "benign request" }] });

  // deny (enforce) → blocked, deny-wins
  opa.setMode("deny"); initBackend(false);
  let denyBlocked = false;
  try { await say(wrapClient()); } catch { denyBlocked = true; }
  check("backend DENY (enforce) blocks the call (deny-wins)", denyBlocked);

  // shadow → observed, not enforced (call proceeds)
  opa.setMode("deny"); initBackend(true);
  const hitsBefore = stub.hits();
  let shadowThrew = false;
  try { await say(wrapClient()); } catch { shadowThrew = true; }
  check("backend deny in SHADOW mode does NOT block (observe-only)", !shadowThrew && stub.hits() === hitsBefore + 1);

  // error → fail-closed block
  opa.setMode("error"); initBackend(false);
  let errBlocked = false;
  try { await say(wrapClient()); } catch { errBlocked = true; }
  check("backend ERROR is fail-closed (blocks in enforce mode)", errBlocked);

  await obsvr.flush();
  const events = ingest.getEvents();

  const denyEv = events.find((e) => e.event_type === "blocked_call" && e.external_backend?.outcome === "deny");
  check("blocked event records external_backend provenance (outcome deny, type opa)", !!denyEv && denyEv.external_backend.type === "opa" && denyEv.action_source === "external_backend", JSON.stringify(denyEv?.external_backend));
  check("blocked event rule_id is backend:opa", denyEv?.rule_id === "backend:opa", String(denyEv?.rule_id));
  const shadowEv = events.find((e) => e.event_type === "llm_call" && e.external_backend?.shadow === true);
  check("shadow observation is recorded on the allowed event (shadow:true, outcome deny)", !!shadowEv && shadowEv.external_backend.outcome === "deny");
  const errEv = events.find((e) => e.event_type === "blocked_call" && e.external_backend?.outcome === "error");
  check("fail-closed block records external_backend outcome error", !!errEv);

  verifyCapturedChain(events, API_KEY, "external-backend chain");

  // ── 3. SSRF guard at init() (literal-IP static throw) ───────────────────────
  const initThrows = (url, allowPrivateNetwork) => {
    try {
      obsvr.init({ apiKey: API_KEY, ingestUrl: ingest.url, policyRefreshIntervalMs: 0, externalPolicyBackend: { type: "opa", url, allowPrivateNetwork } });
      return false;
    } catch { return true; }
  };
  check("SECURITY: metadata backend 169.254.169.254 rejected at init even WITH allowPrivateNetwork", initThrows("http://169.254.169.254/v1/data/x", true));
  check("SECURITY: private backend 10.0.0.1 rejected at init WITHOUT allowPrivateNetwork", initThrows("http://10.0.0.1:8181/v1/data/x", false));
  check("private backend 10.0.0.1 permitted at init WITH allowPrivateNetwork", !initThrows("http://10.0.0.1:8181/v1/data/x", true));
  check("SECURITY: non-http(s) backend scheme rejected at init", initThrows("file:///etc/passwd", true));

  obsvr._reset();
  await opa.stop();
  await stub.stop();
  await ingest.stop();
  return done.results();
}

if (import.meta.url === `file://${process.argv[1]}`) run();
