/**
 * Structured policy-rules engine — offline E2E.
 *
 * Drives the rules engine two ways:
 *   1) through obsvr.wrap() against an OFFLINE OpenAI-shaped HTTP stub (no key,
 *      no network) — keyword / regex / model_gate / quota / shadow rules,
 *   2) through the exported engine API — explain(), derivePolicyVersion(),
 *      deriveRuleHash(), exportToRego().
 *
 * Every wrap() event is a signed governance record; the run ends with
 * assertSignedEvent() on a governance event and verifyCapturedChain() over the
 * whole capture.
 *
 *   node integrations/rules-suite/test.mjs
 */
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { existsSync, readFileSync, realpathSync } from "node:fs";
import {
  obsvr,
  explain,
  derivePolicyVersion,
  deriveRuleHash,
  exportToRego,
  resetQuota,
  getQuotaStatus,
} from "@obsvr/sdk";
import OpenAI from "openai";
import { startMockIngest } from "../../lib/mock-ingest.mjs";
import { check, done, showEvents } from "../../lib/check.mjs";
import { assertSignedEvent, verifyCapturedChain } from "../../lib/assert-governance.mjs";

export const meta = { offline: true };

const API_KEY = process.env.OBSVR_API_KEY || "obsvr-test-key";

/** Offline OpenAI-shaped provider: responds 200 with a chat.completion to any
 *  POST. No key, no real network — the wrap() proxy talks only to 127.0.0.1. */
function startOpenAIStub() {
  let hits = 0;
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      hits += 1;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          id: "chatcmpl-stub",
          object: "chat.completion",
          created: Math.floor(Date.now() / 1000),
          model: "gpt-4o",
          choices: [
            { index: 0, message: { role: "assistant", content: "stubbed offline reply" }, finish_reason: "stop" },
          ],
          usage: { prompt_tokens: 5, completion_tokens: 3, total_tokens: 8 },
        }),
      );
    });
  });
  return new Promise((resolve) =>
    server.listen(0, "127.0.0.1", () =>
      resolve({
        baseURL: `http://127.0.0.1:${server.address().port}/v1`,
        hits: () => hits,
        stop: () => new Promise((r) => server.close(r)),
      }),
    ),
  );
}

/** Resolve conformance/fixtures through the linked @obsvr/sdk package (works
 *  whether the symlink points at the internal sdk or the public build). */
function resolveFixturesDir() {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [];
  try {
    // Realpath the node_modules symlink → <repo>/sdk; fixtures are a sibling.
    const real = realpathSync(join(here, "..", "..", "node_modules", "@obsvr", "sdk"));
    candidates.push(join(real, "..", "conformance", "fixtures"));
    candidates.push(join(real, "conformance", "fixtures"));
  } catch {
    /* not linked that way */
  }
  try {
    const require = createRequire(import.meta.url);
    const pkg = require.resolve("@obsvr/sdk/package.json");
    candidates.push(join(dirname(pkg), "..", "conformance", "fixtures"));
  } catch {
    /* package.json not exported — the realpath candidate above covers it */
  }
  for (const dir of candidates) {
    if (existsSync(join(dir, "rules_hash.json"))) return dir;
  }
  return null;
}

export async function run() {
  const mock = await startMockIngest(); // obsvr ingest capture
  const stub = await startOpenAIStub(); // offline OpenAI-shaped provider

  // policyRefreshIntervalMs:0 so the mock's /policies poll (default { rules: [] })
  // can never overwrite the rules we pass in init.
  const initWrap = (policyRules, extra = {}) => {
    obsvr.init({
      apiKey: API_KEY,
      ingestUrl: mock.url,
      environment: "development",
      policyRules,
      policyRefreshIntervalMs: 0,
      ...extra,
    });
    // Fresh client each scenario: wrap() binds getConfig() at wrap time, and a
    // re-init replaces the config object.
    return obsvr.wrap(new OpenAI({ apiKey: "test", baseURL: stub.baseURL }));
  };

  const create = (client, model, content) =>
    client.chat.completions.create({ model, max_tokens: 16, messages: [{ role: "user", content }] });

  // ── 1) keyword rule (action: block) ────────────────────────────────────────
  {
    const oa = initWrap([
      { id: "kw-block", name: "Block embargo talk", enabled: true, action: "block", type: "keyword", conditions: { keywords: ["embargo"] } },
    ]);
    let blocked = false;
    try {
      await create(oa, "gpt-4o", "Please discuss the embargo details.");
    } catch (e) {
      blocked = /blocked by policy/i.test(String(e.message));
    }
    check("keyword rule blocks a matching prompt pre-call", blocked);

    const reply = await create(oa, "gpt-4o", "Say hello briefly.");
    check("clean prompt is allowed through to the offline provider", reply?.choices?.[0]?.message?.content === "stubbed offline reply");
  }

  // ── 2) regex rule (action: block) ──────────────────────────────────────────
  {
    const oa = initWrap([
      { id: "rx-block", name: "Block account numbers", enabled: true, action: "block", type: "regex", conditions: { pattern: "ACCT-[0-9]{6}" } },
    ]);
    let blocked = false;
    try {
      await create(oa, "gpt-4o", "Look up account ACCT-123456 for me.");
    } catch (e) {
      blocked = /blocked by policy/i.test(String(e.message));
    }
    check("regex rule matches and blocks the pattern", blocked);
  }

  // ── 3) model_gate rule: denied model blocks, allowed model passes ──────────
  {
    const oa = initWrap([
      { id: "mg-block", name: "Deny gpt-4 family", enabled: true, action: "block", type: "model_gate", conditions: { denied_models: ["gpt-4"] } },
    ]);
    let blocked = false;
    try {
      await create(oa, "gpt-4o", "Summarize this."); // gpt-4o ⊂ prefix "gpt-4"
    } catch (e) {
      blocked = /blocked by policy/i.test(String(e.message));
    }
    check("model_gate blocks a denied model (gpt-4o via prefix gpt-4)", blocked);

    const reply = await create(oa, "gpt-3.5-turbo", "Summarize this."); // not denied
    check("model_gate allows a non-denied model", reply?.choices?.[0]?.message?.content === "stubbed offline reply");
  }

  // ── 4) quota rule: the (limit+1)th governed call blocks ────────────────────
  {
    resetQuota("project", "project"); // isolate the per-process meter bucket
    const oa = initWrap([
      { id: "qt-block", name: "Per-project quota", enabled: true, action: "block", type: "quota", conditions: { quota_limit: 2, quota_window_ms: 60_000, quota_scope: "project" }, applies_to: "prompt" },
    ]);
    const a = await create(oa, "gpt-4o", "call one"); // count 1 <= 2 → allowed
    const b = await create(oa, "gpt-4o", "call two"); // count 2 <= 2 → allowed
    check("quota allows calls up to the limit", a?.choices?.[0]?.message?.content === "stubbed offline reply" && b?.choices?.[0]?.message?.content === "stubbed offline reply");
    let blocked = false;
    try {
      await create(oa, "gpt-4o", "call three"); // count 3 > 2 → blocked
    } catch (e) {
      blocked = /blocked by policy/i.test(String(e.message));
    }
    check("quota blocks the (limit+1)th governed call", blocked);
  }

  // ── 5) shadow rule: records what it WOULD do, never affects the decision ───
  {
    const oa = initWrap([
      { id: "sh-block", name: "Shadow block secretword", enabled: true, mode: "shadow", action: "block", type: "keyword", conditions: { keywords: ["secretword"] } },
    ]);
    const reply = await create(oa, "gpt-4o", "please handle secretword now"); // active = allow (shadow inert)
    check("shadow rule does NOT block the active call", reply?.choices?.[0]?.message?.content === "stubbed offline reply");
  }

  // ── explain(): check-only shape + no quota consumption ─────────────────────
  {
    const explainRules = [
      { id: "kw-embargo", name: "Block embargo", enabled: true, action: "block", type: "keyword", conditions: { keywords: ["embargo"] } },
      { id: "sh-secret", name: "Shadow block secretword", enabled: true, mode: "shadow", action: "block", type: "keyword", conditions: { keywords: ["secretword"] } },
    ];
    obsvr.init({ apiKey: API_KEY, ingestUrl: mock.url, environment: "development", policyRules: explainRules, policyRefreshIntervalMs: 0, piiPolicy: {} });

    const ex = explain("please review the embargo and secretword");
    check("explain(): active decision is block", ex.decision === "block");
    check("explain(): fired rule_id is the keyword rule", ex.rule_id === "kw-embargo");
    check("explain(): reason is a string", typeof ex.reason === "string" && ex.reason.length > 0);
    check("explain(): rules_hash equals derivePolicyVersion(rules)", ex.rules_hash === derivePolicyVersion(explainRules));
    check("explain(): pii shape { detected:false, types:[] } on clean text", ex.pii && ex.pii.detected === false && Array.isArray(ex.pii.types));
    check("explain(): shadow_outcome recorded { rule_id, would }", ex.shadow_outcome && ex.shadow_outcome.rule_id === "sh-secret" && ex.shadow_outcome.would === "block" && typeof ex.shadow_outcome.reason === "string");
    check("explain(): not_evaluated === ['customer_hook','multi_turn_injection']", JSON.stringify(ex.not_evaluated) === JSON.stringify(["customer_hook", "multi_turn_injection"]));

    const exPii = explain("my ssn is 123-45-6789");
    check("explain(): PII detected surfaces { detected:true, types:['ssn'...] }", exPii.pii.detected === true && exPii.pii.types.includes("ssn"));
    check("explain(): SSN under piiPolicy {} yields decision block", exPii.decision === "block");
  }

  // explain() consumes NO quota: 3 explains under a limit-1 quota rule leave the
  // real meter at 0.
  {
    resetQuota("user_id", "explain-probe-user");
    obsvr.init({
      apiKey: API_KEY,
      ingestUrl: mock.url,
      environment: "development",
      policyRules: [{ id: "q-probe", name: "probe quota", enabled: true, action: "block", type: "quota", conditions: { quota_limit: 1, quota_window_ms: 60_000, quota_scope: "user_id" } }],
      policyRefreshIntervalMs: 0,
    });
    for (let i = 0; i < 3; i++) explain("hello there", { metadata: { user_id: "explain-probe-user" } });
    const status = getQuotaStatus("user_id", "explain-probe-user", 1, 60_000);
    check("explain() consumes no quota (meter used stays 0 after 3 explains)", status.used === 0);
  }

  // ── derivePolicyVersion / deriveRuleHash vs the cross-SDK fixture ──────────
  const fixturesDir = resolveFixturesDir();
  if (!fixturesDir) {
    check("conformance fixtures resolved", false, "could not locate conformance/fixtures via the linked @obsvr/sdk");
  } else {
    const fx = JSON.parse(readFileSync(join(fixturesDir, "rules_hash.json"), "utf8"));
    check(`derivePolicyVersion(fixture.rules) === set_hash ${fx.expected.set_hash}`, derivePolicyVersion(fx.rules) === fx.expected.set_hash);
    check(`derivePolicyVersion([]) === ${fx.expected.empty_set_hash}`, derivePolicyVersion([]) === fx.expected.empty_set_hash);
    check(`all-disabled rule set hashes to ${fx.expected.all_disabled_hash}`, derivePolicyVersion(fx.rules.map((r) => ({ ...r, enabled: false }))) === fx.expected.all_disabled_hash);
    for (const [id, expected] of Object.entries(fx.expected.rule_hashes)) {
      const rule = fx.rules.find((r) => r.id === id);
      check(`deriveRuleHash(${id}) === ${expected}`, !!rule && deriveRuleHash(rule) === expected);
    }

    // effective_policy.json is an INGEST-side effective-policy RESOLUTION fixture
    // (pack < org < project ordering, override semantics) executed by the ingest
    // tests — it does not map to the SDK's exportToRego output, so it is
    // consciously deferred here.
    const ep = JSON.parse(readFileSync(join(fixturesDir, "effective_policy.json"), "utf8"));
    check("effective_policy.json deferred (ingest resolution fixture, not a rego-export mapping)", Array.isArray(ep.cases) && ep.cases.some((c) => "packs" in c || "org_rules" in c || "project_rules" in c));
  }

  // ── exportToRego(): fixed-module smoke + delegation ───────────────────────
  {
    const regoRules = [
      { id: "kw-embargo", name: "Block embargo", enabled: true, action: "block", type: "keyword", conditions: { keywords: ["embargo"] } },
      { id: "qt-quota", name: "Stateful quota", enabled: true, action: "block", type: "quota", conditions: { quota_limit: 5, quota_window_ms: 1_000, quota_scope: "project" } },
    ];
    const bundle = exportToRego(regoRules);
    check("rego bundle declares `package obsvr.policy`", bundle.rego.includes("package obsvr.policy"));
    check("rego bundle carries the first-match decision predicate", bundle.rego.includes("default decision") && bundle.rego.includes("decision :="));
    check("rego data.json exports the keyword rule id", bundle.data.includes("kw-embargo"));
    check("rego bundle rules_hash === derivePolicyVersion(rules)", bundle.rules_hash === derivePolicyVersion(regoRules));
    check("stateful quota rule is delegated, not exported to rego", bundle.delegated.some((d) => d.rule_id === "qt-quota" && d.type === "quota"));
    check("rego manifest names the entrypoint data.obsvr.policy.decision", bundle.manifest.includes("data.obsvr.policy.decision"));
  }

  // ── governance envelope + full-chain verification ─────────────────────────
  await obsvr.flush();
  const events = mock.getEvents();
  showEvents(events);

  const kwBlockedEv = events.find((e) => e.event_type === "blocked_call" && e.rule_id === "kw-block");
  const rxBlockedEv = events.find((e) => e.event_type === "blocked_call" && e.rule_id === "rx-block");
  const mgBlockedEv = events.find((e) => e.event_type === "blocked_call" && e.rule_id === "mg-block");
  const qtBlockedEv = events.find((e) => e.event_type === "blocked_call" && e.rule_id === "qt-block");
  const shadowEv = events.find((e) => e.event_type === "llm_call" && e.shadow_outcome);

  check("keyword block recorded as a signed blocked_call", !!kwBlockedEv);
  check("regex block recorded as a signed blocked_call", !!rxBlockedEv);
  check("model_gate block recorded as a signed blocked_call", !!mgBlockedEv);
  check("quota block recorded as a signed blocked_call", !!qtBlockedEv);
  check("shadow outcome rode an ALLOWED llm_call (active decision unaffected)", !!shadowEv && shadowEv.action_taken === "allowed");
  check("shadow_outcome shape { rule_id, would, reason } on the event", shadowEv?.shadow_outcome?.rule_id === "sh-block" && shadowEv.shadow_outcome.would === "block" && typeof shadowEv.shadow_outcome.reason === "string");

  // Governance blocked_call + llm_call carry the full signed decision record.
  const govBlocked = kwBlockedEv || events.find((e) => e.event_type === "blocked_call");
  if (govBlocked) assertSignedEvent(govBlocked, "governance blocked_call");
  const govLlm = events.find((e) => e.event_type === "llm_call");
  if (govLlm) assertSignedEvent(govLlm, "governance llm_call");

  verifyCapturedChain(events, API_KEY, "rules-suite chain");

  await obsvr.flush();
  await mock.stop();
  await stub.stop();
  return done.results();
}

if (import.meta.url === `file://${process.argv[1]}`) run();
