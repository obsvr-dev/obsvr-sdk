/**
 * deny-wins — declared conflict resolution, where rule ORDER stops mattering.
 *
 * Twin of py/integrations/deny-wins/test.py. TypeScript reached this only
 * indirectly before 2026-08-04, through external-backend's merge path; this
 * drives the local engine directly.
 *
 * `ruleResolution` declares how a ruleset resolves when several rules match:
 *
 *   first_match (the original contract, and what an UNDECLARED ruleset does)
 *       the first rule that renders an outcome decides, so a matched
 *       `topic_allow` pre-empts every rule after it. The verdict is a function
 *       of DOCUMENT ORDER.
 *
 *   deny_wins (opt-in)
 *       every rule is evaluated and the STRONGEST outcome prevails
 *       (block > redact > flag > permit); ties break on the smallest rule id.
 *       Both keys are order-insensitive, so every permutation of the same rule
 *       list must resolve to the same verdict AND the same recorded rule_id.
 *
 * THE CLAIM UNDER TEST is a property, not an example: *the same rules in
 * reverse order produce the same verdict under deny_wins, and do NOT under
 * first_match.* Testing only the deny_wins half would pass against an engine
 * that blocks everything, so the first_match half is what gives it meaning.
 *
 * DISCIPLINE: every verdict is measured by what the CALLER RECEIVED and by a
 * SIDE-EFFECT execution count (one appended line per request the stub serves),
 * never inferred from the events under test.
 *
 * Offline: no provider key, no network beyond loopback.
 *
 *   node integrations/deny-wins/test.mjs
 */
import { createServer } from "node:http";
import { mkdtempSync, appendFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import OpenAI from "openai";
import { obsvr } from "@obsvr/sdk";
import { startMockIngest } from "../../lib/mock-ingest.mjs";
import { check, done } from "../../lib/check.mjs";

export const meta = { offline: true };

const API_KEY = process.env.OBSVR_API_KEY || "obsvr-test-key";

/** Both rules match this text, so the pair genuinely conflicts. */
const PROMPT = "the quarterly embargo briefing for partners";

/** The permitting rule. `action` is constrained to block/redact/flag by the
 *  /policies validator — "allow" is NOT an action, it is what the topic_allow
 *  TYPE renders. A rule declaring action "allow" is rejected on the poll and
 *  lands as `sdk:rule_rejected`, which reads exactly like a working deny. */
const ALLOW_RULE = {
  id: "a-allow-briefing",
  name: "Briefings are allowed",
  enabled: true,
  action: "flag",
  type: "topic_allow",
  conditions: { topics: ["briefing"] },
};
const BLOCK_RULE = {
  id: "b-block-embargo",
  name: "Block embargo talk",
  enabled: true,
  action: "block",
  type: "keyword",
  conditions: { keywords: ["embargo"] },
};

let TMP, MARKER;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function marks() {
  return existsSync(MARKER) ? readFileSync(MARKER, "utf8").split("\n").filter(Boolean).length : 0;
}

function startOpenAIStub() {
  const server = createServer((req, res) => {
    let b = ""; req.on("data", (c) => (b += c));
    req.on("end", () => {
      appendFileSync(MARKER, "call\n");
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ id: "c", object: "chat.completion", created: 0, model: "gpt-4o-mini", choices: [{ index: 0, message: { role: "assistant", content: "PROVIDER_PAYLOAD" }, finish_reason: "stop" }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } }));
    });
  });
  return new Promise((r) => server.listen(0, "127.0.0.1", () => r({ port: server.address().port, stop: () => new Promise((res) => server.close(res)) })));
}

/** Drive one call under a rule ORDER and a declared resolution. */
async function verdict(rules, ruleResolution) {
  const stub = await startOpenAIStub();
  const ingest = await startMockIngest({ policies: { rules } });
  obsvr._reset();
  obsvr.init({
    apiKey: API_KEY,
    ingestUrl: ingest.url,
    environment: "development",
    policyRefreshIntervalMs: 50,
    ...(ruleResolution ? { ruleResolution } : {}),
  });
  const client = obsvr.wrap(new OpenAI({ apiKey: "test-not-real", baseURL: `http://127.0.0.1:${stub.port}/v1` }), {
    user_id: "user_alice",
    service_name: "billing-svc",
  });
  await ingest.waitForPoll(1, 3000);
  await sleep(120);

  const before = marks();
  let payload = null;
  let threw = null;
  try {
    const res = await client.chat.completions.create({ model: "gpt-4o-mini", max_tokens: 8, messages: [{ role: "user", content: PROMPT }] });
    payload = res?.choices?.[0]?.message?.content ?? null;
  } catch (e) {
    threw = e;
  }
  await obsvr.flush();
  const ev = ingest.getEvents()[0];
  obsvr._reset();
  await ingest.stop();
  await stub.stop();
  return {
    executions: marks() - before,
    payload,
    blocked: threw !== null,
    rule_id: ev?.rule_id,
    engine_version: ev?.engine_version,
  };
}

export async function run() {
  TMP = mkdtempSync(join(tmpdir(), "obsvr-denywins-"));
  MARKER = join(TMP, "executions.log");

  try {
    const forward = [ALLOW_RULE, BLOCK_RULE];
    const reverse = [BLOCK_RULE, ALLOW_RULE];

    // ── first_match: ORDER DECIDES ──────────────────────────────────────────
    // This half is what gives the deny_wins half meaning. Without it, "both
    // orders blocked" is equally consistent with an engine that blocks
    // everything and never reads the rules at all.
    const fmAllowFirst = await verdict(forward, "first_match");
    const fmBlockFirst = await verdict(reverse, "first_match");

    check("first_match [allow, block]: the allow pre-empts — the call RUNS", fmAllowFirst.executions === 1 && !fmAllowFirst.blocked, `executions=${fmAllowFirst.executions} blocked=${fmAllowFirst.blocked}`);
    check("first_match [allow, block]: the caller receives the provider payload", fmAllowFirst.payload === "PROVIDER_PAYLOAD", String(fmAllowFirst.payload));
    check("first_match [block, allow]: the block comes first — ZERO executions", fmBlockFirst.executions === 0 && fmBlockFirst.blocked, `executions=${fmBlockFirst.executions} blocked=${fmBlockFirst.blocked}`);
    check("first_match [block, allow]: the caller received NO payload", fmBlockFirst.payload === null, String(fmBlockFirst.payload));
    check(
      "first_match: REVERSING the same rules CHANGES the verdict (order-sensitive)",
      fmAllowFirst.blocked !== fmBlockFirst.blocked,
      `allow-first blocked=${fmAllowFirst.blocked} block-first blocked=${fmBlockFirst.blocked}`,
    );

    // ── deny_wins: ORDER STOPS MATTERING ────────────────────────────────────
    const dwAllowFirst = await verdict(forward, "deny_wins");
    const dwBlockFirst = await verdict(reverse, "deny_wins");

    check("deny_wins [allow, block]: the block prevails — ZERO executions", dwAllowFirst.executions === 0 && dwAllowFirst.blocked, `executions=${dwAllowFirst.executions}`);
    check("deny_wins [allow, block]: the caller received NO payload", dwAllowFirst.payload === null, String(dwAllowFirst.payload));
    check("deny_wins [block, allow]: the block prevails from the other position too", dwBlockFirst.executions === 0 && dwBlockFirst.blocked, `executions=${dwBlockFirst.executions}`);
    // THE CLAIM.
    check(
      "deny_wins: REVERSING the same rules produces the SAME verdict (order-insensitive)",
      dwAllowFirst.blocked === true && dwBlockFirst.blocked === true,
      `allow-first blocked=${dwAllowFirst.blocked} block-first blocked=${dwBlockFirst.blocked}`,
    );
    // Not just the same verdict — the same RECORDED RULE. A resolution that
    // agreed on "blocked" while naming a different rule per permutation would
    // still make the audit trail order-dependent.
    check(
      "deny_wins: both orders record the SAME rule_id, not just the same verdict",
      dwAllowFirst.rule_id === dwBlockFirst.rule_id && dwAllowFirst.rule_id === BLOCK_RULE.id,
      `${dwAllowFirst.rule_id} vs ${dwBlockFirst.rule_id}`,
    );

    // ── the declared mode is stamped on the record ──────────────────────────
    check("deny_wins is stamped as engine_version obsvr-rules/2", dwAllowFirst.engine_version === "obsvr-rules/2", String(dwAllowFirst.engine_version));
    check("first_match is stamped as engine_version obsvr-rules/1", fmBlockFirst.engine_version === "obsvr-rules/1", String(fmBlockFirst.engine_version));

    // ── UNDECLARED evaluates as first_match ────────────────────────────────
    // The compatibility promise: a ruleset that never declared a mode must not
    // silently change behaviour when the feature ships.
    const undeclared = await verdict(forward, undefined);
    check("an UNDECLARED ruleset still evaluates as first_match (the allow pre-empts)", undeclared.executions === 1 && !undeclared.blocked, `executions=${undeclared.executions} blocked=${undeclared.blocked}`);
    check("an UNDECLARED ruleset is stamped obsvr-rules/1, like an explicit first_match", undeclared.engine_version === "obsvr-rules/1", String(undeclared.engine_version));

    return done.results();
  } finally {
    obsvr._reset();
    rmSync(TMP, { recursive: true, force: true });
  }
}

if (import.meta.url === `file://${process.argv[1]}`) run();
