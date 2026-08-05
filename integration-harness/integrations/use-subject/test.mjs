/**
 * use-subject — the ambient per-request principal, in TypeScript.
 *
 * `useSubject` was mentioned in two TS suites before 2026-08-04 (llamaindex,
 * spans) but nothing drove the claim that matters: the ambient principal must
 * reach BOTH channels.
 *
 *   the SIGNED RECORD      — buildAuditEvent resolves the principal
 *   the ENFORCING CHANNEL  — the per-user quota bucket, the session-taint key,
 *                            the requirePrincipal gate, the decision digest
 *
 * Testing only the record would have passed while the enforcing side saw
 * nobody — the shape of the bug fixed three commits before this suite was
 * written, where an ambient-only principal was attributed on the record but
 * invisible to enforcement, so the SDK refused a call whose own event named
 * the principal the refusal said was missing.
 *
 * The enforcing channel is driven through a per-user QUOTA, because a quota is
 * the one control whose behaviour PROVES which bucket it counted in: give it a
 * limit of 1, and whether the second call is refused tells you whether the SDK
 * considered it the same principal. Two different ambient subjects must not
 * share a bucket, and one subject must share it with itself.
 *
 * DISCIPLINE: executions are counted with a SIDE EFFECT (one appended line per
 * request the stub serves), and every leg asserts what the CALLER RECEIVED.
 *
 * Offline: no provider key, no network beyond loopback.
 *
 *   node integrations/use-subject/test.mjs
 */
import { createServer } from "node:http";
import { mkdtempSync, appendFileSync, readFileSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import OpenAI from "openai";
import { obsvr, useSubject } from "@obsvr/sdk";
import { startMockIngest } from "../../lib/mock-ingest.mjs";
import { check, done } from "../../lib/check.mjs";

export const meta = { offline: true };

const API_KEY = process.env.OBSVR_API_KEY || "obsvr-test-key";

/** A per-USER quota of 1. The bucket a call lands in is only observable
 *  through whether the NEXT call is refused, which is what makes this the
 *  right probe for "did the enforcing channel see the ambient principal?". */
const USER_QUOTA_RULE = {
  id: "q-per-user",
  name: "One call per user",
  enabled: true,
  action: "block",
  type: "quota",
  conditions: { quota_limit: 1, quota_window_ms: 60_000, quota_scope: "user_id" },
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

/**
 * Run the alice/alice/bob quota sequence in a CLEAN interpreter, attributing
 * either explicitly or through the ambient scope, and return the three verdicts.
 *
 * A fresh process is required, not preferred: the quota meter is process-global
 * and survives obsvr._reset(), so a second scenario in this process would start
 * already-spent and report "blocked" for a reason that has nothing to do with
 * the principal. Returns "" if the child could not run, which fails the check
 * rather than silently comparing two empty strings.
 */
function runFresh(mode) {
  const script = `
import { createServer } from "node:http";
import OpenAI from "openai";
import { obsvr, useSubject } from "@obsvr/sdk";
import { startMockIngest } from "./lib/mock-ingest.mjs";
const RULE = ${JSON.stringify(USER_QUOTA_RULE)};
const srv = createServer((q, s) => { let b = ""; q.on("data", d => b += d); q.on("end", () => { s.writeHead(200, {"content-type":"application/json"}); s.end(JSON.stringify({id:"c",object:"chat.completion",created:0,model:"m",choices:[{index:0,message:{role:"assistant",content:"ok"},finish_reason:"stop"}],usage:{prompt_tokens:1,completion_tokens:1,total_tokens:2}})); }); });
await new Promise(r => srv.listen(0, "127.0.0.1", r));
const ing = await startMockIngest({ policies: { rules: [RULE] } });
obsvr.init({ apiKey: "k", ingestUrl: ing.url, environment: "development", policyRefreshIntervalMs: 50 });
await ing.waitForPoll(1, 3000); await new Promise(r => setTimeout(r, 150));
const base = \`http://127.0.0.1:\${srv.address().port}/v1\`;
const t = async (c, x) => { try { await c.chat.completions.create({ model: "m", messages: [{ role: "user", content: x }] }); return "allowed"; } catch { return "blocked"; } };
let out;
if ("${mode}" === "ambient") {
  const c = obsvr.wrap(new OpenAI({ apiKey: "x", baseURL: base }));
  out = [await useSubject("user:alice", () => t(c, "a1")), await useSubject("user:alice", () => t(c, "a2")), await useSubject("user:bob", () => t(c, "b1"))];
} else {
  const ca = obsvr.wrap(new OpenAI({ apiKey: "x", baseURL: base }), { user_id: "alice" });
  const cb = obsvr.wrap(new OpenAI({ apiKey: "x", baseURL: base }), { user_id: "bob" });
  out = [await t(ca, "a1"), await t(ca, "a2"), await t(cb, "b1")];
}
console.log("VERDICTS" + out.join(","));
process.exit(0);
`;
  const file = join(TMP, `fresh-${mode}.mjs`);
  try {
    // Written INSIDE the harness so bare specifiers (@obsvr/sdk, openai)
    // resolve exactly as they do for a real consumer.
    const target = join(process.cwd(), `.use-subject-${mode}.mjs`);
    writeFileSync(target, script, "utf8");
    try {
      const out = execFileSync("node", [target], { encoding: "utf8" });
      const line = out.split("\n").find((l) => l.startsWith("VERDICTS"));
      return line ? line.slice("VERDICTS".length) : "";
    } finally {
      rmSync(target, { force: true });
    }
  } catch {
    return "";
  }
}

/** A governed client plus its capture, reusable across several calls. */
async function session({ rules = [], wrapOpts = {} } = {}) {
  const stub = await startOpenAIStub();
  const ingest = await startMockIngest({ policies: { rules } });
  obsvr._reset();
  obsvr.init({ apiKey: API_KEY, ingestUrl: ingest.url, environment: "development", policyRefreshIntervalMs: 50 });
  const client = obsvr.wrap(new OpenAI({ apiKey: "test-not-real", baseURL: `http://127.0.0.1:${stub.port}/v1` }), wrapOpts);
  await ingest.waitForPoll(1, 3000);
  await sleep(120);

  return {
    /** One governed call; returns { ran, payload }. */
    async call(text = "hello") {
      const before = marks();
      try {
        const res = await client.chat.completions.create({ model: "gpt-4o-mini", max_tokens: 8, messages: [{ role: "user", content: text }] });
        return { ran: marks() - before === 1, payload: res?.choices?.[0]?.message?.content ?? null };
      } catch {
        return { ran: marks() - before === 1, payload: null };
      }
    },
    async principals() {
      await obsvr.flush();
      return ingest.getEvents().filter((e) => e.event_type === "llm_call" || e.event_type === "blocked_call").map((e) => e.user_id);
    },
    async close() {
      // FLUSH BEFORE RESET, always. _reset() with events still queued leaves
      // the sender wedged for the rest of the process — the next suite in the
      // run then captures nothing at all and reads as a broken integration.
      // (Found the hard way: this suite's quota block was the one path that
      // closed without flushing, and it silently took the mcp suite down with
      // it in the full offline run.)
      await obsvr.flush();
      obsvr._reset();
      await ingest.stop();
      await stub.stop();
    },
  };
}

export async function run() {
  TMP = mkdtempSync(join(tmpdir(), "obsvr-subject-"));
  MARKER = join(TMP, "executions.log");

  try {
    // ── 1. THE SIGNED RECORD ────────────────────────────────────────────────
    {
      const s = await session();
      await s.call("outside any scope");
      await useSubject("user:alice;tenant:acme;service:billing", () => s.call("inside the scope"));
      await s.call("after the scope");
      const got = await s.principals();
      await s.close();
      check("a call OUTSIDE any scope records no ambient principal", got[0] == null, JSON.stringify(got));
      check("a call INSIDE useSubject records that principal on the signed event", got[1] === "alice", JSON.stringify(got));
      check("the scope does not leak: the call AFTER it records no principal", got[2] == null, JSON.stringify(got));
    }

    // Explicit-wins precedence.
    {
      const s = await session({ wrapOpts: { user_id: "wrapped_bob" } });
      await useSubject("user:alice", () => s.call("explicit vs ambient"));
      const got = await s.principals();
      await s.close();
      check("an EXPLICIT wrap-time principal wins over the ambient scope", got[0] === "wrapped_bob", JSON.stringify(got));
    }

    // Parsing forms + nested merge.
    {
      const s = await session();
      await useSubject("bare_carol", () => s.call("bare token is a user id"));
      await useSubject({ user_id: "obj_dave" }, () => s.call("object form"));
      await useSubject("user:outer", async () => {
        await useSubject("tenant:inner_only", () => s.call("nested merge keeps the outer user"));
        await useSubject("user:inner_wins", () => s.call("nested merge, inner user wins"));
      });
      const got = await s.principals();
      await s.close();
      check("a bare token parses as the user id", got[0] === "bare_carol", JSON.stringify(got));
      check("an object subject is accepted", got[1] === "obj_dave", JSON.stringify(got));
      check("nested scopes MERGE over the enclosing subject", got[2] === "outer", JSON.stringify(got));
      check("nested scopes let the inner value win", got[3] === "inner_wins", JSON.stringify(got));
    }

    // The scope must be restored when the block throws, or one failed request
    // leaks its identity onto later, unrelated calls.
    {
      const s = await session();
      try {
        await useSubject("user:exploding", () => { throw new Error("boom"); });
      } catch { /* expected */ }
      await s.call("after a throw inside the scope");
      const got = await s.principals();
      await s.close();
      check("a throw inside the scope does not leak the identity onward", got[0] == null, JSON.stringify(got));
    }

    // The ambient scope must survive an await inside it — the ordinary shape
    // of every real async handler.
    {
      const s = await session();
      await useSubject("user:async_alice", async () => {
        await sleep(10);
        await s.call("after an await inside the scope");
      });
      const got = await s.principals();
      await s.close();
      check("the ambient subject SURVIVES an await inside the scope", got[0] === "async_alice", JSON.stringify(got));
    }

    // ── 2. THE ENFORCING CHANNEL ────────────────────────────────────────────
    // A per-user quota of 1. If the ambient principal reaches enforcement,
    // alice's second call is refused while bob's first is not.
    {
      // The fresh-process comparison runs FIRST, while no governed session is
      // open. execFileSync blocks this process's event loop for the child's
      // lifetime, and doing that with a live sender wedges it — the next suite
      // in the run then captures no events at all. Ask the children first,
      // then open the session.
      const explicit = runFresh("explicit");
      const ambient = runFresh("ambient");

      const s = await session({ rules: [USER_QUOTA_RULE] });
      const a1 = await useSubject("user:alice", () => s.call("alice 1"));
      const a2 = await useSubject("user:alice", () => s.call("alice 2"));
      const b1 = await useSubject("user:bob", () => s.call("bob 1"));
      await s.close();

      check("quota: alice's FIRST call runs", a1.ran === true && a1.payload === "PROVIDER_PAYLOAD", JSON.stringify(a1));
      check(
        "quota: alice's SECOND call is refused — the ambient principal reached the ENFORCING channel",
        a2.ran === false && a2.payload === null,
        `${JSON.stringify(a2)} — the quota never metered the ambient subject at all`,
      );

      // THE useSubject CLAIM, stated as the comparison that isolates it: the
      // ambient path must enforce exactly as an EXPLICIT principal does. Run
      // in fresh processes (above) because the quota meter is process-global
      // and a second scenario in this one would start already-spent.
      check(
        "the AMBIENT principal enforces identically to an EXPLICIT one",
        explicit === ambient && explicit !== "",
        `explicit=[${explicit}] ambient=[${ambient}]`,
      );

      // A PER-USER QUOTA ISOLATES BY PRINCIPAL. The leg that makes "per user"
      // mean per user: bob has spent nothing, so his first call runs even
      // though alice has exhausted her own limit of 1.
      //
      // Found by this suite 2026-08-04 as a cross-language divergence — under
      // quota_scope "user_id" with limit 1, Python allowed bob's first call
      // and TypeScript refused it — and closed the same week. The cause was
      // not useSubject: TS behaved identically under an EXPLICIT user_id,
      // because the rules eval context was built from raw per-call metadata,
      // so a principal arriving by wrap-time option or ambient scope metered
      // the shared 'default' bucket and one user's spend exhausted the limit
      // for everyone. The wrap path now resolves the principal once and the
      // quota keys on that.
      check(
        "quota: a DIFFERENT principal's first call runs — the limit is per user",
        b1.ran === true && b1.payload === "PROVIDER_PAYLOAD",
        `${JSON.stringify(b1)} — bob has spent nothing; a per-user limit must not refuse him for alice's spend`,
      );
    }

    return done.results();
  } finally {
    obsvr._reset();
    rmSync(TMP, { recursive: true, force: true });
  }
}

if (import.meta.url === `file://${process.argv[1]}`) run();
