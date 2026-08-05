/**
 * approval-wait — the BLOCKING human-in-the-loop hold (`approvalWaitMs`).
 *
 * A `require_approval` rule refuses a call until a human grants it. Without a
 * wait budget the refusal is immediate: the SDK files an approval request and
 * tells the caller to come back. With `approvalWaitMs > 0` the call is instead
 * HELD in the caller's thread while the SDK re-polls the grant channel, and
 * resolves exactly one of three ways — granted, timed out, or unavailable.
 *
 * WHY EACH LEG EXISTS:
 *
 *   - The hold is measured with a CLOCK, not with a mock. "It waited" is the
 *     whole feature; asserting it against a stubbed timer would prove only that
 *     the stub was called. Elapsed time is bounded on BOTH sides — a release
 *     that returns instantly did not hold, and one that runs to the deadline
 *     did not release.
 *   - Every refusal is paired with an ALLOW CONTROL over the same rule. A
 *     provider call that never happened looks identical to one that was
 *     refused.
 *   - Execution is counted with a SIDE EFFECT (one appended line per request
 *     the stub serves), never inferred from events — events are what is under
 *     test.
 *   - Every leg asserts what the CALLER RECEIVED, because zero executions is
 *     not refusal on its own.
 *
 * The grant channel is the /policies poll, exactly as in production: grants
 * ride the same document as the rules, so the wait adds no second, weaker way
 * in. The mock serves `{ rules, approvals }` and the suite mutates `approvals`
 * mid-flight to simulate a human clicking approve.
 *
 * APPROVAL_TIMEOUT is deliberately NOT APPROVAL_REQUIRED: the first means
 * "we asked and waited and nobody answered", the second means "refused; ask and
 * retry". Collapsing them would erase whether a human was ever given the
 * chance, so both codes are asserted by name.
 *
 * Offline: no provider key, no network beyond loopback.
 *
 *   node integrations/approval-wait/test.mjs
 */
import { createServer } from "node:http";
import { mkdtempSync, appendFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import OpenAI from "openai";
import { obsvr } from "@obsvr/sdk";
import { startMockIngest } from "../../lib/mock-ingest.mjs";
import { check, done } from "../../lib/check.mjs";
import { assertSignedEvent } from "../../lib/assert-governance.mjs";

export const meta = { offline: true };

const API_KEY = process.env.OBSVR_API_KEY || "obsvr-test-key";
const RULE_ID = "wire-transfer-approval";
const TRIGGER = "please wire the funds";

const APPROVAL_RULE = {
  id: RULE_ID,
  name: "Wire transfers need a human",
  enabled: true,
  action: "block",
  type: "keyword",
  conditions: { keywords: ["wire"], require_approval: true },
};

/** A grant that covers the rule and has not expired. Bound only to the rule:
 *  the SDK's finer pins (rule_hash / action_hash) only narrow, so a grant that
 *  omits them is exactly as strong as the issuer made it. */
const grant = (secondsAhead = 300) => ({
  rule_id: RULE_ID,
  expires_at: new Date(Date.now() + secondsAhead * 1000).toISOString(),
});

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

/** Stand up a governed client with the approval rule and a wait budget. */
async function scenario({ approvalWaitMs, approvals = [] }) {
  const stub = await startOpenAIStub();
  const ingest = await startMockIngest({ policies: { rules: [APPROVAL_RULE], approvals } });
  obsvr._reset();
  obsvr.init({
    apiKey: API_KEY,
    ingestUrl: ingest.url,
    environment: "development",
    policyRefreshIntervalMs: 50,
    approvalWaitMs,
    approvalPollMs: 100, // poll briskly so a 2s budget is not mostly idle
  });
  const client = obsvr.wrap(new OpenAI({ apiKey: "test-not-real", baseURL: `http://127.0.0.1:${stub.port}/v1` }), {
    user_id: "user_alice",
    service_name: "billing-svc",
  });
  await ingest.waitForPoll(1, 3000);
  await sleep(120);
  return { stub, ingest, client };
}

/** Make one governed call, timing it and reporting what the caller received. */
async function timedCall(client, prompt) {
  const before = marks();
  const started = Date.now();
  let payload = null;
  let threw = null;
  try {
    const res = await client.chat.completions.create({ model: "gpt-4o-mini", max_tokens: 8, messages: [{ role: "user", content: prompt }] });
    payload = res?.choices?.[0]?.message?.content ?? null;
  } catch (e) {
    threw = e;
  }
  return { elapsed: Date.now() - started, executions: marks() - before, payload, threw };
}

async function teardown({ stub, ingest }) {
  await obsvr.flush();
  const events = ingest.getEvents();
  const requests = ingest.approvalRequests();
  obsvr._reset();
  await ingest.stop();
  await stub.stop();
  return { events, requests };
}

export async function run() {
  TMP = mkdtempSync(join(tmpdir(), "obsvr-approval-"));
  MARKER = join(TMP, "executions.log");

  try {
    // ── ALLOW CONTROL: the same ruleset, a prompt that does NOT trip it ─────
    // Without this, every hold and refusal below is consistent with an SDK
    // that blocked everything, or a stub that was never reachable.
    {
      const s = await scenario({ approvalWaitMs: 0 });
      const r = await timedCall(s.client, "just say hello");
      const { events } = await teardown(s);
      check("control: a non-matching prompt RUNS under the same approval rule — executions: 1", r.executions === 1, `executions: ${r.executions}`);
      check("control: the caller receives the provider payload", r.payload === "PROVIDER_PAYLOAD", String(r.payload));
      check("control: nothing recorded a block", !events.some((e) => e.event_type === "blocked_call"));
    }

    // ── waitMs = 0: refuse IMMEDIATELY and file a request ───────────────────
    {
      const s = await scenario({ approvalWaitMs: 0 });
      const r = await timedCall(s.client, TRIGGER);
      const { events, requests } = await teardown(s);

      check("wait=0: ZERO executions — the provider was never called", r.executions === 0, `executions: ${r.executions}`);
      check("wait=0: the caller received NO payload", r.payload === null, String(r.payload));
      check("wait=0: the caller got a refusal", r.threw !== null);
      // The defining property of wait=0: it does not hold. Generous bound so
      // this is about "did not wait", not about machine speed.
      check("wait=0: the call did NOT hold (returned promptly)", r.elapsed < 1500, `elapsed ${r.elapsed}ms`);

      const blocked = events.find((e) => e.event_type === "blocked_call");
      check("wait=0: a blocked_call event is recorded", !!blocked);
      check("wait=0: recorded under APPROVAL_REQUIRED (ask and retry)", blocked?.reason_code === "APPROVAL_REQUIRED", String(blocked?.reason_code));
      check("wait=0: the block names the approval rule", blocked?.rule_id === RULE_ID, String(blocked?.rule_id));
      if (blocked) assertSignedEvent(blocked, "approval refusal");

      // A refusal that files no request leaves the human nothing to approve.
      check("wait=0: an approval REQUEST was filed for a human to act on", requests.length >= 1, `${requests.length} requests`);
      check("wait=0: the filed request names the rule it is asking about", requests[0]?.rule_id === RULE_ID, JSON.stringify(requests[0]));
      // Binding fields the grant channel narrows on, so an issued grant can be
      // pinned to this rule version and this exact call rather than to
      // "anything that trips this rule".
      check(
        "wait=0: the request carries the rule_hash and action_hash bindings",
        typeof requests[0]?.rule_hash === "string" && typeof requests[0]?.action_hash === "string",
        JSON.stringify(requests[0]),
      );

      // THE RECORD AND THE REQUEST CHANNEL NAME THE SAME PRINCIPAL. Asserted
      // as a pair, because the failure this suite found was the two
      // disagreeing about one call: the blocked event named user_alice while
      // the request filed for it carried no user_id at all, so a reviewer was
      // asked to authorise a wire transfer without being told who asked, and
      // an issuer wanting to bind the grant to that principal had nothing to
      // bind to — while hasApproval() narrows on user_id whenever a grant
      // declares one. Found by this suite 2026-08-04 and closed the same
      // week: the wrap path now resolves the principal once, from per-call
      // metadata / wrap-time option / ambient subject, and every consumer
      // reads that one view. Python asserts the same pair positively in
      // py/integrations/approval-wait/test.py.
      //
      // Here the principal arrives by the WRAP-TIME option, which is the
      // channel that was dropped; keep it that way, or this stops covering
      // the case it was written for.
      check(
        "the blocked event for this call names the principal",
        blocked?.user_id === "user_alice",
        String(blocked?.user_id),
      );
      check(
        "and the approval request filed for it names the SAME principal",
        requests[0]?.user_id === "user_alice",
        `user_id on the request: ${JSON.stringify(requests[0]?.user_id)} — the record and the request channel must agree about one call`,
      );
    }

    // ── waitMs > 0, grant ALREADY present: released without holding ─────────
    // Separates "a grant releases the call" from "the wait loop released it",
    // so the timed leg below is about the WAIT rather than about grants.
    {
      const s = await scenario({ approvalWaitMs: 2000, approvals: [grant()] });
      const r = await timedCall(s.client, TRIGGER);
      const { events } = await teardown(s);
      check("pre-existing grant: the held call RUNS — executions: 1", r.executions === 1, `executions: ${r.executions}`);
      check("pre-existing grant: the caller receives the provider payload", r.payload === "PROVIDER_PAYLOAD", String(r.payload));
      check("pre-existing grant: nothing recorded a block", !events.some((e) => e.event_type === "blocked_call"));
      check("pre-existing grant: the call did not burn the wait budget", r.elapsed < 1500, `elapsed ${r.elapsed}ms`);
    }

    // ── waitMs > 0, grant ARRIVES DURING the wait: HELD, then released ──────
    {
      const s = await scenario({ approvalWaitMs: 4000, approvals: [] });
      const GRANT_AT = 700;
      // The human clicks approve while the caller is still blocked.
      const approver = sleep(GRANT_AT).then(() => s.ingest.setPolicies({ rules: [APPROVAL_RULE], approvals: [grant()] }));
      const r = await timedCall(s.client, TRIGGER);
      await approver;
      const { events } = await teardown(s);

      check("grant during wait: the call was RELEASED and ran — executions: 1", r.executions === 1, `executions: ${r.executions}`);
      check("grant during wait: the caller receives the provider payload", r.payload === "PROVIDER_PAYLOAD", String(r.payload));
      check("grant during wait: no refusal was recorded", !events.some((e) => e.event_type === "blocked_call"));
      // Bounded on BOTH sides, by the clock: it really held until the grant
      // landed, and it really released rather than running to the deadline.
      check(
        `grant during wait: the call was HELD until the grant (>= ${GRANT_AT}ms)`,
        r.elapsed >= GRANT_AT,
        `elapsed ${r.elapsed}ms — released before the grant existed`,
      );
      check(
        "grant during wait: it RELEASED rather than running to the deadline",
        r.elapsed < 4000,
        `elapsed ${r.elapsed}ms — ran the full budget`,
      );
    }

    // ── waitMs > 0, NO grant: hold to the deadline, then APPROVAL_TIMEOUT ───
    {
      const WAIT = 1200;
      const s = await scenario({ approvalWaitMs: WAIT, approvals: [] });
      const r = await timedCall(s.client, TRIGGER);
      const { events } = await teardown(s);

      check("wait expiry: ZERO executions — the provider was never called", r.executions === 0, `executions: ${r.executions}`);
      check("wait expiry: the caller received NO payload", r.payload === null, String(r.payload));
      check("wait expiry: the caller got a refusal", r.threw !== null);
      check(
        `wait expiry: the call HELD for the full budget (>= ${WAIT}ms)`,
        r.elapsed >= WAIT,
        `elapsed ${r.elapsed}ms — it did not actually wait`,
      );

      const blocked = events.find((e) => e.event_type === "blocked_call");
      check("wait expiry: a blocked_call event is recorded", !!blocked);
      // The distinction the SDK draws on purpose, asserted by name.
      check(
        "wait expiry: recorded under APPROVAL_TIMEOUT, NOT APPROVAL_REQUIRED",
        blocked?.reason_code === "APPROVAL_TIMEOUT",
        String(blocked?.reason_code),
      );
      check("wait expiry: the block still names the approval rule", blocked?.rule_id === RULE_ID, String(blocked?.rule_id));
      if (blocked) assertSignedEvent(blocked, "approval timeout");
    }

    return done.results();
  } finally {
    obsvr._reset();
    rmSync(TMP, { recursive: true, force: true });
  }
}

if (import.meta.url === `file://${process.argv[1]}`) run();
