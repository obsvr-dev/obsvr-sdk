/**
 * Error paths + fail-open/closed hooks — offline E2E.
 *
 * Against an OFFLINE OpenAI-shaped stub (no key, no network), proves the
 * wrap() core-proxy error semantics (proxy/wrapper.ts):
 *
 *   1) Provider returns HTTP 500 -> the ORIGINAL provider error is re-thrown to
 *      the caller UNCHANGED (not an obsvr policy error), AND a signed audit event
 *      is still emitted (success:false, error_type set).
 *   2) on_pre_call hook that exceeds hookTimeoutMs (=50):
 *        failMode "open"   -> call ALLOWED  (llm_call, action_taken "allowed")
 *        failMode "closed" -> call BLOCKED  (blocked_call, action_taken "blocked")
 *   3) Same shape for a hook that THROWS (open -> allowed, closed -> blocked).
 *
 * Ends with assertSignedEvent() on the error + a blocked event, and
 * verifyCapturedChain() over the whole capture.
 *
 *   node integrations/error-paths/test.mjs
 */
import { createServer } from "node:http";
import { obsvr } from "@obsvr/sdk";
import OpenAI from "openai";
import { startMockIngest } from "../../lib/mock-ingest.mjs";
import { check, done, showEvents } from "../../lib/check.mjs";
import { assertSignedEvent, verifyCapturedChain } from "../../lib/assert-governance.mjs";

export const meta = { offline: true };

const API_KEY = process.env.OBSVR_API_KEY || "obsvr-test-key";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Offline OpenAI-shaped provider whose status is switchable: default 200 with a
 *  normal chat.completion; setStatus(500) makes it return a server error body. */
function startStub() {
  let status = 200;
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      if (status >= 400) {
        res.writeHead(status, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: { message: `stub error ${status}`, type: "server_error", code: null } }));
        return;
      }
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
        setStatus: (s) => {
          status = s;
        },
        stop: () => new Promise((r) => server.close(r)),
      }),
    ),
  );
}

export async function run() {
  const mock = await startMockIngest();
  const stub = await startStub();

  const wrapFresh = (extra, user_id) => {
    // Re-init replaces the config object; wrap() binds getConfig() at wrap time,
    // so each scenario re-wraps a fresh client. policyRefreshIntervalMs:0 keeps
    // the enforcement-integrity gate out of the way (no stale-sync degradation),
    // so the hook path is the thing under test.
    obsvr.init({ apiKey: API_KEY, ingestUrl: mock.url, environment: "development", sampleRate: 1, policyRefreshIntervalMs: 0, ...extra });
    return obsvr.wrap(new OpenAI({ apiKey: "test", baseURL: stub.baseURL, maxRetries: 0 }), { user_id });
  };
  const create = (client, content) => client.chat.completions.create({ model: "gpt-4o", max_tokens: 16, messages: [{ role: "user", content }] });

  // ── 1) provider 500 -> original error re-thrown, audit event still signed ──
  stub.setStatus(500);
  const errClient = wrapFresh({}, "err-500");
  let caught = null;
  try {
    await create(errClient, "please trigger a 500");
  } catch (e) {
    caught = e;
  }
  check("provider 500 threw to the caller", !!caught);
  check("re-thrown error is the ORIGINAL provider error, not an obsvr policy block", !!caught && !/blocked by policy/i.test(String(caught?.message)));
  check("re-thrown error carries the provider status 500", caught?.status === 500 || /\b500\b/.test(String(caught?.message)), String(caught?.status ?? caught?.message));
  stub.setStatus(200);

  // hook fixtures (both never resolve in time / never succeed)
  const slowHook = async () => {
    await sleep(200); // > hookTimeoutMs (50)
    return { decision: "allow" };
  };
  const throwHook = async () => {
    throw new Error("hook boom");
  };

  // ── 2) hook timeout ─────────────────────────────────────────────────────────
  const toOpen = wrapFresh({ onPreCall: slowHook, hookTimeoutMs: 50, failMode: "open" }, "to-open");
  const toOpenReply = await create(toOpen, "hi (timeout, open)");
  check("hook timeout + failMode open ALLOWS the call", toOpenReply?.choices?.[0]?.message?.content === "stubbed reply");

  const toClosed = wrapFresh({ onPreCall: slowHook, hookTimeoutMs: 50, failMode: "closed" }, "to-closed");
  let toClosedBlocked = false;
  try {
    await create(toClosed, "hi (timeout, closed)");
  } catch (e) {
    toClosedBlocked = /blocked by policy/i.test(String(e?.message));
  }
  check("hook timeout + failMode closed BLOCKS the call", toClosedBlocked);

  // ── 3) hook throws ──────────────────────────────────────────────────────────
  const thOpen = wrapFresh({ onPreCall: throwHook, hookTimeoutMs: 50, failMode: "open" }, "th-open");
  const thOpenReply = await create(thOpen, "hi (throw, open)");
  check("hook throw + failMode open ALLOWS the call", thOpenReply?.choices?.[0]?.message?.content === "stubbed reply");

  const thClosed = wrapFresh({ onPreCall: throwHook, hookTimeoutMs: 50, failMode: "closed" }, "th-closed");
  let thClosedBlocked = false;
  try {
    await create(thClosed, "hi (throw, closed)");
  } catch (e) {
    thClosedBlocked = /blocked by policy/i.test(String(e?.message));
  }
  check("hook throw + failMode closed BLOCKS the call", thClosedBlocked);

  await obsvr.flush();
  const events = mock.getEvents();
  showEvents(events);

  // ── audit-on-error: a FAILED OpenAI-shaped call still emits a signed event ──
  // Regression guard for the wrapper.ts:505 fix. The OpenAI branch of
  // buildAuditEvent previously called the response extractor unguarded, so on a
  // failed call (response=null) it threw inside the error path's try/catch and
  // the forensic record was silently dropped — the exact events an auditor most
  // needs. The anthropic/google/responses branches already guarded null; the fix
  // brings the OpenAI family to parity (Python's wrap.py already emitted on
  // error). This asserts the failed 500 call now produces a proper signed record.
  const errEv = events.find((e) => e.user_id === "err-500");
  check(
    "audit-on-error: failed OpenAI 500 call emits a forensic event (wrapper.ts:505 fixed)",
    errEv !== undefined,
    errEv === undefined ? "no error event emitted — the audit-on-error fix may have regressed" : undefined,
  );
  check("error event records success=false", errEv?.success === false, String(errEv?.success));
  check("error event carries the provider status 500", errEv?.status_code === 500, String(errEv?.status_code));
  check("error event classifies the error_type", typeof errEv?.error_type === "string" && errEv.error_type.length > 0, String(errEv?.error_type));
  check("error event is HMAC-signed (part of the chain)", typeof errEv?.sdk_sig === "string" && errEv.sdk_sig.length === 64);

  // ── exact action_taken on the wrap() path per scenario ─────────────────────
  const toOpenEv = events.find((e) => e.user_id === "to-open");
  check("timeout + open recorded as an ALLOWED llm_call", toOpenEv?.event_type === "llm_call" && toOpenEv?.action_taken === "allowed");

  const toClosedEv = events.find((e) => e.user_id === "to-closed");
  check("timeout + closed recorded as a BLOCKED blocked_call", toClosedEv?.event_type === "blocked_call" && toClosedEv?.action_taken === "blocked");
  check("timeout + closed policy_reason names 'hook_timeout (fail_closed)'", /hook_timeout \(fail_closed\)/.test(String(toClosedEv?.policy_reason)), String(toClosedEv?.policy_reason));

  const thOpenEv = events.find((e) => e.user_id === "th-open");
  check("throw + open recorded as an ALLOWED llm_call", thOpenEv?.event_type === "llm_call" && thOpenEv?.action_taken === "allowed");

  const thClosedEv = events.find((e) => e.user_id === "th-closed");
  check("throw + closed recorded as a BLOCKED blocked_call", thClosedEv?.event_type === "blocked_call" && thClosedEv?.action_taken === "blocked");
  check("throw + closed policy_reason names 'hook_error (fail_closed)'", /hook_error \(fail_closed\)/.test(String(thClosedEv?.policy_reason)), String(thClosedEv?.policy_reason));

  // a governance blocked_call carries the full signed decision record
  if (toClosedEv) assertSignedEvent(toClosedEv, "timeout-closed blocked_call", { decisionRecord: true });

  // ── full-chain verification (error, allowed, and blocked events all signed) ─
  verifyCapturedChain(events, API_KEY, "error-paths chain");

  await obsvr.flush();
  await mock.stop();
  await stub.stop();
  return done.results();
}

if (import.meta.url === `file://${process.argv[1]}`) run();
