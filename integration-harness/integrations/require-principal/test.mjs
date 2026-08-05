/**
 * require-principal — fail-closed refusal of an UNATTRIBUTED call.
 *
 * `requirePrincipal: true` refuses a governed call whose enforcing channel
 * carries no user_id at all, with PRINCIPAL_REQUIRED, before any scanning layer
 * runs. The point is an audit trail in which every recorded action names who
 * caused it; a call nobody can be held to is refused rather than logged
 * anonymously.
 *
 * WHY EACH LEG EXISTS:
 *
 *   - Every refusal is paired with an ALLOW CONTROL over the same code path. A
 *     provider call that never happened looks identical to one that was
 *     refused, so without the control a "blocked" leg passes just as happily
 *     against an SDK that broke every call, or none.
 *   - Execution is counted with a SIDE EFFECT, not inferred from events: the
 *     stub appends one line per request it serves, so the line count IS the
 *     execution count. Events are the thing under test here and cannot also be
 *     the evidence that something ran.
 *   - Every leg asserts what the CALLER RECEIVED. "Zero executions" is not
 *     refusal on its own — a cached or short-circuited path also executes
 *     nothing while still handing the caller a payload.
 *
 * The four admission paths, because they are four different channels and the
 * gate reads only one of them:
 *
 *   unattributed        -> REFUSED
 *   explicit userId     -> admitted
 *   ambient useSubject  -> admitted   <- this was a live bug: the ambient scope
 *                                        attributed the signed record but was
 *                                        invisible to enforcement, so the SDK
 *                                        refused a call whose own event named
 *                                        the principal it called absent.
 *   empty-string userId -> admitted   <- documented boundary: an empty string
 *                                        is a SUPPLIED principal; only an
 *                                        absent one refuses.
 *
 * And the refusal's own record must AGREE with its verdict — a blocked event
 * must not name a user_id it simultaneously claims was missing.
 *
 * Offline: no provider key, no network beyond loopback.
 *
 *   node integrations/require-principal/test.mjs
 */
import { createServer } from "node:http";
import { mkdtempSync, appendFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import OpenAI from "openai";
import { obsvr, useSubject } from "@obsvr/sdk";
import { startMockIngest } from "../../lib/mock-ingest.mjs";
import { check, done } from "../../lib/check.mjs";
import { assertSignedEvent } from "../../lib/assert-governance.mjs";

export const meta = { offline: true };

const API_KEY = process.env.OBSVR_API_KEY || "obsvr-test-key";

let TMP, MARKER;

/** Executions counted directly: one appended line per request the stub serves. */
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
 * One governed call under a given config, reporting what the CALLER got.
 * `wrapOpts` is what the caller attributes with; `inScope` optionally runs the
 * call inside a useSubject() scope.
 */
async function attempt({ requirePrincipal, wrapOpts = {}, subject = null }) {
  const stub = await startOpenAIStub();
  const ingest = await startMockIngest();
  obsvr._reset();
  obsvr.init({ apiKey: API_KEY, ingestUrl: ingest.url, environment: "development", policyRefreshIntervalMs: 0, requirePrincipal });
  const client = obsvr.wrap(new OpenAI({ apiKey: "test-not-real", baseURL: `http://127.0.0.1:${stub.port}/v1` }), wrapOpts);

  const before = marks();
  const call = () => client.chat.completions.create({ model: "gpt-4o-mini", max_tokens: 8, messages: [{ role: "user", content: "attributed?" }] });

  let received = null;
  let threw = null;
  try {
    received = subject ? await useSubject(subject, call) : await call();
  } catch (e) {
    threw = e;
  }
  await obsvr.flush();
  const events = ingest.getEvents();
  obsvr._reset();
  await ingest.stop();
  await stub.stop();

  return {
    executions: marks() - before,
    payload: received?.choices?.[0]?.message?.content ?? null,
    threw,
    events,
  };
}

export async function run() {
  TMP = mkdtempSync(join(tmpdir(), "obsvr-principal-"));
  MARKER = join(TMP, "executions.log");

  try {
    // ── ALLOW CONTROL: the gate is OFF, so an unattributed call runs ────────
    // Without this, every "blocked" below is consistent with an SDK that
    // refuses unconditionally, or with a stub that was never reachable.
    const off = await attempt({ requirePrincipal: false });
    check("control (gate off): an unattributed call RUNS — executions: 1", off.executions === 1, `executions: ${off.executions}`);
    check("control (gate off): the caller receives the provider payload", off.payload === "PROVIDER_PAYLOAD", String(off.payload));
    check("control (gate off): nothing recorded a block", !off.events.some((e) => e.event_type === "blocked_call"));

    // ── REFUSE: the gate is ON and the call names nobody ───────────────────
    const refused = await attempt({ requirePrincipal: true });
    check("gate on + unattributed: ZERO executions — the provider was never called", refused.executions === 0, `executions: ${refused.executions}`);
    check("gate on + unattributed: the caller received NO payload", refused.payload === null, String(refused.payload));
    check("gate on + unattributed: the caller got a refusal, not a silent empty result", refused.threw !== null, "no exception raised");
    check(
      "gate on + unattributed: the refusal is distinguishable from a provider/network error",
      /blocked by policy/i.test(String(refused.threw?.message)),
      String(refused.threw?.message).slice(0, 200),
    );

    const blocked = refused.events.find((e) => e.event_type === "blocked_call");
    check("gate on + unattributed: a blocked_call event is recorded", !!blocked);
    check("the block is attributed to the principal gate (rule_id)", blocked?.rule_id === "sdk:principal_required", String(blocked?.rule_id));
    check("the block carries reason_code PRINCIPAL_REQUIRED", blocked?.reason_code === "PRINCIPAL_REQUIRED", String(blocked?.reason_code));
    check("the block is sourced to policy_rules, not a guess", blocked?.action_source === "policy_rules", String(blocked?.action_source));
    if (blocked) assertSignedEvent(blocked, "principal refusal");

    // THE RECORD AGREES WITH ITS VERDICT. This is the live bug's signature: an
    // event that refuses for "no principal" while naming a principal is a
    // record contradicting its own reason, and it verifies perfectly.
    check(
      "the refusal's own record does NOT name a user_id it claims was absent",
      blocked ? blocked.user_id == null || blocked.user_id === "" : false,
      `user_id on the blocked event: ${JSON.stringify(blocked?.user_id)}`,
    );
    check("the refusal's verdict field says blocked", blocked?.action_taken === "blocked", String(blocked?.action_taken));

    // ── ADMIT: an explicit user_id ─────────────────────────────────────────
    // NOTE: wrap options are snake_case (IntegrationOptions/WrapOptions). A
    // camelCase key is not a compile error for a JS caller — it is silently
    // ignored, which presents as an unattributed call and a refusal here.
    const explicit = await attempt({ requirePrincipal: true, wrapOpts: { user_id: "user_alice", service_name: "billing-svc" } });
    check("gate on + explicit userId: the call RUNS — executions: 1", explicit.executions === 1, `executions: ${explicit.executions}`);
    check("gate on + explicit userId: the caller receives the provider payload", explicit.payload === "PROVIDER_PAYLOAD", String(explicit.payload));
    check("gate on + explicit userId: nothing recorded a block", !explicit.events.some((e) => e.event_type === "blocked_call"));
    check(
      "gate on + explicit userId: the signed record names that principal",
      explicit.events.find((e) => e.event_type === "llm_call")?.user_id === "user_alice",
      String(explicit.events.find((e) => e.event_type === "llm_call")?.user_id),
    );

    // ── ADMIT: an AMBIENT useSubject scope only ────────────────────────────
    // The regression this pins: the ambient scope fed the signed channel but
    // not the enforcing one, so this call was refused while its own event
    // named the principal the refusal said was missing.
    const ambient = await attempt({ requirePrincipal: true, subject: "user:amb_bob;tenant:acme" });
    check("gate on + AMBIENT use_subject only: the call RUNS — executions: 1", ambient.executions === 1, `executions: ${ambient.executions}`);
    check("gate on + AMBIENT use_subject only: the caller receives the provider payload", ambient.payload === "PROVIDER_PAYLOAD", String(ambient.payload));
    check(
      "gate on + AMBIENT use_subject only: nothing recorded a block",
      !ambient.events.some((e) => e.event_type === "blocked_call"),
      `blocked reason: ${ambient.events.find((e) => e.event_type === "blocked_call")?.reason_code}`,
    );
    check(
      "gate on + AMBIENT use_subject only: the signed record names the ambient principal",
      ambient.events.find((e) => e.event_type === "llm_call")?.user_id === "amb_bob",
      String(ambient.events.find((e) => e.event_type === "llm_call")?.user_id),
    );

    // ── ADMIT: the documented absent-vs-empty boundary ─────────────────────
    // An empty string is a SUPPLIED principal. Asserted positively so the
    // distinction stays measured rather than decaying into a silent pass.
    const empty = await attempt({ requirePrincipal: true, wrapOpts: { user_id: "" } });
    check("gate on + EMPTY-STRING userId is a supplied principal: the call RUNS", empty.executions === 1, `executions: ${empty.executions}`);
    check("gate on + EMPTY-STRING userId: the caller receives the provider payload", empty.payload === "PROVIDER_PAYLOAD", String(empty.payload));

    return done.results();
  } finally {
    obsvr._reset();
    rmSync(TMP, { recursive: true, force: true });
  }
}

if (import.meta.url === `file://${process.argv[1]}`) run();
