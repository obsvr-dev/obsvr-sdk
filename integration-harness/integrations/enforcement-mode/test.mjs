/**
 * enforcement-mode — `enforcementMode: "monitor"` and the two carve-outs.
 *
 * Monitor mode is ONE conversion point after the decision is final: the whole
 * pipeline still runs, every event still emits, and the would-be verdict rides
 * `shadow_outcome`. It is the adoption path — turn a ruleset on, watch what it
 * WOULD have refused, then switch to enforce.
 *
 * The interesting content of this suite is not that monitor converts blocks. It
 * is the two classes that enforce in BOTH modes, because each is a way monitor
 * mode could otherwise become a one-flag defeat of the whole product:
 *
 *   LAYER 0  — the enforcement-integrity gate (paused project / revoked key /
 *              fail-closed staleness). If monitor suppressed this, revoking a
 *              key would stop mattering the moment someone set one flag. The
 *              SDK re-derives this carve-out at the conversion point rather
 *              than trusting a snapshot, so a stale `degraded` cannot extend
 *              monitor mode to a paused project.
 *   CANARY   — a planted honeytoken in outbound content is an exfiltration in
 *              flight. Observing it leave is not monitoring, it is the leak.
 *
 * DISCIPLINE:
 *   - Every conversion leg is paired with the SAME scenario under enforce, so
 *     "monitor allowed it" is measured against "enforce refused it" rather
 *     than against nothing.
 *   - Executions are counted with a SIDE EFFECT (one line appended per request
 *     the stub serves). Under monitor the provider really is reached, so the
 *     count is the difference that matters and events cannot supply it.
 *   - Every leg asserts what the CALLER RECEIVED.
 *
 * Offline: no provider key, no network beyond loopback.
 *
 *   node integrations/enforcement-mode/test.mjs
 */
import { createServer } from "node:http";
import { mkdtempSync, appendFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import OpenAI from "openai";
import { obsvr, mintCanary } from "@obsvr/sdk";
import { startMockIngest } from "../../lib/mock-ingest.mjs";
import { check, done, unknown } from "../../lib/check.mjs";
import { assertSignedEvent } from "../../lib/assert-governance.mjs";

export const meta = { offline: true };

const API_KEY = process.env.OBSVR_API_KEY || "obsvr-test-key";
const RULE_ID = "kw-embargo";
const TRIGGER = "please discuss the embargo details";

const BLOCK_RULE = {
  id: RULE_ID,
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

/** One governed call under a given mode/policy source. */
async function attempt({ enforcementMode, policies = { rules: [BLOCK_RULE] }, prompt = TRIGGER, failMode, mintCanaryFirst = false }) {
  const stub = await startOpenAIStub();
  const ingest = await startMockIngest({ policies });
  obsvr._reset();
  obsvr.init({
    apiKey: API_KEY,
    ingestUrl: ingest.url,
    environment: "development",
    policyRefreshIntervalMs: 50,
    enforcementMode,
    ...(failMode ? { failMode } : {}),
  });
  const client = obsvr.wrap(new OpenAI({ apiKey: "test-not-real", baseURL: `http://127.0.0.1:${stub.port}/v1` }), {
    user_id: "user_alice",
    service_name: "billing-svc",
  });
  await ingest.waitForPoll(1, 3000);
  await sleep(120);

  // Minted AFTER init: obsvr._reset() clears the canary registry, so a token
  // minted before this point would be gone by the time the call is made and
  // the "canary blocks" leg would pass for the wrong reason (nothing to leak).
  let leaked = prompt;
  if (mintCanaryFirst) {
    const minted = mintCanary("monitor-carveout");
    const token = typeof minted === "string" ? minted : minted?.token;
    leaked = `here is the secret ${token}`;
  }

  const before = marks();
  let payload = null;
  let threw = null;
  try {
    const res = await client.chat.completions.create({ model: "gpt-4o-mini", max_tokens: 8, messages: [{ role: "user", content: leaked }] });
    payload = res?.choices?.[0]?.message?.content ?? null;
  } catch (e) {
    threw = e;
  }
  await obsvr.flush();
  const events = ingest.getEvents();
  obsvr._reset();
  await ingest.stop();
  await stub.stop();
  return { executions: marks() - before, payload, threw, events };
}

export async function run() {
  TMP = mkdtempSync(join(tmpdir(), "obsvr-mode-"));
  MARKER = join(TMP, "executions.log");

  try {
    // ── ALLOW CONTROL: enforce mode, a prompt the rule does not match ───────
    {
      const r = await attempt({ enforcementMode: "enforce", prompt: "just say hello" });
      check("control (enforce, non-matching): the call RUNS — executions: 1", r.executions === 1, `executions: ${r.executions}`);
      check("control (enforce, non-matching): the caller receives the payload", r.payload === "PROVIDER_PAYLOAD", String(r.payload));
      check("control (enforce, non-matching): nothing recorded a block", !r.events.some((e) => e.event_type === "blocked_call"));
    }

    // ── ENFORCE: the rule refuses ───────────────────────────────────────────
    // The paired half of the conversion leg below: without it, "monitor
    // allowed it" is consistent with a rule that never matched at all.
    let enforced;
    {
      enforced = await attempt({ enforcementMode: "enforce" });
      check("enforce: ZERO executions — the provider was never called", enforced.executions === 0, `executions: ${enforced.executions}`);
      check("enforce: the caller received NO payload", enforced.payload === null, String(enforced.payload));
      check("enforce: the caller got a refusal", enforced.threw !== null);
      const b = enforced.events.find((e) => e.event_type === "blocked_call");
      check("enforce: a blocked_call event is recorded", !!b);
      check("enforce: the block names the rule", b?.rule_id === RULE_ID, String(b?.rule_id));
      check("enforce: no shadow_outcome — this verdict was applied, not shadowed", b?.shadow_outcome == null, JSON.stringify(b?.shadow_outcome));
    }

    // ── MONITOR: the same block converts to an allow, carrying the verdict ──
    {
      const r = await attempt({ enforcementMode: "monitor" });
      check("monitor: the SAME call now RUNS — executions: 1", r.executions === 1, `executions: ${r.executions}`);
      check("monitor: the caller receives the provider payload", r.payload === "PROVIDER_PAYLOAD", String(r.payload));
      check("monitor: the caller got no refusal", r.threw === null, String(r.threw?.message));

      // The whole pipeline still ran and still emitted — monitor is a
      // conversion, not a bypass.
      const ev = r.events.find((e) => e.event_type === "llm_call") ?? r.events[0];
      check("monitor: an event was still emitted", !!ev);
      check("monitor: the applied verdict is allowed", ev?.action_taken === "allowed", String(ev?.action_taken));
      // The point of the mode: the would-be verdict is preserved.
      check("monitor: the would-be verdict rides shadow_outcome", ev?.shadow_outcome != null, JSON.stringify(ev?.shadow_outcome));
      check(
        "monitor: shadow_outcome records the block that WOULD have happened",
        JSON.stringify(ev?.shadow_outcome ?? {}).includes("block"),
        JSON.stringify(ev?.shadow_outcome),
      );
      check(
        "monitor: shadow_outcome names the rule that would have fired",
        JSON.stringify(ev?.shadow_outcome ?? {}).includes(RULE_ID),
        JSON.stringify(ev?.shadow_outcome),
      );
      if (ev) assertSignedEvent(ev, "monitor conversion");
    }

    // ── CARVE-OUT 1: LAYER 0 does NOT convert ───────────────────────────────
    // /policies 403 is a paused project or a revoked key. A monitor mode that
    // suppressed this would make revocation a no-op behind one flag.
    {
      const killPolicies = () => ({ status: 403, body: {} });
      const enforceKill = await attempt({ enforcementMode: "enforce", policies: killPolicies });
      const monitorKill = await attempt({ enforcementMode: "monitor", policies: killPolicies });

      check("layer 0 (enforce): a revoked key blocks — ZERO executions", enforceKill.executions === 0, `executions: ${enforceKill.executions}`);
      check(
        "layer 0 (MONITOR): a revoked key STILL blocks — ZERO executions",
        monitorKill.executions === 0,
        `executions: ${monitorKill.executions} — monitor mode defeated the kill switch`,
      );
      check("layer 0 (MONITOR): the caller still received NO payload", monitorKill.payload === null, String(monitorKill.payload));
      check("layer 0 (MONITOR): the caller still got a refusal", monitorKill.threw !== null);
      const kb = monitorKill.events.find((e) => e.event_type === "blocked_call");
      check(
        "layer 0 (MONITOR): recorded as the enforcement-integrity gate",
        kb?.rule_id === "sdk:project_paused_or_key_revoked",
        String(kb?.rule_id),
      );
      check("layer 0 (MONITOR): the verdict really is blocked, not shadowed", kb?.action_taken === "blocked", String(kb?.action_taken));
    }

    // ── CARVE-OUT 2: a CANARY leak does NOT convert ─────────────────────────
    // A planted honeytoken in outbound content is an exfiltration in flight.
    {
      if (typeof mintCanary !== "function") {
        unknown("canary carve-out under monitor mode", "mintCanary is not exported by this build");
      } else {
        // No rules at all: the ONLY thing that can block here is the canary
        // floor, so a block proves the floor fired rather than a rule.
        const control = await attempt({ enforcementMode: "monitor", policies: { rules: [] }, prompt: "nothing secret here" });
        check(
          "canary control: with no rules and no leak, the call RUNS",
          control.executions === 1,
          `executions: ${control.executions}`,
        );
        const r = await attempt({ enforcementMode: "monitor", policies: { rules: [] }, mintCanaryFirst: true });
        check(
          "canary (MONITOR): a leaked honeytoken STILL blocks — ZERO executions",
          r.executions === 0,
          `executions: ${r.executions} — monitor mode let a canary out the door`,
        );
        check("canary (MONITOR): the caller received NO payload", r.payload === null, String(r.payload));
        const cb = r.events.find((e) => e.event_type === "blocked_call");
        check("canary (MONITOR): recorded as a canary leak", cb?.rule_id === "sdk:canary_leak", String(cb?.rule_id));
        check("canary (MONITOR): the verdict really is blocked, not shadowed", cb?.action_taken === "blocked", String(cb?.action_taken));
      }
    }

    // ── CARVE-OUT 3: a CRASHED DETECTOR still blocks under monitor ──────────
    // Recorded as UNEVALUATED rather than asserted: making a detector raise
    // needs the SDK's internals to be perturbed, and this harness must not
    // modify the SDK tree. It IS covered by the mutation check for this suite,
    // which runs against a scratch copy. Left visible so the gap in LIVE
    // coverage is measured rather than absent.
    unknown(
      "crashed detector still blocks under monitor mode",
      "needs a detector to raise; not reachable through the public API without modifying the SDK tree",
    );

    return done.results();
  } finally {
    obsvr._reset();
    rmSync(TMP, { recursive: true, force: true });
  }
}

if (import.meta.url === `file://${process.argv[1]}`) run();
