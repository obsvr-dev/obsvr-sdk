/**
 * chain-verify — the tamper-evident core, at scale and against the pinned vectors.
 *
 * Two layers, no provider key:
 *   1. N=200 governed calls against an offline OpenAI-shaped stub → the WHOLE
 *      capture must verify as one HMAC chain, by BOTH the SDK's exported
 *      verifyAuditChain() AND our independent recompute (verifyCapturedChain).
 *   2. Conformance cross-check against conformance/fixtures/signing_vectors.json:
 *      derive the signing key from the fixture's api_key and recompute each
 *      event's sdk_sig byte-for-byte — this pins the signing algorithm itself,
 *      not just self-consistency.
 *
 * Signing (source: sdk/src/proxy/sender/fire-and-forget.ts):
 *   key = HMAC_SHA256("obsvr-sdk-signing-v1", api_key)
 *   content_hash = SHA256((prompt??"")+(response??""))
 *   sig = HMAC_SHA256(key, [session, seq, ts, content_hash, prev_sig??""].join("|"))
 *
 * Run: node integrations/chain-verify/test.mjs
 */
import { createServer } from "node:http";
import OpenAI from "openai";
import { verifyAuditChain, obsvr } from "@obsvr/sdk";
import { startMockIngest } from "../../lib/mock-ingest.mjs";
import { check, done, showEvents } from "../../lib/check.mjs";
import {
  verifyCapturedChain,
  assertSignedEvent,
  deriveSigningKey,
  recomputeSig,
} from "../../lib/assert-governance.mjs";
import { loadFixture, linkedSdkVersion } from "../../lib/fixtures.mjs";

export const meta = { offline: true };

const API_KEY = process.env.OBSVR_API_KEY || "obsvr-test-key";

/** Minimal offline OpenAI Chat Completions endpoint. No key, no network. */
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
          id: `chatcmpl-${hits}`,
          object: "chat.completion",
          created: Math.floor(Date.now() / 1000),
          model: "gpt-4o-mini-2024-07-18",
          choices: [{ index: 0, message: { role: "assistant", content: `reply ${hits}` }, finish_reason: "stop" }],
          usage: { prompt_tokens: 5, completion_tokens: 3, total_tokens: 8 },
        }),
      );
    });
  });
  return new Promise((resolve) =>
    server.listen(0, "127.0.0.1", () =>
      resolve({ port: server.address().port, hits: () => hits, stop: () => new Promise((r) => server.close(r)) }),
    ),
  );
}

export async function run() {
  const ingest = await startMockIngest();
  const stub = await startOpenAIStub();
  obsvr.init({
    apiKey: API_KEY,
    ingestUrl: ingest.url,
    environment: "development",
    policyRefreshIntervalMs: 0,
  });
  const openai = obsvr.wrap(new OpenAI({ apiKey: "test-not-real", baseURL: `http://127.0.0.1:${stub.port}/v1` }), {
    user_id: "chain_user",
    service_name: "chain-svc",
  });

  // ── 1. N=200 governed calls → one verifiable chain ──────────────────────────
  const N = 200;
  for (let i = 0; i < N; i++) {
    await openai.chat.completions.create({
      model: "gpt-4o-mini",
      max_tokens: 16,
      messages: [{ role: "user", content: `benign message ${i}` }],
    });
  }
  await obsvr.flush();
  const events = ingest.getEvents();
  console.log(`   captured ${events.length} signed events from ${N} governed calls (stub saw ${stub.hits()} calls)`);

  const llm = events.filter((e) => e.event_type === "llm_call");
  check(`all ${N} governed calls produced llm_call events`, llm.length === N, `got ${llm.length}`);
  assertSignedEvent(llm[0], "first llm_call", { decisionRecord: true });
  verifyCapturedChain(events, API_KEY, "200-call chain");

  // Regression guard: the runtime sdk_version stamp must equal the LINKED
  // package.json version (the 2.0.0-stamp-on-a-0.9.0-package bug class).
  const manifestVersion = linkedSdkVersion();
  check(
    `runtime sdk_version stamp matches the linked manifest (node/${manifestVersion})`,
    llm[0]?.sdk_version === `node/${manifestVersion}`,
    `event=${llm[0]?.sdk_version} manifest=${manifestVersion}`,
  );

  await stub.stop();
  await ingest.stop();

  // ── 2. Conformance: signing_vectors.json byte-equal recompute ───────────────
  const vec = loadFixture("signing_vectors");
  const signingKey = deriveSigningKey(vec.api_key);
  check(
    "signing key derived from fixture api_key matches signing_key_hex",
    signingKey.toString("hex") === vec.signing_key_hex,
    `got ${signingKey.toString("hex")}`,
  );

  // Rebuild full events (session id lives at the top level of the fixture) and
  // recompute each sdk_sig; then run the SDK's own verifier over them too.
  //
  // The rebuild SPREADS the vector rather than copying named fields across.
  // chain_format has to survive it — that field routes both verifiers to the
  // right content-hash rule and is itself signed, so dropping it reads every
  // format-2 vector as format 1 and mismatches on every event. Format 3 turned
  // that from a rule about one field into a rule about the whole event: the
  // eight decision fields are signed now, and a hand-listed copy that predates
  // them silently drops all eight, so both verifiers rebuilt a preimage over
  // content the fixture never signed and reported a signature mismatch on a
  // fixture that was correct. Copying the event whole is the only version of
  // this that cannot rot the next time the signed set grows.
  const fixtureEvents = vec.events.map((e) => ({
    ...e,
    sdk_session_id: vec.session_id,
    chain_format: e.chain_format ?? vec.chain_format,
  }));

  let allByteEqual = true;
  for (const e of fixtureEvents) {
    const recomputed = recomputeSig(e, signingKey);
    if (recomputed !== e.sdk_sig) allByteEqual = false;
  }
  check("every fixture sdk_sig recomputes byte-for-byte from the vectors", allByteEqual);

  const sdkVerdict = verifyAuditChain(fixtureEvents, vec.api_key);
  check(
    "SDK verifyAuditChain() accepts the fixture chain",
    sdkVerdict.valid === true && sdkVerdict.eventsVerified === fixtureEvents.length,
    sdkVerdict.reason,
  );

  // Negative control: flip one byte of a signature → the verifier must reject.
  const tampered = fixtureEvents.map((e, i) =>
    i === 1 ? { ...e, response: e.response + "X" } : { ...e },
  );
  const tamperVerdict = verifyAuditChain(tampered, vec.api_key);
  check("tampering with a signed field is detected (chain rejected)", tamperVerdict.valid === false);

  showEvents(llm.slice(0, 1));
  return done.results();
}

if (import.meta.url === `file://${process.argv[1]}`) run();
