/**
 * device-seal — the optional Ed25519 non-repudiation tier, end to end.
 *
 * The HMAC chain is keyed from the API key, so every key holder can mint a
 * complete valid chain: that is integrity, not non-repudiation. The device seal
 * is the opt-in second signature by a key the operator holds and the backend
 * never sees. It is ADDITIVE — the HMAC chain is untouched, and every existing
 * verifier keeps working — so a suite that only asked "does the chain still
 * verify?" would pass identically with the seal switched off. Every leg here
 * therefore asserts on device_sig / device_key_id specifically.
 *
 * What this establishes:
 *
 *   A. PINNED VECTORS. conformance/fixtures/signing_vectors.json pins the key
 *      id, the preimage and the signature bytes (Ed25519 is deterministic per
 *      RFC 8032, so one literal pin covers both languages). The harness's own
 *      reimplementation must reproduce them, with a negative control so "it
 *      verifies" is not just "it returns true for everything".
 *   B. LIVE SEAL. A real wrap() capture under a configured device key: every
 *      event carries device_key_id + device_sig, and the signature verifies
 *      over the SAME preimage the HMAC covers — recomputed independently here,
 *      not read back from the SDK.
 *   C. THE SDK VERIFIER agrees, and counts the sealed events.
 *   D. AN UNPINNED KEY IS FOREIGN. Trust comes from what the verifier pinned,
 *      never from the key id the record claims — a record signed by a key
 *      nobody pinned must not be trusted on first use.
 *   E. A MISSING SEAL ON A PINNED CHAIN IS A BREAK. Pinning asserts the
 *      expectation, so a stripped seal cannot read as clean.
 *   F. THE TIER WORKS WITHOUT AN API KEY. --device-pubkey alone verifies
 *      content, order and the decision fields with no secret shared.
 *   G. THE CLI an auditor actually runs (obsvr-verify --device-pubkey) over a
 *      real captured chain, keyed and device-only.
 *   H. THE SDK NEVER GENERATES A KEY. A configured-but-missing key file must
 *      REFUSE at init rather than ship unsigned events under a config that
 *      promised signing.
 *
 * The key used is the RFC 8032 test-vector seed the SDK's own fixture pins —
 * publicly known, test-only material, written to a scratch file at run time.
 * Nothing here generates key material and nothing persists it.
 *
 * Offline: no provider key, no network beyond loopback. A keyed leg (a real
 * provider call carrying the seal) runs only when OPENAI_API_KEY is set and
 * SKIPS loudly otherwise.
 *
 *   node integrations/device-seal/test.mjs
 */
import { createServer } from "node:http";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { createPrivateKey, createPublicKey } from "node:crypto";
import OpenAI from "openai";
import { obsvr, verifyAuditChain } from "@obsvr/sdk";
import { startMockIngest } from "../../lib/mock-ingest.mjs";
import { check, done, unknown } from "../../lib/check.mjs";
import {
  deviceKeyId,
  devicePreimage,
  signaturePayload,
  verifyDeviceSig,
  verifyCapturedChain,
} from "../../lib/assert-governance.mjs";
import { loadFixture, sdkPkgRoot } from "../../lib/fixtures.mjs";

export const meta = { offline: true };

const API_KEY = process.env.OBSVR_API_KEY || "obsvr-test-key";
// The SHIPPED verifier, located through the resolved package rather than an
// absolute path: this leg exists to prove the CLI a customer runs agrees with
// the chain the SDK just signed, so it has to find the same build the suites
// above imported, on any checkout.
const CLI = join(sdkPkgRoot(), "dist", "cli-verify.js");

/** A second, unrelated Ed25519 key — the "someone else's key" in leg D. Fixed
 *  bytes rather than generated, so this suite never mints key material. */
const FOREIGN_SEED_HEX = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";

function startOpenAIStub() {
  const server = createServer((req, res) => {
    let b = ""; req.on("data", (c) => (b += c));
    req.on("end", () => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ id: "c", object: "chat.completion", created: 0, model: "gpt-4o-mini", choices: [{ index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } }));
    });
  });
  return new Promise((r) => server.listen(0, "127.0.0.1", () => r({ port: server.address().port, stop: () => new Promise((res) => server.close(res)) })));
}

/** Drive a real wrap() capture with the device key installed. */
async function sealedCapture(keyFile, { calls = 3, userId = "seal_user" } = {}) {
  const stub = await startOpenAIStub();
  const ingest = await startMockIngest();
  obsvr._reset();
  obsvr.init({
    apiKey: API_KEY,
    ingestUrl: ingest.url,
    environment: "development",
    policyRefreshIntervalMs: 0,
    deviceSigningKeyFile: keyFile,
  });
  const client = obsvr.wrap(new OpenAI({ apiKey: "test-not-real", baseURL: `http://127.0.0.1:${stub.port}/v1` }), {
    user_id: userId,
    service_name: "seal-svc",
  });
  for (let i = 0; i < calls; i++) {
    await client.chat.completions.create({ model: "gpt-4o-mini", max_tokens: 8, messages: [{ role: "user", content: `sealed call ${i}` }] });
  }
  await obsvr.flush();
  const events = ingest.getEvents();
  obsvr._reset();
  await ingest.stop();
  await stub.stop();
  return events;
}

/** Run the shipped CLI over a bundle and return {code, out}. */
function runCli(args) {
  try {
    return { code: 0, out: execFileSync("node", [CLI, ...args], { encoding: "utf8" }) };
  } catch (e) {
    return { code: e.status ?? -1, out: `${e.stdout ?? ""}${e.stderr ?? ""}` };
  }
}

export async function run() {
  const vec = loadFixture("signing_vectors");
  const ds = vec?.device_signatures;
  if (!ds) return done.skip("signing_vectors.json has no device_signatures block — SDK fixture predates the device tier");

  const pub = Buffer.from(ds.public_key_b64, "base64");
  const tmp = mkdtempSync(join(tmpdir(), "obsvr-device-"));
  const keyFile = join(tmp, "device.key");
  writeFileSync(keyFile, ds.seed_hex, "utf8");

  try {
    // ── A. PINNED VECTORS ───────────────────────────────────────────────────
    check("key id is derived from the public key, matching the pinned fixture", deviceKeyId(pub) === ds.key_id, `${deviceKeyId(pub)} != ${ds.key_id}`);
    check(
      "harness reproduces every pinned device signature byte-for-byte",
      ds.cases.every((c) => verifyDeviceSig(pub, ds.key_id, c.signature_payload, c.device_sig)),
      `failing: ${ds.cases.filter((c) => !verifyDeviceSig(pub, ds.key_id, c.signature_payload, c.device_sig)).map((c) => c.name).join(",")}`,
    );
    // Control: without this, "verifies" is consistent with a verifier that
    // returns true unconditionally.
    check(
      "control: a pinned signature does NOT verify over a different payload",
      !verifyDeviceSig(pub, ds.key_id, `${ds.cases[0].signature_payload}x`, ds.cases[0].device_sig),
    );
    // The key id is INSIDE the signature, so it cannot be swapped.
    check(
      "control: a pinned signature does NOT verify under a substituted key id",
      !verifyDeviceSig(pub, "0000000000000000", ds.cases[0].signature_payload, ds.cases[0].device_sig),
    );
    check(
      "the device preimage is domain-separated (obsvr-device/1 || 0 || key_id || 0 || payload)",
      devicePreimage("kid", "pay").equals(Buffer.concat([Buffer.from("obsvr-device/1"), Buffer.from([0]), Buffer.from("kid"), Buffer.from([0]), Buffer.from("pay")])),
    );

    // ── B. LIVE SEAL over a real capture ────────────────────────────────────
    const events = await sealedCapture(keyFile);
    check("a device-signed capture produced events", events.length >= 3, `${events.length} events`);

    check(
      "every event carries a device_sig",
      events.length > 0 && events.every((e) => typeof e.device_sig === "string" && /^[0-9a-f]{128}$/.test(e.device_sig)),
      `missing/malformed on ${events.filter((e) => !/^[0-9a-f]{128}$/.test(String(e.device_sig))).length} of ${events.length}`,
    );
    check(
      "every event carries the DERIVED device_key_id (not a configured one)",
      events.length > 0 && events.every((e) => e.device_key_id === ds.key_id),
      `ids seen: ${[...new Set(events.map((e) => e.device_key_id))].join(",")}`,
    );
    // The heart of the tier: the device signature covers the SAME preimage the
    // HMAC covers. Recomputed here from the stored fields, so a seal over some
    // other payload — or over nothing — cannot pass.
    check(
      "every device_sig verifies over the SAME preimage the HMAC covers",
      events.length > 0 && events.every((e) => verifyDeviceSig(pub, e.device_key_id, signaturePayload(e), e.device_sig)),
      `first failing seq: ${events.find((e) => !verifyDeviceSig(pub, e.device_key_id, signaturePayload(e), e.device_sig))?.seq_no}`,
    );
    // Additive: the HMAC chain is untouched by the seal.
    verifyCapturedChain(events, API_KEY, "device-sealed chain");

    // ── C. THE SDK VERIFIER agrees ──────────────────────────────────────────
    const pinnedOk = verifyAuditChain(events, API_KEY, [pub]);
    check("SDK verifyAuditChain() accepts the chain under the pinned device key", pinnedOk.valid === true, pinnedOk.reason);
    check("SDK reports deviceChecked when keys are pinned", pinnedOk.deviceChecked === true);
    check("SDK counts every event as device-signed", pinnedOk.deviceSignedEvents === events.length, `${pinnedOk.deviceSignedEvents} of ${events.length}`);

    // ── D. AN UNPINNED KEY IS FOREIGN ───────────────────────────────────────
    // Trust is what the verifier pinned. A chain sealed by a key nobody pinned
    // must be reported foreign, never trusted because the record named itself.
    const foreignPub = ed25519PublicFromSeed(FOREIGN_SEED_HEX);
    const foreign = verifyAuditChain(events, API_KEY, [foreignPub]);
    check("a chain sealed by an UNPINNED key is rejected", foreign.valid === false);
    check(
      "the rejection names the unknown key rather than a signature mismatch",
      /Device key unknown/.test(String(foreign.reason)),
      String(foreign.reason),
    );
    check(
      "control: the foreign key really is a different key",
      deviceKeyId(foreignPub) !== ds.key_id,
    );

    // ── E. A MISSING SEAL ON A PINNED CHAIN IS A BREAK ──────────────────────
    const stripped = events.map((e, i) => (i === 1 ? { ...e, device_sig: undefined, device_key_id: undefined } : { ...e }));
    const strippedVerdict = verifyAuditChain(stripped, API_KEY, [pub]);
    check("stripping a seal from a pinned chain is a BREAK", strippedVerdict.valid === false);
    check(
      "the break names the missing device signature",
      /Device signature missing/.test(String(strippedVerdict.reason)),
      String(strippedVerdict.reason),
    );
    // Positive control on the same bytes: without pinning, the stripped chain
    // still passes the HMAC tier — which is exactly why pinning must assert.
    check(
      "control: the same stripped chain still passes the HMAC-only tier",
      verifyAuditChain(stripped, API_KEY).valid === true,
    );

    // A tampered decision field must break the DEVICE seal too, not just the
    // HMAC — otherwise the seal attests to less than it appears to.
    const tampered = events.map((e, i) => (i === 0 ? { ...e, action_taken: e.action_taken === "allowed" ? "blocked" : "allowed" } : { ...e }));
    check(
      "a rewritten verdict breaks the device seal independently of the HMAC",
      !verifyDeviceSig(pub, tampered[0].device_key_id, signaturePayload(tampered[0]), tampered[0].device_sig),
    );

    // ── F. THE TIER WORKS WITHOUT AN API KEY ────────────────────────────────
    const deviceOnly = verifyAuditChain(events, null, [pub]);
    check("device-only verification (no api key) accepts the chain", deviceOnly.valid === true, deviceOnly.reason);
    check("device-only verification still counts the seals", deviceOnly.deviceSignedEvents === events.length);
    const deviceOnlyForeign = verifyAuditChain(events, null, [foreignPub]);
    check("device-only verification still rejects an unpinned key", deviceOnlyForeign.valid === false);

    // ── G. THE CLI an auditor runs ──────────────────────────────────────────
    const bundle = join(tmp, "bundle.json");
    writeFileSync(bundle, JSON.stringify(events), "utf8");
    const keyed = runCli([bundle, "--api-key", API_KEY, "--device-pubkey", ds.public_key_b64, "--json"]);
    check("obsvr-verify --device-pubkey exits 0 on a real sealed chain", keyed.code === 0, keyed.out.slice(0, 300));
    check("the CLI reports the device tier as checked", /"deviceChecked"\s*:\s*true/.test(keyed.out), keyed.out.slice(0, 300));
    check(
      `the CLI counts all ${events.length} sealed events`,
      new RegExp(`"deviceSignedEvents"\\s*:\\s*${events.length}`).test(keyed.out),
      keyed.out.slice(0, 300),
    );

    const cliDeviceOnly = runCli([bundle, "--device-pubkey", ds.public_key_b64, "--json"]);
    check("obsvr-verify with --device-pubkey ALONE (no --api-key) exits 0", cliDeviceOnly.code === 0, cliDeviceOnly.out.slice(0, 300));

    const cliForeign = runCli([bundle, "--api-key", API_KEY, "--device-pubkey", Buffer.from(foreignPub).toString("base64"), "--json"]);
    check("obsvr-verify FAILS (non-zero) against an unpinned key", cliForeign.code !== 0, `exit ${cliForeign.code}`);

    const strippedBundle = join(tmp, "stripped.json");
    writeFileSync(strippedBundle, JSON.stringify(stripped), "utf8");
    const cliStripped = runCli([strippedBundle, "--api-key", API_KEY, "--device-pubkey", ds.public_key_b64, "--json"]);
    check("obsvr-verify FAILS (non-zero) when a pinned chain is missing a seal", cliStripped.code !== 0, `exit ${cliStripped.code}`);

    // ── H. THE SDK NEVER GENERATES A KEY ────────────────────────────────────
    // A config that promised signing and cannot sign must refuse, loudly. A
    // silent no-op here would ship unsigned events under a signing config.
    obsvr._reset();
    let refused = null;
    try {
      obsvr.init({ apiKey: API_KEY, ingestUrl: "http://127.0.0.1:1", environment: "development", policyRefreshIntervalMs: 0, deviceSigningKeyFile: join(tmp, "does-not-exist.key") });
    } catch (e) {
      refused = e;
    }
    obsvr._reset();
    check("init() REFUSES a configured device key file that does not exist", refused !== null);
    check(
      "the refusal says the SDK never generates keys",
      /never generates|generate/i.test(String(refused?.message)),
      String(refused?.message).slice(0, 200),
    );

    // ── KEYED LEG: the seal riding a REAL provider call ─────────────────────
    if (!process.env.OPENAI_API_KEY) {
      // Loudly unevaluated, never a silent pass: the offline legs above prove
      // the seal over a stub, not over a real provider round trip.
      unknown("[keyed] device seal rides a real provider call", "no OPENAI_API_KEY — live leg not run");
    } else {
      const liveIngest = await startMockIngest();
      obsvr._reset();
      obsvr.init({ apiKey: API_KEY, ingestUrl: liveIngest.url, environment: "development", policyRefreshIntervalMs: 0, deviceSigningKeyFile: keyFile });
      const live = obsvr.wrap(new OpenAI({ apiKey: process.env.OPENAI_API_KEY }), { user_id: "seal_live", service_name: "seal-svc" });
      await live.chat.completions.create({ model: "gpt-4o-mini", max_tokens: 8, messages: [{ role: "user", content: "say ok" }] });
      await obsvr.flush();
      const liveEvents = liveIngest.getEvents();
      obsvr._reset();
      await liveIngest.stop();
      check("[keyed] a real provider call produced a sealed event", liveEvents.length >= 1 && typeof liveEvents[0].device_sig === "string");
      check(
        "[keyed] the live seal verifies over the same preimage the HMAC covers",
        liveEvents.length >= 1 && verifyDeviceSig(pub, liveEvents[0].device_key_id, signaturePayload(liveEvents[0]), liveEvents[0].device_sig),
      );
      check("[keyed] the SDK verifier accepts the live sealed chain", verifyAuditChain(liveEvents, API_KEY, [pub]).valid === true);
    }

    return done.results();
  } finally {
    obsvr._reset();
    rmSync(tmp, { recursive: true, force: true });
  }
}

/** Raw 32-byte Ed25519 public key from a raw seed, via node:crypto. Used only
 *  to obtain a SECOND, unrelated key for the foreign-key legs — the seed is a
 *  fixed literal, so this derives a public key rather than generating one. */
function ed25519PublicFromSeed(seedHex) {
  // PKCS8 envelope for a raw Ed25519 seed.
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seedHex, "hex")]);
  const priv = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  const pubDer = createPublicKey(priv).export({ format: "der", type: "spki" });
  return pubDer.subarray(pubDer.length - 32);
}

if (import.meta.url === `file://${process.argv[1]}`) run();
