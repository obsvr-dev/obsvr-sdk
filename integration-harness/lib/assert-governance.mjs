/**
 * Shared governance + crypto assertions for the obsvr integration harness.
 *
 * These deepen every integration from "an event arrived" to "the event carries
 * the full signed-governance envelope AND the whole capture is a verifiable
 * HMAC chain". Two independent verifiers are used deliberately:
 *   1. the SDK's own exported `verifyAuditChain()` (what an auditor would run), and
 *   2. an independent manual HMAC recompute here (so a bug in the SDK verifier
 *      cannot mask a bug in the SDK signer, and vice-versa).
 *
 * Signing contract (source: sdk-typescript/src/proxy/chain-format.ts,
 * sdk-typescript/src/proxy/sender/fire-and-forget.ts,
 * sdk-typescript/src/governance/verify-chain.ts):
 *   signing_key = HMAC_SHA256(key="obsvr-sdk-signing-v1", msg=api_key).digest()
 *
 *   chain_format 1 (legacy; existing chains must keep verifying forever)
 *     content_hash = SHA256( (prompt ?? "") + (response ?? "") ).hex
 *     sig_payload  = [ session, seq, ts, content_hash, prev_sig ?? "" ].join("|")
 *
 *   chain_format 2
 *     content_hash = SHA256( "obsvr:content/2" || 0x00
 *                            || u64be(byteLen(prompt))   || prompt
 *                            || u64be(byteLen(response)) || response ).hex
 *     sig_payload  = [ "2", session, seq, ts, content_hash, prev_sig ?? "" ].join("|")
 *
 *   chain_format 3 (what the SDK signs today)
 *     decision_hash = SHA256( "obsvr:decision/3" || 0x00
 *                             || for each field of DECISION_FIELD_ORDER:
 *                                  presence_byte || u64be(byteLen(v)) || v ).hex
 *     sig_payload  = [ "3", session, seq, ts, content_hash, decision_hash,
 *                      prev_sig ?? "" ].join("|")
 *
 *   sdk_sig = HMAC_SHA256(signing_key, sig_payload).hex   (64 lowercase hex)
 *
 * Format 2 length-prefixes each field so the prompt/response boundary is itself
 * signed — under format 1 the same bytes could be re-split across that boundary
 * and still verify, which is exactly the attribution the chain claims to prove.
 * The event's own `chain_format` selects the rule; leading the payload with the
 * format number puts that claim under the HMAC too.
 *
 * Format 3 extends that reasoning from the content to the VERDICT. Under
 * formats 1 and 2 nothing about the decision was signed, so action_taken could
 * be rewritten from "blocked" to "allowed" and the chain still verified — the
 * exact inversion an enforcement record exists to prevent. The presence byte
 * per field is what keeps an absent field distinct from a present-and-empty
 * one, so `rule_id: null` and `rule_id: ""` cannot share a preimage.
 *
 * This reimplementation lagged the SDK: it stopped at format 2 while the SDK
 * moved to 3, so every recompute over a live capture rebuilt a format-3 payload
 * without its decision digest and reported a signature mismatch. The SDK's own
 * verifier passed alongside it, which is the reading that matters — the
 * independent check was the broken one, and an independent check that fails
 * against a correct signer is just as useless as one that passes against a
 * broken one. Anything added to the SDK's signed preimage has to land here too.
 *
 * This is deliberately a REIMPLEMENTATION of that spec, not a call into the
 * SDK's chain-format module: importing the SDK's own hasher here would let a
 * single bug satisfy both the signer and the check that is supposed to be
 * independent of it.
 * seq_no is process-global and monotonic (1-based); a single suite's capture is
 * therefore a CONTIGUOUS seq block that both verifiers accept.
 *
 * decision_input_hash / engine_version are ADDITIVE governance fields present on
 * governance LLM-call/blocked/evaluate events (the wrap() core-proxy path, the
 * framework-integration LLM path via applyPreCallPolicy, and governance
 * evaluate()). They are NOT present on tool_call / policy_flag / span /
 * delegation events built from DEFAULT_COMPLIANCE — so assertSignedEvent takes a
 * `decisionRecord` flag (default true) that those callers turn off.
 */
import { createHmac, createHash, createPublicKey, verify } from "node:crypto";
import { verifyAuditChain } from "@obsvr/sdk";
import { check } from "./check.mjs";

const HEX64 = /^[0-9a-f]{64}$/;
const SIGNING_SALT = "obsvr-sdk-signing-v1";

/** engine_version stamped by the 0.9.0 rules engine (RULES_ENGINE_SEMANTICS_VERSION = 1). */
export const ENGINE_VERSION = "obsvr-rules/1";
/** sdk_version is a `node/<semver>` build tag (constants.ts SDK_VERSION). Its
 *  exact value has churned this session (2.0.0 → 0.9.0), so we pin the FORMAT,
 *  not a brittle magic value — the meaningful invariant is that every event
 *  carries a well-formed node build tag. */
const SDK_VERSION_RE = /^node\/\d+\.\d+\.\d+/;

/** signing_key = HMAC_SHA256("obsvr-sdk-signing-v1", api_key). */
export function deriveSigningKey(apiKey) {
  return createHmac("sha256", SIGNING_SALT).update(String(apiKey)).digest();
}

const CHAIN_FORMAT_LEGACY = 1;
const CHAIN_FORMAT_CURRENT = 3;
const CONTENT_HASH_DOMAIN_TAG = "obsvr:content/2";
const DECISION_HASH_DOMAIN_TAG = "obsvr:decision/3";

/** The decision/attribution fields format 3 signs, in the ONE order the digest
 *  is defined over. Order and membership are part of the signature: changing
 *  either changes every format-3 sig and would require a new format number. */
export const DECISION_FIELD_ORDER = [
  "action_taken",
  "action_reason",
  "reason_code",
  "rule_id",
  "policy_version",
  "model",
  "provider",
  "user_id",
];

/** u64 big-endian byte-length prefix. Byte counts, not JS string length — the
 *  two runtimes agree on UTF-8 bytes, not on native string units. */
function lenPrefix(byteLength) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(byteLength));
  return buf;
}

/** Content hash under the event's declared chain format. */
function contentHashFor(format, prompt, response) {
  if (format === CHAIN_FORMAT_LEGACY) {
    return createHash("sha256")
      .update((prompt ?? "") + (response ?? ""))
      .digest("hex");
  }
  const p = Buffer.from(prompt ?? "", "utf8");
  const r = Buffer.from(response ?? "", "utf8");
  return createHash("sha256")
    .update(CONTENT_HASH_DOMAIN_TAG)
    .update(Buffer.from([0]))
    .update(lenPrefix(p.length))
    .update(p)
    .update(lenPrefix(r.length))
    .update(r)
    .digest("hex");
}

/** Digest over the decision/attribution fields an event carries. Format 3+. */
export function decisionHashOf(ev) {
  const h = createHash("sha256").update(DECISION_HASH_DOMAIN_TAG).update(Buffer.from([0]));
  for (const key of DECISION_FIELD_ORDER) {
    const raw = ev?.[key];
    const present = raw !== undefined && raw !== null;
    h.update(Buffer.from([present ? 1 : 0]));
    const bytes = Buffer.from(present ? String(raw) : "", "utf8");
    h.update(lenPrefix(bytes.length));
    h.update(bytes);
  }
  return h.digest("hex");
}

/** Recompute an event's sdk_sig from its stored fields (independent of the SDK).
 *  An event with no `chain_format` is read as format 1, which is what events
 *  minted before the field existed are. */
export function recomputeSig(ev, signingKey) {
  return createHmac("sha256", signingKey).update(signaturePayload(ev)).digest("hex");
}

/** The exact preimage STRING the HMAC is taken over.
 *
 *  Split out of recomputeSig because the optional device seal signs this same
 *  string (wrapped in its own domain-separated envelope). Deriving the device
 *  preimage from anywhere else would let the two tiers drift apart while both
 *  kept verifying — the device signature would attest to a payload the HMAC
 *  never covered, which is precisely the property the seal exists to deny. */
export function signaturePayload(ev) {
  const format = ev.chain_format ?? CHAIN_FORMAT_LEGACY;
  const fields = [
    ev.sdk_session_id,
    String(ev.seq_no),
    String(ev.timestamp_sdk),
    contentHashFor(format, ev.prompt, ev.response),
  ];
  if (format >= CHAIN_FORMAT_CURRENT) fields.push(decisionHashOf(ev));
  fields.push(ev.prev_sig ?? "");
  if (format !== CHAIN_FORMAT_LEGACY) fields.unshift(String(format));
  return fields.join("|");
}

// ── optional device seal (Ed25519 non-repudiation tier) ─────────────────────
// Source: sdk-typescript/src/proxy/device-identity.ts (twin:
// sdk-python/obsvr/device_identity.py). Reimplemented here for the same reason
// the HMAC is: a check that calls the SDK's own signer cannot catch the SDK's
// own signer being wrong.
//
//   key_id        = sha256(raw 32-byte public key).hex[:16]
//   device_preimage = "obsvr-device/1" || 0x00 || key_id || 0x00 || sig_payload
//   device_sig    = Ed25519(device_preimage).hex

/** Leads the device preimage; inside the signature so it cannot be swapped. */
export const DEVICE_SIG_VERSION = "obsvr-device/1";
const DEVICE_KEY_ID_LEN = 16;

/** key_id = sha256(raw public key).hex[:16] — derived, never configured. */
export function deviceKeyId(rawPublicKey) {
  if (rawPublicKey?.length !== 32) throw new Error(`device public key must be 32 raw bytes, got ${rawPublicKey?.length}`);
  return createHash("sha256").update(rawPublicKey).digest("hex").slice(0, DEVICE_KEY_ID_LEN);
}

/** The exact bytes the device key signs. */
export function devicePreimage(keyId, sigPayload) {
  return Buffer.concat([
    Buffer.from(DEVICE_SIG_VERSION, "utf8"), Buffer.from([0]),
    Buffer.from(keyId, "utf8"), Buffer.from([0]),
    Buffer.from(sigPayload, "utf8"),
  ]);
}

/** Wrap a raw 32-byte Ed25519 key in the SPKI DER envelope node:crypto wants. */
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
export function ed25519PublicKeyFromRaw(rawPublicKey) {
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, rawPublicKey]),
    format: "der",
    type: "spki",
  });
}

/** Verify a device_sig over an event, independently of the SDK. */
export function verifyDeviceSig(rawPublicKey, keyId, sigPayload, sigHex) {
  if (typeof sigHex !== "string" || !/^[0-9a-f]+$/.test(sigHex)) return false;
  return verify(null, devicePreimage(keyId, sigPayload), ed25519PublicKeyFromRaw(rawPublicKey), Buffer.from(sigHex, "hex"));
}

/**
 * Assert a single event carries the signed-governance envelope.
 * @param ev     the captured wire event
 * @param label  short prefix for the check lines
 * @param opts.decisionRecord  also assert decision_input_hash + engine_version
 *               (true for governance LLM/blocked/evaluate events; false for
 *                tool_call / policy_flag / span events). Default true.
 */
export function assertSignedEvent(ev, label = "event", opts = {}) {
  const { decisionRecord = true } = opts;
  check(`${label}: sdk_sig is 64-hex HMAC`, HEX64.test(String(ev?.sdk_sig)), String(ev?.sdk_sig));
  check(
    `${label}: sdk_session_id present`,
    typeof ev?.sdk_session_id === "string" && ev.sdk_session_id.length > 0,
  );
  check(`${label}: seq_no >= 1`, Number.isInteger(ev?.seq_no) && ev.seq_no >= 1, String(ev?.seq_no));
  check(`${label}: timestamp_sdk present`, Number.isFinite(ev?.timestamp_sdk), String(ev?.timestamp_sdk));
  check(`${label}: sdk_version is a node/<semver> build tag`, SDK_VERSION_RE.test(String(ev?.sdk_version)), String(ev?.sdk_version));
  check(
    `${label}: policy_version present`,
    typeof ev?.policy_version === "string" && ev.policy_version.length > 0,
    String(ev?.policy_version),
  );
  if (decisionRecord) {
    check(
      `${label}: decision_input_hash is 64-hex`,
      HEX64.test(String(ev?.decision_input_hash)),
      String(ev?.decision_input_hash),
    );
    check(`${label}: engine_version = ${ENGINE_VERSION}`, ev?.engine_version === ENGINE_VERSION, String(ev?.engine_version));
  }
}

/**
 * Verify a whole captured set as an HMAC chain, with BOTH the SDK's exported
 * verifier and an independent manual recompute. Sorts by seq_no first (arrival
 * order can differ from seq order for batched sends). Call at the end of every
 * integration run on the mock-ingest capture.
 *
 * @param events  captured wire events (mixed types ok; only signed ones checked)
 * @param apiKey  the api_key the SDK signed with (the value passed to obsvr.init;
 *                trimmed here to match resolveConfig's api_key.trim()).
 * @param label   prefix for the check lines
 */
export function verifyCapturedChain(events, apiKey, label = "chain") {
  const signed = (events ?? []).filter((e) => e && typeof e.sdk_sig === "string");
  if (signed.length === 0) {
    check(`${label}: has signed events to verify`, false, "no signed events captured");
    return { ok: false };
  }
  const sorted = [...signed].sort((a, b) => (a.seq_no ?? 0) - (b.seq_no ?? 0));
  const key = String(apiKey ?? "").trim();

  // 1) SDK's own verifier (the auditor path).
  const res = verifyAuditChain(sorted, key);
  const sdkOk = res.valid === true && res.eventsVerified === sorted.length;
  check(
    `${label}: SDK verifyAuditChain() valid over ${sorted.length} events`,
    sdkOk,
    res.reason || `verified ${res.eventsVerified}/${sorted.length}`,
  );

  // 2) Independent manual HMAC recompute + linkage + contiguity.
  const signingKey = deriveSigningKey(key);
  let sigOk = true;
  let linkOk = true;
  let seqOk = true;
  let firstBad = null;
  for (let i = 0; i < sorted.length; i++) {
    const ev = sorted[i];
    if (ev.sdk_sig !== recomputeSig(ev, signingKey)) {
      sigOk = false;
      if (firstBad === null) firstBad = i;
    }
    if (i > 0) {
      if (ev.prev_sig !== sorted[i - 1].sdk_sig) linkOk = false;
      if ((ev.seq_no ?? 0) !== (sorted[i - 1].seq_no ?? 0) + 1) seqOk = false;
    }
  }
  check(
    `${label}: independent HMAC recompute matches every sdk_sig`,
    sigOk,
    firstBad !== null ? `first mismatch at sorted index ${firstBad} (seq ${sorted[firstBad]?.seq_no})` : undefined,
  );
  check(`${label}: prev_sig links each event to the prior sdk_sig`, linkOk);
  check(`${label}: seq_no contiguous across the delivered chain`, seqOk);

  // Two failures the contiguity check above already trips on but MISREPORTS,
  // which matters because they are different defects with different causes.
  //
  // A duplicated seq_no is worse than a gap: the chain still verifies pairwise
  // while two events claim the same position, so "not contiguous" reads as
  // "one was dropped" when in fact one is unaccounted for. A fork — two events
  // naming the same prev_sig — is worse still, because verifyAuditChain walks a
  // single path and would report a valid chain over whichever branch it
  // followed while silently omitting the other. Naming them separately turns a
  // confusing ordering failure into the concurrency bug it actually is.
  const seqCounts = new Map();
  const parentCounts = new Map();
  for (const ev of sorted) {
    const s = ev.seq_no ?? 0;
    seqCounts.set(s, (seqCounts.get(s) ?? 0) + 1);
    if (ev.prev_sig) parentCounts.set(ev.prev_sig, (parentCounts.get(ev.prev_sig) ?? 0) + 1);
  }
  const dupSeqs = [...seqCounts.entries()].filter(([, n]) => n > 1).map(([s]) => s);
  const forks = [...parentCounts.entries()].filter(([, n]) => n > 1).map(([p]) => String(p).slice(0, 12));
  check(
    `${label}: no two events claim the same seq_no`,
    dupSeqs.length === 0,
    dupSeqs.length ? `duplicated seq_no: ${dupSeqs.join(", ")}` : undefined,
  );
  check(
    `${label}: no two events claim the same parent (chain does not fork)`,
    forks.length === 0,
    forks.length ? `forked at prev_sig: ${forks.join(", ")}` : undefined,
  );

  // Each event must carry its own identity. A request_id shared across
  // concurrent calls means per-call state leaked between them, and a chain
  // check cannot see it because the chain stays perfectly well-formed.
  const ids = sorted.map((e) => e.request_id).filter(Boolean);
  const dupIds = ids.length - new Set(ids).size;
  check(
    `${label}: every event carries a distinct request_id`,
    dupIds === 0,
    dupIds ? `${dupIds} duplicate request_id(s) across ${ids.length} events` : undefined,
  );

  return {
    ok: sdkOk && sigOk && linkOk && seqOk && dupSeqs.length === 0 && forks.length === 0 && dupIds === 0,
    count: sorted.length,
  };
}
