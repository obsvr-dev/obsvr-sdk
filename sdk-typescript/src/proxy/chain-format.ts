/**
 * Audit-chain format — the content-hash preimage and signature payload,
 * shared by the signer (proxy/sender/fire-and-forget.ts) and the verifier
 * (governance/verify-chain.ts) so the two cannot drift apart. Twin:
 * sdk-python/obsvr/chain_format.py. Pinned by
 * conformance/fixtures/signing_vectors.json, which both languages consume.
 *
 * WHY FORMAT 2 EXISTS. Format 1 hashed the bare concatenation
 * `sha256(prompt + response)`, and a concatenation does not remember where
 * one field ended and the next began: sha256("AB" + "C") and
 * sha256("A" + "BC") are the same digest. An event's content could therefore
 * be re-split at a different prompt/response boundary — moving text from
 * "what the model said" into "what the user said", or the reverse — and the
 * chain still verified. The chain's whole claim is attribution of who said
 * what, so the boundary must be part of what is signed.
 *
 * Format 2 makes the preimage unambiguous by construction:
 *
 *   sha256( "obsvr:content/2" || 0x00
 *           || u64be(len(prompt))   || prompt
 *           || u64be(len(response)) || response )
 *
 * with both fields as UTF-8 bytes and lengths counted in bytes. A length
 * prefix per field means no re-split of the same bytes can reproduce the
 * preimage: the split points are stated inside it. The leading tag plus NUL
 * domain-separates this digest from every other sha256 in the SDK (the
 * tool-content hash, the pinning hash), so a digest minted for one purpose
 * can never be replayed as another. The 8-byte length cannot overflow for
 * any string either runtime can hold.
 *
 * The signature payload also changes: format 2 leads with the format number
 * (`2|session|seq|ts|hash|prev`), so an event's format claim is itself under
 * the HMAC. The `chain_format` field on the event routes the verifier; a
 * forged or stripped field can only make verification FAIL (the recomputed
 * payload will not match), never redirect a signature minted under one
 * format into verifying under the other.
 *
 * WHY FORMAT 3 EXISTS. Formats 1 and 2 sign the CONTENT and the ORDER, and
 * nothing else: the preimage was
 * `format | session | seq | timestamp | content_hash | prev_sig`, with no
 * decision field in it. So a party who could edit a stored event before ingest
 * could rewrite `action_taken` from "blocked" to "allowed" — inverting the
 * enforcement record — and the shipped offline verifier, run with the CORRECT
 * API key, still reported the chain valid. Measured, not theorised: a tamper
 * matrix over a real chain rewrote all eight of `action_taken`,
 * `action_reason`, `reason_code`, `rule_id`, `policy_version`, `model`,
 * `provider` and `user_id`, and every one verified clean, while the content and
 * ordering controls broke exactly as they should.
 *
 * The server countersignature was always the thing that sealed those fields,
 * and `SECURITY.md` said so. But `obsvr-verify` is shipped as the user-facing
 * OFFLINE verifier, and a compliance officer running it got a clean result on a
 * fully rewritten verdict history. For an evidence product that is the worst
 * shape of defect available: a false negative that reads exactly like a true
 * one.
 *
 * Format 3 folds a decision digest into the preimage:
 *
 *   3|session|seq|ts|content_hash|decision_hash|prev
 *
 * The decision digest is framed the same way and for the same reason as the
 * format-2 content hash — eight fields concatenated bare would re-split at a
 * different boundary exactly as prompt/response did:
 *
 *   sha256( "obsvr:decision/3" || 0x00
 *           || for each field, in DECISION_FIELD_ORDER:
 *                presence_byte || u64be(len(value)) || value )
 *
 * The presence byte (0x01 present, 0x00 absent) is what keeps an ABSENT field
 * distinct from one present-and-empty. Without it `rule_id: null` and
 * `rule_id: ""` would produce the same preimage, and "no rule fired" would be
 * interchangeable with "a rule with an empty id fired".
 *
 * The content hash is UNCHANGED between formats 2 and 3: the content framing
 * did not need fixing, and `obsvr:content/2` names the content-preimage
 * version rather than the chain format.
 *
 * Formats 1 and 2 stay implemented here forever: chains signed before each
 * change are existing evidence and must keep verifying — explicitly, as the
 * format they were signed under, never silently under a newer rule.
 *
 * No two formats share a valid signature. Formats 2 and later lead their
 * payload with their own format number; format 1 does NOT, and is reproduced
 * byte-for-byte as it always was, because its signatures already exist and
 * prefixing them now would invalidate every legacy chain. Format 1 is instead
 * distinguished by carrying neither the leading format field nor the decision
 * hash. The earlier wording said each format leads with its number, which an
 * implementer following it would have applied to format 1 and broken every
 * legacy signature.
 *
 * @packageDocumentation
 */
import { createHash } from "crypto";

/** The pre-framing format: `sha256(prompt + response)`, boundary unsigned. */
export const CHAIN_FORMAT_LEGACY = 1;
/** Length-prefixed, domain-tagged content preimage. Content and order only. */
export const CHAIN_FORMAT_CONTENT_ONLY = 2;
/** Content, order AND the decision fields. What the SDK signs today. */
export const CHAIN_FORMAT_CURRENT = 3;
/** Every format this build can verify, oldest first. */
export const CHAIN_FORMATS_SUPPORTED = [1, 2, 3] as const;
/** Domain tag leading every format-2 content preimage. */
export const CONTENT_HASH_DOMAIN_TAG = "obsvr:content/2";
/** Domain tag leading every format-3 decision preimage. */
export const DECISION_HASH_DOMAIN_TAG = "obsvr:decision/3";

/**
 * The decision/attribution fields format 3 signs, in the ONE order the digest
 * is defined over. Both languages iterate this list; changing the order or the
 * membership changes every format-3 signature and requires a new format.
 */
export const DECISION_FIELD_ORDER = [
  "action_taken",
  "action_reason",
  "reason_code",
  "rule_id",
  "policy_version",
  "model",
  "provider",
  "user_id",
] as const;

/** The decision fields, as read off an event. Absent and empty are distinct. */
export type DecisionFields = {
  [K in (typeof DECISION_FIELD_ORDER)[number]]?: string | null;
};

/** u64 big-endian length prefix. Bytes, not code units — the two runtimes
 * agree on UTF-8 byte counts, not on their native string lengths. */
function lenPrefix(byteLength: number): Buffer {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(byteLength));
  return buf;
}

/**
 * Content hash under the given chain format. Absent fields hash as empty —
 * in format 2 an absent prompt is still a stated zero-length field, so
 * ("", "x") and ("x", "") produce different digests where format 1 collided.
 */
export function contentHash(format: number, prompt: string, response: string): string {
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

/**
 * Read the signed decision fields off an event.
 *
 * ONE reader, used by both the signer and the verifier. If they read the field
 * set differently — even in how they treat an absent value — every signature
 * verifies as broken, and the bug would look like tampering. That failure mode
 * is why this is not two functions.
 */
export function decisionFieldsOf(event: Record<string, unknown>): DecisionFields {
  const out: DecisionFields = {};
  for (const key of DECISION_FIELD_ORDER) {
    const value = event[key];
    out[key] = value === undefined || value === null ? undefined : String(value);
  }
  return out;
}

/**
 * Digest over the decision/attribution fields. Format 3 and later only.
 *
 * Each field contributes a presence byte, a u64be byte-length, and its UTF-8
 * bytes, in `DECISION_FIELD_ORDER`. The presence byte distinguishes an absent
 * field from a present-and-empty one; the length prefix stops two different
 * field sets sharing a preimage the way an unframed concatenation would.
 */
export function decisionHash(fields: DecisionFields): string {
  const h = createHash("sha256")
    .update(DECISION_HASH_DOMAIN_TAG)
    .update(Buffer.from([0]));
  for (const key of DECISION_FIELD_ORDER) {
    const value = fields[key];
    const present = value !== undefined && value !== null;
    h.update(Buffer.from([present ? 1 : 0]));
    const bytes = Buffer.from(present ? String(value) : "", "utf8");
    h.update(lenPrefix(bytes.length));
    h.update(bytes);
  }
  return h.digest("hex");
}

/**
 * The exact string the HMAC signs. Formats 2 and 3 lead with the format number
 * so the format claim is itself tamper-evident; format 1 is reproduced
 * byte-for-byte as it always was, because its signatures already exist.
 *
 * `decision` is read only for format 3 and later. Passing it for an older
 * format is harmless and changes nothing, which is what lets one call site sign
 * any format.
 */
export function signaturePayload(
  format: number,
  sessionId: string,
  seqNo: number,
  timestampSdk: number,
  prompt: string,
  response: string,
  prevSig: string | null,
  decision?: DecisionFields
): string {
  const fields = [
    sessionId,
    String(seqNo),
    String(timestampSdk),
    contentHash(format, prompt, response),
  ];
  if (format >= CHAIN_FORMAT_CURRENT) {
    fields.push(decisionHash(decision ?? {}));
  }
  fields.push(prevSig ?? "");
  if (format !== CHAIN_FORMAT_LEGACY) {
    fields.unshift(String(format));
  }
  return fields.join("|");
}
