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
 * Format 1 stays implemented here forever: chains signed before the change
 * are existing evidence and must keep verifying — explicitly, as format 1,
 * never silently under the new rule (the formats share no valid signature,
 * because the content-hash preimages differ even for empty content).
 *
 * @packageDocumentation
 */
import { createHash } from "crypto";

/** The pre-framing format: `sha256(prompt + response)`, boundary unsigned. */
export const CHAIN_FORMAT_LEGACY = 1;
/** Length-prefixed, domain-tagged content preimage. What the SDK signs today. */
export const CHAIN_FORMAT_CURRENT = 2;
/** Domain tag leading every format-2 content preimage. */
export const CONTENT_HASH_DOMAIN_TAG = "obsvr:content/2";

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
 * The exact string the HMAC signs. Format 2 leads with the format number so
 * the format claim is tamper-evident; format 1 is reproduced byte-for-byte
 * as it always was, because its signatures already exist.
 */
export function signaturePayload(
  format: number,
  sessionId: string,
  seqNo: number,
  timestampSdk: number,
  prompt: string,
  response: string,
  prevSig: string | null
): string {
  const fields = [
    sessionId,
    String(seqNo),
    String(timestampSdk),
    contentHash(format, prompt, response),
    prevSig ?? "",
  ];
  if (format !== CHAIN_FORMAT_LEGACY) {
    fields.unshift(String(format));
  }
  return fields.join("|");
}
