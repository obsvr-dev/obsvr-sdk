/**
 * Cross-language signing parity test.
 *
 * conformance/fixtures/signing_vectors.json is asserted by both the TS and
 * Python suites (twin: sdk-python/tests/test_signing.py). If either
 * language's signing algorithm drifts, its suite fails against the shared
 * vectors — guaranteeing @obsvr/sdk (npm) and obsvr-sdk (PyPI) stay
 * byte-for-byte compatible so ingest verifies both identically.
 *
 * The vectors pin THREE things: the signing-key derivation, the format-2
 * content-hash preimage (including the boundary cases format 1 collided
 * on — that collision is itself pinned under `legacy_digest`, so the defect
 * the format change closed stays demonstrable), and the chained signatures
 * under both formats. Format 1 vectors are frozen forever: chains signed
 * before the change are existing evidence.
 */
import { createHmac } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import {
  CHAIN_FORMAT_CURRENT,
  CHAIN_FORMAT_LEGACY,
  contentHash,
  signaturePayload,
} from "../../src/proxy/chain-format";

// Resolve the shared fixture upward from cwd (same pattern as
// conformance.test.ts) so the one signing_vectors.json drives both suites.
function findFixture(rel: string): string {
  let dir = process.cwd();
  for (let i = 0; i < 6; i++) {
    const candidate = join(dir, rel);
    if (existsSync(candidate)) return candidate;
    dir = dirname(dir);
  }
  throw new Error(`fixture not found upward from ${process.cwd()}: ${rel}`);
}

interface ContentHashCase {
  id: string;
  note?: string;
  prompt: string;
  response: string;
  digest: string;
  legacy_digest: string;
}

const vectors = JSON.parse(
  readFileSync(findFixture("conformance/fixtures/signing_vectors.json"), "utf-8"),
);

function deriveKey(apiKey: string): Buffer {
  return createHmac("sha256", "obsvr-sdk-signing-v1").update(apiKey).digest();
}

function sign(
  key: Buffer,
  format: number,
  session: string,
  seq: number,
  ts: number,
  prompt: string,
  response: string,
  prev: string,
): string {
  const payload = signaturePayload(format, session, seq, ts, prompt, response, prev || null);
  return createHmac("sha256", key).update(payload).digest("hex");
}

describe("cross-language signing vectors", () => {
  it("derives the same signing key as the shared vector", () => {
    const key = deriveKey(vectors.api_key);
    expect(key.toString("hex")).toBe(vectors.signing_key_hex);
  });

  it("produces the pinned content hash for every case, in both formats", () => {
    for (const c of vectors.content_hash.cases as ContentHashCase[]) {
      expect(contentHash(CHAIN_FORMAT_CURRENT, c.prompt, c.response)).toBe(c.digest);
      expect(contentHash(CHAIN_FORMAT_LEGACY, c.prompt, c.response)).toBe(c.legacy_digest);
    }
  });

  it("format 2 binds the prompt/response boundary: the must_differ pairs differ", () => {
    const byId = new Map(
      (vectors.content_hash.cases as ContentHashCase[]).map((c) => [c.id, c]),
    );
    for (const [a, b] of vectors.content_hash.must_differ as Array<[string, string]>) {
      expect(byId.get(a)!.digest).not.toBe(byId.get(b)!.digest);
    }
  });

  it("format 1 did NOT bind the boundary: the equal_under_legacy pairs collide", () => {
    // The pinned demonstration of the defect format 2 closed. If this ever
    // fails, the legacy implementation drifted — which would break existing
    // evidence, so the collision is asserted, not just remembered.
    const byId = new Map(
      (vectors.content_hash.cases as ContentHashCase[]).map((c) => [c.id, c]),
    );
    for (const [a, b] of vectors.content_hash.equal_under_legacy as Array<[string, string]>) {
      expect(byId.get(a)!.legacy_digest).toBe(byId.get(b)!.legacy_digest);
    }
  });

  it("produces the same chained format-2 signatures as the shared vectors", () => {
    const key = deriveKey(vectors.api_key);
    let prev = "";
    for (const ev of vectors.events) {
      expect(ev.chain_format).toBe(CHAIN_FORMAT_CURRENT);
      const sig = sign(
        key,
        CHAIN_FORMAT_CURRENT,
        vectors.session_id,
        ev.seq_no,
        ev.timestamp_sdk,
        ev.prompt,
        ev.response,
        prev,
      );
      expect(sig).toBe(ev.sdk_sig);
      expect(ev.prev_sig).toBe(prev);
      prev = sig;
    }
  });

  it("still reproduces the frozen format-1 signatures", () => {
    const key = deriveKey(vectors.api_key);
    let prev = "";
    for (const ev of vectors.legacy_v1_events.events) {
      const sig = sign(
        key,
        CHAIN_FORMAT_LEGACY,
        vectors.session_id,
        ev.seq_no,
        ev.timestamp_sdk,
        ev.prompt,
        ev.response,
        prev,
      );
      expect(sig).toBe(ev.sdk_sig);
      expect(ev.prev_sig).toBe(prev);
      prev = sig;
    }
  });
});
