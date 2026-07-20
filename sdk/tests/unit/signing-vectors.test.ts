/**
 * Cross-language signing parity test.
 *
 * conformance/fixtures/signing_vectors.json is asserted by both the TS and
 * Python suites (twin: sdk-python/tests/test_signing.py). If either
 * language's signing algorithm drifts, its suite fails against the shared
 * vectors — guaranteeing @obsvr/sdk (npm) and obsvr-sdk (PyPI) stay
 * byte-for-byte compatible so ingest verifies both identically.
 */
import { createHmac, createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";

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

const vectors = JSON.parse(
  readFileSync(findFixture("conformance/fixtures/signing_vectors.json"), "utf-8"),
);

function deriveKey(apiKey: string): Buffer {
  return createHmac("sha256", "obsvr-sdk-signing-v1").update(apiKey).digest();
}

function sign(
  key: Buffer,
  session: string,
  seq: number,
  ts: number,
  prompt: string,
  response: string,
  prev: string,
): string {
  const contentHash = createHash("sha256")
    .update((prompt ?? "") + (response ?? ""))
    .digest("hex");
  const payload = [session, String(seq), String(ts), contentHash, prev ?? ""].join("|");
  return createHmac("sha256", key).update(payload).digest("hex");
}

describe("cross-language signing vectors", () => {
  it("derives the same signing key as the shared vector", () => {
    const key = deriveKey(vectors.api_key);
    expect(key.toString("hex")).toBe(vectors.signing_key_hex);
  });

  it("produces the same chained signatures as the shared vectors", () => {
    const key = deriveKey(vectors.api_key);
    let prev = "";
    for (const ev of vectors.events) {
      const sig = sign(
        key,
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
