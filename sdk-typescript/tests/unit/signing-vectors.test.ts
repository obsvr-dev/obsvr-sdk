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
  CHAIN_FORMAT_CONTENT_ONLY,
  CHAIN_FORMAT_CLASSIFIED,
  CHAIN_FORMAT_CURRENT,
  CHAIN_FORMAT_DECISION_FIELDS,
  CHAIN_FORMAT_LEGACY,
  contentHash,
  decisionFieldsOf,
  decisionHash,
  signaturePayload,
} from "../../src/proxy/chain-format";
import { filterArgs } from "../../src/proxy/filters/filter";

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
  // Independent protocol-vector verification over a synthetic test API key;
  // this is not password storage or a password-based KDF.
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
  decision?: Record<string, unknown>,
): string {
  const payload = signaturePayload(
    format,
    session,
    seq,
    ts,
    prompt,
    response,
    prev || null,
    decision,
  );
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

  it("produces the same chained format-4 signatures as the shared vectors", () => {
    const key = deriveKey(vectors.api_key);
    let prev = "";
    for (const ev of vectors.events) {
      expect(ev.chain_format).toBe(CHAIN_FORMAT_CLASSIFIED);
      const sig = sign(
        key,
        CHAIN_FORMAT_CLASSIFIED,
        vectors.session_id,
        ev.seq_no,
        ev.timestamp_sdk,
        ev.prompt,
        ev.response,
        prev,
        // Format 4 signs the decision and classification fields carried on the
        // vector event itself. Read them the way the SDK does.
        decisionFieldsOf(ev, CHAIN_FORMAT_CLASSIFIED),
      );
      expect(sig).toBe(ev.sdk_sig);
      expect(ev.prev_sig).toBe(prev);
      prev = sig;
    }
  });

  it("still reproduces the frozen format-3 signatures", () => {
    const key = deriveKey(vectors.api_key);
    let prev = "";
    for (const ev of vectors.legacy_v3_events.events) {
      const sig = sign(
        key,
        CHAIN_FORMAT_DECISION_FIELDS,
        vectors.session_id,
        ev.seq_no,
        ev.timestamp_sdk,
        ev.prompt,
        ev.response,
        prev,
        decisionFieldsOf(ev, CHAIN_FORMAT_DECISION_FIELDS),
      );
      expect(sig).toBe(ev.sdk_sig);
      prev = sig;
    }
  });

  it("still reproduces the frozen format-2 signatures", () => {
    const key = deriveKey(vectors.api_key);
    let prev = "";
    for (const ev of vectors.legacy_v2_events.events) {
      expect(ev.chain_format).toBe(CHAIN_FORMAT_CONTENT_ONLY);
      const sig = sign(
        key,
        CHAIN_FORMAT_CONTENT_ONLY,
        vectors.session_id,
        ev.seq_no,
        ev.timestamp_sdk,
        ev.prompt,
        ev.response,
        prev,
        // Deliberately passed: format 2 must IGNORE it. If a future edit made
        // the older format read this argument, every pre-format-3 chain in
        // existence would stop verifying, and this line is what catches it.
        decisionFieldsOf(ev),
      );
      expect(sig).toBe(ev.sdk_sig);
      prev = sig;
    }
  });

  it("matches every pinned decision-hash case", () => {
    for (const c of vectors.decision_hash.cases) {
      expect(decisionHash(c.fields, CHAIN_FORMAT_CLASSIFIED)).toBe(c.digest);
    }
  });

  it("coerces every pinned non-string user_id to the shared canonical string", () => {
    // A non-string user_id is coerced to ONE canonical string at the audit
    // boundary before anything stores or signs it; the fixture pins both the
    // string and the decision digest over it, and the Python suite pins the
    // same cases through its own boundary. `raw` arrives here through the
    // same JSON parse a stored export goes through, which is exactly where
    // the two runtimes' scalar renderings part company.
    for (const c of vectors.user_id_coercion.cases) {
      const { audit_fields } = filterArgs([{ model: "m", user_id: c.raw }]);
      expect(audit_fields.user_id).toBe(c.canonical);
      expect(decisionHash({ user_id: c.canonical }, CHAIN_FORMAT_CLASSIFIED)).toBe(c.digest);
    }
  });

  it("distinguishes an absent decision field from a present-and-empty one", () => {
    const byId = new Map<string, { digest: string }>(
      vectors.decision_hash.cases.map((c: { id: string; digest: string }) => [c.id, c]),
    );
    expect(byId.get("all_absent")!.digest).not.toBe(
      byId.get("rule_id_present_but_empty")!.digest,
    );
    // And the pair format 3 exists for.
    expect(byId.get("blocked_full")!.digest).not.toBe(
      byId.get("action_taken_flipped_to_allowed")!.digest,
    );
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
