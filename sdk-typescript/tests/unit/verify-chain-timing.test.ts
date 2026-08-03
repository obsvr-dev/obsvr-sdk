/**
 * The signature comparison in verifyAuditChain is constant-time.
 *
 * The verifier is library surface, run against caller-supplied chains - not
 * only by the offline CLI - so the stored-vs-recomputed comparison must not
 * leak how many leading bytes matched. `timingSafeEqual` with a length guard
 * is the Node idiom; the guard leaks only the lengths, which are public (a
 * well-formed sdk_sig is 64 hex characters, and the recomputed digest always
 * is). Twin reasoning: hmac.compare_digest in sdk-python/obsvr/verify_chain.py.
 *
 * The wiring is pinned on the source text because a timing property has no
 * verdict to assert on: an early-exit `!==` returns the same booleans. The
 * behavioral tests alongside prove the verdicts survived the change.
 */
import { readFileSync } from "node:fs";
import * as path from "path";
import { createHmac } from "node:crypto";
import { verifyAuditChain } from "../../src/governance/verify-chain";
import {
  CHAIN_FORMAT_CURRENT,
  decisionFieldsOf,
  signaturePayload,
} from "../../src/proxy/chain-format";
import type { AuditEvent } from "../../src/proxy/types";

const SRC = readFileSync(
  path.resolve(
    path.dirname(new URL(import.meta.url).pathname),
    "..",
    "..",
    "src",
    "governance",
    "verify-chain.ts",
  ),
  "utf-8",
);

test("recomputed signatures go through timingSafeEqual, not !==", () => {
  expect(SRC).toContain("timingSafeEqual(");
  expect(SRC).not.toContain("event.sdk_sig !== expectedSig");
});

test("the comparison is length-guarded before timingSafeEqual", () => {
  // timingSafeEqual throws on unequal lengths, so the guard is what turns a
  // wrong-length signature into a verdict instead of an exception.
  expect(SRC).toMatch(/storedBuf\.length !== expectedBuf\.length/);
});

// The verdicts the comparison produces, unchanged by the timing-safe path.
const API_KEY = "test-api-key";
const SESSION = "44444444-4444-4444-4444-444444444444";

function signedEvent(): AuditEvent {
  const key = createHmac("sha256", "obsvr-sdk-signing-v1").update(API_KEY).digest();
  const event: Record<string, unknown> = {
    sdk_session_id: SESSION,
    seq_no: 1,
    timestamp_sdk: 1700000000000,
    prompt: "p",
    response: "r",
    chain_format: CHAIN_FORMAT_CURRENT,
  };
  const payload = signaturePayload(
    CHAIN_FORMAT_CURRENT,
    SESSION,
    1,
    1700000000000,
    "p",
    "r",
    null,
    decisionFieldsOf(event),
  );
  event.sdk_sig = createHmac("sha256", key).update(payload).digest("hex");
  return event as unknown as AuditEvent;
}

test("a genuine signature still verifies", () => {
  expect(verifyAuditChain([signedEvent()], API_KEY).valid).toBe(true);
});

test("a wrong-length signature is a verdict, not an exception", () => {
  const event = signedEvent();
  event.sdk_sig = "abc"; // shorter than any real digest
  const result = verifyAuditChain([event], API_KEY);
  expect(result.valid).toBe(false);
  expect(result.reason).toBe("Signature mismatch at event 0");
});

test("a non-string signature is a verdict, not an exception", () => {
  const event = signedEvent();
  (event as unknown as Record<string, unknown>).sdk_sig = 12345;
  const result = verifyAuditChain([event], API_KEY);
  expect(result.valid).toBe(false);
  expect(result.reason).toBe("Signature mismatch at event 0");
});
