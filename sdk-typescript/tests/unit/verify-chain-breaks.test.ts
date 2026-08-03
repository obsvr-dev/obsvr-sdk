/**
 * One run, the full damage report: `breaks` lists every independent break the
 * verifier found, while `brokenAt` / `reason` / `eventsVerified` keep their
 * first-break meaning for existing readers. Twin:
 * sdk-python/tests/test_verify_chain.py::TestEveryBreakReported.
 */
import { createHmac } from "node:crypto";
import { verifyAuditChain } from "../../src/governance/verify-chain";
import {
  CHAIN_FORMAT_CURRENT,
  decisionFieldsOf,
  signaturePayload,
} from "../../src/proxy/chain-format";
import { AUDIT_GAP_OPERATION } from "../../src/proxy/audit-gap";
import type { AuditEvent } from "../../src/proxy/types";

const API_KEY = "test-api-key";
const SESSION = "33333333-3333-3333-3333-333333333333";

function deriveKey(apiKey: string): Buffer {
  return createHmac("sha256", "obsvr-sdk-signing-v1").update(apiKey).digest();
}

/** A valid format-3 chain of n events, signed the way the sender signs. */
function signedChain(n: number, prompts?: string[]): AuditEvent[] {
  const key = deriveKey(API_KEY);
  const events: AuditEvent[] = [];
  let prev: string | null = null;
  for (let i = 0; i < n; i++) {
    const event: Record<string, unknown> = {
      sdk_session_id: SESSION,
      seq_no: i + 1,
      timestamp_sdk: 1700000000000 + i,
      prompt: prompts?.[i] ?? `prompt-${i}`,
      response: `response-${i}`,
      chain_format: CHAIN_FORMAT_CURRENT,
    };
    if (prev) event.prev_sig = prev;
    const payload = signaturePayload(
      CHAIN_FORMAT_CURRENT,
      SESSION,
      i + 1,
      event.timestamp_sdk as number,
      event.prompt as string,
      event.response as string,
      prev,
      decisionFieldsOf(event),
    );
    event.sdk_sig = createHmac("sha256", key).update(payload).digest("hex");
    prev = event.sdk_sig as string;
    events.push(event as unknown as AuditEvent);
  }
  return events;
}

describe("every break reported", () => {
  test("three independent breaks reported in one run", () => {
    const events = signedChain(7);
    events[1].prompt = "tampered"; // content edit -> bad signature
    events.splice(3, 1); // deletion -> seq gap
    events[events.length - 1].sdk_sig = "0".repeat(64); // forged signature
    const result = verifyAuditChain(events, API_KEY);
    expect(result.valid).toBe(false);
    expect(result.breaks.map((b) => b.reason)).toEqual([
      "Signature mismatch at event 1",
      "seq_no gap at event 3: expected 4, got 5",
      "Signature mismatch at event 5",
    ]);
    expect(result.breaks.map((b) => b.index)).toEqual([1, 3, 5]);
  });

  test("first break still names brokenAt and reason", () => {
    const events = signedChain(7);
    events[1].prompt = "tampered";
    events.splice(3, 1);
    const result = verifyAuditChain(events, API_KEY);
    expect(result.brokenAt).toBe(1);
    expect(result.breaks[0].index).toBe(1);
    expect(result.reason).toBe(result.breaks[0].reason);
    // Backward-compatible meaning: events verified before the FIRST break.
    expect(result.eventsVerified).toBe(1);
  });

  test("single break yields a single-entry list", () => {
    const events = signedChain(3);
    events[1].prompt = "tampered";
    const result = verifyAuditChain(events, API_KEY);
    expect(result.breaks).toEqual([
      { index: 1, reason: "Signature mismatch at event 1" },
    ]);
  });

  test("a valid chain reports an empty list, not an absent one", () => {
    const result = verifyAuditChain(signedChain(3), API_KEY);
    expect(result.valid).toBe(true);
    expect(result.breaks).toEqual([]);
  });

  test("forged sdk_sig severs the link to its successor", () => {
    // An edited sdk_sig is two facts, and both are reported: the event's own
    // signature no longer verifies, and its successor's prev_sig was minted
    // against the value that is no longer there. Re-anchoring on the stored
    // sdk_sig keeps the report at those two facts instead of failing every
    // event downstream.
    const events = signedChain(4);
    events[1].sdk_sig = "0".repeat(64);
    const result = verifyAuditChain(events, API_KEY);
    expect(result.breaks.map((b) => b.reason)).toEqual([
      "Signature mismatch at event 1",
      "Chain break at event 2: prev_sig does not match prior event's sdk_sig",
    ]);
  });

  test("foreign-session event does not derail the chain", () => {
    const events = signedChain(3);
    const foreign = {
      ...events[1],
      sdk_session_id: "99999999-9999-9999-9999-999999999999",
    };
    const result = verifyAuditChain(
      [events[0], foreign, events[1], events[2]],
      API_KEY,
    );
    expect(result.valid).toBe(false);
    expect(result.breaks).toHaveLength(1);
    expect(result.breaks[0].reason).toContain("Session ID mismatch at event 1");
  });

  test("gap tally still covers only the prefix before the first break", () => {
    const events = signedChain(3, [
      "prompt-0",
      "prompt-1",
      "obsvr:audit-gap/1 dropped=7 reason=queue_overflow",
    ]);
    // `operation` is outside the signature preimage, so stamping it after
    // signing leaves a marker whose own signature verifies.
    (events[2] as unknown as Record<string, unknown>).operation = AUDIT_GAP_OPERATION;
    expect(verifyAuditChain(events, API_KEY).eventsDeclaredLost).toBe(7);

    events[0].prompt = "tampered";
    const result = verifyAuditChain(events, API_KEY);
    expect(result.valid).toBe(false);
    // The marker's own signature still verified, but it sits past the first
    // break, so it is outside the tally - as it always was.
    expect(result.gapMarkers).toBe(0);
    expect(result.eventsDeclaredLost).toBe(0);
  });
});
