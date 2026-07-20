#!/usr/bin/env node
/**
 * obsvr-verify: offline evidence verification for auditors.
 *
 *   npx obsvr-verify <bundle.json> [--api-key <key>]
 *
 * Input: an exported obsvr evidence file — an incident evidence bundle
 * (obsvr-incident-evidence-v1, `trace.steps`), a trace evidence bundle, or a
 * plain JSON array of audit events. Two verification tiers:
 *
 *  - WITHOUT --api-key: structural chain verification. prev_sig linkage,
 *    seq_no continuity, session consistency, and timestamp monotonicity are
 *    checked from the events alone. Detects reordering, insertion, and
 *    deletion; cannot detect a re-signed forgery (that needs the key).
 *  - WITH --api-key: HMAC re-verification (verifyAuditChain) — every signature
 *    is recomputed over the content + chain preimage, so any content tamper or
 *    reorder breaks. The client signature does NOT cover the decision/
 *    attribution fields (verdict, rule, tenant); those are sealed by the server
 *    countersignature at ingest, not by this offline check.
 *
 * Exit code 0 = verified at the requested tier; 1 = broken; 2 = usage error.
 * Deliberately dependency-free and offline: an auditor must be able to
 * verify obsvr's evidence without trusting obsvr's servers or UI.
 */

import { readFileSync } from "node:fs";
import { verifyAuditChain } from "./governance/verify-chain.js";
import type { AuditEvent } from "./proxy/types.js";

function fail(msg: string, code = 1): never {
  console.error(`✗ ${msg}`);
  process.exit(code);
}

function extractEvents(parsed: unknown): AuditEvent[] {
  if (Array.isArray(parsed)) return parsed as AuditEvent[];
  const obj = parsed as Record<string, any>;
  if (Array.isArray(obj?.trace?.steps)) return obj.trace.steps as AuditEvent[];
  if (Array.isArray(obj?.steps)) return obj.steps as AuditEvent[];
  if (Array.isArray(obj?.events)) return obj.events as AuditEvent[];
  fail("Unrecognized file shape: expected an event array, or a bundle with trace.steps / steps / events", 2);
}

/** Keyless structural verification: linkage, continuity, monotonicity. */
function verifyStructure(events: AuditEvent[]): { valid: boolean; reason?: string; at?: number } {
  const sorted = [...events].sort((a, b) => (a.seq_no ?? 0) - (b.seq_no ?? 0));
  for (let i = 0; i < sorted.length; i++) {
    const e = sorted[i];
    if (typeof e.sdk_sig !== "string" || e.sdk_sig.length !== 64) {
      return { valid: false, reason: "missing or malformed sdk_sig", at: i };
    }
    if (i === 0) continue;
    const prev = sorted[i - 1];
    if (e.sdk_session_id !== prev.sdk_session_id) continue; // chains are per-session
    if ((e.seq_no ?? 0) !== (prev.seq_no ?? 0) + 1) {
      return { valid: false, reason: `seq_no gap: ${prev.seq_no} -> ${e.seq_no}`, at: i };
    }
    if (e.prev_sig != null && e.prev_sig !== prev.sdk_sig) {
      return { valid: false, reason: `prev_sig does not link to the prior event's sdk_sig at seq ${e.seq_no}`, at: i };
    }
    if ((e.timestamp_sdk ?? 0) < (prev.timestamp_sdk ?? 0)) {
      return { valid: false, reason: `timestamp regression at seq ${e.seq_no}`, at: i };
    }
  }
  return { valid: true };
}

const args = process.argv.slice(2);
const keyFlag = args.indexOf("--api-key");
const apiKey = keyFlag >= 0 ? args[keyFlag + 1] : undefined;
const file = args.find(
  (a, i) => !a.startsWith("--") && (keyFlag < 0 || i !== keyFlag + 1),
);

if (!file) {
  console.error("Usage: obsvr-verify <bundle.json> [--api-key <key>]");
  process.exit(2);
}

let parsed: unknown;
try {
  parsed = JSON.parse(readFileSync(file, "utf8"));
} catch (e) {
  fail(`Cannot read ${file}: ${e instanceof Error ? e.message : String(e)}`, 2);
}

const events = extractEvents(parsed);
console.log(`Loaded ${events.length} event(s) from ${file}`);

if (apiKey) {
  // Group per session: the HMAC chain is per sdk_session_id.
  const sessions = new Map<string, AuditEvent[]>();
  for (const e of events) {
    const sid = String(e.sdk_session_id ?? "unknown");
    sessions.set(sid, [...(sessions.get(sid) ?? []), e]);
  }
  let verified = 0;
  for (const [sid, sessionEvents] of sessions) {
    const result = verifyAuditChain(
      sessionEvents.sort((a, b) => (a.seq_no ?? 0) - (b.seq_no ?? 0)),
      apiKey,
    );
    if (!result.valid) {
      fail(`session ${sid}: ${result.reason} (event index ${result.brokenAt})`);
    }
    verified += result.eventsVerified;
  }
  console.log(
    `✓ CONTENT + CHAIN verification passed: ${verified} signature(s) recomputed and chain-linked across ${sessions.size} session(s).\n` +
      `  This attests prompt/response CONTENT integrity and event ORDER. The client\n` +
      `  signature does NOT cover the decision/attribution fields (verdict, rule,\n` +
      `  tenant) — those are sealed by the server countersignature at ingest.`,
  );
} else {
  const result = verifyStructure(events);
  if (!result.valid) fail(result.reason ?? "chain broken");
  console.log(
    `✓ STRUCTURAL verification passed: linkage, continuity, and monotonicity hold for ${events.length} event(s).\n` +
      `  Note: without --api-key, signatures were not recomputed - a holder of the\n` +
      `  signing key could still have re-signed altered content. Pass --api-key for\n` +
      `  full HMAC re-verification, and check the daily Merkle root (git anchor /\n` +
      `  RFC 3161 token) for the no-insert/no-delete guarantee across days.`,
  );
}
