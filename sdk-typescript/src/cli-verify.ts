#!/usr/bin/env node
/**
 * obsvr-verify: offline evidence verification for auditors.
 *
 *   npx obsvr-verify <bundle.json> [--api-key <key>] [--allow-gaps]
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
 *    reorder breaks. Under chain format 3, the current signing format, the
 *    preimage also covers the decision/attribution fields (action_taken,
 *    action_reason, reason_code, rule_id, policy_version, model, provider,
 *    user_id); chains signed under formats 1 and 2 bind content and order only.
 *    The client signature does NOT cover tenant_id, token counts, metadata,
 *    operation, or content_provenance; those are sealed by the server
 *    countersignature at ingest, not by this offline check.
 *
 * Either tier also reports GAP MARKERS: events the SDK signed to record that
 * its bounded queue dropped events it never got to chain. A chain carrying
 * markers is still valid - the marker is the SDK telling the truth about a
 * loss - but it is not complete, and the two must not be reported as the same
 * thing. That distinction has to survive into the exit code: `obsvr-verify
 * chain.json && deploy` reads only the status, and a record missing most of
 * its events must not pass a gate that means "all clear".
 *
 * Exit codes:
 *   0  verified at the requested tier, and the chain declares no loss
 *   1  broken - a signature, link, or continuity check failed
 *   2  usage error
 *   3  VALID BUT INCOMPLETE - every check passed and the chain itself declares
 *      events it dropped. Distinct from 1 because nothing is wrong with the
 *      evidence; distinct from 0 because it is not all of it.
 *
 * `--allow-gaps` maps 3 back to 0. It exists so that strict CAN be the
 * default: a team whose posture already accepts bounded-queue loss would
 * otherwise pin an old version or stop checking the exit code at all, and an
 * explicit, greppable flag in their CI config is a better record of that
 * decision than either. It suppresses only the STATUS - the declared loss is
 * still printed, so the disclosure survives the opt-out.
 *
 * Deliberately dependency-free and offline: an auditor must be able to
 * verify obsvr's evidence without trusting obsvr's servers or UI.
 */

import { readFileSync } from "node:fs";
import { verifyAuditChain } from "./governance/verify-chain.js";
import { readAuditGapClaim } from "./proxy/audit-gap.js";
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

/** Valid, and short by however many events its markers declare. */
const EXIT_INCOMPLETE = 3;

/**
 * Print the chain's own declaration of what is missing, and return the exit
 * status it earns. Kept identical, word for word, to the Python CLI's -
 * scripts/check-cli-verify-parity.mjs compares stdout byte for byte, and an
 * auditor comparing two runs should not have to wonder whether different
 * wording means a different finding.
 */
function reportGaps(markers: number, lost: number): number {
  if (markers === 0) return 0;
  console.log(
    `! ${lost} event(s) declared LOST by ${markers} gap marker(s) in this chain.\n` +
      `  The chain is intact and these markers are signed: the SDK recorded that its\n` +
      `  bounded queue dropped these events before they could be chained. What is here\n` +
      `  is genuine and in order - it is not all of it.\n` +
      (allowGaps
        ? `  Exiting 0: --allow-gaps accepts declared loss as a pass.`
        : `  Exiting ${EXIT_INCOMPLETE} (valid but incomplete). --allow-gaps accepts it as a pass.`),
  );
  return allowGaps ? 0 : EXIT_INCOMPLETE;
}

const args = process.argv.slice(2);
const keyFlag = args.indexOf("--api-key");
const apiKey = keyFlag >= 0 ? args[keyFlag + 1] : undefined;
const allowGaps = args.includes("--allow-gaps");
const file = args.find(
  (a, i) => !a.startsWith("--") && (keyFlag < 0 || i !== keyFlag + 1),
);

if (!file) {
  console.error("Usage: obsvr-verify <bundle.json> [--api-key <key>] [--allow-gaps]");
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
  let gapMarkers = 0;
  let eventsLost = 0;
  for (const [sid, sessionEvents] of sessions) {
    const result = verifyAuditChain(
      sessionEvents.sort((a, b) => (a.seq_no ?? 0) - (b.seq_no ?? 0)),
      apiKey,
    );
    if (!result.valid) {
      fail(`session ${sid}: ${result.reason} (event index ${result.brokenAt})`);
    }
    verified += result.eventsVerified;
    gapMarkers += result.gapMarkers;
    eventsLost += result.eventsDeclaredLost;
  }
  console.log(
    `✓ CONTENT + CHAIN verification passed: ${verified} signature(s) recomputed and chain-linked across ${sessions.size} session(s).\n` +
      `  This attests prompt/response CONTENT integrity, event ORDER, and — under\n` +
      `  chain format 3, the current signing format — the decision/attribution\n` +
      `  fields: action_taken, action_reason, reason_code, rule_id, policy_version,\n` +
      `  model, provider, user_id. Chains signed under formats 1 and 2 bind content\n` +
      `  and order only. The client signature does NOT cover tenant_id, token\n` +
      `  counts, metadata, operation, or content_provenance — those are sealed by\n` +
      `  the server countersignature at ingest.`,
  );
  process.exit(reportGaps(gapMarkers, eventsLost));
} else {
  const result = verifyStructure(events);
  if (!result.valid) fail(result.reason ?? "chain broken");
  // Keyless, the marker's count is read but not authenticated - same tier as
  // every other field at this level, and stated as such above.
  let gapMarkers = 0;
  let eventsLost = 0;
  for (const e of events) {
    // Must require the event to BE a marker, not merely to contain the
    // string: parsing every prompt let a user forge a loss declaration.
    const gap = readAuditGapClaim(e);
    if (gap) {
      gapMarkers++;
      eventsLost += gap.dropped;
    }
  }
  console.log(
    `✓ STRUCTURAL verification passed: linkage, continuity, and monotonicity hold for ${events.length} event(s).\n` +
      `  Note: without --api-key, signatures were not recomputed - a holder of the\n` +
      `  signing key could still have re-signed altered content. Pass --api-key for\n` +
      `  full HMAC re-verification, and check the daily Merkle root (git anchor /\n` +
      `  RFC 3161 token) for the no-insert/no-delete guarantee across days.`,
  );
  process.exit(reportGaps(gapMarkers, eventsLost));
}
