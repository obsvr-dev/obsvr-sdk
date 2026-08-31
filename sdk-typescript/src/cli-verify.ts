#!/usr/bin/env node
/**
 * obsvr-verify: offline evidence verification for auditors.
 *
 *   npx obsvr-verify <bundle.json> [--api-key <key>] [--device-pubkey <key>]...
 *                    [--allow-gaps] [--json]
 *
 * Input: an exported obsvr evidence file — an incident evidence bundle
 * (obsvr-incident-evidence-v1, `trace.steps`), a trace evidence bundle, or a
 * plain JSON array of audit events. Two verification tiers:
 *
 *  - WITHOUT --api-key: structural chain verification. Events are grouped per
 *    sdk_session_id (a chain is per session) and each chain is checked for
 *    prev_sig linkage, seq_no continuity from 1, timestamp monotonicity and a
 *    constant chain_format, from the events alone; every event after the first
 *    must CARRY a prev_sig, or an unsigned insertion with a plausible seq_no
 *    and a well-formed sdk_sig would pass this tier by simply omitting the
 *    field. It reads NO content, decision or attribution field and recomputes
 *    no signature, so it detects reordering, and insertion into or deletion
 *    from the MIDDLE of a chain — and it does NOT detect an edit to any field
 *    (which needs no key at all), an event appended after the last, or the last
 *    one removed. Every claim about what an event SAYS comes from the
 *    --api-key tier.
 *  - WITH --device-pubkey (repeatable; base64/hex raw key or a PEM path): the
 *    optional non-repudiation tier. Every event must carry a device_sig by a
 *    pinned key that verifies over the same payload the HMAC covers. Works
 *    WITH --api-key (both seals checked) or ALONE.
 *  - WITH --api-key: HMAC re-verification (verifyAuditChain) — every signature
 *    is recomputed over the content + chain preimage, so any content tamper or
 *    reorder breaks. Format 3 and later cover decision fields; format 4 adds
 *    operation/source/event_type, and format 5 adds source_lineage_hash.
 *    Formats 1 and 2 bind content and order only. The client signature does
 *    NOT cover tenant_id, token counts, cost, or arbitrary metadata; those are
 *    sealed by the server countersignature at ingest.
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
 * A broken keyed run reports EVERY break the verifier found, one line per
 * break (verifyAuditChain re-anchors and keeps scanning), so an auditor
 * triaging a tampered export gets the full damage report from one run.
 * `--json` replaces the prose with one machine-readable document on stdout -
 * same verdicts, same exit codes, per-session break lists included. Usage and
 * file-read errors (exit 2) stay on stderr in either mode.
 *
 * Deliberately dependency-free and offline: an auditor must be able to
 * verify obsvr's evidence without trusting obsvr's servers or UI.
 */

import { readFileSync } from "node:fs";
import { verifyAuditChain, type ChainVerificationResult } from "./governance/verify-chain.js";
import { readAuditGapClaim } from "./proxy/audit-gap.js";
import { deriveDeviceKeyId, loadDevicePublicKey } from "./proxy/device-identity.js";
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

/**
 * What the keyless tier examines, and what it does not. Emitted verbatim in
 * --json as `checked` / `notChecked`, so a machine consumer of `valid: true`
 * can see the scope of the claim instead of inferring one. Kept identical to
 * the Python CLI's STRUCTURAL_CHECKED / STRUCTURAL_NOT_CHECKED.
 */
const STRUCTURAL_CHECKED = [
  "sdk_sig_present",
  "seq_no_continuity",
  "chain_starts_at_one",
  "prev_sig_linkage",
  "timestamp_monotonicity",
  "chain_format_consistency",
];
const STRUCTURAL_NOT_CHECKED = [
  "sdk_sig_recomputation",
  "prompt",
  "response",
  "action_taken",
  "action_reason",
  "reason_code",
  "rule_id",
  "policy_version",
  "model",
  "provider",
  "user_id",
  "append_after_last_event",
  "removal_of_last_event",
];

/**
 * Keyless structural verification: linkage, continuity, monotonicity.
 *
 * GROUPED PER SESSION, LIKE THE KEYED TIER. A chain is per `sdk_session_id`,
 * and this used to sort every event in the bundle by `seq_no` and then
 * `continue` past any adjacent pair whose sessions differed. On a bundle with
 * more than one session the global sort INTERLEAVES them — session A's seq 1,
 * session B's seq 1, A's seq 2, B's seq 2 — so every adjacent pair was
 * cross-session and not one linkage, continuity or monotonicity check ever ran.
 * Measured on two three-event sessions with every `prev_sig` wrong and every
 * timestamp regressing: the tier returned valid and the CLI printed
 * "✓ STRUCTURAL verification passed". Multi-session bundles are the normal
 * shape for a fleet, so the tier was closest to a no-op exactly where it was
 * most likely to be used. The keyed path has always grouped first.
 */
function verifyStructure(events: AuditEvent[]): { valid: boolean; reason?: string; at?: number } {
  const sessions = new Map<string, AuditEvent[]>();
  for (const e of events) {
    const sid = String(e.sdk_session_id ?? "unknown");
    const bucket = sessions.get(sid);
    if (bucket) bucket.push(e);
    else sessions.set(sid, [e]);
  }
  for (const [sid, sessionEvents] of sessions) {
    const result = verifySessionStructure(sessionEvents);
    if (!result.valid) {
      return sessions.size > 1
        ? { ...result, reason: `session ${sid}: ${result.reason}` }
        : result;
    }
  }
  return { valid: true };
}

/** The structural checks for ONE chain. */
function verifySessionStructure(events: AuditEvent[]): { valid: boolean; reason?: string; at?: number } {
  const sorted = [...events].sort((a, b) => (a.seq_no ?? 0) - (b.seq_no ?? 0));
  for (let i = 0; i < sorted.length; i++) {
    const e = sorted[i];
    if (typeof e.sdk_sig !== "string" || e.sdk_sig.length !== 64) {
      return { valid: false, reason: "missing or malformed sdk_sig", at: i };
    }
    if (i === 0) {
      // A chain starts at 1. Without this a bundle whose leading events were
      // deleted verifies clean, because every surviving pair still links: the
      // loss is only visible at the head. The keyed tier has always checked the
      // initial seq_no; this tier can check it too, from the events alone.
      const first = e.seq_no ?? 0;
      if (first !== 1) {
        return {
          valid: false,
          reason: `chain does not start at seq_no 1 (starts at ${first}): events before it are missing from this bundle`,
          at: i,
        };
      }
      continue;
    }
    const prev = sorted[i - 1];
    if ((e.seq_no ?? 0) !== (prev.seq_no ?? 0) + 1) {
      return { valid: false, reason: `seq_no gap: ${prev.seq_no} -> ${e.seq_no}`, at: i };
    }
    if (e.prev_sig == null) {
      // Linkage is required, not optional: an event that OMITS prev_sig is
      // not exempt from the check, or an unsigned insertion would pass this
      // tier by leaving the field out.
      return { valid: false, reason: `missing prev_sig at seq ${e.seq_no}: every event after the first must link to its predecessor`, at: i };
    }
    if (e.prev_sig !== prev.sdk_sig) {
      return { valid: false, reason: `prev_sig does not link to the prior event's sdk_sig at seq ${e.seq_no}`, at: i };
    }
    if ((e.timestamp_sdk ?? 0) < (prev.timestamp_sdk ?? 0)) {
      return { valid: false, reason: `timestamp regression at seq ${e.seq_no}`, at: i };
    }
    if (e.chain_format !== prev.chain_format) {
      // One chain is signed under one format. A format that changes mid-chain
      // is either a forgery or two chains spliced together, and the keyed tier
      // already refuses it.
      return {
        valid: false,
        reason: `chain_format changes mid-chain at seq ${e.seq_no}: ${prev.chain_format} -> ${e.chain_format}`,
        at: i,
      };
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

/**
 * The --json document, serialized identically in both languages: compact and
 * with non-ASCII left raw, which is what the Python CLI's serializer emits -
 * the parity harness compares the two byte for byte.
 */
function jsonLine(doc: Record<string, unknown>): string {
  return JSON.stringify(doc);
}

const args = process.argv.slice(2);
const keyFlag = args.indexOf("--api-key");
// An explicitly passed --api-key must carry a usable key. Absent, the CLI
// verifies structure only and says so; EMPTY, it used to do the same thing
// silently and exit 0 - and `--api-key "$SECRET"` with the secret unset is the
// ordinary CI shape that produces exactly that. A tampered chain then passed.
// Refusing here keeps the distinction the caller actually made: no flag means
// "structure only", and a flag whose value did not arrive means the run cannot
// do what was asked.
if (keyFlag >= 0 && (keyFlag + 1 >= args.length || args[keyFlag + 1] === "")) {
  console.error(
    "obsvr-verify: --api-key was passed with no key. Pass a key, or omit\n" +
      "  the flag entirely for structural verification. An empty value is\n" +
      "  refused rather than downgraded: in CI an unset secret expands to\n" +
      "  one, and the downgrade is silent.",
  );
  process.exit(2);
}
const apiKey = keyFlag >= 0 ? args[keyFlag + 1] : undefined;
const allowGaps = args.includes("--allow-gaps");
const asJson = args.includes("--json");
const valueIndices = new Set<number>();
if (keyFlag >= 0) valueIndices.add(keyFlag + 1);
const deviceKeyArgs: string[] = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--device-pubkey" && i + 1 < args.length) {
    deviceKeyArgs.push(args[i + 1]);
    valueIndices.add(i + 1);
  }
}
const file = args.find((a, i) => !a.startsWith("--") && !valueIndices.has(i));

if (!file) {
  console.error(
    "Usage: obsvr-verify <bundle.json> [--api-key <key>] [--device-pubkey <key>]... [--allow-gaps] [--json]",
  );
  process.exit(2);
}

const deviceKeys: Buffer[] = [];
const pinnedIds: string[] = [];
for (const value of deviceKeyArgs) {
  try {
    const raw = loadDevicePublicKey(value);
    deviceKeys.push(raw);
    pinnedIds.push(deriveDeviceKeyId(raw));
  } catch (e) {
    fail(`--device-pubkey: ${e instanceof Error ? e.message : String(e)}`, 2);
  }
}

let parsed: unknown;
try {
  parsed = JSON.parse(readFileSync(file, "utf8"));
} catch (e) {
  fail(`Cannot read ${file}: ${e instanceof Error ? e.message : String(e)}`, 2);
}

const events = extractEvents(parsed);
if (!asJson) {
  console.log(`Loaded ${events.length} event(s) from ${file}`);
}

/**
 * A per-session entry for the --json document. Key order matches the Python
 * result's serializer exactly - the two documents are compared byte for byte.
 */
function sessionDoc(sid: string, result: ChainVerificationResult): Record<string, unknown> {
  const doc: Record<string, unknown> = {
    sessionId: sid,
    valid: result.valid,
    eventsVerified: result.eventsVerified,
  };
  if (result.brokenAt !== undefined) doc.brokenAt = result.brokenAt;
  if (result.reason !== undefined) doc.reason = result.reason;
  doc.gapMarkers = result.gapMarkers;
  doc.eventsDeclaredLost = result.eventsDeclaredLost;
  doc.breaks = result.breaks;
  if (result.chainFormat !== undefined) doc.chainFormat = result.chainFormat;
  doc.deviceSignedEvents = result.deviceSignedEvents;
  doc.deviceChecked = result.deviceChecked;
  if (result.deviceUnverifiedReason !== undefined) {
    doc.deviceUnverifiedReason = result.deviceUnverifiedReason;
  }
  return doc;
}

if (apiKey || deviceKeys.length > 0) {
  // Group per session: the HMAC chain is per sdk_session_id.
  const sessions = new Map<string, AuditEvent[]>();
  for (const e of events) {
    const sid = String(e.sdk_session_id ?? "unknown");
    sessions.set(sid, [...(sessions.get(sid) ?? []), e]);
  }
  const reports: Array<[string, ChainVerificationResult]> = [];
  let anyInvalid = false;
  let verified = 0;
  let gapMarkers = 0;
  let eventsLost = 0;
  let deviceSigned = 0;
  for (const [sid, sessionEvents] of sessions) {
    const result = verifyAuditChain(
      sessionEvents.sort((a, b) => (a.seq_no ?? 0) - (b.seq_no ?? 0)),
      apiKey ?? null,
      deviceKeys.length > 0 ? deviceKeys : null,
    );
    reports.push([sid, result]);
    anyInvalid = anyInvalid || !result.valid;
    verified += result.eventsVerified;
    gapMarkers += result.gapMarkers;
    eventsLost += result.eventsDeclaredLost;
    deviceSigned += result.deviceSignedEvents;
  }
  const code = anyInvalid ? 1 : gapMarkers === 0 || allowGaps ? 0 : EXIT_INCOMPLETE;
  const mode = apiKey ? "content+chain" : "content+device";
  if (asJson) {
    console.log(
      jsonLine({
        mode,
        valid: !anyInvalid,
        sessions: reports.map(([sid, result]) => sessionDoc(sid, result)),
        eventsVerified: verified,
        gapMarkers,
        eventsDeclaredLost: eventsLost,
        deviceSignedEvents: deviceSigned,
        deviceChecked: deviceKeys.length > 0,
        allowGaps,
        exitCode: code,
      }),
    );
    process.exit(code);
  }
  if (anyInvalid) {
    // Every break in every session, one line each - the full damage report
    // from one run, not one index per run.
    for (const [sid, result] of reports) {
      for (const brk of result.breaks) {
        console.error(`✗ session ${sid}: ${brk.reason} (event index ${brk.index})`);
      }
    }
    process.exit(1);
  }
  if (apiKey) {
    console.log(
      `✓ CONTENT + CHAIN verification passed: ${verified} signature(s) recomputed and chain-linked across ${sessions.size} session(s).\n` +
        `  This attests prompt/response CONTENT integrity and event ORDER. Format 3\n` +
        `  and later bind action_taken, action_reason, reason_code, rule_id,\n` +
        `  policy_version, model, provider, and user_id. Format 4 adds operation, source, and\n` +
        `  event_type; format 5 adds source_lineage_hash. Formats 1 and 2 bind\n` +
        `  content and order only. The client signature does NOT cover tenant_id,\n` +
        `  token counts, cost, or arbitrary metadata; the server countersignature\n` +
        `  seals the complete accepted event at ingest.`,
    );
  } else {
    console.log(
      `✓ CONTENT + DEVICE verification passed: ${verified} device signature(s) recomputed and chain-linked across ${sessions.size} session(s).\n` +
        `  Each event's Ed25519 device seal was verified under the pinned public\n` +
        `  key(s) over the same payload the HMAC covers — content, order, and the\n` +
        `  fields supported by each event's chain format — so this run needed no\n` +
        `  API key and shared no secret. It does NOT check the HMAC chain: run with\n` +
        `  --api-key as well to attest both seals.`,
    );
  }
  if (deviceKeys.length > 0) {
    console.log(
      `✓ device signatures verified: ${verified} event(s) under pinned key(s) ${[...pinnedIds].sort().join(", ")}`,
    );
  } else if (deviceSigned > 0) {
    console.log(
      `note: ${deviceSigned} event(s) carry device signatures not verified in this run (no --device-pubkey supplied)`,
    );
  }
  process.exit(reportGaps(gapMarkers, eventsLost));
} else {
  const result = verifyStructure(events);
  // Keyless, the marker's count is read but not authenticated - same tier as
  // every other field at this level, and stated as such above.
  let gapMarkers = 0;
  let eventsLost = 0;
  if (result.valid) {
    for (const e of events) {
      // Must require the event to BE a marker, not merely to contain the
      // string: parsing every prompt let a user forge a loss declaration.
      const gap = readAuditGapClaim(e);
      if (gap) {
        gapMarkers++;
        eventsLost += gap.dropped;
      }
    }
  }
  if (asJson) {
    const code = !result.valid ? 1 : gapMarkers === 0 || allowGaps ? 0 : EXIT_INCOMPLETE;
    const doc: Record<string, unknown> = {
      mode: "structural",
      valid: result.valid,
      events: events.length,
    };
    if (result.reason !== undefined) doc.reason = result.reason;
    // What this verdict COVERS, in the machine-readable output, because a
    // script reads `valid` and cannot see the tier's footnote. A CI job gating
    // on `valid: true` from a keyless run is gating on ordering alone, and
    // nothing in the document used to say so.
    doc.checked = STRUCTURAL_CHECKED;
    doc.notChecked = STRUCTURAL_NOT_CHECKED;
    doc.gapMarkers = gapMarkers;
    doc.eventsDeclaredLost = eventsLost;
    doc.allowGaps = allowGaps;
    doc.exitCode = code;
    console.log(jsonLine(doc));
    process.exit(code);
  }
  if (!result.valid) fail(result.reason ?? "chain broken");
  console.log(
    `✓ STRUCTURAL verification passed: linkage, continuity, and monotonicity hold for ${events.length} event(s).\n` +
      `  This tier reads NO content, decision or attribution field, so it does not\n` +
      `  check them. An edit to action_taken, reason_code, rule_id, prompt, response,\n` +
      `  model, provider or user_id passes here, and needs no signing key: only the\n` +
      `  ordering fields are examined. It also cannot detect an event appended after\n` +
      `  the last one, or the last one removed.\n` +
      `  Pass --api-key for full HMAC re-verification - that is the only tier that\n` +
      `  says anything about what an event CONTAINS - and check the daily Merkle root\n` +
      `  (git anchor / RFC 3161 token) for the no-insert/no-delete guarantee across days.`,
  );
  const deviceSigned = events.filter(
    (e) => typeof (e as { device_sig?: unknown }).device_sig === "string",
  ).length;
  if (deviceSigned > 0) {
    console.log(
      `note: ${deviceSigned} event(s) carry device signatures not verified in this run (no --device-pubkey supplied)`,
    );
  }
  process.exit(reportGaps(gapMarkers, eventsLost));
}
