/**
 * Canary-leak detection (honeytoken tripwire).
 *
 * The app MINTS a canary token and PLANTS it where only the model should ever
 * see it — a system prompt, a retrieved document, a tool description, a
 * secret-looking config value. If that exact token later appears on a surface
 * it must never reach — the model's OUTPUT, a tool-call ARGUMENT (exfil
 * attempt), a tool RESULT, or echoed back in USER input — the planted context
 * has leaked. That is a CRITICAL, unsuppressible signal.
 *
 * Hygiene (the design goal naive honeytokens miss): the raw token
 * is returned to the app exactly once, at mint. The registry stores only
 * SHA-256(token). Detection is candidate-extraction + hash-compare: a prefix
 * regex finds candidate tokens in text, each candidate is hashed, and the
 * hash is looked up in the active-canary set. So the raw secret never lives
 * at rest, never rides an event, and never appears in a log — events carry
 * only a public token-id and a short hash prefix. A serialization test pins
 * that no minted token ever appears in an emitted event.
 *
 * Detection runs over the de-obfuscation VIEWS (base64/hex/percent-decoded,
 * invisible-stripped) as well as the raw text, so a token exfiltrated
 * base64-encoded or split by zero-width characters is still caught.
 *
 * Honest boundary (SECURITY.md): a canary is a tripwire, not prevention. On
 * the response surface the tokens have already been produced; the SDK records
 * the leak and (where the surface is pre-delivery, e.g. a tool call or tool
 * result) blocks it, but it cannot un-send what a streamed response already
 * emitted. Do NOT plant canaries on a scanned surface (user input, model
 * output, tool args/results) — that is a self-inflicted true positive.
 */

import { randomBytes } from "node:crypto";
import { sha256Hex } from "./decision-record.js";
import { deobfuscate } from "./deobfuscate.js";

/** Distinctive, regex-findable prefix. Lowercase; the body is lowercase hex. */
export const CANARY_PREFIX = "obsvr-cnry-";
/** 16 random bytes → 32 lowercase hex chars = 128 bits of entropy. */
const CANARY_BODY_BYTES = 16;
const CANARY_BODY_LEN = CANARY_BODY_BYTES * 2;

/**
 * Candidate matcher: the prefix followed by exactly 32 hex chars. Case is
 * tolerated on the hex (a surface may upper-case it); the canonical form is
 * lower-cased before hashing. Global + case-insensitive.
 */
const CANARY_CANDIDATE_RE = new RegExp(`${CANARY_PREFIX}[0-9a-f]{${CANARY_BODY_LEN}}`, "gi");

/** A minted canary as handed back to the app (the ONLY time the raw token exists to the caller). */
export interface MintedCanary {
  /** The raw token to plant. Never stored by the SDK; never appears on events. */
  token: string;
  /** Public correlation id (safe to log / put on events). */
  id: string;
  /** First 12 hex of SHA-256(token) — the public evidence stamp on a leak event. */
  hashPrefix: string;
  /**
   * Whether the token was actually registered as an ACTIVE tripwire. False
   * only when the registry is at its cap (see `canaryRegistrySaturated`): the
   * token is returned but will NEVER be detected — a loud warning is logged so
   * a dead canary is never silently trusted. Check this in long-lived /
   * multi-tenant processes that may mint many canaries.
   */
  registered: boolean;
}

/** What the registry keeps per active canary — never the raw token. */
interface CanaryRecord {
  id: string;
  hashPrefix: string;
  /** Optional operator label for where it was planted (free text, non-secret). */
  label?: string;
}

const MAX_CANARIES = 10_000;

// Process-global registry: token planted anywhere leaks anywhere, so the scope
// is the process, not a per-client store (unlike tool pins). Keyed by the FULL
// sha256 of the canonical token; value never contains the token.
const registry = new Map<string, CanaryRecord>();
let idCounter = 0;
let saturated = false;

/** @internal test hook — clears the canary registry. */
export function _resetCanaries(): void {
  registry.clear();
  idCounter = 0;
  saturated = false;
}

/** Number of active canaries (the pipeline scan is skipped when this is 0). */
export function canaryRegistrySize(): number {
  return registry.size;
}

/** True once a mint was refused because the registry was full. */
export function canaryRegistrySaturated(): boolean {
  return saturated;
}

function canonicalToken(raw: string): string {
  return raw.toLowerCase();
}

/**
 * Whole-text placeholder for a stored copy on a canary hit. The surface text
 * contains the raw token (and possibly an encoded form of it), so the stored
 * prompt/response is replaced wholesale rather than trying to splice out every
 * encoding — the audit trail must never carry the secret it is hunting for.
 */
export const CANARY_REDACTION_PLACEHOLDER = "[REDACTED:canary_leak]";

/**
 * Build the non-secret evidence bundle for a leak event (ids + hash prefixes +
 * the views that surfaced it + the surface label). Rides
 * `metadata.obsvr_telemetry.canary_leak` — a reserved channel that survives
 * metadata trimming, so a CRITICAL leak signal is never silently dropped.
 * Never contains the raw token.
 */
export function canaryLeakTelemetry(
  hits: CanaryHit[],
  surface: string,
): Record<string, unknown> {
  return {
    canary_leak: {
      surface,
      ids: hits.map((h) => h.id),
      hash_prefixes: hits.map((h) => h.hashPrefix),
      via: [...new Set(hits.map((h) => h.via))],
      // Surface registry saturation on the leak event: when true, some minted
      // canaries were never registered (dead tripwires) — the operator needs
      // to know coverage is incomplete.
      ...(saturated ? { registry_saturated: true } : {}),
    },
  };
}

/**
 * Mint a canary: generate a fresh token, register only its hash, and return
 * the raw token to the caller exactly once. `label` is an optional non-secret
 * note about where you plan to plant it (rides leak events for triage).
 */
export function mintCanary(opts?: { label?: string }): MintedCanary {
  const body = randomBytes(CANARY_BODY_BYTES).toString("hex");
  const token = CANARY_PREFIX + body;
  const hash = sha256Hex(token);
  const hashPrefix = hash.slice(0, 12);
  const id = `cnry_${(idCounter++).toString(36)}_${hashPrefix.slice(0, 6)}`;
  let registered = true;
  if (registry.size >= MAX_CANARIES && !registry.has(hash)) {
    // Refuse rather than evict — evicting a planted canary silently disables
    // its tripwire. But the NEW token is then a dead tripwire, so warn loudly
    // (a security control that silently fails is worse than a noisy one).
    saturated = true;
    registered = false;
    // eslint-disable-next-line no-console
    console.warn(
      `[obsvr] canary registry is full (${MAX_CANARIES}); minted canary ${id} is NOT active and will never be detected. ` +
        `Reduce the number of live canaries or start a fresh process.`,
    );
  } else {
    registry.set(hash, { id, hashPrefix, ...(opts?.label !== undefined ? { label: opts.label } : {}) });
  }
  return { token, id, hashPrefix, registered };
}

export type CanaryVia = "raw" | "deobfuscated" | "percent" | "hex" | "base64";

/** A candidate canary token found in text, reduced to its hash (no raw token). */
export interface CanaryCandidate {
  /** Full SHA-256 of the canonical (lower-cased) candidate token. */
  hash: string;
  /** Which surface it was found on: "raw" or a de-obfuscation method. */
  via: CanaryVia;
}

/**
 * Registry-INDEPENDENT candidate extraction (pinned in canary.json). Finds
 * every `obsvr-cnry-<32hex>` in the raw text and in each de-obfuscation view,
 * reduces each to the SHA-256 of its canonical (lower-cased) form, and
 * de-dupes by hash keeping the FIRST via (raw before views). This is the raw
 * material of detection — scanForCanary just filters it by registry
 * membership. The token itself is never returned.
 */
export function canaryCandidates(text: string): CanaryCandidate[] {
  if (!text) return [];
  const seen = new Set<string>();
  const out: CanaryCandidate[] = [];
  const scanSurface = (surface: string, via: CanaryVia): void => {
    CANARY_CANDIDATE_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = CANARY_CANDIDATE_RE.exec(surface)) !== null) {
      const hash = sha256Hex(canonicalToken(m[0]));
      if (seen.has(hash)) continue;
      seen.add(hash);
      out.push({ hash, via });
    }
  };
  scanSurface(text, "raw");
  for (const v of deobfuscate(text)) {
    scanSurface(v.text, v.method);
  }
  return out;
}

/** A confirmed leak — carries only non-secret identifiers. */
export interface CanaryHit {
  id: string;
  hashPrefix: string;
  label?: string;
  via: CanaryVia;
}

export interface CanaryScanResult {
  leaked: boolean;
  hits: CanaryHit[];
}

const EMPTY_RESULT: CanaryScanResult = { leaked: false, hits: [] };

/**
 * Scan `text` (and its de-obfuscation views) for any active canary. Returns
 * only non-secret identifiers — never the matched token. A no-op (returns the
 * shared empty result) when no canaries are registered, so the pipeline pays
 * nothing until a canary is actually minted.
 */
export function scanForCanary(text: string): CanaryScanResult {
  if (registry.size === 0 || !text) return EMPTY_RESULT;
  const hits: CanaryHit[] = [];
  for (const cand of canaryCandidates(text)) {
    const rec = registry.get(cand.hash);
    if (rec) {
      hits.push({ id: rec.id, hashPrefix: rec.hashPrefix, ...(rec.label !== undefined ? { label: rec.label } : {}), via: cand.via });
    }
  }
  return hits.length > 0 ? { leaked: true, hits } : EMPTY_RESULT;
}
