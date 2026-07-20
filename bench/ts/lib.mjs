/**
 * Shared benchmark library for the obsvr TS SDK.
 *
 * Responsibilities: tier/config recipes, in-process mock provider, fetch-level
 * capture stub, streaming HMAC-chain verifier, percentile stats, env/meta
 * collection, JSON writer, and a table printer.
 *
 * HONESTY CONTRACT:
 *  - Measures SDK overhead ONLY. The provider is an in-process canned object and
 *    the transport is stubbed at global.fetch; zero real network time is timed.
 *  - The REAL queue / batching / signing / drop-counting stay in the measured
 *    path (only the fetch send is stubbed).
 *  - The streaming verifier recomputes each event's HMAC on the fly and never
 *    retains events (a bounded reorder buffer aside); the cross-check re-runs the
 *    SDK's own exported verifyAuditChain over the first N events and the two
 *    verdicts must agree.
 */
import { createHmac, createHash } from "node:crypto";
import { execSync } from "node:child_process";
import os from "node:os";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { obsvr, verifyAuditChain } from "../../sdk/dist/index.js";
import {
  getSenderStats,
  getQueueSize,
  _resetSender,
} from "../../sdk/dist/proxy/sender/fire-and-forget.js";
import { _resetAllQuotas } from "../../sdk/dist/governance/quota.js";
import { _resetEscrow } from "../../sdk/dist/governance/escrow.js";
import { _resetInjectionSessions } from "../../sdk/dist/policy/injection-session.js";

export {
  obsvr,
  verifyAuditChain,
  getSenderStats,
  getQueueSize,
  _resetSender,
};

// Repo-relative so the harness runs from any clone (this file is bench/ts/lib.mjs).
const REPO_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SDK_DIR = join(REPO_DIR, "sdk");
const RESULTS_DIR = join(REPO_DIR, "bench", "results");

// ── Signing (replicated from sdk/src/governance/verify-chain.ts +
//    sdk/src/proxy/sender/fire-and-forget.ts; salt is constant across the SDK) ──
const SIGNING_SALT = "obsvr-sdk-signing-v1";

export function deriveSigningKey(apiKey) {
  return createHmac("sha256", SIGNING_SALT).update(apiKey).digest();
}

function contentHash(prompt, response) {
  return createHash("sha256")
    .update((prompt ?? "") + (response ?? ""))
    .digest("hex");
}

export function computeSig(signingKey, sessionId, seqNo, tsSdk, prompt, response, prevSig) {
  const hash = contentHash(prompt, response);
  const payload = [sessionId, String(seqNo), String(tsSdk), hash, prevSig ?? ""].join("|");
  return createHmac("sha256", signingKey).update(payload).digest("hex");
}

// ─────────────────────────────────────────────────────────────────────────────
// Streaming chain verifier
// Recompute each event's HMAC as it arrives at the transport, tracking per-session
// running (expectedSeq, prevSig). Events may batch; within a batch they are sorted
// by seq_no. A bounded reorder buffer tolerates (and records) any cross-batch
// out-of-order arrival rather than mis-reporting a gap. Events are NOT retained
// beyond the reorder window.
// ─────────────────────────────────────────────────────────────────────────────
export class StreamingChainVerifier {
  constructor(apiKey, { reorderCap = 512 } = {}) {
    this.signingKey = deriveSigningKey(apiKey);
    this.sessionId = null;
    this.expectedSeq = 1;
    this.prevSig = null;
    this.processed = 0;
    this.gaps = 0;
    this.dupes = 0;
    this.sigFailures = 0;
    this.chainBreaks = 0;
    this.sessionMismatches = 0;
    this.reorderObserved = false;
    this.maxReorderHeld = 0;
    this.reorderCap = reorderCap;
    this.reorderBuffer = new Map(); // seq_no -> event (bounded)
    this.lastSdkVersion = null;
  }

  /** Feed a raw POST body (single object or batch array). */
  ingestBody(url, body) {
    const u = String(url);
    let events;
    if (u.endsWith("/ingest/batch")) {
      events = Array.isArray(body) ? body.slice() : [body];
    } else if (u.endsWith("/ingest")) {
      events = [body];
    } else {
      return; // /policies or anything else: not an event POST
    }
    events.sort((a, b) => (a.seq_no ?? 0) - (b.seq_no ?? 0));
    for (const e of events) this.feed(e);
  }

  feed(event) {
    if (event == null || typeof event.seq_no !== "number") return;
    if (this.sessionId === null) this.sessionId = event.sdk_session_id ?? null;
    else if (event.sdk_session_id !== this.sessionId) this.sessionMismatches++;
    if (event.sdk_version) this.lastSdkVersion = event.sdk_version;

    const seq = event.seq_no;
    if (seq === this.expectedSeq) {
      this._process(event);
      this._drainBuffer();
    } else if (seq > this.expectedSeq) {
      if (this.reorderBuffer.has(seq)) {
        this.dupes++;
      } else {
        this.reorderBuffer.set(seq, event);
        this.reorderObserved = true;
        if (this.reorderBuffer.size > this.maxReorderHeld) this.maxReorderHeld = this.reorderBuffer.size;
      }
      if (this.reorderBuffer.size > this.reorderCap) this._forceAdvance();
    } else {
      this.dupes++; // seq below expected → already processed
    }
  }

  _process(event) {
    // signature
    const expectedSig = computeSig(
      this.signingKey,
      event.sdk_session_id,
      event.seq_no,
      event.timestamp_sdk ?? 0,
      event.prompt ?? "",
      event.response ?? "",
      event.prev_sig ?? null,
    );
    if (event.sdk_sig !== expectedSig) this.sigFailures++;
    // prev_sig linkage
    if (this.processed > 0) {
      if ((event.prev_sig ?? null) !== (this.prevSig ?? null)) this.chainBreaks++;
    }
    this.processed++;
    this.prevSig = event.sdk_sig ?? null;
    this.expectedSeq = event.seq_no + 1;
  }

  _drainBuffer() {
    while (this.reorderBuffer.has(this.expectedSeq)) {
      const e = this.reorderBuffer.get(this.expectedSeq);
      this.reorderBuffer.delete(this.expectedSeq);
      this._process(e);
    }
  }

  _forceAdvance() {
    // The expected seq never arrived within the window → real gap. Skip to the
    // lowest buffered seq and continue.
    this.gaps++;
    let lowest = Infinity;
    for (const k of this.reorderBuffer.keys()) if (k < lowest) lowest = k;
    if (lowest !== Infinity) {
      this.expectedSeq = lowest;
      this._drainBuffer();
    }
  }

  finalize() {
    // Anything still buffered means a lower seq never arrived → gap(s).
    if (this.reorderBuffer.size > 0) {
      this.gaps += this.reorderBuffer.size;
      this.reorderBuffer.clear();
    }
  }

  summary() {
    return {
      events: this.processed,
      gaps: this.gaps,
      dupes: this.dupes,
      sig_failures: this.sigFailures,
      chain_breaks: this.chainBreaks,
      session_mismatches: this.sessionMismatches,
      reorder_observed: this.reorderObserved,
      max_reorder_held: this.maxReorderHeld,
      valid:
        this.gaps === 0 &&
        this.dupes === 0 &&
        this.sigFailures === 0 &&
        this.chainBreaks === 0 &&
        this.sessionMismatches === 0,
    };
  }
}

// ── Cross-check collector: retain first N events, then compare the SDK's own
//    verifyAuditChain against a fresh streaming pass over the same N. ──
export class CrossCheckCollector {
  constructor(limit) {
    this.limit = limit;
    this.events = [];
    this.done = false;
  }
  ingestBody(url, body) {
    if (this.done) return;
    const u = String(url);
    let arr;
    if (u.endsWith("/ingest/batch")) arr = Array.isArray(body) ? body : [body];
    else if (u.endsWith("/ingest")) arr = [body];
    else return;
    for (const e of arr) {
      if (this.events.length >= this.limit) {
        this.done = true;
        break;
      }
      this.events.push(e);
    }
  }
  verify(apiKey) {
    const sorted = this.events.slice().sort((a, b) => (a.seq_no ?? 0) - (b.seq_no ?? 0));
    const official = verifyAuditChain(sorted, apiKey);
    const sv = new StreamingChainVerifier(apiKey);
    for (const e of sorted) sv.feed(e);
    sv.finalize();
    const s = sv.summary();
    const agrees = official.valid === s.valid && official.eventsVerified === s.events;
    return {
      n: sorted.length,
      official_valid: official.valid,
      official_events_verified: official.eventsVerified,
      official_reason: official.reason ?? null,
      streaming_valid: s.valid,
      streaming_events: s.events,
      agrees,
    };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mock provider (OpenAI chat shape) + fetch capture
// ─────────────────────────────────────────────────────────────────────────────
export function makeMockProvider() {
  return {
    chat: {
      completions: {
        create: async () => ({
          choices: [{ message: { content: "ok" } }],
          usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
          model: "gpt-4o-mock",
        }),
      },
    },
  };
}

/**
 * Install a global.fetch capture stub. Handles both /ingest (single object body)
 * and /ingest/batch (array body); the batch path calls response.json(). Feeds any
 * provided sinks (verifier, collector). `delayMs` (mutable via the returned handle)
 * models a slow transport without adding it to the measured hot path.
 */
export function installFetchCapture({ verifier, collector, delayMs = 0 } = {}) {
  const handle = {
    delayMs,
    singlePosts: 0,
    batchPosts: 0,
    otherRequests: 0,
    eventsPosted: 0,
    restore: null,
  };
  const prev = global.fetch;
  handle.restore = () => {
    global.fetch = prev;
  };
  global.fetch = async (url, opts) => {
    if (handle.delayMs > 0) {
      await new Promise((r) => setTimeout(r, handle.delayMs));
    }
    const u = String(url);
    let body;
    try {
      body = opts && typeof opts.body === "string" ? JSON.parse(opts.body) : undefined;
    } catch {
      body = undefined;
    }
    if (u.endsWith("/ingest/batch")) {
      handle.batchPosts++;
      const arr = Array.isArray(body) ? body : body ? [body] : [];
      handle.eventsPosted += arr.length;
      if (verifier) verifier.ingestBody(u, body);
      if (collector) collector.ingestBody(u, body);
    } else if (u.endsWith("/ingest")) {
      handle.singlePosts++;
      handle.eventsPosted += 1;
      if (verifier) verifier.ingestBody(u, body);
      if (collector) collector.ingestBody(u, body);
    } else {
      handle.otherRequests++;
    }
    return { ok: true, status: 200, json: async () => ({ count: 0 }) };
  };
  return handle;
}

// ─────────────────────────────────────────────────────────────────────────────
// Reset seams (never call mid-capture — seq restarts under the same session id)
// ─────────────────────────────────────────────────────────────────────────────
export function resetAll() {
  obsvr._reset();
  _resetSender();
  _resetAllQuotas();
  _resetInjectionSessions();
  _resetEscrow();
}

/** Flush + drain grace, then confirm the queue is empty (best effort). */
export async function drain(maxRounds = 60) {
  for (let i = 0; i < maxRounds; i++) {
    await obsvr.flush(5000);
    if (getQueueSize() === 0) return true;
    await new Promise((r) => setTimeout(r, 50));
  }
  return getQueueSize() === 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Policy-rule builders (all NON-matching so nothing blocks benign traffic)
// ─────────────────────────────────────────────────────────────────────────────
const NONMATCH = "zzz-nonmatching-sentinel-zzz";

export function keywordRule(i = 0) {
  return {
    id: `kw-${i}`,
    name: `keyword ${i}`,
    enabled: true,
    action: "block",
    type: "keyword",
    conditions: { keywords: [`${NONMATCH}-kw-${i}`] },
  };
}
export function regexRule(i = 0) {
  return {
    id: `rx-${i}`,
    name: `regex ${i}`,
    enabled: true,
    action: "block",
    type: "regex",
    conditions: { pattern: `${NONMATCH}-rx-${i}-[0-9]{9}` },
  };
}
export function topicDenyRule(i = 0) {
  return {
    id: `td-${i}`,
    name: `topic_deny ${i}`,
    enabled: true,
    action: "block",
    type: "topic_deny",
    conditions: { topics: [`${NONMATCH}-topic-${i}`] },
  };
}
export function modelGateRule(i = 0) {
  // allowed_models includes the mock's model → never blocks.
  return {
    id: `mg-${i}`,
    name: `model_gate ${i}`,
    enabled: true,
    action: "block",
    type: "model_gate",
    conditions: { allowed_models: ["gpt-4o", "gpt-4", "gpt-3.5"] },
  };
}
export function quotaRule(i = 0) {
  // Requests-unit quota scoped by user_id, limit far above anything we generate.
  return {
    id: `q-${i}`,
    name: `quota ${i}`,
    enabled: true,
    action: "block",
    type: "quota",
    conditions: {
      quota_scope: "user_id",
      quota_unit: "requests",
      quota_limit: 10_000_000,
      quota_window_ms: 60_000,
    },
  };
}
export function shadowRule(i = 0) {
  return {
    id: `sh-${i}`,
    name: `shadow ${i}`,
    enabled: true,
    mode: "shadow",
    action: "block",
    type: "keyword",
    conditions: { keywords: [`${NONMATCH}-shadow-${i}`] },
  };
}

const noopHook = async () => ({ decision: "allow" });

const BASE = { api_key: "bench-key", ingest_url: "http://127.0.0.1:9", policy_refresh_interval_ms: 0, sample_rate: 1 };

// Part A ladder. `null` config => ungoverned (call the raw mock).
export function partAConfig(tier) {
  switch (tier) {
    case "U":
      return null;
    case "A0":
      return { ...BASE };
    case "A1":
      return { ...BASE, policy_rules: [keywordRule(1), regexRule(1), topicDenyRule(1), modelGateRule(1), keywordRule(2)] };
    case "A2":
      return { ...BASE, pii_policy: {}, policy_rules: [keywordRule(1), regexRule(1), topicDenyRule(1), modelGateRule(1), keywordRule(2)] };
    case "A3":
      return { ...BASE, pii_policy: {}, policy_rules: [keywordRule(1), regexRule(1), topicDenyRule(1), modelGateRule(1), keywordRule(2), quotaRule(1)] };
    case "A4":
      return {
        ...BASE,
        pii_policy: {},
        policy_rules: [keywordRule(1), regexRule(1), topicDenyRule(1), modelGateRule(1), keywordRule(2), quotaRule(1), shadowRule(1)],
        on_pre_call: noopHook,
        hook_trigger: "always",
        multi_turn_injection: { enabled: true },
      };
    default:
      throw new Error(`unknown Part A tier: ${tier}`);
  }
}

export const PART_A_TIERS = ["U", "A0", "A1", "A2", "A3", "A4"];

// Part B tiers.
export function partBConfig(tier) {
  switch (tier) {
    case "L0":
      return { ...BASE };
    case "L1":
      return { ...BASE, policy_rules: [keywordRule(1), regexRule(1), topicDenyRule(1)] };
    case "L2":
      return {
        ...BASE,
        pii_policy: {},
        policy_rules: [
          keywordRule(1), regexRule(1), topicDenyRule(1), modelGateRule(1), keywordRule(2), regexRule(2),
          quotaRule(1),
        ],
      };
    case "L3":
      return {
        ...BASE,
        pii_policy: {},
        fail_mode: "closed",
        policy_rules: [
          keywordRule(1), regexRule(1), topicDenyRule(1), modelGateRule(1), keywordRule(2), regexRule(2),
          keywordRule(3), regexRule(3), topicDenyRule(2), keywordRule(4), regexRule(4), topicDenyRule(3),
          quotaRule(1), shadowRule(1), shadowRule(2),
        ],
        on_pre_call: noopHook,
        hook_trigger: "always",
        multi_turn_injection: { enabled: true },
      };
    default:
      throw new Error(`unknown Part B tier: ${tier}`);
  }
}

export const PART_B_TIERS = ["L0", "L1", "L2", "L3"];

// ─────────────────────────────────────────────────────────────────────────────
// Deterministic benign payloads (seeded; no PII patterns, no rule keywords)
// ─────────────────────────────────────────────────────────────────────────────
const WORDS = [
  "the", "quick", "brown", "system", "reviews", "quarterly", "metrics", "for",
  "planning", "weather", "in", "boston", "remains", "mild", "today", "please",
  "summarize", "these", "notes", "about", "logistics", "and", "scheduling",
  "meetings", "next", "week", "with", "the", "operations", "team", "regarding",
  "inventory", "levels", "across", "regional", "warehouses", "this", "month",
];

function lcg(seed) {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 4294967296;
  };
}

/** Benign text of ~targetChars characters, deterministic in `seed`. */
export function seededText(targetChars, seed) {
  const rnd = lcg(seed + 7);
  let out = "";
  while (out.length < targetChars) {
    out += WORDS[Math.floor(rnd() * WORDS.length)] + " ";
  }
  return out.slice(0, targetChars);
}

/** Pre-generate N distinct benign prompts of ~300-500 chars. */
export function makePromptPool(n = 1000) {
  const pool = new Array(n);
  for (let i = 0; i < n; i++) {
    const len = 300 + Math.floor(lcg(i * 31 + 1)() * 200); // 300-500
    pool[i] = seededText(len, i * 101 + 3) + `#${i}`;
  }
  return pool;
}

export function makeUserIds(n = 100) {
  const ids = new Array(n);
  for (let i = 0; i < n; i++) ids[i] = `bench-user-${i}`;
  return ids;
}

// ─────────────────────────────────────────────────────────────────────────────
// Stats
// ─────────────────────────────────────────────────────────────────────────────
export function percentiles(samples) {
  // samples: Float64Array (any unit). Returns {p50,p95,p99,mean,max,n}.
  const n = samples.length;
  if (n === 0) return { p50: 0, p95: 0, p99: 0, mean: 0, max: 0, n: 0 };
  const sorted = Float64Array.from(samples);
  sorted.sort();
  let sum = 0;
  for (let i = 0; i < n; i++) sum += sorted[i];
  const at = (p) => sorted[Math.min(n - 1, Math.floor((p / 100) * n))];
  return {
    p50: at(50),
    p95: at(95),
    p99: at(99),
    mean: sum / n,
    max: sorted[n - 1],
    n,
  };
}

export function round(x, d = 3) {
  const f = Math.pow(10, d);
  return Math.round(x * f) / f;
}

// ─────────────────────────────────────────────────────────────────────────────
// Env / meta
// ─────────────────────────────────────────────────────────────────────────────
function safeExec(cmd) {
  try {
    return execSync(cmd, { stdio: ["ignore", "pipe", "ignore"] }).toString().trim();
  } catch {
    return null;
  }
}

export function collectMeta(part, args, stampedVersion) {
  let manifest = "unknown";
  try {
    manifest = JSON.parse(fs.readFileSync(`${SDK_DIR}/package.json`, "utf8")).version;
  } catch { /* ignore */ }
  const cpus = os.cpus();
  const macos = safeExec("sw_vers -productVersion");
  return {
    lang: "ts",
    part,
    sdk_version_manifest: manifest,
    sdk_version_stamped: stampedVersion ?? "node/2.0.0",
    node: process.version,
    os: macos ? `macOS ${macos}` : `${os.type()} ${os.release()}`,
    cpu: cpus[0] ? cpus[0].model : "unknown",
    cores: cpus.length,
    ram_gb: Math.round(os.totalmem() / 1024 / 1024 / 1024),
    date_utc: new Date().toISOString(),
    git_rev: safeExec(`git -C ${REPO_DIR} rev-parse --short HEAD`),
    args,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Output
// ─────────────────────────────────────────────────────────────────────────────
export function writeJson(outPath, obj) {
  fs.mkdirSync(outPath.replace(/\/[^/]+$/, ""), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(obj, null, 2));
}

export function printTable(headers, rows) {
  const widths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => String(r[i] ?? "").length)),
  );
  const line = (cells) => cells.map((c, i) => String(c ?? "").padStart(widths[i])).join("  ");
  console.log(line(headers));
  console.log(widths.map((w) => "-".repeat(w)).join("  "));
  for (const r of rows) console.log(line(r));
}

// ─────────────────────────────────────────────────────────────────────────────
// Arg parsing:  --iters N  --calls N  --tier L0  --out FILE  --quick  --payload N[,N]
// ─────────────────────────────────────────────────────────────────────────────
export function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      if (eq !== -1) {
        out[a.slice(2, eq)] = a.slice(eq + 1);
      } else if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) {
        out[a.slice(2)] = argv[++i];
      } else {
        out[a.slice(2)] = true;
      }
    } else {
      out._.push(a);
    }
  }
  return out;
}

export { REPO_DIR, SDK_DIR, RESULTS_DIR };
