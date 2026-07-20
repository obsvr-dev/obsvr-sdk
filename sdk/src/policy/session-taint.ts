/**
 * Session taint latch.
 *
 * When a prompt-injection or a canary leak is detected in a session, the
 * session is marked TAINTED. Subsequent EGRESS in that session — a tool call,
 * tool-call arguments, an MCP call, a framework tool execution — is then
 * escalated (flagged, or blocked in strict mode), because a session that has
 * been compromised once should not be trusted to keep acting: the per-call
 * scanners can miss a cleverly staged exfiltration, but the latch remembers
 * that the session is suspect.
 *
 * This is a session-level LATCH, not data-flow label propagation: it does not
 * tag individual values and follow them: it records that a session id is
 * compromised and escalates that session's later egress. Simpler taint
 * latches seed only on injection and only block remote URLs, unbounded and
 * forever; obsvr seeds on injection AND canary, escalates every egress the
 * SDK sees, bounds the store, and defaults to FLAG (not a blanket block) so
 * one detection never bricks a session.
 *
 * Honest boundary (SECURITY.md): the latch is keyed on the caller-supplied
 * session identity (`metadata.user_id ?? session_id ?? tenant_id`); with no
 * session id every call shares the "global" bucket, so taint is only
 * meaningful when the app threads a real session id. In-process only (resets
 * on restart) — an in-process library persisting trust state to disk is a new
 * attack surface, so this stays in memory like the canary/pin stores.
 */

/** Taint sub-config of the top-level config (all fields optional, off by default). */
export interface SessionTaintConfig {
  enabled?: boolean;
  /** flag (default): annotate a tainted session's egress; block: refuse it. */
  action?: "block" | "flag";
}

interface TaintRecord {
  /** The signal that first tainted the session (kept; the latch is monotonic). */
  reason: string;
  updatedAt: number;
}

const MAX_TAINTED_SESSIONS = 10_000;

// Process-global: a session is identified by a caller-supplied key that is the
// same across the wrapper, the integrations, and MCP, so taint set at
// detection is visible at egress anywhere in the process.
const tainted = new Map<string, TaintRecord>();

/** @internal test hook — clears the taint store. */
export function _resetSessionTaint(): void {
  tainted.clear();
}

/** Number of tainted sessions (the enforce/set sites skip work when 0). */
export function sessionTaintSize(): number {
  return tainted.size;
}

/**
 * An identity value counts only if it is a NON-EMPTY string or a finite
 * number — so an empty string / null / boolean / object falls through to the
 * next channel. This is byte-identical to the Python `_pick_identity` (a
 * naive `a ?? b` vs `a or b` split silently diverges on falsy-but-present
 * values like "" and collapses every empty-id session into one bucket).
 */
function pickIdentity(v: unknown): string | undefined {
  if (typeof v === "string") return v === "" ? undefined : v;
  if (typeof v === "number" && Number.isFinite(v)) return String(v);
  return undefined;
}

/**
 * Derive the session key the taint latch uses: the first present, non-empty
 * identity among user_id / session_id / tenant_id, else "global". SET (at
 * detection) and ENFORCE (at egress) MUST call this on the same identity
 * metadata or the latch silently no-ops, so every egress path folds the same
 * resolved identity in before calling this.
 */
export function deriveSessionKey(metadata: Record<string, unknown> | undefined): string {
  const m = metadata ?? {};
  return pickIdentity(m.user_id) ?? pickIdentity(m.session_id) ?? pickIdentity(m.tenant_id) ?? "global";
}

/**
 * Mark a session tainted. Monotonic: the FIRST reason is kept (the original
 * compromise), only the timestamp refreshes. Bounded: refuses past the cap
 * (evicting the oldest first) so the store never grows without limit. `now`
 * is injected for determinism.
 */
export function markTainted(sessionKey: string, reason: string, now: number): void {
  const existing = tainted.get(sessionKey);
  if (existing) {
    existing.updatedAt = now;
    return;
  }
  if (tainted.size >= MAX_TAINTED_SESSIONS) {
    // Evict the oldest to make room — unlike canary/pins (where eviction
    // silently disables protection), a taint latch is advisory-leaning and an
    // ancient session is the least valuable to keep; the newest compromise
    // matters most.
    let oldestKey: string | undefined;
    let oldestAt = Infinity;
    for (const [k, v] of tainted) {
      if (v.updatedAt < oldestAt) { oldestAt = v.updatedAt; oldestKey = k; }
    }
    if (oldestKey !== undefined) tainted.delete(oldestKey);
  }
  tainted.set(sessionKey, { reason, updatedAt: now });
}

/** The taint reason for a session, or undefined if not tainted. */
export function taintReason(sessionKey: string): string | undefined {
  return tainted.get(sessionKey)?.reason;
}

/**
 * Refresh a tainted session's recency (no-op if untainted). Called at ENFORCE
 * so an actively-enforced compromised session stays "recently used" and is not
 * evicted by an attacker flooding the store with fresh sessions to age out a
 * long-lived victim (the eviction is oldest-updatedAt).
 */
export function touchTaint(sessionKey: string, now: number): void {
  const rec = tainted.get(sessionKey);
  if (rec) rec.updatedAt = now;
}

export type TaintEnforcement = "none" | "flag" | "block";

export interface TaintVerdict {
  enforcement: TaintEnforcement;
  /** The originating compromise signal (absent when not tainted). */
  reason?: string;
}

/**
 * Pure enforcement decision for a session at an egress point (fixture-pinned
 * in taint.json). A tainted session escalates per mode; an untainted one is a
 * no-op. Does NOT mutate the store.
 */
export function evaluateSessionTaint(
  sessionKey: string,
  config: { enabled?: boolean; action?: "block" | "flag" } | undefined,
): TaintVerdict {
  if (!config?.enabled) return { enforcement: "none" };
  const reason = taintReason(sessionKey);
  if (reason === undefined) return { enforcement: "none" };
  return { enforcement: config.action === "block" ? "block" : "flag", reason };
}

/** Resolve the taint sub-config (absent/disabled => undefined). */
export function resolveSessionTaint(
  config: { sessionTaint?: SessionTaintConfig } | undefined,
): Required<Pick<SessionTaintConfig, "enabled" | "action">> | undefined {
  const t = config?.sessionTaint;
  if (!t?.enabled) return undefined;
  return { enabled: true, action: t.action === "block" ? "block" : "flag" };
}
