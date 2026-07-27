/**
 * In-memory quota tracker for rate-limit governance.
 * Uses fixed windows with auto-cleanup of expired entries.
 *
 * SCALING LIMITATION (disclosed honestly — a compliance product should surface
 * this before an auditor finds it): counters live in THIS process's memory, so
 * a quota rule is enforced PER SDK INSTANCE by default, not across a fleet. A
 * customer running N horizontally-scaled instances gets up to N x the
 * configured limit in aggregate (each instance meters its own share). Likewise,
 * token budgets (quota_unit: "tokens") are recorded AFTER a call completes, so
 * enforcement lags by one call and is an approximate budget, not an exact
 * cutoff.
 *
 * FLEET-WIDE ENFORCEMENT (ADR-7): when the server allocator hands this instance
 * an escrow share for a rule on the /policies poll (see governance/escrow.ts),
 * request-unit quota is enforced against that bounded server-granted share
 * instead of this per-process meter — closing the N x gap without per-call
 * network latency. This meter remains the fallback for rules the server does
 * not escrow (backward compatible). Token-unit budgets are not yet escrowed.
 *
 * MEMORY BOUND: both meters cap how many distinct scopes they track, and past
 * the cap they refuse new scopes rather than evicting live counters — see
 * `makeRoom` for why a quota store makes that call differently from the taint
 * latch.
 */

/**
 * A meter's answer about one scope.
 *
 * `metered` is the load-bearing addition: `allowed: true` alone cannot
 * distinguish "counted, under limit" from "could not count at all", and those
 * are different facts about whether the rule was enforced.
 */
export interface QuotaVerdict {
  allowed: boolean;
  remaining: number;
  resetAt: number;
  /** False when the bounded store had no slot for this scope. */
  metered: boolean;
}

interface QuotaEntry {
  count: number;
  windowStart: number;
  /**
   * Window this entry was opened with. Only the sweep reads it: expiry on the
   * normal path is still decided by the CALLING rule's window, unchanged. Two
   * rules with different windows and the same scope already share one counter,
   * so the sweep goes by whichever window last opened the entry.
   */
  windowMs: number;
}

/**
 * A bounded meter: the entries, plus a lower bound on when the next one can
 * expire. The bound is what keeps the cap cheap — see `makeRoom`.
 */
interface BoundedMeter {
  entries: Map<string, QuotaEntry>;
  /**
   * `min(windowStart + windowMs)` over the entries, or Infinity when empty.
   *
   * Only ever a LOWER bound: inserts lower it, and deletions can leave it
   * pointing at an entry that is gone. Stale-low is the safe direction — it
   * costs one sweep that finds nothing, and can never skip a sweep while
   * something is actually expired.
   */
  earliestExpiry: number;
}

/** In-memory quota store: key = "scope:scopeValue" */
const requestMeter: BoundedMeter = { entries: new Map(), earliestExpiry: Infinity };

/**
 * Distinct scopes either meter can track. Both stores are process-global and
 * keyed by a CALLER-SUPPLIED scope value — quota_scope: "user_id" is one entry
 * per distinct end user — so without a cap they grow for the life of the
 * process. Bounded like the other process-global stores (injection sessions,
 * tool pins, canaries).
 */
const MAX_QUOTA_SCOPES = 10_000;

/** True while a saturation episode is being warned about; reset when it clears. */
let warned = false;

/**
 * Make room for a NEW key, or report that there is none.
 *
 * Eviction policy — expired windows only, never a live one. Expiry is judged
 * against the window stored ON the entry, so an entry that goes is one the next
 * touch would have overwritten with a fresh counter anyway: dropping it changes
 * no decision. An entry still inside its window IS the enforcement state, and
 * dropping it would reset that scope's counter to zero. Since scope values are
 * caller-supplied, a caller able to mint them could then flood the store with
 * fresh keys to evict a live counter — their own, or a victim's — and buy a
 * full fresh quota. That is a rate-limit bypass, so this store refuses instead,
 * the same call tool-pinning.ts and canary.ts make where eviction would
 * silently disable the control. (session-taint.ts does evict oldest-first: a
 * taint latch is advisory-leaning and an ancient session is the least valuable
 * thing it holds. A quota counter is not advisory.)
 *
 * A refused scope is UNMETERED, and the verdict says so (`metered: false`)
 * rather than being indistinguishable from a scope that was counted and found
 * under limit. What happens next is NOT decided here: the rules engine
 * resolves it by failMode, the same way every other enforcement layer that
 * cannot run resolves (policy/detector-guard.ts), and declares it on the
 * call's own event either way. A meter that quietly stops metering is the
 * enforcement-side twin of a dropped event that leaves no gap marker.
 */
function makeRoom(meter: BoundedMeter, now: number): boolean {
  if (!saturatedNow(meter, now)) return true;
  if (!warned) {
    warned = true;
    // eslint-disable-next-line no-console
    console.warn(
      `[obsvr] quota store is full (${MAX_QUOTA_SCOPES} scopes with live windows); ` +
        `NEW scopes are NOT metered until a window elapses. Counters already tracked are unaffected. ` +
        `Each affected call declares this on its own event; failMode decides whether it proceeds.`,
    );
  }
  return false;
}

/**
 * Is this meter full of LIVE windows right now?
 *
 * The `earliestExpiry` bound is what makes this cheap. Once full, the naive
 * check re-scans all MAX_QUOTA_SCOPES entries on every new scope and deletes
 * nothing while every window is live — a per-call O(n) scan on the in-process
 * hot path, triggered by exactly the flood the cap exists to survive. When
 * `now` has not reached the earliest possible expiry, no entry CAN be expired,
 * so the scan is skipped and the answer is O(1).
 */
function saturatedNow(meter: BoundedMeter, now: number): boolean {
  if (meter.entries.size < MAX_QUOTA_SCOPES) return false;
  if (now < meter.earliestExpiry) return true;
  // The bound has been reached or is stale: settle it with one real sweep.
  sweepExpired(meter, now);
  return meter.entries.size >= MAX_QUOTA_SCOPES;
}

/** Drop every entry whose own window has elapsed and re-derive the bound. */
function sweepExpired(meter: BoundedMeter, now: number): void {
  let earliest = Infinity;
  for (const [k, v] of meter.entries) {
    const expiresAt = v.windowStart + v.windowMs;
    if (expiresAt <= now) meter.entries.delete(k);
    else if (expiresAt < earliest) earliest = expiresAt;
  }
  meter.earliestExpiry = earliest;
  // A recovered meter must be able to warn again if it saturates a second
  // time: one warning per episode, not one per process.
  if (meter.entries.size < MAX_QUOTA_SCOPES) warned = false;
}

/** Record a newly opened window against the meter's expiry bound. */
function trackExpiry(meter: BoundedMeter, now: number, windowMs: number): void {
  const expiresAt = now + windowMs;
  if (expiresAt < meter.earliestExpiry) meter.earliestExpiry = expiresAt;
}

/**
 * Verdict for a scope the bounded store could not admit: allowed here, but
 * `metered: false` so the caller can neither mistake it for an under-limit
 * count nor pass it on silently.
 */
function unmetered(limit: number, windowMs: number): QuotaVerdict {
  return { allowed: true, remaining: limit, resetAt: Date.now() + windowMs, metered: false };
}

function makeKey(scope: string, scopeValue: string): string {
  return `${scope}:${scopeValue}`;
}

function getOrCreate(meter: BoundedMeter, key: string, windowMs: number): QuotaEntry | undefined {
  const now = Date.now();
  const existing = meter.entries.get(key);

  if (existing && (now - existing.windowStart) < windowMs) {
    return existing;
  }

  // Window expired or doesn't exist - start fresh. An expired entry reuses its
  // own slot, so an already-tracked scope is never turned away.
  if (!existing && !makeRoom(meter, now)) return undefined;
  const entry: QuotaEntry = { count: 0, windowStart: now, windowMs };
  meter.entries.set(key, entry);
  trackExpiry(meter, now, windowMs);
  return entry;
}

/**
 * Check if a quota would be exceeded (does NOT increment).
 */
export function checkQuota(
  scope: string,
  scopeValue: string,
  limit: number,
  windowMs: number
): QuotaVerdict {
  const key = makeKey(scope, scopeValue);
  const entry = getOrCreate(requestMeter, key, windowMs);
  if (!entry) return unmetered(limit, windowMs);
  const remaining = Math.max(0, limit - entry.count);
  return {
    allowed: entry.count < limit,
    remaining,
    resetAt: entry.windowStart + windowMs,
    metered: true,
  };
}

/**
 * Increment quota counter and check if allowed.
 */
export function incrementQuota(
  scope: string,
  scopeValue: string,
  limit: number,
  windowMs: number
): QuotaVerdict {
  const key = makeKey(scope, scopeValue);
  const entry = getOrCreate(requestMeter, key, windowMs);
  if (!entry) return unmetered(limit, windowMs);

  entry.count++;
  const remaining = Math.max(0, limit - entry.count);

  return {
    allowed: entry.count <= limit,
    remaining,
    resetAt: entry.windowStart + windowMs,
    metered: true,
  };
}

/**
 * Reset quota for a specific scope/value.
 */
export function resetQuota(scope: string, scopeValue: string): void {
  requestMeter.entries.delete(makeKey(scope, scopeValue));
}

/**
 * Get current quota status without modifying.
 */
export function getQuotaStatus(
  scope: string,
  scopeValue: string,
  limit: number,
  windowMs: number
): { used: number; remaining: number; resetAt: number } {
  const key = makeKey(scope, scopeValue);
  const entry = getOrCreate(requestMeter, key, windowMs);
  if (!entry) return { used: 0, remaining: limit, resetAt: Date.now() + windowMs };
  return {
    used: entry.count,
    remaining: Math.max(0, limit - entry.count),
    resetAt: entry.windowStart + windowMs,
  };
}

// ── Token budgets (Cost Governance) ─────────────────────────────────────────
// Meters cumulative total_tokens per scope in a fixed window. Usage is
// recorded POST-call (providers only report usage in the response), so the
// pre-call check enforces against tokens consumed by PRIOR calls: budgets are
// approximate cutoffs, not exact. Per-process, same caveat as request quotas.

/** Token-usage store: key = "tokens:scope:scopeValue" */
const tokenMeter: BoundedMeter = { entries: new Map(), earliestExpiry: Infinity };

/**
 * Pre-call check: has this scope already consumed its token budget?
 * Does NOT increment (tokens are only known post-call).
 */
export function checkTokenBudget(
  scope: string,
  scopeValue: string,
  limit: number,
  windowMs: number
): QuotaVerdict {
  const key = `tokens:${makeKey(scope, scopeValue)}`;
  const entry = getOrCreate(tokenMeter, key, windowMs);
  if (!entry) return unmetered(limit, windowMs);
  const remaining = Math.max(0, limit - entry.count);
  return {
    allowed: entry.count < limit,
    remaining,
    resetAt: entry.windowStart + windowMs,
    metered: true,
  };
}

/**
 * Post-call: record tokens consumed by a completed call against a scope.
 * Call with the provider-reported total_tokens.
 */
export function recordTokenUsage(
  scope: string,
  scopeValue: string,
  tokens: number,
  windowMs: number
): void {
  if (!Number.isFinite(tokens) || tokens <= 0) return;
  const key = `tokens:${makeKey(scope, scopeValue)}`;
  const entry = getOrCreate(tokenMeter, key, windowMs);
  if (!entry) return;
  entry.count += tokens;
}

/** Scopes currently tracked by each meter (diagnostics, tests). */
export function quotaStoreSize(): { requests: number; tokens: number } {
  return { requests: requestMeter.entries.size, tokens: tokenMeter.entries.size };
}

/**
 * Is either meter full of live windows RIGHT NOW — i.e. would a new scope be
 * refused if one arrived this instant?
 *
 * Deliberately a current-state question, not a latch. "This process once
 * refused a scope, possibly hours ago and for one call" and "new scopes are
 * going unmetered as of now" call for different responses, and a flag that
 * never clears can only answer the first while looking like it answers the
 * second. Saturation is a transient condition: it ends on its own the moment
 * a tracked window elapses.
 */
export function quotaStoreSaturated(): boolean {
  const now = Date.now();
  return saturatedNow(requestMeter, now) || saturatedNow(tokenMeter, now);
}

/**
 * Clear all quota entries (for testing).
 */
export function _resetAllQuotas(): void {
  requestMeter.entries.clear();
  requestMeter.earliestExpiry = Infinity;
  tokenMeter.entries.clear();
  tokenMeter.earliestExpiry = Infinity;
  warned = false;
}
