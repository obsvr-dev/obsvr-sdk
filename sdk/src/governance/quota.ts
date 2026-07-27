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

/** In-memory quota store: key = "scope:scopeValue" */
const quotaStore = new Map<string, QuotaEntry>();

/**
 * Distinct scopes either meter can track. Both stores are process-global and
 * keyed by a CALLER-SUPPLIED scope value — quota_scope: "user_id" is one entry
 * per distinct end user — so without a cap they grow for the life of the
 * process. Bounded like the other process-global stores (injection sessions,
 * tool pins, canaries).
 */
const MAX_QUOTA_SCOPES = 10_000;

let saturated = false;
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
 * A refused scope is UNMETERED, not blocked. The meter cannot say the scope
 * exceeded its limit, only that it has nowhere to count; turning "no counter
 * slots" into a denial would hand the same flooder a way to block every new
 * identity, and the SDK's default posture elsewhere is fail-open. Saturation
 * warns once and is readable via `quotaStoreSaturated()`.
 */
function makeRoom(store: Map<string, QuotaEntry>, now: number): boolean {
  if (store.size < MAX_QUOTA_SCOPES) return true;
  for (const [k, v] of store) {
    if ((now - v.windowStart) >= v.windowMs) store.delete(k);
  }
  if (store.size < MAX_QUOTA_SCOPES) return true;
  saturated = true;
  if (!warned) {
    warned = true;
    // eslint-disable-next-line no-console
    console.warn(
      `[obsvr] quota store is full (${MAX_QUOTA_SCOPES} scopes with live windows); ` +
        `NEW scopes are NOT metered until a window elapses. Counters already tracked are unaffected.`,
    );
  }
  return false;
}

/** Verdict for a scope the bounded store could not admit: allowed, uncounted. */
function unmetered(limit: number, windowMs: number): { allowed: boolean; remaining: number; resetAt: number } {
  return { allowed: true, remaining: limit, resetAt: Date.now() + windowMs };
}

function makeKey(scope: string, scopeValue: string): string {
  return `${scope}:${scopeValue}`;
}

function getOrCreate(key: string, windowMs: number): QuotaEntry | undefined {
  const now = Date.now();
  const existing = quotaStore.get(key);

  if (existing && (now - existing.windowStart) < windowMs) {
    return existing;
  }

  // Window expired or doesn't exist - start fresh. An expired entry reuses its
  // own slot, so an already-tracked scope is never turned away.
  if (!existing && !makeRoom(quotaStore, now)) return undefined;
  const entry: QuotaEntry = { count: 0, windowStart: now, windowMs };
  quotaStore.set(key, entry);
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
): { allowed: boolean; remaining: number; resetAt: number } {
  const key = makeKey(scope, scopeValue);
  const entry = getOrCreate(key, windowMs);
  if (!entry) return unmetered(limit, windowMs);
  const remaining = Math.max(0, limit - entry.count);
  return {
    allowed: entry.count < limit,
    remaining,
    resetAt: entry.windowStart + windowMs,
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
): { allowed: boolean; remaining: number; resetAt: number } {
  const key = makeKey(scope, scopeValue);
  const entry = getOrCreate(key, windowMs);
  if (!entry) return unmetered(limit, windowMs);

  entry.count++;
  const remaining = Math.max(0, limit - entry.count);

  return {
    allowed: entry.count <= limit,
    remaining,
    resetAt: entry.windowStart + windowMs,
  };
}

/**
 * Reset quota for a specific scope/value.
 */
export function resetQuota(scope: string, scopeValue: string): void {
  quotaStore.delete(makeKey(scope, scopeValue));
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
  const entry = getOrCreate(key, windowMs);
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
const tokenStore = new Map<string, QuotaEntry>();

function getOrCreateTokens(key: string, windowMs: number): QuotaEntry | undefined {
  const now = Date.now();
  const existing = tokenStore.get(key);
  if (existing && (now - existing.windowStart) < windowMs) {
    return existing;
  }
  if (!existing && !makeRoom(tokenStore, now)) return undefined;
  const entry: QuotaEntry = { count: 0, windowStart: now, windowMs };
  tokenStore.set(key, entry);
  return entry;
}

/**
 * Pre-call check: has this scope already consumed its token budget?
 * Does NOT increment (tokens are only known post-call).
 */
export function checkTokenBudget(
  scope: string,
  scopeValue: string,
  limit: number,
  windowMs: number
): { allowed: boolean; remaining: number; resetAt: number } {
  const key = `tokens:${makeKey(scope, scopeValue)}`;
  const entry = getOrCreateTokens(key, windowMs);
  if (!entry) return unmetered(limit, windowMs);
  const remaining = Math.max(0, limit - entry.count);
  return {
    allowed: entry.count < limit,
    remaining,
    resetAt: entry.windowStart + windowMs,
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
  const entry = getOrCreateTokens(key, windowMs);
  if (!entry) return;
  entry.count += tokens;
}

/** Scopes currently tracked by each meter (diagnostics, tests). */
export function quotaStoreSize(): { requests: number; tokens: number } {
  return { requests: quotaStore.size, tokens: tokenStore.size };
}

/**
 * True once either meter refused a new scope because every tracked window was
 * still live — some scopes are going unmetered until a window elapses.
 */
export function quotaStoreSaturated(): boolean {
  return saturated;
}

/**
 * Clear all quota entries (for testing).
 */
export function _resetAllQuotas(): void {
  quotaStore.clear();
  tokenStore.clear();
  saturated = false;
  warned = false;
}
