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
 */

interface QuotaEntry {
  count: number;
  windowStart: number;
}

/** In-memory quota store: key = "scope:scopeValue" */
const quotaStore = new Map<string, QuotaEntry>();

function makeKey(scope: string, scopeValue: string): string {
  return `${scope}:${scopeValue}`;
}

function getOrCreate(key: string, windowMs: number): QuotaEntry {
  const now = Date.now();
  const existing = quotaStore.get(key);

  if (existing && (now - existing.windowStart) < windowMs) {
    return existing;
  }

  // Window expired or doesn't exist - start fresh
  const entry: QuotaEntry = { count: 0, windowStart: now };
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

function getOrCreateTokens(key: string, windowMs: number): QuotaEntry {
  const now = Date.now();
  const existing = tokenStore.get(key);
  if (existing && (now - existing.windowStart) < windowMs) {
    return existing;
  }
  const entry: QuotaEntry = { count: 0, windowStart: now };
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
  entry.count += tokens;
}

/**
 * Clear all quota entries (for testing).
 */
export function _resetAllQuotas(): void {
  quotaStore.clear();
  tokenStore.clear();
}
