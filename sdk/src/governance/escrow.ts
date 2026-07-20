/**
 * Fleet-quota escrow — client side of ADR-7.
 *
 * WHY: the per-process quota meter in `quota.ts` enforces a rule PER SDK
 * INSTANCE, so N horizontally-scaled instances get up to N x the configured
 * limit in aggregate (that file discloses the gap honestly). Escrow closes it
 * WITHOUT adding any per-call network latency.
 *
 * HOW: the server allocator hands each instance a bounded LOCAL SHARE of a
 * rule's global budget on the periodic `/policies` poll, tagged with an
 * `epoch`. Between polls the instance spends that share locally (one decrement
 * per governed call) and BLOCKS when it is exhausted — no network on the call
 * path. On the next poll the instance REPORTS how much of the granted share it
 * used (tagged with the epoch it was granted under), and the allocator
 * reconciles the prior grant and re-slices the global budget into a fresh
 * share + epoch.
 *
 * FAIL-CLOSED: on a poll failure no fresh grant arrives, so the instance keeps
 * spending only its residual share and then blocks — it NEVER fabricates
 * share. When a `/policies` response carries no escrow for a rule, escrow is
 * not in effect for it and the rule falls back to the per-process meter
 * (backward compatible with servers that never send escrow).
 *
 * The decision semantics here are pinned cross-language by
 * `conformance/fixtures/quota_escrow.json` (twin: `sdk-python/obsvr/escrow.py`).
 */

/** Wire shape of a single rule's grant inside a `/policies` response. */
export interface EscrowShare {
  /** The local budget this instance may spend before its next poll. */
  share: number;
  /** Monotonically-increasing (per rule) grant epoch. */
  epoch: number;
}

/** Live state for one rule's current grant. */
interface EscrowGrant {
  /** Units of the current grant still spendable locally. */
  remaining: number;
  /** Epoch the current grant was issued under. */
  epoch: number;
  /** Units spent (allowed) since the current grant was applied. */
  consumed: number;
}

/** Result of spending / peeking a rule's local share. */
export interface EscrowSpendResult {
  /**
   * True when escrow is in effect for the rule. When false the caller MUST
   * fall back to the per-process meter (backward compatibility).
   */
  escrow: boolean;
  allowed: boolean;
  remaining: number;
}

/** rule_id -> current grant. Absence means "no escrow in effect for this rule". */
const escrowState = new Map<string, EscrowGrant>();

/** Whether the server has an escrow grant in effect for this rule. */
export function hasEscrow(ruleId: string): boolean {
  return escrowState.has(ruleId);
}

/**
 * Apply one grant for a rule. A grant whose epoch does not strictly exceed the
 * rule's current epoch is treated as stale/replayed and ignored (mirrors the
 * server's "a stale report against an old epoch is ignored" rule so a
 * reordered or duplicated response can never resurrect a spent share or
 * silently reset the consumption counter). Applying a grant resets the
 * per-epoch consumption counter, so callers MUST snapshot consumption
 * (`snapshotConsumption`) BEFORE applying a poll response.
 */
export function applyEscrowGrant(ruleId: string, share: number, epoch: number): void {
  // Never fabricate share: reject non-finite / negative values outright.
  if (!Number.isFinite(share) || share < 0 || !Number.isFinite(epoch)) return;
  const existing = escrowState.get(ruleId);
  if (existing && epoch <= existing.epoch) return; // stale / replayed grant
  escrowState.set(ruleId, { remaining: Math.floor(share), epoch, consumed: 0 });
}

/**
 * Apply the `quota_escrow` map from a `/policies` response.
 * - Rules present in the map get their grant applied (stale epochs ignored).
 * - Rules that currently hold escrow but are ABSENT from the map lose it and
 *   fall back to the per-process meter (contract: absent rule => no escrow).
 * - An absent/invalid map clears all escrow (absent field => no escrow).
 * NOTE: snapshot consumption BEFORE calling this — a fresh grant resets it.
 */
export function applyEscrowResponse(
  map: Record<string, EscrowShare> | undefined | null,
): void {
  if (!map || typeof map !== "object") {
    escrowState.clear();
    return;
  }
  for (const ruleId of [...escrowState.keys()]) {
    if (!Object.prototype.hasOwnProperty.call(map, ruleId)) {
      escrowState.delete(ruleId);
    }
  }
  for (const [ruleId, grant] of Object.entries(map)) {
    if (grant && typeof grant.share === "number" && typeof grant.epoch === "number") {
      applyEscrowGrant(ruleId, grant.share, grant.epoch);
    }
  }
}

/**
 * Spend one unit of a rule's local share. Blocks (allowed=false) when the
 * share is exhausted; never goes negative and never fabricates share. A
 * blocked call does NOT count toward consumption (the resource was not used).
 */
export function spendEscrowShare(ruleId: string): EscrowSpendResult {
  const grant = escrowState.get(ruleId);
  if (!grant) return { escrow: false, allowed: false, remaining: 0 };
  if (grant.remaining <= 0) return { escrow: true, allowed: false, remaining: 0 };
  grant.remaining -= 1;
  grant.consumed += 1;
  return { escrow: true, allowed: true, remaining: grant.remaining };
}

/**
 * Peek a rule's share without consuming (checkOnly path: shadow / explain,
 * EV-22). Same allow/block decision as `spendEscrowShare` but side-effect free.
 */
export function peekEscrowShare(ruleId: string): EscrowSpendResult {
  const grant = escrowState.get(ruleId);
  if (!grant) return { escrow: false, allowed: false, remaining: 0 };
  return { escrow: true, allowed: grant.remaining > 0, remaining: grant.remaining };
}

/**
 * Snapshot consumption since each rule's current grant, for the next poll's
 * `quota_consumed` report. Every rule with a live grant is reported (even
 * consumed=0) so the allocator can reconcile the prior grant and reclaim the
 * unused portion. Each entry is tagged with the epoch it was granted under.
 */
export function snapshotConsumption(): Record<string, { consumed: number; epoch: number }> {
  const out: Record<string, { consumed: number; epoch: number }> = {};
  for (const [ruleId, grant] of escrowState.entries()) {
    out[ruleId] = { consumed: grant.consumed, epoch: grant.epoch };
  }
  return out;
}

/** Current grant view for a rule (tests/inspection); undefined when none. */
export function getEscrowStatus(
  ruleId: string,
): { remaining: number; epoch: number; consumed: number } | undefined {
  const grant = escrowState.get(ruleId);
  return grant ? { ...grant } : undefined;
}

/** @internal test hook */
export function _resetEscrow(): void {
  escrowState.clear();
}
