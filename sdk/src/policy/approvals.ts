/**
 * Human-in-the-loop approvals.
 *
 * An action_gate (or any rule) with `require_approval: true` blocks until a
 * human grants a time-boxed approval in the dashboard. Grants are delivered
 * to the SDK alongside policy rules on the /policies poll, so an approved
 * retry succeeds within one poll interval (30s default).
 *
 * An approval is scoped to a rule id, optionally pinned to one end-user
 * (metadata user_id), and always expires. There are no permanent grants:
 * "approved forever" is just a disabled rule, which is a policy change and
 * belongs in the policy editor where it gets its own audit trail.
 */

export interface ApprovalGrant {
  id: string;
  rule_id: string;
  /** When set, the grant applies only to this end user. */
  user_id?: string | null;
  /** ISO timestamp after which the grant is void. */
  expires_at: string;
  approved_by?: string;
  /**
   * Canonical hash of the rule definition the approval was requested
   * under (deriveRuleHash). A grant is void once the rule is edited:
   * an approval for yesterday's rule must never satisfy today's
   * stricter one. Absent on legacy grants, which stay honored.
   */
  rule_hash?: string | null;
}

let grants: ApprovalGrant[] = [];

/** Replace the grant set (called from the policy poll). */
export function updateApprovals(next: ApprovalGrant[]): void {
  grants = Array.isArray(next) ? next : [];
}

/**
 * Whether an unexpired grant covers this rule (and user, when pinned).
 * When both the grant and the caller carry a rule hash, they must match:
 * a grant minted under a different rule definition is void.
 */
export function hasApproval(ruleId: string, userId?: string, currentRuleHash?: string): boolean {
  const now = Date.now();
  return grants.some((g) => {
    if (g.rule_id !== ruleId) return false;
    if (Date.parse(g.expires_at) <= now) return false;
    if (g.user_id && g.user_id !== userId) return false;
    if (g.rule_hash && currentRuleHash && g.rule_hash !== currentRuleHash) return false;
    return true;
  });
}

/** Current unexpired grants (for tests/inspection). */
export function getApprovalGrants(): ApprovalGrant[] {
  const now = Date.now();
  return grants.filter((g) => Date.parse(g.expires_at) > now);
}

/**
 * File an approval request with ingest (fire-and-forget). Called when a
 * require_approval rule blocks without a grant. Ingest deduplicates by
 * (rule, user), so retry storms do not flood the dashboard queue.
 */
export function requestApproval(
  config: { ingest_url: string; api_key: string; timeout?: number },
  req: { rule_id?: string; rule_name?: string; operation?: string; user_id?: string; rule_hash?: string },
): void {
  if (!config.ingest_url) return;
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), config.timeout ?? 5000);
  if (typeof t === "object" && (t as unknown as { unref?: () => void }).unref) {
    (t as unknown as { unref: () => void }).unref();
  }
  fetch(`${config.ingest_url}/approvals/request`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-API-Key": config.api_key },
    body: JSON.stringify(req),
    signal: controller.signal,
  })
    .catch(() => { /* best-effort */ })
    .finally(() => clearTimeout(t));
}

/** @internal test hook */
export function _resetApprovals(): void {
  grants = [];
}
