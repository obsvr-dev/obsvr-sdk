/**
 * Human-in-the-loop approvals.
 *
 * An action_gate (or any rule) with `require_approval: true` blocks until a
 * human grants a time-boxed approval in the dashboard. Grants are delivered
 * to the SDK alongside policy rules on the /policies poll, so an approved
 * retry succeeds within one poll interval (30s default).
 *
 * An approval is scoped to a rule id, optionally pinned to one end-user
 * (metadata user_id), pinned to the rule definition and to the ACTION it was
 * granted for, and always expires. There are no permanent grants: "approved
 * forever" is just a disabled rule, which is a policy change and belongs in
 * the policy editor where it gets its own audit trail.
 *
 * ## Action binding, and what it is worth
 *
 * A grant scoped only to a rule id answers "did someone approve something?".
 * For a product whose claim is that the record proves what was authorized,
 * the question has to be "was THIS call approved?" — otherwise one human
 * approving a $50 transfer leaves a live grant that satisfies a $5,000,000
 * one, because both trip the same rule. So a grant may additionally carry an
 * `action_hash`: the digest of the decision-relevant facts of the call it was
 * granted for ({@link buildApprovalAction}). When both the grant and the call
 * carry one, they must match.
 *
 * What the hash binds is stated in buildApprovalAction, and so is what it
 * deliberately does not: the free-text prompt is NOT in it. A retry of an
 * approved request rarely reproduces its text byte for byte — timestamps and
 * ids drift — and a binding that voids itself on a whitespace change is a
 * binding operators switch off. The structured facts the industry rule types
 * actually decide on (action name, amount, namespaces, subject) are what
 * distinguish one action from another, and those are bound.
 *
 * A grant with no `action_hash` still satisfies, which is what keeps a
 * server that has not started minting them working — the same compatibility
 * rule `rule_hash` already follows. That is a real weakening and it is the
 * grant issuer's to close, not the SDK's: the SDK cannot invent a binding the
 * granting party never made.
 */

import { sha256Hex } from "./decision-record.js";
import { canonicalJsonForHash } from "./tool-pinning.js";

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
  /**
   * Digest of the ACTION the approval was granted for
   * ({@link approvalActionHash}). A grant carrying one satisfies only a call
   * whose action hashes the same, so it cannot be spent on a different call
   * that happens to trip the same rule. Absent on legacy grants, which stay
   * honored.
   */
  action_hash?: string | null;
}

/** Schema tag of the canonical approval-action document. */
export const APPROVAL_ACTION_SCHEMA = "obsvr-action/1";

/** The facts that distinguish one approvable action from another. */
export interface ApprovalActionInput {
  ruleId: string;
  ruleHash: string;
  actionName?: unknown;
  amount?: unknown;
  callerNamespace?: unknown;
  targetNamespace?: unknown;
  userId?: unknown;
}

/**
 * The canonical action document.
 *
 * WHAT IT BINDS: the rule that demanded approval, that rule's definition, and
 * the structured facts the approvable rule types actually decide on — the
 * action name, the amount, the caller and target namespaces, and the subject.
 * Those are what make "wire_transfer of 50 to accounting" a different action
 * from "wire_transfer of 5000000 to an external account", which is the reuse
 * this exists to stop.
 *
 * WHAT IT DOES NOT BIND, deliberately: the prompt text. An approved request
 * and its retry differ in it more often than not — ids, timestamps,
 * re-serialization — and a grant that voided itself on a whitespace change
 * would be turned off within a week. The cost is stated rather than hidden: an
 * attacker who can vary the free text while holding every structured fact
 * constant is inside the scope one human approved, which is the scope the
 * human was shown.
 *
 * Absent and non-finite values are OMITTED rather than serialized as null —
 * the same convention as the canonical decision-input and rule projections, so
 * "no amount" and "amount: null" cannot hash differently.
 */
export function buildApprovalAction(
  input: ApprovalActionInput,
): Record<string, unknown> {
  const doc: Record<string, unknown> = { schema: APPROVAL_ACTION_SCHEMA };
  if (typeof input.actionName === "string" && input.actionName.length > 0) {
    doc.action_name = input.actionName;
  }
  if (typeof input.amount === "number" && Number.isFinite(input.amount)) {
    doc.amount = input.amount;
  }
  if (typeof input.callerNamespace === "string" && input.callerNamespace.length > 0) {
    doc.caller_namespace = input.callerNamespace;
  }
  doc.rule_hash = input.ruleHash;
  doc.rule_id = input.ruleId;
  if (typeof input.targetNamespace === "string" && input.targetNamespace.length > 0) {
    doc.target_namespace = input.targetNamespace;
  }
  if (typeof input.userId === "string" && input.userId.length > 0) {
    doc.user_id = input.userId;
  }
  return doc;
}

/**
 * SHA-256 (lowercase 64-hex) of the canonical action document. Byte-identical
 * in both SDKs; pinned by conformance/fixtures/approvals.json.
 *
 * Uses the cross-SDK-stable canonicalizer rather than the rules-hash one: an
 * `amount` reaches here from caller-supplied context, so it is attacker-shaped
 * input, and the stable canonicalizer REFUSES values the two runtimes cannot
 * render identically instead of normalizing them into agreement. A throw here
 * means no action hash, which the caller resolves by refusing the grant — an
 * approval that cannot be bound is not an approval.
 */
export function approvalActionHash(input: ApprovalActionInput): string {
  return sha256Hex(canonicalJsonForHash(buildApprovalAction(input)));
}

/**
 * {@link approvalActionHash}, or undefined when the action carries a value the
 * two runtimes cannot render identically. Callers treat undefined as "this
 * call has no action hash", which under the matching rule means an unbound
 * grant still satisfies and a bound one does not.
 */
export function safeApprovalActionHash(
  input: ApprovalActionInput,
): string | undefined {
  try {
    return approvalActionHash(input);
  } catch {
    return undefined;
  }
}

let grants: ApprovalGrant[] = [];

/** Replace the grant set (called from the policy poll). */
export function updateApprovals(next: ApprovalGrant[]): void {
  grants = Array.isArray(next) ? next : [];
}

/** What a call presents to the grant store. */
export interface ApprovalClaim {
  ruleId: string;
  userId?: string;
  /** Canonical hash of the rule definition as it stands now. */
  ruleHash?: string;
  /** Digest of this call's action ({@link approvalActionHash}). */
  actionHash?: string;
  /** Injected for determinism; defaults to the wall clock. */
  now?: number;
}

/**
 * Whether an unexpired grant covers this claim. Pure apart from the grant
 * store: no I/O, no mutation, so the same claim against the same store always
 * answers the same way. Pinned by conformance/fixtures/approvals.json.
 *
 * Each pin only narrows: when BOTH the grant and the call carry a value they
 * must match; when either side is silent the check does not apply. That is
 * what lets a grant issuer adopt the bindings one at a time without every
 * outstanding grant going void on upgrade — and it is why an unbound grant is
 * exactly as strong as the issuer made it, no stronger.
 */
export function hasApproval(claim: ApprovalClaim): boolean {
  return matchApproval(claim) !== undefined;
}

/**
 * Is this grant still live at `now`?
 *
 * `Date.parse` returns NaN for anything it cannot read, and EVERY comparison
 * with NaN is false — so `Date.parse(expires_at) <= now` fell straight through
 * for `"never"`, `""`, `"forever"` or any other unparseable string, and the
 * grant matched forever. Measured: four such values matched at the current time
 * AND at the year 9999, while `getApprovalGrants()` used the mirrored
 * comparison `> now`, which is ALSO false for NaN — so the permanent grant was
 * invisible to the inspection API at the same time as being live in the gate.
 * An operator listing grants saw nothing.
 *
 * The header of this module says approvals always expire and there are no
 * permanent grants. That was true of the intent and false of the code, so the
 * code moved. Unparseable now means expired, which is the direction a
 * human-in-the-loop authorization has to fail in, and one predicate serves both
 * the gate and the listing so they cannot disagree again.
 */
function isLive(g: ApprovalGrant, now: number): boolean {
  const expiresAt = Date.parse(g.expires_at);
  return Number.isFinite(expiresAt) && expiresAt > now;
}

/** The grant that satisfies a claim, or undefined. */
export function matchApproval(claim: ApprovalClaim): ApprovalGrant | undefined {
  const now = claim.now ?? Date.now();
  return grants.find((g) => {
    if (g.rule_id !== claim.ruleId) return false;
    if (!isLive(g, now)) return false;
    if (g.user_id && g.user_id !== claim.userId) return false;
    if (g.rule_hash && claim.ruleHash && g.rule_hash !== claim.ruleHash) return false;
    if (g.action_hash && claim.actionHash && g.action_hash !== claim.actionHash) return false;
    return true;
  });
}

/**
 * Re-check a claim that was satisfied earlier in the same call.
 *
 * The pre-call pipeline can spend real time between deciding and executing —
 * a customer hook has a two-second budget, an external policy backend has its
 * own — and a grant that expires inside that window would otherwise let a call
 * proceed on an authorization that is no longer live. This runs after every
 * layer that can delay the call and before the outbound request, so the
 * remaining gap is the SDK's own final assembly rather than a hook timeout.
 *
 * It cannot close the gap entirely: nothing in an in-process library can make
 * the check and the provider's receipt of the request simultaneous. What it
 * removes is the part of the window that is measured in seconds.
 */
export function revalidateApproval(claim: ApprovalClaim): boolean {
  return hasApproval(claim);
}

/** Current unexpired grants (for tests/inspection). Same predicate the gate
 * uses, so what an operator can list is what can authorize a call. */
export function getApprovalGrants(): ApprovalGrant[] {
  const now = Date.now();
  return grants.filter((g) => isLive(g, now));
}

/**
 * File an approval request with ingest (fire-and-forget). Called when a
 * require_approval rule blocks without a grant. Ingest deduplicates by
 * (rule, user), so retry storms do not flood the dashboard queue.
 */
export function requestApproval(
  config: { ingest_url: string; api_key: string; timeout?: number },
  req: {
    rule_id?: string;
    rule_name?: string;
    operation?: string;
    user_id?: string;
    rule_hash?: string;
    /** So the granting party can mint a grant bound to THIS action. Without
     * it the dashboard has nothing to bind to and can only issue a
     * rule-scoped grant, which is the weaker thing this exists to replace. */
    action_hash?: string;
  },
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
