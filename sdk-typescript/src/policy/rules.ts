/**
 * Structured policy rules engine.
 * @packageDocumentation
 */
import { createHash } from 'node:crypto';
import type { PolicyDecisionResult, QuotaUnmetered } from './hook.js';
import { hasApproval, safeApprovalActionHash } from './approvals.js';
import { recordCheckOnlyFailure } from './detector-guard.js';
import { incrementQuota, checkQuota, checkTokenBudget } from '../governance/quota.js';
import { hasEscrow, spendEscrowShare, peekEscrowShare } from '../governance/escrow.js';
import { safeRegexTest } from '../utils/safe-regex.js';
import { normalizeForMatching } from './normalize.js';
import { ReasonCode, ruleTypeToReasonCode } from '../governance/reason-codes.js';
import { extractSqlFacets, readFacet } from './protocol-facets.js';

export interface PolicyRule {
  id: string;
  name: string;
  enabled: boolean;
  /**
   * "shadow" rules are evaluated AFTER the active decision and only
   * record what they would have done (would_have outcomes on the audit
   * event); they never affect the decision, returned content, quotas,
   * or approvals (EV-20/21). Default: "enforce".
   */
  mode?: 'enforce' | 'shadow';
  action: 'block' | 'redact' | 'flag';
  type:
    | 'keyword'
    | 'regex'
    | 'topic_deny'
    | 'topic_allow'
    // 'pii' is a VALID, authored policy type (it validates and participates in the
    // policy_version/rules_hash) but has no branch in evaluatePolicyRules by design:
    // PII enforcement is handled by the dedicated builtin scanner (policy/hook.ts,
    // driven by pii_policy + pii_types), not the generic rule loop. Kept as a type
    // so PII intent is expressible in a policy and sealed into the policy hash.
    | 'pii'
    | 'action_gate'
    | 'namespace_isolation'
    | 'cross_tenant_block'
    | 'destructive_op_gate'
    | 'source_grounding'
    | 'environment_gate'
    | 'quota'
    | 'model_gate'
    /**
     * Matches PARSED protocol structure rather than raw characters. A rule
     * saying "the verb is DROP" survives a comment, a quote-style change or a
     * line break that defeats a regex, and does not fire on prose that merely
     * mentions the word. Fully deterministic (policy/protocol-facets.ts).
     */
    | 'protocol_facet';
  conditions: {
    keywords?: string[];
    pattern?: string;
    topics?: string[];
    pii_types?: string[];
    /** Action types to match (e.g. "wire_transfer", "delete_record"). */
    action_types?: string[];
    /** Numeric threshold condition applied to a field in PolicyEvalContext. */
    threshold?: { field: string; operator: '>' | '<' | '>=' | '<=' | '=='; value: number };
    /** Time-of-day window restriction (24h format). */
    time_window?: { allow_hours: [number, number]; timezone?: string };
    /** Field on the caller identifying its namespace. */
    caller_namespace_field?: string;
    /** Field on the target identifying its namespace. */
    target_namespace_field?: string;
    /** Operations classified as destructive (e.g. "DROP TABLE", "rm -rf"). */
    destructive_operations?: string[];
    /** Require explicit approval before proceeding. */
    require_approval?: boolean;
    /** Field containing source document references. */
    source_document_field?: string;
    /** Minimum ratio of grounded content (0–1). */
    min_grounding_ratio?: number;
    /** Target environments this rule applies to. */
    target_environments?: string[];
    /** Maximum requests (or tokens, see quota_unit) allowed within the quota window. */
    quota_limit?: number;
    /** Duration of the quota window in milliseconds. */
    quota_window_ms?: number;
    /** Scope key used to bucket quota counters. 'project' meters the whole project as one bucket. */
    quota_scope?: 'user_id' | 'service_name' | 'tenant_id' | 'project';
    /**
     * What the quota meters. 'requests' (default) counts calls;
     * 'tokens' meters cumulative total_tokens reported by prior calls in the
     * window (usage is recorded post-call via recordTokenUsage, so enforcement
     * lags by one call - budgets are approximate, not exact cutoffs).
     */
    quota_unit?: 'requests' | 'tokens';
    /** model_gate: models allowed through (exact or prefix match, e.g. "gpt-4"). */
    allowed_models?: string[];
    /** model_gate: models always blocked. Deny wins over allow. */
    denied_models?: string[];
    /** model_gate: providers allowed through (e.g. ["openai", "anthropic"]). */
    allowed_providers?: string[];
    /**
     * protocol_facet: which parsed facet to address, e.g. "sql.verb",
     * "sql.tables", "sql.functions", "sql.target", "sql.multiple_statements".
     */
    facet?: string;
    /**
     * protocol_facet: values that MATCH (the rule fires when the facet holds
     * any of them). Compared case-insensitively against the facet's values.
     */
    facet_in?: string[];
    /**
     * protocol_facet: values that do NOT match — the rule fires when the facet
     * holds a value outside this list, which is the allowlist shape. An empty
     * facet (nothing to compare) does NOT fire this: absence is handled by the
     * unparseable rule below, not by pretending an empty list is a violation.
     */
    facet_not_in?: string[];
  };
  applies_to?: 'prompt' | 'response' | 'both';
}

/**
 * Optional context provided alongside text for industry-specific rule evaluation.
 * When omitted, the engine falls back to text-only matching (backward compatible).
 */
export interface PolicyEvalContext {
  actionName?: string;
  amount?: number;
  callerNamespace?: string;
  targetNamespace?: string;
  currentEnvironment?: string;
  delegationChain?: { chain: string[]; depth: number };
  sourceDocuments?: string[];
  metadata?: Record<string, unknown>;
  /** Model requested for this call (model_gate). */
  model?: string;
  /** Provider handling this call (model_gate). */
  provider?: string;
}

/**
 * Evaluate a list of policy rules against text.
 * - All enabled rules run in order.
 * - 'block' wins over 'redact'; first block short-circuits.
 * - 'topic_allow' short-circuits to allow if matched (nothing else has blocked yet).
 * - Returns PolicyDecisionResult with rule_id of the fired rule.
 *
 * The optional `context` parameter enables industry-specific rule types
 * (action_gate, namespace_isolation, etc.). Without it, only the original
 * text-based rule types are evaluated - fully backward compatible.
 */
export function evaluatePolicyRules(
  rules: PolicyRule[],
  text: string,
  target: 'prompt' | 'response' = 'prompt',
  context?: PolicyEvalContext,
  opts?: {
    /** Check-only evaluation (EV-22): identical decision logic but no
     * quota consumption. Used by shadow evaluation and explain(). */
    checkOnly?: boolean;
    /**
     * The operator's failure posture, for the one case the rules engine can
     * hit an enforcement layer that cannot run: a quota scope the bounded
     * store had no slot for. Absent behaves as "open", the SDK-wide default.
     */
    failMode?: 'open' | 'closed';
  },
): PolicyDecisionResult {
  // The unmetered record is collected here and attached to whatever verdict
  // comes out, including one produced by a LATER rule: the fact "this call's
  // quota rule did not run" is true of the call regardless of what decided it.
  const unmetered: { record?: QuotaUnmetered } = {};
  const result = evaluateRules(rules, text, target, context, opts, unmetered);
  return unmetered.record ? { ...result, quota_unmetered: unmetered.record } : result;
}

function evaluateRules(
  rules: PolicyRule[],
  text: string,
  target: 'prompt' | 'response' = 'prompt',
  context?: PolicyEvalContext,
  opts?: { checkOnly?: boolean; failMode?: 'open' | 'closed' },
  unmetered: { record?: QuotaUnmetered } = {},
): PolicyDecisionResult {
  // §6: normalize once, up front, so every text-matching rule (keyword, regex,
  // topic, action_gate, destructive_op, source_grounding) sees the same
  // confusable/zero-width-folded copy. Matching-only: the engine returns a
  // decision + rule_id, never modified text, so the stored/forwarded content is
  // untouched. Identity on plain ASCII, so existing behavior is unchanged.
  text = normalizeForMatching(text);
  for (const rule of rules) {
    if (!rule.enabled) continue;
    // Shadow rules are inert in active evaluation (EV-20); they run only
    // through evaluateShadowRules after the active decision is final.
    if (rule.mode === 'shadow') continue;

    const appliesToTarget =
      !rule.applies_to ||
      rule.applies_to === 'both' ||
      rule.applies_to === target;
    if (!appliesToTarget) continue;

    let matched = false;

    if (rule.type === 'keyword' && rule.conditions.keywords) {
      const lower = text.toLowerCase();
      matched = rule.conditions.keywords.some((kw) =>
        lower.includes(kw.toLowerCase()),
      );
    } else if (rule.type === 'regex' && rule.conditions.pattern) {
      // ReDoS guard: customer-supplied patterns are validated for
      // catastrophic-backtracking shapes and run against bounded input.
      // Rejected patterns are treated as no-match (never throw mid-call).
      matched = safeRegexTest(rule.conditions.pattern, text);
    } else if (rule.type === 'topic_deny' && rule.conditions.topics) {
      const lower = text.toLowerCase();
      matched = rule.conditions.topics.some((t) => lower.includes(t.toLowerCase()));
    } else if (rule.type === 'topic_allow' && rule.conditions.topics) {
      const lower = text.toLowerCase();
      matched = rule.conditions.topics.some((t) => lower.includes(t.toLowerCase()));
    } else if (rule.type === 'action_gate') {
      matched = evaluateActionGate(rule, text, context);
    } else if (rule.type === 'namespace_isolation') {
      matched = evaluateNamespaceIsolation(rule, context);
    } else if (rule.type === 'cross_tenant_block') {
      matched = evaluateCrossTenantBlock(rule, context);
    } else if (rule.type === 'destructive_op_gate') {
      matched = evaluateDestructiveOpGate(rule, text, context);
    } else if (rule.type === 'source_grounding') {
      matched = evaluateSourceGrounding(rule, text, context);
    } else if (rule.type === 'environment_gate') {
      matched = evaluateEnvironmentGate(rule, context);
    } else if (rule.type === 'model_gate') {
      matched = evaluateModelGate(rule, context);
    } else if (rule.type === 'protocol_facet') {
      matched = evaluateProtocolFacet(rule, text);
    } else if (rule.type === 'quota') {
      if (!rule.conditions.quota_limit || !rule.conditions.quota_window_ms || !rule.conditions.quota_scope) continue;
      // Phase-aware consumption: a rule in scope for both phases meters and
      // enforces on the REQUEST (prompt) phase only — the response pass of
      // the SAME call must never burn a second unit (and its allowance was
      // already decided pre-call), so it is skipped here. Only rules
      // explicitly scoped to the response meter on the response phase.
      if (target === 'response' && rule.applies_to !== 'response') continue;
      // Bucket selection: callers (e.g. the proxy wrapper) may spread
      // identity fields at the TOP level of the context rather than under
      // metadata; honor both (same fallback the approvals path uses) so a
      // scoped rule never silently meters the 'default' bucket.
      const scopeValue = rule.conditions.quota_scope === 'project'
        ? 'project'
        : (context?.metadata?.[rule.conditions.quota_scope] as string
          ?? ((context as unknown as Record<string, unknown> | undefined)?.[rule.conditions.quota_scope] as string)
          ?? 'default');
      const unit = rule.conditions.quota_unit ?? 'requests';
      let result: { allowed: boolean; remaining: number; metered?: boolean };
      if (unit === 'tokens') {
        result = checkTokenBudget(
          rule.conditions.quota_scope,
          scopeValue,
          rule.conditions.quota_limit,
          rule.conditions.quota_window_ms,
        );
      } else if (hasEscrow(rule.id)) {
        // Fleet-quota escrow (ADR-7) is in effect for this rule: spend this
        // instance's server-granted LOCAL share instead of the per-process
        // meter — zero network on the call path. The /policies poll refills
        // the share and reports consumption. An exhausted share blocks with
        // the same quota_exceeded verdict shape as the per-process meter.
        // checkOnly (shadow/explain, EV-22) peeks without consuming.
        const e = opts?.checkOnly ? peekEscrowShare(rule.id) : spendEscrowShare(rule.id);
        result = { allowed: e.allowed, remaining: e.remaining };
      } else {
        // No escrow grant for this rule: fall back to today's per-process
        // meter (backward compatible with servers that never send escrow).
        result = (opts?.checkOnly ? checkQuota : incrementQuota)(
          rule.conditions.quota_scope,
          scopeValue,
          rule.conditions.quota_limit,
          rule.conditions.quota_window_ms,
        );
      }
      // The bounded meter had no counter slot for this scope, so this rule was
      // NOT enforced on this call. Resolve it the way every other enforcement
      // layer that cannot run resolves — by failMode (policy/detector-guard.ts:
      // "every internal failure resolves by failMode, EXCEPT the floor class",
      // and a quota rule is not floor class). Declaring it is not optional
      // either way: an allowed call whose quota rule never ran is
      // byte-identical on the wire to one that was counted and found under
      // limit, and an auditor replaying it would read a rule that was in force
      // and never exceeded.
      //
      // Why failMode rather than always allowing: "closed" means "never fail
      // open", and an unmeterable scope is precisely a case where the SDK
      // cannot say whether the limit holds. It does cost availability — a
      // caller who can mint scope values can saturate the store and have new
      // identities refused — but that is the trade the operator selected, and
      // under "open" that same flood buys the flooder UNMETERED quota, which
      // is the worse outcome for someone who asked for fail-closed. "open"
      // stays the default, so this only reaches operators who opted in.
      if (result.metered === false) {
        const failClosed = opts?.failMode === 'closed';
        unmetered.record = {
          rule_id: rule.id,
          scope: rule.conditions.quota_scope,
          unit,
          resolution: failClosed ? 'closed' : 'open',
        };
        if (failClosed) {
          return {
            decision: 'block',
            rule_id: rule.id,
            reason_code: ReasonCode.QUOTA_UNMETERED,
            reason:
              `Quota rule '${rule.id}' could not be metered: the quota store has no counter ` +
              `slot for scope '${rule.conditions.quota_scope}'. Blocked because failMode is 'closed'`,
          };
        }
        continue;
      }
      if (!result.allowed) {
        return {
          decision: rule.action === 'flag' ? 'allow' : rule.action,
          rule_id: rule.id,
          reason_code: ReasonCode.QUOTA_EXCEEDED,
          reason: `Quota exceeded: ${result.remaining} remaining of ${rule.conditions.quota_limit} per ${rule.conditions.quota_window_ms}ms window`,
        };
      }
      continue;
    }

    if (!matched) continue;

    if (rule.type === 'topic_allow') {
      return { decision: 'allow', rule_id: rule.id, reason_code: ReasonCode.PERMITTED, reason: rule.name };
    }

    if (rule.action === 'block') {
      // Human-in-the-loop: a require_approval rule passes when an unexpired
      // grant covers it (optionally pinned to this end user); otherwise it
      // blocks and asks the caller to file an approval request.
      if (rule.conditions.require_approval === true) {
        const userId = context?.metadata?.user_id as string | undefined
          ?? (context as Record<string, unknown> | undefined)?.user_id as string | undefined;
        // Pin the approval to THIS rule definition: a grant minted under
        // an older version of the rule (different hash) is void.
        const ruleHash = deriveRuleHash(rule);
        // ...and to THIS action, so a grant issued for one call cannot be
        // spent on a different call that happens to trip the same rule.
        const actionHash = safeApprovalActionHash({
          ruleId: rule.id,
          ruleHash,
          actionName: context?.actionName,
          amount: context?.amount,
          callerNamespace: context?.callerNamespace,
          targetNamespace: context?.targetNamespace,
          userId,
        });
        const claim = { ruleId: rule.id, userId, ruleHash, actionHash };
        if (hasApproval(claim)) {
          return {
            decision: 'allow',
            rule_id: rule.id,
            reason_code: ReasonCode.APPROVAL_GRANTED,
            reason: `approved: ${rule.name}`,
            rule_hash: ruleHash,
            // Carried so the caller can re-check the grant after the layers
            // that can delay the call, immediately before it goes out.
            approval_granted: claim,
          };
        }
        return {
          decision: 'block',
          rule_id: rule.id,
          reason_code: ReasonCode.APPROVAL_REQUIRED,
          reason: `approval_required: ${rule.name}`,
          approval_required: true,
          rule_hash: ruleHash,
          ...(actionHash !== undefined ? { action_hash: actionHash } : {}),
        };
      }
      return { decision: 'block', rule_id: rule.id, reason_code: ruleTypeToReasonCode(rule.type), reason: rule.name };
    }

    if (rule.action === 'redact') {
      return { decision: 'redact', rule_id: rule.id, reason_code: ruleTypeToReasonCode(rule.type), reason: rule.name };
    }

    // flag: don't block, but note the rule fired. reason_code classifies
    // WHY the rule engaged (the decision field stays authoritative: a flag
    // matches but allows).
    return { decision: 'allow', rule_id: rule.id, reason_code: ruleTypeToReasonCode(rule.type), reason: rule.name };
  }

  return { decision: 'allow', reason_code: ReasonCode.PERMITTED };
}

// ---------------------------------------------------------------------------
// Industry-specific rule evaluators
// ---------------------------------------------------------------------------

/**
 * FinTech: action_gate - matches action types, thresholds, and time windows.
 */
function evaluateActionGate(
  rule: PolicyRule,
  text: string,
  context?: PolicyEvalContext,
): boolean {
  const { conditions } = rule;

  // Action type matching
  if (conditions.action_types && conditions.action_types.length > 0) {
    const actionName = context?.actionName ?? text;
    const lower = actionName.toLowerCase();
    const actionMatch = conditions.action_types.some(
      (at) => lower.includes(at.toLowerCase()),
    );
    if (!actionMatch) return false;
  }

  // Threshold evaluation
  if (conditions.threshold) {
    const { field, operator, value } = conditions.threshold;
    const actual = resolveThresholdField(field, context);
    if (actual === undefined) return false;
    if (!compareThreshold(actual, operator, value)) return false;
  }

  // Time window evaluation
  if (conditions.time_window) {
    const { allow_hours, timezone } = conditions.time_window;
    const now = getCurrentHour(timezone);
    const [start, end] = allow_hours;
    // If outside the allowed window, the gate fires (blocks)
    if (start <= end) {
      if (now >= start && now < end) return false; // within window = allowed
    } else {
      // Wraps midnight, e.g. [22, 6]
      if (now >= start || now < end) return false;
    }
    return true;
  }

  return true;
}

/**
 * Healthcare: namespace_isolation - blocks when caller and target namespaces differ.
 *
 * Exported as the single source of truth: the industry barrel re-exports this
 * same function, so there is exactly one namespace evaluator in the package
 * and its fail-closed asymmetric handling cannot silently diverge.
 */
export function evaluateNamespaceIsolation(
  rule: PolicyRule,
  context?: PolicyEvalContext,
): boolean {
  if (!context) return false;
  const caller = context.callerNamespace;
  const target = context.targetNamespace;
  // Both absent: the call is not namespaced, so the isolation rule does not
  // apply (no disruption to non-namespaced setups). But an ASYMMETRIC context —
  // one namespace present, the other missing — is exactly how an attacker nulls
  // out a namespace to defeat isolation, so treat it as a boundary crossing
  // (fail-closed) rather than silently allowing.
  if (!caller && !target) return false;
  if (!caller || !target) return true;
  return caller !== target;
}

/**
 * SaaS: cross_tenant_block - detects cross-tenant access attempts.
 *
 * Exported as the single source of truth (see evaluateNamespaceIsolation).
 */
export function evaluateCrossTenantBlock(
  rule: PolicyRule,
  context?: PolicyEvalContext,
): boolean {
  if (!context) return false;
  const caller = context.callerNamespace;
  const target = context.targetNamespace;
  // See evaluateNamespaceIsolation: unnamespaced calls pass; an asymmetric
  // context (one side missing) fails closed as a cross-tenant access.
  if (!caller && !target) return false;
  if (!caller || !target) return true;
  return caller !== target;
}

/**
 * SaaS: destructive_op_gate - detects destructive operations in text.
 */
function evaluateDestructiveOpGate(
  rule: PolicyRule,
  text: string,
  context?: PolicyEvalContext,
): boolean {
  const ops = rule.conditions.destructive_operations;
  if (!ops || ops.length === 0) return false;
  const lower = text.toLowerCase();
  const actionName = (context?.actionName ?? '').toLowerCase();
  return ops.some(
    (op) => lower.includes(op.toLowerCase()) || actionName.includes(op.toLowerCase()),
  );
}

/**
 * Legal: source_grounding - flags when output is insufficiently grounded
 * in source documents.
 */
function evaluateSourceGrounding(
  rule: PolicyRule,
  text: string,
  context?: PolicyEvalContext,
): boolean {
  const minRatio = rule.conditions.min_grounding_ratio;
  if (minRatio === undefined) return false;
  const sources = context?.sourceDocuments;
  if (!sources || sources.length === 0) return true; // no sources = ungrounded
  const score = computeGroundingScore(text, sources);
  return score < minRatio;
}

/**
 * DevOps: environment_gate - blocks actions in restricted environments.
 */
function evaluateEnvironmentGate(
  rule: PolicyRule,
  context?: PolicyEvalContext,
): boolean {
  const targets = rule.conditions.target_environments;
  if (!targets || targets.length === 0) return false;
  const current = context?.currentEnvironment;
  if (!current) return false;
  return targets.includes(current);
}

/**
 * protocol_facet - match PARSED protocol structure rather than raw characters.
 *
 * FAILS CLOSED. Text the decomposer cannot speak about returns
 * `parsed: false`, and that MATCHES — the rule's action applies. This is the
 * opposite of every other rule type here, and deliberately so: a facet rule
 * exists because "the verb is DROP" is a stronger question than a pattern
 * match, and a statement an attacker made unparseable would otherwise be the
 * bypass. An operator who wants unparseable input permitted should not be
 * using a facet rule for it.
 *
 * Runs on the SAME normalized copy every other text rule sees, so a
 * confusable-folded or zero-width-split statement is decomposed from the text
 * the rest of the engine already agreed on.
 */
function evaluateProtocolFacet(rule: PolicyRule, text: string): boolean {
  const facet = rule.conditions.facet;
  if (typeof facet !== 'string' || facet.length === 0) return false;
  if (!facet.startsWith('sql.')) return false; // only SQL facets exist today
  const facets = extractSqlFacets(text);
  if (!facets.parsed) return true; // fail closed: cannot evaluate is a match
  const values = readFacet(facets, facet);
  const lower = (list: string[] | undefined): string[] =>
    (list ?? []).map((v) => String(v).toLowerCase());

  const inList = rule.conditions.facet_in;
  if (inList && inList.length > 0) {
    const wanted = new Set(lower(inList));
    if (values.some((v) => wanted.has(v.toLowerCase()))) return true;
  }
  const notInList = rule.conditions.facet_not_in;
  if (notInList && notInList.length > 0 && values.length > 0) {
    const allowed = new Set(lower(notInList));
    if (values.some((v) => !allowed.has(v.toLowerCase()))) return true;
  }
  return false;
}

/**
 * model_gate - restrict which models/providers a call may use.
 *
 * Matching (rule FIRES = matched = the configured action applies):
 * - denied_models: fires when the requested model matches any entry
 *   (exact or prefix, so "gpt-4" covers "gpt-4o"). Deny wins over allow.
 * - allowed_models: fires when the model does NOT match any entry.
 * - allowed_providers: fires when the provider is not in the list.
 * Without model/provider context the gate cannot evaluate and never fires.
 */
function evaluateModelGate(
  rule: PolicyRule,
  context?: PolicyEvalContext,
): boolean {
  const { allowed_models, denied_models, allowed_providers } = rule.conditions;
  const model = (context?.model ?? '').toLowerCase();
  const provider = (context?.provider ?? '').toLowerCase();

  const matches = (list: string[], value: string): boolean =>
    list.some((entry) => {
      const e = entry.toLowerCase();
      return value === e || value.startsWith(e);
    });

  if (denied_models && denied_models.length > 0 && model) {
    if (matches(denied_models, model)) return true;
  }
  if (allowed_models && allowed_models.length > 0 && model) {
    if (!matches(allowed_models, model)) return true;
  }
  if (allowed_providers && allowed_providers.length > 0 && provider) {
    if (!allowed_providers.map((p) => p.toLowerCase()).includes(provider)) {
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function resolveThresholdField(
  field: string,
  context?: PolicyEvalContext,
): number | undefined {
  if (!context) return undefined;
  if (field === 'amount') return context.amount;
  const meta = context.metadata;
  if (meta && field in meta) {
    const v = meta[field];
    return typeof v === 'number' ? v : undefined;
  }
  return undefined;
}

function compareThreshold(
  actual: number,
  operator: '>' | '<' | '>=' | '<=' | '==',
  value: number,
): boolean {
  switch (operator) {
    case '>': return actual > value;
    case '<': return actual < value;
    case '>=': return actual >= value;
    case '<=': return actual <= value;
    case '==': return actual === value;
    default: return false;
  }
}

function getCurrentHour(timezone?: string): number {
  if (timezone) {
    try {
      const fmt = new Intl.DateTimeFormat('en-US', {
        hour: 'numeric',
        hour12: false,
        timeZone: timezone,
      });
      return parseInt(fmt.format(new Date()), 10);
    } catch {
      // Invalid timezone - fall back to local
    }
  }
  return new Date().getHours();
}

/**
 * Compute a simple grounding score: fraction of output words found in source docs.
 */
export function computeGroundingScore(output: string, sources: string[]): number {
  const outputWords = output.toLowerCase().split(/\s+/).filter((w) => w.length > 3);
  if (outputWords.length === 0) return 1;
  const sourceText = sources.join(' ').toLowerCase();
  const grounded = outputWords.filter((w) => sourceText.includes(w));
  return grounded.length / outputWords.length;
}

/**
 * JSON serialization with recursively sorted object keys and compact
 * separators. This is the canonical form both SDKs hash (policy_version,
 * rules_hash), so any change here is a cross-language breaking change: update
 * the shared fixture and the Python twin together.
 *
 * THIS SIDE IS THE REFERENCE. The Python `_canonical_json` is a hand-written
 * port of it, not a `json.dumps` call — `json.dumps` and `JSON.stringify`
 * disagree on whole-valued floats, negative zero, exponent form, unpaired
 * surrogates, and the sort order of astral keys, and a differential property
 * test found about a third of random documents hitting one of those. Pinned by
 * conformance/fixtures/canonical_json.json and re-checked against generated
 * documents by scripts/check-canonical-json-parity.mjs.
 */
export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map((v) => stableStringify(v === undefined ? null : v)).join(',') + ']';
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + stableStringify(obj[k])).join(',') + '}';
}

/** Canonical projection of a rule: only governance-relevant fields, so
 * cosmetic/unknown fields (server timestamps, editor metadata) never
 * change the hash. Keys with null/undefined values are omitted. */
function canonicalRule(r: PolicyRule): Record<string, unknown> {
  const projected: Record<string, unknown> = {
    action: r.action,
    conditions: r.conditions ?? {},
    enabled: r.enabled,
    id: r.id,
    name: r.name,
    type: r.type,
  };
  const appliesTo = (r as { applies_to?: unknown }).applies_to;
  if (appliesTo !== undefined && appliesTo !== null) projected.applies_to = appliesTo;
  // "shadow" is a material behavior change (rule not enforced), so it is
  // part of the canonical definition; the default "enforce" is omitted so
  // pre-shadow hashes stay stable.
  if (r.mode === 'shadow') projected.mode = 'shadow';
  return projected;
}

/**
 * Derive the canonical rules hash for the enabled rule set: 16-hex-char
 * prefix of SHA-256 over the stableStringify'd canonical projections,
 * sorted by id (codepoint order, NOT locale order, for cross-language
 * determinism). Returns "none" when no rules are enabled. Stamped on
 * every audit event as policy_version; must match the Python SDK's
 * derive_policy_version byte for byte (pinned by the shared fixture).
 */
export function derivePolicyVersion(rules: PolicyRule[]): string {
  // Guarded at the function, like redactForStorage, because there is one
  // correct answer at all ~20 of its call sites and most of them are on live
  // host paths - the wrapper's per-call stamp, the integrations, MCP, the poll
  // header, the policy log. This reads the same rule objects the matcher does,
  // so a malformed rule raises HERE, before any detector span is entered.
  //
  // Always open: the policy version is a provenance field, not a control. It
  // records which rules a decision ran under; it never decides anything, so a
  // version that cannot be computed must not block a call. "unknown" is the
  // honest value and is distinguishable from the legitimate "none".
  try {
    if (!rules || rules.length === 0) return 'none';
    const sorted = rules
      .filter((r) => r.enabled)
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    if (sorted.length === 0) return 'none';
    const hash = createHash('sha256')
      .update(stableStringify(sorted.map(canonicalRule)))
      .digest('hex');
    return hash.slice(0, 16);
  } catch (err) {
    recordCheckOnlyFailure('policy_rules', err);
    return 'unknown';
  }
}

/**
 * Hash of ONE rule's canonical definition. Approvals are pinned to this:
 * an approval granted while a rule had hash H is void once the rule is
 * edited (its hash changes), so a stale or tampered approval can never
 * satisfy a stricter rule. 16-hex-char SHA-256 prefix.
 */
export function deriveRuleHash(rule: PolicyRule): string {
  return createHash('sha256')
    .update(stableStringify(canonicalRule(rule)))
    .digest('hex')
    .slice(0, 16);
}

/**
 * Anti-tamper policy floor: evaluate operator-declared FLOOR rules that
 * cannot be silently disabled or downgraded. Every floor rule is coerced to
 * `{ enabled: true, mode: 'enforce' }` before evaluation, so flipping a floor
 * rule to `enabled:false` or `mode:'shadow'` cannot make it inert. Because the
 * engine is first-match-in-order and a customer `topic_allow` short-circuits
 * to allow, the floor is evaluated as its OWN pass BEFORE the customer rules,
 * and its decision is non-overridable (the caller excludes a floor block from
 * the hook-override branches, and the floor lives in its own config field so a
 * remote /policies sync — which replaces only the SERVER rule set — can never delete
 * it). Byte-identical to the Python `evaluate_floor`.
 */
export function evaluateFloor(
  floorRules: PolicyRule[] | undefined,
  text: string,
  target: 'prompt' | 'response' = 'prompt',
  context?: PolicyEvalContext,
): PolicyDecisionResult {
  if (!floorRules || floorRules.length === 0) {
    return { decision: 'allow', reason_code: ReasonCode.PERMITTED };
  }
  const enforced = floorRules.map((r) => ({ ...r, enabled: true, mode: 'enforce' as const }));
  // The floor always resolves closed, failMode or not — the same rule
  // detector-guard.ts applies to the floor class: a floor is the operator's
  // non-overridable baseline, so a floor rule that CANNOT RUN is the strongest
  // form of "cannot guarantee". A floor quota the meter has no slot for
  // therefore blocks, where the same rule in policyRules would follow failMode.
  return evaluatePolicyRules(enforced, text, target, context, { failMode: 'closed' });
}

/**
 * Hash of the FLOOR definition (its own version, SEPARATE from
 * `derivePolicyVersion` so it does not perturb the frozen rules-hash
 * vectors). Stamped on events when a floor is active, so a change to the
 * floor definition is itself on the tamper-evident audit chain. "none" when
 * empty. Byte-identical to the Python `derive_floor_version`.
 */
export function deriveFloorVersion(floorRules: PolicyRule[] | undefined): string {
  if (!floorRules || floorRules.length === 0) return 'none';
  // Every floor rule enforces regardless of its declared enabled/mode, so the
  // hash is over the canonical projection with those coerced — a downgrade
  // attempt changes nothing the floor evaluates, and the hash reflects that.
  const coerced = floorRules
    .map((r) => canonicalRule({ ...r, enabled: true, mode: 'enforce' as const }))
    .sort((a, b) => (String(a.id) < String(b.id) ? -1 : String(a.id) > String(b.id) ? 1 : 0));
  return createHash('sha256').update(stableStringify(coerced)).digest('hex').slice(0, 16);
}

/** What a shadow rule would have done (EV-21). */
export interface ShadowOutcome {
  rule_id: string;
  would: 'block' | 'redact' | 'flag';
  /** Closed-vocabulary code for a would-have verdict (additive to `reason`). */
  reason_code: ReasonCode;
  reason: string;
}

/**
 * Evaluate ONLY the shadow-mode rules, after the active decision is
 * final. Same semantics as active evaluation but check-only (no quota
 * consumption, EV-20/22) and the result is a would-have record, never a
 * decision. Returns null when no shadow rule matched.
 */
export function evaluateShadowRules(
  rules: PolicyRule[],
  text: string,
  target: 'prompt' | 'response' = 'prompt',
  context?: PolicyEvalContext,
): ShadowOutcome | null {
  const shadowRules = rules.filter((r) => r.enabled && r.mode === 'shadow');
  if (shadowRules.length === 0) return null;
  // Re-mark as enforce so the evaluator does not skip them; checkOnly
  // guarantees the run is side-effect free.
  const activeShaped = shadowRules.map((r) => ({ ...r, mode: 'enforce' as const }));
  // No failMode here, deliberately: a shadow rule is defined as never
  // decision-affecting, and this surface is structurally always open (the same
  // reasoning recordCheckOnlyFailure states). Honouring failMode would let a
  // check-only unit block a call, which is the one thing shadow mode promises
  // it cannot do — so an unmeterable shadow quota stays a would-have record.
  const result = evaluatePolicyRules(activeShaped, text, target, context, { checkOnly: true });
  if (!result.rule_id) return null;
  const fired = shadowRules.find((r) => r.id === result.rule_id);
  // A matched topic_allow means "would have allowed": not a would-have
  // outcome worth recording.
  if (fired?.type === 'topic_allow') return null;
  const would =
    result.decision === 'block' ? 'block'
    : result.decision === 'redact' ? 'redact'
    : 'flag';
  return {
    rule_id: result.rule_id,
    would,
    reason_code: ReasonCode.SHADOW_WOULD_BLOCK,
    reason: result.reason ?? '',
  };
}
