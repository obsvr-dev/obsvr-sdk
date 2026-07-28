/**
 * One-way Rego (OPA) EXPORT of the Obsvr policy rule set.
 *
 * This is an INTEROP artifact, NOT a second evaluator and NOT a migration: the
 * Obsvr SDK rules engine (rules.ts) remains the single source of truth. Export
 * lets a buyer who standardizes on OPA run Obsvr's deterministic rule subset in
 * their own `opa eval` pipeline, and lets us answer "do you support OPA?" with a
 * fixture-provable yes — without adopting a policy language (the team's
 * documented "NEVER build a policy language" stance stays intact because this is
 * read-only, one-way, and generated).
 *
 * Design: rather than code-generate bespoke Rego per rule (brittle), we emit a
 * FIXED Rego module that interprets the rules carried as `data.obsvr.rules`, and
 * a `data.json` holding the enabled rules + the canonical rules_hash. The module
 * reproduces the SDK's first-match semantics (EV-8) over the
 * cleanly-expressible rule types. Stateful/contextual rules that pure Rego
 * cannot decide — `quota`, approval-gated blocks (`require_approval`), and
 * `source_grounding` — are DELEGATED: excluded from the Rego decision and listed
 * in the bundle's delegation manifest with `decision: "delegated"`, so the
 * export never silently mis-decides a rule it cannot faithfully evaluate.
 *
 * RE2 caveat: OPA's `regex.match` is RE2; `regex`-type rules using lookarounds
 * or backreferences will not translate and are flagged in the manifest.
 */

import type { PolicyRule } from './rules.js';
import { derivePolicyVersion } from './rules.js';

/** Rule types pure Rego can faithfully decide in this export. */
const EXPRESSIBLE_TYPES = new Set([
  'keyword',
  'regex',
  'topic_deny',
  'topic_allow',
  'environment_gate',
  'model_gate',
  'namespace_isolation',
  'cross_tenant_block',
  'destructive_op_gate',
  'action_gate',
]);

/** Why a rule is delegated to the Obsvr SDK rather than exported to Rego. */
export interface DelegatedRule {
  rule_id: string;
  type: string;
  reason: string;
}

export interface RegoExportBundle {
  /** The fixed Rego interpreter module (package obsvr.policy). */
  rego: string;
  /** data.json: { rules: [...enabled expressible rules...], rules_hash }. */
  data: string;
  /** Bundle manifest: rules_hash, counts, and the delegation list. */
  manifest: string;
  /** README explaining the bundle, entrypoint, and delegated rules. */
  readme: string;
  /** Canonical rules_hash of the FULL enabled set (matches policy_version). */
  rules_hash: string;
  /** Rules pure Rego cannot faithfully decide (enforced by the Obsvr SDK). */
  delegated: DelegatedRule[];
}

/** A `regex` pattern is RE2-incompatible if it uses lookaround or backreferences. */
function isRe2Incompatible(pattern: string): boolean {
  return /\(\?[=!<]/.test(pattern) || /\\[1-9]/.test(pattern);
}

/** Decide whether a rule is exportable to Rego or must be delegated. */
function classify(rule: PolicyRule): DelegatedRule | null {
  if (rule.type === 'quota') {
    return { rule_id: rule.id, type: rule.type, reason: 'stateful: quota counters are enforced by the Obsvr SDK at runtime' };
  }
  if (rule.type === 'source_grounding') {
    return { rule_id: rule.id, type: rule.type, reason: 'requires grounded-ratio computation over source documents; enforced by the Obsvr SDK' };
  }
  if (rule.action === 'block' && rule.conditions.require_approval === true) {
    return { rule_id: rule.id, type: rule.type, reason: 'stateful: approval-grant state is held by the Obsvr SDK; the block/allow outcome depends on a live grant' };
  }
  if (!EXPRESSIBLE_TYPES.has(rule.type)) {
    return { rule_id: rule.id, type: rule.type, reason: 'rule type is not expressible in the Rego export' };
  }
  // action_gate with a numeric threshold or a time window depends on the request
  // amount / the current wall-clock in a specific timezone. The fixed Rego module
  // only matches action names, so exporting such a rule would silently drop the
  // threshold/time gate (e.g. "wire > $10k out of hours" → "block every wire").
  // Delegate it rather than mis-decide (the module's stated guarantee).
  if (
    rule.type === 'action_gate' &&
    (rule.conditions.threshold !== undefined || rule.conditions.time_window !== undefined)
  ) {
    return {
      rule_id: rule.id,
      type: rule.type,
      reason:
        'action_gate uses a numeric threshold or time window that pure Rego cannot faithfully evaluate; enforced by the Obsvr SDK',
    };
  }
  if (rule.type === 'regex' && rule.conditions.pattern && isRe2Incompatible(rule.conditions.pattern)) {
    return { rule_id: rule.id, type: rule.type, reason: 'regex uses lookaround/backreferences that OPA RE2 does not support' };
  }
  return null;
}

/**
 * The fixed Rego interpreter. Package `obsvr.policy`; entrypoint
 * `data.obsvr.policy.decision`. Reproduces evaluatePolicyRules first-match
 * semantics over data.obsvr.rules for the expressible subset.
 *
 * Input document shape:
 *   { "text": "<prompt or response>",
 *     "target": "prompt" | "response",
 *     "context": { "currentEnvironment": "...", "model": "...", "provider": "...",
 *                  "callerNamespace": "...", "targetNamespace": "...",
 *                  "actionName": "...", "amount": <number> } }
 */
const REGO_MODULE = `# GENERATED by @obsvr/sdk rego-export — do not edit by hand.
# Faithful, one-way export of the Obsvr policy engine's deterministic rule
# subset. Source of truth remains the Obsvr SDK; regenerate on rule changes.
package obsvr.policy

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# Rules ride in data.obsvr.rules as an ordered array (enabled, enforce-mode,
# expressible rules only — see the bundle manifest for delegated rules).
rules := data.obsvr.rules

_lower(s) := lower(s)

# applies_to gate: default/both, or matches input.target.
_applies(rule) if not rule.applies_to
_applies(rule) if rule.applies_to == "both"
_applies(rule) if rule.applies_to == input.target

# --- per-type match predicates -------------------------------------------------
_match(rule) if {
  rule.type == "keyword"
  some kw in rule.conditions.keywords
  contains(_lower(input.text), _lower(kw))
}
_match(rule) if {
  rule.type == "regex"
  regex.match(rule.conditions.pattern, input.text)
}
_match(rule) if {
  rule.type in {"topic_deny", "topic_allow"}
  some t in rule.conditions.topics
  contains(_lower(input.text), _lower(t))
}
_match(rule) if {
  rule.type == "environment_gate"
  input.context.currentEnvironment in rule.conditions.target_environments
}
_match(rule) if {
  rule.type == "destructive_op_gate"
  some op in rule.conditions.destructive_operations
  contains(_lower(input.text), _lower(op))
}
_match(rule) if {
  rule.type == "destructive_op_gate"
  some op in rule.conditions.destructive_operations
  contains(_lower(input.context.actionName), _lower(op))
}
_match(rule) if {
  rule.type in {"namespace_isolation", "cross_tenant_block"}
  input.context.callerNamespace != input.context.targetNamespace
}
_match(rule) if {
  rule.type == "model_gate"
  some denied in rule.conditions.denied_models
  startswith(_lower(input.context.model), _lower(denied))
}
_match(rule) if {
  rule.type == "model_gate"
  count(rule.conditions.allowed_models) > 0
  not _model_allowed(rule)
}
_model_allowed(rule) if {
  some allowed in rule.conditions.allowed_models
  startswith(_lower(input.context.model), _lower(allowed))
}
# model_gate keyed on allowed_providers: fires when the provider is not listed.
_match(rule) if {
  rule.type == "model_gate"
  count(rule.conditions.allowed_providers) > 0
  not _provider_allowed(rule)
}
_provider_allowed(rule) if {
  some p in rule.conditions.allowed_providers
  _lower(input.context.provider) == _lower(p)
}
# action_gate: case-insensitive SUBSTRING match on the action name, matching the
# SDK evaluator (threshold/time-window variants are delegated, not exported).
_match(rule) if {
  rule.type == "action_gate"
  some a in rule.conditions.action_types
  contains(_lower(input.context.actionName), _lower(a))
}

# --- first-match decision ------------------------------------------------------
_hits contains i if {
  some i
  rule := rules[i]
  _applies(rule)
  _match(rule)
}

_first := min(_hits)

_outcome(rule) := {"decision": "allow", "rule_id": rule.id, "reason": rule.name} if rule.type == "topic_allow"
_outcome(rule) := {"decision": "block", "rule_id": rule.id, "reason": rule.name} if {
  rule.type != "topic_allow"
  rule.action == "block"
}
_outcome(rule) := {"decision": "redact", "rule_id": rule.id, "reason": rule.name} if {
  rule.type != "topic_allow"
  rule.action == "redact"
}
_outcome(rule) := {"decision": "allow", "rule_id": rule.id, "reason": rule.name} if {
  rule.type != "topic_allow"
  rule.action == "flag"
}

default decision := {"decision": "allow"}
decision := _outcome(rules[_first]) if count(_hits) > 0
`;

/**
 * Compile a policy rule set into an OPA/Rego bundle. Returns the fixed Rego
 * interpreter, a data.json of the exported (enabled, expressible, enforce-mode)
 * rules, a manifest (rules_hash + delegation list), and a README. The rules_hash
 * is the canonical policy_version over the FULL enabled set, so an auditor can
 * tie the bundle back to a specific Obsvr policy version.
 */
export function exportToRego(rules: PolicyRule[]): RegoExportBundle {
  const rulesHash = derivePolicyVersion(rules);
  const delegated: DelegatedRule[] = [];
  const exported: PolicyRule[] = [];

  for (const rule of rules) {
    if (!rule.enabled) continue; // disabled rules do not participate (matches SDK)
    if (rule.mode === 'shadow') {
      delegated.push({ rule_id: rule.id, type: rule.type, reason: 'shadow-mode rule: records would-have outcomes; not enforced' });
      continue;
    }
    const d = classify(rule);
    if (d) {
      delegated.push(d);
      continue;
    }
    exported.push(rule);
  }

  const data = JSON.stringify({ obsvr: { rules: exported, rules_hash: rulesHash } }, null, 2);

  const manifest = JSON.stringify(
    {
      format: 'obsvr-rego-export-v1',
      generated_at: new Date().toISOString(),
      entrypoint: 'data.obsvr.policy.decision',
      rules_hash: rulesHash,
      exported_rule_count: exported.length,
      delegated_rule_count: delegated.length,
      delegated,
      note: 'One-way export. The Obsvr SDK remains the source of truth. Delegated rules are enforced by the Obsvr SDK at runtime and are intentionally absent from the Rego decision.',
    },
    null,
    2,
  );

  const readme = [
    '# Obsvr Rego (OPA) policy export',
    '',
    `Canonical Obsvr policy version (rules_hash): \`${rulesHash}\``,
    '',
    'This bundle is a **one-way export** of the Obsvr policy engine for use in an',
    'OPA pipeline. The Obsvr SDK remains the source of truth; regenerate this',
    'bundle whenever the policy changes.',
    '',
    '## Files',
    '- `obsvr_policy.rego` — fixed interpreter, package `obsvr.policy`.',
    '- `data.json` — the exported rules under `data.obsvr.rules` + `rules_hash`.',
    '- `manifest.json` — rules_hash, counts, and the delegated-rule list.',
    '',
    '## Evaluate',
    '```',
    'opa eval -d obsvr_policy.rego -d data.json \\',
    '  -i input.json \'data.obsvr.policy.decision\'',
    '```',
    'where `input.json` is `{ "text": "...", "target": "prompt", "context": { ... } }`.',
    '',
    `## Delegated rules (${delegated.length})`,
    delegated.length === 0
      ? 'None — the entire enabled rule set is expressible in this export.'
      : 'These rules are **enforced by the Obsvr SDK at runtime** and are intentionally',
    ...(delegated.length === 0 ? [] : delegated.map((d) => `- \`${d.rule_id}\` (${d.type}) — ${d.reason}`)),
    ...(delegated.length === 0 ? [] : ['', 'absent from the Rego decision, so the export never mis-decides a rule it cannot faithfully evaluate.']),
    '',
  ].join('\n');

  return { rego: REGO_MODULE, data, manifest, readme, rules_hash: rulesHash, delegated };
}
