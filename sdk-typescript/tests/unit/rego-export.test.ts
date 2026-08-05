import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { exportToRego } from '../../src/policy/rego-export';
import { evaluatePolicyRules, derivePolicyVersion, type PolicyRule, type PolicyEvalContext } from '../../src/policy/rules';

/**
 * One-way Rego export. Structural checks run always; a behavioral PARITY check
 * runs the generated bundle through `opa eval` and compares its decision to the
 * SDK evaluator.
 *
 * The parity half REQUIRES opa and fails without it — see the comment above
 * that describe block for why it is not allowed to skip quietly.
 * `scripts/install-opa.sh` installs the pinned binary; CI calls it wherever the
 * suite runs.
 */

function rule(p: Partial<PolicyRule> & Pick<PolicyRule, 'id' | 'type'>): PolicyRule {
  return { name: p.id, enabled: true, action: 'block', conditions: {}, ...p } as PolicyRule;
}

const RULES: PolicyRule[] = [
  rule({ id: 'kw-secret', type: 'keyword', conditions: { keywords: ['secret'] } }),
  rule({ id: 'topic-ok', type: 'topic_allow', conditions: { topics: ['weather'] } }),
  rule({ id: 're-ssn', type: 'regex', conditions: { pattern: '\\d{3}-\\d{2}-\\d{4}' } }),
  rule({ id: 'env-prod', type: 'environment_gate', action: 'block', conditions: { target_environments: ['production'] } }),
  rule({ id: 'model-deny', type: 'model_gate', conditions: { denied_models: ['gpt-3'] } }),
  rule({ id: 'quota-1', type: 'quota', conditions: { quota_limit: 10, quota_window_ms: 1000, quota_scope: 'project' } }),
  rule({ id: 'appr-1', type: 'action_gate', action: 'block', conditions: { action_types: ['wire'], require_approval: true } }),
  rule({ id: 'shadow-1', type: 'keyword', mode: 'shadow', conditions: { keywords: ['x'] } }),
  rule({ id: 're-lookahead', type: 'regex', conditions: { pattern: 'foo(?=bar)' } }),
  rule({ id: 'disabled-1', type: 'keyword', enabled: false, conditions: { keywords: ['y'] } }),
];

describe('exportToRego — structure', () => {
  const bundle = exportToRego(RULES);

  it('stamps the canonical rules_hash (matches policy_version)', () => {
    expect(bundle.rules_hash).toBe(derivePolicyVersion(RULES));
    expect(JSON.parse(bundle.manifest).rules_hash).toBe(bundle.rules_hash);
    expect(JSON.parse(bundle.data).obsvr.rules_hash).toBe(bundle.rules_hash);
  });

  it('exports the expressible rules and delegates the stateful/unsupported ones', () => {
    const exportedIds = JSON.parse(bundle.data).obsvr.rules.map((r: any) => r.id);
    expect(exportedIds).toEqual(expect.arrayContaining(['kw-secret', 'topic-ok', 're-ssn', 'env-prod', 'model-deny']));
    const delegatedIds = bundle.delegated.map((d) => d.rule_id);
    // quota + approval-gated + shadow + RE2-incompatible regex are delegated; disabled is dropped.
    expect(delegatedIds).toEqual(expect.arrayContaining(['quota-1', 'appr-1', 'shadow-1', 're-lookahead']));
    expect(exportedIds).not.toContain('disabled-1');
    expect(exportedIds).not.toContain('quota-1');
    expect(exportedIds).not.toContain('re-lookahead');
  });

  it('produces a Rego module with the documented entrypoint', () => {
    expect(bundle.rego).toContain('package obsvr.policy');
    expect(JSON.parse(bundle.manifest).entrypoint).toBe('data.obsvr.policy.decision');
    expect(bundle.readme).toContain('opa eval');
  });

  it('delegates action_gate rules with a threshold or time window', () => {
    // These cannot be faithfully expressed in the action-name-only Rego, so
    // exporting them would silently drop the threshold/time gate.
    const rules: PolicyRule[] = [
      rule({ id: 'ag-plain', type: 'action_gate', conditions: { action_types: ['delete'] } }),
      rule({ id: 'ag-threshold', type: 'action_gate', conditions: { action_types: ['wire'], threshold: { field: 'amount', operator: '>', value: 10000 } } }),
      rule({ id: 'ag-window', type: 'action_gate', conditions: { action_types: ['wire'], time_window: { allow_hours: [9, 17], timezone: 'UTC' } } }),
    ];
    const b = exportToRego(rules);
    const exportedIds = JSON.parse(b.data).obsvr.rules.map((r: any) => r.id);
    const delegatedIds = b.delegated.map((d) => d.rule_id);
    expect(exportedIds).toContain('ag-plain'); // plain action-name gate is faithfully exported
    expect(delegatedIds).toEqual(expect.arrayContaining(['ag-threshold', 'ag-window']));
    expect(exportedIds).not.toContain('ag-threshold');
    expect(exportedIds).not.toContain('ag-window');
  });

  it('emits provider-aware, case-insensitive substring matchers', () => {
    // model_gate keyed on allowed_providers is now expressible (previously
    // dropped → "always allow"); action_gate uses substring + lower() to match
    // the SDK evaluator instead of exact case-sensitive equality.
    expect(bundle.rego).toContain('rule.conditions.allowed_providers');
    expect(bundle.rego).toContain('_provider_allowed');
    expect(bundle.rego).toContain('contains(_lower(input.context.actionName), _lower(a))');
    expect(bundle.rego).toContain('startswith(_lower(input.context.model), _lower(denied))');
  });
});

// --- behavioral parity via opa eval ------------------------------------------
function opaAvailable(): boolean {
  try {
    execFileSync('opa', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}
const HAS_OPA = opaAvailable();

/**
 * The documented local opt-out, and the ONLY way this block goes quiet.
 * Nothing in CI sets it, so deleting the opa install step turns the parity
 * check red rather than silent.
 */
const PARITY_OPTIONAL = process.env.OBSVR_SKIP_OPA_PARITY === '1';

/** Proof the parity body was entered, not merely declared. See below. */
let opaEvaluations = 0;

/**
 * WHY THIS BLOCK IS NOT ALLOWED TO SKIP QUIETLY.
 *
 * These are the only assertions anywhere that the Rego bundle an operator
 * exports and the SDK's own evaluator reach the SAME verdict. Everything above
 * checks the bundle's STRUCTURE — that a rule was emitted, that a stateful one
 * was delegated — which a semantically wrong matcher passes cleanly.
 *
 * The block used to degrade, when opa was absent, to a test named "SKIPPED"
 * whose body was `expect(true).toBe(true)`, carrying a comment that parity
 * "runs in CI where opa is present". opa was installed in no workflow, no
 * script and no manifest, so the check had never executed anywhere while
 * reporting a pass on every run — a green tick standing in for a check that
 * did not exist.
 *
 * So a missing opa is a FAILURE here. A check that cannot run must not look
 * like a check that passed; the honest states are ran, skipped, or red, and
 * "absent" is not allowed to render as the first one.
 */
describe('exportToRego — behavioral parity with the SDK evaluator (opa eval)', () => {
  (PARITY_OPTIONAL ? it.skip : it)('has opa on PATH, so the parity cases below actually run', () => {
    if (!HAS_OPA) {
      throw new Error(
        'opa is not on PATH, so the Rego parity cases below did not run.\n' +
          'They are the only check that the exported bundle and the SDK evaluator agree, ' +
          'and they must not report green without executing.\n' +
          'Install it with scripts/install-opa.sh (CI does), or set OBSVR_SKIP_OPA_PARITY=1 ' +
          'to opt this local tree out — CI never sets it.',
      );
    }
  });

  // Honest skip, never a fake pass: an absent opa leaves these reported as
  // skipped while the gate above goes red.
  const parityIt = HAS_OPA ? it : it.skip;

  const bundle = exportToRego(RULES);

  function opaDecision(text: string, target: 'prompt' | 'response', context: PolicyEvalContext): string {
    const dir = mkdtempSync(join(tmpdir(), 'rego-'));
    try {
      writeFileSync(join(dir, 'p.rego'), bundle.rego);
      writeFileSync(join(dir, 'data.json'), bundle.data);
      writeFileSync(join(dir, 'input.json'), JSON.stringify({ text, target, context }));
      const out = execFileSync(
        'opa',
        ['eval', '-d', join(dir, 'p.rego'), '-d', join(dir, 'data.json'), '-i', join(dir, 'input.json'), 'data.obsvr.policy.decision'],
        { encoding: 'utf8' },
      );
      opaEvaluations += 1;
      return JSON.parse(out).result[0].expressions[0].value.decision;
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  // Only rules present in BOTH engines can be compared — exclude the delegated
  // ones (quota/approval/shadow) from the SDK reference set for parity.
  const exportedRuleIds = new Set(JSON.parse(bundle.data).obsvr.rules.map((r: any) => r.id));
  const sdkRules = RULES.filter((r) => exportedRuleIds.has(r.id));

  /**
   * THE CORPUS HAS TO BE ABLE TO DISAGREE, WHICH THE FIRST FIVE COULD NOT.
   *
   * Every original case was lowercase on both sides, so the exported matchers
   * and the SDK evaluator returned the same verdict whether or not the Rego
   * folded case at all: rewriting `contains(_lower(input.text), _lower(kw))`
   * to `contains(input.text, kw)` left all five green. That is a real semantic
   * divergence — an operator's exported bundle would miss `SECRET` where the
   * SDK blocks it — passing a check written to catch exactly this.
   *
   * The MIXED-CASE rows below are what make the folding load-bearing, one per
   * matcher the structural assertions claim is case-insensitive (keyword,
   * topic_allow, model_gate). The response-target row exercises the other
   * value of `input.target`, which nothing else here varied.
   */
  const cases: Array<[string, string, 'prompt' | 'response', PolicyEvalContext]> = [
    ['keyword blocks', 'this is a secret', 'prompt', {}],
    ['topic_allow short-circuits', 'the weather is nice', 'prompt', {}],
    ['no match allows', 'hello world', 'prompt', {}],
    ['regex ssn blocks', 'ssn 123-45-6789', 'prompt', {}],
    ['model_gate deny blocks', 'anything', 'prompt', { model: 'gpt-3-turbo' } as PolicyEvalContext],
    ['keyword folds case', 'this is a SECRET', 'prompt', {}],
    ['topic_allow folds case', 'The WEATHER is nice', 'prompt', {}],
    ['model_gate folds case', 'anything', 'prompt', { model: 'GPT-3-Turbo' } as PolicyEvalContext],
    ['regex blocks on the response target too', 'ssn 123-45-6789', 'response', {}],
  ];

  for (const [label, text, target, context] of cases) {
    parityIt(`matches the SDK decision: ${label}`, () => {
      const sdk = evaluatePolicyRules(sdkRules, text, target, context, { checkOnly: true }).decision;
      expect(opaDecision(text, target, context)).toBe(sdk);
    });
  }

  // Declared last so it observes the cases above (jest runs a describe body's
  // tests in declaration order). An assertion loop that silently iterates an
  // empty corpus is the same failure as the placeholder this file removed:
  // zero comparisons, reported green. This counts the opa invocations that
  // actually happened, so the corpus cannot shrink to nothing unnoticed.
  parityIt('evaluated every case in the corpus through opa', () => {
    expect(cases.length).toBeGreaterThanOrEqual(9);
    expect(opaEvaluations).toBe(cases.length);
  });

  // Parity over a corpus this small only means something if the corpus can
  // DISAGREE. If the two engines returned 'allow' everywhere, every assertion
  // above would hold while proving nothing about the exported matchers.
  parityIt('covers both verdicts, so agreement is not agreement on one answer', () => {
    const verdicts = new Set(
      cases.map(([, text, target, context]) =>
        evaluatePolicyRules(sdkRules, text, target, context, { checkOnly: true }).decision,
      ),
    );
    expect(verdicts.has('block')).toBe(true);
    expect(verdicts.has('allow')).toBe(true);
  });
});
