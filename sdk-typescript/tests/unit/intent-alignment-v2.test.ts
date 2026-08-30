import * as fs from 'node:fs';
import * as path from 'node:path';
import { buildActionContextV2 } from '../../src/governance/action-context-v2';
import {
  IntentAlignmentV2ValidationError,
  buildIntentPolicyV2,
  canonicalizeIntentPolicyV2,
  evaluateIntentAlignmentV2,
  intentPolicyV2Hash,
  type IntentPolicyV2Input,
} from '../../src/policy/intent-alignment-v2';

function findFixture(relative: string): string {
  let directory = process.cwd();
  for (let index = 0; index < 6; index += 1) {
    const candidate = path.join(directory, relative);
    if (fs.existsSync(candidate)) return candidate;
    directory = path.dirname(directory);
  }
  throw new Error(`fixture not found: ${relative}`);
}

const FIXTURE = JSON.parse(fs.readFileSync(
  findFixture('conformance/fixtures/intent_alignment_v2.json'), 'utf8',
)) as {
  claimable: boolean;
  base_context: Record<string, any>;
  base_policy: IntentPolicyV2Input;
  policy_expect: { document: object; canonical: string; hash: string };
  cases: Array<{ id: string; target: string; expect: object }>;
};
const LAYERED = JSON.parse(fs.readFileSync(
  findFixture('conformance/fixtures/action_context_layers_v2.json'), 'utf8',
)) as { input: Record<string, any> };

describe('v2 intent alignment', () => {
  it('normalizes raw policy targets to hashes only', () => {
    expect(FIXTURE.claimable).toBe(false);
    const document = buildIntentPolicyV2(FIXTURE.base_policy);
    expect(document).toEqual(FIXTURE.policy_expect.document);
    expect(canonicalizeIntentPolicyV2(FIXTURE.base_policy))
      .toBe(FIXTURE.policy_expect.canonical);
    expect(intentPolicyV2Hash(FIXTURE.base_policy)).toBe(FIXTURE.policy_expect.hash);
    expect(JSON.stringify(document)).not.toContain('workspace/租户🚀');
    expect(JSON.stringify(document)).not.toContain('allowed_targets');
  });

  for (const case_ of FIXTURE.cases) {
    it(case_.id, () => {
      const context = structuredClone(FIXTURE.base_context);
      context.current_action.target = case_.target;
      expect(evaluateIntentAlignmentV2({
        context: context as any,
        policy: FIXTURE.base_policy,
        base_result: { action_taken: 'allowed' },
      })).toEqual(case_.expect);
    });
  }

  it('evaluates an already canonical v2 context and policy identically', () => {
    const raw = evaluateIntentAlignmentV2({
      context: FIXTURE.base_context as any,
      policy: FIXTURE.base_policy,
      base_result: { action_taken: 'allowed' },
    });
    expect(evaluateIntentAlignmentV2({
      context: buildActionContextV2(FIXTURE.base_context as any),
      policy: buildIntentPolicyV2(FIXTURE.base_policy),
      base_result: { action_taken: 'allowed' },
    })).toEqual(raw);
  });

  it('preserves optional layers when a canonical context is revalidated', () => {
    const raw = evaluateIntentAlignmentV2({
      context: LAYERED.input as any,
      policy: FIXTURE.base_policy,
      base_result: { action_taken: 'allowed' },
    });
    expect(evaluateIntentAlignmentV2({
      context: buildActionContextV2(LAYERED.input as any),
      policy: FIXTURE.base_policy,
      base_result: { action_taken: 'allowed' },
    })).toEqual(raw);
  });

  it('caps policy sets and identifiers and rejects surrogates', () => {
    const setOverflow = structuredClone(FIXTURE.base_policy) as any;
    setOverflow.intent_scopes[0].allowed_targets = Array.from(
      { length: 65 }, (_, index) => `target-${index}`,
    );
    expect(() => buildIntentPolicyV2(setOverflow)).toThrow(IntentAlignmentV2ValidationError);
    const identifier = structuredClone(FIXTURE.base_policy) as any;
    identifier.intent_scopes[0].intent_id = 'x'.repeat(257);
    expect(() => buildIntentPolicyV2(identifier)).toThrow(IntentAlignmentV2ValidationError);
    const surrogate = structuredClone(FIXTURE.base_policy) as any;
    surrogate.intent_scopes[0].allowed_targets = ['\ud800'];
    expect(() => buildIntentPolicyV2(surrogate)).toThrow(IntentAlignmentV2ValidationError);
  });
});
