import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { buildActionContext, type ActionContextInput } from '../../src/governance/action-context';
import {
  IntentAlignmentValidationError,
  buildIntentPolicy,
  canonicalizeIntentPolicy,
  evaluateIntentAlignment,
  intentPolicyHash,
  type IntentAlignmentResult,
  type IntentBaseResult,
  type IntentPolicyInput,
} from '../../src/policy/intent-alignment';

function findFixture(rel: string): string {
  let dir = process.cwd();
  for (let i = 0; i < 6; i++) {
    const candidate = path.join(dir, rel);
    if (fs.existsSync(candidate)) return candidate;
    dir = path.dirname(dir);
  }
  throw new Error(`fixture not found upward from ${process.cwd()}: ${rel}`);
}

type Target = 'context' | 'policy' | 'base_result';
interface Mutation {
  target?: Target;
  path: Array<string | number>;
  value?: unknown;
  delete?: boolean;
}
interface ValidCase {
  id: string;
  context_form?: 'document';
  mutations: Mutation[];
  expect: Partial<IntentAlignmentResult> & Pick<IntentAlignmentResult, 'outcome' | 'reason_code'>;
}
interface InvalidPolicyCase {
  id: string;
  mutation: Mutation;
}
interface InvalidBaseCase {
  id: string;
  mutation?: Mutation;
  second_mutation?: Mutation;
  mutations?: Mutation[];
}

const FIXTURE = JSON.parse(
  fs.readFileSync(findFixture('conformance/fixtures/intent_alignment.json'), 'utf8'),
) as {
  claimable: boolean;
  description: string;
  base_context: ActionContextInput;
  base_result: IntentBaseResult;
  base_policy: IntentPolicyInput;
  policy_expect: { canonical: string; hash: string };
  expected_defaults: Pick<
    IntentAlignmentResult,
    'engine_version' | 'context_hash' | 'policy_hash' | 'evaluator_hash'
  >;
  valid_cases: ValidCase[];
  invalid_policy_cases: InvalidPolicyCase[];
  invalid_base_cases: InvalidBaseCase[];
};

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function mutate(root: unknown, mutation: Mutation): void {
  let cursor = root;
  for (const segment of mutation.path.slice(0, -1)) {
    cursor = (cursor as Record<string | number, unknown>)[segment];
  }
  const last = mutation.path[mutation.path.length - 1];
  if (mutation.delete === true) {
    delete (cursor as Record<string | number, unknown>)[last];
  } else {
    (cursor as Record<string | number, unknown>)[last] = mutation.value;
  }
}

function materialize(case_: ValidCase) {
  const roots = {
    context: clone(FIXTURE.base_context),
    policy: clone(FIXTURE.base_policy),
    base_result: clone(FIXTURE.base_result),
  };
  for (const mutation of case_.mutations) {
    mutate(roots[mutation.target as Target], mutation);
  }
  return {
    context: case_.context_form === 'document'
      ? buildActionContext(roots.context)
      : roots.context,
    policy: roots.policy,
    base_result: roots.base_result,
  };
}

describe('Obsvr-authored intent alignment', () => {
  it('pins a local, normalized policy without claiming official vectors', () => {
    expect(FIXTURE.claimable).toBe(false);
    expect(FIXTURE.description).toContain('not an official AARM conformance vector');
    const canonical = canonicalizeIntentPolicy(FIXTURE.base_policy);
    expect(Buffer.from(canonical, 'utf8')).toEqual(
      Buffer.from(FIXTURE.policy_expect.canonical, 'utf8'),
    );
    expect(buildIntentPolicy(FIXTURE.base_policy)).toEqual(
      JSON.parse(FIXTURE.policy_expect.canonical),
    );
    expect(intentPolicyHash(FIXTURE.base_policy)).toBe(FIXTURE.policy_expect.hash);
    expect(createHash('sha256').update(canonical, 'utf8').digest('hex'))
      .toBe(FIXTURE.policy_expect.hash);
  });

  for (const case_ of FIXTURE.valid_cases) {
    it(case_.id, () => {
      const expected = { ...FIXTURE.expected_defaults, ...case_.expect };
      expect(evaluateIntentAlignment(materialize(case_))).toEqual(expected);
    });
  }

  it('covers all five compatibility outcomes', () => {
    expect(new Set(FIXTURE.valid_cases.map((case_) => case_.expect.outcome)))
      .toEqual(new Set(['ALLOW', 'DENY', 'MODIFY', 'STEP_UP', 'DEFER']));
  });

  it('binds approval details into the evaluation input hash', () => {
    const first = FIXTURE.valid_cases.find((case_) => case_.id === 'approval_required');
    const second = FIXTURE.valid_cases.find(
      (case_) => case_.id === 'approval_binding_changes_input_hash',
    );
    expect(first?.expect.input_hash).toBeDefined();
    expect(second?.expect.input_hash).toBeDefined();
    expect(first?.expect.input_hash).not.toBe(second?.expect.input_hash);
  });

  for (const case_ of FIXTURE.invalid_policy_cases) {
    it(`rejects policy ${case_.id}`, () => {
      const policy = clone(FIXTURE.base_policy);
      mutate(policy, case_.mutation);
      expect(() => buildIntentPolicy(policy)).toThrow(IntentAlignmentValidationError);
    });
  }

  for (const case_ of FIXTURE.invalid_base_cases) {
    it(`rejects base result ${case_.id}`, () => {
      const base = clone(FIXTURE.base_result);
      if (case_.mutation) mutate(base, case_.mutation);
      if (case_.second_mutation) mutate(base, case_.second_mutation);
      for (const mutation of case_.mutations ?? []) mutate(base, mutation);
      expect(() => evaluateIntentAlignment({
        context: FIXTURE.base_context,
        policy: FIXTURE.base_policy,
        base_result: base,
      })).toThrow(IntentAlignmentValidationError);
    });
  }
});
