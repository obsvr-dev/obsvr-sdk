import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  buildApprovalAction,
  approvalActionHash,
  hasApproval,
  updateApprovals,
  _resetApprovals,
  type ApprovalGrant,
} from '../../src/policy/approvals';

/**
 * Cross-SDK approval-binding conformance (TS side). Twin:
 * sdk-python/tests/test_approvals_conformance.py.
 *
 * A grant scoped only to a rule id says someone approved something. These
 * cases pin the stronger claim: that a grant names the call it was issued for
 * and cannot be spent on another one that happens to trip the same rule.
 */

function findFixture(rel: string): string {
  let dir = process.cwd();
  for (let i = 0; i < 6; i++) {
    const candidate = path.join(dir, rel);
    if (fs.existsSync(candidate)) return candidate;
    dir = path.dirname(dir);
  }
  throw new Error(`fixture not found upward from ${process.cwd()}: ${rel}`);
}

interface ActionCase {
  id: string;
  desc?: string;
  /** Names a case this one is intentionally identical to. */
  same_as?: string;
  action: {
    rule_id: string;
    rule_hash: string;
    action_name?: unknown;
    amount?: unknown;
    caller_namespace?: unknown;
    target_namespace?: unknown;
    user_id?: unknown;
  };
  expect: { document: Record<string, unknown>; hash: string };
}
interface MatchCase {
  id: string;
  desc?: string;
  grants: ApprovalGrant[];
  claim: { rule_id: string; user_id?: string; rule_hash?: string; action_hash?: string };
  expect: boolean;
}

const fixture = JSON.parse(
  fs.readFileSync(findFixture('conformance/fixtures/approvals.json'), 'utf-8'),
) as { action_cases: ActionCase[]; match_cases: MatchCase[] };

/** Fixture actions use wire spelling; the TS input uses the SDK's own names. */
function toInput(a: ActionCase['action']) {
  return {
    ruleId: a.rule_id,
    ruleHash: a.rule_hash,
    actionName: a.action_name,
    amount: a.amount,
    callerNamespace: a.caller_namespace,
    targetNamespace: a.target_namespace,
    userId: a.user_id,
  };
}

describe('conformance: the canonical approval-action document', () => {
  for (const c of fixture.action_cases) {
    it(c.id, () => {
      expect(buildApprovalAction(toInput(c.action))).toEqual(c.expect.document);
      expect(approvalActionHash(toInput(c.action))).toBe(c.expect.hash);
    });
  }

  it('every distinct action in the corpus hashes distinctly', () => {
    // The whole point of the digest: two actions a human would describe
    // differently must not be interchangeable in a grant. Cases that declare
    // `same_as` are intentionally identical and are the only allowed
    // collisions, so an accidental one still fails here.
    const byHash = new Map<string, string[]>();
    for (const c of fixture.action_cases) {
      const h = approvalActionHash(toInput(c.action));
      byHash.set(h, [...(byHash.get(h) ?? []), c.id]);
    }
    const declared = new Map(
      fixture.action_cases.filter((c) => c.same_as).map((c) => [c.id, c.same_as as string]),
    );
    const unexpected = [...byHash.values()]
      .filter((ids) => ids.length > 1)
      .filter((ids) => !ids.every((id) => declared.get(id) !== undefined || ids.some((o) => declared.get(o) === id)));
    expect(unexpected).toEqual([]);
    // ...and every declared equivalence must actually hold.
    const hashOf = (id: string): string =>
      approvalActionHash(toInput(fixture.action_cases.find((c) => c.id === id)!.action));
    for (const [id, other] of declared) expect(hashOf(id)).toBe(hashOf(other));
  });
});

describe('conformance: grant matching', () => {
  afterEach(() => _resetApprovals());

  for (const c of fixture.match_cases) {
    it(c.id, () => {
      _resetApprovals();
      updateApprovals(c.grants);
      expect(
        hasApproval({
          ruleId: c.claim.rule_id,
          userId: c.claim.user_id,
          ruleHash: c.claim.rule_hash,
          actionHash: c.claim.action_hash,
        }),
      ).toBe(c.expect);
    });
  }
});
