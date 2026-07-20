import {
  updateApprovals,
  hasApproval,
  _resetApprovals,
} from '../../src/policy/approvals';
import {
  evaluatePolicyRules,
  deriveRuleHash,
  PolicyRule,
} from '../../src/policy/rules';

/**
 * Approval pinning: a grant minted under one rule definition must not
 * satisfy the rule after it is edited (hash mismatch voids the grant).
 * Legacy grants without a hash stay honored.
 */

const FUTURE = new Date(Date.now() + 3600_000).toISOString();

const rule: PolicyRule = {
  id: 'r-gate',
  name: 'Dangerous op gate',
  enabled: true,
  action: 'block',
  type: 'action_gate',
  conditions: { require_approval: true, action_types: ['delete'] },
};

afterEach(() => _resetApprovals());

describe('hasApproval with rule hash pinning', () => {
  it('honors a grant whose hash matches the current rule', () => {
    const hash = deriveRuleHash(rule);
    updateApprovals([{ id: 'g1', rule_id: 'r-gate', expires_at: FUTURE, rule_hash: hash }]);
    expect(hasApproval('r-gate', undefined, hash)).toBe(true);
  });

  it('voids a grant minted under a different rule definition', () => {
    const oldHash = deriveRuleHash({ ...rule, name: 'Old name' });
    const currentHash = deriveRuleHash(rule);
    expect(oldHash).not.toBe(currentHash);
    updateApprovals([{ id: 'g1', rule_id: 'r-gate', expires_at: FUTURE, rule_hash: oldHash }]);
    expect(hasApproval('r-gate', undefined, currentHash)).toBe(false);
  });

  it('honors legacy grants without a hash', () => {
    updateApprovals([{ id: 'g1', rule_id: 'r-gate', expires_at: FUTURE }]);
    expect(hasApproval('r-gate', undefined, deriveRuleHash(rule))).toBe(true);
  });
});

describe('evaluatePolicyRules approval flow', () => {
  it('blocks with rule_hash when no grant exists', () => {
    const result = evaluatePolicyRules([rule], 'please delete everything', 'prompt', {
      action_name: 'delete',
    } as never);
    expect(result.decision).toBe('block');
    expect(result.approval_required).toBe(true);
    expect(result.rule_hash).toBe(deriveRuleHash(rule));
  });

  it('allows when a matching-hash grant exists, blocks again after rule edit', () => {
    updateApprovals([
      { id: 'g1', rule_id: 'r-gate', expires_at: FUTURE, rule_hash: deriveRuleHash(rule) },
    ]);
    const allowed = evaluatePolicyRules([rule], 'please delete everything', 'prompt', {
      action_name: 'delete',
    } as never);
    expect(allowed.decision).toBe('allow');

    // The rule is edited: same id, different definition. The old grant
    // must no longer bind.
    const edited: PolicyRule = {
      ...rule,
      conditions: { ...rule.conditions, action_types: ['delete', 'drop'] },
    };
    const blocked = evaluatePolicyRules([edited], 'please delete everything', 'prompt', {
      action_name: 'delete',
    } as never);
    expect(blocked.decision).toBe('block');
    expect(blocked.approval_required).toBe(true);
  });
});
