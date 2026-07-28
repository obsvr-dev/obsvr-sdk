import { init, _reset, setTenantPolicy } from '../../src/proxy/config';
import { snapshotPolicy, getPolicyAtTime, emitPolicyChangedEvent, _resetPolicyLog } from '../../src/policy/policy-log';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import type { PolicyRule } from '../../src/policy/rules';

beforeEach(() => { _reset(); _resetSender(); _resetPolicyLog(); });

describe('policy log', () => {
  it('snapshotPolicy stores and retrieves snapshot', () => {
    const rules: PolicyRule[] = [{ id: 'r1', name: 'test', enabled: true, action: 'block', type: 'keyword', conditions: { keywords: ['bad'] } }];
    snapshotPolicy(rules);
    const after = new Date(Date.now() + 1000);
    const snap = getPolicyAtTime(after);
    expect(snap).not.toBeNull();
    expect(snap!.rules_snapshot).toBe(JSON.stringify(rules));
  });

  it('setTenantPolicy emits policy_changed event structure', () => {
    init({ api_key: 'test' });
    const rules: PolicyRule[] = [{ id: 'r1', name: 'block-bad', enabled: true, action: 'block', type: 'keyword', conditions: { keywords: ['bad'] } }];
    const event = emitPolicyChangedEvent([], rules, 'tenant1', 'admin');
    expect(event.event_type).toBe('policy_changed');
    expect(event.tenant_id).toBe('tenant1');
    expect(event.diff.added).toContain('r1');
    expect(event.previous_version).toBe('none'); // empty rules -> none
    expect(event.new_version).not.toBe('none'); // has rules
  });

  it('getPolicyAtTime returns null for time before any snapshot', () => {
    const pastTime = new Date(Date.now() - 100000);
    expect(getPolicyAtTime(pastTime)).toBeNull();
  });

  it('captures body-level field changes for modified rules', () => {
    const prev: PolicyRule[] = [{ id: 'r1', name: 'block-bad', enabled: true, action: 'block', type: 'keyword', conditions: { keywords: ['bad'] } }];
    const next: PolicyRule[] = [{ id: 'r1', name: 'block-bad', enabled: true, action: 'redact', type: 'keyword', conditions: { keywords: ['bad', 'worse'] } }];
    const event = emitPolicyChangedEvent(prev, next, 'tenant1', 'admin');

    expect(event.diff.modified).toEqual(['r1']);
    expect(event.diff.rule_changes).toHaveLength(1);
    const change = event.diff.rule_changes[0];
    expect(change.id).toBe('r1');
    const fields = change.fields.map((f) => f.field).sort();
    expect(fields).toEqual(['action', 'conditions']);
    const action = change.fields.find((f) => f.field === 'action')!;
    expect(action.from).toBe('block');
    expect(action.to).toBe('redact');
  });

  it('emits an ingest-valid event carrying the change payload in metadata', () => {
    const rules: PolicyRule[] = [{ id: 'r1', name: 'block-bad', enabled: true, action: 'block', type: 'keyword', conditions: { keywords: ['bad'] } }];
    const event = emitPolicyChangedEvent([], rules, 'tenant1', 'admin');

    // RawEventSchema requires these two; policy_version = new_version.
    expect(typeof event.request_id).toBe('string');
    expect(event.request_id.length).toBeGreaterThan(0);
    expect(event.model).toBe('');
    expect(event.policy_version).toBe(event.new_version);
    // The structured change rides in metadata (the channel canonical preserves).
    expect(event.metadata.policy_change.new_version).toBe(event.new_version);
    expect(event.metadata.policy_change.diff.added).toContain('r1');
  });
});
