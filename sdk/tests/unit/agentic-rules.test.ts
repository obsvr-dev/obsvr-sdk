import {
  DelegationTracker,
  createDelegationTracker,
  hasCircularDelegation,
} from '../../src/policy/industry/agentic';

describe('Agentic: DelegationTracker', () => {
  it('allows valid delegation within depth limit', () => {
    const tracker = new DelegationTracker({
      maxDepth: 3,
      blockCircular: true,
    });
    expect(tracker.recordDelegation('agent-a', 'agent-b')).toBeNull();
    expect(tracker.getChain()).toEqual(['agent-b']);
    expect(tracker.getDepth()).toBe(1);
  });

  it('allows multi-level delegation within limits', () => {
    const tracker = new DelegationTracker({
      maxDepth: 3,
      blockCircular: true,
    });
    expect(tracker.recordDelegation('a', 'b')).toBeNull();
    expect(tracker.recordDelegation('b', 'c')).toBeNull();
    expect(tracker.recordDelegation('c', 'd')).toBeNull();
    expect(tracker.getDepth()).toBe(3);
  });

  it('blocks when depth exceeds maxDepth', () => {
    const tracker = new DelegationTracker({
      maxDepth: 2,
      blockCircular: true,
    });
    tracker.recordDelegation('a', 'b');
    tracker.recordDelegation('b', 'c');
    const violation = tracker.recordDelegation('c', 'd');
    expect(violation).not.toBeNull();
    expect(violation!.type).toBe('depth_exceeded');
    expect(violation!.depth).toBe(3);
  });

  it('blocks circular delegation when blockCircular is true', () => {
    const tracker = new DelegationTracker({
      maxDepth: 10,
      blockCircular: true,
    });
    tracker.recordDelegation('a', 'b');
    tracker.recordDelegation('b', 'c');
    const violation = tracker.recordDelegation('c', 'b');
    expect(violation).not.toBeNull();
    expect(violation!.type).toBe('circular');
    expect(violation!.chain).toEqual(['b', 'c', 'b']);
  });

  it('allows circular when blockCircular is false', () => {
    const tracker = new DelegationTracker({
      maxDepth: 10,
      blockCircular: false,
    });
    tracker.recordDelegation('a', 'b');
    tracker.recordDelegation('b', 'c');
    expect(tracker.recordDelegation('c', 'b')).toBeNull();
  });

  it('blocks delegation to non-allowed delegate', () => {
    const tracker = new DelegationTracker({
      maxDepth: 5,
      allowedDelegates: ['agent-b', 'agent-c'],
      blockCircular: true,
    });
    const violation = tracker.recordDelegation('a', 'agent-x');
    expect(violation).not.toBeNull();
    expect(violation!.type).toBe('not_allowed');
  });

  it('allows delegation to allowed delegate', () => {
    const tracker = new DelegationTracker({
      maxDepth: 5,
      allowedDelegates: ['agent-b', 'agent-c'],
      blockCircular: true,
    });
    expect(tracker.recordDelegation('a', 'agent-b')).toBeNull();
  });

  it('returnFromDelegation pops the chain', () => {
    const tracker = new DelegationTracker({
      maxDepth: 5,
      blockCircular: true,
    });
    tracker.recordDelegation('a', 'b');
    tracker.recordDelegation('b', 'c');
    expect(tracker.getDepth()).toBe(2);
    tracker.returnFromDelegation();
    expect(tracker.getDepth()).toBe(1);
    expect(tracker.getChain()).toEqual(['b']);
  });

  it('wouldCreateCircular detects future circular', () => {
    const tracker = new DelegationTracker({
      maxDepth: 10,
      blockCircular: true,
    });
    tracker.recordDelegation('a', 'b');
    expect(tracker.wouldCreateCircular('b')).toBe(true);
    expect(tracker.wouldCreateCircular('c')).toBe(false);
  });

  it('reset clears all state', () => {
    const tracker = new DelegationTracker({
      maxDepth: 5,
      blockCircular: true,
    });
    tracker.recordDelegation('a', 'b');
    tracker.recordDelegation('b', 'c');
    tracker.reset();
    expect(tracker.getDepth()).toBe(0);
    expect(tracker.getChain()).toEqual([]);
  });
});

describe('Agentic: createDelegationTracker', () => {
  it('creates a DelegationTracker instance', () => {
    const tracker = createDelegationTracker({
      maxDepth: 3,
      blockCircular: true,
    });
    expect(tracker).toBeInstanceOf(DelegationTracker);
  });
});

describe('Agentic: hasCircularDelegation', () => {
  it('detects circular chain', () => {
    expect(hasCircularDelegation(['a', 'b', 'c', 'b'])).toBe(true);
  });

  it('returns false for non-circular chain', () => {
    expect(hasCircularDelegation(['a', 'b', 'c', 'd'])).toBe(false);
  });

  it('handles empty chain', () => {
    expect(hasCircularDelegation([])).toBe(false);
  });

  it('detects self-reference', () => {
    expect(hasCircularDelegation(['a', 'a'])).toBe(true);
  });
});
