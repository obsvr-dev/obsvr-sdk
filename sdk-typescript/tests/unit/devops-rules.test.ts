import {
  evaluateEnvironmentGate,
  LoopDetector,
  createLoopDetector,
  captureStateSnapshot,
  isRestrictedEnvironment,
} from '../../src/policy/industry/devops';
import type { PolicyRule, PolicyEvalContext } from '../../src/policy/rules';

function makeRule(envs: string[]): PolicyRule {
  return {
    id: 'devops-1',
    name: 'Environment gate',
    enabled: true,
    action: 'block',
    type: 'environment_gate',
    conditions: { target_environments: envs },
  };
}

describe('DevOps: evaluateEnvironmentGate', () => {
  it('fires when environment matches target', () => {
    const ctx: PolicyEvalContext = { currentEnvironment: 'production' };
    expect(evaluateEnvironmentGate(makeRule(['production']), ctx)).toBe(true);
  });

  it('does not fire for non-target environment', () => {
    const ctx: PolicyEvalContext = { currentEnvironment: 'development' };
    expect(evaluateEnvironmentGate(makeRule(['production']), ctx)).toBe(false);
  });

  it('returns false when no context', () => {
    expect(evaluateEnvironmentGate(makeRule(['production']))).toBe(false);
  });

  it('returns false when no target environments', () => {
    const ctx: PolicyEvalContext = { currentEnvironment: 'production' };
    expect(evaluateEnvironmentGate(makeRule([]), ctx)).toBe(false);
  });

  it('matches multiple environments', () => {
    const ctx: PolicyEvalContext = { currentEnvironment: 'staging' };
    expect(evaluateEnvironmentGate(makeRule(['production', 'staging']), ctx)).toBe(true);
  });
});

describe('DevOps: LoopDetector', () => {
  it('returns null when within limits', () => {
    const detector = new LoopDetector({
      maxIterations: 5,
      windowMs: 10000,
      action: 'block',
    });
    for (let i = 0; i < 5; i++) {
      expect(detector.recordIteration()).toBeNull();
    }
  });

  it('fires when exceeding maxIterations', () => {
    const detector = new LoopDetector({
      maxIterations: 3,
      windowMs: 10000,
      action: 'block',
    });
    detector.recordIteration();
    detector.recordIteration();
    detector.recordIteration();
    const result = detector.recordIteration();
    expect(result).not.toBeNull();
    expect(result!.action).toBe('block');
    expect(result!.iterationCount).toBe(4);
  });

  it('escalates instead of blocking when configured', () => {
    const detector = new LoopDetector({
      maxIterations: 2,
      windowMs: 10000,
      action: 'escalate',
    });
    detector.recordIteration();
    detector.recordIteration();
    const result = detector.recordIteration();
    expect(result).not.toBeNull();
    expect(result!.action).toBe('escalate');
  });

  it('getIterationCount returns current count', () => {
    const detector = new LoopDetector({
      maxIterations: 10,
      windowMs: 10000,
      action: 'block',
    });
    detector.recordIteration();
    detector.recordIteration();
    expect(detector.getIterationCount()).toBe(2);
  });

  it('reset clears state', () => {
    const detector = new LoopDetector({
      maxIterations: 10,
      windowMs: 10000,
      action: 'block',
    });
    detector.recordIteration();
    detector.recordIteration();
    detector.reset();
    expect(detector.getIterationCount()).toBe(0);
  });
});

describe('DevOps: createLoopDetector', () => {
  it('creates a LoopDetector instance', () => {
    const detector = createLoopDetector({
      maxIterations: 5,
      windowMs: 10000,
      action: 'block',
    });
    expect(detector).toBeInstanceOf(LoopDetector);
  });
});

describe('DevOps: captureStateSnapshot', () => {
  it('captures snapshot with metadata', () => {
    const snap = captureStateSnapshot('det-1', 5, { tool: 'kubectl' });
    expect(snap.detectorId).toBe('det-1');
    expect(snap.iterationCount).toBe(5);
    expect(snap.timestamp).toBeGreaterThan(0);
    expect(snap.metadata).toEqual({ tool: 'kubectl' });
  });
});

describe('DevOps: isRestrictedEnvironment', () => {
  it('returns true for production by default', () => {
    expect(isRestrictedEnvironment('production')).toBe(true);
  });

  it('returns false for development', () => {
    expect(isRestrictedEnvironment('development')).toBe(false);
  });

  it('uses custom restricted list', () => {
    expect(isRestrictedEnvironment('staging', ['staging', 'production'])).toBe(true);
  });
});
