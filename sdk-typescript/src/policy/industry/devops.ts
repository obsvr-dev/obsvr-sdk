/**
 * DevOps industry policy module.
 *
 * Provides environment gating (block actions in production),
 * loop detection (sliding-window counter), and state snapshot capture.
 *
 * @packageDocumentation
 */

import type { PolicyRule, PolicyEvalContext } from '../rules.js';

/**
 * Evaluate environment gate: fires when the current environment matches
 * one of the restricted target environments.
 */
export function evaluateEnvironmentGate(
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
 * Sliding-window loop detector.
 *
 * Tracks iteration timestamps in a rolling window. When the number of
 * iterations within `windowMs` exceeds `maxIterations`, the detector
 * fires.
 */
export class LoopDetector {
  private readonly maxIterations: number;
  private readonly windowMs: number;
  private readonly action: 'block' | 'escalate';
  private timestamps: number[] = [];

  constructor(config: { maxIterations: number; windowMs: number; action: 'block' | 'escalate' }) {
    this.maxIterations = config.maxIterations;
    this.windowMs = config.windowMs;
    this.action = config.action;
  }

  /**
   * Record a new iteration. Returns the action to take if the loop
   * threshold is exceeded, or null if within limits.
   */
  recordIteration(): { action: 'block' | 'escalate'; iterationCount: number } | null {
    const now = Date.now();
    this.timestamps.push(now);

    // Prune timestamps outside the window
    const cutoff = now - this.windowMs;
    this.timestamps = this.timestamps.filter((t) => t >= cutoff);

    if (this.timestamps.length > this.maxIterations) {
      return { action: this.action, iterationCount: this.timestamps.length };
    }
    return null;
  }

  /**
   * Get the current iteration count within the window.
   */
  getIterationCount(): number {
    const now = Date.now();
    const cutoff = now - this.windowMs;
    this.timestamps = this.timestamps.filter((t) => t >= cutoff);
    return this.timestamps.length;
  }

  /**
   * Reset the detector state.
   */
  reset(): void {
    this.timestamps = [];
  }
}

/**
 * Create a LoopDetector from an AgentPolicy's loopDetection config.
 */
export function createLoopDetector(
  config: { maxIterations: number; windowMs: number; action: 'block' | 'escalate' },
): LoopDetector {
  return new LoopDetector(config);
}

/**
 * Capture a state snapshot for debugging loop behavior.
 */
export function captureStateSnapshot(
  detectorId: string,
  iterationCount: number,
  metadata?: Record<string, unknown>,
): {
  detectorId: string;
  iterationCount: number;
  timestamp: number;
  metadata?: Record<string, unknown>;
} {
  return {
    detectorId,
    iterationCount,
    timestamp: Date.now(),
    metadata,
  };
}

/**
 * Check if an environment is considered restricted.
 */
export function isRestrictedEnvironment(
  environment: string,
  restrictedList: string[] = ['production'],
): boolean {
  return restrictedList.includes(environment);
}
