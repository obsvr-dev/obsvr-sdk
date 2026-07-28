/**
 * Agentic industry policy module.
 *
 * Provides delegation tracking with an in-memory graph, circular chain
 * detection, and depth limit enforcement.
 *
 * @packageDocumentation
 */

/**
 * Tracks agent-to-agent delegation chains.
 * Maintains an in-memory directed graph of delegation relationships.
 */
export class DelegationTracker {
  private readonly maxDepth: number;
  private readonly allowedDelegates: string[] | undefined;
  private readonly blockCircular: boolean;
  /** Adjacency list: delegator → delegatee */
  private readonly graph = new Map<string, Set<string>>();
  /** Active chain for the current execution */
  private activeChain: string[] = [];

  constructor(config: {
    maxDepth: number;
    allowedDelegates?: string[];
    blockCircular: boolean;
  }) {
    this.maxDepth = config.maxDepth;
    this.allowedDelegates = config.allowedDelegates;
    this.blockCircular = config.blockCircular;
  }

  /**
   * Record a delegation from one agent to another.
   * Returns a violation if depth, circularity, or allowlist rules are broken.
   */
  recordDelegation(
    fromAgent: string,
    toAgent: string,
  ): DelegationViolation | null {
    // Allowlist check
    if (this.allowedDelegates && !this.allowedDelegates.includes(toAgent)) {
      return {
        type: 'not_allowed',
        message: `Agent "${toAgent}" is not in the allowed delegates list`,
        chain: [...this.activeChain, toAgent],
        depth: this.activeChain.length + 1,
      };
    }

    // Circular delegation check
    if (this.blockCircular && this.activeChain.includes(toAgent)) {
      return {
        type: 'circular',
        message: `Circular delegation detected: ${[...this.activeChain, toAgent].join(' → ')}`,
        chain: [...this.activeChain, toAgent],
        depth: this.activeChain.length + 1,
      };
    }

    // Depth limit check
    if (this.activeChain.length >= this.maxDepth) {
      return {
        type: 'depth_exceeded',
        message: `Delegation depth ${this.activeChain.length + 1} exceeds max ${this.maxDepth}`,
        chain: [...this.activeChain, toAgent],
        depth: this.activeChain.length + 1,
      };
    }

    // Record the delegation
    if (!this.graph.has(fromAgent)) {
      this.graph.set(fromAgent, new Set());
    }
    this.graph.get(fromAgent)!.add(toAgent);
    this.activeChain.push(toAgent);

    return null;
  }

  /**
   * Pop the last delegate from the active chain (delegation returned).
   */
  returnFromDelegation(): void {
    this.activeChain.pop();
  }

  /**
   * Get the current delegation chain.
   */
  getChain(): string[] {
    return [...this.activeChain];
  }

  /**
   * Get the current delegation depth.
   */
  getDepth(): number {
    return this.activeChain.length;
  }

  /**
   * Check if a delegation would create a circular reference.
   */
  wouldCreateCircular(toAgent: string): boolean {
    return this.activeChain.includes(toAgent);
  }

  /**
   * Reset the tracker state.
   */
  reset(): void {
    this.graph.clear();
    this.activeChain = [];
  }
}

/**
 * Delegation violation details.
 */
export interface DelegationViolation {
  type: 'circular' | 'depth_exceeded' | 'not_allowed';
  message: string;
  chain: string[];
  depth: number;
}

/**
 * Create a DelegationTracker from an AgentPolicy's delegationPolicy config.
 */
export function createDelegationTracker(config: {
  maxDepth: number;
  allowedDelegates?: string[];
  blockCircular: boolean;
}): DelegationTracker {
  return new DelegationTracker(config);
}

/**
 * Validate a delegation chain for circular references.
 */
export function hasCircularDelegation(chain: string[]): boolean {
  const seen = new Set<string>();
  for (const agent of chain) {
    if (seen.has(agent)) return true;
    seen.add(agent);
  }
  return false;
}
