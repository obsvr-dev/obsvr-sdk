import {
  CoverageRequirementsError,
  assertCoverageRequirements,
  coverageRequirementFailures,
} from '../../src/governance/coverage-attestation';
import { assertEnforcementBoundary } from '../../src/governance/enforcement-smoke';

describe('runtime coverage requirements', () => {
  const snapshot = {
    langchain: {
      model: { bound: true, enforcementDepth: 'enforce' as const },
      tracing: { bound: true, enforcementDepth: 'observe' as const },
    },
  };

  it('requires exact symbols at enforce depth', () => {
    expect(() => assertCoverageRequirements([
      { integration: 'langchain', minimum_depth: 'enforce', symbols: ['model'] },
    ], snapshot)).not.toThrow();

    const failures = coverageRequirementFailures([
      { integration: 'langchain', minimum_depth: 'enforce', symbols: ['tracing', 'tools'] },
    ], snapshot);
    expect(failures).toEqual([
      expect.objectContaining({ symbol: 'tools', reason: 'missing' }),
      expect.objectContaining({ symbol: 'tracing', reason: 'insufficient_depth' }),
    ]);
    expect(() => assertCoverageRequirements([
      { integration: 'langchain', minimum_depth: 'enforce', symbols: ['tracing'] },
    ], snapshot)).toThrow(CoverageRequirementsError);
  });

  it('proves a caller factory deny reaches zero downstream calls', async () => {
    let transportCalls = 0;
    const result = await assertEnforcementBoundary({
      name: 'spotdraft-ai-factory',
      invokeBlockedCall: async () => {
        throw new Error('blocked by policy');
      },
      transportCalls: () => transportCalls,
    });
    expect(result).toEqual({
      name: 'spotdraft-ai-factory',
      blocked: true,
      transport_calls: 0,
    });
  });

  it('fails when a claimed deny still reaches transport', async () => {
    let transportCalls = 0;
    await expect(assertEnforcementBoundary({
      name: 'bypassed-factory',
      invokeBlockedCall: async () => {
        transportCalls++;
        throw new Error('too late');
      },
      transportCalls: () => transportCalls,
    })).rejects.toThrow(/reached downstream transport/);
  });
});
