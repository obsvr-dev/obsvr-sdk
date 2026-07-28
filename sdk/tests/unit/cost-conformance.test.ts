import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  resolveCallCost,
  priceTokens,
  costMetadata,
  longestPrefixKey,
  type CostPolicyConfig,
  type ResolvedCost,
} from '../../src/governance/cost';

/**
 * Cross-SDK layered-cost conformance (TS side). Twin:
 * sdk-python/tests/test_cost_conformance.py.
 *
 * The amounts are integer micro-units and the rounding rule is written out in
 * both languages rather than delegated to a built-in, so these cases are
 * exact: a difference of one micro-unit between the SDKs fails here.
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

interface ResolveCase {
  id: string;
  desc?: string;
  inputs: {
    policy?: CostPolicyConfig;
    model?: string;
    action_name?: string;
    caller_estimate_micros?: unknown;
    input_tokens?: unknown;
    output_tokens?: unknown;
  };
  expect: ResolvedCost;
}
interface PriceCase { id: string; tokens: number; micros_per_1k: number; expect: number }
interface MetadataCase { id: string; cost: ResolvedCost; expect: Record<string, unknown> }

const fixture = JSON.parse(
  fs.readFileSync(findFixture('conformance/fixtures/cost.json'), 'utf-8'),
) as { resolve_cases: ResolveCase[]; price_cases: PriceCase[]; metadata_cases: MetadataCase[] };

describe('conformance: layered cost resolution', () => {
  for (const c of fixture.resolve_cases) {
    it(c.id, () => {
      expect(
        resolveCallCost({
          policy: c.inputs.policy,
          model: c.inputs.model,
          actionName: c.inputs.action_name,
          callerEstimateMicros: c.inputs.caller_estimate_micros,
          inputTokens: c.inputs.input_tokens,
          outputTokens: c.inputs.output_tokens,
        }),
      ).toEqual(c.expect);
    });
  }
});

describe('conformance: rate arithmetic', () => {
  for (const c of fixture.price_cases) {
    it(c.id, () => {
      expect(priceTokens(c.tokens, c.micros_per_1k)).toBe(c.expect);
    });
  }
});

describe('conformance: what reaches the event', () => {
  for (const c of fixture.metadata_cases) {
    it(c.id, () => {
      expect(costMetadata(c.cost)).toEqual(c.expect);
    });
  }
});

describe('cost resolution: properties the fixture cases rest on', () => {
  it('the longest matching prefix is chosen and is unique', () => {
    const table = { 'gpt': 1, 'gpt-4': 2, 'gpt-4o': 3 };
    expect(longestPrefixKey(table, 'gpt-4o-mini')).toBe('gpt-4o');
    expect(longestPrefixKey(table, 'gpt-4-turbo')).toBe('gpt-4');
    expect(longestPrefixKey(table, 'gpt-3.5')).toBe('gpt');
    expect(longestPrefixKey(table, 'claude-3')).toBeUndefined();
    expect(longestPrefixKey(undefined, 'gpt-4')).toBeUndefined();
    expect(longestPrefixKey(table, '')).toBeUndefined();
  });

  it('an empty key never matches (it would match everything)', () => {
    expect(longestPrefixKey({ '': 1, 'gpt': 2 }, 'gpt-4')).toBe('gpt');
    expect(longestPrefixKey({ '': 1 }, 'anything')).toBeUndefined();
  });

  it('the delta is present only when both an estimate and a metered figure are', () => {
    const policy: CostPolicyConfig = {
      currency: 'USD',
      rates: { m: { input_micros_per_1k: 1000 } },
    };
    expect(resolveCallCost({ policy, model: 'm', inputTokens: 1000 }).delta_micros).toBeUndefined();
    expect(resolveCallCost({ callerEstimateMicros: 5 }).delta_micros).toBeUndefined();
    expect(
      resolveCallCost({ policy, model: 'm', inputTokens: 1000, callerEstimateMicros: 5 })
        .delta_micros,
    ).toBe(995);
  });

  it('keeps the estimate alongside the correction rather than replacing it', () => {
    // The whole argument for this living in an evidence product: the gap is
    // only auditable if both numbers survive to the record.
    const result = resolveCallCost({
      policy: { currency: 'USD', rates: { m: { input_micros_per_1k: 1000 } } },
      model: 'm',
      inputTokens: 10_000,
      callerEstimateMicros: 100,
    });
    expect(result.estimate_micros).toBe(100);
    expect(result.metered_micros).toBe(10_000);
    expect(result.delta_micros).toBe(9_900);
  });

  it('is pure: the same inputs resolve identically every time', () => {
    const inputs = {
      policy: { currency: 'USD', rates: { m: { input_micros_per_1k: 7 } } },
      model: 'm',
      inputTokens: 123,
      callerEstimateMicros: 1,
    };
    expect(resolveCallCost(inputs)).toEqual(resolveCallCost(inputs));
  });
});
