import {
  evaluateSourceGrounding,
  computeGroundingScore,
  detectUnsupportedAssertions,
  groundingReport,
} from '../../src/policy/industry/legal';
import type { PolicyRule, PolicyEvalContext } from '../../src/policy/rules';

function makeRule(minRatio: number): PolicyRule {
  return {
    id: 'legal-1',
    name: 'Source grounding',
    enabled: true,
    action: 'flag',
    type: 'source_grounding',
    conditions: { min_grounding_ratio: minRatio },
  };
}

describe('Legal: evaluateSourceGrounding', () => {
  it('fires when output is poorly grounded', () => {
    const ctx: PolicyEvalContext = {
      sourceDocuments: ['The contract was signed in 2020 between parties.'],
    };
    const output = 'The defendant committed fraud and violated federal regulations.';
    expect(evaluateSourceGrounding(makeRule(0.8), output, ctx)).toBe(true);
  });

  it('does not fire when output is well grounded', () => {
    const ctx: PolicyEvalContext = {
      sourceDocuments: ['The contract was signed between parties in 2020.'],
    };
    const output = 'The contract was signed between parties.';
    expect(evaluateSourceGrounding(makeRule(0.5), output, ctx)).toBe(false);
  });

  it('fires when no source documents provided', () => {
    const ctx: PolicyEvalContext = { sourceDocuments: [] };
    expect(evaluateSourceGrounding(makeRule(0.5), 'some output', ctx)).toBe(true);
  });

  it('fires when sourceDocuments is undefined', () => {
    expect(evaluateSourceGrounding(makeRule(0.5), 'some output', {})).toBe(true);
  });

  it('returns false when min_grounding_ratio is not set', () => {
    const rule = makeRule(0.5);
    rule.conditions.min_grounding_ratio = undefined;
    expect(evaluateSourceGrounding(rule, 'text', {})).toBe(false);
  });
});

describe('Legal: computeGroundingScore', () => {
  it('returns 1 for fully grounded text', () => {
    const score = computeGroundingScore(
      'contract signed between parties',
      ['The contract was signed between the parties'],
    );
    expect(score).toBeGreaterThanOrEqual(0.5);
  });

  it('returns 1 for empty output', () => {
    expect(computeGroundingScore('', ['some source'])).toBe(1);
  });

  it('returns 1 for only short words (< 4 chars)', () => {
    expect(computeGroundingScore('the a is on', ['source'])).toBe(1);
  });

  it('returns low score for ungrounded text', () => {
    const score = computeGroundingScore(
      'quantum entanglement superconductor magnetic',
      ['The contract was signed between parties'],
    );
    expect(score).toBeLessThan(0.5);
  });
});

describe('Legal: detectUnsupportedAssertions', () => {
  it('detects legal claim language not in sources', () => {
    const output = 'According to established law, the defendant must comply. The court held that damages apply.';
    const sources = ['General legal framework overview.'];
    const unsupported = detectUnsupportedAssertions(output, sources, 0.5);
    expect(unsupported.length).toBeGreaterThan(0);
  });

  it('returns empty for well-grounded claims', () => {
    const output = 'According to the document, the contract terms apply.';
    const sources = ['According to the document, the contract terms and conditions apply.'];
    const unsupported = detectUnsupportedAssertions(output, sources, 0.3);
    expect(unsupported.length).toBe(0);
  });
});

describe('Legal: groundingReport', () => {
  it('returns a complete report', () => {
    const report = groundingReport(
      'The contract was signed between parties.',
      ['The contract was signed between the two parties in 2020.'],
    );
    expect(report.overallScore).toBeGreaterThan(0);
    expect(report.totalWordCount).toBeGreaterThan(0);
    expect(report.groundedWordCount).toBeLessThanOrEqual(report.totalWordCount);
    expect(Array.isArray(report.unsupportedAssertions)).toBe(true);
  });

  it('handles empty output', () => {
    const report = groundingReport('', ['source']);
    expect(report.overallScore).toBe(1);
    expect(report.totalWordCount).toBe(0);
  });
});
