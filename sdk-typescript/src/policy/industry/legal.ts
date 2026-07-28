/**
 * Legal industry policy module.
 *
 * Provides source grounding scoring - measures how well an LLM output
 * is grounded in provided source documents. Flags unsupported assertions.
 *
 * @packageDocumentation
 */

import type { PolicyRule, PolicyEvalContext } from '../rules.js';

/**
 * Evaluate source grounding: flags when output is insufficiently grounded
 * in source documents.
 */
export function evaluateSourceGrounding(
  rule: PolicyRule,
  text: string,
  context?: PolicyEvalContext,
): boolean {
  const minRatio = rule.conditions.min_grounding_ratio;
  if (minRatio === undefined) return false;
  const sources = context?.sourceDocuments;
  if (!sources || sources.length === 0) return true; // no sources = ungrounded
  const score = computeGroundingScore(text, sources);
  return score < minRatio;
}

/**
 * Compute a grounding score: fraction of output words (>3 chars) found
 * in the concatenated source documents.
 *
 * Returns a value between 0 and 1. A score of 1 means every substantive
 * word in the output appears in the source documents.
 */
export function computeGroundingScore(output: string, sources: string[]): number {
  const outputWords = output
    .toLowerCase()
    .split(/\s+/)
    .filter((w) => w.length > 3);
  if (outputWords.length === 0) return 1;
  const sourceText = sources.join(' ').toLowerCase();
  const grounded = outputWords.filter((w) => sourceText.includes(w));
  return grounded.length / outputWords.length;
}

/**
 * Detect unsupported assertions in LLM output by finding sentences that
 * contain strong claim language but have low source grounding.
 */
export function detectUnsupportedAssertions(
  output: string,
  sources: string[],
  threshold: number = 0.5,
): string[] {
  const CLAIM_PATTERNS = [
    /\b(?:according to|based on|it is established that)\b/i,
    /\b(?:the court held|the statute requires|the law states)\b/i,
    /\b(?:must|shall|is required to|is obligated to)\b/i,
    /\b(?:in\s+\w+\s+v\.\s+\w+)\b/i, // case citations
  ];

  const sentences = output.split(/[.!?]+/).filter((s) => s.trim().length > 10);
  const unsupported: string[] = [];

  for (const sentence of sentences) {
    const trimmed = sentence.trim();
    const hasClaim = CLAIM_PATTERNS.some((p) => p.test(trimmed));
    if (!hasClaim) continue;

    const score = computeGroundingScore(trimmed, sources);
    if (score < threshold) {
      unsupported.push(trimmed);
    }
  }

  return unsupported;
}

/**
 * Compute a detailed grounding report for an output against source documents.
 */
export function groundingReport(
  output: string,
  sources: string[],
): {
  overallScore: number;
  unsupportedAssertions: string[];
  groundedWordCount: number;
  totalWordCount: number;
} {
  const outputWords = output
    .toLowerCase()
    .split(/\s+/)
    .filter((w) => w.length > 3);
  const totalWordCount = outputWords.length;
  if (totalWordCount === 0) {
    return {
      overallScore: 1,
      unsupportedAssertions: [],
      groundedWordCount: 0,
      totalWordCount: 0,
    };
  }
  const sourceText = sources.join(' ').toLowerCase();
  const groundedWordCount = outputWords.filter((w) => sourceText.includes(w)).length;
  const overallScore = groundedWordCount / totalWordCount;
  const unsupportedAssertions = detectUnsupportedAssertions(output, sources);

  return {
    overallScore,
    unsupportedAssertions,
    groundedWordCount,
    totalWordCount,
  };
}
