import { ReasonCode, mapLegacyDecision, ruleTypeToReasonCode } from '../../src/governance/reason-codes';

describe('ReasonCode', () => {
  it('has all expected codes', () => {
    expect(ReasonCode.PERMITTED).toBe('PERMITTED');
    expect(ReasonCode.TRANSMISSION_BLOCKED).toBe('TRANSMISSION_BLOCKED');
    expect(ReasonCode.QUOTA_EXCEEDED).toBe('QUOTA_EXCEEDED');
    expect(ReasonCode.PII_DETECTED).toBe('PII_DETECTED');
    expect(ReasonCode.TOOL_DENIED).toBe('TOOL_DENIED');
  });
});

describe('ruleTypeToReasonCode', () => {
  it('maps known rule types', () => {
    expect(ruleTypeToReasonCode('keyword')).toBe(ReasonCode.KEYWORD_BLOCKED);
    expect(ruleTypeToReasonCode('regex')).toBe(ReasonCode.REGEX_MATCHED);
    expect(ruleTypeToReasonCode('quota')).toBe(ReasonCode.QUOTA_EXCEEDED);
    expect(ruleTypeToReasonCode('destructive_op_gate')).toBe(ReasonCode.DESTRUCTIVE_OPERATION_BLOCKED);
    expect(ruleTypeToReasonCode('environment_gate')).toBe(ReasonCode.ENVIRONMENT_BLOCKED);
  });

  it('returns UNKNOWN_BLOCKED for unknown types', () => {
    expect(ruleTypeToReasonCode('nonexistent')).toBe(ReasonCode.UNKNOWN_BLOCKED);
  });
});

describe('mapLegacyDecision', () => {
  it('maps allow to PERMITTED', () => {
    const result = mapLegacyDecision('allow');
    expect(result.decision).toBe('PERMITTED');
    expect(result.reason_code).toBe(ReasonCode.PERMITTED);
  });

  it('maps block to BLOCKED with context', () => {
    const result = mapLegacyDecision('block', { rule_type: 'keyword' });
    expect(result.decision).toBe('BLOCKED');
    expect(result.reason_code).toBe(ReasonCode.KEYWORD_BLOCKED);
  });

  it('maps block with pii context', () => {
    const result = mapLegacyDecision('block', { action_reason: 'pii_detected' });
    expect(result.decision).toBe('BLOCKED');
    expect(result.reason_code).toBe(ReasonCode.PII_DETECTED);
  });

  it('maps block with hook context', () => {
    const result = mapLegacyDecision('block', { reason: 'blocked by hook' });
    expect(result.decision).toBe('BLOCKED');
    expect(result.reason_code).toBe(ReasonCode.HOOK_BLOCKED);
  });

  it('maps redact to BLOCKED', () => {
    const result = mapLegacyDecision('redact');
    expect(result.decision).toBe('BLOCKED');
    expect(result.reason_code).toBe(ReasonCode.UNKNOWN_BLOCKED);
  });
});
