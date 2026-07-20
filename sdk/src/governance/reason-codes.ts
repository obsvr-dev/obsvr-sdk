/**
 * Closed registry of policy-verdict reason codes.
 *
 * This is the SINGLE shared source of the reason-code vocabulary for the
 * TypeScript SDK. Every policy verdict the engine emits carries a
 * `reason_code` drawn from this enum PLUS an optional free-form `reason`
 * detail (so no information is lost). The Python SDK mirrors this exact
 * set in obsvr/reason_codes.py, and both are pinned to the shared fixture
 * conformance/fixtures/reason_codes.json. A CI staleness check
 * (tests/unit/reason-codes.test.ts + sdk-python/tests/test_reason_codes.py)
 * fails if the two SDKs diverge, if either drifts from the fixture, or if
 * the engine can emit a code that is not in this registry.
 *
 * Values are stable, screaming-snake-case wire strings: they appear on
 * audit events and in the deterministic response contract, so renaming an
 * existing value is a breaking change. New codes are additive.
 */
export enum ReasonCode {
  PERMITTED = 'PERMITTED',
  TRANSMISSION_BLOCKED = 'TRANSMISSION_BLOCKED',
  DESTRUCTIVE_OPERATION_BLOCKED = 'DESTRUCTIVE_OPERATION_BLOCKED',
  QUOTA_EXCEEDED = 'QUOTA_EXCEEDED',
  PII_DETECTED = 'PII_DETECTED',
  POLICY_VIOLATION = 'POLICY_VIOLATION',
  NAMESPACE_VIOLATION = 'NAMESPACE_VIOLATION',
  CROSS_TENANT_BLOCKED = 'CROSS_TENANT_BLOCKED',
  ENVIRONMENT_BLOCKED = 'ENVIRONMENT_BLOCKED',
  SOURCE_GROUNDING_FAILED = 'SOURCE_GROUNDING_FAILED',
  TOPIC_BLOCKED = 'TOPIC_BLOCKED',
  KEYWORD_BLOCKED = 'KEYWORD_BLOCKED',
  REGEX_MATCHED = 'REGEX_MATCHED',
  MODEL_GATE_BLOCKED = 'MODEL_GATE_BLOCKED',
  HOOK_BLOCKED = 'HOOK_BLOCKED',
  HOOK_TIMEOUT = 'HOOK_TIMEOUT',
  TOOL_DENIED = 'TOOL_DENIED',
  DELEGATION_BLOCKED = 'DELEGATION_BLOCKED',
  LOOP_DETECTED = 'LOOP_DETECTED',
  APPROVAL_REQUIRED = 'APPROVAL_REQUIRED',
  APPROVAL_GRANTED = 'APPROVAL_GRANTED',
  SHADOW_WOULD_BLOCK = 'SHADOW_WOULD_BLOCK',
  INJECTION_DETECTED = 'INJECTION_DETECTED',
  EXTERNAL_BACKEND_DENY = 'EXTERNAL_BACKEND_DENY',
  MCP_TOOL_DENIED = 'MCP_TOOL_DENIED',
  MCP_RESULT_BLOCKED = 'MCP_RESULT_BLOCKED',
  UNKNOWN_BLOCKED = 'UNKNOWN_BLOCKED',
}

/**
 * The full closed registry as a frozen, sorted array of wire strings.
 * Runtime mirror of the enum for the CI staleness check and for callers
 * that need to validate an inbound code against the vocabulary.
 */
export const REASON_CODES: readonly string[] = Object.freeze(
  (Object.values(ReasonCode) as string[]).slice().sort(),
);

/**
 * Canonical PolicyRule-type -> ReasonCode mapping. Every enforceable rule
 * type has an explicit entry; this is pinned in the shared fixture so TS
 * and Python classify a fired rule identically. Adding a rule type without
 * adding a mapping here (and in the Python twin + fixture) fails CI.
 */
export const RULE_TYPE_TO_REASON_CODE: Readonly<Record<string, ReasonCode>> = Object.freeze({
  keyword: ReasonCode.KEYWORD_BLOCKED,
  regex: ReasonCode.REGEX_MATCHED,
  topic_deny: ReasonCode.TOPIC_BLOCKED,
  topic_allow: ReasonCode.PERMITTED,
  pii: ReasonCode.PII_DETECTED,
  action_gate: ReasonCode.POLICY_VIOLATION,
  namespace_isolation: ReasonCode.NAMESPACE_VIOLATION,
  cross_tenant_block: ReasonCode.CROSS_TENANT_BLOCKED,
  destructive_op_gate: ReasonCode.DESTRUCTIVE_OPERATION_BLOCKED,
  source_grounding: ReasonCode.SOURCE_GROUNDING_FAILED,
  environment_gate: ReasonCode.ENVIRONMENT_BLOCKED,
  quota: ReasonCode.QUOTA_EXCEEDED,
  model_gate: ReasonCode.MODEL_GATE_BLOCKED,
});

/** Map a legacy PolicyRule type to a ReasonCode */
export function ruleTypeToReasonCode(ruleType: string): ReasonCode {
  return RULE_TYPE_TO_REASON_CODE[ruleType] ?? ReasonCode.UNKNOWN_BLOCKED;
}

/** Map legacy 'allow'|'block'|'redact' decision + optional context to standardized form */
export function mapLegacyDecision(
  decision: 'allow' | 'block' | 'redact',
  context?: { rule_type?: string; reason?: string; action_reason?: string }
): { decision: GovernanceDecision; reason_code: ReasonCode } {
  if (decision === 'allow') {
    return { decision: 'PERMITTED', reason_code: ReasonCode.PERMITTED };
  }

  // Map to specific reason code based on context
  if (context?.rule_type) {
    return { decision: 'BLOCKED', reason_code: ruleTypeToReasonCode(context.rule_type) };
  }
  if (context?.action_reason === 'pii_detected') {
    return { decision: 'BLOCKED', reason_code: ReasonCode.PII_DETECTED };
  }
  if (context?.reason?.includes('hook')) {
    return { decision: 'BLOCKED', reason_code: ReasonCode.HOOK_BLOCKED };
  }

  return { decision: 'BLOCKED', reason_code: ReasonCode.UNKNOWN_BLOCKED };
}

// Import from types (circular-safe since this is just the enum)
import type { GovernanceDecision } from './types.js';
