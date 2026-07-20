/**
 * Synchronous governance evaluation endpoint.
 * Core "governance-as-a-service" capability.
 *
 * @packageDocumentation
 */
import { randomUUID } from 'crypto';
import type { EvaluateRequest, EvaluateResponse, GovernanceDecision } from './types.js';
import { ReasonCode, mapLegacyDecision, ruleTypeToReasonCode } from './reason-codes.js';
import { issueExecutionToken } from './token.js';
import { getConfig, isInitialized, isPolicyEnforcementDegraded } from '../proxy/config.js';
import { evaluatePolicyRules, derivePolicyVersion, evaluateShadowRules, evaluateFloor, deriveFloorVersion } from '../policy/rules.js';
import type { PolicyEvalContext, ShadowOutcome } from '../policy/rules.js';
import {
  ENGINE_VERSION,
  buildDecisionInput,
  computeDecisionInputHash,
} from '../policy/decision-record.js';
import type { HookDisposition } from '../policy/decision-record.js';
import { evaluatePolicyHook, resolvePiiPolicy } from '../policy/hook.js';
import { runConfiguredPiiScan, escalateViewOnlyAction, redactForStorage } from '../policy/deobfuscate.js';
import type { DeobfuscationView } from '../policy/deobfuscate.js';
import { sendAuditAsync } from '../proxy/sender/fire-and-forget.js';
import type { ResolvedConfig } from '../proxy/types.js';
import type { AuditEvent } from '../proxy/types.js';

/**
 * Evaluate an action against the governance policy engine.
 * Returns a standardized PERMITTED/BLOCKED response with optional JWT execution token.
 */
export async function evaluate(
  request: EvaluateRequest,
  config?: ResolvedConfig
): Promise<EvaluateResponse> {
  const cfg = config ?? (isInitialized() ? getConfig() : undefined);
  if (!cfg) {
    throw new Error('Governance not initialized. Call obsvr.init() first or pass config directly.');
  }

  const now = Date.now();
  const nonce = randomUUID();
  const payloadText = JSON.stringify(request.payload);

  let decision: GovernanceDecision = 'PERMITTED';
  let reasonCode: ReasonCode = ReasonCode.PERMITTED;
  let reason: string | undefined;
  let ruleId: string | undefined;

  // 0. Enforcement-integrity gate (EV-3): blocks when the project is paused /
  //    the key is revoked (SDK kill switch) or failMode=closed policy-sync
  //    staleness. Mirrors the proxy wrapper / integrations / MCP gates
  //    exactly: the block is NOT customer-overridable, so PII scan, rules,
  //    and the customer hook are all skipped below.
  const degraded = isPolicyEnforcementDegraded(cfg);
  if (degraded.degraded) {
    decision = 'BLOCKED';
    reasonCode = ReasonCode.POLICY_VIOLATION;
    ruleId = `sdk:${degraded.reason}`;
    reason =
      degraded.reason === 'project_paused_or_key_revoked'
        ? 'Project paused or API key revoked (SDK kill switch)'
        : `Policy sync unavailable with failMode=closed (${degraded.reason})`;
  }

  // 1. PII scan (skipped when the integrity gate already blocked). With
  //    deobfuscation enabled the scanner also sees decoded/stripped views;
  //    a view-only redact resolution escalates to block (no locatable span).
  let piiVia: DeobfuscationView['method'] | undefined;
  let piiBlocked = false;
  if (decision === 'PERMITTED') {
    const piiResult = runConfiguredPiiScan(payloadText, cfg.deobfuscation);
    if (piiResult.pii_detected && cfg.pii_policy) {
      const piiDecision = resolvePiiPolicy(piiResult.detected_types, cfg.pii_policy);
      const piiAction = escalateViewOnlyAction(piiDecision.action, piiResult.via);
      if (piiAction === 'block') {
        decision = 'BLOCKED';
        reasonCode = ReasonCode.PII_DETECTED;
        piiBlocked = true;
        piiVia = piiResult.via;
        reason = `PII detected: ${piiResult.detected_types.join(', ')}${
          piiResult.via !== undefined ? ` (via ${piiResult.via})` : ''
        }`;
      }
    }
  }

  // 1.5. Anti-tamper policy FLOOR (mirrors applyPreCallPolicy step 1.4 and
  //      the proxy wrapper): the operator baseline is evaluated BEFORE the
  //      customer rules and the customer hook — both of which are guarded by
  //      `decision === 'PERMITTED'` below — so neither can un-block or
  //      downgrade a floor decision on this surface. enabled:false / mode:
  //      shadow floor rules still enforce (evaluateFloor coerces them). This
  //      closes the governance-endpoint bypass of the floor guarantee.
  const floorRules = cfg.policyFloor;
  const floorActive = !!(floorRules && floorRules.length > 0);
  if (decision === 'PERMITTED' && floorRules && floorRules.length > 0) {
    const floorResult = evaluateFloor(floorRules, payloadText, 'prompt', {
      actionName: request.action_type,
      metadata: {
        ...request.metadata,
        user_id: request.user_id,
        service_name: request.service_name,
        tenant_id: request.tenant_id,
      },
    });
    if (floorResult.decision === 'block' || floorResult.decision === 'redact') {
      // A floor redact is treated as BLOCKED for external consumers (parity
      // with the customer-rules redact branch below): governance emits a
      // permit/deny verdict, so an unlocatable-span redact fails closed.
      decision = 'BLOCKED';
      ruleId = floorResult.rule_id;
      reason = floorResult.reason;
      const matchedFloor = floorRules.find(r => r.id === floorResult.rule_id);
      reasonCode = matchedFloor ? ruleTypeToReasonCode(matchedFloor.type) : ReasonCode.POLICY_VIOLATION;
    }
  }

  // 2. Policy rules evaluation (only if not already blocked)
  if (decision === 'PERMITTED' && cfg.policyRules?.length) {
    const evalContext: PolicyEvalContext = {
      actionName: request.action_type,
      metadata: {
        ...request.metadata,
        user_id: request.user_id,
        service_name: request.service_name,
        tenant_id: request.tenant_id,
      },
    };

    const rulesResult = evaluatePolicyRules(
      cfg.policyRules,
      payloadText,
      'prompt',
      evalContext
    );

    if (rulesResult.decision === 'block') {
      decision = 'BLOCKED';
      ruleId = rulesResult.rule_id;
      reason = rulesResult.reason;
      // Try to derive specific reason code from rule
      if (rulesResult.rule_id) {
        const matchedRule = cfg.policyRules.find(r => r.id === rulesResult.rule_id);
        if (matchedRule) {
          reasonCode = ruleTypeToReasonCode(matchedRule.type);
        } else {
          reasonCode = ReasonCode.POLICY_VIOLATION;
        }
      } else {
        reasonCode = ReasonCode.POLICY_VIOLATION;
      }
    } else if (rulesResult.decision === 'redact') {
      // Redact is treated as BLOCKED for external consumers
      decision = 'BLOCKED';
      ruleId = rulesResult.rule_id;
      reason = rulesResult.reason;
      reasonCode = ReasonCode.POLICY_VIOLATION;
    }
  }

  // 3. Customer pre-call hook (only if not already blocked)
  // Hook disposition for the decision record (ADR-2): configured-but-not-run
  // (already blocked upstream) is "skipped"; outcomes overwrite it below.
  let hookDisposition: HookDisposition = cfg.on_pre_call ? 'skipped' : 'not_configured';
  if (decision === 'PERMITTED' && cfg.on_pre_call) {
    const hookEvent = {
      prompt: payloadText,
      operation: request.action_type,
      tenant_id: request.tenant_id,
    };
    const timeoutMs = cfg.hookTimeoutMs ?? 5000;
    const hookResult = await evaluatePolicyHook(cfg.on_pre_call, hookEvent, timeoutMs);
    if (hookResult === 'hook_timeout') {
      hookDisposition = 'timeout';
      decision = 'BLOCKED';
      reasonCode = ReasonCode.HOOK_TIMEOUT;
      reason = 'Policy hook timed out';
    } else if (hookResult.decision === 'block') {
      hookDisposition = 'block';
      decision = 'BLOCKED';
      reasonCode = ReasonCode.HOOK_BLOCKED;
      reason = hookResult.reason ?? 'Blocked by policy hook';
      ruleId = hookResult.rule_id;
    } else {
      hookDisposition = hookResult.decision === 'redact' ? 'redact' : 'allow';
    }
  }

  // 4. Issue execution token if permitted
  let executionToken: string | undefined;
  if (decision === 'PERMITTED') {
    try {
      executionToken = issueExecutionToken(cfg.api_key, {
        action: request.action_type,
        decision: 'PERMITTED',
        rule_id: ruleId,
      });
    } catch {
      // Token issuance failure should not block the decision
    }
  }

  const response: EvaluateResponse = {
    decision,
    reason_code: reasonCode,
    reason,
    rule_id: ruleId,
    timestamp: now,
    nonce,
    execution_token: executionToken,
  };

  // Canonical decision record (ADR-2): commit exactly what this evaluation
  // ran over. `payloadText` is the text the PII scan, rules, and hook saw.
  const decisionInput = buildDecisionInput({
    rulesHash: derivePolicyVersion(cfg.policyRules ?? []),
    degraded: degraded.degraded,
    degradedReason: degraded.reason,
    target: 'request',
    evaluatedText: payloadText,
    userId: request.user_id,
    serviceName: request.service_name,
    tenantId: request.tenant_id,
    hook: hookDisposition,
  });
  const decisionInputHash = computeDecisionInputHash(decisionInput);

  // 5. Emit audit event (fire-and-forget)
  try {
    const auditEvent: Partial<AuditEvent> = {
      request_id: nonce,
      environment: cfg.environment ?? 'production',
      provider: 'unknown',
      model: 'governance',
      operation: request.action_type,
      source: 'governance-evaluate',
      // A PII-caused block never stores the offending payload raw (parity
      // with every other blocked-event site): span-redacted for raw hits,
      // the whole-text placeholder for view-only hits (spans unlocatable).
      prompt: piiBlocked ? redactForStorage(payloadText, piiVia) : payloadText,
      response: JSON.stringify(response),
      event_type: decision === 'PERMITTED' ? 'llm_call' : 'blocked_call',
      action_taken: decision === 'PERMITTED' ? 'allowed' : 'blocked',
      action_reason: reasonCode === ReasonCode.PII_DETECTED ? 'pii_detected' :
                     decision === 'BLOCKED' ? 'policy_violation' : 'none',
      action_source: ruleId ? 'policy_rules' : 'unknown',
      policy_version: cfg.policyRules ? derivePolicyVersion(cfg.policyRules) : '',
      redacted_types: [],
      rule_id: ruleId,
      policy_reason: reason,
      tenant_id: request.tenant_id,
      // Canonical decision record (ADR-2, additive — not in the chain preimage)
      decision_input_hash: decisionInputHash,
      engine_version: ENGINE_VERSION,
      // Server-side normalizer mirror: seal which view defeated the obfuscation, and (when
      // a floor is active) the sealed floor-definition hash on EVERY event —
      // matching the proxy wrapper — so a change to the floor is auditable
      // from the allowed-event stream, not just blocks.
      ...(() => {
        const md: Record<string, unknown> = {};
        if (piiVia !== undefined) md.security_normalized = piiVia;
        if (floorActive) md.obsvr_telemetry = { floor_version: deriveFloorVersion(cfg.policyFloor) };
        return Object.keys(md).length ? { metadata: md } : {};
      })(),
    };
    sendAuditAsync(cfg, auditEvent as AuditEvent);
  } catch {
    // Audit emission failure should not affect the response
  }

  return response;
}

/** Result of a check-only explain() run (EV-22). */
export interface ExplainResult {
  decision: 'allow' | 'block' | 'redact';
  rule_id?: string;
  reason?: string;
  /** Canonical hash of the active rule set this explanation ran under. */
  rules_hash: string;
  /**
   * Sealed floor-definition hash (EV — anti-tamper floor). Only present when
   * `config.policyFloor` is non-empty; additive, absent otherwise so no-floor
   * explain() output is unchanged. A floor block/redact is reflected in
   * `decision` above and cannot be un-done by the customer rules.
   */
  floor_version?: string;
  pii: {
    detected: boolean;
    types: string[];
    /**
     * Which de-obfuscation view surfaced the hit (server-side normalizer mirror).
     * Only ever present when `config.deobfuscation.enabled` and the raw
     * text was clean — additive, absent otherwise.
     */
    via?: DeobfuscationView['method'];
  };
  shadow_outcome: ShadowOutcome | null;
  /** Steps explain() deliberately does not execute (advisory scope). */
  not_evaluated: Array<'customer_hook' | 'multi_turn_injection'>;
}

/**
 * Check-only policy explanation (EV-22): runs the same built-in PII scan
 * and structured-rule evaluation a real call would, but consumes no
 * quota, advances no injection-session state, files no approval
 * requests, and emits no audit events. Customer hooks are not invoked.
 * Safe to call from tests, dashboards, and CI.
 */
export function explain(
  text: string,
  options?: {
    target?: 'prompt' | 'response';
    metadata?: Record<string, unknown>;
    actionName?: string;
    config?: ResolvedConfig;
  },
): ExplainResult {
  const cfg = options?.config ?? (isInitialized() ? getConfig() : undefined);
  if (!cfg) {
    throw new Error('Governance not initialized. Call obsvr.init() first or pass config directly.');
  }
  const rules = cfg.policyRules ?? [];
  const result: ExplainResult = {
    decision: 'allow',
    rules_hash: derivePolicyVersion(rules),
    pii: { detected: false, types: [] },
    shadow_outcome: null,
    not_evaluated: ['customer_hook', 'multi_turn_injection'],
  };

  const piiResult = runConfiguredPiiScan(text, cfg.deobfuscation);
  result.pii = {
    detected: piiResult.pii_detected,
    types: piiResult.detected_types,
    ...(piiResult.via !== undefined ? { via: piiResult.via } : {}),
  };
  if (piiResult.pii_detected && cfg.pii_policy) {
    const piiDecision = resolvePiiPolicy(piiResult.detected_types, cfg.pii_policy);
    // Mirror the live pipeline: a view-only redact resolution escalates to
    // block (no locatable span), so explain() predicts the real outcome.
    const piiAction = escalateViewOnlyAction(piiDecision.action, piiResult.via);
    if (piiAction === 'block') {
      result.decision = 'block';
      result.reason = `PII detected: ${piiResult.detected_types.join(', ')}${
        piiResult.via !== undefined ? ` (via ${piiResult.via})` : ''
      }`;
    } else if (piiAction === 'redact') {
      result.decision = 'redact';
      result.reason = `PII would be redacted: ${piiResult.detected_types.join(', ')}`;
    }
  }

  // Anti-tamper policy floor: predicted exactly the way the live pipeline
  // enforces it (before the customer rules, coercing shadow/disabled floor
  // rules to enforce), so explain() never reports "allow" for an action a
  // floor would block. Present the sealed floor hash when a floor is active.
  const floorActive = !!(cfg.policyFloor && cfg.policyFloor.length > 0);
  if (floorActive) {
    result.floor_version = deriveFloorVersion(cfg.policyFloor);
    if (result.decision !== 'block') {
      const floorResult = evaluateFloor(cfg.policyFloor, text, options?.target ?? 'prompt', {
        actionName: options?.actionName,
        currentEnvironment: cfg.environment,
        metadata: options?.metadata ?? {},
      });
      if (floorResult.decision === 'block' || floorResult.decision === 'redact') {
        result.decision = floorResult.decision;
        result.rule_id = floorResult.rule_id;
        result.reason = floorResult.reason;
      }
    }
  }

  if (result.decision !== 'block' && rules.length > 0) {
    const evalCtx: PolicyEvalContext = {
      actionName: options?.actionName,
      currentEnvironment: cfg.environment,
      metadata: options?.metadata ?? {},
    };
    const rulesResult = evaluatePolicyRules(
      rules,
      text,
      options?.target ?? 'prompt',
      evalCtx,
      { checkOnly: true },
    );
    if (rulesResult.decision === 'block' || rulesResult.decision === 'redact') {
      result.decision = rulesResult.decision;
      result.rule_id = rulesResult.rule_id;
      result.reason = rulesResult.reason;
    } else if (rulesResult.rule_id && !result.rule_id) {
      result.rule_id = rulesResult.rule_id;
      result.reason = rulesResult.reason;
    }
  }

  result.shadow_outcome = evaluateShadowRules(
    rules,
    text,
    options?.target ?? 'prompt',
    { actionName: options?.actionName, currentEnvironment: cfg.environment, metadata: options?.metadata ?? {} },
  );

  return result;
}

/**
 * Convenience function: evaluate using the singleton config.
 */
export async function evaluateAction(
  actionType: string,
  payload: Record<string, unknown>,
  options?: { tenant_id?: string; user_id?: string; service_name?: string }
): Promise<EvaluateResponse> {
  return evaluate({
    action_type: actionType,
    payload,
    tenant_id: options?.tenant_id,
    user_id: options?.user_id,
    service_name: options?.service_name,
  });
}
