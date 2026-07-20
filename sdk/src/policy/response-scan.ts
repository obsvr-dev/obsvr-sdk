/**
 * MCP tool-RESULT governance (ADR-6, response-side interception).
 *
 * MCP governance historically scanned only the discovery (tools/list) and
 * request (tools/call arguments) phases. But the tool RESULT is the
 * exfiltration / poisoning channel: a compromised or confused-deputy tool can
 * return PII, secrets, or injection payloads that flow straight back into the
 * model's context. This module is the response twin of the request-side
 * scanner — it evaluates the SAME policy rules (response target) and the SAME
 * built-in PII / secret / injection scanner against the tool result, then
 * decides:
 *
 *   BLOCK    — a blocked pattern (a `block` policy rule, or a PII/secret type
 *              resolved to `block`) is present: the result is withheld from the
 *              caller entirely. Unlike an LLM response, a tool result has NOT
 *              yet reached the model, so blocking is a real, enforceable control.
 *   SANITIZE — a `redact` outcome: the offending spans are redacted from the
 *              result before it reaches the caller (redact wins nothing over a
 *              block; block dominates).
 *   ALLOW    — clean, or detect-only: the result passes through unchanged and is
 *              audited.
 *
 * Matching runs on the §6-normalized copy (via evaluatePolicyRules /
 * runBuiltinPiiScan); the returned/sanitized content is only ever redacted,
 * never normalized. Used by the MCP client-patch integration
 * (integrations/mcp.ts), and behavior matches the Python twin
 * (obsvr/response_scan.py).
 *
 * @packageDocumentation
 */

import type { ResolvedConfig } from "../proxy/types.js";
import { resolvePiiPolicy, redactBuiltinPii } from "./hook.js";
import { runConfiguredPiiScan, escalateViewOnlyAction } from "./deobfuscate.js";
import type { DeobfuscationView } from "./deobfuscate.js";
import { scanForCanary, canaryRegistrySize, canaryLeakTelemetry } from "./canary.js";
import { evaluatePolicyRules, derivePolicyVersion } from "./rules.js";
import type { PolicyEvalContext } from "./rules.js";

/**
 * Authenticated caller identity, when the MCP layer resolved one. Threaded into
 * the response decision context (so user/service/tenant-scoped rules apply) and
 * stamped on the audit event.
 */
export interface McpPrincipal {
  user_id?: string;
  service_name?: string;
  tenant_id?: string;
}

/** Verdict for a governed MCP tool result. */
export interface McpResponseScan {
  /** What to do with the result before it reaches the caller. */
  action: "allow" | "block" | "sanitize";
  event_type: "tool_call" | "blocked_call";
  action_taken: "allowed" | "blocked" | "redacted";
  action_reason: "none" | "pii_detected" | "policy_violation";
  action_source: "unknown" | "builtin" | "policy_rules";
  policy_version: string;
  redacted_types: string[];
  blocked_types: string[];
  /** All PII/secret/injection types detected in the result (informational). */
  detected_types: string[];
  rule_id?: string;
  policy_reason?: string;
  /**
   * Which de-obfuscation view surfaced the hit (server-side normalizer mirror). Absent
   * for an overt raw-text match and with deobfuscation disabled. Present ⟹
   * spans are unlocatable, so a redact-mode verdict escalated to BLOCK
   * (sanitize would silently no-op and forward the encoded payload).
   */
  via?: DeobfuscationView["method"];
  /**
   * Canary-leak evidence when a planted honeytoken came back in the tool
   * result (a confused-deputy / exfiltration channel). Forces BLOCK — the
   * result has NOT reached the model, so withholding it is real prevention.
   * Rides `metadata.obsvr_telemetry.canary_leak`; never the raw token.
   */
  canaryTelemetry?: Record<string, unknown>;
}

/**
 * Scan a governed MCP tool RESULT (rendered to text) and decide allow / block /
 * sanitize. Pure over its inputs; no I/O, no mutation.
 */
export function scanMcpToolResult(
  responseText: string,
  config: ResolvedConfig,
  principal?: McpPrincipal,
): McpResponseScan {
  const policyVersion = derivePolicyVersion(config.policyRules ?? []);

  let action: McpResponseScan["action"] = "allow";
  let actionReason: McpResponseScan["action_reason"] = "none";
  let actionSource: McpResponseScan["action_source"] = "unknown";
  let ruleId: string | undefined;
  let policyReason: string | undefined;
  let redactedTypes: string[] = [];
  let blockedTypes: string[] = [];
  let detectedTypes: string[] = [];

  // 1. Structured policy rules, response target. Identity rides along so
  //    user/service/tenant-scoped rules meter the right bucket, never 'default'.
  if (config.policyRules && config.policyRules.length > 0) {
    const evalContext: PolicyEvalContext = {
      metadata: {
        ...(principal?.user_id ? { user_id: principal.user_id } : {}),
        ...(principal?.service_name ? { service_name: principal.service_name } : {}),
        ...(principal?.tenant_id ? { tenant_id: principal.tenant_id } : {}),
      },
    };
    const rulesResult = evaluatePolicyRules(config.policyRules, responseText, "response", evalContext);
    if (rulesResult.decision === "block") {
      action = "block";
      actionReason = "policy_violation";
      actionSource = "policy_rules";
      ruleId = rulesResult.rule_id;
      policyReason = rulesResult.reason;
    } else if (rulesResult.decision === "redact") {
      action = "sanitize";
      actionReason = "policy_violation";
      actionSource = "policy_rules";
      ruleId = rulesResult.rule_id;
      policyReason = rulesResult.reason;
    }
  }

  // 2. Built-in PII / secret / injection scan on the result. A blocked type
  //    escalates to BLOCK (block dominates any redact from step 1); a redact
  //    type sanitizes; detect_only records the finding but passes through.
  let via: DeobfuscationView["method"] | undefined;
  if (config.pii_policy) {
    const scan = runConfiguredPiiScan(responseText, config.deobfuscation);
    if (scan.pii_detected) {
      detectedTypes = scan.detected_types;
      via = scan.via;
      const resolved = resolvePiiPolicy(scan.detected_types, config.pii_policy);
      // A view-only hit has no locatable span: sanitize would no-op and
      // forward the encoded payload, so redact escalates to BLOCK (the tool
      // result has not reached the model yet — blocking is enforceable).
      const piiAction = escalateViewOnlyAction(resolved.action, via);
      if (piiAction === "block") {
        action = "block";
        if (actionReason === "none") actionReason = "pii_detected";
        if (actionSource === "unknown") actionSource = "builtin";
        blockedTypes = resolved.blockedTypes;
        redactedTypes = [...new Set([...redactedTypes, ...resolved.redactedTypes])];
        if (!policyReason) {
          policyReason =
            resolved.action === "redact"
              ? `PII/secret hidden behind ${via} encoding in tool result (redact escalated to block: no locatable span): ${scan.detected_types.join(", ")}`
              : `PII/secret detected in tool result: ${scan.detected_types.join(", ")}`;
        }
      } else if (piiAction === "redact") {
        if (action !== "block") action = "sanitize";
        if (actionReason === "none") actionReason = "pii_detected";
        if (actionSource === "unknown") actionSource = "builtin";
        redactedTypes = [...new Set([...redactedTypes, ...resolved.redactedTypes])];
        if (!policyReason) policyReason = `PII redacted in tool result: ${scan.detected_types.join(", ")}`;
      } else {
        // detect_only: record the finding; do not change the action.
        if (actionReason === "none") {
          actionReason = "pii_detected";
          actionSource = "builtin";
        }
      }
    }
  }

  // Canary-leak scan on the tool RESULT (a confused-deputy exfil channel).
  // Forces BLOCK: the result has NOT reached the model, so withholding it is
  // real prevention. Dominant over PII/rules. Only when a canary is minted.
  let canaryTelemetry: Record<string, unknown> | undefined;
  if (canaryRegistrySize() > 0 && responseText) {
    const leak = scanForCanary(responseText);
    if (leak.leaked) {
      action = "block";
      actionReason = "policy_violation";
      actionSource = "builtin";
      ruleId = "sdk:canary_leak";
      policyReason = `Canary token leaked in tool result (${leak.hits.map((h) => h.id).join(", ")})`;
      canaryTelemetry = canaryLeakTelemetry(leak.hits, "tool_result");
    }
  }

  const eventType: McpResponseScan["event_type"] = action === "block" ? "blocked_call" : "tool_call";
  const actionTaken: McpResponseScan["action_taken"] =
    action === "block" ? "blocked" : action === "sanitize" ? "redacted" : "allowed";

  return {
    action,
    event_type: eventType,
    action_taken: actionTaken,
    action_reason: actionReason,
    action_source: actionSource,
    policy_version: policyVersion,
    redacted_types: redactedTypes,
    blocked_types: blockedTypes,
    detected_types: detectedTypes,
    rule_id: ruleId,
    policy_reason: policyReason,
    ...(via !== undefined ? { via } : {}),
    ...(canaryTelemetry !== undefined ? { canaryTelemetry } : {}),
  };
}

/**
 * Redact PII/secrets from an MCP tool result before it reaches the caller,
 * preserving the result's structure. Handles a bare string, or the standard
 * `{ content: [{ type, text }], ... }` MCP CallToolResult shape. Returns a NEW
 * object (never mutates the upstream result). Non-text content is untouched.
 */
export function sanitizeMcpResult(result: unknown): unknown {
  if (typeof result === "string") return redactBuiltinPii(result);
  if (result && typeof result === "object") {
    const r = result as Record<string, unknown>;
    if (Array.isArray(r.content)) {
      return {
        ...r,
        content: (r.content as unknown[]).map((item) => {
          if (item && typeof item === "object") {
            const it = item as Record<string, unknown>;
            if (typeof it.text === "string") {
              return { ...it, text: redactBuiltinPii(it.text) };
            }
          }
          return item;
        }),
      };
    }
  }
  return result;
}
