"""MCP tool-RESULT governance (ADR-6, response-side interception).

EXACT parity with sdk/src/policy/response-scan.ts.

MCP governance historically scanned only the discovery (list_tools) and request
(call_tool arguments) phases. But the tool RESULT is the exfiltration /
poisoning channel: a compromised or confused-deputy tool can return PII,
secrets, or injection payloads that flow straight back into the model's context.
This module is the response twin of the request-side scanner -- it evaluates the
SAME policy rules (response target) and the SAME built-in PII / secret /
injection scanner against the tool result, then decides:

    BLOCK    -- a blocked pattern (a ``block`` policy rule, or a PII/secret type
                resolved to ``block``) is present: the result is withheld from
                the caller entirely. Unlike an LLM response, a tool result has
                NOT yet reached the model, so blocking is a real, enforceable
                control.
    SANITIZE -- a ``redact`` outcome: the offending spans are redacted from the
                result before it reaches the caller (block dominates redact).
    ALLOW    -- clean, or detect-only: the result passes through unchanged and is
                audited.

Matching runs on the §6-normalized copy (via evaluate_policy_rules /
run_builtin_pii_scan); the returned/sanitized content is only ever redacted,
never normalized.
"""

from typing import Any, Dict, List, Optional

from .config import ResolvedConfig
from .deobfuscate import escalate_view_only_action, run_configured_pii_scan
from .policy import redact_builtin_pii, resolve_pii_policy
from .rules import derive_policy_version, evaluate_policy_rules


def scan_mcp_tool_result(
    response_text: str,
    config: ResolvedConfig,
    principal: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Scan a governed MCP tool RESULT (rendered to text) and decide
    allow / block / sanitize. Pure over its inputs; no I/O, no mutation.

    Returns a dict with keys: action, event_type, action_taken, action_reason,
    action_source, policy_version, redacted_types, blocked_types,
    detected_types, rule_id, policy_reason.
    """
    policy_rules = getattr(config, "policy_rules", None) or []
    policy_version = derive_policy_version(policy_rules)

    action = "allow"
    action_reason = "none"
    action_source = "unknown"
    rule_id: Optional[str] = None
    policy_reason: Optional[str] = None
    redacted_types: List[str] = []
    blocked_types: List[str] = []
    detected_types: List[str] = []

    principal = principal or {}

    # 1. Structured policy rules, response target. Identity rides along so
    #    user/service/tenant-scoped rules meter the right bucket, never 'default'.
    if policy_rules:
        meta: Dict[str, Any] = {}
        if principal.get("user_id"):
            meta["user_id"] = principal["user_id"]
        if principal.get("service_name"):
            meta["service_name"] = principal["service_name"]
        if principal.get("tenant_id"):
            meta["tenant_id"] = principal["tenant_id"]
        rules_result = evaluate_policy_rules(
            policy_rules, response_text, "response", {"metadata": meta}
        )
        decision = rules_result.get("decision", "allow")
        if decision == "block":
            action = "block"
            action_reason = "policy_violation"
            action_source = "policy_rules"
            rule_id = rules_result.get("rule_id")
            policy_reason = rules_result.get("reason")
        elif decision == "redact":
            action = "sanitize"
            action_reason = "policy_violation"
            action_source = "policy_rules"
            rule_id = rules_result.get("rule_id")
            policy_reason = rules_result.get("reason")

    # 2. Built-in PII / secret / injection scan on the result. A blocked type
    #    escalates to BLOCK (block dominates any redact from step 1); a redact
    #    type sanitizes; detect_only records the finding but passes through.
    via: Optional[str] = None
    if getattr(config, "pii_policy", None) is not None:
        scan = run_configured_pii_scan(response_text, getattr(config, "deobfuscation", None))
        if scan["pii_detected"]:
            detected_types = list(scan["detected_types"])
            via = scan.get("via")
            resolved = resolve_pii_policy(scan["detected_types"], config.pii_policy)
            # A view-only hit has no locatable span: sanitize would no-op and
            # forward the encoded payload, so redact escalates to BLOCK (the
            # tool result has not reached the model yet — blocking is
            # enforceable). Parity with the TS response-scan.
            pii_action = escalate_view_only_action(resolved["action"], via)
            if pii_action == "block":
                action = "block"
                if action_reason == "none":
                    action_reason = "pii_detected"
                if action_source == "unknown":
                    action_source = "builtin"
                blocked_types = resolved["blocked_types"]
                redacted_types = list(dict.fromkeys(redacted_types + resolved["redacted_types"]))
                if not policy_reason:
                    if resolved["action"] == "redact":
                        policy_reason = (
                            "PII/secret hidden behind %s encoding in tool result "
                            "(redact escalated to block: no locatable span): %s"
                            % (via, ", ".join(scan["detected_types"]))
                        )
                    else:
                        policy_reason = (
                            "PII/secret detected in tool result: "
                            + ", ".join(scan["detected_types"])
                        )
            elif pii_action == "redact":
                if action != "block":
                    action = "sanitize"
                if action_reason == "none":
                    action_reason = "pii_detected"
                if action_source == "unknown":
                    action_source = "builtin"
                redacted_types = list(dict.fromkeys(redacted_types + resolved["redacted_types"]))
                if not policy_reason:
                    policy_reason = (
                        "PII redacted in tool result: " + ", ".join(scan["detected_types"])
                    )
            else:
                # detect_only: record the finding; do not change the action.
                if action_reason == "none":
                    action_reason = "pii_detected"
                    action_source = "builtin"

    # Canary-leak scan on the tool RESULT (a confused-deputy exfil channel).
    # Forces BLOCK: the result has NOT reached the model, so withholding it is
    # real prevention. Dominant over PII/rules. Only when a canary is minted.
    canary_telemetry = None
    from .canary import canary_registry_size
    if canary_registry_size() > 0 and response_text:
        from .canary import scan_for_canary, canary_leak_telemetry
        leak = scan_for_canary(response_text)
        if leak["leaked"]:
            action = "block"
            action_reason = "policy_violation"
            action_source = "builtin"
            rule_id = "sdk:canary_leak"
            ids = ", ".join(h["id"] for h in leak["hits"])
            policy_reason = f"Canary token leaked in tool result ({ids})"
            canary_telemetry = canary_leak_telemetry(leak["hits"], "tool_result")

    event_type = "blocked_call" if action == "block" else "tool_call"
    action_taken = (
        "blocked" if action == "block" else "redacted" if action == "sanitize" else "allowed"
    )

    result = {
        "action": action,
        "event_type": event_type,
        "action_taken": action_taken,
        "action_reason": action_reason,
        "action_source": action_source,
        "policy_version": policy_version,
        "redacted_types": redacted_types,
        "blocked_types": blocked_types,
        "detected_types": detected_types,
        "rule_id": rule_id,
        "policy_reason": policy_reason,
    }
    if via is not None:
        # Server-side normalizer mirror: which view defeated the obfuscation (key only
        # present on view-only hits — TS parity).
        result["via"] = via
    if canary_telemetry is not None:
        result["canary_telemetry"] = canary_telemetry
    return result


def sanitize_mcp_result(result: Any) -> Any:
    """Redact PII/secrets from an MCP tool result before it reaches the caller,
    preserving the result's structure. Handles the standard CallToolResult shape
    (``.content`` list of items with a ``.text`` attribute or dict key) and bare
    strings. Mutates text fields in place on the result object when possible and
    returns it; a bare string returns a new redacted string.
    """
    if isinstance(result, str):
        return redact_builtin_pii(result)

    content = getattr(result, "content", None)
    if content is None and isinstance(result, dict):
        content = result.get("content")
    if isinstance(content, list):
        for item in content:
            text = getattr(item, "text", None)
            if isinstance(text, str):
                try:
                    item.text = redact_builtin_pii(text)
                except Exception:
                    pass
            elif isinstance(item, dict) and isinstance(item.get("text"), str):
                item["text"] = redact_builtin_pii(item["text"])
    return result
